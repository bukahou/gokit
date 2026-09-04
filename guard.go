package localauth

import (
	"context"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// LookupFunc 由消费者提供: 按用户名查出密码哈希。
//
// ⚠️ 查不到时返回 found=false 而不是错误 ——「查不到」是正常业务路径。
// 而 err != nil 表示真的出了故障 (数据库不可达等), 它会走一条【独立】的
// 错误码, 不并入凭据失败: 合并之后, 一次数据库故障在监控里长得跟
// 「所有人密码都输错了」一模一样。
type LookupFunc func(ctx context.Context, username string) (hash string, found bool, err error)

// AuditEvent 是守卫发出的审计事件。消费者决定怎么处理。
type AuditEvent struct {
	Kind     string // "denied" / "locked" / "allowed"
	Username string
	ClientIP string
	At       time.Time
}

// AuditHook 让消费者接住审计事件。
//
// ⚠️ 「账号被锁」这件事必须能经【带外通道】通知到账号持有者 ——
// 因为响应体里看不出来 (那是刻意的, 见 LoginOutcome)。
// 一个在故障处置压力下输错一次密码被锁的人, 会以为是自己记错了密码,
// 而浪费的是关键时间。攻击者收不到那条通知, 所以带外通知不泄漏。
//
// 本包只发事件, ⛔ 不投递 —— 投递需要邮件通道, 那是消费者的事。
type AuditHook func(AuditEvent)

// LoginOutcome 是登录守卫的结果。
//
// ⛔ 它刻意【不含】失败原因, 也不含 retryAfter。
//
// 若带上原因, 「处于退避中」与「密码错误」就成了两个可区分的响应, 而
// 「处于退避中」意味着「这个用户名近期被试过」—— 一次探测即可读出。
// 把它做成结构上不可携带, 而不是叮嘱调用方别透出去:
// 能用类型表达的约束, 不该留给纪律。
type LoginOutcome struct{ Allowed bool }

// Option 是构造期可选项。
type Option func(*Guard)

// WithCost 设置目标 bcrypt cost。
//
// ⛔ 刻意【没有】运行时的 SetCost —— cost 与 dummy hash 同源于一次构造,
// 一旦允许运行时改, 「dummy 的 cost 与目标不一致」就重新变成可表达的状态,
// 而那时没人会记得为什么不能加。
func WithCost(c int) Option { return func(g *Guard) { g.cost = c } }

// WithPolicy 换一条退避曲线。
func WithPolicy(p Policy) Option { return func(g *Guard) { g.policy = p } }

// WithMinPasswordLen 设置口令下限。
func WithMinPasswordLen(n int) Option { return func(g *Guard) { g.minLen = n } }

// WithAuditHook 接住审计事件。
func WithAuditHook(h AuditHook) Option { return func(g *Guard) { g.audit = h } }

// WithClock 供测试注入时钟。
func WithClock(f func() time.Time) Option { return func(g *Guard) { g.now = f } }

// Guard 是守卫本体。用 New 构造。
type Guard struct {
	ip        ClientIPStrategy
	admission Admission
	ipStore   FailureStore
	acctStore FailureStore

	policy Policy
	cost   int
	minLen int
	audit  AuditHook
	now    func() time.Time

	// verifier 是口令校验的唯一实现, 与宿主共用同一份 (见 verifier.go)。
	verifier *Verifier
}

// New 构造守卫。
//
// 四个位置参数【必填且无零值语义】。
//
// 为什么是位置参数而不是一个可以留空的 Config: 编译期强于运行期 ——
// 运行期检查仍然允许「代码写完、部署时才发现起不来」, 而必填参数让这个决定
// 必须在【写代码时】做出, 而那是唯一有人在思考部署拓扑的时刻。
func New(
	ip ClientIPStrategy,
	admission Admission,
	ipStore FailureStore,
	acctStore FailureStore,
	opts ...Option,
) (*Guard, error) {
	g := &Guard{
		ip:        ip,
		admission: admission,
		ipStore:   ipStore,
		acctStore: acctStore,
		policy:    DefaultPolicy(),
		cost:      bcrypt.DefaultCost,
		minLen:    6,
		now:       time.Now,
	}
	for _, o := range opts {
		o(g)
	}

	switch {
	case g.ip == nil:
		return nil, newErr(CodeMisconfigured, "必须显式传入 ClientIPStrategy")
	case g.admission == nil:
		return nil, newErr(CodeMisconfigured, "必须显式传入 Admission")
	case g.ipStore == nil:
		return nil, newErr(CodeMisconfigured, "必须显式传入 IP 维度的 FailureStore")
	case g.acctStore == nil:
		return nil, newErr(CodeMisconfigured, "必须显式传入账号维度的 FailureStore")
	case g.ipStore == g.acctStore:
		// ⚠️ 两个维度共用一个存储实例, 等价于把它们合成一个键空间:
		// 一个 IP 与一个用户名可能撞进同一行。两个计数器必须是两个。
		return nil, newErr(CodeMisconfigured, "两个维度必须是两个独立的 FailureStore")
	}

	if bp, ok := g.policy.(BackoffPolicy); ok {
		if err := bp.valid(); err != nil {
			return nil, err
		}
	}

	// 校验器在此现生成: 它与 cost 同源于这一次构造, 所以
	// 「dummy 的 cost 与目标不一致」这个状态【构造不出来】。
	// crypto/rand 与一次 bcrypt 的开销只在这里付, 不在请求路径上。
	v, err := NewVerifier(g.cost)
	if err != nil {
		return nil, err
	}
	g.verifier = v

	return g, nil
}

// Login 是登录守卫的唯一入口。
//
// 编排顺序如下, 每一步的位置都是有理由的:
//
//	① 取 clientIP —— 空串则【降级】(关 IP 维度), 不是失败
//	② 查 IP 退避 —— 命中则【不烧 bcrypt】直接拒
//	③ 无条件跑唯一一次 bcrypt
//	④ 成功优先 —— 密码对就放行并清零, 不受账号退避约束
//	⑤ 查账号退避 —— 命中则拒, 且【不 Bump 不 Reset】
//	⑥ 结算 —— 两个维度各 Bump 一次
func (g *Guard) Login(
	ctx context.Context,
	clientIP string,
	username, password string,
	lookup LookupFunc,
) (LoginOutcome, error) {
	now := g.now()

	// ① 客户端身份。
	//
	// ⚠️ 解析【不在这一层】—— 它需要 HTTP 头, 而本包的调用方常常隔着一次
	// RPC (gateway 在边缘解析, user 服务才是跑守卫的地方)。
	// 所以解析用 ClientIPStrategy 在边缘做一次, 这里只收结果。
	//
	// 空串 = 来源不可用 → 【降级】: 关掉 IP 维度, 账号维度照常。
	// ⛔ 不是失败。理由与代价都写在 ipUnavailable 那一段, 改之前先读它。
	ipAvailable := clientIP != ""
	if !ipAvailable {
		g.emit("ip_source_unavailable", username, "", now)
	}

	// ② IP 维度可以【提前】拒绝, 而账号维度不行 —— 因为 IP 不是凭据内容。
	//
	// 同一个 IP 下、只在凭据内容上不同的两组输入, 走的仍是完全相同的路径;
	// 不同 IP 之间的差异是攻击者自己造成的, 学不到新东西。
	// 所以这里提前返回不构成差分泄漏, 而它是本层唯一能省下 bcrypt 的地方 ——
	// ⚠️ 账号维度【不省】CPU, 那是设计使然, 不是遗漏: 提前判定账号
	// 会造出「被锁的账号返回得快」这个预言机。
	if ipAvailable {
		if ipState, err := g.ipStore.Peek(ctx, clientIP); err == nil {
			if g.policy.Blocked(ipState, now) {
				g.emit("denied", username, clientIP, now)
				return LoginOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
			}
		} else {
			// 存储不可用时不阻断登录, 但这是一次静默的防护损失, 必须可见。
			g.emit("ip_store_unavailable", username, clientIP, now)
		}
	}

	// ③ bcrypt 的唯一调用点, 支配下面所有凭据相关的返回。
	hash, found, err := lookup(ctx, username)
	if err != nil {
		// ⛔ 不得并入凭据失败 —— 见 CodeLookupUnavailable 的注释。
		return LoginOutcome{}, wrapErr(CodeLookupUnavailable, "查询用户失败", err)
	}
	if !found {
		// ⚠️ 这里【不】自己换 dummy —— 代换规则在 Verifier 里, 一处判定。
		// 传空串即可: Verifier 认「这是不是一个合法的 bcrypt hash」,
		// 于是「用户不存在」与「联邦账号无本地口令」走的是同一条路径,
		// 且都不可能因 dummy 匹配而放行。
		hash = ""
	}
	ok := g.verifier.Verify(hash, password)

	// ④ 成功优先于账号退避。
	//
	// ⚠️ 若把这一步放在 ⑤ 之后, 会出现一个很难发现的后果:
	// 账号处于退避中时, 合法用户输入【正确密码】也走不到 Reset,
	// 计数只能靠窗口自然过期, 而攻击者在窗口一过补一次失败即重新压住 ——
	// 合法用户唯一的恢复途径是在缝隙里抢登进去, 对自动化攻击者基本赢不了。
	//
	// 代价必须写明: 拿对密码的人不受账号退避约束, 即账号维度从「锁定」
	// 降为「减速」, 它只挡不知道密码的人。而那恰好是它想挡的那一类 ——
	// 拿着正确凭据的攻击者 (撞库) 本来就不在守卫库的能力范围内,
	// 那要靠泄漏口令库比对 / MFA / 异常检测。所以这个降级没有让我们
	// 失去任何原本拥有的东西。
	if ok {
		if ipAvailable {
			_ = g.ipStore.Reset(ctx, clientIP)
		}
		_ = g.acctStore.Reset(ctx, username)
		g.emit("allowed", username, clientIP, now)
		return LoginOutcome{Allowed: true}, nil
	}

	// ⑤ 账号退避。
	if acctState, err := g.acctStore.Peek(ctx, username); err == nil {
		if g.policy.Blocked(acctState, now) {
			// ⛔ 不 Bump 也不 Reset。
			//
			// 若在这里 Bump: 攻击者持续打一个账号, 每次被拒每次计数 +1,
			// 计数无上限增长、退避窗口指数拉长, 账号被永久锁死。
			// 那正是这一层想防的东西的反面。
			g.emit("locked", username, clientIP, now)
			return LoginOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
		}
	} else {
		g.emit("acct_store_unavailable", username, clientIP, now)
	}

	// ⑥ 结算。两个维度各记一次。
	//
	// ⚠️ 账号维度对【不存在的用户名】同样记录 —— 否则「有没有被计数」
	// 本身就泄漏了账号是否存在。这也是键必须是提交上来的字符串
	// 而不是解析后的用户 id 的原因: 不存在的用户名没有 id。
	//
	// ⚠️ IP 不可用时【不得】拿空串当键去 Bump —— 那会把所有来源不明的
	// 失败堆进同一行, 然后在阈值处把【所有人】一起拒掉。
	// 一个降级措施变成一次自伤式的全站拒绝服务, 比不做还糟。
	if ipAvailable {
		_, _ = g.ipStore.Bump(ctx, clientIP, now)
	}
	_, _ = g.acctStore.Bump(ctx, username, now)

	g.emit("denied", username, clientIP, now)
	return LoginOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
}

// Admit 是注册准入的入口。自助注册与联邦 JIT 建号都必须过它。
func (g *Guard) Admit(ctx context.Context, req AdmitRequest) error {
	return g.admission.Admit(ctx, req)
}

func (g *Guard) emit(kind, username, ip string, at time.Time) {
	if g.audit == nil {
		return
	}
	g.audit(AuditEvent{Kind: kind, Username: username, ClientIP: ip, At: at})
}
