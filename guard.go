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

// EventKind 是审计事件的【稳定机器标识】。
//
// ⚠️ 必须是类型化常量而不是裸字符串, 理由是一个很安静的失效:
// 告警规则按这个值匹配, 而一个打错字母的 g.emit("ip_source_unavailble", …)
// 编译得过、日志照发、规则永远不响 —— 没有任何症状。
// 常量让这个状态编译不过。
//
// ⛔ 这些值一旦发布就【不可改名】: 它们是外部告警规则的匹配键,
// 改名等于静默关掉那条规则。要换语义就加一个新的 Kind。
type EventKind string

const (
	// EventAllowed 登录成功。
	EventAllowed EventKind = "login.allowed"
	// EventDenied 凭据类失败 (密码错 / 用户不存在 / 被 IP 维度提前拒)。
	EventDenied EventKind = "login.denied"
	// EventLocked 【账号】维度退避拦截。
	//
	// ⚠️ 名字里没有 "account" 是历史包袱 —— 它先于 EventIPBlocked 存在,
	// 而 EventKind 的值是外部告警规则的匹配键, ⛔ 改名会静默关掉那条规则。
	// 所以这里保持原样并在注释里说清语义, 而不是为了对称去重命名。
	EventLocked EventKind = "login.locked"

	// EventIPBlocked 【IP】维度退避拦截。
	//
	// ⭐ 它必须与 EventDenied 分开, 理由是【我们自己要看得见】:
	//
	// 对外不可区分是刻意的 —— 响应体若能区分"处于退避中"与"密码错误",
	// 一次探测就能读出"这个用户名近期被试过"。
	// 但审计日志是【给运维看的内部信号】, 在那里也不可区分就成了缺陷:
	// 日志流里分不出「有人在爆破」和「用户忘了密码」。
	//
	// 早先这条走的是 EventDenied, 于是唯一能看出退避触发的地方是计数表 ——
	// 那要轮询。有了这个 Kind, 告警就能建在日志流上。
	//
	// ⛔ 它【不是】降级信号 (Degraded() 返回 false): 这是防护正在生效,
	// 不是防护失效。两者混在一起会让"防护正常工作"触发降级告警。
	EventIPBlocked EventKind = "login.ip_blocked"

	// ⭐ 下面三个是【防护降级】信号 —— 它们存在的全部意义就是被告警。
	//
	// 站点在这三种状态下看起来完全正常, 唯一的症状就是这几条事件。
	// 不接告警的话, 一个配错的部署会永久少一个控制面而没人知道。

	// EventIPSourceUnavailable 解析不出客户端来源 IP, IP 维度已降级。
	EventIPSourceUnavailable EventKind = "login.ip_source_unavailable"
	// EventIPStoreUnavailable IP 维度的计数存储不可用, 本次未生效。
	EventIPStoreUnavailable EventKind = "login.ip_store_unavailable"
	// EventAccountStoreUnavailable 账号维度的计数存储不可用, 本次未生效。
	EventAccountStoreUnavailable EventKind = "login.account_store_unavailable"

	// ⭐ 会话相关 (批次二)。

	// EventSessionReplayDetected ⭐ 一个【已被换走】的 refresh token 又被拿来换。
	//
	// ⚠️ 这是【最值得看的一条】: 它要么是攻击者在用偷到的 token,
	// 要么是客户端并发/重试。⭐ 两者都会导致该用户全部会话被吊销,
	// 所以它同时是"用户为什么突然全部登出"的唯一解释来源。
	// ⛔ 缺了它, 用户会遇到一次无法解释的全体登出。
	//
	// ⚠️ 语义在 2026-09-05 收窄过: 它曾经覆盖"任何一次刷新失败", 于是
	// 正常登出后的一次后台刷新也会记成重放【并触发全体吊销】。
	// ⛔ 不要再把它放宽 —— 一个在正常使用中就会大量出现的"安全事件",
	// 等于没有这个事件: 真的重放会被淹没在噪声里。
	EventSessionReplayDetected EventKind = "session.replay_detected"

	// EventSessionRefreshRejected 刷新被拒, 但【不是】重放。
	//
	// 覆盖: 会话已登出 / 已被别的设备登出 / 已过期 / token 查无来历。
	// ⭐ 这些在正常使用中本来就会发生, 所以它是【运行事件而非安全事件】——
	// 级别刻意低于 replay_detected, 否则告警会被它淹掉。
	//
	// ⚠️ 消费者据此把它记在 DEBUG —— 生产默认看不到。
	// ⛔ 因此不要指望靠它发现撞库/扫描: 那要看 /api/auth/refresh 的
	// 401 访问日志, 或将来把"查无来历"拆成独立 Kind 再单独定级。
	EventSessionRefreshRejected EventKind = "session.refresh_rejected"
	// EventSessionAccountInactive 刷新时发现账号已被封禁/停用。
	EventSessionAccountInactive EventKind = "session.account_inactive"
	// EventSessionPasswordChanged 会话建立于改密之前, 已失效。
	EventSessionPasswordChanged EventKind = "session.password_changed"

	// ⭐ 口令策略相关 (批次三 §14)。

	// EventPasswordBreached 新口令出现在已知泄露集合中。
	//
	// ⚠️ INFO 级 —— 用户选了个烂口令是【正常业务流程】, 不是安全事件。
	// geass 采用警告放行(用户裁决), 所以它甚至不中断流程。
	// ⛔ 记成 WARN/ERROR 会让它在正常使用中持续刷屏, 淹掉真正要看的东西。
	EventPasswordBreached EventKind = "password.breached"

	// EventBreachCheckUnavailable ⭐ 泄露库查不了, 已按 §14.2.1 fail-open 放行。
	//
	// ⚠️⚠️ 这条是【fail-open 的代价凭证】, 也是本仓唯一一次允许
	// "零值通向放行"(BreachUnknown 占零值位)的补偿控制。
	//
	// ⛔ 没有它, 泄露库可以挂三个月而没有任何人知道 —— 因为 fail-open
	// 的表现与"一切正常"完全一样: 用户照常改密, 没有报错, 没有拒绝。
	// 这正是最难发现的那类失效。
	//
	// WARN 级, 聚合超阈值即告警。
	EventBreachCheckUnavailable EventKind = "password.breach_check_unavailable"

	// EventPasswordChanged 用户改了口令 (⑤)。INFO —— 审计回溯用。
	EventPasswordChanged EventKind = "password.changed"

	// EventPasswordInitialized SSO 账号首次设置了口令 (⑥)。
	//
	// ⚠️ 与 changed 分开记 —— 它是【认证面的实质变化】:
	// 一个原本只能 SSO 登录的账号从此多了一条口令入口。
	// ⛔ 混进 changed 就查不出"谁给自己开了第二条入口"。
	EventPasswordInitialized EventKind = "password.initialized"

	// EventPasswordRevokeFailed 口令已改, 但吊销旧会话失败。
	//
	// ⚠️⚠️ ERROR 级 —— 这是少数真正需要人介入的情形:
	// 口令变了而旧会话还活着。§7.7 应当在下一次 refresh 时兜住,
	// 但"应当"不等于"确认", 而攻击者的会话可能就在其中。
	EventPasswordRevokeFailed EventKind = "password.revoke_failed"

	// EventPasswordReissueFailed 改密成功但没能为当前设备重签。
	//
	// ⚠️ WARN 而非 ERROR: 用户重新登录即可, 没有安全后果。
	EventPasswordReissueFailed EventKind = "password.reissue_failed"
)

// AllEventKinds 列出全部事件类型。
//
// ⭐ 它的用途是让消费者【能够穷举】: 把审计事件映射成日志/告警的那段
// switch 是本清单的一份副本, 而副本一定会漏。
//
// ⚠️ 2026-09-05 漏过一次: 批次二加了四个 session 事件, 消费者侧
// (internal/user auditToSlog) 一个 case 都没加也没有 default,
// 于是它们在生产中【一条都不记】—— 包括 replay_detected,
// 也就是"用户为什么突然全部登出"的唯一解释来源。
//
// ⛔ 新增 EventKind 时必须同时加进这里。忘了加不会立刻出错,
// 但消费者侧的穷举测试就覆盖不到它 —— 所以消费者【还必须有 default】,
// 两道网各自独立, 单靠任何一道都不够。
func AllEventKinds() []EventKind {
	return []EventKind{
		EventAllowed,
		EventDenied,
		EventIPBlocked,
		EventLocked,
		EventIPSourceUnavailable,
		EventIPStoreUnavailable,
		EventAccountStoreUnavailable,
		EventSessionReplayDetected,
		EventSessionRefreshRejected,
		EventSessionAccountInactive,
		EventSessionPasswordChanged,
		EventPasswordBreached,
		EventBreachCheckUnavailable,
		EventPasswordChanged,
		EventPasswordInitialized,
		EventPasswordRevokeFailed,
		EventPasswordReissueFailed,
	}
}

// Degraded 报告这个事件是否表示【防护已降级】。
//
// 给消费者一个统一判据, 免得每一家各自维护一份 Kind 清单 ——
// 那种清单在加新 Kind 时必然漏掉一处, 而漏掉的表现是告警不响。
func (k EventKind) Degraded() bool {
	switch k {
	// ⚠️ 会话事件【都不是降级】—— replay_detected 是防护正在生效,
	// account_inactive / password_changed 是吊销按预期工作。
	// ⛔ 混进降级会让"防护正常"触发降级告警。
	case EventIPSourceUnavailable, EventIPStoreUnavailable, EventAccountStoreUnavailable:
		return true
	default:
		return false
	}
}

// AuditEvent 是守卫发出的审计事件。消费者决定怎么处理。
type AuditEvent struct {
	Kind EventKind

	// Username 是【用户提交的登录标识】—— 登录类事件填它。
	//
	// ⚠️ 会话类事件填的是 UserID 而不是这里: 刷新时手上只有会话记录,
	// 根本没有用户名。⛔ 曾经把 UserID 塞进本字段, 于是日志里
	// username="01a06f96-1dd6-..." —— 按用户名查什么都查不到。
	Username string

	// UserID 是内部主键。⭐ 会话类事件用它。
	UserID string

	ClientIP string
	At       time.Time

	// Detail 是可选的补充说明 (如"已吊销 N 条会话" / "吊销失败: ...")。
	// ⛔ 不得放任何凭证或其哈希。
	//
	// ⚠️⚠️ 消费者【必须】把它记进日志。2026-09-05 生产实测它被整个丢掉了,
	// 后果不只是少一个数字: sessionDetail 用这个字段传递【吊销失败】——
	// 重放检测判定成立却没能吊销成功, 意味着攻击者那条链还活着,
	// 而这个失败当时在日志里完全不可见。
	Detail string
}

// AuditHook 让消费者接住审计事件。
//
// ⚠️ 「账号被锁」这件事必须能经【带外通道】通知到账号持有者 ——
// 因为响应体里看不出来 (那是刻意的, 见 LoginOutcome)。
// 一个在故障处置压力下输错一次密码被锁的人, 会以为是自己记错了密码,
// 而浪费的是关键时间。攻击者收不到那条通知, 所以带外通知不泄漏。
//
// 本包只发事件, ⛔ 不投递 —— 投递需要邮件通道, 那是消费者的事。
// ⚠️ 必须带 ctx。本钩子在【请求路径上】被调用, 而消费者几乎一定是写日志 ——
// 不带 ctx 的日志 TraceId 为空, APM 里跳不回对应的调用链。
// 而降级类事件恰恰最需要"这是哪一次请求"。
type AuditHook func(context.Context, AuditEvent)

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
		minLen:    DefaultMinPasswordLen,
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
		g.emit(ctx, EventIPSourceUnavailable, username, "", now)
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
				// ⚠️ 事件与 EventDenied 分开, 但【返回值完全一样】——
				// 可区分的只有内部日志, 对外仍是同一个 CodeInvalidCredentials。
				g.emit(ctx, EventIPBlocked, username, clientIP, now)
				return LoginOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
			}
		} else {
			// 存储不可用时不阻断登录, 但这是一次静默的防护损失, 必须可见。
			g.emit(ctx, EventIPStoreUnavailable, username, clientIP, now)
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
		g.emit(ctx, EventAllowed, username, clientIP, now)
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
			g.emit(ctx, EventLocked, username, clientIP, now)
			return LoginOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
		}
	} else {
		g.emit(ctx, EventAccountStoreUnavailable, username, clientIP, now)
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

	g.emit(ctx, EventDenied, username, clientIP, now)
	return LoginOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
}

// Admit 是注册准入的入口。自助注册与联邦 JIT 建号都必须过它。
func (g *Guard) Admit(ctx context.Context, req AdmitRequest) error {
	return g.admission.Admit(ctx, req)
}

func (g *Guard) emit(ctx context.Context, kind EventKind, username, ip string, at time.Time) {
	if g.audit == nil {
		return
	}
	g.audit(ctx, AuditEvent{Kind: kind, Username: username, ClientIP: ip, At: at})
}
