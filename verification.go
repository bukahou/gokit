package localauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// ============ 验证凭证 (§22.3 / §23) ============
//
// 注册 / 找回密码 / 改邮箱 三条流程共用同一套「6 位码」凭证。
//
// # ⭐ selector 在人手转录场景里是什么
//
// §23 保留 selector/verifier 是为了区分「找到但不对」与「根本没有」——
// 链接 token 里 selector 是 URL 的前半段。6 位码没法让用户多抄一段,
// 所以这里由 (subject, purpose) 扮演 selector:
//
//	(subject, purpose) 无未消费行 → 根本没有 → 拒绝, ⛔ 不计 attempts (没有对象可计)
//	有行, 校验不过             → 找到但不对 → attempts+1, 到上限作废
//	有行, 校验通过             → 消费
//
// 「找到但不对」能计数而「根本没有」不计, 正是限流需要的区分:
// 攻击者猜码只能消耗那一行的几次机会, 猜不存在的邮箱什么都消耗不到。

// TokenPurpose 区分用途。⛔ 一个用途的码不得用于另一个用途 ——
// 它参与 HMAC 输入, 所以哪怕两行的码相同, 哈希也不同。
type TokenPurpose string

const (
	PurposeRegister        TokenPurpose = "register"
	PurposeRecoverPassword TokenPurpose = "recover_password"
	PurposeChangeEmail     TokenPurpose = "change_email"
)

// VerificationRecord 是一条验证凭证的【非机密】视图。⛔ 不含码, 不含哈希。
type VerificationRecord struct {
	ID        string
	Purpose   TokenPurpose
	Subject   string // 归属: 已有用户用 userID; 注册时用户还不存在, 用 email
	Payload   string // 附带数据: change_email 时是新地址; recover 时是码发往的地址
	Attempts  int
	ExpiresAt time.Time
}

// VerificationStore 是验证凭证的存储契约。
//
// ⚠️ 与 SessionStore 同一纪律: 参数只有哈希, "存明文"在类型上写不出来。
type VerificationStore interface {
	// Issue 写入一条新记录。⚠️ 实现必须先作废同 (subject, purpose) 的未消费行 ——
	// 一人一码, 重发即覆盖, 否则用户手里同时有效的码会越来越多。
	Issue(ctx context.Context, rec VerificationRecord, verifierHash []byte) (id string, err error)

	// FindPending 取该 (subject, purpose) 下未消费、未过期的行及其哈希。
	// 没有 → found=false, ⛔ 不是错误。
	FindPending(ctx context.Context, purpose TokenPurpose, subject string) (VerificationRecord, []byte, bool, error)

	// BumpAttempts 原子 +1, 返回之后的值。
	BumpAttempts(ctx context.Context, id string) (int, error)

	// Consume 一次性消费。⚠️ 必须是单条原子语句并以受影响行数判定 ——
	// 两个并发请求拿同一个码, 只能有一个成功。
	Consume(ctx context.Context, id string, at time.Time) (bool, error)
}

// VerifiedProof 是「码已校验通过」的凭据。
//
// # ⭐ 它只能从 VerificationGuard.Verify 拿到
//
// id 字段不导出, 包外无法构造一个"有效的" proof。于是需要 proof 的操作
// (重置口令、改邮箱写入) 在【类型上】就不可能绕过校验 ——
// 这与 SessionStore 的参数全是哈希是同一手法: 让错误的用法写不出来。
type VerifiedProof struct {
	id      string
	Purpose TokenPurpose
	Subject string
	Payload string
}

func (p VerifiedProof) valid() bool { return p.id != "" }

// ============ 投递与地址解析契约 ============

// VerificationMessage 是一条要投递的验证消息。模板、语言、通道都在应用。
type VerificationMessage struct {
	To      string
	Purpose TokenPurpose
	// Code 6 位码。⚠️ 纯通知类消息 (Notice 非空) 时为空。
	Code string
	// Notice 非空表示这不是验证码, 而是一条通知:
	//   NoticeExistingAccount  有人用你的邮箱注册, 但它已经是你的账号了
	//   NoticeEmailChanged     你的邮箱刚被改成了 NewAddress
	Notice     NoticeKind
	NewAddress string
}

// NoticeKind 通知类消息的种类。
type NoticeKind string

const (
	NoticeNone            NoticeKind = ""
	NoticeExistingAccount NoticeKind = "existing_account"
	NoticeEmailChanged    NoticeKind = "email_changed"
)

// MessageSender 把消息投递出去。模块只定契约; SMTP / 模板 / 将来的短信都在应用。
type MessageSender interface {
	SendVerification(ctx context.Context, msg VerificationMessage) error
}

// RecoveryAddressResolver 回答「往哪里发找回码」—— 且两个方法都【只认本应用验证过的地址】。
//
// ⛔ 18.3.3 / 18.3.5: 实现只查 email 列且要求 email_verified=1,
// 永不查 upstream_email, 永不 COALESCE。
//
// ⭐ 两个方法都要, 因为【请求与完成之间地址可能被改了】—— 2026-09-05 实测到的
// 接管链正是这个形状: 先换恢复地址, 再申请找回。完成时必须复查
// "码发往的地址"仍是"此刻的已验证地址", 不一致 → 拒绝。
type RecoveryAddressResolver interface {
	// UserByVerifiedAddress 找回入口: 按地址查用户。
	UserByVerifiedAddress(ctx context.Context, address string) (userID string, found bool, err error)
	// VerifiedRecoveryAddress 该用户【此刻】的已验证地址。没有 → ("", false, nil)。
	//
	// ⭐ 18.3.2: 没有已验证地址 = 找回流程对该账号不可用。
	// "不实现 = 安全", 而不是"忘记实现 = 洞" —— 联邦账号在这里自然落空。
	VerifiedRecoveryAddress(ctx context.Context, userID string) (address string, found bool, err error)
}

// ============ 发码限流 ============

// SendThrottle 发码限流参数。
//
// # 为什么放模块
//
// 发码是【外部成本】: 被刷 = SMTP 配额烧光 + 对任意邮箱的骚扰。
// 三条流程都要, 放应用就是三份摹本; 且它是流程的一步 (拒绝要早于任何写入),
// 编排在模块里才能保证顺序。
type SendThrottle struct {
	// 地址维度: 同一地址在 AddressWindow 内最多 PerAddress 次, 每次之间至少间隔 Cooldown。
	PerAddress    int
	AddressWindow time.Duration
	Cooldown      time.Duration
	// IP 维度: 同一 IP 在 IPWindow 内最多 PerIP 次。
	PerIP    int
	IPWindow time.Duration
}

// DefaultSendThrottle 用户裁决 D4 (2026-09-05): 地址 3/10min + 60s 冷却, IP 20/h。
func DefaultSendThrottle() SendThrottle {
	return SendThrottle{
		PerAddress: 3, AddressWindow: 10 * time.Minute, Cooldown: 60 * time.Second,
		PerIP: 20, IPWindow: time.Hour,
	}
}

// ============ 守卫 ============

// VerificationGuard 负责 6 位码的签发 / 投递 / 校验 / 消费 / 限流。
//
// 三条业务流程 (注册 / 找回 / 改邮箱) 各自的编排在各自的 Guard 里, 它们共用这一个。
type VerificationGuard struct {
	store     VerificationStore
	sender    MessageSender
	addrStore FailureStore
	ipStore   FailureStore
	pepper    []byte
	ttl       time.Duration
	maxTries  int
	throttle  SendThrottle
	audit     AuditHook
	now       func() time.Time
	// sendTimeout 异步投递的超时。
	sendTimeout time.Duration
}

// VerificationOption 配置 VerificationGuard。
type VerificationOption func(*VerificationGuard)

// WithVerificationTTL 码的有效期 (默认 10 分钟, 用户裁决 D8)。
func WithVerificationTTL(d time.Duration) VerificationOption {
	return func(g *VerificationGuard) { g.ttl = d }
}

// WithVerificationMaxAttempts 同一个码最多试几次 (默认 5, 用户裁决 D8)。
func WithVerificationMaxAttempts(n int) VerificationOption {
	return func(g *VerificationGuard) { g.maxTries = n }
}

// WithSendThrottle 发码限流参数 (默认 DefaultSendThrottle)。
func WithSendThrottle(t SendThrottle) VerificationOption {
	return func(g *VerificationGuard) { g.throttle = t }
}

// WithVerificationAudit 接住审计事件。
func WithVerificationAudit(h AuditHook) VerificationOption {
	return func(g *VerificationGuard) { g.audit = h }
}

// WithVerificationClock 换时钟 (测试用)。
func WithVerificationClock(f func() time.Time) VerificationOption {
	return func(g *VerificationGuard) { g.now = f }
}

// NewVerificationGuard 构造。
//
// ⚠️ pepper 必填且不得为空。
//
// # 为什么 6 位码要 pepper 而 refresh token 只用裸 SHA-256
//
// refresh 是 256 bit 随机数, 离线爆破物理上不可行。6 位码只有 10^6 个可能:
// 库泄漏时裸哈希秒破。HMAC 的 pepper 不在库里 (K8s Secret), 没有它, 库里的
// 哈希就是随机数。
//
// ⚠️ pepper 丢失的代价只是【在途的 10 分钟验证码全部作废】—— 用户重新申请一次
// 即可。与 AKASHA_PAIRWISE_SALT 那种"丢了永久失效"不是一个量级, 所以它不需要
// 那种级别的保管纪律。
//
// ⚠️ addrStore / ipStore 必填: 缺了限流就静默消失, 而失效的表现是"SMTP 配额被
// 刷光"—— 到那时才发现。
func NewVerificationGuard(
	store VerificationStore, sender MessageSender,
	addrStore, ipStore FailureStore, pepper []byte,
	opts ...VerificationOption,
) (*VerificationGuard, error) {
	g := &VerificationGuard{
		store: store, sender: sender, addrStore: addrStore, ipStore: ipStore,
		pepper: pepper, ttl: 10 * time.Minute, maxTries: 5,
		throttle: DefaultSendThrottle(), now: time.Now, sendTimeout: 30 * time.Second,
	}
	for _, o := range opts {
		o(g)
	}
	switch {
	case store == nil:
		return nil, newErr(CodeMisconfigured, "必须传入 VerificationStore")
	case sender == nil:
		return nil, newErr(CodeMisconfigured, "必须传入 MessageSender")
	case addrStore == nil || ipStore == nil:
		return nil, newErr(CodeMisconfigured, "必须传入两个 FailureStore (发码限流的地址维度与 IP 维度)")
	case len(pepper) < 16:
		return nil, newErr(CodeMisconfigured, "验证码 pepper 必须至少 16 字节")
	case g.ttl <= 0 || g.maxTries <= 0:
		return nil, newErr(CodeMisconfigured, "验证码 TTL 与尝试上限必须为正")
	}
	return g, nil
}

// hashVerifier 计算存储用的哈希。
//
// ⚠️ purpose 与 subject 参与输入: 同一个码在不同用途 / 不同主体下哈希不同,
// 所以一行的哈希不可能与另一行对上 —— 哪怕码碰巧相同。
func (g *VerificationGuard) hashVerifier(purpose TokenPurpose, subject, code string) []byte {
	mac := hmac.New(sha256.New, g.pepper)
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write([]byte(subject))
	mac.Write([]byte{0})
	mac.Write([]byte(code))
	return mac.Sum(nil)
}

// GenerateCode 生成 6 位数字码 (crypto/rand, 保留前导零)。
func GenerateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("生成验证码失败: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// CheckSendAllowed 发码限流。⚠️ 通过即计数 —— 它是"允许并记一次", 不是纯查询。
//
// # 两个维度独立
//
// 地址维度防"对一个邮箱狂轰", IP 维度防"一个 IP 对很多邮箱狂轰"。
// 复合键会被两个维度的轮换分别绕开 (见 001_login_failures.sql 的注释)。
//
// # 计数存储不可用时放行 + 留痕
//
// fail-closed 等于"计数表抖动 = 没人能注册"。放行期间的代价是邮件被刷,
// 而那被 SMTP 侧的配额兜住; 留痕让它可计数 (verification.throttle_unavailable)。
//
// ⚠️ ip 为空 (来源不可信) 时只做地址维度, 并留痕 —— ⛔ 不得把空串当一个键计数,
// 那会让所有 IP 未知的请求共享一个桶, 一个人就能把所有人锁掉。
func (g *VerificationGuard) CheckSendAllowed(ctx context.Context, purpose TokenPurpose, address, ip string) error {
	now := g.now()

	addrKey := "send:" + string(purpose) + ":" + address
	if blocked, err := g.checkWindow(ctx, g.addrStore, addrKey, g.throttle.PerAddress, g.throttle.AddressWindow, g.throttle.Cooldown, now); err != nil {
		g.emitVerification(ctx, EventVerificationThrottleUnavailable, address, "地址维度: "+err.Error())
	} else if blocked {
		g.emitVerification(ctx, EventVerificationThrottled, address, "地址维度")
		return newErr(CodeTooManyRequests, "操作过于频繁, 请稍后再试")
	}

	if ip == "" {
		g.emitVerification(ctx, EventVerificationIPUnavailable, address, "")
		return nil
	}
	ipKey := "send:ip:" + ip
	if blocked, err := g.checkWindow(ctx, g.ipStore, ipKey, g.throttle.PerIP, g.throttle.IPWindow, 0, now); err != nil {
		g.emitVerification(ctx, EventVerificationThrottleUnavailable, address, "IP 维度: "+err.Error())
	} else if blocked {
		g.emitVerification(ctx, EventVerificationThrottled, address, "IP 维度 "+ip)
		return newErr(CodeTooManyRequests, "操作过于频繁, 请稍后再试")
	}
	return nil
}

// checkWindow 固定窗口计数: 窗口内达到上限 → 阻断; 窗口过期 → 重置后重新计数。
func (g *VerificationGuard) checkWindow(
	ctx context.Context, store FailureStore, key string, limit int, window, cooldown time.Duration, now time.Time,
) (bool, error) {
	st, err := store.Peek(ctx, key)
	if err != nil {
		return false, err
	}
	if st.Count > 0 && !st.FirstFailAt.IsZero() && now.Sub(st.FirstFailAt) >= window {
		// 窗口过期, 从头计
		if err := store.Reset(ctx, key); err != nil {
			return false, err
		}
		st = FailureState{}
	}
	if st.Count > 0 && cooldown > 0 && now.Sub(st.LastFailAt) < cooldown {
		return true, nil
	}
	if st.Count >= limit {
		return true, nil
	}
	if _, err := store.Bump(ctx, key, now); err != nil {
		return false, err
	}
	return false, nil
}

// IssueAndSend 签发一个码并投递。同步; 调用方决定是否放进 goroutine。
func (g *VerificationGuard) IssueAndSend(
	ctx context.Context, purpose TokenPurpose, subject, address, payload string,
) error {
	code, err := GenerateCode()
	if err != nil {
		return err
	}
	rec := VerificationRecord{Purpose: purpose, Subject: subject, Payload: payload, ExpiresAt: g.now().Add(g.ttl)}
	if _, err := g.store.Issue(ctx, rec, g.hashVerifier(purpose, subject, code)); err != nil {
		return wrapErr(CodeLookupUnavailable, "写入验证码失败", err)
	}
	if err := g.sender.SendVerification(ctx, VerificationMessage{To: address, Purpose: purpose, Code: code}); err != nil {
		return wrapErr(CodeLookupUnavailable, "投递验证码失败", err)
	}
	return nil
}

// SendAsync 在后台完成 fn, 失败进审计。
//
// # ⭐ 为什么发码要异步 —— 时序枚举
//
// 找回密码: 命中才「生成码 + 写库 + SMTP 往返」, 未命中直接返回 ——
// 差距是数量级的, 响应时间就是一个"这个邮箱存在吗"的预言机。
// 把可变成本整个挪出请求路径, 两个分支剩下的都是一次索引查询。
//
// ⚠️ 异步意味着「投递失败」用户看不到 —— 这是刻意的: 告诉他就等于
// 告诉他邮箱存在。失败进 verification.send_failed (WARN, 可计数)。
//
// ⚠️ ctx 必须与请求脱钩 (WithoutCancel): 请求一返回, 原 ctx 就被取消了。
func (g *VerificationGuard) SendAsync(ctx context.Context, address string, fn func(context.Context) error) {
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), g.sendTimeout)
	go func() {
		defer cancel()
		if err := fn(bg); err != nil {
			g.emitVerification(bg, EventVerificationSendFailed, address, err.Error())
		}
	}()
}

// Verify 校验一个码。通过 → VerifiedProof; ⚠️ 此时【不】消费。
//
// 所有失败对外都是同一个错误 —— 「根本没有」「码不对」「试太多次」「已过期」
// 在响应上不可区分。区分只发生在内部 (计不计 attempts)。
func (g *VerificationGuard) Verify(ctx context.Context, purpose TokenPurpose, subject, code string) (VerifiedProof, error) {
	invalid := newErr(CodeInvalidCode, "验证码无效或已过期")
	if code == "" {
		return VerifiedProof{}, invalid
	}
	rec, hash, found, err := g.store.FindPending(ctx, purpose, subject)
	if err != nil {
		return VerifiedProof{}, wrapErr(CodeLookupUnavailable, "查询验证码失败", err)
	}
	if !found || !g.now().Before(rec.ExpiresAt) {
		return VerifiedProof{}, invalid // 根本没有 / 已过期: ⛔ 不计 attempts
	}
	if rec.Attempts >= g.maxTries {
		g.emitVerification(ctx, EventVerificationExhausted, subject, string(purpose))
		return VerifiedProof{}, invalid
	}
	if subtle.ConstantTimeCompare(hash, g.hashVerifier(purpose, subject, code)) != 1 {
		if n, err := g.store.BumpAttempts(ctx, rec.ID); err == nil && n >= g.maxTries {
			g.emitVerification(ctx, EventVerificationExhausted, subject, string(purpose))
		}
		g.emitVerification(ctx, EventVerificationCodeMismatch, subject, string(purpose))
		return VerifiedProof{}, invalid
	}
	return VerifiedProof{id: rec.ID, Purpose: purpose, Subject: subject, Payload: rec.Payload}, nil
}

// Consume 一次性消费。⚠️ 并发下只有一个调用方能成功。
func (g *VerificationGuard) Consume(ctx context.Context, proof VerifiedProof) error {
	if !proof.valid() {
		return newErr(CodeMisconfigured, "无效的 VerifiedProof")
	}
	ok, err := g.store.Consume(ctx, proof.id, g.now())
	if err != nil {
		return wrapErr(CodeLookupUnavailable, "消费验证码失败", err)
	}
	if !ok {
		return errors.New("验证码已被消费")
	}
	return nil
}

func (g *VerificationGuard) emitVerification(ctx context.Context, kind EventKind, subject, detail string) {
	if g.audit == nil {
		return
	}
	g.audit(ctx, AuditEvent{Kind: kind, Username: subject, At: g.now(), Detail: detail})
}
