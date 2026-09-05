package localauth

import (
	"context"
	"time"
)

// AccountStatus 是刷新时复查账号状态的结果。
//
// ⚠️ 模块【不解释】宿主的状态取值 —— 它只问一个问题：这个账号现在还能不能用。
// ⛔ 不要把它做成 int 或字符串枚举，那会让模块开始理解 geass 的 status 语义，
// 而三家的取值一定不同（与「共享模块永远不解释 role 值」同源）。
type AccountStatus struct {
	// Active 账号当前是否可用。false = 封禁/停用/已删。
	Active bool
	// PasswordChangedAt 最近一次改密时间。零值表示从未改过。
	//
	// ⭐ 用它做吊销判定而不是「改密时逐条删 session」——
	// 逐条删只能删掉 sessions 表里的东西，而 access token 不落库，
	// 改密后已签发的 access 在 TTL 内仍然有效，删多少行都管不着它们。
	PasswordChangedAt time.Time
}

// AccountStatusFunc 由消费者提供：按 userID 查账号当前状态。
//
// ⚠️ 查不到用户时返回 Active=false 而不是错误 —— 用户没了，会话当然失效。
// error 只用于真的故障（数据库不可达），⛔ 它与「账号不可用」走完全不同的分支：
// 前者应当报 5xx 并告警，后者是一次正常的 401。
type AccountStatusFunc func(ctx context.Context, userID string) (AccountStatus, error)

// SessionGuard 是会话生命周期的守卫。
//
// # 它保证的四条不变量（§7）
//
//	7.5 存储前哈希 · access 不落库  —— 由 SessionStore 的签名保证（只收 []byte 哈希）
//	7.6 用一次即轮换 + 并发防护      —— 由 Rotate 的单条原子语句 + 受影响行数保证
//	7.7 刷新时复查账号状态           —— 由 Refresh 的编排保证（轮换之后、签票之前）
//	7.3 吊销清单                     —— 由 RevokeAll / 重放检测保证
type SessionGuard struct {
	store      SessionStore
	status     AccountStatusFunc
	refreshTTL time.Duration
	audit      AuditHook
	now        func() time.Time
}

// NewSessionGuard 构造会话守卫。
//
// 三个必填参数无零值语义 —— 与 Guard.New 同一条理由：
// 让「忘了配」在【写代码时】就暴露，而不是部署后才发现。
func NewSessionGuard(
	store SessionStore,
	status AccountStatusFunc,
	refreshTTL time.Duration,
	opts ...SessionOption,
) (*SessionGuard, error) {
	g := &SessionGuard{store: store, status: status, refreshTTL: refreshTTL, now: time.Now}
	for _, o := range opts {
		o(g)
	}
	switch {
	case g.store == nil:
		return nil, newErr(CodeMisconfigured, "必须显式传入 SessionStore")
	case g.status == nil:
		// ⛔ 不给它一个"永远返回 Active"的默认实现 —— 那会让 7.7 静默失效,
		// 而失效的表现是"被封禁的用户还能刷新", 没有任何症状。
		return nil, newErr(CodeMisconfigured, "必须显式传入 AccountStatusFunc (7.7 复查账号状态)")
	case g.refreshTTL <= 0:
		return nil, newErr(CodeMisconfigured, "refreshTTL 必须为正")
	}
	return g, nil
}

// SessionOption 是构造期可选项。
type SessionOption func(*SessionGuard)

// WithSessionAudit 接住会话相关的审计事件。
func WithSessionAudit(h AuditHook) SessionOption {
	return func(g *SessionGuard) { g.audit = h }
}

// WithSessionClock 供测试注入时钟。
func WithSessionClock(f func() time.Time) SessionOption {
	return func(g *SessionGuard) { g.now = f }
}

// ============ 会话生命周期 ============

// Issue 建一条新会话，返回交给客户端的 refresh 明文与落库后的记录。
//
// ⚠️ 明文只在这个返回值里出现一次。⛔ 调用方不得把它写进任何日志、
// 任何持久化、任何响应之外的地方。
//
// ⭐ 同时返回记录是为了拿到【会话 id】—— 调用方要把它放进 access token 的
// sid claim, 好让"当前会话是哪条"这个判定不需要 refresh 明文。
// ⛔ 否则会话列表接口就得让客户端把 refresh 传上来, 那是把长期凭证
// 塞进一个只需要读的请求里。
func (g *SessionGuard) Issue(ctx context.Context, rec SessionRecord) (string, SessionRecord, error) {
	token, err := NewRefreshToken()
	if err != nil {
		return "", SessionRecord{}, err
	}
	rec.CreatedAt = g.now()
	rec.LastActiveAt = rec.CreatedAt
	rec.ExpiresAt = rec.CreatedAt.Add(g.refreshTTL)

	created, err := g.store.Create(ctx, rec, HashRefreshToken(token))
	if err != nil {
		return "", SessionRecord{}, err
	}
	// ⚠️ 用【落库后】的记录 —— 它带着存储层生成的 ID。
	// ⛔ 返回入参 rec 的话 ID 是空的, 而 sid claim 会因此为空。
	if created.ID == "" {
		return "", SessionRecord{}, newErr(CodeMisconfigured,
			"SessionStore.Create 未返回会话 ID —— sid claim 会为空, 当前会话判定失效")
	}
	return token, created, nil
}

// RefreshOutcome 是一次刷新的结果。
type RefreshOutcome struct {
	Session SessionRecord
	// NewRefreshToken 是轮换出的新明文。⭐ 每次刷新都会变。
	NewRefreshToken string
}

// Refresh 校验并轮换一个 refresh token。
//
// 编排顺序如下，⚠️ 每一步的位置都是有理由的：
//
//	① 轮换（单条原子语句）—— 失败即视为重放，见 ②
//	② 重放处置：⭐ 吊销该用户全部会话
//	③ 复查账号状态 —— ⛔ 必须在签新票【之前】
//	④ 比对 password_changed_at
func (g *SessionGuard) Refresh(ctx context.Context, oldToken string) (RefreshOutcome, error) {
	oldHash := HashRefreshToken(oldToken)

	newToken, err := NewRefreshToken()
	if err != nil {
		return RefreshOutcome{}, err
	}
	now := g.now()

	// ① 轮换。⭐ 这一步同时完成了「校验」与「作废旧的」——
	// 它们是同一条语句，所以中间没有任何可以插进来的时刻。
	rec, outcome, err := g.store.Rotate(ctx, oldHash, HashRefreshToken(newToken), now.Add(g.refreshTTL))
	if err != nil {
		// ⛔ 存储故障【不得】当作重放 —— 那会让一次数据库抖动
		// 变成一大批用户的全部会话被吊销。
		return RefreshOutcome{}, wrapErr(CodeLookupUnavailable, "轮换会话失败", err)
	}

	switch outcome {
	case RotateRotated:
		// 继续往下走。

	case RotateReplayed:
		// ② ⭐ 真重放: 这个 token 已经被换走过, 现在又有人拿它来换。
		//
		// # 为什么是「吊销该用户全部会话」而不是只拒绝这一次
		//
		// ⚠️ 这是本文件最重要的一处判断，理由是【代价不对称】：
		//
		//   误伤（合法客户端并发/重试）→ 用户重登一次
		//   漏放（攻击者偷到 refresh 先用）→ 合法方后用被拒、自己重登，
		//     而【攻击者那条链完好无损】，可以一直续到 refreshTTL 结束
		//
		// 也就是说：不吊销的话，重放检测把【受害者】踢了出去而把攻击者留下 ——
		// 正好反了。重放检测存在的全部意义，就是让"合法方后到"这件事
		// 成为把攻击者踢出去的信号。
		//
		// ⛔ 因此这里【没有开关】。一个能关掉的安全机制，在需要它的那天
		// 一定还没开。
		//
		// ⚠️ 代价必须写明：用户会被全部登出且【不知道为什么】。
		// 所以审计事件是必须的，而且将来要能带外通知。
		//
		// ⚠️⚠️ 但这段论证【只对真重放成立】。2026-09-05 之前它被套用在
		// "没有匹配的有效行"这个更大的集合上, 于是一条【已被正常登出】的
		// 会话来刷新也走这里 —— 那里没有任何攻击者需要踢出去,
		// 吊销全部只是把用户自己踢了。见下面的 RotateRevoked 分支。
		if rec.UserID != "" {
			n, revErr := g.store.RevokeAllByUser(ctx, rec.UserID)
			g.emitSession(ctx, EventSessionReplayDetected, rec.UserID, now, n, revErr)
		} else {
			g.emitSession(ctx, EventSessionReplayDetected, "", now, 0, nil)
		}
		return RefreshOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")

	case RotateRevoked:
		// ③ 会话已失效(自己登出 / 被别的设备登出 / 过期)。
		//
		// ⭐ 这是【正常事件】, 处置只有"拒绝这一次"。
		//
		// ⛔ 绝不能吊销全部会话。这条会话已经是死的了, 没有第二方需要踢出去;
		// 而"登出其它设备"之后, 被登出那台设备做一次例行后台刷新就会走到这里 ——
		// 若在此吊销全部, 点按钮的人几秒后也会掉线, 正是那个按钮要防的事。
		//
		// ⚠️ 审计级别刻意低于重放: 这类事件在正常使用中【本来就会发生】,
		// 把它记成安全事件只会淹掉真正的重放。
		g.emitSession(ctx, EventSessionRefreshRejected, rec.UserID, now, 0, nil)
		return RefreshOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")

	default:
		// ④ RotateUnknown —— 查无来历。⭐ 仍然发事件, 但没有可吊销的对象,
		// 也无从判断是不是重放。
		//
		// ⚠️ 消费者把这个事件记在 DEBUG(生产默认关闭) —— 因为它与"已登出"
		// 共用一个 Kind, 而后者在正常使用中大量发生。
		// ⛔ 所以【不要】指望靠它发现撞库/扫描: 那要看
		// /api/auth/refresh 的 401 访问日志(那条是 INFO), 或者将来把
		// Unknown 拆成独立 Kind 再单独定级。
		g.emitSession(ctx, EventSessionRefreshRejected, "", now, 0, nil)
		return RefreshOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
	}

	// ③ 复查账号状态。⛔ 顺序不能与签票对调 ——
	// 先签后查等于已经把新凭证交出去了，再发现账号被封也收不回来。
	st, err := g.status(ctx, rec.UserID)
	if err != nil {
		return RefreshOutcome{}, wrapErr(CodeLookupUnavailable, "复查账号状态失败", err)
	}
	if !st.Active {
		// ⭐ 顺手把这条会话也吊销掉 —— 一个被封的账号不该留着活会话，
		// 哪怕它下一次刷新也会被这里拦住。
		_ = g.store.RevokeByHash(ctx, HashRefreshToken(newToken))
		g.emitSession(ctx, EventSessionAccountInactive, rec.UserID, now, 0, nil)
		return RefreshOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
	}

	// ④ 改密吊销：会话建立于改密之前 → 失效。
	//
	// ⚠️ 用「会话创建时间」而不是「token 签发时间」—— 轮换会更新 token，
	// 但会话的 CreatedAt 不变，所以它才是"这条链什么时候开始的"。
	// ⛔ 若拿轮换后的时间比，改密后只要刷新一次就能洗白。
	if !st.PasswordChangedAt.IsZero() && rec.CreatedAt.Before(st.PasswordChangedAt) {
		_ = g.store.RevokeByHash(ctx, HashRefreshToken(newToken))
		g.emitSession(ctx, EventSessionPasswordChanged, rec.UserID, now, 0, nil)
		return RefreshOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
	}

	return RefreshOutcome{Session: rec, NewRefreshToken: newToken}, nil
}

// Logout 按 refresh 明文吊销单条会话。
//
// ⚠️ 找不到时【不报错】—— 登出是幂等的，而且"这个 token 存不存在"
// 本身就是不该泄漏的信息。
func (g *SessionGuard) Logout(ctx context.Context, token string) error {
	return g.store.RevokeByHash(ctx, HashRefreshToken(token))
}

// List 列出该用户的有效会话。
//
// ⚠️ "哪一条是当前会话"由调用方用【access token 的 sid claim】判定,
// ⛔ 不由前端猜, 也⛔不要求客户端把 refresh 明文传上来 ——
// 后者是把长期凭证塞进一个只需要读的请求。
func (g *SessionGuard) List(ctx context.Context, userID string) ([]SessionRecord, error) {
	return g.store.ListByUser(ctx, userID)
}

// RevokeOne 吊销指定会话。⚠️ userID 必传 —— 见 SessionStore.RevokeByID。
func (g *SessionGuard) RevokeOne(ctx context.Context, userID, sessionID string) error {
	return g.store.RevokeByID(ctx, userID, sessionID)
}

// RevokeOthers 一键登出其它设备，⭐ 保留 keepSessionID 那一条。
//
// ⚠️ 必须排除当前会话 —— 否则用户点完自己也掉线,
// 体验上等同于"这个按钮把我踹了"。
func (g *SessionGuard) RevokeOthers(ctx context.Context, userID, keepSessionID string) (int, error) {
	return g.store.RevokeOthersByUser(ctx, userID, keepSessionID)
}

// RevokeAll 吊销该用户全部会话（封禁 / 改密）。
func (g *SessionGuard) RevokeAll(ctx context.Context, userID string) (int, error) {
	return g.store.RevokeAllByUser(ctx, userID)
}

func (g *SessionGuard) emitSession(ctx context.Context, kind EventKind, userID string, at time.Time, revoked int, revErr error) {
	if g.audit == nil {
		return
	}
	g.audit(ctx, AuditEvent{Kind: kind, Username: userID, At: at, Detail: sessionDetail(revoked, revErr)})
}

func sessionDetail(revoked int, err error) string {
	if err != nil {
		return "吊销失败: " + err.Error()
	}
	if revoked > 0 {
		return "已吊销 " + itoa(revoked) + " 条会话"
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
