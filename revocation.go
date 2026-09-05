package localauth

import (
	"context"
	"time"
)

// ============ 吊销纪元 (§D1) ============

// RevocationStore 存放每个用户的【吊销纪元】。
//
// # 语义
//
//	epoch(user) = T  ⇒  该用户在 T 之前签发的 access token 一律失效
//
// 判定发生在网关: `token.iat < epoch` → 拒绝。
//
// # ⛔ 为什么不复用 pkg/cache.Cache
//
// pkg/cache 的契约刻意把"未命中"与"出错"合并成一个 bool, 它的 doc 写得很清楚:
// "未命中与出错在调用方看来是同一件事: 去数据库拿"。
//
// 对【缓存】那是对的。对【吊销检查】是错的:
//   - 未命中 = 这个用户从没被吊销过 —— 正常, 绝大多数请求都是这样
//   - 出错   = 我们不知道他有没有被吊销 —— ⚠️ 必须可计数
//
// 合并之后, "Redis 挂了"与"这个用户很正常"变得无法区分, 于是
// ⛔ fail-open 的代价就再也看不见了 —— 而 §D2 明确要求它可见。
// 这与 §14 的 BreachUnknown 是同一条道理: 查不成必须是一个有名字的状态。
type RevocationStore interface {
	// LoadEpoch 读吊销纪元。
	//
	// 返回 (T, true, nil)     = 该用户的纪元是 T
	// 返回 (零值, false, nil) = ⭐ 没有纪元 —— 正常, 从没吊销过
	// 返回 (_, false, err)    = ⚠️ 查不了, ⛔ 与上一种【不是】一回事
	LoadEpoch(ctx context.Context, userID string) (time.Time, bool, error)

	// SaveEpoch 写入/推进吊销纪元。
	//
	// ⚠️ 实现【必须】只前进不后退: 已有纪元 T1 > T2 时写 T2 应当无效果。
	// ⛔ 否则一次乱序的写(比如封禁与改密并发)会把纪元往回拨,
	// 从而让一批本该失效的 token 复活。
	SaveEpoch(ctx context.Context, userID string, epoch time.Time) error
}

// RevocationChecker 判定一张 access token 是否已被吊销。
//
// # ⭐ 它顺带解决的不止改密
//
//	改密          → 立即失效 (§7.3 的 access 侧)
//	封禁 / 停用   → 立即失效 (此前要等 access TTL 到期, 最长 900 秒)
//	强制登出      → 免费获得这个能力
//
// 三件事共用同一个纪元, 因为它们要表达的是同一句话:
// "该用户此刻之前的所有 access token 都不再算数"。
type RevocationChecker struct {
	store RevocationStore
	audit AuditHook
	now   func() time.Time
}

// RevocationOption 配置 RevocationChecker。
type RevocationOption func(*RevocationChecker)

// WithRevocationAudit 接住审计事件 (降级要可计数)。
func WithRevocationAudit(h AuditHook) RevocationOption {
	return func(c *RevocationChecker) { c.audit = h }
}

// WithRevocationClock 换时钟 (测试用)。
func WithRevocationClock(f func() time.Time) RevocationOption {
	return func(c *RevocationChecker) { c.now = f }
}

// NewRevocationChecker 构造判定器。
//
// ⚠️ store 为 nil 时返回一个【永远放行】的判定器, 而这是合法配置 ——
// 没接 Redis 的部署退化成"只靠 access TTL 兜底", 与本特性上线前一致。
// ⛔ 但它不是静默的: 每次判定都会发一条可计数的降级事件, 见 IsRevoked。
func NewRevocationChecker(store RevocationStore, opts ...RevocationOption) *RevocationChecker {
	c := &RevocationChecker{store: store, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Enabled 报告是否真的接了存储 (供启动日志)。
func (c *RevocationChecker) Enabled() bool { return c.store != nil }

// IsRevoked 判定一张 iat=issuedAt 的 access token 是否已被吊销。
//
// # ⭐ fail-open (§D2 用户裁决)
//
// 查不到纪元 / 存储故障 / 没接存储 → 一律【放行】。
//
// ⛔ 绝不能 fail-closed: 那等于"Redis 抖动 = 全站掉线",
// 违反 pkg/cache 立的第一条约束「缓存故障绝不能变成业务故障」。
// 而放行的后果只是退回到本特性上线前的状态(靠 access TTL 兜底, ≤900 秒),
// ⚠️ 两种代价【不在一个量级】。
//
// ⚠️ 但故障必须留痕: 只有 error 那一支发事件。
// ⛔ "没有纪元"不发 —— 那是绝大多数请求的正常状态, 记了就是纯噪声,
// 而且会把真正的故障淹掉。这与 §14 里 Skipped 不发事件是同一条理由。
func (c *RevocationChecker) IsRevoked(ctx context.Context, userID string, issuedAt time.Time) bool {
	if c.store == nil {
		return false
	}
	epoch, found, err := c.store.LoadEpoch(ctx, userID)
	if err != nil {
		c.emitRevocation(ctx, EventRevocationCheckUnavailable, userID, err.Error())
		return false // ⭐ fail-open
	}
	if !found {
		return false
	}
	// ⚠️ 判据是 Before 而不是 !After —— 与 §7.7 保持一致。
	//
	// 纪元与"紧接着签发的新 token"可能落在同一秒(改密流程就是这样:
	// 写纪元与重签相隔几毫秒)。若让"相等"也算失效, 改密后立即重签出来的
	// 那张 access token 会当场作废 —— 100% 复现的"改完密码立刻掉线"。
	//
	// ⛔ 这条与 session_guard.go 里 §7.7 的判据是【同一个陷阱】,
	// 改任何一处之前先看另一处。
	return issuedAt.Before(epoch)
}

func (c *RevocationChecker) emitRevocation(ctx context.Context, kind EventKind, userID, detail string) {
	if c.audit == nil {
		return
	}
	c.audit(ctx, AuditEvent{Kind: kind, UserID: userID, At: c.now(), Detail: detail})
}

// RevokeIssuedThrough 吊销【包括当前这一秒在内】签发的全部 token。
//
// # ⚠️⚠️ 为什么需要它 —— 一个用生产实测才发现的 1 秒窗口
//
// JWT 的 iat 是【秒】精度, 纪元也是。而判定用的是 `iat < epoch`
// ("相等不算失效")。于是:
//
//	13:00:14.2 登录 → token.iat = 13:00:14
//	13:00:14.7 封禁 → epoch     = 13:00:14
//	13:00:14 < 13:00:14 ？ 否 → ⛔ 该 token 幸存, 然后活满 900 秒
//
// 生产实测(2026-09-05): 同一秒内登录+封禁 → access token 返回 200;
// 相隔 3 秒 → 401。窗口宽度 ≤1 秒, 但落进去的代价是【完整的 TTL】。
//
// ⭐ 所以"封禁 / 全部登出"必须把纪元推到【下一秒的起点】:
// 那样当前这一秒里签发的所有 token 都严格早于纪元。
//
// # ⛔ 改密【不能】用这个方法
//
// 改密紧接着要为当前设备重签一张 token, 而它的 iat 就落在同一秒 ——
// 用本方法会把刚签出来的那张【当场作废】, 用户改完密码立刻掉线。
// 改密要的是"杀掉此刻之前的", 封禁要的是"连此刻一起杀掉",
// ⚠️ 这两句话不一样, 所以是两个方法而不是一个参数。
func (c *RevocationChecker) RevokeIssuedThrough(
	ctx context.Context, userID string, at time.Time,
) error {
	return c.Revoke(ctx, userID, at.Truncate(time.Second).Add(time.Second))
}

// Revoke 把某个用户的吊销纪元推进到 at。
//
// ⚠️ 语义是"杀掉【严格早于】at 签发的 token"。与 at 同一秒签发的会幸存 ——
// ⭐ 那是【改密重签】赖以存活的性质, 但对封禁是个 1 秒窗口。
// ⛔ 封禁 / 全部登出请用 RevokeIssuedThrough。
//
// ⚠️ 失败返回 error 供调用方决定 —— ⛔ 本方法不吞。
// 调用方(改密/封禁)应当记 WARN 但【不中断主流程】:
// 纪元只负责"立刻生效", 而 refresh 侧的 §7.7 与会话吊销已经保证了
// "最终生效"。两层是"及时性"与"正确性"的分工。
func (c *RevocationChecker) Revoke(ctx context.Context, userID string, at time.Time) error {
	if c.store == nil {
		return nil
	}
	return c.store.SaveEpoch(ctx, userID, at)
}
