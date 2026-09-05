package localauth

import (
	"context"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ============ 凭证存储契约 ============

// Credential 是一个账号的口令现状。
type Credential struct {
	// Hash 是 bcrypt 哈希。⭐ 空串表示【该账号没有口令】(纯 OIDC 登录)。
	//
	// ⚠️ 空串不是"错误"也不是"未加载" —— 它是一个合法且常见的状态,
	// 而"能不能设初始口令"正是靠它判断的。
	Hash string
	// Active 账号当前是否允许登录 (宿主的 CanLogin 白名单)。
	Active bool
}

// CredentialStore 是口令的存储契约。
//
// ⚠️ SaveCredential 【必须在同一条语句里】写入 hash 与 changedAt。
//
// ⛔ 分两步写是一个静默的安全缺口: 口令变了而时间戳没变, 意味着
// §7.7 的"改密即失效"判据永远不成立 —— 所有旧会话【永久有效】,
// 而且没有任何症状(改密成功了, 用户满意, 攻击者的会话也还在)。
//
// ⚠️ 2026-09-05 的 login_count 事故正是"两张表的列混进同一条 UPDATE"
// 导致整条回滚; 这里是反过来的要求 —— 同一张表的两列【必须】一起写。
type CredentialStore interface {
	LoadCredential(ctx context.Context, userID string) (Credential, bool, error)
	SaveCredential(ctx context.Context, userID, hash string, changedAt time.Time) error
}

// AccessTokenIssuer 由宿主提供: 为一条新会话签发 access token。
//
// # ⭐ 为什么是回调而不是让模块自己签
//
// JWT 签发是 auth 服务的职责, localauth 不知道密钥、算法、claims 形状,
// ⛔ 也不该知道 —— 让它知道就等于把认证中心的一部分复制进了模块。
//
// 但"改密后重签"这件事的【顺序与失败处置】仍然属于编排, 必须留在模块里:
// 签发失败不是致命错误(用户重登即可), 而调用方很容易把它写成
// "签发失败 → 整个改密失败" —— 那会让一次成功的改密看起来失败了,
// 用户很可能拿旧口令重试, 然后困惑于它为什么不管用。
//
// ⚠️ 返回 error 时守卫【不中断】, 只是不带回新 token 并发一条 WARN。
type AccessTokenIssuer func(ctx context.Context, userID, sessionID string) (token string, expiresAt time.Time, err error)

// ============ 改密守卫 ============

// PasswordGuard 编排"改口令"这件事的完整流程 (§18 ⑤⑥)。
//
// # ⭐ 为什么编排在模块里而不是在应用里
//
// 改密不是一次写入, 是一个【有顺序要求】的序列:
//
//	验旧口令 → 评估新口令 → 写(hash + changedAt) → 吊销全部 → 重签当前设备
//
// 顺序错了会产生没有症状的缺口。举两个:
//   - 先写 hash 后验旧口令 → 任何人都能改任何人的口令
//   - 先重签后吊销 → 刚签出来的那对立刻被自己吊销, 用户当场掉线
//
// ⛔ 把顺序交给每个应用各写一遍, 就是同一条规则的 N 份摹本。
type PasswordGuard struct {
	creds    CredentialStore
	sessions *SessionGuard
	policy   *PasswordPolicy
	verifier *Verifier
	cost     int
	minLen   int
	audit    AuditHook
	now      func() time.Time
	issuer   AccessTokenIssuer
}

// ChangeRequest 是一次改密/设密请求。
type ChangeRequest struct {
	UserID string

	// OldPassword 旧口令。
	//
	// ⚠️ 【首次设密时为空】, 而这不是"可以省略"的意思 ——
	// 是否允许为空由 Credential.Hash 是否为空【单独判定】,
	// ⛔ 不由调用方传不传决定。否则调用方漏传就等于跳过了旧口令校验。
	OldPassword string

	NewPassword string

	// CurrentSessionID 发起本次改密的会话 (来自 access token 的 sid claim)。
	//
	// ⭐ 用于改密后【立即为当前设备重签】。为空则不重签, 用户需重新登录。
	CurrentSessionID string

	DeviceInfo string
	ClientIP   string
}

// ChangeOutcome 是改密结果。
type ChangeOutcome struct {
	// Advice 新口令的泄露评估。⚠️ 必须一路带到前端 —— geass 采用
	// 警告放行, 前端要据此提示用户。⛔ 不要在后端丢掉它。
	Advice PasswordAdvice

	// RevokedCount 被吊销的会话数 (含当前那条)。
	RevokedCount int

	// NewRefreshToken / NewSession 是为当前设备重签的新会话。
	//
	// ⚠️ 为空表示【没有重签】(没传 CurrentSessionID, 或重签失败) ——
	// 此时用户需要重新登录, 调用方应据此调整返回给前端的提示。
	NewRefreshToken string
	NewSession      SessionRecord

	// NewAccessToken / NewAccessExpiresAt 仅在配了 AccessTokenIssuer 且
	// 签发成功时非空。⚠️ 为空【不等于】改密失败。
	NewAccessToken     string
	NewAccessExpiresAt time.Time
}

// PasswordGuardOption 配置 PasswordGuard。
type PasswordGuardOption func(*PasswordGuard)

// WithPasswordCost 设置 bcrypt cost (测试用低 cost)。
func WithPasswordCost(c int) PasswordGuardOption {
	return func(g *PasswordGuard) { g.cost = c }
}

// WithPasswordMinLen 设置新口令最短长度。
func WithPasswordMinLen(n int) PasswordGuardOption {
	return func(g *PasswordGuard) { g.minLen = n }
}

// WithAccessTokenIssuer 提供 access token 签发能力。
//
// ⚠️ 不传 = 改密后只返回新 refresh token, 不返回 access token。
// 前端仍需用 refresh 换一次 —— 可用但多一次往返。
func WithAccessTokenIssuer(f AccessTokenIssuer) PasswordGuardOption {
	return func(g *PasswordGuard) { g.issuer = f }
}

// WithPasswordAudit 接住审计事件。
func WithPasswordAudit(h AuditHook) PasswordGuardOption {
	return func(g *PasswordGuard) { g.audit = h }
}

// WithPasswordClock 换时钟 (测试用)。
func WithPasswordClock(f func() time.Time) PasswordGuardOption {
	return func(g *PasswordGuard) { g.now = f }
}

// NewPasswordGuard 构造改密守卫。
//
// ⚠️ creds / sessions / policy 三者【都是必填】:
//   - 缺 sessions → 改密不吊销会话, §7.3 静默失效
//   - 缺 policy → 泄露检查静默消失
//
// ⛔ 不给默认值 —— 这两种失效都没有症状, 而"构造时报错"是有症状的。
func NewPasswordGuard(
	creds CredentialStore,
	sessions *SessionGuard,
	policy *PasswordPolicy,
	opts ...PasswordGuardOption,
) (*PasswordGuard, error) {
	g := &PasswordGuard{
		creds:    creds,
		sessions: sessions,
		policy:   policy,
		cost:     bcrypt.DefaultCost,
		minLen:   DefaultMinPasswordLen,
		now:      time.Now,
	}
	for _, o := range opts {
		o(g)
	}
	if creds == nil {
		return nil, newErr(CodeMisconfigured, "必须传入 CredentialStore")
	}
	if sessions == nil {
		return nil, newErr(CodeMisconfigured, "必须传入 SessionGuard (改密要吊销会话, §7.3)")
	}
	if policy == nil {
		return nil, newErr(CodeMisconfigured, "必须传入 PasswordPolicy (泄露检查, §14)")
	}
	v, err := NewVerifier(g.cost)
	if err != nil {
		return nil, err
	}
	g.verifier = v
	return g, nil
}

// Change 改口令 (⑤) 或首次设密 (⑥)。
//
// # 编排顺序 (⛔ 不可调换)
//
//	① 取凭证        —— 账号不存在 / 存储故障 → 拒绝, 无副作用
//	② 账号状态      —— 不可登录的账号不许改口令
//	③ 旧口令        —— 有 hash ⇒ 必须验; 无 hash ⇒ 这是首次设密, 不验
//	④ 新口令长度    —— 本地规则, 先于外网检查(省一次往返)
//	⑤ 泄露评估      —— 警告放行, 不中断 (用户裁决)
//	⑥ 写 hash + changedAt (同一条语句)
//	⑦ 吊销全部会话
//	⑧ 为当前设备重签
//
// # ⭐ ⑥ 与 ⑦ 是"正确性"与"及时性"的分层
//
// ⑥ 一旦落库, 所有旧会话在【下一次 refresh】时必然被 §7.7 拦下 ——
// 这个保证不依赖 ⑦。⑦ 只是让它们【立刻】失效。
//
// ⚠️ 所以 ⑦ 失败【不回滚 ⑥】: 口令已经变了, 回滚会让用户以为改密失败
// 而实际上已经改了 —— 那是更坏的状态。⑦ 失败记 ERROR 并继续。
//
// # ⭐ 为什么 ⑦ 要吊销【全部】而不是"除当前之外"
//
// §7.7 的判据是 session.CreatedAt < PasswordChangedAt。当前会话的
// CreatedAt 必然早于改密时刻, 所以哪怕这里刻意跳过它,
// ⛔ 它也会在下一次 refresh 时被 §7.7 干掉 —— 用户几分钟后莫名掉线,
// 而日志显示的是"会话建立于改密之前", 看起来完全正常。
//
// 出路是 ⑧: 吊销全部之后【立即重签】。语义诚实 —— 所有旧凭证失效,
// 而当前设备刚证明了自己知道旧口令, 所以它重新认证过了。
func (g *PasswordGuard) Change(ctx context.Context, req ChangeRequest) (ChangeOutcome, error) {
	if req.UserID == "" {
		return ChangeOutcome{}, newErr(CodeMisconfigured, "缺少 user_id")
	}

	// ① 取凭证
	cred, found, err := g.creds.LoadCredential(ctx, req.UserID)
	if err != nil {
		return ChangeOutcome{}, wrapErr(CodeLookupUnavailable, "读取凭证失败", err)
	}
	if !found {
		// ⚠️ 与"旧口令错误"返回同一个错误码 —— ⛔ 不泄漏账号是否存在。
		return ChangeOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
	}

	// ② 账号状态
	if !cred.Active {
		return ChangeOutcome{}, newErr(CodeInvalidCredentials, "账号状态不允许该操作")
	}

	// ③ 旧口令
	//
	// ⭐ 判据是【库里有没有 hash】, ⛔ 不是"调用方传没传 OldPassword"。
	// 后者意味着调用方漏传就跳过了校验 —— 一个纯粹由调用方失误
	// 造成的鉴权绕过。
	isInitialSet := cred.Hash == ""
	if !isInitialSet {
		if req.OldPassword == "" {
			return ChangeOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
		}
		// ⚠️ 走 Verifier 而不是直接 bcrypt.Compare —— 那里有定时安全
		// 所需的三条性质(唯一调用点/错误坍缩为 bool/每条路径都真干活)。
		if !g.verifier.Verify(cred.Hash, req.OldPassword) {
			return ChangeOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
		}
	}

	// ④ 长度 —— 本地规则先行, 省一次外网往返
	// ⚠️ 长度校验与哈希【共用 hashWithCost 里那一份规则】——
	// 在这里先判一次只是为了【省掉一次外网往返】(泄露检查在 ⑤),
	// ⛔ 不是第二份规则。真正的把关在 ⑥。
	if len(req.NewPassword) < g.minLen || len(req.NewPassword) > MaxPasswordBytes {
		// 走一次 hashWithCost 拿到精确的错误码与文案, ⛔ 不自己拼。
		if _, err := hashWithCost(req.NewPassword, bcrypt.MinCost, g.minLen); err != nil {
			return ChangeOutcome{}, err
		}
	}

	// ⑤ 泄露评估 —— ⭐ 警告放行, 不中断 (用户裁决 2026-09-05)
	advice := g.policy.EvaluateNewPassword(ctx, req.NewPassword)

	// ⑥ 写入 (hash + changedAt 必须同一条语句, 见 CredentialStore 注释)
	hash, err := hashWithCost(req.NewPassword, g.cost, g.minLen)
	if err != nil {
		return ChangeOutcome{}, err
	}
	changedAt := g.now()
	if err := g.creds.SaveCredential(ctx, req.UserID, hash, changedAt); err != nil {
		// 无副作用: 单条语句要么全成要么全不成。
		return ChangeOutcome{}, wrapErr(CodeLookupUnavailable, "保存新口令失败", err)
	}

	kind := EventPasswordChanged
	if isInitialSet {
		kind = EventPasswordInitialized
	}

	// ⑦ 吊销全部 —— ⚠️ 失败不回滚 ⑥
	out := ChangeOutcome{Advice: advice}
	n, revErr := g.sessions.RevokeAll(ctx, req.UserID)
	out.RevokedCount = n
	if revErr != nil {
		// ⛔ 这条必须是 ERROR 级: 口令已改但旧会话还活着,
		// 需要人介入确认 §7.7 是否兜住了(它应该兜住, 但"应该"不等于"确认")。
		g.emitPassword(ctx, EventPasswordRevokeFailed, req.UserID, changedAt,
			"口令已更新但吊销会话失败: "+revErr.Error())
	}

	// ⑧ 重签当前设备
	if req.CurrentSessionID != "" {
		tok, rec, issueErr := g.sessions.Issue(ctx, SessionRecord{
			UserID:     req.UserID,
			DeviceInfo: req.DeviceInfo,
			ClientIP:   req.ClientIP,
		})
		if issueErr != nil {
			// ⚠️ 不是致命错误: 口令改好了, 只是用户得重新登录。
			// 调用方据 NewRefreshToken 为空判断并调整前端提示。
			g.emitPassword(ctx, EventPasswordReissueFailed, req.UserID, changedAt,
				issueErr.Error())
		} else {
			out.NewRefreshToken, out.NewSession = tok, rec
			// ⭐ 顺带签一张 access token, 让前端【零往返】继续用。
			// ⚠️ 签发失败不中断 —— 前端拿 refresh 换一次即可。
			if g.issuer != nil {
				at, exp, atErr := g.issuer(ctx, req.UserID, rec.ID)
				if atErr != nil {
					g.emitPassword(ctx, EventPasswordReissueFailed, req.UserID, changedAt,
						"refresh 已重签但 access token 签发失败: "+atErr.Error())
				} else {
					out.NewAccessToken, out.NewAccessExpiresAt = at, exp
				}
			}
		}
	}

	g.emitPassword(ctx, kind, req.UserID, changedAt, "已吊销 "+itoa(n)+" 条会话")
	return out, nil
}

func (g *PasswordGuard) emitPassword(
	ctx context.Context, kind EventKind, userID string, at time.Time, detail string,
) {
	if g.audit == nil {
		return
	}
	g.audit(ctx, AuditEvent{Kind: kind, UserID: userID, At: at, Detail: detail})
}
