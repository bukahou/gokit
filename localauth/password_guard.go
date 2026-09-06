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
type AccessTokenIssuer func(ctx context.Context, userID, sessionID string, issuedAt time.Time) (token string, expiresAt time.Time, err error)

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
	// revoker 推进吊销纪元, 让【已签发的 access token】立即失效。
	//
	// ⚠️ 没有它, 改密只对 refresh 侧立即生效(§7.7), 而旧的 access token
	// 仍能用满 TTL(默认 900 秒)。⛔ 那意味着"改密踢掉攻击者"这件事
	// 有一个 15 分钟的窗口 —— 而攻击者恰恰在那个窗口里最活跃。
	revoker *RevocationChecker
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
	// Advice 新口令的泄露评估。⚠️ 必须一路带到前端 —— 宿主可采用
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

// WithPasswordRevoker 让改密同时推进吊销纪元 (批次三 D1)。
//
// ⚠️ 不传 = 改密只对 refresh 侧立即生效, access token 要等 TTL 到期。
func WithPasswordRevoker(r *RevocationChecker) PasswordGuardOption {
	return func(g *PasswordGuard) { g.revoker = r }
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

	// ④⑤⑥ 长度 → 泄露评估 → 哈希 → 写 hash + changedAt (与 ResetWithProof 共用)
	advice, changedAt, err := g.applyNewPassword(ctx, req.UserID, req.NewPassword)
	if err != nil {
		return ChangeOutcome{}, err
	}

	kind := EventPasswordChanged
	if isInitialSet {
		kind = EventPasswordInitialized
	}

	// ⑦ 吊销全部 —— ⚠️ 失败不回滚 ⑥
	out := ChangeOutcome{Advice: advice}
	out.RevokedCount = g.revokeAll(ctx, req.UserID, changedAt)

	// ⑦.5 ⭐ 推进吊销纪元 —— 让已签发的 access token 立即失效。
	//
	// # ⭐ 纪元的值必须是 changedAt, 不是"写入的那一刻"
	//
	// changedAt 在 ⑥ 之前就取好了, 而 ⑧ 重签出的 access token 其 iat 必然 >= changedAt ——
	// ⛔ 所以新 token 不会被自己作废, 且这与 ⑦.5 和 ⑧ 谁先谁后【无关】。
	// ⚠️⚠️ 2026-09-06 (v0.2.0) 修正: 旧写法 Revoke(changedAt) 把纪元设在 changedAt 那一秒,
	// 而判定是 `iat < epoch`(相等不算失效) —— 于是与 changedAt【同一秒签发】的其它设备 token
	// 满足 iat == epoch 而幸存, 且幸存到 access TTL 结束(生产 900 秒), 不是一秒。
	// 生产实测扫 14 个登录相位命中 1 次。⛔ 但只把纪元换成 Through 会连刚重签的 token 一起作废,
	// ✅ 所以重签的 iat 也定到同一个 epoch(见下方 reissueAt): iat == epoch 靠"相等不算失效"幸存,
	//    其它设备 iat ≤ changedAt < epoch 全部失效。两个目标同时成立, 窗口关闭。
	// 顺序上仍放在重签之前: 若进程在两步之间崩溃, "已吊销但没重签"好过"已重签但没吊销"。
	reissueAt := nextSecond(changedAt)
	if g.revoker != nil {
		if err := g.revoker.RevokeIssuedThrough(ctx, req.UserID, changedAt); err != nil {
			g.emitPassword(ctx, EventRevocationWriteFailed, req.UserID, changedAt, err.Error())
		}
	}

	// ⑧ 重签当前设备
	if req.CurrentSessionID != "" {
		re, issueErr := g.reissuer().Reissue(ctx, req.UserID, req.DeviceInfo, req.ClientIP, reissueAt)
		if issueErr != nil {
			// ⚠️ 不是致命错误: 口令改好了, 只是用户得重新登录。
			g.emitPassword(ctx, EventPasswordReissueFailed, req.UserID, changedAt, issueErr.Error())
		} else {
			out.NewRefreshToken, out.NewSession = re.RefreshToken, re.Session
			out.NewAccessToken, out.NewAccessExpiresAt = re.AccessToken, re.AccessExpiresAt
			if re.AccessErr != nil {
				g.emitPassword(ctx, EventPasswordReissueFailed, req.UserID, changedAt,
					"refresh 已重签但 access token 签发失败: "+re.AccessErr.Error())
			}
		}
	}

	g.emitPassword(ctx, kind, req.UserID, changedAt, "已吊销 "+itoa(out.RevokedCount)+" 条会话")
	return out, nil
}

// applyNewPassword 是 Change 与 ResetWithProof 共用的核心: 长度 → 泄露评估 → 哈希 → 落库。
//
// ⚠️ hash 与 changedAt 由 CredentialStore 在同一条语句里写 —— 见其契约注释。
func (g *PasswordGuard) applyNewPassword(ctx context.Context, userID, newPassword string) (PasswordAdvice, time.Time, error) {
	// ⚠️ 长度校验与哈希【共用 hashWithCost 里那一份规则】—— 这里先判一次只是为了
	// 省掉一次外网往返 (泄露检查), ⛔ 不是第二份规则。真正的把关在下面的哈希。
	if len(newPassword) < g.minLen || len(newPassword) > MaxPasswordBytes {
		if _, err := hashWithCost(newPassword, bcrypt.MinCost, g.minLen); err != nil {
			return PasswordAdvice{}, time.Time{}, err
		}
	}
	advice := g.policy.EvaluateNewPassword(ctx, newPassword) // ⭐ 警告放行 (用户裁决)
	hash, err := hashWithCost(newPassword, g.cost, g.minLen)
	if err != nil {
		return PasswordAdvice{}, time.Time{}, err
	}
	changedAt := g.now()
	if err := g.creds.SaveCredential(ctx, userID, hash, changedAt); err != nil {
		return PasswordAdvice{}, time.Time{}, wrapErr(CodeLookupUnavailable, "保存新口令失败", err)
	}
	return advice, changedAt, nil
}

// revokeAll 吊销全部会话, 失败只留痕 (口令已改, 回滚更糟)。
func (g *PasswordGuard) revokeAll(ctx context.Context, userID string, at time.Time) int {
	n, err := g.sessions.RevokeAll(ctx, userID)
	if err != nil {
		// ⛔ ERROR 级: 口令已改但旧会话还活着, 需要人确认 §7.7 是否兜住了。
		g.emitPassword(ctx, EventPasswordRevokeFailed, userID, at, "口令已更新但吊销会话失败: "+err.Error())
	}
	return n
}

func (g *PasswordGuard) reissuer() *DeviceReissuer {
	return NewDeviceReissuer(g.sessions, g.issuer)
}

// ResetRequest 凭验证码重置口令 (找回密码, §18 ④)。
type ResetRequest struct {
	UserID      string
	NewPassword string
}

// ResetWithProof 凭已校验的验证码重置口令 —— 【不验旧口令】。
//
// # ⭐ 跳过旧口令是凭 proof, ⛔ 不是凭 OldPassword 为空
//
// Change 里 "OldPassword 为空可通过" 的判据是【库里没有 hash】(首次设密)。
// 找回是另一种合法的跳过, 依据是"用户刚证明了自己拥有已验证的恢复地址"——
// 那个证明就是 VerifiedProof, 它只能从 VerificationGuard.Verify 拿到。
// 两种跳过必须是两个方法: 混在一起, 任何一处的判据放松都会波及另一处。
//
// # 与 Change 的差异
//
//	· 不验旧口令 (凭 proof)
//	· 纯 OIDC 账号 (无 hash) 拒绝 —— 找回不能给账号【凭空装上】口令, 那是 ⑥ 的事且要登录态
//	· 纪元用 RevokeIssuedThrough —— 没有要保住的 token (用户没有会话), 连此刻一起杀
//	· 不重签 —— 让用户用新口令登录
func (g *PasswordGuard) ResetWithProof(ctx context.Context, req ResetRequest, proof VerifiedProof) (ChangeOutcome, error) {
	if !proof.valid() || proof.Purpose != PurposeRecoverPassword || proof.Subject != req.UserID {
		// ⛔ 一个不匹配的 proof 与没有 proof 是一回事。
		return ChangeOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
	}
	cred, found, err := g.creds.LoadCredential(ctx, req.UserID)
	if err != nil {
		return ChangeOutcome{}, wrapErr(CodeLookupUnavailable, "读取凭证失败", err)
	}
	if !found || !cred.Active || cred.Hash == "" {
		return ChangeOutcome{}, newErr(CodeInvalidCredentials, "凭据无效")
	}
	advice, changedAt, err := g.applyNewPassword(ctx, req.UserID, req.NewPassword)
	if err != nil {
		return ChangeOutcome{}, err
	}
	out := ChangeOutcome{Advice: advice}
	out.RevokedCount = g.revokeAll(ctx, req.UserID, changedAt)
	if g.revoker != nil {
		if err := g.revoker.RevokeIssuedThrough(ctx, req.UserID, changedAt); err != nil {
			g.emitPassword(ctx, EventRevocationWriteFailed, req.UserID, changedAt, err.Error())
		}
	}
	g.emitPassword(ctx, EventPasswordReset, req.UserID, changedAt, "已吊销 "+itoa(out.RevokedCount)+" 条会话")
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
