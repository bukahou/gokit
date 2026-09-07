package localauth

import (
	"context"
	"time"
)

// ============ 改邮箱 (§18 ⑩) ============

// EmailChanger 是改邮箱的存储契约。
type EmailChanger interface {
	EmailTaken(ctx context.Context, email string) (bool, error)
	// ChangeVerifiedEmail 在【同一条语句】里写 email = newEmail, email_verified = 1,
	// 返回改之前的地址 (可能为空: 联邦账号首次设邮箱)。
	// 唯一冲突 → Code 为 CodeEmailTaken 的错误。
	ChangeVerifiedEmail(ctx context.Context, userID, newEmail string) (oldEmail string, err error)
}

// EmailChangeGuard 编排「申请改邮箱 → 验证新地址 → 写入 → 通知旧地址 → 吊销 → 重签」。
//
// # 18.5.1 三件缺一不可
//
//	① 验证新邮箱  → Request 只发码不改库; Confirm 里验证与写入是同一步
//	② 通知旧邮箱  → Confirm 里异步投递 NoticeEmailChanged, 失败可计数
//	③ 触发吊销    → Confirm 里吊销全部 + 纪元 + 重签当前设备 (用户裁决 D3)
//
// # 18.3.4 安全出口划在「验证」不在「触碰」
//
// Request 【不改库】: email / email_verified 纹丝不动, 只给新地址发码。
// 实测过的接管链正是从"资料接口直接写 email"开始的 ——
// 改邮箱的唯一入口就是这里, 而这里的写入发生在验证之后。
type EmailChangeGuard struct {
	verif    *VerificationGuard
	emails   EmailChanger
	sessions *SessionGuard
	revoker  *RevocationChecker
	reissue  *DeviceReissuer
	audit    AuditHook
	now      func() time.Time
}

// EmailChangeOption 配置 EmailChangeGuard。
type EmailChangeOption func(*EmailChangeGuard)

// WithEmailChangeRevoker 接吊销纪元 (可选; 缺则 access token 要等 TTL)。
func WithEmailChangeRevoker(r *RevocationChecker) EmailChangeOption {
	return func(g *EmailChangeGuard) { g.revoker = r }
}

// WithEmailChangeReissuer 接重签器 (可选; 缺则用户需重新登录)。
func WithEmailChangeReissuer(r *DeviceReissuer) EmailChangeOption {
	return func(g *EmailChangeGuard) { g.reissue = r }
}

// WithEmailChangeClock 换时钟 (测试用)。
func WithEmailChangeClock(f func() time.Time) EmailChangeOption {
	return func(g *EmailChangeGuard) { g.now = f }
}

// WithEmailChangeAudit 接住审计事件。
func WithEmailChangeAudit(h AuditHook) EmailChangeOption {
	return func(g *EmailChangeGuard) { g.audit = h }
}

// NewEmailChangeGuard 构造。verif / emails / sessions 必填 —— 缺 sessions 就没有 18.5.1 的 ③。
func NewEmailChangeGuard(
	verif *VerificationGuard, emails EmailChanger, sessions *SessionGuard,
	opts ...EmailChangeOption,
) (*EmailChangeGuard, error) {
	g := &EmailChangeGuard{verif: verif, emails: emails, sessions: sessions, now: time.Now}
	for _, o := range opts {
		o(g)
	}
	switch {
	case verif == nil:
		return nil, newErr(CodeMisconfigured, "必须传入 VerificationGuard")
	case emails == nil:
		return nil, newErr(CodeMisconfigured, "必须传入 EmailChanger")
	case sessions == nil:
		return nil, newErr(CodeMisconfigured, "必须传入 SessionGuard (18.5.1 改邮箱必须触发吊销)")
	}
	return g, nil
}

// EmailChangeRequest 申请改邮箱。
type EmailChangeRequest struct {
	UserID   string
	NewEmail string
	ClientIP string
}

// Request 给【新地址】发码。⛔ 不改库。
//
// 新地址已被占用 → 对请求方仍然成功 (防枚举), 但给那个地址的主人发一封通知。
func (g *EmailChangeGuard) Request(ctx context.Context, req EmailChangeRequest) error {
	if err := g.verif.CheckSendAllowed(ctx, PurposeChangeEmail, req.NewEmail, req.ClientIP); err != nil {
		return err
	}
	taken, err := g.emails.EmailTaken(ctx, req.NewEmail)
	if err != nil {
		return wrapErr(CodeLookupUnavailable, "查询邮箱失败", err)
	}
	if taken {
		g.verif.SendAsync(ctx, req.NewEmail, func(bg context.Context) error {
			return g.verif.sender.SendVerification(bg, VerificationMessage{
				To: req.NewEmail, Purpose: PurposeChangeEmail, Notice: NoticeExistingAccount,
			})
		})
		return nil
	}
	g.verif.SendAsync(ctx, req.NewEmail, func(bg context.Context) error {
		// payload = 新地址: 确认时从 proof 取, ⛔ 不让客户端在确认请求里再报一次地址
		return g.verif.IssueAndSend(bg, PurposeChangeEmail, req.UserID, req.NewEmail, req.NewEmail)
	})
	return nil
}

// EmailChangeConfirm 确认改邮箱。
type EmailChangeConfirm struct {
	UserID           string
	Code             string
	CurrentSessionID string
	DeviceInfo       string
	ClientIP         string
}

// EmailChangeOutcome 改邮箱结果。
type EmailChangeOutcome struct {
	OldEmail     string
	NewEmail     string
	RevokedCount int
	Reissued     Reissued // ⚠️ RefreshToken 为空 = 没能重签, 用户需重新登录
}

// Confirm 验码并写入。
//
//	① 验码 (不消费)
//	② 一条 UPDATE: email = 新地址, email_verified = 1  ← ⭐ 验证与写入同一步
//	   唯一冲突 (窗口期被人占了) → 拒绝, 码未消费
//	③ 消费
//	④ 通知旧地址 (异步, 失败可计数)
//	   ⭐ 这是唯一让受害者知道"我的恢复地址被改了"的渠道, 所以失败必须可见
//	⑤ 吊销全部 + 纪元 + 重签当前设备
//
// # ⭐ 纪元推到下一秒起点, 重签 iat 也定在那一秒 (v0.2.0)
//
// 与改密完全同一处理, 理由见 password_guard.go 里同名注释: 纪元若只推到 changedAt 那一秒,
// 与它同秒签发的其它设备 token 会幸存到 TTL 结束; 而只推纪元不动重签 iat, 刚重签的
// token 又会被自己作废。两者必须一起改。
func (g *EmailChangeGuard) Confirm(ctx context.Context, req EmailChangeConfirm) (EmailChangeOutcome, error) {
	proof, err := g.verif.Verify(ctx, PurposeChangeEmail, req.UserID, req.Code)
	if err != nil {
		return EmailChangeOutcome{}, err
	}
	old, err := g.emails.ChangeVerifiedEmail(ctx, req.UserID, proof.Payload)
	if err != nil {
		return EmailChangeOutcome{}, err
	}
	changedAt := g.now()
	out := EmailChangeOutcome{OldEmail: old, NewEmail: proof.Payload}

	if err := g.verif.Consume(ctx, proof); err != nil {
		g.emit(ctx, EventVerificationConsumeFailed, req.UserID, err.Error())
	}

	if old != "" && old != proof.Payload {
		g.verif.SendAsync(ctx, old, func(bg context.Context) error {
			if err := g.verif.sender.SendVerification(bg, VerificationMessage{
				To: old, Purpose: PurposeChangeEmail, Notice: NoticeEmailChanged, NewAddress: proof.Payload,
			}); err != nil {
				g.emit(bg, EventEmailNotifyFailed, req.UserID, "旧地址 "+old+": "+err.Error())
				return nil // 已单独留痕, 不再重复记 send_failed
			}
			return nil
		})
	}

	n, revErr := g.sessions.RevokeAll(ctx, req.UserID)
	out.RevokedCount = n
	if revErr != nil {
		g.emit(ctx, EventPasswordRevokeFailed, req.UserID, "邮箱已改但吊销会话失败: "+revErr.Error())
	}
	if g.revoker != nil {
		if err := g.revoker.RevokeIssuedThrough(ctx, req.UserID, changedAt); err != nil {
			g.emit(ctx, EventRevocationWriteFailed, req.UserID, err.Error())
		}
	}
	if g.reissue != nil && req.CurrentSessionID != "" {
		re, err := g.reissue.Reissue(ctx, req.UserID, req.DeviceInfo, req.ClientIP, nextSecond(changedAt))
		if err != nil {
			g.emit(ctx, EventPasswordReissueFailed, req.UserID, err.Error())
		} else {
			if re.AccessErr != nil {
				g.emit(ctx, EventPasswordReissueFailed, req.UserID, "refresh 已重签但 access 签发失败: "+re.AccessErr.Error())
			}
			out.Reissued = re
		}
	}
	g.emit(ctx, EventEmailChanged, req.UserID, old+" → "+proof.Payload+", 已吊销 "+itoa(n)+" 条会话")
	return out, nil
}

func (g *EmailChangeGuard) emit(ctx context.Context, kind EventKind, userID, detail string) {
	if g.audit == nil {
		return
	}
	g.audit(ctx, AuditEvent{Kind: kind, UserID: userID, At: g.now(), Detail: detail})
}
