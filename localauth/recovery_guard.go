package localauth

import (
	"context"
	"time"
)

// ============ 找回密码 (§18 ④) ============

// RecoveryGuard 编排「申请找回 → 验码 → 重置口令」。
//
// # 18.3 五条约束在这里的落点
//
//	18.3.1 投递目标必须是本应用验证过的地址  → resolver 只认 email_verified=1
//	18.3.2 不实现 = 安全                      → 联邦账号 email 为 NULL, 自然落入"查不到", 不需要特判
//	18.3.3 upstream_email 永不提升            → 模块根本不知道有这个字段
//	18.3.4 安全出口划在「验证」不在「触碰」   → 见 EmailChangeGuard
//	18.3.5 认证路径禁止 COALESCE              → resolver 的实现里钉了测试
type RecoveryGuard struct {
	verif     *VerificationGuard
	resolver  RecoveryAddressResolver
	passwords *PasswordGuard
	audit     AuditHook
	now       func() time.Time
}

// RecoveryOption 配置 RecoveryGuard。
type RecoveryOption func(*RecoveryGuard)

// WithRecoveryAudit 接住审计事件。
func WithRecoveryAudit(h AuditHook) RecoveryOption {
	return func(g *RecoveryGuard) { g.audit = h }
}

// NewRecoveryGuard 构造。三个依赖都必填。
func NewRecoveryGuard(
	verif *VerificationGuard, resolver RecoveryAddressResolver, passwords *PasswordGuard,
	opts ...RecoveryOption,
) (*RecoveryGuard, error) {
	g := &RecoveryGuard{verif: verif, resolver: resolver, passwords: passwords, now: time.Now}
	for _, o := range opts {
		o(g)
	}
	switch {
	case verif == nil:
		return nil, newErr(CodeMisconfigured, "必须传入 VerificationGuard")
	case resolver == nil:
		return nil, newErr(CodeMisconfigured, "必须传入 RecoveryAddressResolver (18.3.1)")
	case passwords == nil:
		return nil, newErr(CodeMisconfigured, "必须传入 PasswordGuard (找回成功 = 改密)")
	}
	return g, nil
}

// Request 申请找回。
//
// # ⭐ 对外永远成功 (除限流)
//
// 用户不存在 / 存在但无已验证地址 / 存在且已发码 —— 三者返回完全相同,
// 且请求路径上只做【一次索引查找】, 生成与投递整个异步。
// 响应层与时序层都不泄漏"这个邮箱存在吗"。
//
// ⚠️ 限流拒绝是唯一的非成功返回。它按地址计数, 与存在与否无关, 所以不泄漏。
func (g *RecoveryGuard) Request(ctx context.Context, address, clientIP string) error {
	if err := g.verif.CheckSendAllowed(ctx, PurposeRecoverPassword, address, clientIP); err != nil {
		return err
	}
	userID, found, err := g.resolver.UserByVerifiedAddress(ctx, address)
	if err != nil {
		// ⚠️ 存储故障也返回成功 —— 报错会让"故障"与"不存在"可区分。
		// 但必须留痕, 否则找回功能可以坏三个月没人知道。
		g.emit(ctx, EventVerificationSendFailed, "", "查找恢复地址失败: "+err.Error())
		return nil
	}
	if !found {
		return nil // ⭐ 不存在 / 未验证 / 联邦账号: 同一条路
	}
	g.verif.SendAsync(ctx, address, func(bg context.Context) error {
		// payload 记下【码发往的地址】—— 完成时要复查它仍是当前已验证地址
		return g.verif.IssueAndSend(bg, PurposeRecoverPassword, userID, address, address)
	})
	return nil
}

// CompleteRequest 完成找回。
type CompleteRequest struct {
	Address     string
	Code        string
	NewPassword string
}

// Complete 验码并重置口令。
//
//	① 按地址找用户 —— 查不到与码错同一个错误
//	② 验码 (不消费)
//	③ ⭐ 复查: 码发往的地址 == 此刻的已验证地址。不等 → 拒绝
//	   (请求与完成之间地址被改了 —— 正是 实测到的接管链的形状)
//	④ 凭 proof 重置 (跳过旧口令是【凭 proof】, ⛔ 不是凭 OldPassword 为空)
//	   吊销全部, 不重签 (用户没有会话, 让他用新口令登录)
//	⑤ 消费 —— 失败记 WARN 不回滚 (口令已改; 码在 TTL 内再用也只是再改一次)
func (g *RecoveryGuard) Complete(ctx context.Context, req CompleteRequest) (PasswordAdvice, error) {
	invalid := newErr(CodeInvalidCode, "验证码无效或已过期")

	userID, found, err := g.resolver.UserByVerifiedAddress(ctx, req.Address)
	if err != nil {
		return PasswordAdvice{}, wrapErr(CodeLookupUnavailable, "查找恢复地址失败", err)
	}
	if !found {
		return PasswordAdvice{}, invalid
	}
	proof, err := g.verif.Verify(ctx, PurposeRecoverPassword, userID, req.Code)
	if err != nil {
		return PasswordAdvice{}, err
	}
	current, ok, err := g.resolver.VerifiedRecoveryAddress(ctx, userID)
	if err != nil {
		return PasswordAdvice{}, wrapErr(CodeLookupUnavailable, "复查恢复地址失败", err)
	}
	if !ok || current != proof.Payload {
		g.emit(ctx, EventRecoveryAddressChanged, userID, "码发往 "+proof.Payload)
		return PasswordAdvice{}, invalid
	}
	out, err := g.passwords.ResetWithProof(ctx, ResetRequest{UserID: userID, NewPassword: req.NewPassword}, proof)
	if err != nil {
		return PasswordAdvice{}, err
	}
	if err := g.verif.Consume(ctx, proof); err != nil {
		g.emit(ctx, EventVerificationConsumeFailed, userID, err.Error())
	}
	return out.Advice, nil
}

func (g *RecoveryGuard) emit(ctx context.Context, kind EventKind, userID, detail string) {
	if g.audit == nil {
		return
	}
	g.audit(ctx, AuditEvent{Kind: kind, UserID: userID, At: g.now(), Detail: detail})
}
