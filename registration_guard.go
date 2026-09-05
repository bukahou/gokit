package localauth

import (
	"context"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ============ 注册编排 (§18 ③) ============

// NewAccount 是要建的账号。⛔ 不含权限 —— 注册即"有 user_id 无权限"。
type NewAccount struct {
	Username     string
	Email        string // 已由验证码证明归属 → 宿主写入时 email_verified = true
	PasswordHash string
	DisplayName  string
}

// AccountCreator 是建号的存储契约。
//
// ⚠️ CreateAccount 撞唯一索引时必须返回 Code 为 CodeUsernameTaken / CodeEmailTaken 的错误
// (用 newErr 构造), 而不是原样上抛 —— 一次正常的并发撞车不该被报成 500。
type AccountCreator interface {
	UsernameTaken(ctx context.Context, username string) (bool, error)
	EmailTaken(ctx context.Context, email string) (bool, error)
	CreateAccount(ctx context.Context, acct NewAccount) (userID string, err error)
}

// RegistrationGuard 编排「发码 → 验码 → 建号」。
type RegistrationGuard struct {
	verif     *VerificationGuard
	accounts  AccountCreator
	admission Admission
	policy    *PasswordPolicy
	cost      int
	minLen    int
	audit     AuditHook
	now       func() time.Time
}

// RegistrationOption 配置 RegistrationGuard。
type RegistrationOption func(*RegistrationGuard)

// WithRegistrationCost bcrypt cost (测试用低 cost)。
func WithRegistrationCost(c int) RegistrationOption {
	return func(g *RegistrationGuard) { g.cost = c }
}

// WithRegistrationAudit 接住审计事件。
func WithRegistrationAudit(h AuditHook) RegistrationOption {
	return func(g *RegistrationGuard) { g.audit = h }
}

// NewRegistrationGuard 构造。四个依赖都必填 —— 缺任何一个都是一种静默失效:
// 缺 admission 谁都能注册, 缺 policy 泄露检查消失。
func NewRegistrationGuard(
	verif *VerificationGuard, accounts AccountCreator, admission Admission, policy *PasswordPolicy,
	opts ...RegistrationOption,
) (*RegistrationGuard, error) {
	g := &RegistrationGuard{
		verif: verif, accounts: accounts, admission: admission, policy: policy,
		cost: bcrypt.DefaultCost, minLen: DefaultMinPasswordLen, now: time.Now,
	}
	for _, o := range opts {
		o(g)
	}
	switch {
	case verif == nil:
		return nil, newErr(CodeMisconfigured, "必须传入 VerificationGuard")
	case accounts == nil:
		return nil, newErr(CodeMisconfigured, "必须传入 AccountCreator")
	case admission == nil:
		return nil, newErr(CodeMisconfigured, "必须传入 Admission (谁能建号)")
	case policy == nil:
		return nil, newErr(CodeMisconfigured, "必须传入 PasswordPolicy (§14.3.1 注册必做泄露检查)")
	}
	return g, nil
}

// SendCodeRequest 发注册码。
type SendCodeRequest struct {
	Username string
	Email    string
	ClientIP string
}

// SendCode 发注册验证码。
//
//	① 限流 (地址 + IP)
//	② 用户名已占 → 明确拒绝 (用户名本来就是公开的, 不怕枚举)
//	③ 邮箱已占 → ⭐ 对请求方仍然成功, 但给【那个邮箱的主人】发一封通知
//	   —— 请求方得不到"这个邮箱被注册过"的信息, 而真正的主人知道有人在试
//	④ 异步签发 + 投递
func (g *RegistrationGuard) SendCode(ctx context.Context, req SendCodeRequest) error {
	if err := g.verif.CheckSendAllowed(ctx, PurposeRegister, req.Email, req.ClientIP); err != nil {
		return err
	}
	if taken, err := g.accounts.UsernameTaken(ctx, req.Username); err != nil {
		return wrapErr(CodeLookupUnavailable, "查询用户名失败", err)
	} else if taken {
		return newErr(CodeUsernameTaken, "用户名已存在")
	}
	taken, err := g.accounts.EmailTaken(ctx, req.Email)
	if err != nil {
		return wrapErr(CodeLookupUnavailable, "查询邮箱失败", err)
	}
	if taken {
		g.verif.SendAsync(ctx, req.Email, func(bg context.Context) error {
			return g.verif.sender.SendVerification(bg, VerificationMessage{
				To: req.Email, Purpose: PurposeRegister, Notice: NoticeExistingAccount,
			})
		})
		return nil
	}
	g.verif.SendAsync(ctx, req.Email, func(bg context.Context) error {
		return g.verif.IssueAndSend(bg, PurposeRegister, req.Email, req.Email, "")
	})
	return nil
}

// RegistrationRequest 完成注册。
type RegistrationRequest struct {
	Username    string
	Password    string
	DisplayName string // 空则用 Username
	Email       string
	Code        string
}

// RegisterOutcome 注册结果。
type RegisterOutcome struct {
	UserID string
	// Advice 泄露评估。用户裁决 D5: 命中也放行, 带给前端提示。
	Advice PasswordAdvice
}

// Register 完成注册。
//
//	① 准入 —— ⛔ 必须在一切之前: 被拒的请求不该碰数据库, 也不该从"用户名已存在"里读出任何东西
//	② 验码 (不消费)
//	③ 泄露评估 (§14.3.1 必做; 警告放行)
//	④ 哈希
//	⑤ 建号 —— 唯一冲突翻译成 CodeUsernameTaken / CodeEmailTaken, 码未消费, 用户改个名重试
//	⑥ 消费 —— 失败记 WARN 但【不回滚 ⑤】: 码在 TTL 内再用, ⑤ 会因邮箱已占而冲突, 无害
func (g *RegistrationGuard) Register(ctx context.Context, req RegistrationRequest) (RegisterOutcome, error) {
	if err := g.admission.Admit(ctx, AdmitRequest{Email: req.Email}); err != nil {
		return RegisterOutcome{}, err
	}
	proof, err := g.verif.Verify(ctx, PurposeRegister, req.Email, req.Code)
	if err != nil {
		return RegisterOutcome{}, err
	}
	advice := g.policy.EvaluateNewPassword(ctx, req.Password)
	hash, err := hashWithCost(req.Password, g.cost, g.minLen)
	if err != nil {
		return RegisterOutcome{}, err
	}
	name := req.DisplayName
	if name == "" {
		name = req.Username
	}
	userID, err := g.accounts.CreateAccount(ctx, NewAccount{
		Username: req.Username, Email: req.Email, PasswordHash: hash, DisplayName: name,
	})
	if err != nil {
		return RegisterOutcome{}, err
	}
	if err := g.verif.Consume(ctx, proof); err != nil {
		g.emit(ctx, EventVerificationConsumeFailed, userID, err.Error())
	}
	g.emit(ctx, EventAccountRegistered, userID, req.Username)
	return RegisterOutcome{UserID: userID, Advice: advice}, nil
}

func (g *RegistrationGuard) emit(ctx context.Context, kind EventKind, userID, detail string) {
	if g.audit == nil {
		return
	}
	g.audit(ctx, AuditEvent{Kind: kind, UserID: userID, At: g.now(), Detail: detail})
}
