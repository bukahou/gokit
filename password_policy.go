package localauth

import (
	"context"
	"time"
)

// PasswordAdvice 是对一个【新口令】的评估结果。
//
// # ⛔ 为什么它不是 error
//
// geass 采用【警告放行】而非拒绝 (用户裁决, 2026-09-05):
// 命中泄露库 → 提示但仍然允许设置。
//
// 所以它不是错误, 是一条【建议】—— 塞进 error 会强迫调用方
// 用 errors.Is 去判断"这个 error 到底要不要中断流程",
// 而那正是 error 最不该表达的东西。
//
// ⚠️ 出参必须一路带到前端 (如 JSON 的 `passwordBreached`), 让前端决定怎么提示。
// ⛔ 后端替前端决定"这条提示重不重要"是错的分层。
type PasswordAdvice struct {
	// Breached 该口令出现在已知泄露集合中。
	Breached bool
	// BreachCount 出现次数。⭐ 警告的说服力几乎全在这个数字上 ——
	// "出现过 3 次"与"出现过 200 万次"对用户是完全不同的风险。
	BreachCount int
	// Checked 是否真的完成了一次检查。
	//
	// ⚠️ false 有两种成因(未启用 / 查询失败), 对【用户】没有区别:
	// 两种情况下"没有警告"都不等于"这个口令是安全的"。
	// ⛔ 前端不得把 Checked=false && Breached=false 显示成"口令安全"。
	Checked bool
}

// PasswordPolicy 是新口令的评估策略 (§14)。
//
// # ⭐ fail-open 与计数【只在这里】发生
//
// BreachChecker 的实现只负责查, 不做策略判断。放行/拒绝/记事件
// 全部收在本类型的一个方法里 —— 三份实现各写一套 fail-open,
// 就是同一条规则的三份摹本, 而摹本只会漂移。
type PasswordPolicy struct {
	breach BreachChecker
	audit  AuditHook
	now    func() time.Time
}

// PolicyOption 配置 PasswordPolicy。
type PolicyOption func(*PasswordPolicy)

// WithBreachChecker 启用泄露口令检查。
//
// ⚠️ 不传 = no-op (BreachSkipped)。⛔ 不是 nil ——
// 见 NewPasswordPolicy 的注释。
func WithBreachChecker(c BreachChecker) PolicyOption {
	return func(p *PasswordPolicy) {
		if c != nil {
			p.breach = c
		}
	}
}

// WithPolicyAudit 接住审计事件。
func WithPolicyAudit(h AuditHook) PolicyOption {
	return func(p *PasswordPolicy) { p.audit = h }
}

// WithPolicyClock 换时钟 (测试用)。
func WithPolicyClock(f func() time.Time) PolicyOption {
	return func(p *PasswordPolicy) { p.now = f }
}

// NewPasswordPolicy 构造口令策略。
//
// # ⭐ 默认实现是 no-op, 而且字段【永远非 nil】
//
// 沿用 pkg/cache 已确立的做法, 它的 doc 把理由写得很清楚:
// "若改用 if cache != nil 之类的分支, 本地跑到的就是另一条路径,
// 线上才第一次执行缓存代码"。
//
// 所以调用点永远不判 nil, 本地开发与生产走【同一条代码路径】,
// 只是 no-op 的结论恒为 Skipped。
//
// ⚠️ "当前用的是哪个实现"靠 BreachKind() 在【启动日志】里体现 ——
// 那是 Skipped 那一侧唯一合适的可见性形态。
func NewPasswordPolicy(opts ...PolicyOption) *PasswordPolicy {
	p := &PasswordPolicy{
		breach: NewNoopBreachChecker(),
		now:    time.Now,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// BreachKind 返回当前泄露检查实现名, 供启动日志打印。
func (p *PasswordPolicy) BreachKind() string { return p.breach.Kind() }

// EvaluateNewPassword 评估一个新口令。
//
// ⚠️ 返回值【不含 error 的语义分支】: 查询失败不是调用方的问题,
// 本方法内部已经按 §14.2.1 fail-open 处理完毕并留了痕。
//
// # ⭐ fail-open 的代价在这里被记下来
//
// Unknown → 放行, 但发 EventBreachCheckUnavailable (WARN)。
// 该事件挂在 AllEventKinds() 上被穷举测试覆盖, 所以它
// ⛔ 不可能像批次二那四个会话事件一样被消费者静默漏掉。
// 「泄露库挂了三个月没人知道」这个失效, 解药就是这一条。
func (p *PasswordPolicy) EvaluateNewPassword(ctx context.Context, plaintext string) PasswordAdvice {
	res, err := p.breach.Check(ctx, plaintext)

	switch res.Verdict {
	case BreachFound:
		// ⚠️ INFO 而非 WARN/ERROR: 用户选了个烂口令是【正常业务流程】。
		// 本仓的级别语义要求 ERROR 少到每一条都值得看,
		// 而这条在正常使用中会持续出现。
		p.emitPolicy(ctx, EventPasswordBreached, "出现次数 "+itoa(res.Count))
		return PasswordAdvice{Breached: true, BreachCount: res.Count, Checked: true}

	case BreachUnknown:
		// ⭐ fail-open (§14.2.1) —— 但必须可计数。
		detail := "泄露库不可用"
		if err != nil {
			detail = err.Error()
		}
		p.emitPolicy(ctx, EventBreachCheckUnavailable, detail)
		return PasswordAdvice{Checked: false}

	case BreachSkipped:
		// 未启用。⛔ 不发事件 —— 它在正常使用中【每次都会发生】,
		// 记成事件就是纯噪声, 而且会淹掉真正的 Unavailable。
		// 可见性由启动日志的 BreachKind() 承担。
		return PasswordAdvice{Checked: false}

	default: // BreachClean
		return PasswordAdvice{Checked: true}
	}
}

func (p *PasswordPolicy) emitPolicy(ctx context.Context, kind EventKind, detail string) {
	if p.audit == nil {
		return
	}
	p.audit(ctx, AuditEvent{Kind: kind, At: p.now(), Detail: detail})
}
