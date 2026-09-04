package localauth

import "time"

// Policy 判定「当前这个计数状态算不算处于退避中」。
//
// 它是【纯函数】: 只看传入的 state 与 now, 不做 I/O、不读全局。
// 这让它可以被表驱动单测穷举, 也让「换一条退避曲线」不需要任何一家做数据迁移。
type Policy interface {
	Blocked(s FailureState, now time.Time) bool
}

// BackoffPolicy 是默认策略: 达阈值即拒绝, 计数随时间线性衰减, 并有封顶。
//
// ⛔ 刻意【不做】递增延迟。理由: 任何「响应时间随账号状态变化」的机制
// 本身就是预言机, 而递增延迟的全部作用就是让响应时间随账号状态变化 ——
// 那不是实现没修好, 是目的与时序一致性直接对立。
// 需要递增延迟的部署可以自己实现 Policy, 但那等于显式接受一个账号状态时序预言机。
type BackoffPolicy struct {
	// Threshold 有效计数达到它即视为处于退避中。
	Threshold int

	// Ceiling 有效计数的封顶。
	//
	// ⚠️ 没有封顶时, 一次分布式突发 (比如几千次) 会造出一个按比例超长的
	// 锁定窗口 —— 因为衰减是线性的, 几千次就要衰减几千个周期。
	// 封顶让锁定时长有天花板。
	//
	// 注意封顶只发生在【判定】里: 存储仍然记录真实计数 (笨存储不变),
	// 策略在库里 (策略不下放不变)。
	Ceiling int

	// DecayInterval 每过一个该时长, 有效计数减一。
	//
	// ⚠️ 没有衰减时会出现【跨周期单调累积】:
	//   打 → 被拒 → 等窗口过期 → 再打一次 → 计数更高 → 窗口更长 → …
	// 而计数只在成功登录时清零, 所以合法用户被压住之后, 他能翻身的机会
	// 随窗口指数拉长而趋近于零。这是软化版的永久锁死。
	//
	// ⚠️ 且它与「保留期须长于最长退避窗口」这条规则叠加会更糟:
	// 那条规则意味着那一行在整个保留期内都留着高计数。
	// 两条各自正确的规则, 叠起来就是单调累积 —— 所以衰减不是可选项。
	DecayInterval time.Duration
}

// DefaultPolicy 是一组保守的默认值。
//
// 阈值 10 / 封顶 20 / 每 5 分钟衰减 1。
//
// 最坏锁定时长 = (Ceiling − Threshold + 1) × DecayInterval = 11 × 5min = 55 分钟
// (判定是 eff >= Threshold, 所以要衰减到 9 才放行, 那是第 11 格)。
// 且维持它需要攻击者持续施压: 每次 Bump 都会把 LastFailAt 推到当下。
func DefaultPolicy() BackoffPolicy {
	return BackoffPolicy{Threshold: 10, Ceiling: 20, DecayInterval: 5 * time.Minute}
}

// Blocked 实现 Policy。
func (p BackoffPolicy) Blocked(s FailureState, now time.Time) bool {
	if s.Count <= 0 {
		return false
	}

	c := s.Count
	if p.Ceiling > 0 && c > p.Ceiling {
		c = p.Ceiling
	}

	if p.DecayInterval > 0 && now.After(s.LastFailAt) {
		c -= int(now.Sub(s.LastFailAt) / p.DecayInterval)
	}

	return c >= p.Threshold
}

// valid 供构造期自检。
func (p BackoffPolicy) valid() error {
	switch {
	case p.Threshold <= 0:
		return newErr(CodeMisconfigured, "Policy.Threshold 必须为正")
	case p.Ceiling > 0 && p.Ceiling < p.Threshold:
		return newErr(CodeMisconfigured, "Policy.Ceiling 不得小于 Threshold, 否则永不触发")
	case p.DecayInterval <= 0:
		// ⚠️ 允许显式关闭衰减, 但那会导致跨周期单调累积, 必须是刻意的选择。
		return newErr(CodeMisconfigured, "Policy.DecayInterval 必须为正 (关闭衰减会导致跨周期单调累积)")
	}
	return nil
}
