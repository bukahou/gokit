package localauth

import (
	"testing"
	"time"
)

func TestBackoffPolicy(t *testing.T) {
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	p := BackoffPolicy{Threshold: 10, Ceiling: 20, DecayInterval: 5 * time.Minute}

	cases := []struct {
		name  string
		count int
		since time.Duration // now - LastFailAt
		want  bool
	}{
		{"零计数不拦", 0, 0, false},
		{"未达阈值不拦", 9, 0, false},
		{"刚达阈值就拦", 10, 0, true},
		{"超阈值拦", 15, 0, true},

		// 衰减: 每 5 分钟减 1
		{"衰减一格后仍达阈值", 11, 5 * time.Minute, true},
		{"衰减到阈值以下即放行", 10, 5 * time.Minute, false},
		{"衰减足够久后放行", 20, 55 * time.Minute, false},

		// 封顶 20 / 阈值 10 / 每 5 分钟衰减 1, 而判定是 eff >= Threshold ——
		// 所以要衰减到 9 才放行, 需 11 格 = 55 分钟。上界 = (Ceiling-Threshold+1) × DecayInterval。
		{"封顶后: 一万次计数在 55 分钟时仍拦", 10000, 54 * time.Minute, true},
		{"封顶后: 一万次计数在 56 分钟后放行", 10000, 56 * time.Minute, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := FailureState{Count: c.count, LastFailAt: base.Add(-c.since)}
			if got := p.Blocked(s, base); got != c.want {
				t.Errorf("Blocked(count=%d, since=%v) = %v, 期望 %v", c.count, c.since, got, c.want)
			}
		})
	}
}

// TestBackoffPolicy_没有封顶会造出超长锁定 是对「为什么需要封顶」的反向验证。
//
// 若删掉封顶 (Ceiling=0 表示不封顶), 一次一万次的分布式突发就会造出
// 一万个衰减周期的锁定 —— 本测试断言那确实会发生, 从而说明封顶不是装饰。
func TestBackoffPolicy_没有封顶会造出超长锁定(t *testing.T) {
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	noCeiling := BackoffPolicy{Threshold: 10, DecayInterval: 5 * time.Minute} // Ceiling 未设

	s := FailureState{Count: 10000, LastFailAt: base.Add(-24 * time.Hour)}
	if !noCeiling.Blocked(s, base) {
		t.Fatal("无封顶时, 一万次计数在 24 小时后本应仍被拦 —— 若这里放行了, 说明封顶的必要性论证不成立")
	}

	withCeiling := BackoffPolicy{Threshold: 10, Ceiling: 20, DecayInterval: 5 * time.Minute}
	if withCeiling.Blocked(s, base) {
		t.Fatal("有封顶时, 同样的计数在 24 小时后应当早已放行")
	}
}

// TestBackoffPolicy_跨周期累积 演示 (乙) 单独不够、必须配衰减。
//
// 场景: 攻击者打到阈值 → 等窗口过期 → 补一次失败 → 计数更高 → 窗口更长。
// 没有衰减时窗口单调变长; 有衰减时它有上界。
func TestBackoffPolicy_跨周期累积(t *testing.T) {
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	noDecay := BackoffPolicy{Threshold: 10, Ceiling: 0} // DecayInterval 未设 = 不衰减

	// 不衰减时: 计数只增不减, 过多久都拦。
	s := FailureState{Count: 11, LastFailAt: base.Add(-365 * 24 * time.Hour)}
	if !noDecay.Blocked(s, base) {
		t.Fatal("不衰减时, 一年前的 11 次失败本应仍拦 —— 若放行, 说明衰减的必要性论证不成立")
	}

	// 衰减 + 封顶时, 同一状态早已放行。
	if DefaultPolicy().Blocked(s, base) {
		t.Fatal("默认策略下, 一年前的失败应当早已衰减完")
	}
}

func TestBackoffPolicy_构造期自检(t *testing.T) {
	cases := []struct {
		name string
		p    BackoffPolicy
	}{
		{"阈值为零", BackoffPolicy{Threshold: 0, DecayInterval: time.Minute}},
		{"封顶小于阈值", BackoffPolicy{Threshold: 10, Ceiling: 5, DecayInterval: time.Minute}},
		{"未设衰减", BackoffPolicy{Threshold: 10}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.p.valid(); err == nil {
				t.Error("期望构造期报错, 实际通过了")
			}
		})
	}
	if err := DefaultPolicy().valid(); err != nil {
		t.Errorf("默认策略应当合法: %v", err)
	}
}
