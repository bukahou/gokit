package localauth

import "context"

// ============ 泄露口令检查 (§14) ============

// BreachVerdict 是一次泄露检查的结论。
//
// # ⛔ 为什么不是 bool + error
//
// 用 bool 的话, 调用方必须自己写 `if err != nil { 放行 }` ——
// 于是 fail-open 这条策略散落在【每一个调用点】, 而散落的策略必然漂移。
// 更要紧的是 §14.2.3 要求"查不了"这件事【可计数】: 合并进 error 就数不出来,
// 因为没人能区分"查了, 干净"与"根本没查成"。
//
// ⚠️ 本仓刚为这种形状付过两次代价: 批次二的四个审计事件因为消费者
// switch 漏了 case 而【一条都不记】, 而那个函数自己的注释早就预言过。
// 所以这里把"没查成"做成一个有名字的状态, 让它无法被顺手忽略。
type BreachVerdict int

const (
	// BreachUnknown 想查但没查成 (网络失败 / 超时 / 上游 5xx)。
	//
	// ⭐⭐ 刻意占据【零值位】, 而这是本仓唯一一次让零值通向"放行"。
	//
	// 别处 (model.Status / RotateOutcome) 都刻意把零值放在保守的那一侧,
	// 理由是"默认值不得通向破坏力"。这里反过来, 是因为 §14.2.1 明令 fail-open:
	// ⛔ 泄露库挂掉不该让所有人注册不了、改不了密码 —— 那是把一个
	// 【建议性】检查变成了全站故障。
	//
	// ⚠️ 例外必须有补偿, 否则就是开后门。补偿是: 每一次 Unknown 都发一条
	// 可计数的 WARN 审计事件 (EventBreachCheckUnavailable), 而该事件挂在
	// AllEventKinds() 上被穷举测试覆盖 —— 它【不可能】被静默漏掉。
	BreachUnknown BreachVerdict = iota

	// BreachClean 确认未出现在已知泄露集合中。
	BreachClean

	// BreachFound 确认出现过。Count 给出出现次数。
	BreachFound

	// BreachSkipped 按配置未做检查 (no-op 实现)。
	//
	// ⚠️ 与 Unknown 是【两件事】, ⛔ 不要合并:
	//   Unknown = 想查但失败了 → 要计数、要告警 (可能挂了三个月没人知道)
	//   Skipped = 根本没打算查 → 启动时可见一次即可
	//
	// ⭐ 用同一个状态表达两者, 必然是"要么每请求刷屏、要么静默"二选一。
	BreachSkipped
)

func (v BreachVerdict) String() string {
	switch v {
	case BreachClean:
		return "clean"
	case BreachFound:
		return "found"
	case BreachSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

// BreachResult 是一次检查的完整结果。
type BreachResult struct {
	Verdict BreachVerdict
	// Count 该口令在已知泄露集合中出现的次数。⚠️ 仅 BreachFound 有意义。
	//
	// ⭐ 它值得带出来: "出现过 3 次"与"出现过 200 万次"对用户是完全不同的
	// 风险提示, 而我们采用的是【警告放行】而非拒绝 —— 警告的说服力
	// 几乎全在这个数字上。
	Count int
}

// BreachChecker 检查一个口令明文是否出现在已知泄露集合中。
//
// # ⛔ 实现不得做任何策略判断
//
// 实现【只负责查】: 查到返回 Found, 没查到返回 Clean, 查不成返回 Unknown + error。
// ⛔ 不得自行决定放行还是拒绝 —— 那是 PasswordPolicy 的事。
// 三份实现各写一套 fail-open, 就是同一条规则的三份摹本, 而摹本只会漂移:
// 改对了一处不会有任何症状提示另外两处没改。
//
// # ⚠️ 明文只在进程内停留
//
// 传进来的是【口令明文】。实现绝不能把它写日志、写文件、或原样发到网络上 ——
// 在线实现走 k-anonymity 正是为此: 只发 SHA-1 的前 5 位。
type BreachChecker interface {
	Check(ctx context.Context, plaintext string) (BreachResult, error)

	// Kind 返回实现名, 用于【启动日志】。
	//
	// ⭐ 它的存在是为了让"当前用的是哪个实现"在【部署时】就看得见,
	// 而不是等到需要它的那天才发现挂的是 no-op。
	// ⚠️ 这解决的是 Skipped 那一侧的可见性 —— 与 Unknown 的每请求计数
	// 是两个不同的机制, 因为它们是两个不同的问题。
	Kind() string
}

// NewNoopBreachChecker 返回"不做检查"的实现。⭐ 这是模块默认。
//
// ⛔ 它返回 BreachSkipped 而【不是】BreachClean。
//
// 返回 Clean 等于断言"这个口令没有泄露过"—— 那是撒谎, 而且是那种
// 不会有任何症状的谎: 下游看到 Clean 就以为检查过了。
// 本仓刚被同一种形状坑过一次 (`_ = err` 顶着一句"失败仅记日志"的注释,
// 而那件事根本没发生)。
func NewNoopBreachChecker() BreachChecker { return noopBreachChecker{} }

type noopBreachChecker struct{}

func (noopBreachChecker) Check(context.Context, string) (BreachResult, error) {
	return BreachResult{Verdict: BreachSkipped}, nil
}

func (noopBreachChecker) Kind() string { return "noop" }
