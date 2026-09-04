package localauth

import (
	"context"
	"time"
)

// FailureState 是失败计数的【原始事实】。
//
// ⚠️ 它刻意【不含】lockedUntil 之类的判定结果 —— 那会让退避曲线落进每个
// 应用各自的存储实现里, 等于同一份策略写了 N 遍, 而调阈值就要 N 次迁移。
// 判定全部在 Policy 里, 存储只负责记事实。
type FailureState struct {
	Count       int
	FirstFailAt time.Time
	LastFailAt  time.Time
}

// FailureStore 是失败计数的存储契约。实现由消费者提供。
//
// # 为什么 Bump 必须原子
//
// 副本数 > 1 时,「读出来 +1 再写回去」有读-改-写竞态: 攻击者并发发起 N 个
// 请求, 它们可能都读到同一个旧值, 最终只 +1。计数丢失 = 退避形同虚设。
// 实现必须用单条原子语句 (例如 INSERT ... ON DUPLICATE KEY UPDATE count=count+1),
// 并返回【自增之后】的状态 —— 判定依赖的是自增后的值。
//
// # 账号维度的键: 排序规则必须与用户名列一致
//
// 键是【用户提交的原始字符串】。只要两侧的折叠规则不同, 就会出现
// 「同一个用户占两个计数桶」(退避被绕开) 或「两个用户共用一个桶」(打 A 锁死 B)。
//
// ⚠️ 分歧点【随数据库而变】, 不要凭一个环境的自查下结论。本仓两处实测:
//
//	环境          users.username        服务器默认值          忘写 COLLATE 的后果
//	本地 MySQL    utf8mb4_general_ci    utf8mb4_0900_ai_ci    分歧在 ß (两边都折叠大小写)
//	生产 TiDB     utf8mb4_general_ci    utf8mb4_bin           逐字节比 → 每个大小写变体一个桶
//
// 也就是说「在本地拿 alice/ALICE 试了一下没问题」在生产上恰好是最严重的那种漏。
// 见证串必须从当前库的实际排序规则推导, 见 repository 侧的 discriminatingPair。
//
// ⛔ 不要在 Go 侧自己写规范化来「对齐」: 那是对数据库折叠规则的一份摹本,
// 两份实现会漂移, 而攻击者只需要找到一个只在一边成立的字符。
// ✅ 正确做法是让计数键列与用户名列【共享同一条排序规则】——
// 复用的不是参数也不是函数, 是规则本身, 所以不可能漂移。
//
// ⛔ 而且该排序规则必须在 DDL 里【显式钉死】, 不得继承服务器默认值:
// 同一份 schema 换一个数据库就可能换一套折叠规则, 而这个漂移没有任何症状。
// 本仓实测: users.username = utf8mb4_general_ci, 服务器默认值 = utf8mb4_0900_ai_ci
// —— 不写 COLLATE 就会对不上, 且两边都是 _ci, 光看后缀看不出来。
//
// # 键含用户提交的原文
//
// 很多人拿邮箱当用户名, 所以这张表实际上会变成一张邮箱表。
// 须按【含 PII】对待: 有保留期 · 不进日志 · 不进运维明文导出。
//
// # 保留期
//
// 键空间可被攻击者任意扩张 (每个随机用户名一行), 必须有 TTL 清理。
// ⚠️ 保留期必须【显著长于】最长退避窗口 —— 否则清理会抹掉退避状态,
// 等于给攻击者一次免费重置。⛔ 也不要与其它表共用一个统一保留期。
type FailureStore interface {
	// Peek 只读, 不得改变任何状态。
	Peek(ctx context.Context, key string) (FailureState, error)

	// Bump 原子自增, 返回自增【之后】的状态。
	Bump(ctx context.Context, key string, now time.Time) (FailureState, error)

	// Reset 清除该键的计数。键不存在时返回 nil。
	Reset(ctx context.Context, key string) error
}
