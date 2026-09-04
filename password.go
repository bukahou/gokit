package localauth

import (
	"regexp"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

// MaxPasswordBytes 是 bcrypt 的硬上限。73 字节起 GenerateFromPassword 报错。
//
// ⚠️ 必须显式拒绝, 两个都不能选:
//   - 原样抛出底层错误 → 变成 5xx。而这条纯靠一个长口令就能触发, 无需任何凭据,
//     且它专门命中使用长 passphrase 的人 —— 安全意识最强的用户命中率最高。
//   - 静默截断 (部分实现的做法) → 口令后半段无效, 没有任何症状。
const MaxPasswordBytes = 72

// costPattern 从 bcrypt hash 前缀里取 cost。格式形如 $2a$10$...
var costPattern = regexp.MustCompile(`^\$2[aby]?\$(\d{2})\$`)

// costOf 解析一个 bcrypt hash 的 cost。
//
// ⚠️ cost 编码在 hash 串【自身】里 —— 所以校验一次的耗时由【存的那一行】决定,
// 与任何配置变量无关。这也意味着「让防御路径复用真路径的同一个 cost 变量」
// 在这里做不到: 真路径根本没有「一个」cost。
func costOf(hash string) (int, bool) {
	m := costPattern.FindStringSubmatch(hash)
	if m == nil {
		return 0, false
	}
	c, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return c, true
}

// HashPassword 按当前 cost 哈希口令。
func (g *Guard) HashPassword(plain string) (string, error) {
	if len(plain) < g.minLen {
		return "", newErr(CodePasswordTooShort,
			"口令至少 "+strconv.Itoa(g.minLen)+" 字节")
	}
	if len(plain) > MaxPasswordBytes {
		return "", newErr(CodePasswordTooLong,
			"口令不得超过 "+strconv.Itoa(MaxPasswordBytes)+" 字节")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plain), g.cost)
	if err != nil {
		return "", wrapErr(CodeMisconfigured, "哈希口令失败", err)
	}
	return string(h), nil
}

// verify 是 bcrypt 的【唯一调用点】。
//
// 三条不可动摇的性质, 各由不同机制保证, 互不替代:
//
//	① 唯一调用点且支配所有凭据相关的返回路径 —— 由 Login 的编排保证
//	② 错误在此坍缩为 bool —— 由本函数的签名保证 (返回 bool, error 不逃出去)
//	③ 每条路径都真的【干了活】—— 由绝对下界耗时测试保证
//
// ⚠️ ③ 不能被 ① 替代: dummy 若是一个非法 hash, 调用点仍然被到达、
// 仍然支配所有返回, 而 bcrypt 会在 20ns 内报「hash 太短」返回 ——
// ① 是结构判据, 看不见「返回得多快」。
func (g *Guard) verify(hash, plain string) bool {
	// ② 错误在这里坍缩。⛔ 不得把 err 传出去:
	// 空 hash 得到的是 ErrHashTooShort 而非 ErrMismatchedHashAndPassword,
	// 一旦让它逃出去, 调用方的兜底分支就会把「账号存在但没有本地密码」
	// 打成另一个状态码 —— 泄漏从时序级升级成一次请求即可读出。
	ok := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil

	// ⭐ 工作量补齐 —— 消除「快 = 老账号」这个 cost 预言机。
	//
	// 升级 cost 是最佳实践, 而存量行改不了 (重哈希需要明文, 明文只在登录那一刻存在)。
	// 于是老账号 36ms、新账号 145ms,「快」唯一标识老账号。
	// 而按 cost 重哈希只在【登录成功】时发生, 所以休眠账号永不迁移 ——
	// 这个预言机随时间【提纯】而不是收敛, 而休眠账号恰恰是攻击者最想要的。
	//
	// 做法: bcrypt 的 cost 是指数的 (cost N = 2^N 轮), 所以
	//   补跑 2^(目标 − 存量) − 1 次, 总工作量 = 2^目标, 与该行存的 cost 无关。
	// 实测比值与理论吻合 (cost12/cost10 = 4.00), 补齐后偏差 < 1%。
	//
	// ⚠️ 补跑用【这一行自己的 hash】, 不另造 dummy ——
	// 那就是「直接执行被防护路径的计算」, 而不是对它的一份摹本。
	if extra := g.padRounds(hash); extra > 0 {
		acc := ok
		for i := 0; i < extra; i++ {
			// acc 参与运算, 防止这段被当成无副作用的死代码消掉 ——
			// 「代码在场」不等于「代码起作用」。
			acc = acc != (bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil)
		}
		g.padSink = acc
	}

	return ok
}

// padRounds 算这一行需要补跑几次。
//
// ⚠️ 存量 cost 高于目标时补不了 (做不了负功)。这类账号会比其它账号慢,
// 是一个反方向的预言机 —— 所以规则是 cost【只增不减】。
// ⛔ 但那不等于「不能降」: 若确须降低 (例如发现造成超时),
// 代价是对该批账号强制重置密码。而该批账号是【可枚举】的 ——
// cost 明文写在 $2a$NN$ 前缀里, 一条 LIKE 查询就能算出范围,
// 所以那是一个能先算代价再决定的动作, 不是盲跳。
func (g *Guard) padRounds(hash string) int {
	c, ok := costOf(hash)
	if !ok || c >= g.cost {
		return 0
	}
	return (1 << uint(g.cost-c)) - 1
}
