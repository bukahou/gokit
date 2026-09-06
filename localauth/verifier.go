package localauth

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

// Verifier 是口令校验的唯一实现。
//
// # 为什么单独成一个类型
//
// 「定时安全地校验一个口令」这件事有三条各自独立的性质 (见 Verify 的注释),
// 而需要它的不止 Guard 一处 —— 宿主里那些还没接守卫的旧路径同样需要。
// 若各写一份, 就是同一条规则的两份摹本, 而摹本只会漂移:
// 改对了一处不会有任何症状提示另一处没改。
//
// 所以这里是唯一实现, Guard 与宿主共用同一个实例。
type Verifier struct {
	cost int

	// dummyHash 用于「查不到用户」「账号没有本地口令」等情形下跑等量运算。
	//
	// ⚠️ 明文取自 crypto/rand 且【不保留】—— 见 NewVerifier。
	dummyHash string

	// padSink 承接补齐运算的结果, 防止它被编译器当成死代码消掉。
	padSink bool
}

// NewVerifier 构造校验器。cost 与 dummy 同源于这一次构造。
//
// ⚠️ dummy 的明文来自 crypto/rand 且构造完即丢弃, 没有任何地方留存。
// 早先的写法是一个源码常量 —— 那让「拿这个常量当口令」成为一次真实的
// 认证绕过 (见 Verify 里 substituted 的注释)。改用随机明文是纵深防御,
// ⛔ 但它【不是】那条绕过的修复: 修复是 Verify 里的结构性拒绝。
// 两者不可互相替代 —— 前者让攻击者猜不到, 后者让猜到了也没用。
func NewVerifier(cost int) (*Verifier, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, wrapErr(CodeMisconfigured, "生成 dummy 明文失败", err)
	}
	// base64 之后长度 44 字节, 在 bcrypt 的 72 字节上限内。
	h, err := bcrypt.GenerateFromPassword(
		[]byte(base64.RawStdEncoding.EncodeToString(secret)), cost)
	if err != nil {
		return nil, wrapErr(CodeMisconfigured, "生成 dummy hash 失败", err)
	}
	return &Verifier{cost: cost, dummyHash: string(h)}, nil
}

// Cost 返回目标 cost。
func (v *Verifier) Cost() int { return v.cost }

// Verify 校验口令。这是 bcrypt 在【凭据路径上的唯一调用点】。
//
// 三条不可动摇的性质, 各由不同机制保证, 互不替代:
//
//	① 唯一调用点且支配所有凭据相关的返回路径 —— 由调用方的编排保证
//	② 错误在此坍缩为 bool —— 由本函数的签名保证 (返回 bool, error 不逃出去)
//	③ 每条路径都真的【干了活】—— 由绝对下界耗时测试保证
//
// ⚠️ ③ 不能被 ① 替代: dummy 若是一个非法 hash, 调用点仍然被到达、
// 仍然支配所有返回, 而 bcrypt 会在 20ns 内报「hash 太短」返回 ——
// ① 是结构判据, 看不见「返回得多快」。
func (v *Verifier) Verify(storedHash, plain string) bool {
	// 代换规则 —— 一条规则覆盖三种情形, 而不是让调用方各记一遍:
	//   · 用户不存在        (调用方传空串)
	//   · 账号没有本地口令  (联邦账号, DB 里存的就是空串)
	//   · 存的 hash 已损坏
	// 三者都必须跑满等量运算, 否则「返回得快」就把这几类账号标了出来。
	// 判据是「这是不是一个合法的 bcrypt hash」, 而不是调用方的某个布尔参数 ——
	// 参数会被忘记传, hash 自己不会说谎。
	hash, substituted := storedHash, false
	if _, ok := costOf(hash); !ok {
		hash, substituted = v.dummyHash, true
	}

	// ② 错误在这里坍缩。⛔ 不得把 err 传出去:
	// 空 hash 得到的是 ErrHashTooShort 而非 ErrMismatchedHashAndPassword,
	// 一旦让它逃出去, 调用方的兜底分支就会把「账号存在但没有本地口令」
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
	if extra := v.padRounds(hash); extra > 0 {
		acc := ok
		for i := 0; i < extra; i++ {
			// acc 参与运算, 防止这段被当成无副作用的死代码消掉 ——
			// 「代码在场」不等于「代码起作用」。
			acc = acc != (bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil)
		}
		v.padSink = acc
	}

	// ⛔ 发生过代换就绝不放行 —— 这是一条【结构性】拒绝。
	//
	// 早先的写法是: 查不到用户时把 hash 换成 dummy, 然后照常返回比对结果。
	// 那意味着【拿 dummy 的明文当口令, 就能登录任何不存在的用户名】——
	// 当时 dummy 明文还是一行源码常量, 所以这是一次真实可用的认证绕过。
	//
	// 现在 dummy 明文取自 crypto/rand, 猜不到了。但那只是让它变难, 没有让它
	// 不可能: 只要「代换后的比对结果」还能通向放行, 这条路径就仍然存在。
	// 所以真正的修复是这一行 —— 让「因 dummy 匹配而放行」这个状态
	// 【表达不出来】, 而不是让它难以触发。
	if substituted {
		return false
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
func (v *Verifier) padRounds(hash string) int {
	c, ok := costOf(hash)
	if !ok || c >= v.cost {
		return 0
	}
	return (1 << uint(v.cost-c)) - 1
}
