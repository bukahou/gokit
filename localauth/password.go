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

// DefaultMinPasswordLen 是口令长度下限的默认值。
//
// ⚠️ Guard 与 PasswordGuard 【共用】这一个常量 —— 两处各写一个 6,
// 就会出现"注册要 6 位、改密要 8 位"这种没人察觉的不一致。
const DefaultMinPasswordLen = 6

// HashPassword 按当前 cost 哈希口令。
func (g *Guard) HashPassword(plain string) (string, error) {
	return hashWithCost(plain, g.cost, g.minLen)
}

// hashWithCost 是包级实现, 供 Guard 与 PasswordGuard 共用。
//
// ⚠️ 抽出来是因为改密路径也要哈希 —— ⛔ 在那边再写一份
// "查长度 → 查上限 → GenerateFromPassword", 就是同一条规则的两份摹本,
// 而摹本只会漂移(改对了一处不会有任何症状提示另一处没改)。
func hashWithCost(plain string, cost, minLen int) (string, error) {
	if len(plain) < minLen {
		return "", newErr(CodePasswordTooShort,
			"口令至少 "+strconv.Itoa(minLen)+" 字节")
	}
	if len(plain) > MaxPasswordBytes {
		return "", newErr(CodePasswordTooLong,
			"口令不得超过 "+strconv.Itoa(MaxPasswordBytes)+" 字节")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plain), cost)
	if err != nil {
		return "", wrapErr(CodeMisconfigured, "哈希口令失败", err)
	}
	return string(h), nil
}
