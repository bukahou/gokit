package localauth

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// ⭐ TestVerifier_代换过就绝不放行 —— 一次真实的认证绕过, 这条钉住它。
//
// 早先的写法是: Login 查不到用户时把 hash 换成 dummy, 然后照常返回比对结果。
// 而 dummy 的明文当时是一行【源码常量】。于是:
//
//	拿那个常量当口令 → 登录任何不存在的用户名 → Allowed: true
//
// 现在 dummy 明文取自 crypto/rand。但随机化只是让人猜不到, 没有让这条路径消失 ——
// 所以修复是 Verify 里的 substituted 拒绝, 而这条测试验的正是那一行。
//
// ⚠️ 这里刻意【直接构造出攻击者猜中明文的情形】(自己造一个已知明文的 dummy),
// 而不是去测「随机明文猜不中」—— 后者测的是运气, 不是防御。
func TestVerifier_代换过就绝不放行(t *testing.T) {
	const known = "attacker-knows-this"
	h, err := bcrypt.GenerateFromPassword([]byte(known), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	// 造一个 dummy 明文已泄漏的校验器 —— 即最坏情况。
	v := &Verifier{cost: bcrypt.MinCost, dummyHash: string(h)}

	// 存的 hash 非法 (用户不存在 / 联邦账号无本地口令), 且口令正好是 dummy 的明文。
	for _, stored := range []string{"", "not-a-bcrypt-hash", "$2a$xx$broken"} {
		if v.Verify(stored, known) {
			t.Fatalf("stored=%q 且口令等于 dummy 明文时放行了 —— 认证绕过。"+
				"代换过的比对结果【绝不能】通向放行", stored)
		}
	}

	// 反过来: 合法 hash + 正确口令必须照常放行, 否则这条拒绝把正常登录也拦了。
	if !v.Verify(string(h), known) {
		t.Fatal("合法 hash + 正确口令被拒 —— substituted 判定误伤了正常路径")
	}
}

// TestVerifier_dummy明文不得可预测 —— 纵深防御那一层。
//
// 它不能替代上面那条结构性拒绝, 只是让攻击者连尝试的起点都没有。
func TestVerifier_dummy明文不得可预测(t *testing.T) {
	v1, err := NewVerifier(bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := NewVerifier(bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if v1.dummyHash == v2.dummyHash {
		t.Fatal("两次构造得到同一个 dummy hash —— 明文不是随机的")
	}

	// 早先那个源码常量必须已经不再是 dummy 的明文。
	for _, guess := range []string{"localauth-dummy", "dummy", ""} {
		if bcrypt.CompareHashAndPassword([]byte(v1.dummyHash), []byte(guess)) == nil {
			t.Fatalf("dummy 明文是可猜的 %q", guess)
		}
	}
}

// ⭐ TestLogin_不存在的用户名不得被任何口令登入
//
// 上一条测的是 Verifier, 这条测的是【编排之后的实际行为】——
// 即那次绕过在 Login 这一层确实已经关掉。
//
// ⚠️ 诚实标注: 实测过, 这一条【即使把 substituted 拒绝去掉也照样绿】——
// 因为 dummy 明文是随机的, 这里猜的那几个值本来就撞不上。
// 也就是说它【检测不出】那个结构性缺陷, 真正钉住缺陷的是上面那条。
// 保留它是因为它验的是另一件事: 编排层没有别的路径能放行未知用户。
// ⛔ 不要因为它绿就以为绕过被覆盖了 —— 这正是「哨兵看起来有意义但没判别力」
// 的又一个实例, 区别只在这次我知道它没有。
func TestLogin_不存在的用户名不得被任何口令登入(t *testing.T) {
	g := mustGuard(t)
	// lookup 永远返回「查不到」。
	none := func(context.Context, string) (string, bool, error) { return "", false, nil }

	// 把 dummy 明文可能的取值都试一遍, 包括早先那个源码常量。
	for i, pw := range []string{"localauth-dummy", "", "dummy", strings.Repeat("a", 44)} {
		out, err := g.Login(context.Background(), reqFrom("203.0.113.20"+string(rune('0'+i))),
			"ghost", pw, none)
		if err == nil || out.Allowed {
			t.Fatalf("口令 %q 登入了不存在的用户名 —— 认证绕过", pw)
		}
		if CodeOf(err) != CodeInvalidCredentials {
			t.Errorf("口令 %q: 期望 %q, 得到 %q", pw, CodeInvalidCredentials, CodeOf(err))
		}
	}
}
