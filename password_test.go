package localauth

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestCostOf(t *testing.T) {
	cases := []struct {
		hash string
		want int
		ok   bool
	}{
		{"$2a$10$abcdefghijklmnopqrstuv", 10, true},
		{"$2a$12$abcdefghijklmnopqrstuv", 12, true},
		{"$2b$04$abcdefghijklmnopqrstuv", 4, true},
		{"", 0, false},
		{"not-a-hash", 0, false},
		{"$2a$xx$abc", 0, false},
	}
	for _, c := range cases {
		got, ok := costOf(c.hash)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("costOf(%q) = (%d,%v), 期望 (%d,%v)", c.hash, got, ok, c.want, c.ok)
		}
	}
}

func TestPadRounds(t *testing.T) {
	g := &Guard{cost: 12}

	cases := []struct {
		name  string
		cost  int
		want  int
		about string
	}{
		{"低两档补 3 次", 10, 3, "2^(12-10)-1 = 3 → 总工作量 4× = cost12"},
		{"低一档补 1 次", 11, 1, "2^1-1 = 1 → 总工作量 2× = cost12"},
		{"同档不补", 12, 0, ""},
		{"高于目标不补", 13, 0, "做不了负功 —— 所以 cost 只增不减"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := bcrypt.GenerateFromPassword([]byte("x"), c.cost)
			if err != nil {
				t.Fatal(err)
			}
			if got := g.padRounds(string(h)); got != c.want {
				t.Errorf("padRounds(cost=%d) = %d, 期望 %d  (%s)", c.cost, got, c.want, c.about)
			}
		})
	}

	// 非法 hash 不补 —— 它由绝对下界测试负责抓, 不是这里。
	if got := g.padRounds(""); got != 0 {
		t.Errorf("空 hash 应当补 0 次, 得到 %d", got)
	}
}

func TestHashPassword_长度边界(t *testing.T) {
	g := mustGuard(t, WithCost(bcrypt.MinCost), WithMinPasswordLen(6))

	cases := []struct {
		name string
		pw   string
		code Code
	}{
		{"太短", "12345", CodePasswordTooShort},
		{"下限刚好", "123456", ""},
		{"72 字节刚好", strings.Repeat("a", 72), ""},
		{"73 字节超限", strings.Repeat("a", 73), CodePasswordTooLong},
		{"长 passphrase 超限", strings.Repeat("correct horse ", 10), CodePasswordTooLong},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := g.HashPassword(c.pw)
			got := CodeOf(err)
			if got != c.code {
				t.Errorf("HashPassword(%d 字节) 得到码 %q, 期望 %q", len(c.pw), got, c.code)
			}
		})
	}
}

// TestHashPassword_不得原样抛出底层错误 是对「73 字节会变成 500」那个缺陷的反向验证。
//
// 若 HashPassword 把 bcrypt 的错误原样返回, CodeOf 会拿不到类型化的码,
// 调用方的兜底分支就会把它映射成 5xx —— 而这条纯靠一个长口令即可触发。
func TestHashPassword_不得原样抛出底层错误(t *testing.T) {
	g := mustGuard(t, WithCost(bcrypt.MinCost))

	_, err := g.HashPassword(strings.Repeat("a", 100))
	if err == nil {
		t.Fatal("100 字节口令应当被拒")
	}
	if CodeOf(err) != CodePasswordTooLong {
		t.Fatalf("期望类型化码 %q, 得到 %q —— 未类型化的错误会被调用方兜底成 5xx",
			CodePasswordTooLong, CodeOf(err))
	}

	// 对照: 底层错误长什么样。若上面那条被写成 return err, 拿到的就是它。
	_, raw := bcrypt.GenerateFromPassword([]byte(strings.Repeat("a", 100)), bcrypt.MinCost)
	if CodeOf(raw) != "" {
		t.Fatal("底层错误本不应携带本包的码 —— 这条对照失效了")
	}
}
