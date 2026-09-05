package localauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ============ no-op ============

// TestNoopChecker_返回Skipped而不是Clean 守的是"不许撒谎"。
func TestNoopChecker_返回Skipped而不是Clean(t *testing.T) {
	res, err := NewNoopBreachChecker().Check(context.Background(), "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict == BreachClean {
		t.Fatal("⛔ no-op 返回了 Clean —— 那是在断言'这个口令没泄露过', " +
			"而它根本没查。下游看到 Clean 会以为检查过了")
	}
	if res.Verdict != BreachSkipped {
		t.Fatalf("应返回 BreachSkipped, got %v", res.Verdict)
	}
}

// TestBreachVerdict_零值是Unknown 记录一个【刻意的例外】。
func TestBreachVerdict_零值是Unknown(t *testing.T) {
	var zero BreachVerdict
	if zero != BreachUnknown {
		t.Fatalf("零值应为 BreachUnknown, got %v", zero)
	}
	// ⚠️ 本仓别处(model.Status / RotateOutcome)都刻意让零值倒向保守一侧。
	// 这里反过来是 §14.2.1 明令的 fail-open, 补偿是可计数的 WARN 事件。
	// ⛔ 谁要改这条, 先读 breach.go 里 BreachUnknown 的注释。
}

// ============ 在线实现 (k-anonymity) ============

// TestPwnedChecker_只发前5位 是 k-anonymity 的核心断言。
func TestPwnedChecker_只发前5位(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotPadding string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath, gotPadding = r.URL.Path, r.Header.Get("Add-Padding")
		mu.Unlock()
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:1\n"))
	}))
	defer srv.Close()

	c := NewPwnedRangeChecker(WithPwnedBaseURL(srv.URL), WithPwnedHTTPClient(srv.Client()))
	if _, err := c.Check(context.Background(), "password"); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	if gotPath != "/range/5BAA6" {
		t.Errorf("⛔ 请求路径 = %q, 期望 /range/5BAA6 —— "+
			"只有前 5 位可以出网, 发完整哈希等于把'某人在用这个口令'告诉第三方", gotPath)
	}
	if strings.Contains(gotPath, "61E4C9B93F3F") {
		t.Error("⛔⛔ 完整哈希出现在了 URL 里 —— k-anonymity 被破坏")
	}
	if gotPadding != "true" {
		t.Error("缺 Add-Padding 头 —— 响应体大小本身是可观测的前缀指纹")
	}
}

// TestPwnedChecker_命中与未命中 走真实的 SHA-1 后缀比对。
func TestPwnedChecker_命中与未命中(t *testing.T) {
	// SHA-1("password") = 5BAA6 + 1E4C9B93F3F0682250B6CF8331B7EE68FD8
	const suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(
			"0000000000000000000000000000000000A:5\r\n" +
				suffix + ":9659365\r\n" +
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n"))
	}))
	defer srv.Close()
	c := NewPwnedRangeChecker(WithPwnedBaseURL(srv.URL), WithPwnedHTTPClient(srv.Client()))

	res, err := c.Check(context.Background(), "password")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != BreachFound || res.Count != 9659365 {
		t.Fatalf("应命中且带出次数, got verdict=%v count=%d", res.Verdict, res.Count)
	}

	res, err = c.Check(context.Background(), "这个口令的前缀不同所以不会命中")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != BreachClean {
		t.Fatalf("未命中应为 Clean, got %v", res.Verdict)
	}
}

// TestPwnedChecker_padding假行不得当成命中 —— count=0 是上游塞的假数据。
func TestPwnedChecker_padding假行不得当成命中(t *testing.T) {
	const suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(suffix + ":0\n")) // ⭐ count=0 = padding
	}))
	defer srv.Close()
	c := NewPwnedRangeChecker(WithPwnedBaseURL(srv.URL), WithPwnedHTTPClient(srv.Client()))
	res, _ := c.Check(context.Background(), "password")
	if res.Verdict == BreachFound {
		t.Fatal("⛔ 把 padding 假行(count=0)当成了命中 —— " +
			"那会让每一个口令都被判为泄露")
	}
}

// TestPwnedChecker_失败返回Unknown而不是Clean 是 fail-open 能被计数的前提。
func TestPwnedChecker_失败返回Unknown而不是Clean(t *testing.T) {
	t.Run("上游 5xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		c := NewPwnedRangeChecker(WithPwnedBaseURL(srv.URL), WithPwnedHTTPClient(srv.Client()))
		res, err := c.Check(context.Background(), "password")
		if res.Verdict != BreachUnknown {
			t.Errorf("⛔ 上游 5xx 应为 Unknown(可计数), got %v —— "+
				"判成 Clean 等于'查失败了但报告说没泄露'", res.Verdict)
		}
		if err == nil {
			t.Error("应带 error 供日志记录")
		}
	})

	t.Run("连不上", func(t *testing.T) {
		c := NewPwnedRangeChecker(WithPwnedBaseURL("http://127.0.0.1:1"))
		res, _ := c.Check(context.Background(), "password")
		if res.Verdict != BreachUnknown {
			t.Errorf("连不上应为 Unknown, got %v", res.Verdict)
		}
	})
}

// ============ 离线实现 ============

func TestLocalChecker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "top.txt")
	// SHA-1("password") 全量
	content := "# 注释行\n\n5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\n不是哈希的行\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewLocalBreachChecker(path)
	if err != nil {
		t.Fatal(err)
	}

	res, _ := c.Check(context.Background(), "password")
	if res.Verdict != BreachFound || res.Count != 9659365 {
		t.Errorf("应命中, got %v count=%d", res.Verdict, res.Count)
	}
	res, _ = c.Check(context.Background(), "一个不在集合里的口令")
	if res.Verdict != BreachClean {
		t.Errorf("未命中应为 Clean, got %v", res.Verdict)
	}
}

// TestLocalChecker_空集合必须拒绝构造 —— 空集会让每个口令都判 Clean。
func TestLocalChecker_空集合必须拒绝构造(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, []byte("# 只有注释\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalBreachChecker(path); err == nil {
		t.Fatal("⛔ 空数据集竟然构造成功 —— " +
			"它会让每个口令都判 Clean, 是一个'看起来在工作'的失效")
	}
}

// TestLocalChecker_装不上必须报错而不是降级 —— 启动期配错要响。
func TestLocalChecker_装不上必须报错而不是降级(t *testing.T) {
	if _, err := NewLocalBreachChecker("/不存在的路径/x.txt"); err == nil {
		t.Fatal("⛔ 文件不存在竟然构造成功 —— 配了离线实现却装不上, " +
			"那是部署错误, 应当启动即炸而不是静默变成'不检查'")
	}
}

// ============ 策略层: fail-open 与计数 ============

func TestPolicy_三种结论的处置(t *testing.T) {
	cases := []struct {
		name       string
		checker    BreachChecker
		wantAdvice PasswordAdvice
		wantEvents []EventKind
	}{
		{
			name:       "命中 → 警告放行 + INFO 事件",
			checker:    stubChecker{res: BreachResult{Verdict: BreachFound, Count: 42}},
			wantAdvice: PasswordAdvice{Breached: true, BreachCount: 42, Checked: true},
			wantEvents: []EventKind{EventPasswordBreached},
		},
		{
			name:       "⭐ 查不了 → 放行, 但必须留下可计数的痕迹",
			checker:    stubChecker{res: BreachResult{Verdict: BreachUnknown}, err: errStub},
			wantAdvice: PasswordAdvice{Checked: false},
			wantEvents: []EventKind{EventBreachCheckUnavailable},
		},
		{
			name:       "未启用 → 放行, ⛔ 不发事件(每次都会发生, 记了就是噪声)",
			checker:    NewNoopBreachChecker(),
			wantAdvice: PasswordAdvice{Checked: false},
			wantEvents: nil,
		},
		{
			name:       "干净 → 放行, 不发事件",
			checker:    stubChecker{res: BreachResult{Verdict: BreachClean}},
			wantAdvice: PasswordAdvice{Checked: true},
			wantEvents: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []EventKind
			p := NewPasswordPolicy(
				WithBreachChecker(c.checker),
				WithPolicyAudit(func(_ context.Context, e AuditEvent) {
					got = append(got, e.Kind)
				}),
			)
			adv := p.EvaluateNewPassword(context.Background(), "x")
			if adv != c.wantAdvice {
				t.Errorf("advice = %+v, want %+v", adv, c.wantAdvice)
			}
			if len(got) != len(c.wantEvents) {
				t.Fatalf("事件数 = %d %v, want %d %v", len(got), got, len(c.wantEvents), c.wantEvents)
			}
			for i := range got {
				if got[i] != c.wantEvents[i] {
					t.Errorf("事件[%d] = %s, want %s", i, got[i], c.wantEvents[i])
				}
			}
		})
	}
}

// TestPolicy_默认是noop且字段非nil 守的是"本地与生产同一条代码路径"。
func TestPolicy_默认是noop且字段非nil(t *testing.T) {
	p := NewPasswordPolicy()
	if p.breach == nil {
		t.Fatal("⛔ breach 为 nil —— 调用点就会被迫写 if != nil, " +
			"于是本地跑到的是另一条路径, 线上才第一次执行检查代码")
	}
	if p.BreachKind() != "noop" {
		t.Errorf("默认实现应为 noop, got %s", p.BreachKind())
	}
	// ⭐ 默认实现下也必须能安全调用, 不 panic 不报错
	if adv := p.EvaluateNewPassword(context.Background(), "x"); adv.Checked {
		t.Error("noop 下 Checked 应为 false —— ⛔ 不得让前端以为'检查过且安全'")
	}
}

type stubChecker struct {
	res BreachResult
	err error
}

func (s stubChecker) Check(context.Context, string) (BreachResult, error) { return s.res, s.err }
func (s stubChecker) Kind() string                                        { return "stub" }

var errStub = &stubError{}

type stubError struct{}

func (*stubError) Error() string { return "上游炸了" }
