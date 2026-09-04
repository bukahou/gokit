package localauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ============ 测试脚手架 ============

func mustGuard(t *testing.T, opts ...Option) *Guard {
	t.Helper()
	base := []Option{WithCost(bcrypt.MinCost)}
	g, err := New(TrustCloudflare(), AdmitAll(), NewMemStore(), NewMemStore(), append(base, opts...)...)
	if err != nil {
		t.Fatalf("构造守卫失败: %v", err)
	}
	return g
}

func reqFrom(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	r.Header.Set(headerCFConnectingIP, ip)
	return r
}

// lookupOf 造一个只认识 known 里那些用户的 LookupFunc。
func lookupOf(t *testing.T, cost int, known map[string]string) LookupFunc {
	t.Helper()
	hashes := map[string]string{}
	for u, pw := range known {
		h, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
		if err != nil {
			t.Fatal(err)
		}
		hashes[u] = string(h)
	}
	return func(_ context.Context, u string) (string, bool, error) {
		h, ok := hashes[u]
		return h, ok, nil
	}
}

// ============ 构造期必填 ============

func TestNew_四个参数必填(t *testing.T) {
	ok := func() (ClientIPStrategy, Admission, FailureStore, FailureStore) {
		return TrustCloudflare(), AdmitAll(), NewMemStore(), NewMemStore()
	}

	t.Run("缺信任源", func(t *testing.T) {
		_, a, s1, s2 := ok()
		if _, err := New(nil, a, s1, s2); CodeOf(err) != CodeMisconfigured {
			t.Errorf("期望 %q, 得到 %q", CodeMisconfigured, CodeOf(err))
		}
	})
	t.Run("缺准入", func(t *testing.T) {
		i, _, s1, s2 := ok()
		if _, err := New(i, nil, s1, s2); CodeOf(err) != CodeMisconfigured {
			t.Error("缺 Admission 应当拒绝构造")
		}
	})
	t.Run("两个维度共用一个 store", func(t *testing.T) {
		i, a, s1, _ := ok()
		if _, err := New(i, a, s1, s1); CodeOf(err) != CodeMisconfigured {
			t.Error("两个维度共用一个 store 等价于合成复合键, 应当拒绝构造")
		}
	})
	t.Run("四个都在则成功", func(t *testing.T) {
		i, a, s1, s2 := ok()
		if _, err := New(i, a, s1, s2, WithCost(bcrypt.MinCost)); err != nil {
			t.Errorf("期望构造成功: %v", err)
		}
	})
}

func TestNew_dummy按当前cost现生成(t *testing.T) {
	for _, c := range []int{bcrypt.MinCost, 6} {
		g := mustGuard(t, WithCost(c))
		got, ok := costOf(g.dummyHash)
		if !ok || got != c {
			t.Errorf("cost=%d 时 dummy 的 cost = %d (ok=%v), 二者必须同源于一次构造", c, got, ok)
		}
	}
}

// ============ 客户端身份来源 ============

func TestTrustCloudflare(t *testing.T) {
	s := TrustCloudflare()

	cases := []struct {
		name    string
		setup   func(*http.Request)
		want    string
		wantErr bool
	}{
		{"正常", func(r *http.Request) { r.Header.Set(headerCFConnectingIP, "203.0.113.7") }, "203.0.113.7", false},
		{"头缺失必须报错", func(*http.Request) {}, "", true},
		{"头非法必须报错", func(r *http.Request) { r.Header.Set(headerCFConnectingIP, "not-an-ip") }, "", true},
		{
			"⭐ 伪造 XFF 必须被忽略",
			func(r *http.Request) {
				r.Header.Set(headerCFConnectingIP, "203.0.113.7")
				r.Header.Set("X-Forwarded-For", "1.2.3.4")
				r.Header.Set("X-Real-IP", "5.6.7.8")
			},
			"203.0.113.7", false,
		},
		{
			"⭐ 只有伪造的 XFF 时必须报错, ⛔ 不得回退",
			func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "1.2.3.4")
			},
			"", true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/login", nil)
			r.RemoteAddr = "10.0.0.1:12345" // ⛔ 回退到它就说明实现错了
			c.setup(r)

			got, err := s.ClientIP(r)
			if c.wantErr {
				if err == nil {
					t.Fatalf("期望报错, 得到 %q —— 静默回退会让限流键可伪造或坍缩", got)
				}
				if CodeOf(err) != CodeClientIPUnavailable {
					t.Errorf("期望码 %q, 得到 %q", CodeClientIPUnavailable, CodeOf(err))
				}
				return
			}
			if err != nil {
				t.Fatalf("未期望的错误: %v", err)
			}
			if got != c.want {
				t.Errorf("得到 %q, 期望 %q", got, c.want)
			}
		})
	}
}

// ============ 编排 ============

func TestLogin_基本(t *testing.T) {
	g := mustGuard(t)
	lookup := lookupOf(t, bcrypt.MinCost, map[string]string{"alice": "correct-horse"})

	t.Run("密码对则放行", func(t *testing.T) {
		out, err := g.Login(context.Background(), reqFrom("203.0.113.1"), "alice", "correct-horse", lookup)
		if err != nil || !out.Allowed {
			t.Fatalf("期望放行, 得到 out=%v err=%v", out, err)
		}
	})
	t.Run("密码错则拒", func(t *testing.T) {
		_, err := g.Login(context.Background(), reqFrom("203.0.113.2"), "alice", "wrong", lookup)
		if CodeOf(err) != CodeInvalidCredentials {
			t.Fatalf("期望 %q, 得到 %q", CodeInvalidCredentials, CodeOf(err))
		}
	})
	t.Run("用户不存在也是同一个码", func(t *testing.T) {
		_, err := g.Login(context.Background(), reqFrom("203.0.113.3"), "nobody", "whatever", lookup)
		if CodeOf(err) != CodeInvalidCredentials {
			t.Fatalf("期望 %q, 得到 %q", CodeInvalidCredentials, CodeOf(err))
		}
	})
}

// TestLogin_查用户故障必须是独立的码 —— 否则一次数据库故障在监控里
// 长得跟「所有人密码都输错了」一模一样。
func TestLogin_查用户故障必须是独立的码(t *testing.T) {
	g := mustGuard(t)
	boom := func(context.Context, string) (string, bool, error) {
		return "", false, errBoom{}
	}
	_, err := g.Login(context.Background(), reqFrom("203.0.113.9"), "alice", "x", boom)
	if CodeOf(err) != CodeLookupUnavailable {
		t.Fatalf("期望 %q, 得到 %q —— 并入凭据失败会让故障不可观测",
			CodeLookupUnavailable, CodeOf(err))
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "boom" }

// ⭐ TestLogin_成功优先于账号退避
//
// 这是本编排里最容易写反的一步。若把账号退避判定放在成功判定之前,
// 合法用户输入【正确密码】也走不到 Reset —— 计数只能靠窗口自然过期,
// 而攻击者在窗口一过补一次失败即重新压住。
func TestLogin_成功优先于账号退避(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	g := mustGuard(t,
		WithPolicy(BackoffPolicy{Threshold: 3, Ceiling: 10, DecayInterval: time.Hour}),
		WithClock(func() time.Time { return now }),
	)
	lookup := lookupOf(t, bcrypt.MinCost, map[string]string{"alice": "correct-horse"})
	ctx := context.Background()

	// 攻击者从三个不同 IP 把 alice 的账号计数打到阈值 (换 IP 是为了不撞 IP 维度)。
	for i := 0; i < 3; i++ {
		_, _ = g.Login(ctx, reqFrom("198.51.100."+strconv.Itoa(i)), "alice", "wrong", lookup)
	}
	if st, _ := g.acctStore.Peek(ctx, "alice"); !g.policy.Blocked(st, now) {
		t.Fatalf("前置条件不成立: alice 应已处于退避中, 当前 count=%d", st.Count)
	}

	// 合法用户从自己的 IP 拿【正确密码】登录 —— 必须成功, 且计数清零。
	out, err := g.Login(ctx, reqFrom("203.0.113.50"), "alice", "correct-horse", lookup)
	if err != nil || !out.Allowed {
		t.Fatalf("账号处于退避中时, 正确密码【必须】仍能登入并解锁, 否则任何账号都可被廉价压住: out=%v err=%v", out, err)
	}
	if st, _ := g.acctStore.Peek(ctx, "alice"); st.Count != 0 {
		t.Errorf("成功登录后账号计数应清零, 当前 count=%d", st.Count)
	}
}

// ⭐ TestLogin_退避中被拒不得再计数 —— akasha 的 (乙)。
//
// 若在退避分支里 Bump, 攻击者持续打一个账号就能让计数无上限增长、
// 退避窗口指数拉长, 账号被永久锁死。
func TestLogin_退避中被拒不得再计数(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	g := mustGuard(t,
		WithPolicy(BackoffPolicy{Threshold: 3, Ceiling: 10, DecayInterval: time.Hour}),
		WithClock(func() time.Time { return now }),
	)
	lookup := lookupOf(t, bcrypt.MinCost, map[string]string{"alice": "correct-horse"})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, _ = g.Login(ctx, reqFrom("198.51.100."+strconv.Itoa(i)), "alice", "wrong", lookup)
	}
	before, _ := g.acctStore.Peek(ctx, "alice")

	// 再打 5 次, 每次都在退避中被拒 —— 计数必须【一动不动】。
	for i := 0; i < 5; i++ {
		_, _ = g.Login(ctx, reqFrom("198.51.100.2"+strconv.Itoa(i)), "alice", "wrong", lookup)
	}
	after, _ := g.acctStore.Peek(ctx, "alice")

	if after.Count != before.Count {
		t.Fatalf("退避中被拒的请求不得计数: 之前 %d, 之后 %d —— 否则账号可被永久锁死",
			before.Count, after.Count)
	}
}

// TestLogin_不存在的用户名同样计数 —— 否则计数器自己就是枚举预言机。
func TestLogin_不存在的用户名同样计数(t *testing.T) {
	g := mustGuard(t)
	lookup := lookupOf(t, bcrypt.MinCost, map[string]string{"alice": "pw"})
	ctx := context.Background()

	_, _ = g.Login(ctx, reqFrom("203.0.113.77"), "no-such-user", "x", lookup)

	st, _ := g.acctStore.Peek(ctx, "no-such-user")
	if st.Count != 1 {
		t.Fatalf("不存在的用户名也必须计数, 当前 count=%d —— 否则「有没有被计数」本身泄漏账号是否存在", st.Count)
	}
}

// TestLogin_IP维度在bcrypt之前拒绝 —— 这是本层唯一能省下 bcrypt 的地方。
func TestLogin_IP维度在bcrypt之前拒绝(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	// 用真实 cost, 这样「有没有烧 bcrypt」在耗时上可分辨。
	g := mustGuard(t,
		WithCost(10),
		WithPolicy(BackoffPolicy{Threshold: 3, Ceiling: 10, DecayInterval: time.Hour}),
		WithClock(func() time.Time { return now }),
	)
	lookup := lookupOf(t, 10, map[string]string{"alice": "pw"})
	ctx := context.Background()
	const ip = "203.0.113.88"

	for i := 0; i < 3; i++ {
		_, _ = g.Login(ctx, reqFrom(ip), "u"+strconv.Itoa(i), "x", lookup)
	}

	start := time.Now()
	_, _ = g.Login(ctx, reqFrom(ip), "alice", "x", lookup)
	elapsed := time.Since(start)

	if elapsed > 5*time.Millisecond {
		t.Fatalf("IP 处于退避中时不应再烧 bcrypt, 实测耗时 %v —— CPU 面没有得到保护", elapsed)
	}
}

// ============ ⭐ 内容哨兵 ============

// TestContentSentinel 断言: 任何两组【只在凭据内容上不同】的输入, 响应必须相同。
//
// ⚠️ 每组输入落在互不相同的限流键上 (不同 IP), ⛔ 不靠「组数少于阈值」侥幸通过 ——
// 那会让哨兵的正确性依赖一个它不控制的参数。
//
// 它写得出来只需要知道「这是一个认证端点」, ⛔ 不需要知道有几条失败路径,
// 更不需要知道存在「账号有没有本地密码」这回事 —— 这正是哨兵与针对性测试的区别。
func TestContentSentinel(t *testing.T) {
	g := mustGuard(t)
	ctx := context.Background()

	realHash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	lookup := func(_ context.Context, u string) (string, bool, error) {
		switch u {
		case "alice":
			return string(realHash), true, nil
		case "federated": // 账号存在但没有本地密码 —— 联邦账号
			return "", true, nil
		default:
			return "", false, nil
		}
	}

	inputs := []struct{ user, pass string }{
		{"nobody", "x"},                      // 不存在
		{"alice", "wrong"},                   // 存在 + 密码错
		{"federated", "anything"},            // ⭐ 存在但无本地密码
		{"", ""},                             // 空用户名空口令
		{"alice", ""},                        // 空口令
		{"ALICE", "wrong"},                   // 大小写变体
		{"alice", string(make([]byte, 200))}, // 超长口令
	}

	seen := map[string]bool{}
	for i, in := range inputs {
		// ⭐ 每组一个独立 IP —— 否则限流会在组间生效, 哨兵就会在
		//    「防护正常工作」时误报, 而一个会误报的哨兵会被删掉。
		_, err := g.Login(ctx, reqFrom("192.0.2."+strconv.Itoa(i+1)), in.user, in.pass, lookup)
		seen[string(CodeOf(err))] = true
	}

	if len(seen) != 1 {
		keys := make([]string, 0, len(seen))
		for k := range seen {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Fatalf("⛔ 响应集合基数 %d ≠ 1: %v —— 凭据相关的失败必须无法区分", len(seen), keys)
	}
	if !seen[string(CodeInvalidCredentials)] {
		t.Fatalf("唯一的那个码应当是 %q", CodeInvalidCredentials)
	}
}

// ============ ⭐ 绝对下界 + 反向验证 ============

const 绝对下界 = 5 * time.Millisecond

// pathTimings 量三条凭据相关路径的耗时。
func pathTimings(t *testing.T, verify func(hash, plain string) bool, realHash, dummy string) map[string]time.Duration {
	t.Helper()
	paths := map[string]string{
		"用户不存在(走 dummy)": dummy,
		"存在+密码错":         realHash,
		"存在但无本地密码":       "", // 联邦账号: hash 为空
	}
	out := map[string]time.Duration{}
	for name, h := range paths {
		if h == "" {
			h = dummy // 正确实现会用 dummy 兜住这一条
		}
		start := time.Now()
		verify(h, "guess")
		out[name] = time.Since(start)
	}
	return out
}

// TestAbsoluteLowerBound 断言每条凭据相关路径都【真的干了活】。
//
// ⚠️ 下界是【绝对值】, ⛔ 不得取自被检查路径中的任何一条 ——
// 若基准来自路径之一, 那条路径退化时基准也退化, 三条会一起「通过」。
// 5ms 与缺陷态 (20ns~0) 之间隔着五个数量级, 没有需要调参的灰区。
func TestAbsoluteLowerBound(t *testing.T) {
	g := mustGuard(t, WithCost(10)) // 真实 cost, 单次约 36ms
	realHash, _ := bcrypt.GenerateFromPassword([]byte("pw"), 10)

	for name, d := range pathTimings(t, g.verify, string(realHash), g.dummyHash) {
		if d < 绝对下界 {
			t.Errorf("路径 %q 耗时 %v < 绝对下界 %v —— 该路径被调用了但没干活", name, d, 绝对下界)
		}
	}
}

// ⭐ TestAbsoluteLowerBound_反向验证 —— 这条检查必须见过它红一次。
//
// 造一个「dummy 是空串」的变体: 它仍然满足「唯一调用点且支配所有返回」,
// bcrypt 却会在 20ns 内报 hash 太短返回。若绝对下界抓不住它, 那条检查是摆设。
func TestAbsoluteLowerBound_反向验证(t *testing.T) {
	mutant := &Guard{cost: 10, dummyHash: ""} // ⛔ 非法 dummy

	start := time.Now()
	mutant.verify(mutant.dummyHash, "guess")
	elapsed := time.Since(start)

	if elapsed >= 绝对下界 {
		t.Fatalf("变异体本应在纳秒级返回, 实测 %v —— 说明这条反向验证失效了", elapsed)
	}
	// 到这里说明: 变异体确实快得离谱, 而 TestAbsoluteLowerBound 会因此 FAIL。
	t.Logf("✅ 变异体耗时 %v, 远低于下界 %v —— 绝对下界检查抓得住它", elapsed, 绝对下界)
}

// ⭐ TestContentSentinel_反向验证 —— 演示「错误不坍缩」会怎样泄漏。
//
// 正确实现里 verify 返回 bool, 错误在调用点原地坍缩。若让错误逃出去,
// 「账号存在但无本地密码」得到的是 ErrHashTooShort 而非 ErrMismatched...,
// 调用方的兜底分支就会把它映射成另一个状态码 —— 一次请求即可读出。
func TestContentSentinel_反向验证(t *testing.T) {
	realHash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)

	// 模拟「错误逃出调用点」的实现。
	leaky := func(hash, plain string) error {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
	}

	errMismatch := leaky(string(realHash), "wrong") // 密码错
	errEmptyHash := leaky("", "wrong")              // 联邦账号

	if errMismatch == nil || errEmptyHash == nil {
		t.Fatal("两条都应当失败")
	}
	if errMismatch.Error() == errEmptyHash.Error() {
		t.Fatal("两条错误本应不同 —— 若相同, 这条反向验证就失效了")
	}
	t.Logf("✅ 错误若不坍缩, 两条路径分别得到 %q 与 %q —— 调用方兜底分支会把后者映射成另一个状态码",
		errMismatch, errEmptyHash)
}

// ============ 准入 ============

func TestAdmission(t *testing.T) {
	ctx := context.Background()

	t.Run("AdmitAll 放行", func(t *testing.T) {
		if err := AdmitAll().Admit(ctx, AdmitRequest{Email: "a@b.com"}); err != nil {
			t.Error(err)
		}
	})
	t.Run("AdmitNone 拒绝", func(t *testing.T) {
		if CodeOf(AdmitNone().Admit(ctx, AdmitRequest{})) != CodeAdmissionDenied {
			t.Error("AdmitNone 应当拒绝")
		}
	})
	t.Run("⭐ 空白名单 = 拒绝所有, 而不是放行所有", func(t *testing.T) {
		if CodeOf(AdmitEmailDomains().Admit(ctx, AdmitRequest{Email: "a@b.com"})) != CodeAdmissionDenied {
			t.Error("空白名单必须拒绝 —— 解释成放行会让「配置写漏了」变成「门大开着」")
		}
	})
	t.Run("域名命中放行, 未命中拒绝", func(t *testing.T) {
		a := AdmitEmailDomains("example.com")
		if err := a.Admit(ctx, AdmitRequest{Email: "u@Example.COM"}); err != nil {
			t.Errorf("大小写不同的同一域名应当放行: %v", err)
		}
		if a.Admit(ctx, AdmitRequest{Email: "u@evil.com"}) == nil {
			t.Error("未命中的域名应当拒绝")
		}
	})
}
