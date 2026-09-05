package localauth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func activeStatus(context.Context, string) (AccountStatus, error) {
	return AccountStatus{Active: true}, nil
}

func newSessionGuard(t *testing.T, status AccountStatusFunc, opts ...SessionOption) (*SessionGuard, SessionStore) {
	t.Helper()
	store := NewSessionMemStore()
	g, err := NewSessionGuard(store, status, time.Hour, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return g, store
}

// ============ 构造期必填 ============

func TestNewSessionGuard_必填(t *testing.T) {
	store := NewSessionMemStore()
	t.Run("缺 store", func(t *testing.T) {
		if _, err := NewSessionGuard(nil, activeStatus, time.Hour); CodeOf(err) != CodeMisconfigured {
			t.Error("缺 SessionStore 应当拒绝构造")
		}
	})
	t.Run("⭐ 缺状态复查函数", func(t *testing.T) {
		// ⛔ 不给它"永远返回 Active"的默认实现 —— 那会让 7.7 静默失效,
		// 而失效的表现是"被封禁的用户还能刷新", 没有任何症状。
		if _, err := NewSessionGuard(store, nil, time.Hour); CodeOf(err) != CodeMisconfigured {
			t.Error("缺 AccountStatusFunc 应当拒绝构造 —— 否则 7.7 会静默失效")
		}
	})
	t.Run("TTL 非正", func(t *testing.T) {
		if _, err := NewSessionGuard(store, activeStatus, 0); CodeOf(err) != CodeMisconfigured {
			t.Error("refreshTTL 必须为正")
		}
	})
}

// ============ 轮换 ============

// ⭐ TestRefresh_用一次即轮换 (§7.6)
func TestRefresh_用一次即轮换(t *testing.T) {
	g, _ := newSessionGuard(t, activeStatus)
	ctx := context.Background()

	tok, _, err := g.Issue(ctx, SessionRecord{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}

	out, err := g.Refresh(ctx, tok)
	if err != nil {
		t.Fatalf("首次刷新应当成功: %v", err)
	}
	if out.NewRefreshToken == "" {
		t.Fatal("刷新必须返回【新的】refresh token —— 不返回的话客户端无从更新")
	}
	if out.NewRefreshToken == tok {
		t.Fatal("轮换后的 token 与旧的相同 —— 那不叫轮换")
	}

	// 新的能用
	if _, err := g.Refresh(ctx, out.NewRefreshToken); err != nil {
		t.Errorf("轮换出的新 token 应当可用: %v", err)
	}
}

// ⭐⭐ TestRefresh_重放即吊销全部会话
//
// # 这条是本文件最重要的一条
//
// ⚠️ 判据是【两件事一起】: 拒绝这一次 + 该用户全部会话被吊销。
// 只验"拒绝"的话，一个只拒绝不吊销的实现同样能通过 —— 而那正是错的那种:
//
//	攻击者偷到 refresh 先用 → 合法方后用被拒、自己重登
//	→ ⛔ 攻击者那条链完好无损，可以一直续到 TTL 结束
//
// 也就是说不吊销的话，重放检测把【受害者】踢出去而把攻击者留下。
func TestRefresh_重放即吊销全部会话(t *testing.T) {
	var events []AuditEvent
	g, store := newSessionGuard(t, activeStatus,
		WithSessionAudit(func(_ context.Context, e AuditEvent) { events = append(events, e) }))
	ctx := context.Background()

	// 同一用户三条会话 (三台设备)
	tokA, _, _ := g.Issue(ctx, SessionRecord{UserID: "u1", DeviceInfo: "A"})
	_, _, _ = g.Issue(ctx, SessionRecord{UserID: "u1", DeviceInfo: "B"})
	_, _, _ = g.Issue(ctx, SessionRecord{UserID: "u1", DeviceInfo: "C"})
	// 另一个用户的会话 —— ⛔ 不得被牵连
	tokOther, _, _ := g.Issue(ctx, SessionRecord{UserID: "u2"})

	if n, _ := store.ListByUser(ctx, "u1"); len(n) != 3 {
		t.Fatalf("前置条件: u1 应有 3 条会话, 实际 %d", len(n))
	}

	// 攻击者(或并发方)先用 tokA 刷新一次 —— 成功, tokA 作废
	if _, err := g.Refresh(ctx, tokA); err != nil {
		t.Fatal(err)
	}
	// 合法方拿着已作废的 tokA 再来 —— 这就是重放
	if _, err := g.Refresh(ctx, tokA); CodeOf(err) != CodeInvalidCredentials {
		t.Fatalf("重放应当被拒且是凭据类错误, 得到 %v", err)
	}

	// ⭐ 判据①: u1 的【全部】会话被吊销
	left, _ := store.ListByUser(ctx, "u1")
	if len(left) != 0 {
		t.Fatalf("重放之后 u1 仍有 %d 条活会话 —— 只拒绝不吊销的话, "+
			"攻击者那条链会完好保留到 TTL 结束", len(left))
	}

	// ⭐ 判据②: ⛔ 别的用户不受牵连
	otherLeft, _ := store.ListByUser(ctx, "u2")
	if len(otherLeft) != 1 {
		t.Fatalf("u2 的会话被牵连吊销了 (剩 %d 条) —— 吊销范围必须限于该用户", len(otherLeft))
	}
	if _, err := g.Refresh(ctx, tokOther); err != nil {
		t.Errorf("u2 应当不受影响: %v", err)
	}

	// ⭐ 判据③: 必须有审计事件 —— 否则用户会遇到一次【无法解释】的全体登出
	var found bool
	for _, e := range events {
		if e.Kind == EventSessionReplayDetected {
			found = true
			t.Logf("审计事件: %s user=%s detail=%q", e.Kind, e.Username, e.Detail)
		}
	}
	if !found {
		t.Fatal("重放未发出 " + string(EventSessionReplayDetected) +
			" —— 那样用户会遇到一次无法解释的全体登出")
	}
}

// ⭐ TestRefresh_并发只有一方成功 (§7.6 并发防护)
func TestRefresh_并发只有一方成功(t *testing.T) {
	g, _ := newSessionGuard(t, activeStatus)
	ctx := context.Background()
	tok, _, _ := g.Issue(ctx, SessionRecord{UserID: "u1"})

	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	var okCount int
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := g.Refresh(ctx, tok); err == nil {
				mu.Lock()
				okCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if okCount != 1 {
		t.Fatalf("并发 %d 次刷新有 %d 次成功, 必须【正好 1 次】—— "+
			"多于 1 说明轮换不是原子的, 一条会话分裂成了多条", n, okCount)
	}
}

// ⭐ TestRefresh_存储故障不得当作重放
//
// ⚠️ 一次数据库抖动若被当成重放, 会导致一大批用户的全部会话被吊销 ——
// 那是把可用性故障放大成了安全事件。
func TestRefresh_存储故障不得当作重放(t *testing.T) {
	store := &failingRotateStore{SessionStore: NewSessionMemStore()}
	g, err := NewSessionGuard(store, activeStatus, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tok, _, _ := g.Issue(ctx, SessionRecord{UserID: "u1"})

	store.fail = true
	_, rerr := g.Refresh(ctx, tok)
	if CodeOf(rerr) != CodeLookupUnavailable {
		t.Fatalf("存储故障应当是 %q 而不是凭据失败, 得到 %q —— "+
			"并入凭据失败会让一次 DB 抖动变成大批用户被吊销",
			CodeLookupUnavailable, CodeOf(rerr))
	}
	store.fail = false

	// ⭐ 故障期间不得吊销任何东西
	left, _ := store.ListByUser(ctx, "u1")
	if len(left) != 1 {
		t.Errorf("存储故障导致会话被吊销了 (剩 %d 条)", len(left))
	}
}

type failingRotateStore struct {
	SessionStore
	fail bool
}

func (s *failingRotateStore) Rotate(ctx context.Context, o, n []byte, e time.Time) (SessionRecord, RotateOutcome, error) {
	if s.fail {
		return SessionRecord{}, RotateUnknown, errors.New("boom")
	}
	return s.SessionStore.Rotate(ctx, o, n, e)
}

// ============ 7.7 复查账号状态 ============

// ⭐ TestRefresh_封禁账号不得刷新
func TestRefresh_封禁账号不得刷新(t *testing.T) {
	banned := false
	g, store := newSessionGuard(t, func(context.Context, string) (AccountStatus, error) {
		return AccountStatus{Active: !banned}, nil
	})
	ctx := context.Background()
	tok, _, _ := g.Issue(ctx, SessionRecord{UserID: "u1"})

	// 未封禁时正常
	out, err := g.Refresh(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}

	banned = true
	if _, err := g.Refresh(ctx, out.NewRefreshToken); CodeOf(err) != CodeInvalidCredentials {
		t.Fatalf("封禁后刷新应当被拒, 得到 %v", err)
	}
	// ⭐ 而且这条会话要被吊销 —— 被封的账号不该留着活会话
	if left, _ := store.ListByUser(ctx, "u1"); len(left) != 0 {
		t.Errorf("封禁后该会话仍活着 (%d 条)", len(left))
	}
}

// ⭐ TestRefresh_改密时间戳吊销
//
// ⚠️ 比对的是【会话创建时间】而不是轮换后的时间 ——
// ⛔ 若拿轮换后的时间比, 改密后只要刷新一次就能"洗白"。
func TestRefresh_改密时间戳吊销(t *testing.T) {
	base := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	now := base
	var pwdChanged time.Time

	g, _ := newSessionGuard(t, func(context.Context, string) (AccountStatus, error) {
		return AccountStatus{Active: true, PasswordChangedAt: pwdChanged}, nil
	}, WithSessionClock(func() time.Time { return now }))
	ctx := context.Background()

	tok, _, _ := g.Issue(ctx, SessionRecord{UserID: "u1"}) // 建于 base

	// 改密发生在会话之后
	now = base.Add(time.Minute)
	pwdChanged = now

	if _, err := g.Refresh(ctx, tok); CodeOf(err) != CodeInvalidCredentials {
		t.Fatalf("会话建立于改密之前, 刷新应当被拒, 得到 %v", err)
	}

	// ⭐ 改密之后【新建】的会话不受影响
	now = base.Add(2 * time.Minute)
	tok2, _, _ := g.Issue(ctx, SessionRecord{UserID: "u1"})
	if _, err := g.Refresh(ctx, tok2); err != nil {
		t.Errorf("改密后新建的会话应当可用: %v", err)
	}
}

// ============ 登出 / 会话列表 ============

func TestLogout(t *testing.T) {
	g, _ := newSessionGuard(t, activeStatus)
	ctx := context.Background()
	tok, _, _ := g.Issue(ctx, SessionRecord{UserID: "u1"})

	if err := g.Logout(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Refresh(ctx, tok); err == nil {
		t.Fatal("登出后 refresh 仍然可用")
	}
	// ⚠️ 登出是幂等的, 且"这个 token 存不存在"不该泄漏
	if err := g.Logout(ctx, "从来不存在的 token"); err != nil {
		t.Errorf("登出不存在的 token 不应报错: %v", err)
	}
}

// ⭐ TestList_必须标出当前会话
func TestList_必须标出当前会话(t *testing.T) {
	g, _ := newSessionGuard(t, activeStatus)
	ctx := context.Background()
	_, _, _ = g.Issue(ctx, SessionRecord{UserID: "u1", DeviceInfo: "A"})
	_, _, _ = g.Issue(ctx, SessionRecord{UserID: "u1", DeviceInfo: "B"})

	recs, err := g.List(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("期望 2 条会话, 得到 %d", len(recs))
	}
	// ⭐ "当前会话是哪条"由调用方用 access token 的 sid claim 判定,
	// ⛔ 不由本模块猜, 也⛔不要求客户端把 refresh 明文传上来。
	// 这里只验列表里确实带着可用于判定的 ID。
	for _, r := range recs {
		if r.ID == "" {
			t.Error("会话记录缺少 ID —— 前端无从判定哪条是当前, 也无从逐条登出")
		}
	}
}

// ⭐ TestRevokeOthers_必须保留当前会话
func TestRevokeOthers_必须保留当前会话(t *testing.T) {
	g, store := newSessionGuard(t, activeStatus)
	ctx := context.Background()
	tokA, recA, _ := g.Issue(ctx, SessionRecord{UserID: "u1", DeviceInfo: "A"})
	_, _, _ = g.Issue(ctx, SessionRecord{UserID: "u1", DeviceInfo: "B"})
	_, _, _ = g.Issue(ctx, SessionRecord{UserID: "u1", DeviceInfo: "C"})

	n, err := g.RevokeOthers(ctx, "u1", recA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("应当吊销 2 条, 实际 %d", n)
	}

	left, _ := store.ListByUser(ctx, "u1")
	if len(left) != 1 || left[0].DeviceInfo != "A" {
		t.Fatalf("当前会话没被保留 —— 用户点完自己也掉线了。剩余: %+v", left)
	}
	// ⭐ 当前会话仍能刷新
	if _, err := g.Refresh(ctx, tokA); err != nil {
		t.Errorf("当前会话应当仍可用: %v", err)
	}
}

// ⭐ TestRevokeOne_必须防 IDOR
func TestRevokeOne_必须防IDOR(t *testing.T) {
	g, store := newSessionGuard(t, activeStatus)
	ctx := context.Background()
	_, _, _ = g.Issue(ctx, SessionRecord{UserID: "victim"})
	victimSessions, _ := store.ListByUser(ctx, "victim")
	if len(victimSessions) != 1 {
		t.Fatal("前置条件不成立")
	}

	// 攻击者拿着受害者的 session id 来吊销
	if err := g.RevokeOne(ctx, "attacker", victimSessions[0].ID); err != nil {
		t.Fatal(err)
	}
	left, _ := store.ListByUser(ctx, "victim")
	if len(left) != 1 {
		t.Fatal("⛔ 越权吊销成功了 —— RevokeByID 必须同时匹配 userID, " +
			"只按 sessionID 删是一个 IDOR")
	}
}

// ============ ⭐ 重放 vs 正常失效 (2026-09-05 生产缺陷) ============
//
// 这一组测试守的是一条【处置相反】的分叉:
//
//	命中 prev 哈希(被换走过) → 重放 → 吊销该用户全部会话
//	命中当前哈希(会话已死)   → 正常 → 只拒绝这一次
//
// ⚠️ 在 2026-09-05 之前 Rotate 只返回一个 bool, 两者合流成"当作重放",
// 于是"登出其它设备"变成了"几秒后全员掉线"。生产实测:
//
//	A 登出其它设备 → A 刷新 200 → B(已被登出) 刷新 401
//	→ ⛔ A 再刷新 401, DB 有效会话归 0
//
// ⛔ 这几个测试红了不要改测试, 那说明分叉又被合流了。

// TestRefresh_登出后再刷新_不得吊销其它会话 是上面那个生产缺陷的最小复现。
func TestRefresh_登出后再刷新_不得吊销其它会话(t *testing.T) {
	g, store := newSessionGuard(t, activeStatus)
	ctx := context.Background()

	// 同一用户两条会话: A(自己) 与 B(另一台设备)。
	tokA, _, err := g.Issue(ctx, SessionRecord{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	tokB, _, err := g.Issue(ctx, SessionRecord{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}

	// B 登出。⭐ 注意 B 的 token 【没有被轮换过】—— 它只是失效了。
	if err := g.Logout(ctx, tokB); err != nil {
		t.Fatal(err)
	}

	// B 那台设备做一次例行后台刷新 —— 这是【正常使用中必然发生】的事。
	if _, err := g.Refresh(ctx, tokB); CodeOf(err) != CodeInvalidCredentials {
		t.Fatalf("已登出的 token 刷新应被拒, got %v", err)
	}

	// ⭐⭐ 核心断言: A 必须【毫发无伤】。
	if _, err := g.Refresh(ctx, tokA); err != nil {
		t.Fatalf("⛔ A 的会话被连坐吊销了 —— "+
			"一次正常的登出后刷新不得触发 RevokeAllByUser: %v", err)
	}

	sessions, err := store.ListByUser(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Errorf("u1 应剩 1 条有效会话(A), got %d", len(sessions))
	}
}

// TestRefresh_登出其它设备后_当前会话存活 复现的是用户可见的那个症状:
// 点了"登出其它设备", 结果自己也掉线。
func TestRefresh_登出其它设备后_当前会话存活(t *testing.T) {
	g, store := newSessionGuard(t, activeStatus)
	ctx := context.Background()

	tokA, recA, err := g.Issue(ctx, SessionRecord{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	tokB, _, err := g.Issue(ctx, SessionRecord{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	tokC, _, err := g.Issue(ctx, SessionRecord{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}

	n, err := g.RevokeOthers(ctx, "u1", recA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("应登出 2 条(B/C), got %d", n)
	}

	// ⚠️ B 与 C 各做一次后台刷新 —— 现实里这几乎一定会发生。
	for name, tok := range map[string]string{"B": tokB, "C": tokC} {
		if _, err := g.Refresh(ctx, tok); CodeOf(err) != CodeInvalidCredentials {
			t.Fatalf("%s 已被登出, 刷新应被拒, got %v", name, err)
		}
	}

	// ⭐⭐ A 仍然必须能刷新。这正是 RevokeOthers 存在的意义。
	if _, err := g.Refresh(ctx, tokA); err != nil {
		t.Fatalf("⛔ 点了'登出其它设备'的人自己掉线了 —— "+
			"被登出设备的例行刷新把当前会话也吊销了: %v", err)
	}
	sessions, _ := store.ListByUser(ctx, "u1")
	if len(sessions) != 1 {
		t.Errorf("应只剩当前会话, got %d", len(sessions))
	}
}

// TestRefresh_真重放仍然吊销全部 守的是【另一侧】——
// ⛔ 修上面那个缺陷不得把重放检测一起关掉。
func TestRefresh_真重放仍然吊销全部(t *testing.T) {
	g, store := newSessionGuard(t, activeStatus)
	ctx := context.Background()

	// u1 有两条会话: 被盗的 stolen, 以及另一台设备 other。
	stolen, _, err := g.Issue(ctx, SessionRecord{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Issue(ctx, SessionRecord{UserID: "u1"}); err != nil {
		t.Fatal(err)
	}

	// 攻击者先用 stolen 换到新的 —— 现在 stolen 落在 prev 上。
	if _, err := g.Refresh(ctx, stolen); err != nil {
		t.Fatal(err)
	}

	// ⭐ 合法客户端随后拿着 stolen 来 —— 这就是重放的真实形态。
	if _, err := g.Refresh(ctx, stolen); CodeOf(err) != CodeInvalidCredentials {
		t.Fatalf("重放应被拒, got %v", err)
	}

	// ⭐⭐ 该用户【全部】会话被吊销, 攻击者手里那条新 token 一并作废。
	sessions, err := store.ListByUser(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Errorf("⛔ 重放检测未吊销全部会话, 攻击者那条链还活着: 剩 %d 条", len(sessions))
	}
}

// TestRefresh_事件分级 断言两种失败发的【不是同一个事件】——
// 否则告警会被正常登出的噪声淹掉。
func TestRefresh_事件分级(t *testing.T) {
	var mu sync.Mutex
	var kinds []EventKind
	hook := func(_ context.Context, e AuditEvent) {
		mu.Lock()
		kinds = append(kinds, e.Kind)
		mu.Unlock()
	}
	g, _ := newSessionGuard(t, activeStatus, WithSessionAudit(hook))
	ctx := context.Background()

	tok, _, err := g.Issue(ctx, SessionRecord{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Logout(ctx, tok); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	kinds = nil
	mu.Unlock()

	_, _ = g.Refresh(ctx, tok) // 已登出 → 应记 refresh_rejected
	_, _ = g.Refresh(ctx, "完全不存在的-token")

	mu.Lock()
	defer mu.Unlock()
	for _, k := range kinds {
		if k == EventSessionReplayDetected {
			t.Errorf("⛔ 正常登出/查无来历被记成了 %s —— "+
				"这类事件在正常使用中大量发生, 记成安全事件会淹掉真的重放", k)
		}
		if k != EventSessionRefreshRejected {
			t.Errorf("预期 %s, got %s", EventSessionRefreshRejected, k)
		}
	}
	if len(kinds) != 2 {
		t.Errorf("两次被拒的刷新应各发一个事件, got %d", len(kinds))
	}
}

// TestRotateOutcome_零值是最保守的那一侧 守的是"默认值不得通向破坏力"。
func TestRotateOutcome_零值是最保守的那一侧(t *testing.T) {
	var zero RotateOutcome
	if zero != RotateUnknown {
		t.Fatalf("⛔ RotateOutcome 的零值必须是 RotateUnknown, got %v", zero)
	}
	// ⚠️ 若零值是 RotateReplayed, 任何忘了赋值的实现都会把
	// "每一次刷新失败" 变成 "吊销该用户全部会话"。
	if zero == RotateReplayed || zero == RotateRotated {
		t.Error("⛔ 零值不得是 Replayed(有破坏力) 或 Rotated(等于放行)")
	}
}

// TestRefresh_改密判据必须是Before而不是不After ⭐ 钉死一个【裕度为零】的语义。
//
// # 为什么这条值得单独测
//
// §7.7 判据: session.CreatedAt.Before(PasswordChangedAt) → 失效。
//
// 改密流程是"吊销全部 → 立即为当前设备重签"。重签出的会话 CreatedAt
// 与 password_changed_at 相隔【几毫秒】, 而 DB 的 datetime 是秒精度 ——
// 截断之后两者【相等】。实测(真库, 连跑 5 次)每一次都相等。
//
// ⛔ 所以"相等不算失效"是重签会话能活下来的【唯一依据】, 裕度是零。
// 谁把判据改成 `!After`(让相等也算失效), 每一个重签出来的会话都会当场作废,
// 症状是"改完密码立刻掉线" —— 100% 复现, 而改判据的人多半以为
// 自己只是"把边界收严一点"。
//
// ⚠️ 端到端那条测试(internal/user/service)能覆盖这个, 但它要 DSN,
// CI 会跳过。所以这条必须在这里, 用内存 store 也能跑。
func TestRefresh_改密判据必须是Before而不是不After(t *testing.T) {
	fixed := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	// ⭐ 会话创建时刻与改密时刻【完全相等】—— 模拟秒精度截断后的真实情形。
	status := func(context.Context, string) (AccountStatus, error) {
		return AccountStatus{Active: true, PasswordChangedAt: fixed}, nil
	}
	g, _ := newSessionGuard(t, status, WithSessionClock(func() time.Time { return fixed }))
	ctx := context.Background()

	tok, rec, err := g.Issue(ctx, SessionRecord{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if !rec.CreatedAt.Equal(fixed) {
		t.Fatalf("前提不成立: 会话 CreatedAt=%v 应等于 %v", rec.CreatedAt, fixed)
	}

	if _, err := g.Refresh(ctx, tok); err != nil {
		t.Fatalf("⛔⛔ CreatedAt 与 PasswordChangedAt 相等时会话被判失效 —— "+
			"改密后重签出的会话与改密时刻【总是】落在同一秒, "+
			"这会让每一次改密都以'立刻掉线'收场: %v", err)
	}

	// ⭐ 而真正早于改密时刻的, 必须失效 —— 这条是另一侧, 不能一起放松。
	older := func(context.Context, string) (AccountStatus, error) {
		return AccountStatus{Active: true, PasswordChangedAt: fixed.Add(time.Second)}, nil
	}
	g2, _ := newSessionGuard(t, older, WithSessionClock(func() time.Time { return fixed }))
	tok2, _, err := g2.Issue(ctx, SessionRecord{UserID: "u2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g2.Refresh(ctx, tok2); CodeOf(err) != CodeInvalidCredentials {
		t.Errorf("⛔ 建立于改密【之前】的会话必须失效, got %v", err)
	}
}
