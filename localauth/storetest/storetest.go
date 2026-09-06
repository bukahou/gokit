// Package storetest 是三个存储契约的【可导出的一致性测试】。
//
// 宿主实现了 FailureStore / SessionStore / VerificationStore 之后, 在自己的
// 测试里调用 RunXxxStoreTests(t, factory), 就能用模块作者写下的同一组断言
// 验证自己的实现 —— 这些断言正是守卫编排所依赖的语义 (原子自增、轮换区分
// 重放与失效、一人一码、一次性消费)。⛔ 一个实现若过不了这里, 守卫在它上面
// 的行为就是未定义的, 不管单测多绿。
//
// 用法:
//
//	func TestMyFailureStore(t *testing.T) {
//		storetest.RunFailureStoreTests(t, func(t *testing.T) localauth.FailureStore {
//			db := openTestDB(t)
//			return NewFailureStore(db, "login_failures_account")
//		})
//	}
//
// factory 每个子测试调用一次, 必须返回【干净】的存储 (空表或独立前缀)。
//
// # 关于精度
//
// 断言对时间字段只要求【秒】精度: 真实存储 (datetime / Redis unix 秒) 大多截到整秒,
// 而 2026-09-05 的教训是 fake 若保留亚秒会掩盖精度类缺陷。所以这里的比较全部
// 先截秒。实现保留亚秒也能过, 但不要依赖它。
//
// # 关于大小写 (刻意不在 Run 里断言)
//
// 账号维度的计数键应当与用户名列共享同一条排序规则 (见 localauth.FailureStore 的注释),
// 但那条规则【随数据库而变】: 有的库大小写不敏感, 有的逐字节比。模块不知道
// 宿主的答案, 所以把它做成两个可选断言 AssertKeysShareBucket / AssertKeysDistinct,
// 由宿主按自己库的实际排序规则选一个调用。⛔ 两个都不调 = 这条边界没有被测。
package storetest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bukahou/gokit/localauth"
)

// sameSecond 报告两个时间是否落在同一秒 (先截秒再比)。
func sameSecond(a, b time.Time) bool {
	return a.Truncate(time.Second).Equal(b.Truncate(time.Second))
}

// ============ FailureStore ============

// RunFailureStoreTests 跑 FailureStore 契约。
func RunFailureStoreTests(t *testing.T, factory func(t *testing.T) localauth.FailureStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	t.Run("Peek 不存在的键返回零值且无错", func(t *testing.T) {
		s := factory(t)
		st, err := s.Peek(ctx, "nobody")
		if err != nil {
			t.Fatalf("Peek 报错: %v", err)
		}
		if st.Count != 0 || !st.FirstFailAt.IsZero() || !st.LastFailAt.IsZero() {
			t.Fatalf("不存在的键应返回零值, got %+v", st)
		}
	})

	t.Run("Bump 返回自增之后的状态并记录首次与末次时间", func(t *testing.T) {
		s := factory(t)
		st, err := s.Bump(ctx, "k", now)
		if err != nil {
			t.Fatal(err)
		}
		if st.Count != 1 {
			t.Fatalf("首次 Bump 后 Count 应为 1, got %d", st.Count)
		}
		if !sameSecond(st.FirstFailAt, now) || !sameSecond(st.LastFailAt, now) {
			t.Fatalf("首次 Bump 后 First/Last 都应是 now, got %+v", st)
		}
		later := now.Add(30 * time.Second)
		st, _ = s.Bump(ctx, "k", later)
		st, _ = s.Bump(ctx, "k", later)
		if st.Count != 3 {
			t.Fatalf("三次 Bump 后 Count 应为 3, got %d", st.Count)
		}
		if !sameSecond(st.FirstFailAt, now) {
			t.Fatalf("FirstFailAt 不得被后续 Bump 改写, got %v want %v", st.FirstFailAt, now)
		}
		if !sameSecond(st.LastFailAt, later) {
			t.Fatalf("LastFailAt 应随最后一次 Bump 更新, got %v want %v", st.LastFailAt, later)
		}
	})

	t.Run("Peek 只读不改变状态", func(t *testing.T) {
		s := factory(t)
		s.Bump(ctx, "k", now)
		a, _ := s.Peek(ctx, "k")
		b, _ := s.Peek(ctx, "k")
		if a.Count != 1 || b.Count != 1 {
			t.Fatalf("Peek 改变了计数: %d / %d", a.Count, b.Count)
		}
	})

	t.Run("Reset 清零, 对不存在的键返回 nil", func(t *testing.T) {
		s := factory(t)
		if err := s.Reset(ctx, "nobody"); err != nil {
			t.Fatalf("Reset 不存在的键不该报错: %v", err)
		}
		s.Bump(ctx, "k", now)
		if err := s.Reset(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		st, _ := s.Peek(ctx, "k")
		if st.Count != 0 {
			t.Fatalf("Reset 后应为 0, got %d", st.Count)
		}
		// Reset 之后再 Bump 是一段新的历史
		st, _ = s.Bump(ctx, "k", now.Add(time.Hour))
		if st.Count != 1 || !sameSecond(st.FirstFailAt, now.Add(time.Hour)) {
			t.Fatalf("Reset 后重新计数应从 1 开始且 FirstFailAt 重置, got %+v", st)
		}
	})

	t.Run("键之间互不影响", func(t *testing.T) {
		s := factory(t)
		s.Bump(ctx, "a", now)
		s.Bump(ctx, "a", now)
		s.Bump(ctx, "b", now)
		a, _ := s.Peek(ctx, "a")
		b, _ := s.Peek(ctx, "b")
		if a.Count != 2 || b.Count != 1 {
			t.Fatalf("a=%d b=%d, 键串了", a.Count, b.Count)
		}
	})

	t.Run("并发 Bump 不丢计数 (原子性)", func(t *testing.T) {
		s := factory(t)
		const n = 64
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.Bump(ctx, "hot", now); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		st, _ := s.Peek(ctx, "hot")
		if st.Count != n {
			t.Fatalf("⛔ 并发 %d 次 Bump 后 Count=%d —— 读-改-写竞态, 退避可被并发绕开", n, st.Count)
		}
	})
}

// AssertKeysShareBucket 断言两个键落在【同一个】计数桶 (宿主的用户名列大小写不敏感时用)。
func AssertKeysShareBucket(t *testing.T, s localauth.FailureStore, a, b string) {
	t.Helper()
	ctx := context.Background()
	s.Reset(ctx, a)
	s.Reset(ctx, b)
	s.Bump(ctx, a, time.Now())
	st, _ := s.Peek(ctx, b)
	if st.Count != 1 {
		t.Fatalf("⛔ %q 与 %q 应共用一个计数桶 (用户名列不区分它们), 但 Bump(%q) 后 Peek(%q)=%d —— 攻击者换个大小写就绕开退避", a, b, a, b, st.Count)
	}
}

// AssertKeysDistinct 断言两个键落在【不同】计数桶 (宿主的用户名列逐字节比较时用)。
func AssertKeysDistinct(t *testing.T, s localauth.FailureStore, a, b string) {
	t.Helper()
	ctx := context.Background()
	s.Reset(ctx, a)
	s.Reset(ctx, b)
	s.Bump(ctx, a, time.Now())
	st, _ := s.Peek(ctx, b)
	if st.Count != 0 {
		t.Fatalf("⛔ %q 与 %q 应是两个计数桶 (用户名列区分它们), 但 Bump(%q) 后 Peek(%q)=%d —— 打 A 会锁死 B", a, b, a, b, st.Count)
	}
}

// ============ SessionStore ============

func rec(user string) localauth.SessionRecord {
	now := time.Now().Truncate(time.Second)
	return localauth.SessionRecord{
		UserID: user, CreatedAt: now, LastActiveAt: now, ExpiresAt: now.Add(time.Hour),
		DeviceInfo: "storetest", ClientIP: "203.0.113.1",
	}
}

func h(s string) []byte { return localauth.HashRefreshToken(s) }

// RunSessionStoreTests 跑 SessionStore 契约。
func RunSessionStoreTests(t *testing.T, factory func(t *testing.T) localauth.SessionStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("Create 返回带 ID 的记录, 且 ID 互不相同", func(t *testing.T) {
		s := factory(t)
		a, err := s.Create(ctx, rec("u1"), h("t1"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := s.Create(ctx, rec("u1"), h("t2"))
		if a.ID == "" || b.ID == "" || a.ID == b.ID {
			t.Fatalf("ID 必须非空且唯一: %q %q", a.ID, b.ID)
		}
		if a.UserID != "u1" {
			t.Fatalf("返回的记录应保留 UserID, got %q", a.UserID)
		}
	})

	t.Run("FindByHash 只命中有效会话", func(t *testing.T) {
		s := factory(t)
		created, _ := s.Create(ctx, rec("u1"), h("t1"))
		got, found, err := s.FindByHash(ctx, h("t1"))
		if err != nil || !found || got.ID != created.ID {
			t.Fatalf("应命中刚建的会话: found=%v id=%q err=%v", found, got.ID, err)
		}
		if _, found, err := s.FindByHash(ctx, h("nope")); err != nil || found {
			t.Fatalf("未知哈希不应命中且不报错: found=%v err=%v", found, err)
		}
		s.RevokeByHash(ctx, h("t1"))
		if _, found, _ := s.FindByHash(ctx, h("t1")); found {
			t.Fatal("已吊销的会话不应被 FindByHash 命中")
		}
	})

	t.Run("Rotate 成功: 旧哈希失效, 新哈希生效, 过期时间更新", func(t *testing.T) {
		s := factory(t)
		created, _ := s.Create(ctx, rec("u1"), h("t1"))
		exp := time.Now().Truncate(time.Second).Add(2 * time.Hour)
		got, out, err := s.Rotate(ctx, h("t1"), h("t2"), exp)
		if err != nil || out != localauth.RotateRotated {
			t.Fatalf("应 Rotated: out=%v err=%v", out, err)
		}
		if got.ID != created.ID || got.UserID != "u1" {
			t.Fatalf("Rotate 应返回该会话的记录, got %+v", got)
		}
		if !sameSecond(got.ExpiresAt, exp) {
			t.Fatalf("ExpiresAt 应更新为 %v, got %v", exp, got.ExpiresAt)
		}
		if _, found, _ := s.FindByHash(ctx, h("t1")); found {
			t.Fatal("轮换后旧哈希不应再命中")
		}
		if _, found, _ := s.FindByHash(ctx, h("t2")); !found {
			t.Fatal("轮换后新哈希应命中")
		}
	})

	t.Run("Rotate 用【上一个】哈希 = 重放, 且必须填上 UserID", func(t *testing.T) {
		s := factory(t)
		s.Create(ctx, rec("u1"), h("t1"))
		s.Rotate(ctx, h("t1"), h("t2"), time.Now().Add(time.Hour))
		got, out, err := s.Rotate(ctx, h("t1"), h("t3"), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if out != localauth.RotateReplayed {
			t.Fatalf("⛔ 拿已被换走的 token 再换应判为 Replayed, got %v —— 分不清重放与失效, 处置会反过来", out)
		}
		if got.UserID != "u1" {
			t.Fatalf("⛔ 重放时必须按上一个哈希反查出归属 (UserID), got %q —— 空 UserID 等于放弃反击", got.UserID)
		}
		if _, found, _ := s.FindByHash(ctx, h("t3")); found {
			t.Fatal("重放不得换出新会话")
		}
	})

	t.Run("Rotate 命中【当前】哈希但会话已吊销 = 正常失效, 不是重放", func(t *testing.T) {
		s := factory(t)
		s.Create(ctx, rec("u1"), h("t1"))
		s.RevokeByHash(ctx, h("t1"))
		got, out, err := s.Rotate(ctx, h("t1"), h("t2"), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if out != localauth.RotateRevoked {
			t.Fatalf("⛔ 已登出的会话再刷新应判为 Revoked, got %v —— 判成重放会把该用户全部会话吊掉", out)
		}
		if got.UserID != "u1" {
			t.Fatalf("Revoked 时也应填上 UserID, got %q", got.UserID)
		}
	})

	t.Run("Rotate 未知哈希 = Unknown, 无错", func(t *testing.T) {
		s := factory(t)
		_, out, err := s.Rotate(ctx, h("ghost"), h("x"), time.Now().Add(time.Hour))
		if err != nil || out != localauth.RotateUnknown {
			t.Fatalf("未知哈希应 Unknown 且无错: out=%v err=%v", out, err)
		}
	})

	t.Run("并发 Rotate 同一旧哈希只能成功一次 (原子性)", func(t *testing.T) {
		s := factory(t)
		s.Create(ctx, rec("u1"), h("t1"))
		const n = 32
		var wg sync.WaitGroup
		var mu sync.Mutex
		rotated := 0
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, out, err := s.Rotate(ctx, h("t1"), h("new"+string(rune('a'+i%26))+string(rune('a'+i/26))), time.Now().Add(time.Hour))
				if err != nil {
					t.Error(err)
					return
				}
				if out == localauth.RotateRotated {
					mu.Lock()
					rotated++
					mu.Unlock()
				}
			}(i)
		}
		wg.Wait()
		if rotated != 1 {
			t.Fatalf("⛔ 并发 %d 次 Rotate 同一旧哈希成功了 %d 次 —— Rotate 不是原子的, 重放检测形同虚设", n, rotated)
		}
	})

	t.Run("RevokeByID 必须同时匹配 userID (防 IDOR)", func(t *testing.T) {
		s := factory(t)
		created, _ := s.Create(ctx, rec("u1"), h("t1"))
		if err := s.RevokeByID(ctx, "someone-else", created.ID); err != nil {
			t.Fatal(err)
		}
		if _, found, _ := s.FindByHash(ctx, h("t1")); !found {
			t.Fatal("⛔ 别人的 userID 不得吊销我的会话 (IDOR)")
		}
		s.RevokeByID(ctx, "u1", created.ID)
		if _, found, _ := s.FindByHash(ctx, h("t1")); found {
			t.Fatal("本人吊销后应失效")
		}
	})

	t.Run("RevokeAllByUser / RevokeOthersByUser / ListByUser", func(t *testing.T) {
		s := factory(t)
		keep, _ := s.Create(ctx, rec("u1"), h("k"))
		s.Create(ctx, rec("u1"), h("o1"))
		s.Create(ctx, rec("u1"), h("o2"))
		s.Create(ctx, rec("u2"), h("other"))

		list, err := s.ListByUser(ctx, "u1")
		if err != nil || len(list) != 3 {
			t.Fatalf("u1 应有 3 条有效会话, got %d err=%v", len(list), err)
		}
		n, err := s.RevokeOthersByUser(ctx, "u1", keep.ID)
		if err != nil || n != 2 {
			t.Fatalf("RevokeOthers 应吊销 2 条, got %d err=%v", n, err)
		}
		if _, found, _ := s.FindByHash(ctx, h("k")); !found {
			t.Fatal("⛔ RevokeOthers 把保留的那条也吊了 —— '登出其它设备'会把自己踢掉")
		}
		list, _ = s.ListByUser(ctx, "u1")
		if len(list) != 1 || list[0].ID != keep.ID {
			t.Fatalf("ListByUser 应只剩保留的那条, got %+v", list)
		}
		n, err = s.RevokeAllByUser(ctx, "u1")
		if err != nil || n != 1 {
			t.Fatalf("RevokeAll 应吊销剩下 1 条, got %d err=%v", n, err)
		}
		if list, _ := s.ListByUser(ctx, "u1"); len(list) != 0 {
			t.Fatalf("RevokeAll 后应为空, got %d", len(list))
		}
		if _, found, _ := s.FindByHash(ctx, h("other")); !found {
			t.Fatal("⛔ 吊销 u1 不得波及 u2")
		}
	})
}

// ============ VerificationStore ============

// VerificationOptions 调整 VerificationStore 契约里【实现可选】的部分。
type VerificationOptions struct {
	// FiltersExpired 为 true 时额外断言 FindPending 不返回已过期的行。
	// 守卫自己也会检查 ExpiresAt, 所以存储不过滤也是合法实现; 过滤了则少扫一行。
	FiltersExpired bool
}

func vrec(purpose localauth.TokenPurpose, subject string) localauth.VerificationRecord {
	return localauth.VerificationRecord{
		Purpose: purpose, Subject: subject, Payload: "payload",
		ExpiresAt: time.Now().Truncate(time.Second).Add(10 * time.Minute),
	}
}

// RunVerificationStoreTests 跑 VerificationStore 契约。
func RunVerificationStoreTests(t *testing.T, factory func(t *testing.T) localauth.VerificationStore, opts ...VerificationOptions) {
	t.Helper()
	var opt VerificationOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	ctx := context.Background()
	const reg = localauth.PurposeRegister

	t.Run("FindPending 没有行时 found=false 且无错", func(t *testing.T) {
		s := factory(t)
		_, _, found, err := s.FindPending(ctx, reg, "a@example.invalid")
		if err != nil || found {
			t.Fatalf("应 found=false 无错: found=%v err=%v", found, err)
		}
	})

	t.Run("Issue 后 FindPending 命中并原样返回哈希与记录", func(t *testing.T) {
		s := factory(t)
		want := vrec(reg, "a@example.invalid")
		id, err := s.Issue(ctx, want, []byte("hash-1"))
		if err != nil || id == "" {
			t.Fatalf("Issue 应返回非空 id: %q err=%v", id, err)
		}
		got, hash, found, err := s.FindPending(ctx, reg, "a@example.invalid")
		if err != nil || !found {
			t.Fatalf("应命中: found=%v err=%v", found, err)
		}
		if got.ID != id || got.Purpose != reg || got.Subject != want.Subject || got.Payload != want.Payload || got.Attempts != 0 {
			t.Fatalf("记录字段不一致: got %+v want id=%q", got, id)
		}
		if !sameSecond(got.ExpiresAt, want.ExpiresAt) {
			t.Fatalf("ExpiresAt 应保留到秒: got %v want %v", got.ExpiresAt, want.ExpiresAt)
		}
		if string(hash) != "hash-1" {
			t.Fatalf("哈希应原样返回, got %q", hash)
		}
	})

	t.Run("一人一码: 同 (subject, purpose) 再 Issue 会作废旧行", func(t *testing.T) {
		s := factory(t)
		s.Issue(ctx, vrec(reg, "a@example.invalid"), []byte("old"))
		newID, _ := s.Issue(ctx, vrec(reg, "a@example.invalid"), []byte("new"))
		got, hash, found, _ := s.FindPending(ctx, reg, "a@example.invalid")
		if !found || got.ID != newID || string(hash) != "new" {
			t.Fatalf("⛔ 重发后应只剩新行: found=%v id=%q hash=%q —— 用户手里同时有效的码会越来越多", found, got.ID, hash)
		}
	})

	t.Run("不同 purpose / subject 互不影响", func(t *testing.T) {
		s := factory(t)
		s.Issue(ctx, vrec(reg, "a@example.invalid"), []byte("r"))
		s.Issue(ctx, vrec(localauth.PurposeRecoverPassword, "a@example.invalid"), []byte("p"))
		s.Issue(ctx, vrec(reg, "b@example.invalid"), []byte("b"))
		if _, hash, found, _ := s.FindPending(ctx, reg, "a@example.invalid"); !found || string(hash) != "r" {
			t.Fatalf("register/a 应仍有效, found=%v hash=%q", found, hash)
		}
		if _, hash, found, _ := s.FindPending(ctx, localauth.PurposeRecoverPassword, "a@example.invalid"); !found || string(hash) != "p" {
			t.Fatalf("recover/a 应仍有效, found=%v hash=%q", found, hash)
		}
		if _, hash, found, _ := s.FindPending(ctx, reg, "b@example.invalid"); !found || string(hash) != "b" {
			t.Fatalf("register/b 应仍有效, found=%v hash=%q", found, hash)
		}
	})

	t.Run("BumpAttempts 原子递增并被 FindPending 看到", func(t *testing.T) {
		s := factory(t)
		id, _ := s.Issue(ctx, vrec(reg, "a@example.invalid"), []byte("x"))
		if n, err := s.BumpAttempts(ctx, id); err != nil || n != 1 {
			t.Fatalf("第一次 Bump 应返回 1: %d err=%v", n, err)
		}
		if n, _ := s.BumpAttempts(ctx, id); n != 2 {
			t.Fatalf("第二次 Bump 应返回 2: %d", n)
		}
		got, _, _, _ := s.FindPending(ctx, reg, "a@example.invalid")
		if got.Attempts != 2 {
			t.Fatalf("FindPending 应看到 Attempts=2, got %d", got.Attempts)
		}
		const n = 32
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); s.BumpAttempts(ctx, id) }()
		}
		wg.Wait()
		got, _, _, _ = s.FindPending(ctx, reg, "a@example.invalid")
		if got.Attempts != 2+n {
			t.Fatalf("⛔ 并发 Bump 丢计数: got %d want %d —— 猜码次数上限可被并发绕开", got.Attempts, 2+n)
		}
	})

	t.Run("Consume 一次性: 第二次 false, 之后 FindPending 不再命中", func(t *testing.T) {
		s := factory(t)
		id, _ := s.Issue(ctx, vrec(reg, "a@example.invalid"), []byte("x"))
		ok, err := s.Consume(ctx, id, time.Now())
		if err != nil || !ok {
			t.Fatalf("首次 Consume 应成功: ok=%v err=%v", ok, err)
		}
		ok, err = s.Consume(ctx, id, time.Now())
		if err != nil || ok {
			t.Fatalf("⛔ 第二次 Consume 应 false: ok=%v err=%v —— 一个码能用两次", ok, err)
		}
		if _, _, found, _ := s.FindPending(ctx, reg, "a@example.invalid"); found {
			t.Fatal("消费后不应再被 FindPending 命中")
		}
		if ok, err := s.Consume(ctx, "no-such-id", time.Now()); err != nil || ok {
			t.Fatalf("消费不存在的 id 应 false 无错: ok=%v err=%v", ok, err)
		}
	})

	t.Run("并发 Consume 同一 id 只能成功一次 (原子性)", func(t *testing.T) {
		s := factory(t)
		id, _ := s.Issue(ctx, vrec(reg, "a@example.invalid"), []byte("x"))
		const n = 32
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := s.Consume(ctx, id, time.Now())
				if err != nil {
					t.Error(err)
					return
				}
				if ok {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("⛔ 并发 %d 次 Consume 成功了 %d 次 —— Consume 不是原子的", n, wins)
		}
	})

	if opt.FiltersExpired {
		t.Run("FindPending 不返回已过期的行 (可选)", func(t *testing.T) {
			s := factory(t)
			r := vrec(reg, "a@example.invalid")
			r.ExpiresAt = time.Now().Add(-time.Minute)
			s.Issue(ctx, r, []byte("x"))
			if _, _, found, _ := s.FindPending(ctx, reg, "a@example.invalid"); found {
				t.Fatal("已过期的行不应返回")
			}
		})
	}
}
