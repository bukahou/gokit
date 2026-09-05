package localauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type memCredStore struct {
	creds map[string]Credential
	saved map[string]time.Time // userID → changedAt
	fail  bool
}

func newMemCredStore() *memCredStore {
	return &memCredStore{creds: map[string]Credential{}, saved: map[string]time.Time{}}
}

func (m *memCredStore) LoadCredential(_ context.Context, id string) (Credential, bool, error) {
	c, ok := m.creds[id]
	return c, ok, nil
}

func (m *memCredStore) SaveCredential(_ context.Context, id, hash string, at time.Time) error {
	if m.fail {
		return errors.New("写库炸了")
	}
	c := m.creds[id]
	c.Hash = hash
	m.creds[id] = c
	m.saved[id] = at // ⭐ 模拟"同一条语句"—— 两者一起变
	return nil
}

func newPwdGuard(t *testing.T, store *memCredStore, opts ...PasswordGuardOption) (*PasswordGuard, SessionStore) {
	t.Helper()
	sessStore := NewSessionMemStore()
	sg, err := NewSessionGuard(sessStore, activeStatus, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	base := []PasswordGuardOption{WithPasswordCost(bcrypt.MinCost)}
	g, err := NewPasswordGuard(store, sg, NewPasswordPolicy(), append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return g, sessStore
}

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := hashWithCost(pw, bcrypt.MinCost, DefaultMinPasswordLen)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// ============ 构造期必填 ============

func TestNewPasswordGuard_必填(t *testing.T) {
	store := newMemCredStore()
	sg, _ := NewSessionGuard(NewSessionMemStore(), activeStatus, time.Hour)
	t.Run("⭐ 缺 SessionGuard", func(t *testing.T) {
		// ⛔ 不给默认值: 缺了它改密就不吊销会话, §7.3 静默失效。
		if _, err := NewPasswordGuard(store, nil, NewPasswordPolicy()); CodeOf(err) != CodeMisconfigured {
			t.Error("缺 SessionGuard 应拒绝构造 —— 否则改密不吊销会话且无症状")
		}
	})
	t.Run("⭐ 缺 PasswordPolicy", func(t *testing.T) {
		if _, err := NewPasswordGuard(store, sg, nil); CodeOf(err) != CodeMisconfigured {
			t.Error("缺 PasswordPolicy 应拒绝构造 —— 否则泄露检查静默消失")
		}
	})
}

// ============ 旧口令校验 ============

// TestChange_旧口令判据是库里有没有hash_不是调用方传没传 是本文件最重要的一条。
func TestChange_旧口令判据是库里有没有hash_不是调用方传没传(t *testing.T) {
	store := newMemCredStore()
	store.creds["u1"] = Credential{Hash: mustHash(t, "oldpass"), Active: true}
	g, _ := newPwdGuard(t, store)

	// ⛔ 调用方"忘了"传旧口令, 绝不能因此跳过校验。
	_, err := g.Change(context.Background(), ChangeRequest{
		UserID: "u1", NewPassword: "brandnewpass",
	})
	if CodeOf(err) != CodeInvalidCredentials {
		t.Fatalf("⛔ 不传 OldPassword 竟然通过了 —— "+
			"那是一个纯由调用方失误造成的鉴权绕过, got %v", err)
	}

	// 传错的也不行
	_, err = g.Change(context.Background(), ChangeRequest{
		UserID: "u1", OldPassword: "wrong", NewPassword: "brandnewpass",
	})
	if CodeOf(err) != CodeInvalidCredentials {
		t.Fatalf("旧口令错误应被拒, got %v", err)
	}

	// 传对的才行
	if _, err = g.Change(context.Background(), ChangeRequest{
		UserID: "u1", OldPassword: "oldpass", NewPassword: "brandnewpass",
	}); err != nil {
		t.Fatalf("旧口令正确时应当成功: %v", err)
	}
}

// TestChange_首次设密不验旧口令 (⑥)
func TestChange_首次设密不验旧口令(t *testing.T) {
	store := newMemCredStore()
	// ⭐ 纯 OIDC 账号: Hash 为空
	store.creds["sso1"] = Credential{Hash: "", Active: true}
	g, _ := newPwdGuard(t, store)

	out, err := g.Change(context.Background(), ChangeRequest{
		UserID: "sso1", NewPassword: "firstpassword",
	})
	if err != nil {
		t.Fatalf("首次设密应当成功: %v", err)
	}
	if store.creds["sso1"].Hash == "" {
		t.Fatal("hash 没写进去")
	}
	if out.Advice.Checked {
		t.Error("默认 noop policy 下 Checked 应为 false")
	}
	// ⭐ 设完之后它就变成普通账号了 —— 再改必须验旧口令
	if _, err := g.Change(context.Background(), ChangeRequest{
		UserID: "sso1", NewPassword: "secondpassword",
	}); CodeOf(err) != CodeInvalidCredentials {
		t.Error("⛔ 设过口令之后再改, 必须验旧口令")
	}
}

// ============ ⭐ 时间戳与吊销 ============

// TestChange_hash与changedAt必须一起写 守的是 §7.7 的前提。
func TestChange_hash与changedAt必须一起写(t *testing.T) {
	store := newMemCredStore()
	store.creds["u1"] = Credential{Hash: mustHash(t, "oldpass"), Active: true}
	g, _ := newPwdGuard(t, store)

	before := store.creds["u1"].Hash
	if _, err := g.Change(context.Background(), ChangeRequest{
		UserID: "u1", OldPassword: "oldpass", NewPassword: "brandnewpass",
	}); err != nil {
		t.Fatal(err)
	}
	if store.creds["u1"].Hash == before {
		t.Fatal("hash 没变")
	}
	if store.saved["u1"].IsZero() {
		t.Fatal("⛔ changedAt 没写 —— §7.7 的判据永远不成立, " +
			"所有旧会话【永久有效】, 而且没有任何症状")
	}
}

// TestChange_吊销全部并重签当前设备 是 D3 裁决的可执行版本。
func TestChange_吊销全部并重签当前设备(t *testing.T) {
	store := newMemCredStore()
	store.creds["u1"] = Credential{Hash: mustHash(t, "oldpass"), Active: true}
	g, sessStore := newPwdGuard(t, store)
	ctx := context.Background()

	// 三台设备
	var cur SessionRecord
	for i := 0; i < 3; i++ {
		_, rec, err := g.sessions.Issue(ctx, SessionRecord{UserID: "u1"})
		if err != nil {
			t.Fatal(err)
		}
		cur = rec
	}

	out, err := g.Change(ctx, ChangeRequest{
		UserID: "u1", OldPassword: "oldpass", NewPassword: "brandnewpass",
		CurrentSessionID: cur.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	if out.RevokedCount != 3 {
		t.Errorf("⛔ 应吊销【全部】3 条(含当前), got %d —— "+
			"保留当前会话在有 §7.7 的前提下做不到, 它会在下次 refresh 时莫名掉线",
			out.RevokedCount)
	}
	if out.NewRefreshToken == "" {
		t.Fatal("⛔ 没有为当前设备重签 —— 用户会被自己的改密操作踢下线")
	}

	// ⭐ 新会话可用
	if _, err := g.sessions.Refresh(ctx, out.NewRefreshToken); err != nil {
		t.Errorf("重签出的 refresh 不可用: %v", err)
	}
	// ⭐ 旧会话全废
	live, _ := sessStore.ListByUser(ctx, "u1")
	for _, s := range live {
		if s.ID == cur.ID {
			t.Error("⛔ 旧的当前会话仍然有效 —— 它的 CreatedAt 早于改密时刻, " +
				"迟早会被 §7.7 干掉, 留着只会制造一个延迟发作的掉线")
		}
	}
}

// TestChange_没给会话id则不重签 —— 调用方据此提示"请重新登录"。
func TestChange_没给会话id则不重签(t *testing.T) {
	store := newMemCredStore()
	store.creds["u1"] = Credential{Hash: mustHash(t, "oldpass"), Active: true}
	g, _ := newPwdGuard(t, store)
	out, err := g.Change(context.Background(), ChangeRequest{
		UserID: "u1", OldPassword: "oldpass", NewPassword: "brandnewpass",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.NewRefreshToken != "" {
		t.Error("没传 CurrentSessionID 时不应重签")
	}
}

// ============ 失败与回退 ============

// TestChange_写库失败时无副作用
func TestChange_写库失败时无副作用(t *testing.T) {
	store := newMemCredStore()
	store.creds["u1"] = Credential{Hash: mustHash(t, "oldpass"), Active: true}
	store.fail = true
	g, sessStore := newPwdGuard(t, store)
	ctx := context.Background()
	if _, _, err := g.sessions.Issue(ctx, SessionRecord{UserID: "u1"}); err != nil {
		t.Fatal(err)
	}

	if _, err := g.Change(ctx, ChangeRequest{
		UserID: "u1", OldPassword: "oldpass", NewPassword: "brandnewpass",
	}); err == nil {
		t.Fatal("写库失败应当返回错误")
	}
	live, _ := sessStore.ListByUser(ctx, "u1")
	if len(live) != 1 {
		t.Errorf("⛔ 写库失败却吊销了会话 —— 口令没变而用户被登出, got %d 条存活", len(live))
	}
}

// TestChange_停用账号不许改口令
func TestChange_停用账号不许改口令(t *testing.T) {
	store := newMemCredStore()
	store.creds["u1"] = Credential{Hash: mustHash(t, "oldpass"), Active: false}
	g, _ := newPwdGuard(t, store)
	if _, err := g.Change(context.Background(), ChangeRequest{
		UserID: "u1", OldPassword: "oldpass", NewPassword: "brandnewpass",
	}); CodeOf(err) != CodeInvalidCredentials {
		t.Errorf("停用账号应被拒, got %v", err)
	}
}

// TestChange_账号不存在与旧口令错误返回同一个码 —— ⛔ 不泄漏账号是否存在。
func TestChange_账号不存在与旧口令错误返回同一个码(t *testing.T) {
	store := newMemCredStore()
	store.creds["u1"] = Credential{Hash: mustHash(t, "oldpass"), Active: true}
	g, _ := newPwdGuard(t, store)
	_, errMissing := g.Change(context.Background(), ChangeRequest{
		UserID: "不存在", OldPassword: "x", NewPassword: "brandnewpass"})
	_, errWrong := g.Change(context.Background(), ChangeRequest{
		UserID: "u1", OldPassword: "wrong", NewPassword: "brandnewpass"})
	if CodeOf(errMissing) != CodeOf(errWrong) {
		t.Errorf("⛔ 两者错误码不同(%v vs %v) —— 可用来枚举账号是否存在",
			CodeOf(errMissing), CodeOf(errWrong))
	}
}

// TestChange_泄露口令仍然放行 是 D6 裁决(警告放行)的可执行版本。
func TestChange_泄露口令仍然放行(t *testing.T) {
	store := newMemCredStore()
	store.creds["u1"] = Credential{Hash: mustHash(t, "oldpass"), Active: true}
	sg, _ := NewSessionGuard(NewSessionMemStore(), activeStatus, time.Hour)
	policy := NewPasswordPolicy(WithBreachChecker(
		stubChecker{res: BreachResult{Verdict: BreachFound, Count: 12345}}))
	g, err := NewPasswordGuard(store, sg, policy, WithPasswordCost(bcrypt.MinCost))
	if err != nil {
		t.Fatal(err)
	}

	out, err := g.Change(context.Background(), ChangeRequest{
		UserID: "u1", OldPassword: "oldpass", NewPassword: "password",
	})
	if err != nil {
		t.Fatalf("⛔ 命中泄露库时被拒绝了 —— 用户裁决是【警告放行】: %v", err)
	}
	if !out.Advice.Breached || out.Advice.BreachCount != 12345 {
		t.Errorf("⛔ 警告没带出去(%+v) —— 前端就无从提示, "+
			"而'放行且不提示'等于这个检查根本不存在", out.Advice)
	}
	if store.creds["u1"].Hash == mustHash(t, "oldpass") {
		t.Error("口令应当真的被改了")
	}
}
