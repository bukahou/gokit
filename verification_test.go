package localauth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ============ 桩 ============

type memSender struct {
	mu   sync.Mutex
	sent []VerificationMessage
	fail bool
}

func (m *memSender) SendVerification(_ context.Context, msg VerificationMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("SMTP 炸了")
	}
	m.sent = append(m.sent, msg)
	return nil
}

func (m *memSender) last() (VerificationMessage, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		return VerificationMessage{}, false
	}
	return m.sent[len(m.sent)-1], true
}

func (m *memSender) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// waitSent 等异步投递落地 —— 投递在 goroutine 里, 测试必须等它。
func waitSent(t *testing.T, s *memSender, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.count() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待 %d 条投递超时, 只有 %d 条", n, s.count())
}

var testPepper = []byte("test-pepper-at-least-16-bytes")

func newVerif(t *testing.T, opts ...VerificationOption) (*VerificationGuard, *memSender, *[]EventKind) {
	t.Helper()
	sender := &memSender{}
	var events []EventKind
	var mu sync.Mutex
	base := []VerificationOption{
		// ⚠️ 默认放宽限流: 编排类测试要连发多次; 限流语义由 TestThrottle_* 单独覆盖。
		WithSendThrottle(SendThrottle{PerAddress: 100, AddressWindow: time.Hour, PerIP: 100, IPWindow: time.Hour}),
		WithVerificationAudit(func(_ context.Context, e AuditEvent) {
			mu.Lock()
			events = append(events, e.Kind)
			mu.Unlock()
		}),
	}
	g, err := NewVerificationGuard(NewVerificationMemStore(), sender, NewMemStore(), NewMemStore(), testPepper, append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return g, sender, &events
}

// ============ 校验语义 ============

func TestVerify_全流程与一次性消费(t *testing.T) {
	g, sender, _ := newVerif(t)
	ctx := context.Background()

	if err := g.IssueAndSend(ctx, PurposeRegister, "a@x.test", "a@x.test", ""); err != nil {
		t.Fatal(err)
	}
	msg, _ := sender.last()
	if len(msg.Code) != 6 {
		t.Fatalf("码应为 6 位, got %q", msg.Code)
	}

	// 错码 → 拒绝
	if _, err := g.Verify(ctx, PurposeRegister, "a@x.test", "000000"); CodeOf(err) != CodeInvalidCode {
		t.Fatalf("错码应 CodeInvalidCode, got %v", err)
	}
	// 对码 → proof
	proof, err := g.Verify(ctx, PurposeRegister, "a@x.test", msg.Code)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.valid() {
		t.Fatal("proof 应有效")
	}
	// 消费一次 OK, 再消费失败
	if err := g.Consume(ctx, proof); err != nil {
		t.Fatal(err)
	}
	if err := g.Consume(ctx, proof); err == nil {
		t.Fatal("⛔ 同一个 proof 被消费了两次")
	}
	// 消费后再验 → 根本没有
	if _, err := g.Verify(ctx, PurposeRegister, "a@x.test", msg.Code); CodeOf(err) != CodeInvalidCode {
		t.Fatal("消费后的码不得再通过")
	}
}

// TestVerify_用途隔离 ⛔ 一个用途的码不得用于另一个用途。
func TestVerify_用途隔离(t *testing.T) {
	g, sender, _ := newVerif(t)
	ctx := context.Background()
	_ = g.IssueAndSend(ctx, PurposeRecoverPassword, "u1", "a@x.test", "a@x.test")
	msg, _ := sender.last()
	if _, err := g.Verify(ctx, PurposeChangeEmail, "u1", msg.Code); err == nil {
		t.Fatal("⛔ 找回密码的码被当成改邮箱的码通过了")
	}
}

// TestVerify_尝试上限 ⭐「找到但不对」计数, 到上限作废。
func TestVerify_尝试上限(t *testing.T) {
	g, sender, events := newVerif(t, WithVerificationMaxAttempts(3))
	ctx := context.Background()
	_ = g.IssueAndSend(ctx, PurposeRegister, "a@x.test", "a@x.test", "")
	msg, _ := sender.last()
	for i := 0; i < 3; i++ {
		_, _ = g.Verify(ctx, PurposeRegister, "a@x.test", "999999")
	}
	// ⭐ 第 4 次哪怕码对也不行 —— 已作废
	if _, err := g.Verify(ctx, PurposeRegister, "a@x.test", msg.Code); err == nil {
		t.Fatal("⛔ 试到上限后正确的码仍然通过 —— 在线猜码没有代价")
	}
	found := false
	for _, e := range *events {
		if e == EventVerificationExhausted {
			found = true
		}
	}
	if !found {
		t.Error("到上限应发 verification.exhausted —— 那是在线猜码的信号")
	}
}

// TestVerify_根本没有不计attempts —— 猜不存在的邮箱什么都消耗不到, 也不该污染别人的计数。
func TestVerify_根本没有不计attempts(t *testing.T) {
	g, _, events := newVerif(t)
	for i := 0; i < 10; i++ {
		_, _ = g.Verify(context.Background(), PurposeRegister, "nobody@x.test", "123456")
	}
	for _, e := range *events {
		if e == EventVerificationCodeMismatch || e == EventVerificationExhausted {
			t.Fatalf("⛔ 对不存在的主体发了 %s —— 「根本没有」不该计数", e)
		}
	}
}

// TestVerify_重发即覆盖 —— 一人一码。
func TestVerify_重发即覆盖(t *testing.T) {
	g, sender, _ := newVerif(t)
	ctx := context.Background()
	_ = g.IssueAndSend(ctx, PurposeRegister, "a@x.test", "a@x.test", "")
	first, _ := sender.last()
	_ = g.IssueAndSend(ctx, PurposeRegister, "a@x.test", "a@x.test", "")
	second, _ := sender.last()
	if first.Code != second.Code {
		if _, err := g.Verify(ctx, PurposeRegister, "a@x.test", first.Code); err == nil {
			t.Fatal("⛔ 重发后旧码仍然有效 —— 用户手里同时有效的码会越来越多")
		}
	}
	if _, err := g.Verify(ctx, PurposeRegister, "a@x.test", second.Code); err != nil {
		t.Fatal("新码应有效")
	}
}

// TestVerify_pepper不同则哈希不同 —— 库泄漏时没有 pepper 等于随机数。
func TestVerify_pepper不同则哈希不同(t *testing.T) {
	store := NewVerificationMemStore()
	g1, _ := NewVerificationGuard(store, &memSender{}, NewMemStore(), NewMemStore(), []byte("pepper-number-one-16b"))
	g2, _ := NewVerificationGuard(store, &memSender{}, NewMemStore(), NewMemStore(), []byte("pepper-number-two-16b"))
	if string(g1.hashVerifier(PurposeRegister, "s", "123456")) == string(g2.hashVerifier(PurposeRegister, "s", "123456")) {
		t.Fatal("⛔ 不同 pepper 得到同一个哈希")
	}
}

func TestNewVerificationGuard_pepper必填(t *testing.T) {
	if _, err := NewVerificationGuard(NewVerificationMemStore(), &memSender{}, NewMemStore(), NewMemStore(), []byte("short")); CodeOf(err) != CodeMisconfigured {
		t.Fatal("短 pepper 应拒绝构造 —— 库泄漏时 10^6 的码靠它撑着")
	}
}

// ============ 发码限流 ============

func TestThrottle_地址维度与冷却(t *testing.T) {
	now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	clock := &now
	g, _, _ := newVerif(t,
		WithVerificationClock(func() time.Time { return *clock }),
		WithSendThrottle(SendThrottle{PerAddress: 3, AddressWindow: 10 * time.Minute, Cooldown: 60 * time.Second, PerIP: 100, IPWindow: time.Hour}))
	ctx := context.Background()

	if err := g.CheckSendAllowed(ctx, PurposeRegister, "a@x.test", "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	// 冷却期内第二次 → 拒
	if err := g.CheckSendAllowed(ctx, PurposeRegister, "a@x.test", "1.1.1.1"); CodeOf(err) != CodeTooManyRequests {
		t.Fatal("⛔ 60s 冷却期内又发了一次")
	}
	*clock = now.Add(61 * time.Second)
	if err := g.CheckSendAllowed(ctx, PurposeRegister, "a@x.test", "1.1.1.1"); err != nil {
		t.Fatal("冷却过后应允许")
	}
	*clock = now.Add(122 * time.Second)
	if err := g.CheckSendAllowed(ctx, PurposeRegister, "a@x.test", "1.1.1.1"); err != nil {
		t.Fatal("第 3 次应允许")
	}
	*clock = now.Add(183 * time.Second)
	if err := g.CheckSendAllowed(ctx, PurposeRegister, "a@x.test", "1.1.1.1"); CodeOf(err) != CodeTooManyRequests {
		t.Fatal("⛔ 10 分钟内第 4 次应被拒 —— SMTP 配额就是这么被刷光的")
	}
	// 别的地址不受影响
	if err := g.CheckSendAllowed(ctx, PurposeRegister, "b@x.test", "1.1.1.1"); err != nil {
		t.Fatal("别的地址不该受影响")
	}
	// 窗口过期后重置
	*clock = now.Add(11 * time.Minute)
	if err := g.CheckSendAllowed(ctx, PurposeRegister, "a@x.test", "1.1.1.1"); err != nil {
		t.Fatal("窗口过期后应重新计数")
	}
}

func TestThrottle_IP维度(t *testing.T) {
	g, _, events := newVerif(t, WithSendThrottle(SendThrottle{PerAddress: 100, AddressWindow: time.Hour, PerIP: 2, IPWindow: time.Hour}))
	ctx := context.Background()
	_ = g.CheckSendAllowed(ctx, PurposeRegister, "a@x.test", "9.9.9.9")
	_ = g.CheckSendAllowed(ctx, PurposeRegister, "b@x.test", "9.9.9.9")
	if err := g.CheckSendAllowed(ctx, PurposeRegister, "c@x.test", "9.9.9.9"); CodeOf(err) != CodeTooManyRequests {
		t.Fatal("⛔ 同一 IP 对很多邮箱狂轰没被拦")
	}
	// ⚠️ IP 为空: 只做地址维度, 且留痕; ⛔ 不得把空串当一个键
	if err := g.CheckSendAllowed(ctx, PurposeRegister, "d@x.test", ""); err != nil {
		t.Fatal("IP 未知时应只做地址维度")
	}
	found := false
	for _, e := range *events {
		if e == EventVerificationIPUnavailable {
			found = true
		}
	}
	if !found {
		t.Error("IP 未知应留痕")
	}
}

// ============ 异步投递 ============

func TestSendAsync_失败留痕(t *testing.T) {
	g, sender, events := newVerif(t)
	sender.fail = true
	done := make(chan struct{})
	g.audit = func(_ context.Context, e AuditEvent) {
		*events = append(*events, e.Kind)
		if e.Kind == EventVerificationSendFailed {
			close(done)
		}
	}
	g.SendAsync(context.Background(), "a@x.test", func(bg context.Context) error {
		return g.IssueAndSend(bg, PurposeRegister, "a@x.test", "a@x.test", "")
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("⛔ 投递失败没有留痕 —— 用户看不到失败(刻意的), 所以这是唯一的可见性")
	}
}

// ============ 三条编排 ============

type memAccounts struct {
	mu       sync.Mutex
	users    map[string]map[string]string // userID → {username, email, verified}
	emailIdx map[string]string
	nameIdx  map[string]string
	seq      int
}

func newMemAccounts() *memAccounts {
	return &memAccounts{users: map[string]map[string]string{}, emailIdx: map[string]string{}, nameIdx: map[string]string{}}
}

func (m *memAccounts) UsernameTaken(_ context.Context, u string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.nameIdx[u]
	return ok, nil
}

func (m *memAccounts) EmailTaken(_ context.Context, e string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.emailIdx[e]
	return ok, nil
}

func (m *memAccounts) CreateAccount(_ context.Context, a NewAccount) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nameIdx[a.Username]; ok {
		return "", newErr(CodeUsernameTaken, "用户名已存在")
	}
	if _, ok := m.emailIdx[a.Email]; ok {
		return "", newErr(CodeEmailTaken, "邮箱已被注册")
	}
	m.seq++
	id := "u" + strings.Repeat("0", 3) + string(rune('0'+m.seq))
	m.users[id] = map[string]string{"username": a.Username, "email": a.Email, "verified": "1", "hash": a.PasswordHash}
	m.nameIdx[a.Username] = id
	m.emailIdx[a.Email] = id
	return id, nil
}

func (m *memAccounts) UserByVerifiedAddress(_ context.Context, addr string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.emailIdx[addr]
	if !ok || m.users[id]["verified"] != "1" {
		return "", false, nil
	}
	return id, true, nil
}

func (m *memAccounts) VerifiedRecoveryAddress(_ context.Context, id string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok || u["verified"] != "1" || u["email"] == "" {
		return "", false, nil
	}
	return u["email"], true, nil
}

func (m *memAccounts) ChangeVerifiedEmail(_ context.Context, id, newEmail string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.emailIdx[newEmail]; ok {
		return "", newErr(CodeEmailTaken, "邮箱已被占用")
	}
	old := m.users[id]["email"]
	delete(m.emailIdx, old)
	m.users[id]["email"] = newEmail
	m.users[id]["verified"] = "1"
	m.emailIdx[newEmail] = id
	return old, nil
}

// credsFromAccounts 让 PasswordGuard 与 memAccounts 共享同一份"用户"。
type credsFromAccounts struct{ a *memAccounts }

func (c credsFromAccounts) LoadCredential(_ context.Context, id string) (Credential, bool, error) {
	c.a.mu.Lock()
	defer c.a.mu.Unlock()
	u, ok := c.a.users[id]
	if !ok {
		return Credential{}, false, nil
	}
	return Credential{Hash: u["hash"], Active: true}, true, nil
}

func (c credsFromAccounts) SaveCredential(_ context.Context, id, hash string, _ time.Time) error {
	c.a.mu.Lock()
	defer c.a.mu.Unlock()
	c.a.users[id]["hash"] = hash
	return nil
}

func TestRegistration_全流程(t *testing.T) {
	verif, sender, _ := newVerif(t)
	accounts := newMemAccounts()
	g, err := NewRegistrationGuard(verif, accounts, AdmitAll(), NewPasswordPolicy(), WithRegistrationCost(bcrypt.MinCost))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := g.SendCode(ctx, SendCodeRequest{Username: "alice", Email: "alice@x.test", ClientIP: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	waitSent(t, sender, 1)
	msg, _ := sender.last()

	// 错码 → 不建号
	if _, err := g.Register(ctx, RegistrationRequest{Username: "alice", Password: "goodpass", Email: "alice@x.test", Code: "000000"}); CodeOf(err) != CodeInvalidCode {
		t.Fatalf("错码应拒, got %v", err)
	}
	if taken, _ := accounts.UsernameTaken(ctx, "alice"); taken {
		t.Fatal("⛔ 错码也建了号")
	}
	out, err := g.Register(ctx, RegistrationRequest{Username: "alice", Password: "goodpass", Email: "alice@x.test", Code: msg.Code})
	if err != nil {
		t.Fatal(err)
	}
	if out.UserID == "" {
		t.Fatal("应返回 userID")
	}

	// ⭐ 已占邮箱再发码: 对请求方仍成功, 但发的是通知不是码
	if err := g.SendCode(ctx, SendCodeRequest{Username: "bob", Email: "alice@x.test", ClientIP: "2.2.2.2"}); err != nil {
		t.Fatalf("已占邮箱对请求方应静默成功(防枚举), got %v", err)
	}
	waitSent(t, sender, 2)
	notice, _ := sender.last()
	if notice.Notice != NoticeExistingAccount || notice.Code != "" {
		t.Fatalf("⛔ 已占邮箱应收到通知而不是码, got %+v", notice)
	}
}

func TestRegistration_准入在一切之前(t *testing.T) {
	verif, _, _ := newVerif(t)
	deny := AdmissionFunc(func(context.Context, AdmitRequest) error { return newErr(CodeAdmissionDenied, "不许") })
	g, _ := NewRegistrationGuard(verif, newMemAccounts(), deny, NewPasswordPolicy(), WithRegistrationCost(bcrypt.MinCost))
	// ⛔ 被拒的人连"码对不对"都不该能问出来
	if _, err := g.Register(context.Background(), RegistrationRequest{Username: "x", Password: "goodpass", Email: "x@x.test", Code: "123456"}); CodeOf(err) != CodeAdmissionDenied {
		t.Fatalf("准入应在验码之前, got %v", err)
	}
}

func newRecoveryFixture(t *testing.T) (*RecoveryGuard, *memAccounts, *memSender, *SessionGuard, *PasswordGuard) {
	t.Helper()
	verif, sender, _ := newVerif(t)
	accounts := newMemAccounts()
	sessions, _ := NewSessionGuard(NewSessionMemStore(), activeStatus, time.Hour)
	pg, err := NewPasswordGuard(credsFromAccounts{accounts}, sessions, NewPasswordPolicy(), WithPasswordCost(bcrypt.MinCost))
	if err != nil {
		t.Fatal(err)
	}
	rg, err := NewRecoveryGuard(verif, accounts, pg)
	if err != nil {
		t.Fatal(err)
	}
	return rg, accounts, sender, sessions, pg
}

func TestRecovery_全流程(t *testing.T) {
	rg, accounts, sender, sessions, _ := newRecoveryFixture(t)
	ctx := context.Background()
	uid, _ := accounts.CreateAccount(ctx, NewAccount{Username: "alice", Email: "alice@x.test", PasswordHash: mustHash(t, "oldpass")})
	tok, _, _ := sessions.Issue(ctx, SessionRecord{UserID: uid})

	// ⭐ 不存在 / 存在 都返回 nil
	if err := rg.Request(ctx, "nobody@x.test", "1.1.1.1"); err != nil {
		t.Fatal("不存在的地址应静默成功")
	}
	if err := rg.Request(ctx, "alice@x.test", "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	waitSent(t, sender, 1)
	msg, _ := sender.last()
	if sender.count() != 1 {
		t.Fatalf("⛔ 不存在的地址也发了信 (共 %d 条)", sender.count())
	}

	if _, err := rg.Complete(ctx, CompleteRequest{Address: "alice@x.test", Code: msg.Code, NewPassword: "brandnewpass"}); err != nil {
		t.Fatal(err)
	}
	// 口令变了
	if bcrypt.CompareHashAndPassword([]byte(accounts.users[uid]["hash"]), []byte("brandnewpass")) != nil {
		t.Fatal("⛔ 口令没改")
	}
	// ⭐ 旧会话全部吊销 (用户没有会话, 不重签)
	if _, err := sessions.Refresh(ctx, tok); err == nil {
		t.Fatal("⛔ 找回后旧会话还活着")
	}
	// 码只能用一次
	if _, err := rg.Complete(ctx, CompleteRequest{Address: "alice@x.test", Code: msg.Code, NewPassword: "another"}); err == nil {
		t.Fatal("⛔ 同一个码用了两次")
	}
}

// TestRecovery_请求与完成之间地址被换 ⭐ 2026-09-05 接管链的形状。
func TestRecovery_请求与完成之间地址被换(t *testing.T) {
	rg, accounts, sender, _, _ := newRecoveryFixture(t)
	ctx := context.Background()
	uid, _ := accounts.CreateAccount(ctx, NewAccount{Username: "alice", Email: "alice@x.test", PasswordHash: mustHash(t, "oldpass")})
	_ = rg.Request(ctx, "alice@x.test", "1.1.1.1")
	waitSent(t, sender, 1)
	msg, _ := sender.last()

	// 攻击者在两步之间把恢复地址改成了自己的
	_, _ = accounts.ChangeVerifiedEmail(ctx, uid, "attacker@evil.test")

	// 用【旧地址】收到的码来完成 —— 地址已不匹配 → 必须拒
	if _, err := rg.Complete(ctx, CompleteRequest{Address: "alice@x.test", Code: msg.Code, NewPassword: "pwned"}); err == nil {
		t.Fatal("⛔ 码发往的地址已不是当前已验证地址, 却完成了重置")
	}
	if bcrypt.CompareHashAndPassword([]byte(accounts.users[uid]["hash"]), []byte("oldpass")) != nil {
		t.Fatal("⛔ 口令被改了")
	}
}

// TestRecovery_未验证与联邦账号不可用 —— 18.3.2 不实现 = 安全。
func TestRecovery_未验证与联邦账号不可用(t *testing.T) {
	rg, accounts, sender, _, _ := newRecoveryFixture(t)
	ctx := context.Background()
	uid, _ := accounts.CreateAccount(ctx, NewAccount{Username: "sso", Email: "sso@x.test", PasswordHash: ""})
	accounts.users[uid]["verified"] = "0"
	if err := rg.Request(ctx, "sso@x.test", "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if sender.count() != 0 {
		t.Fatal("⛔ 未验证地址收到了找回码")
	}
}

// TestResetWithProof_伪造的proof无效 —— 包外构造不出有效 proof, 包内也不认零值。
func TestResetWithProof_伪造的proof无效(t *testing.T) {
	_, accounts, _, _, pg := newRecoveryFixture(t)
	ctx := context.Background()
	uid, _ := accounts.CreateAccount(ctx, NewAccount{Username: "alice", Email: "alice@x.test", PasswordHash: mustHash(t, "oldpass")})
	fake := VerifiedProof{Purpose: PurposeRecoverPassword, Subject: uid}
	if _, err := pg.ResetWithProof(ctx, ResetRequest{UserID: uid, NewPassword: "pwned"}, fake); CodeOf(err) != CodeInvalidCredentials {
		t.Fatal("⛔ 没经过 Verify 的 proof 重置了口令")
	}
	// 用途不对的 proof 也不行
	wrong := VerifiedProof{id: "x", Purpose: PurposeChangeEmail, Subject: uid}
	if _, err := pg.ResetWithProof(ctx, ResetRequest{UserID: uid, NewPassword: "pwned"}, wrong); CodeOf(err) != CodeInvalidCredentials {
		t.Fatal("⛔ 改邮箱的 proof 被当成找回的 proof")
	}
}

func TestEmailChange_全流程与同秒重签存活(t *testing.T) {
	verif, sender, _ := newVerif(t)
	accounts := newMemAccounts()
	sessions, _ := NewSessionGuard(NewSessionMemStore(), activeStatus, time.Hour)
	rev := NewRevocationChecker(newMemRevocationStore())
	g, err := NewEmailChangeGuard(verif, accounts, sessions,
		WithEmailChangeRevoker(rev), WithEmailChangeReissuer(NewDeviceReissuer(sessions, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	uid, _ := accounts.CreateAccount(ctx, NewAccount{Username: "alice", Email: "old@x.test", PasswordHash: "h"})
	_, cur, _ := sessions.Issue(ctx, SessionRecord{UserID: uid})
	otherTok, _, _ := sessions.Issue(ctx, SessionRecord{UserID: uid})

	// Request 不改库
	if err := g.Request(ctx, EmailChangeRequest{UserID: uid, NewEmail: "new@x.test", ClientIP: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if accounts.users[uid]["email"] != "old@x.test" {
		t.Fatal("⛔ Request 阶段就改了库 —— 18.3.4 安全出口在验证不在触碰")
	}
	waitSent(t, sender, 1)
	msg, _ := sender.last()
	if msg.To != "new@x.test" || msg.Purpose != PurposeChangeEmail {
		t.Fatalf("码应发往新地址, got %+v", msg)
	}

	out, err := g.Confirm(ctx, EmailChangeConfirm{UserID: uid, Code: msg.Code, CurrentSessionID: cur.ID})
	if err != nil {
		t.Fatal(err)
	}
	if accounts.users[uid]["email"] != "new@x.test" || accounts.users[uid]["verified"] != "1" {
		t.Fatal("⛔ 确认后库里没变")
	}
	// ① 旧地址收到通知
	waitSent(t, sender, 2)
	notice, _ := sender.last()
	if notice.To != "old@x.test" || notice.Notice != NoticeEmailChanged || notice.NewAddress != "new@x.test" {
		t.Fatalf("⛔ 旧地址没收到通知 —— 那是受害者唯一能知道恢复地址被改的渠道, got %+v", notice)
	}
	// ③ 旧会话吊销, 当前设备重签且【同一秒】签出的 refresh 能用
	if _, err := sessions.Refresh(ctx, otherTok); err == nil {
		t.Fatal("⛔ 其它设备的会话还活着")
	}
	if out.Reissued.RefreshToken == "" {
		t.Fatal("⛔ 没有重签 —— 用户改完邮箱被踢下线")
	}
	if _, err := sessions.Refresh(ctx, out.Reissued.RefreshToken); err != nil {
		t.Fatalf("⛔ 重签出的会话不可用: %v", err)
	}
	// ⭐ 纪元用的是 Revoke 而非 Through: 同一秒签出的 access 必须存活
	if rev.IsRevoked(ctx, uid, time.Now().Truncate(time.Second)) {
		t.Fatal("⛔ 改邮箱用了 RevokeIssuedThrough —— 同一秒重签出的 access token 当场作废, 改完邮箱立刻掉线")
	}
}
