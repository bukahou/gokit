package localauth

import (
	"context"
	"testing"
	"time"
)

// ⭐⭐ 这一组钉的是「改密 / 改邮箱之后, 其它设备的 access token 必须【立刻】失效」——
// 包括与写纪元落在【同一秒】的那些。
//
// # 为什么需要单独一组
//
// 纪元判定是 `iat < epoch`（相等不算失效, 见 revocation.go）。而改密曾用 `Revoke(changedAt)`
// 写纪元, 于是「与 changedAt 同一秒签发」的 token 满足 `iat == epoch` → 幸存,
// 而且是幸存到 access TTL 结束（分钟量级, 由宿主配置）, 不是幸存一秒。
//
// 2026-09-06 生产实测: 扫 14 个登录相位, 命中 1 次 —— `B.iat = 纪元 = 1788684892`,
// 其它设备的 /api/user/info 返回 200。封禁那条路径因为用 `RevokeIssuedThrough`（推到下一秒）
// 早就没有这个窗口, 唯独改密 / 改邮箱这两条留着。
//
// # ⛔ 为什么不能直接改用 RevokeIssuedThrough
//
// 改密紧接着要为当前设备重签一张 token。若纪元推到下一秒而重签的 iat 仍是当前秒,
// 那张刚签出来的 token 会被自己的纪元当场作废 —— 用户改完密码立刻掉线。
// 所以修法必须【同时】把重签 token 的 iat 也定到那一秒:
//
//	epoch = 下一秒起点 T+1
//	重签 iat = T+1  → iat == epoch → 靠"相等不算失效"幸存 ✅
//	其它设备 iat ≤ T → iat < epoch → 全部失效 ✅
//
// 这就是 AccessTokenIssuer 必须接收 issuedAt 的原因（v0.2.0 的 API 变更）。
//
// # 注入时钟, 不靠碰运气
//
// 生产实测要扫 14 个相位才命中 1 次。这里把时钟钉死在某一秒的 0.1 秒处,
// 于是「其它设备的 token 与写纪元同秒」100% 成立 —— ⛔ 一个只在 1/14 概率下变红的
// 测试等于没有测试。

// fixedClock 返回一个钉死的时刻。
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// recordingIssuer 记录每次签发时模块要求的 iat, 并按它生成 token。
// ⭐ 它模拟的是一个【正确实现的宿主】: 模块说 iat 用什么, 就用什么。
type recordingIssuer struct {
	issuedAt []time.Time
	seq      int
}

func (r *recordingIssuer) fn() AccessTokenIssuer {
	return func(_ context.Context, _, _ string, at time.Time) (string, time.Time, error) {
		r.issuedAt = append(r.issuedAt, at)
		r.seq++
		return "access-" + itoa(r.seq), at.Add(15 * time.Minute), nil
	}
}

// last 返回最后一次签发用的 iat。
func (r *recordingIssuer) last(t *testing.T) time.Time {
	t.Helper()
	if len(r.issuedAt) == 0 {
		t.Fatal("⛔ 从未签发过 —— 重签没有发生")
	}
	return r.issuedAt[len(r.issuedAt)-1]
}

// 把「其它设备的 token 是否还有效」这件事写成一个判定, 两个用例共用。
func assertOtherDeviceKilled(t *testing.T, c *RevocationChecker, userID string, otherIat time.Time) {
	t.Helper()
	if !c.IsRevoked(context.Background(), userID, otherIat) {
		t.Fatalf("⛔ 其它设备的 access token 幸存: 它的 iat=%d, 而纪元只推到能让它活下来的位置 —— "+
			"这张 token 会一直有效到 access TTL 结束(分钟量级, 由宿主配置), 而用户改密的动机往往正是"+
			"怀疑账号被盗", otherIat.Unix())
	}
}

func assertCurrentDeviceSurvives(t *testing.T, c *RevocationChecker, userID string, reissuedIat time.Time) {
	t.Helper()
	if c.IsRevoked(context.Background(), userID, reissuedIat) {
		t.Fatalf("⛔ 刚为当前设备重签的 token 被自己的纪元作废了 (iat=%d) —— "+
			"用户改完密码立刻掉线, 100%% 复现", reissuedIat.Unix())
	}
}

func TestChange_同一秒的其它设备token必须失效(t *testing.T) {
	ctx := context.Background()
	// ⭐ 钉在某一秒的 0.1 秒处: 其它设备的 token 与"改密写纪元"落在同一秒, 100% 复现。
	base := time.Date(2026, 9, 6, 12, 0, 30, 100*int(time.Millisecond), time.UTC)
	otherIat := base.Truncate(time.Second) // 其它设备: 与改密同一秒签发

	store := newMemCredStore()
	store.creds["u1"] = Credential{Hash: mustHash(t, "oldpass"), Active: true}
	revStore := newMemRevocationStore()
	checker := NewRevocationChecker(revStore, WithRevocationClock(fixedClock(base)))
	iss := &recordingIssuer{}

	g, sessions := newPwdGuard(t, store,
		WithPasswordClock(fixedClock(base)),
		WithPasswordRevoker(checker),
		WithAccessTokenIssuer(iss.fn()),
	)
	// 两台设备各一条会话
	if _, err := sessions.Create(ctx, SessionRecord{UserID: "u1"}, HashRefreshToken("other")); err != nil {
		t.Fatal(err)
	}
	cur, err := sessions.Create(ctx, SessionRecord{UserID: "u1"}, HashRefreshToken("current"))
	if err != nil {
		t.Fatal(err)
	}

	// ⚠️ CurrentSessionID 必填, 否则 Change 不重签 (那是"管理员代改"的形态)。
	out, err := g.Change(ctx, ChangeRequest{
		UserID: "u1", OldPassword: "oldpass", NewPassword: "brandnewpass",
		CurrentSessionID: cur.ID,
	})
	if err != nil {
		t.Fatalf("改密失败: %v", err)
	}
	if out.NewAccessToken == "" {
		t.Fatal("⛔ 没有为当前设备重签")
	}

	assertOtherDeviceKilled(t, checker, "u1", otherIat)
	assertCurrentDeviceSurvives(t, checker, "u1", iss.last(t))
}

func TestEmailChange_同一秒的其它设备token必须失效(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 9, 6, 12, 0, 30, 100*int(time.Millisecond), time.UTC)
	otherIat := base.Truncate(time.Second)

	revStore := newMemRevocationStore()
	checker := NewRevocationChecker(revStore, WithRevocationClock(fixedClock(base)))
	iss := &recordingIssuer{}

	sg, err := NewSessionGuard(NewSessionMemStore(), activeStatus, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verif, sender, _ := newVerif(t)
	accounts := newMemAccounts()
	ec, err := NewEmailChangeGuard(verif, accounts, sg,
		WithEmailChangeRevoker(checker),
		WithEmailChangeReissuer(NewDeviceReissuer(sg, iss.fn())),
		WithEmailChangeClock(fixedClock(base)),
	)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := accounts.CreateAccount(ctx, NewAccount{Username: "alice", Email: "old@example.invalid", PasswordHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sg.Issue(ctx, SessionRecord{UserID: uid}); err != nil {
		t.Fatal(err)
	}
	_, cur, err := sg.Issue(ctx, SessionRecord{UserID: uid})
	if err != nil {
		t.Fatal(err)
	}

	if err := ec.Request(ctx, EmailChangeRequest{UserID: uid, NewEmail: "new@example.invalid", ClientIP: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	waitSent(t, sender, 1)
	msg, _ := sender.last()
	if _, err := ec.Confirm(ctx, EmailChangeConfirm{UserID: uid, Code: msg.Code, CurrentSessionID: cur.ID}); err != nil {
		t.Fatalf("改邮箱失败: %v", err)
	}

	assertOtherDeviceKilled(t, checker, uid, otherIat)
	assertCurrentDeviceSurvives(t, checker, uid, iss.last(t))
}
