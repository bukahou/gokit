package localauth_test

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/bukahou/gokit/localauth"
)

// noopSender 是最小的 MessageSender: 什么都不投递。真实宿主接 SMTP / 短信。
type noopSender struct{}

func (noopSender) SendVerification(context.Context, localauth.VerificationMessage) error { return nil }

// Example 是最小宿主接线: 三个内存存储 + 不投递的信使 + 不查泄露的检查器。
//
// ⚠️ 内存存储只适合单副本与测试 (多副本下每个进程各一份计数, 退避被稀释);
// 生产要用与用户表同排序规则的数据库表, 并用 storetest 验证自己的实现。
func Example() {
	ctx := context.Background()

	// ---- ① 登录守卫: 限流退避 + 时序一致 ----
	// 宿主只需回答"这个用户名对应的 bcrypt 哈希是什么"; 密码比对、计数、退避全在模块里。
	guard, err := localauth.New(
		localauth.TrustDirect(),            // 客户端 IP 策略: 直连, 不信任任何转发头
		localauth.AdmitAll(),               // 注册准入: 谁都能建号
		localauth.NewMemStore(),            // IP 维度失败计数
		localauth.NewMemStore(),            // 账号维度失败计数
		localauth.WithCost(bcrypt.MinCost), // 示例用最低 cost, 生产用默认值
	)
	if err != nil {
		panic(err)
	}
	stored, _ := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	lookup := func(_ context.Context, username string) (hash string, found bool, err error) {
		if username == "alice" {
			return string(stored), true, nil
		}
		return "", false, nil // 用户不存在: 模块仍会跑等量的 bcrypt, 时序一致
	}
	out, err := guard.Login(ctx, "203.0.113.7", "alice", "correct horse battery staple", lookup)
	fmt.Println("登录放行:", out.Allowed, err)
	out, _ = guard.Login(ctx, "203.0.113.7", "alice", "wrong", lookup)
	fmt.Println("错误口令:", out.Allowed)

	// ---- ② 会话守卫: 签发 / 轮换 / 重放反击 ----
	status := func(context.Context, string) (localauth.AccountStatus, error) {
		return localauth.AccountStatus{Active: true}, nil
	}
	sessions, err := localauth.NewSessionGuard(localauth.NewSessionMemStore(), status, 24*time.Hour)
	if err != nil {
		panic(err)
	}
	refresh, rec, _ := sessions.Issue(ctx, localauth.SessionRecord{UserID: "u-alice", DeviceInfo: "example"})
	fmt.Println("会话已建:", rec.ID != "", "refresh token 非空:", refresh != "")
	rotated, err := sessions.Refresh(ctx, refresh)
	fmt.Println("轮换:", err == nil, "新 token 不同:", rotated.NewRefreshToken != refresh)

	// ---- ③ 验证码 + 口令策略: 注册 / 找回 / 改邮箱共用 ----
	policy := localauth.NewPasswordPolicy(localauth.WithBreachChecker(localauth.NewNoopBreachChecker()))
	verif, err := localauth.NewVerificationGuard(
		localauth.NewVerificationMemStore(), noopSender{},
		localauth.NewMemStore(), localauth.NewMemStore(),
		[]byte("example-pepper-at-least-16-bytes"), // ⚠️ 生产从配置注入, 不进代码
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("验证守卫就绪:", verif != nil, "泄露检查器:", policy.BreachKind())

	// Output:
	// 登录放行: true <nil>
	// 错误口令: false
	// 会话已建: true refresh token 非空: true
	// 轮换: true 新 token 不同: true
	// 验证守卫就绪: true 泄露检查器: noop
}
