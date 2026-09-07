package redisstore

import (
	"github.com/bukahou/gokit/localauth"

	"context"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// Test运行期Redis挂掉_必须fail_open 走【真实客户端 + 真 Redis + 真的把它杀掉】。
//
// ⚠️ 单测里的 failing store 证明的是"如果 store 返回 error, 守卫会放行"。
// 它证明不了【go-redis 客户端在连接断开时到底返回什么】——
// 比如它会不会阻塞很久、会不会 panic、返回的 error 是不是 redis.Nil
// (那会被当成"没有纪元"而不是"查不了", 于是降级事件不会发出来)。
//
// ⭐ 这一层验的正是那个: 同一份客户端代码路径, 遇到真的连接失败。
// ⛔ 生产不做这个实验 —— 那台 Redis 同时服务 media 缓存与会话存储,
// 为验一条防御回退去制造一次全站抖动不划算, 而且验的东西完全一样。
//
//	LOCALAUTH_TEST_KILLABLE_REDIS_PORT=6399 go test ./redisstore/ -run 运行期Redis挂掉
func Test运行期Redis挂掉_必须fail_open(t *testing.T) {
	port := os.Getenv("LOCALAUTH_TEST_KILLABLE_REDIS_PORT")
	if port == "" {
		t.Skip("未设置 LOCALAUTH_TEST_KILLABLE_REDIS_PORT")
	}
	prefix := "failopen:" + strconv.FormatInt(time.Now().UnixNano(), 36) + ":"
	store, err := NewRedisRevocationStore("redis://localhost:"+port+"/0", prefix, time.Hour)
	if err != nil {
		t.Fatalf("连不上可杀的 Redis: %v", err)
	}

	var events []localauth.EventKind
	c := localauth.NewRevocationChecker(store, localauth.WithRevocationAudit(
		func(_ context.Context, e localauth.AuditEvent) { events = append(events, e.Kind) }))
	ctx := context.Background()
	base := time.Now().Truncate(time.Second)

	// ---- Redis 活着: 吊销生效 ----
	if err := c.RevokeIssuedThrough(ctx, "u1", base); err != nil {
		t.Fatal(err)
	}
	if !c.IsRevoked(ctx, "u1", base) {
		t.Fatal("前提不成立: Redis 活着时吊销应当生效")
	}
	if len(events) != 0 {
		t.Fatalf("正常路径不该发事件, got %v", events)
	}
	t.Log("ⓘ Redis 活着: 吊销生效, 无降级事件")

	// ---- ⭐ 杀掉 Redis ----
	if out, err := exec.Command("redis-cli", "-p", port, "SHUTDOWN", "NOSAVE").CombinedOutput(); err != nil {
		t.Logf("SHUTDOWN 返回 (预期连接被断开): %v %s", err, out)
	}
	time.Sleep(500 * time.Millisecond)

	// ---- Redis 死了: 必须放行, 且必须留痕 ----
	start := time.Now()
	revoked := c.IsRevoked(ctx, "u1", base.Add(-time.Hour))
	elapsed := time.Since(start)

	if revoked {
		t.Error("⛔⛔ Redis 挂掉后拒绝了请求 —— 那等于 'Redis 抖动 = 全站掉线'。" +
			"放行的代价只是退回本特性上线前(靠 access TTL 兜底 ≤ 一个 access TTL), " +
			"两者不在一个量级")
	} else {
		t.Log("⭐ Redis 已死: 放行 (fail-open) ✅")
	}

	if len(events) == 0 {
		t.Error("⛔ 降级没有留痕 —— fail-open 的表现与'一切正常'完全一样, " +
			"没有事件就意味着 Redis 可以挂三个月而没人知道")
	} else if events[len(events)-1] != localauth.EventRevocationCheckUnavailable {
		t.Errorf("⛔ 发的不是 %s 而是 %s —— "+
			"若客户端把连接失败报成 redis.Nil, 会被当成'没有纪元'而静默放行",
			localauth.EventRevocationCheckUnavailable, events[len(events)-1])
	} else {
		t.Logf("⭐ 降级已留痕: %s ✅", events[len(events)-1])
	}

	// ⚠️ 顺带看耗时: 请求路径上不能因为 Redis 死了就卡很久。
	t.Logf("ⓘ Redis 已死时单次判定耗时: %v", elapsed)
	// ⚠️ 阈值必须【紧】—— 我第一版写的 3 秒放过了 1.68 秒这个真问题。
	// 判定在每个已登录请求上执行, 多等 1 秒 × QPS = 网关积压。
	if elapsed > 800*time.Millisecond {
		t.Errorf("⛔ Redis 死后单次判定耗时 %v —— 每个已登录请求都要等这么久, "+
			"fail-open 变成了 fail-slow(而 fail-slow 在负载下与 fail-closed 无异)", elapsed)
	}

	// ---- 写入也必须报错而不是假装成功 ----
	if err := c.RevokeIssuedThrough(ctx, "u2", time.Now()); err == nil {
		t.Error("⛔ Redis 死了但 Revoke 返回 nil —— 调用方会以为吊销成功了")
	} else {
		t.Log("⭐ 写入失败如实返回 error ✅")
	}
}
