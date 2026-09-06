package localauth

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// Test纪元_真Redis 验的是【Lua 脚本的原子语义】—— 内存实现证明不了它。
//
// ⚠️ 内存 store 里"只前进不后退"是我自己写的几行 Go, 它证明的是
// "如果实现正确, 语义就正确"。而真正要验的是那段 Lua 在 Redis 里
// 到底是不是这么执行的 —— 那是另一回事。
//
//	GEASS_TEST_REDIS_URL='redis://localhost:6379/9' go test ./pkg/localauth/ -run 纪元_真Redis
func Test纪元_真Redis(t *testing.T) {
	url := os.Getenv("GEASS_TEST_REDIS_URL")
	if url == "" {
		t.Skip("未设置 GEASS_TEST_REDIS_URL")
	}
	prefix := "geasstest:revoke:" + strconv.FormatInt(time.Now().UnixNano(), 36) + ":"
	store, err := NewRedisRevocationStore(url, prefix, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c := NewRevocationChecker(store)

	base := time.Now().Truncate(time.Second)

	t.Run("没写过 → 查不到且不报错", func(t *testing.T) {
		_, found, err := store.LoadEpoch(ctx, "u1")
		if err != nil {
			t.Fatalf("⛔ 未命中被当成了错误: %v —— 那会让每个正常用户都触发降级告警", err)
		}
		if found {
			t.Error("不该找到")
		}
	})

	t.Run("写入后能读回同一个秒级时间", func(t *testing.T) {
		if err := c.Revoke(ctx, "u1", base); err != nil {
			t.Fatal(err)
		}
		got, found, err := store.LoadEpoch(ctx, "u1")
		if err != nil || !found {
			t.Fatalf("读回失败 found=%v err=%v", found, err)
		}
		if !got.Equal(base) {
			t.Errorf("读回 %v, 期望 %v", got, base)
		}
	})

	t.Run("⭐ Lua 脚本: 只前进不后退", func(t *testing.T) {
		late := base.Add(30 * time.Second)
		if err := c.Revoke(ctx, "u2", late); err != nil {
			t.Fatal(err)
		}
		// ⚠️ 乱序: 一个较早的纪元后到
		if err := c.Revoke(ctx, "u2", base); err != nil {
			t.Fatal(err)
		}
		got, _, _ := store.LoadEpoch(ctx, "u2")
		if !got.Equal(late) {
			t.Fatalf("⛔ 纪元被往回拨到 %v (应保持 %v) —— "+
				"base~late 之间签发的 token 会【复活】。"+
				"封禁一个正在改密的用户恰恰是最需要吊销生效的时刻", got, late)
		}
	})

	t.Run("⭐ 判定语义: 同一秒放行, 更早拒绝", func(t *testing.T) {
		if c.IsRevoked(ctx, "u1", base) {
			t.Error("⛔ iat 与纪元同一秒时被拒 —— 改密重签出的 token 总是落在同一秒")
		}
		if !c.IsRevoked(ctx, "u1", base.Add(-time.Second)) {
			t.Error("⛔ 纪元之前签发的 token 应被拒")
		}
	})

	t.Run("TTL 已设置且覆盖 access TTL", func(t *testing.T) {
		// ⚠️ TTL 比 access TTL 短是真实缺口: 纪元先过期而 token 还活着 → 复活。
		rs := store.(*redisRevocationStore)
		d, err := rs.client.TTL(ctx, rs.key("u1")).Result()
		if err != nil {
			t.Fatal(err)
		}
		if d <= 0 {
			t.Fatalf("⛔ key 没有 TTL (%v) —— 要么永不过期(泄漏), 要么已过期", d)
		}
		if d > time.Hour {
			t.Errorf("TTL %v 超过设定的 1h", d)
		}
		t.Logf("ⓘ TTL = %v", d)
	})

	t.Cleanup(func() {
		rs := store.(*redisRevocationStore)
		for _, k := range []string{"u1", "u2"} {
			rs.client.Del(ctx, rs.key(k))
		}
		_ = rs.client.Close()
	})
}
