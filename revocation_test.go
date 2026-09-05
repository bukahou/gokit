package localauth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type memRevocationStore struct {
	mu     sync.Mutex
	epochs map[string]time.Time
	fail   bool
}

func newMemRevocationStore() *memRevocationStore {
	return &memRevocationStore{epochs: map[string]time.Time{}}
}

func (m *memRevocationStore) LoadEpoch(_ context.Context, id string) (time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return time.Time{}, false, errors.New("redis 炸了")
	}
	e, ok := m.epochs[id]
	return e, ok, nil
}

func (m *memRevocationStore) SaveEpoch(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("redis 炸了")
	}
	// ⭐ 只前进不后退 —— 与 Redis 实现的 Lua 脚本语义一致。
	if cur, ok := m.epochs[id]; ok && !at.After(cur) {
		return nil
	}
	m.epochs[id] = at
	return nil
}

func TestRevocation_基本判定(t *testing.T) {
	store := newMemRevocationStore()
	c := NewRevocationChecker(store)
	ctx := context.Background()
	base := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	t.Run("没有纪元 → 放行", func(t *testing.T) {
		if c.IsRevoked(ctx, "u1", base) {
			t.Error("⛔ 从没吊销过的用户被拒了 —— 那是绝大多数请求")
		}
	})

	if err := c.Revoke(ctx, "u1", base); err != nil {
		t.Fatal(err)
	}

	t.Run("⭐ 签发早于纪元 → 拒绝", func(t *testing.T) {
		if !c.IsRevoked(ctx, "u1", base.Add(-time.Second)) {
			t.Error("⛔ 纪元之前签发的 token 应被拒 —— 否则改密/封禁不生效")
		}
	})

	t.Run("⭐⭐ 与纪元【同一秒】→ 放行", func(t *testing.T) {
		// ⚠️ 这条是裕度为零的那一处, 与 §7.7 同源。
		//
		// 改密流程: 取 changedAt → 写库 → 写纪元(=changedAt) → 重签。
		// 重签出的 token 其 iat 与 changedAt 相隔几毫秒, 而纪元存的是
		// unix【秒】—— 截断后两者相等。
		//
		// ⛔ 若"相等"也算失效, 每一次改密都会让新签出来的 access token
		// 当场作废 —— 用户改完密码立刻掉线, 100% 复现。
		if c.IsRevoked(ctx, "u1", base) {
			t.Fatal("⛔⛔ iat 与纪元相等时被判失效 —— " +
				"改密后重签出的 token 与纪元【总是】落在同一秒, " +
				"这会让每一次改密都以'立刻掉线'收场")
		}
	})

	t.Run("签发晚于纪元 → 放行", func(t *testing.T) {
		if c.IsRevoked(ctx, "u1", base.Add(time.Second)) {
			t.Error("纪元之后签发的 token 应放行")
		}
	})

	t.Run("不影响别的用户", func(t *testing.T) {
		if c.IsRevoked(ctx, "u2", base.Add(-time.Hour)) {
			t.Error("⛔ 吊销 u1 影响到了 u2")
		}
	})
}

// TestRevocation_只前进不后退 守的是一个并发下的真实缺口。
func TestRevocation_只前进不后退(t *testing.T) {
	store := newMemRevocationStore()
	c := NewRevocationChecker(store)
	ctx := context.Background()
	late := time.Date(2026, 9, 5, 12, 0, 10, 0, time.UTC)
	early := late.Add(-10 * time.Second)

	if err := c.Revoke(ctx, "u1", late); err != nil {
		t.Fatal(err)
	}
	// ⚠️ 乱序写: 一个较早的纪元后到 (封禁与改密并发时完全可能)。
	if err := c.Revoke(ctx, "u1", early); err != nil {
		t.Fatal(err)
	}
	// ⭐ 纪元不得被拨回去 —— 否则 early~late 之间签发的 token 会【复活】。
	if !c.IsRevoked(ctx, "u1", early.Add(time.Second)) {
		t.Error("⛔ 纪元被往回拨了 —— 一批本该失效的 token 复活了。" +
			"封禁一个正在改密的用户恰恰是最需要吊销生效的时刻")
	}
}

// TestRevocation_存储故障必须fail_open且留痕 是 D2 裁决的可执行版本。
func TestRevocation_存储故障必须fail_open且留痕(t *testing.T) {
	store := newMemRevocationStore()
	var events []EventKind
	c := NewRevocationChecker(store, WithRevocationAudit(
		func(_ context.Context, e AuditEvent) { events = append(events, e.Kind) }))
	ctx := context.Background()
	base := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	if err := c.Revoke(ctx, "u1", base); err != nil {
		t.Fatal(err)
	}
	store.fail = true

	// ⭐ fail-open: 查不了就放行。
	if c.IsRevoked(ctx, "u1", base.Add(-time.Hour)) {
		t.Error("⛔ 存储故障时拒绝了请求 —— 那等于 'Redis 抖动 = 全站掉线', " +
			"违反 pkg/cache 立的第一条约束")
	}
	// ⭐ 但必须留痕, 否则 fail-open 的代价看不见。
	if len(events) != 1 || events[0] != EventRevocationCheckUnavailable {
		t.Errorf("⛔ 降级没留痕 (%v) —— Redis 挂掉后'封禁立即生效'会静默"+
			"退化成'最长 900 秒后生效', 而表现与一切正常完全一样", events)
	}
}

// TestRevocation_正常路径不发事件 —— 否则噪声会淹掉真正的故障。
func TestRevocation_正常路径不发事件(t *testing.T) {
	var events []EventKind
	c := NewRevocationChecker(newMemRevocationStore(), WithRevocationAudit(
		func(_ context.Context, e AuditEvent) { events = append(events, e.Kind) }))
	for i := 0; i < 100; i++ {
		c.IsRevoked(context.Background(), "u1", time.Now())
	}
	if len(events) != 0 {
		t.Errorf("⛔ 「没有纪元」发了 %d 条事件 —— 那是绝大多数请求的正常状态, "+
			"记了就是纯噪声, 而且会把真正的故障淹掉", len(events))
	}
}

// TestRevocation_未配置时永远放行且不panic
func TestRevocation_未配置时永远放行且不panic(t *testing.T) {
	c := NewRevocationChecker(nil)
	if c.Enabled() {
		t.Error("未配置时 Enabled 应为 false")
	}
	if c.IsRevoked(context.Background(), "u1", time.Time{}) {
		t.Error("未配置时应永远放行")
	}
	if err := c.Revoke(context.Background(), "u1", time.Now()); err != nil {
		t.Errorf("未配置时 Revoke 应当无操作且不报错: %v", err)
	}
}
