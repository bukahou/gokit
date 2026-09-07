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
	// ⚠️⚠️ 必须【截断到整秒】—— Redis 实现存的是 epoch.Unix(), 亚秒部分丢失。
	//
	// ⛔ 我第一版没截断, 于是这个 fake 保留了亚秒精度, 而那正好【掩盖】了
	// 一个只在生产出现的缺陷: 封禁写 13:00:14.7, Redis 存成 13:00:14,
	// 同一秒签发的 token(iat=13:00:14) 因"相等不算失效"而幸存。
	// 内存 store 里 13:00:14 < 13:00:14.7 成立, 所以测试是绿的。
	//
	// ⭐ fake 的精度必须与真实存储一致, 否则它掩盖的恰恰是精度类缺陷 ——
	// 而那类缺陷只会在生产被发现。
	at = at.Truncate(time.Second)
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
			"退化成'最长一个 access TTL 之后才生效', 而表现与一切正常完全一样", events)
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

// TestRevocation_同一秒签发的token必须被封禁杀掉 ⭐ 一个生产实测才发现的 1 秒窗口。
//
// # 现象 (生产实测 2026-09-05)
//
//	同一秒内登录+封禁 → access token 返回 200 ⛔ 幸存, 然后活满整个 access TTL
//	相隔 3 秒         → 401 ✅
//
// 成因: JWT 的 iat 是秒精度, 判定是 `iat < epoch`("相等不算失效")。
// 而"相等不算失效"是【改密重签】赖以存活的性质 —— 不能为了封禁去掉它。
//
// ⭐ 出路是让封禁把纪元推到【下一秒的起点】, 于是当前这一秒里签发的
// 全部 token 都严格早于纪元。两个调用点的需求本来就不同:
//
//	改密: 杀掉此刻【之前】的      (要保住马上要签的那张)
//	封禁: 连此刻【一起】杀掉      (没有要保住的东西)
//
// # ⛔⛔ 这两个方法【不能合并】—— 本测试就是那道闸
//
// 它们的实现只差一个 `.Add(time.Second)`, 所以下一个人看到"两个几乎
// 一样的吊销方法"很可能顺手合并成一个。⚠️ 合并即复活这个 1 秒窗口:
//   - 都用 Revoke      → 封禁漏掉同一秒签发的 token
//   - 都用 Through     → 改密后重签出的 token 当场作废(立刻掉线)
//
// ⭐ 下面两个子测试各守一侧, 合并之后【必然有一个变红】。
func TestRevocation_同一秒签发的token必须被封禁杀掉(t *testing.T) {
	store := newMemRevocationStore()
	c := NewRevocationChecker(store)
	ctx := context.Background()

	// ⚠️ 模拟真实时序: token 在 .2 秒签发(iat 截断成整秒), 封禁在 .7 秒。
	sec := time.Date(2026, 9, 5, 13, 0, 14, 0, time.UTC)
	tokenIAT := sec // JWT 的 iat 是整秒
	banAt := sec.Add(700 * time.Millisecond)

	t.Run("ⓘ Revoke 的语义就是『严格早于』, 同一秒会幸存", func(t *testing.T) {
		// ⚠️ 这【不是】bug, 而是改密重签赖以存活的性质。
		// 记在这里是为了让下一个人看到两个方法为什么必须分开。
		if err := c.Revoke(ctx, "leak", banAt); err != nil {
			t.Fatal(err)
		}
		if c.IsRevoked(ctx, "leak", tokenIAT) {
			t.Error("⛔ Revoke 把同一秒签发的 token 也杀了 —— " +
				"那会让改密后重签出的 token 当场作废(改完密码立刻掉线)")
		}
	})

	t.Run("⭐ RevokeIssuedThrough 必须杀掉它", func(t *testing.T) {
		if err := c.RevokeIssuedThrough(ctx, "banned", banAt); err != nil {
			t.Fatal(err)
		}
		if !c.IsRevoked(ctx, "banned", tokenIAT) {
			t.Fatal("⛔⛔ 与封禁【同一秒】签发的 token 幸存了 —— " +
				"它会活满整个 access TTL, " +
				"而封禁这个动作的语义是『现在就把他挡在外面』")
		}
		// ⭐ 但下一秒签发的必须放行 —— 否则解封后立刻登录会被误杀
		if c.IsRevoked(ctx, "banned", sec.Add(time.Second)) {
			t.Error("⛔ 下一秒签发的 token 被误杀 —— 解封后立刻登录会登不进去")
		}
	})
}
