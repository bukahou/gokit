package localauth

import (
	"bytes"
	"context"
	"sync"
	"time"
)

// NewSessionMemStore 返回一个进程内的 SessionStore。
//
// ⚠️ 仅供本地开发与测试。⛔ 多副本下它是错的 —— 每个进程一份，
// 于是"轮换"只在自己这份里生效，重放检测形同虚设。
//
// ⭐ 它存在的意义是让 SessionGuard 的编排能被穷举单测，
// 而编排的正确性（轮换顺序、重放处置、状态复查次序）恰恰是最容易写错、
// 又最不该靠连库测试来验的部分。
func NewSessionMemStore() SessionStore {
	return &sessionMemStore{rows: map[string]*memSession{}}
}

type memSession struct {
	rec  SessionRecord
	hash []byte
	// prevHash 是【上一个】refresh 哈希。
	//
	// ⭐ 它存在的理由不是宽限期(我们没有宽限期), 是【归属判定】:
	// 轮换会把 hash 覆盖掉, 于是重放来的旧 token 匹配不到任何行 ——
	// 连"这是谁的会话"都不知道, 就无从吊销。
	// ⚠️ 没有它, 重放检测只能拒绝而【不能反击】, 攻击者那条链会活到 TTL 结束。
	prevHash []byte
	valid    bool
}

type sessionMemStore struct {
	mu   sync.Mutex
	rows map[string]*memSession // key = 会话 id
	seq  int
}

func (s *sessionMemStore) Create(_ context.Context, rec SessionRecord, hash []byte) (SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	rec.ID = "sess-" + itoa(s.seq)
	s.rows[rec.ID] = &memSession{rec: rec, hash: append([]byte(nil), hash...), valid: true}
	return rec, nil
}

// Rotate 模拟单条原子 UPDATE：⭐ 整个操作在锁内完成，
// 所以并发调用中只有一方能匹配到旧哈希。
func (s *sessionMemStore) Rotate(
	_ context.Context, oldHash, newHash []byte, newExpiry time.Time,
) (SessionRecord, RotateOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.valid && bytes.Equal(r.hash, oldHash) {
			r.prevHash = r.hash
			r.hash = append([]byte(nil), newHash...)
			r.rec.ExpiresAt = newExpiry
			r.rec.LastActiveAt = time.Now()
			return r.rec, RotateRotated, nil
		}
	}

	// ⭐⭐ 没轮换到时, 必须分清是【重放】还是【已正常失效】——
	// 两者的处置相反, 见 RotateOutcome 的注释。
	//
	// ⚠️ 先查 prevHash: 命中它说明这个 token 已经【被换走过】,
	// 也就是存在第二方 —— 那才是重放。
	//
	// ⭐ 它覆盖的正是真实的失窃形态:
	//   攻击者偷到 R1 先用 → R1→R2 (攻击者持 R2)
	//   合法客户端仍持 R1, 用它 → R1 现在是 prevHash → 命中 → 吊销全部
	//   → ⭐ 攻击者的 R2 一并作废
	for _, r := range s.rows {
		if len(r.prevHash) > 0 && bytes.Equal(r.prevHash, oldHash) {
			return SessionRecord{UserID: r.rec.UserID}, RotateReplayed, nil
		}
	}

	// 命中【当前】哈希 = 这个 token 从没被换走过, 只是会话死了
	// (自己登出 / 被别的设备登出 / 过期)。⛔ 这【不是】重放。
	for _, r := range s.rows {
		if bytes.Equal(r.hash, oldHash) {
			return SessionRecord{UserID: r.rec.UserID}, RotateRevoked, nil
		}
	}

	// ⚠️ 轮换两次以上的旧 token 会落到这里(prev 已被覆盖) —— 只能拒绝,
	// 不能反击。那是可接受的: 上面那个顺序才是真实的失窃形态。
	return SessionRecord{}, RotateUnknown, nil
}

func (s *sessionMemStore) FindByHash(_ context.Context, hash []byte) (SessionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.valid && bytes.Equal(r.hash, hash) {
			return r.rec, true, nil
		}
	}
	return SessionRecord{}, false, nil
}

func (s *sessionMemStore) RevokeByHash(_ context.Context, hash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if bytes.Equal(r.hash, hash) {
			r.valid = false
		}
	}
	return nil
}

func (s *sessionMemStore) RevokeByID(_ context.Context, userID, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// ⚠️ userID 必须一起匹配 —— 只按 sessionID 是一个 IDOR。
	if r, ok := s.rows[sessionID]; ok && r.rec.UserID == userID {
		r.valid = false
	}
	return nil
}

func (s *sessionMemStore) RevokeAllByUser(_ context.Context, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.rows {
		if r.valid && r.rec.UserID == userID {
			r.valid = false
			n++
		}
	}
	return n, nil
}

func (s *sessionMemStore) RevokeOthersByUser(_ context.Context, userID string, keepSessionID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.rows {
		if r.valid && r.rec.UserID == userID && r.rec.ID != keepSessionID {
			r.valid = false
			n++
		}
	}
	return n, nil
}

func (s *sessionMemStore) ListByUser(_ context.Context, userID string) ([]SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []SessionRecord
	for _, r := range s.rows {
		if r.valid && r.rec.UserID == userID {
			out = append(out, r.rec)
		}
	}
	return out, nil
}
