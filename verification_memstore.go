package localauth

import (
	"context"
	"strconv"
	"sync"
	"time"
)

// NewVerificationMemStore 进程内 VerificationStore。⚠️ 仅测试与本地开发。
//
// ⭐ 精度与真实存储一致: 时间截断到整秒 (DB 的 datetime 是秒精度)。
// 2026-09-05 的教训: fake 保留亚秒而 Redis 存整秒, 掩盖的正是精度类缺陷。
func NewVerificationMemStore() VerificationStore {
	return &verificationMemStore{rows: map[string]*memVerification{}}
}

type memVerification struct {
	rec      VerificationRecord
	hash     []byte
	consumed bool
}

type verificationMemStore struct {
	mu   sync.Mutex
	rows map[string]*memVerification
	seq  int
}

func (s *verificationMemStore) Issue(_ context.Context, rec VerificationRecord, hash []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 一人一码: 同 (subject, purpose) 的未消费行先作废
	for _, r := range s.rows {
		if !r.consumed && r.rec.Purpose == rec.Purpose && r.rec.Subject == rec.Subject {
			r.consumed = true
		}
	}
	s.seq++
	rec.ID = "vt-" + strconv.Itoa(s.seq)
	rec.ExpiresAt = rec.ExpiresAt.Truncate(time.Second)
	s.rows[rec.ID] = &memVerification{rec: rec, hash: append([]byte(nil), hash...)}
	return rec.ID, nil
}

func (s *verificationMemStore) FindPending(_ context.Context, purpose TokenPurpose, subject string) (VerificationRecord, []byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if !r.consumed && r.rec.Purpose == purpose && r.rec.Subject == subject {
			return r.rec, r.hash, true, nil
		}
	}
	return VerificationRecord{}, nil, false, nil
}

func (s *verificationMemStore) BumpAttempts(_ context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[id]; ok {
		r.rec.Attempts++
		return r.rec.Attempts, nil
	}
	return 0, nil
}

func (s *verificationMemStore) Consume(_ context.Context, id string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[id]
	if !ok || r.consumed {
		return false, nil
	}
	r.consumed = true
	return true, nil
}
