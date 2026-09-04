package localauth

import (
	"context"
	"sync"
	"time"
)

// NewMemStore 返回一个进程内的 FailureStore。
//
// ⛔ 仅供【单副本部署与本地开发】。多副本下它是错的 ——
// 每个副本各有一份计数, 有效阈值等于配置值乘以副本数, 而这个稀释
// 没有任何症状: 测试会通过, 日志正常, 只是防护变松了 N 倍。
//
// ⚠️ 而且它对账号维度还少了一样东西: 数据库那一侧的折叠规则。
// 若查找用户是大小写不敏感的, 这里的 map 是大小写敏感的,
// Alice 与 alice 会落进两个桶 —— 生产必须用与用户表同排序规则的表。
func NewMemStore() FailureStore {
	return &memStore{m: map[string]FailureState{}}
}

type memStore struct {
	mu sync.Mutex
	m  map[string]FailureState
}

func (s *memStore) Peek(_ context.Context, key string) (FailureState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[key], nil
}

func (s *memStore) Bump(_ context.Context, key string, now time.Time) (FailureState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st := s.m[key]
	if st.Count == 0 {
		st.FirstFailAt = now
	}
	st.Count++
	st.LastFailAt = now
	s.m[key] = st
	return st, nil
}

func (s *memStore) Reset(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}
