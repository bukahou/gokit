package localauth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisRevocationStore 是 RevocationStore 的 Redis 实现。
//
// # key 形状
//
//	<prefix><userID>  →  纪元的 unix 秒 (十进制字符串)
//
// # ⭐ TTL 不是"缓存过期", 是一个正确性推论
//
// 纪元只需要活得比【最长寿的 access token】久。超过那个时间之后,
// 所有"签发早于纪元"的 token 本来就都过期了, 纪元再留着也没有任何作用。
//
// ⚠️ 所以 TTL 必须 >= access token TTL, 并留出余量应对时钟偏差。
// ⛔ 设得比 access TTL 短是一个真实的安全缺口: 纪元先过期,
// 而那些本该被拒的 token 还活着 —— 于是它们【复活】。
type redisRevocationStore struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

// NewRedisRevocationStore 构造 Redis 实现 (单实例)。
func NewRedisRevocationStore(redisURL, prefix string, ttl time.Duration) (RevocationStore, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("解析 Redis URL 失败: %w", err)
	}
	return newPingedRevocationStore(redis.NewClient(opt), prefix, ttl)
}

// NewRedisSentinelRevocationStore 构造 Redis 实现 (Sentinel 高可用)。
func NewRedisSentinelRevocationStore(
	masterName string, sentinelAddrs []string, db int, prefix string, ttl time.Duration,
) (RevocationStore, error) {
	if masterName == "" || len(sentinelAddrs) == 0 {
		return nil, errors.New("Sentinel 模式需要 masterName 与 sentinelAddrs")
	}
	return newPingedRevocationStore(redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:    masterName,
		SentinelAddrs: sentinelAddrs,
		DB:            db,
	}), prefix, ttl)
}

// newPingedRevocationStore ⚠️ 构造时 Ping 一次 —— 连不上就【构造失败】。
//
// ⛔ 不静默返回一个"永远查不到"的 store: 那会让服务带着一个
// 恒 fail-open 的吊销检查启动, 而症状与"一切正常"完全一样。
// 启动期配错要响, 运行期故障才 fail-open —— 两个时刻, 两种责任人。
func newPingedRevocationStore(
	c *redis.Client, prefix string, ttl time.Duration,
) (RevocationStore, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("连接 Redis 失败: %w", err)
	}
	if ttl <= 0 {
		return nil, errors.New("吊销纪元 TTL 必须为正")
	}
	return &redisRevocationStore{client: c, prefix: prefix, ttl: ttl}, nil
}

func (s *redisRevocationStore) key(userID string) string { return s.prefix + userID }

func (s *redisRevocationStore) LoadEpoch(
	ctx context.Context, userID string,
) (time.Time, bool, error) {
	v, err := s.client.Get(ctx, s.key(userID)).Result()
	if errors.Is(err, redis.Nil) {
		// ⭐ 没有纪元 = 从没吊销过。这是【绝大多数请求】的正常状态,
		// ⛔ 不是错误 —— 见 RevocationStore 的注释。
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("读取吊销纪元失败: %w", err)
	}
	sec, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		// ⚠️ 值坏了。⛔ 当作"查不了"而不是"没有" —— 后者会静默放行,
		// 而我们并不知道这个用户是不是刚被封。
		return time.Time{}, false, fmt.Errorf("吊销纪元不是合法时间戳 %q: %w", v, err)
	}
	return time.Unix(sec, 0), true, nil
}

// revokeScript 是"只前进不后退"的原子写。
//
// # ⚠️ 为什么必须是脚本而不是 GET + 比较 + SET
//
// 后者是 TOCTOU: 封禁与改密并发时, 两个进程都读到旧值, 然后各自写,
// ⛔ 后写的那个可能把纪元【往回拨】—— 于是一批本该失效的 token 复活。
//
// ⭐ 而且这不是理论风险: 封禁一个正在改密的用户完全可能同时发生,
// 那恰恰是最需要吊销生效的时刻。
//
// KEYS[1] = key, ARGV[1] = 新纪元(unix 秒), ARGV[2] = TTL(秒)
var revokeScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
if cur and tonumber(cur) and tonumber(cur) >= tonumber(ARGV[1]) then
  -- 已有更晚的纪元, 保持不变但刷新 TTL(它仍然要覆盖住最长寿的 token)
  redis.call('EXPIRE', KEYS[1], ARGV[2])
  return cur
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return ARGV[1]
`)

func (s *redisRevocationStore) SaveEpoch(
	ctx context.Context, userID string, epoch time.Time,
) error {
	err := revokeScript.Run(ctx, s.client,
		[]string{s.key(userID)},
		strconv.FormatInt(epoch.Unix(), 10),
		strconv.FormatInt(int64(s.ttl.Seconds()), 10),
	).Err()
	if err != nil {
		return fmt.Errorf("写入吊销纪元失败: %w", err)
	}
	return nil
}
