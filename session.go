package localauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

// ============ 会话凭证 ============

// refreshTokenBytes 是 refresh token 的随机字节数。
//
// 32 字节 = 256 bit。⭐ 这个数字支撑了本文件后面所有的"不需要慢哈希"论证 ——
// ⛔ 调小它必须同时重新评估 hashRefreshToken 的选择。
const refreshTokenBytes = 32

// NewRefreshToken 生成一个新的 refresh token 明文。
//
// ⚠️ 返回的明文【只应该交给客户端】。存储层永远只见哈希 ——
// SessionStore 的签名里没有任何一个参数能接受明文, 那是刻意的。
func NewRefreshToken() (string, error) {
	b := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("生成 refresh token 失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashRefreshToken 计算存储用的哈希。
//
// # ⛔ 刻意【不用】慢哈希 (bcrypt/argon2)
//
// 慢哈希防的是【低熵秘密的离线爆破】—— 也就是口令。
// refresh token 是 256 bit 的密码学随机数, 离线爆破在物理上不可行:
// 就算每秒试 2^64 次, 穷尽 2^256 也需要远超宇宙年龄的时间。
// 用 bcrypt 只会让每次刷新多花 80ms, 而【没有换来任何安全性】。
//
// ⚠️ 这条论证的前提是【高熵】。⛔ 谁将来把 refresh token 改成
// "用户可读的短码"(比如 6 位数字、或者带校验位的 12 字符),
// 必须【同时】把这里换成慢哈希 —— 这两件事绑定, 改一个不改另一个
// 就是一个可离线爆破的凭证库, 而且没有任何症状。
//
// # 为什么不加 salt
//
// salt 防的是彩虹表, 而彩虹表要求秘密空间小到能预计算。2^256 不是那种空间。
// 加 salt 还会让"按哈希查一行"退化成全表扫描 —— 代价实在, 收益为零。
func HashRefreshToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// ============ 存储契约 ============

// SessionRecord 是一条会话的【非机密】视图。
//
// ⛔ 它不含 token 明文, 也不含哈希 —— 哈希是存储层的内部事,
// 列表接口把它带出来只会增加泄漏面而没有任何用途。
type SessionRecord struct {
	// ID 会话标识。由存储层生成, 模块不解释它的格式。
	ID string
	// UserID ⚠️ 是 string 而不是任何具体类型 —— 模块【不假设宿主的 id 形态】。
	// geass 用 UUID、melete 用 int、atlhyper 可能用别的。
	UserID string

	CreatedAt    time.Time
	LastActiveAt time.Time
	ExpiresAt    time.Time

	// DeviceInfo / ClientIP 供用户在会话列表里辨认"这是不是我"。
	//
	// ⚠️ ClientIP 必须是【解析后的可信 IP】(见 ClientIPStrategy),
	// ⛔ 不得是 X-Forwarded-For 整条链 —— 那是客户端可伪造的,
	// 把它展示给用户等于给他看一条攻击者可以随便写的字符串。
	DeviceInfo string
	ClientIP   string
}

// SessionStore 是会话的存储契约。实现由消费者提供。
//
// # ⭐ 明文永远不出现在本接口里
//
// 每一个涉及凭证的参数都是 []byte 哈希。这让「把明文存进库」这件事
// 在类型上【表达不出来】—— 而不是靠一句"记得先哈希"的注释。
//
// # ⚠️ 关于并发的两条硬性要求
//
// Rotate 与 RevokeByHash 必须是【单条原子语句】并以受影响行数判定。
// ⛔ 不得实现成"先查再改" —— 那是 TOCTOU: 两个并发刷新会各自查到有效,
// 然后各自签出一个新 token, 于是一条会话分裂成两条, 而重放检测
// 从此对这条会话失去意义。
type SessionStore interface {
	// Create 建一条会话, ⭐ 返回【落库后】的记录。
	//
	// ⚠️ 必须返回而不是就地修改入参 —— rec 是值传递, 实现里给它填的 ID
	// 传不回调用方。而调用方【需要】那个 ID: 它要进 access token 的 sid claim,
	// 没有它"当前会话是哪条"就判不出来,
	// ⛔ 于是"登出其它设备"会把用户自己也踢掉。
	Create(ctx context.Context, rec SessionRecord, refreshHash []byte) (SessionRecord, error)

	// Rotate 用旧哈希换新哈希。
	//
	// 返回 (记录, true, nil)  = 轮换成功
	// 返回 (记录, false, nil) = ⚠️ 没有匹配的有效行。三种成因【对外不可区分】:
	//                            这个 token 已被用过 / 已被吊销 / 从来不存在
	// 返回 (_, false, err)    = 存储故障, ⛔ 与上一种不是一回事
	//
	// ⚠️ 调用方对「false, nil」的正确处置是【当作重放】—— 见 SessionGuard.Refresh。
	//
	// # ⭐ 实现必须保留【上一个】哈希, 否则重放检测不能反击
	//
	// 轮换会把当前哈希覆盖掉。若不另存一份上一个哈希, 重放来的旧 token
	// 匹配不到任何行 —— 连"这是谁的会话"都不知道, 于是只能拒绝、无从吊销,
	// 而攻击者那条链会完好活到 TTL 结束。
	//
	// ⚠️ 所以【失配时也要尽力填上 UserID】: 按上一个哈希反查出归属,
	// 放进返回的记录里。⛔ 返回一个空 UserID 等于放弃反击。
	//
	// ⚠️ 更早的 token (轮换两次以上) 找不回归属是可接受的 —— 真实的失窃形态是
	// "攻击者先用、合法方随后拿着上一个来", 那正好被覆盖。
	Rotate(ctx context.Context, oldHash, newHash []byte, newExpiry time.Time) (SessionRecord, bool, error)

	// FindByHash 查一条有效会话 (用于判定"当前会话是哪条")。
	FindByHash(ctx context.Context, hash []byte) (SessionRecord, bool, error)

	// RevokeByHash 吊销单条 (登出)。
	RevokeByHash(ctx context.Context, hash []byte) error

	// RevokeByID 吊销指定会话。
	//
	// ⚠️ 必须同时匹配 userID —— ⛔ 只按 sessionID 删是一个 IDOR:
	// 任何登录用户都能吊销任何人的会话。
	RevokeByID(ctx context.Context, userID, sessionID string) error

	// RevokeAllByUser 吊销该用户全部会话。
	// 用于: 封禁 · 改密 · ⭐ 重放检测。
	RevokeAllByUser(ctx context.Context, userID string) (int, error)

	// RevokeOthersByUser 吊销除 keepSessionID 之外的全部会话 (一键登出其它设备)。
	//
	// ⚠️ 必须排除当前会话 —— 否则用户点完自己也掉线,
	// 体验上等同于"这个按钮把我踹了"。
	//
	// ⭐ 用会话 id 而不是哈希来标识"当前": 调用方从 access token 的 sid claim
	// 就能拿到 id, ⛔ 而拿哈希意味着客户端要把 refresh 明文传上来。
	RevokeOthersByUser(ctx context.Context, userID string, keepSessionID string) (int, error)

	// ListByUser 列出有效会话。
	ListByUser(ctx context.Context, userID string) ([]SessionRecord, error)
}
