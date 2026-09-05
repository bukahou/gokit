package localauth

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // 与在线实现同源: 数据集就是按 SHA-1 分发的
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// localBreachChecker 是离线数据集实现 (§14.1.1 本地实现)。
//
// # ⚠️ 它面向 Top-N 常见口令, 不是完整 HIBP 集
//
// 完整集约 8.5 亿条 SHA-1, 全放进 map 需要几十 GB —— 那不是一个
// 业务进程该做的事。本实现的定位是【离线兜底】: 装载一份常见弱口令
// (量级 10^5~10^6), 覆盖绝大多数真实的糟糕选择。
//
// ⭐ 所以它与在线实现【不等价】, 而是覆盖面更窄。
// ⛔ 不要因为"本地也有一份"就以为可以不接在线 —— 那是两个不同的东西。
//
// # 文件格式
//
// 每行一条, 两种都接受:
//
//	5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
//	5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365
//
// 大小写不敏感; 空行与 # 开头的行跳过。
type localBreachChecker struct {
	// hashes 是全量 SHA-1 → 出现次数。
	//
	// ⚠️ 存【完整哈希】而不是后缀 —— 本地没有 k-anonymity 的必要
	// (没有第三方), 而存完整哈希免去了前缀分桶的复杂度。
	hashes map[string]int
	source string
}

// NewLocalBreachChecker 从文件装载离线数据集。
//
// ⚠️ 装载失败【返回 error 而不是降级成 noop】——
// 配置了离线实现却装不上, 那是部署错误, 应该在启动时炸掉,
// ⛔ 而不是静默变成"不检查"然后没人知道。
//
// ⭐ 这与运行期的 fail-open 不冲突: 运行期挂掉要放行(§14.2.1),
// 但【启动期配错】必须响 —— 两者是完全不同的时刻和不同的责任人。
func NewLocalBreachChecker(path string) (BreachChecker, error) {
	f, err := os.Open(path) //nolint:gosec // 路径来自运维配置, 非用户输入
	if err != nil {
		return nil, fmt.Errorf("打开泄露口令数据集失败: %w", err)
	}
	defer func() { _ = f.Close() }()

	c, err := loadLocalBreachSet(f, path)
	if err != nil {
		return nil, err
	}
	if len(c.hashes) == 0 {
		// ⛔ 空数据集会让每个口令都判 Clean —— 又一个"看起来在工作"的失效。
		return nil, fmt.Errorf("泄露口令数据集 %s 里没有任何有效条目", path)
	}
	return c, nil
}

func loadLocalBreachSet(r io.Reader, source string) (*localBreachChecker, error) {
	c := &localBreachChecker{hashes: map[string]int{}, source: source}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hash, count := line, 1
		if sep := strings.IndexByte(line, ':'); sep >= 0 {
			hash = line[:sep]
			if n, err := strconv.Atoi(strings.TrimSpace(line[sep+1:])); err == nil && n > 0 {
				count = n
			}
		}
		hash = strings.ToUpper(strings.TrimSpace(hash))
		if len(hash) != 40 {
			continue // 不是 SHA-1 hex, 跳过而不是报错 —— 数据集里常混着注释行
		}
		c.hashes[hash] = count
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("读取泄露口令数据集失败: %w", err)
	}
	return c, nil
}

func (c *localBreachChecker) Kind() string {
	return fmt.Sprintf("local(%d 条, %s)", len(c.hashes), c.source)
}

// Check 查本地集合。
//
// ⚠️ 本实现【永远不会返回 Unknown】—— 数据在内存里, 没有可失败的环节。
// 它要么 Found 要么 Clean。⭐ 这也是它作为"离线兜底"的价值: 不受网络影响。
func (c *localBreachChecker) Check(_ context.Context, plaintext string) (BreachResult, error) {
	if plaintext == "" {
		return BreachResult{Verdict: BreachClean}, nil
	}
	sum := sha1.Sum([]byte(plaintext)) //nolint:gosec // 数据集按 SHA-1 分发
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	if n, ok := c.hashes[full]; ok {
		return BreachResult{Verdict: BreachFound, Count: n}, nil
	}
	return BreachResult{Verdict: BreachClean}, nil
}
