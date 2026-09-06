package localauth

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // ⚠️ 见下方注释: SHA-1 是 HIBP 协议规定, 不是安全选择
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// pwnedRangeChecker 是 Have I Been Pwned 的 Range API 实现 (§14.1.1 在线实现)。
//
// # ⭐ k-anonymity: 口令明文与完整哈希都不出网
//
//	SHA-1(明文) → 大写 hex (40 字符)
//	前 5 位  → 放进 URL: GET /range/{prefix}
//	后 35 位 → 【只在本地比对】
//
// 上游返回该前缀下的全部后缀 (通常几百到上千条), 我们在本地扫。
// ⛔ 绝不发送完整哈希 —— 那等于把"某人正在用这个口令"告诉了第三方。
//
// # ⚠️ 为什么用 SHA-1 —— 这不是安全选择, 是协议规定
//
// HIBP 的 Range API 索引就是 SHA-1。⛔ 谁把它"顺手升级成 SHA-256",
// 得到的前缀在上游根本不存在, 于是【每次查询都返回空 → 一律判为 Clean】——
// 也就是说检查会静默失效, 而且看起来一切正常 (200, 无报错, 结论"未泄露")。
//
// ⭐ 这正是本仓反复出现的失效形状: 没有症状的那一种。
// 所以这里的 sha1 不是疏忽, 改它之前先想清楚上面这一段。
//
// # 0 新依赖
//
// net/http + crypto/sha1 + bufio, 全部标准库 (§14 要求)。
type pwnedRangeChecker struct {
	client  *http.Client
	baseURL string
}

// PwnedOption 配置在线实现。
type PwnedOption func(*pwnedRangeChecker)

// WithPwnedHTTPClient 换 http.Client (测试用, 或需要走代理时)。
func WithPwnedHTTPClient(c *http.Client) PwnedOption {
	return func(p *pwnedRangeChecker) { p.client = c }
}

// WithPwnedBaseURL 换上游地址 (测试用)。⚠️ 不带结尾斜杠。
func WithPwnedBaseURL(u string) PwnedOption {
	return func(p *pwnedRangeChecker) { p.baseURL = strings.TrimSuffix(u, "/") }
}

// NewPwnedRangeChecker 构造在线实现。
//
// ⚠️ 默认超时 2 秒, 刻意短 ——
// 这是一条【建议性】检查, 它挂掉的正确表现是 fail-open 放行,
// ⛔ 而不是让用户在改密页面上等 30 秒。
func NewPwnedRangeChecker(opts ...PwnedOption) BreachChecker {
	p := &pwnedRangeChecker{
		client:  &http.Client{Timeout: 2 * time.Second},
		baseURL: "https://api.pwnedpasswords.com",
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func (p *pwnedRangeChecker) Kind() string { return "pwned-range" }

func (p *pwnedRangeChecker) Check(ctx context.Context, plaintext string) (BreachResult, error) {
	if plaintext == "" {
		// 空口令由长度策略拦, 不该走到这里; 但也不必为此发一次网络请求。
		return BreachResult{Verdict: BreachClean}, nil
	}

	sum := sha1.Sum([]byte(plaintext)) //nolint:gosec // 协议规定, 见文件头注释
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/range/"+prefix, nil)
	if err != nil {
		return BreachResult{Verdict: BreachUnknown}, fmt.Errorf("构造泄露库请求失败: %w", err)
	}
	// ⭐ Add-Padding 让上游把响应填充到固定条数区间。
	//
	// ⚠️ 不加的话, 响应体大小本身会泄漏"你查的是哪个前缀"给中间人 ——
	// 每个前缀的后缀条数不同, 是一个可观测的指纹。
	// k-anonymity 保护的是【内容】, 这个头保护的是【体积】。
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "gokit-localauth/"+Version)

	resp, err := p.client.Do(req)
	if err != nil {
		return BreachResult{Verdict: BreachUnknown}, fmt.Errorf("请求泄露库失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return BreachResult{Verdict: BreachUnknown},
			fmt.Errorf("泄露库返回 %d", resp.StatusCode)
	}

	// 响应是每行 "SUFFIX:COUNT" 的纯文本。
	//
	// ⚠️ padding 行的 COUNT 是 0 —— 那是上游为了掩盖真实条数塞进来的假数据。
	// ⛔ 把 count=0 当成"泄露过 0 次"会让每一个口令都命中。
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		sep := strings.IndexByte(line, ':')
		if sep < 0 {
			continue
		}
		if !strings.EqualFold(line[:sep], suffix) {
			continue
		}
		count, convErr := strconv.Atoi(strings.TrimSpace(line[sep+1:]))
		if convErr != nil || count <= 0 {
			// count<=0 = padding 假行, 视为未命中。
			continue
		}
		return BreachResult{Verdict: BreachFound, Count: count}, nil
	}
	if err := sc.Err(); err != nil {
		// ⚠️ 读到一半断了 —— ⛔ 不能当 Clean:
		// 我们只扫了一部分后缀, "没找到"这个结论没有根据。
		return BreachResult{Verdict: BreachUnknown}, fmt.Errorf("读取泄露库响应失败: %w", err)
	}
	return BreachResult{Verdict: BreachClean}, nil
}
