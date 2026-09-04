package localauth

import (
	"net"
	"net/http"
	"strings"
)

// ClientIPStrategy 决定「谁是客户端」。
//
// ⛔ 本包【不提供默认值, 也不做自动探测】。构造 Guard 时必须显式传一个。
//
// 理由: 「默认读 X-Forwarded-For」看起来能工作, 有代理时也确实有值,
// 只是那个值由客户端提供、可以任意伪造 —— 而伪造它就等于伪造限流键,
// 每个请求换一个值即可无限试探。这个失效没有任何症状。
//
// 而「未配置时退回 RemoteAddr」同样不行: 在代理之后 RemoteAddr 对所有请求
// 是同一个值, 限流键坍缩成一个, 全体用户共用一份配额 —— 一个攻击者打满
// 就能把所有人拒之门外。那不是防护变弱, 是把限流器变成了 DoS 放大器。
//
// 所以这里没有安全的默认值可选, 只能要求显式配置。
type ClientIPStrategy interface {
	ClientIP(r *http.Request) (string, error)
}

// TrustCloudflare 取 CF-Connecting-IP。
//
// # 它假设了什么
//
// 「所有流量必经 Cloudflare, 且 origin 不可被绕过直连」。
//
// CF Tunnel 天然满足 (origin 主动出站, 没有可直连的公网地址);
// 「CF 代理 + 公网 origin IP」不满足 —— 攻击者拿到 origin IP 直连,
// 就能任意伪造 CF-Connecting-IP, 因为 CF 只覆盖经过它的流量。
//
// ⚠️ 这两种形态的链路【跳数可以完全一样】而安全性相反 ——
// 所以判据不是「中间有几层代理」, 是「能不能绕过」。
// 而这个假设本包无法验证: 它是部署属性, 不是代码属性。
//
// # 头缺失时为什么返回错误而不是回退
//
// 回退到 XFF = 回到可伪造; 回退到 RemoteAddr = 键坍缩成全局共享桶。
// 两个回退都是静默的, 所以这里选择大声失败。
func TrustCloudflare() ClientIPStrategy { return cloudflareStrategy{} }

type cloudflareStrategy struct{}

const headerCFConnectingIP = "CF-Connecting-IP"

func (cloudflareStrategy) ClientIP(r *http.Request) (string, error) {
	if r == nil {
		return "", newErr(CodeClientIPUnavailable, "请求为空")
	}

	// ⛔ 只读这一个头。不读 X-Forwarded-For, 不读 X-Real-IP, 不看 RemoteAddr。
	raw := strings.TrimSpace(r.Header.Get(headerCFConnectingIP))
	if raw == "" {
		return "", newErr(CodeClientIPUnavailable,
			"缺少 "+headerCFConnectingIP+" —— 请求未经预期链路, 或信任源配置与实际部署不符")
	}

	// 该头由 Cloudflare 覆写, 但仍然校验格式: 配置错误时它可能装着别的东西,
	// 而一个非法的键会让计数表里长出无意义的行。
	if net.ParseIP(raw) == nil {
		return "", newErr(CodeClientIPUnavailable, headerCFConnectingIP+" 不是合法 IP")
	}

	return raw, nil
}

// TrustDirect 直接用 RemoteAddr, 供【无代理】的部署与本地开发使用。
//
// ⚠️ 它是一个显式的选择, 不是默认值 —— 这正是它存在的理由:
// 显式选择一个只在无代理时正确的策略, 与不小心落进它, 是两回事。
// ⛔ 在任何代理之后使用它, 限流键都会坍缩成上一跳的地址。
func TrustDirect() ClientIPStrategy { return directStrategy{} }

type directStrategy struct{}

func (directStrategy) ClientIP(r *http.Request) (string, error) {
	if r == nil {
		return "", newErr(CodeClientIPUnavailable, "请求为空")
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if net.ParseIP(host) == nil {
		return "", newErr(CodeClientIPUnavailable, "RemoteAddr 不是合法 IP")
	}
	return host, nil
}
