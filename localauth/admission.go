package localauth

import (
	"context"
	"strings"
)

// AdmitRequest 是准入判定的输入。
//
// 它刻意只带两条入口【都有】的东西 —— 因为准入层站在自助注册与
// 联邦回调【之上】, 不是注册流程的一个子步骤。
// ⛔ 因此它不得依赖任何注册特有的上下文 (验证码、邮件通道),
// 否则联邦回调那条路走不通。
type AdmitRequest struct {
	// Email 自助注册时是用户填的; 联邦回调时是上游 claim (可能为空)。
	Email string
	// Provider 空串表示本地注册; 否则是上游名。
	Provider string
	// Subject 联邦回调的上游 sub; 本地注册为空。
	Subject string
}

// Admission 是【两条入口共用】的准入层: 自助注册与联邦 JIT 建号都必须过它。
//
// ⛔ 管理员建号显式绕过 —— 管理员的权限本身就是那个准入决定,
// 再让它过一遍白名单是把决定做了两遍, 且会导致「管理员无法给白名单外的人建号」
// 这个错误行为。但绕过必须留痕: 那是一个必须发的审计事件, 不是可选日志,
// 否则白名单在事后无法自证有效。
type Admission interface {
	// Admit 返回 nil 表示放行。
	Admit(ctx context.Context, req AdmitRequest) error
}

// AdmitAll 显式选择「谁都能注册」。
//
// ⚠️ 这个函数必须存在。若本包只提供「必须配一份白名单」, 那么本来就开放注册的
// 部署会被迫写一条通配 —— 而一条通配在启动日志里长得像一条【真白名单】,
// AdmitAll() 长得像一个【决定】。
// 显式选择不安全, 与不小心落进不安全, 是两回事。
func AdmitAll() Admission { return admitAll{} }

type admitAll struct{}

func (admitAll) Admit(context.Context, AdmitRequest) error { return nil }

// AdmitNone 拒绝一切。等价于「自助注册关闭」。
//
// 它是 (b) 类配置的保守默认: 安全关键但存在安全默认值 ——
// 那就取最保守的那个, 而不是拒绝启动 (拒绝启动会惩罚一个根本不想开注册的部署方)。
func AdmitNone() Admission { return admitNone{} }

type admitNone struct{}

func (admitNone) Admit(context.Context, AdmitRequest) error {
	return newErr(CodeAdmissionDenied, "自助注册未开启")
}

// AdmitEmailDomains 只放行邮箱后缀命中白名单的请求。
//
// ⚠️ 空白名单 = 拒绝所有, 不是放行所有 —— 一个空集合上的「命中」永远为假,
// 而把它解释成放行会让「配置写漏了」变成「门大开着」。
func AdmitEmailDomains(domains ...string) Admission {
	norm := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(d, "@")))
		if d != "" {
			norm = append(norm, d)
		}
	}
	return admitDomains{domains: norm}
}

type admitDomains struct{ domains []string }

func (a admitDomains) Admit(_ context.Context, req AdmitRequest) error {
	at := strings.LastIndex(req.Email, "@")
	if at < 0 {
		return newErr(CodeAdmissionDenied, "邮箱格式不合法")
	}
	got := strings.ToLower(req.Email[at+1:])
	for _, d := range a.domains {
		if got == d {
			return nil
		}
	}
	return newErr(CodeAdmissionDenied, "邮箱域名不在允许列表内")
}

// AdmissionFunc 让一个函数直接充当 Admission (测试与简单策略用)。
type AdmissionFunc func(ctx context.Context, req AdmitRequest) error

func (f AdmissionFunc) Admit(ctx context.Context, req AdmitRequest) error { return f(ctx, req) }
