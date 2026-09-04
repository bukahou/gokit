package localauth

import "errors"

// Code 是类型化错误码。
//
// 它是【稳定标识符】, 不是给用户看的文案 —— 多语言文案由消费者按 Code 映射,
// 本包不内置任何面向用户的字符串。
type Code string

const (
	// CodeInvalidCredentials 是【凡与凭据相关的失败】的唯一码:
	// 密码错 / 用户不存在 / 账号处于退避中, 全部是它。
	//
	// ⚠️ 注意措辞是「与凭据相关」而不是「登录路径唯一」——
	// CodeClientIPUnavailable 与 CodeLookupUnavailable 也从 Login 返回,
	// 但它们与凭据内容无关, 不构成差分泄漏。
	CodeInvalidCredentials Code = "invalid_credentials"

	// CodeClientIPUnavailable 信任源与实际链路不符 (如配了 CF 但请求没有 CF 头)。
	//
	// 对外应是 403 而不是 5xx: 「请求没走预期链路」是请求问题, 不是服务器故障。
	// ⚠️ 且【不得逐个请求告警】—— 不需要任何凭据就能触发, 逐个告警本身是 DoS。
	// 正确处置: 持续缺失 = 配置错误 (告警一次并保持); 个别缺失 = 疑似绕过 (拒绝, 不告警)。
	CodeClientIPUnavailable Code = "client_ip_unavailable"

	// CodeLookupUnavailable 查用户失败 (数据库故障等)。
	//
	// ⚠️ 必须独立于 CodeInvalidCredentials, 两个理由:
	//   1. 它不针对特定账号, 不构成泄漏, 没有合并的必要;
	//   2. 【可观测性】—— 合并之后, 一次数据库故障在监控里长得跟
	//      「所有人密码都输错了」一模一样: 一片正常的 401。
	CodeLookupUnavailable Code = "lookup_unavailable"

	// CodeAdmissionDenied 注册准入拒绝。
	CodeAdmissionDenied Code = "admission_denied"

	// CodePasswordTooLong 口令超过 bcrypt 的 72 字节上限。
	//
	// ⚠️ 必须显式拒绝: 原样抛出底层错误会变成 5xx (而这条纯靠一个长口令
	// 就能触发, 任何人都可以); 静默截断则让口令后半段无效且无任何症状。
	CodePasswordTooLong Code = "password_too_long"

	// CodePasswordTooShort 口令短于下限。
	CodePasswordTooShort Code = "password_too_short"

	// CodeMisconfigured 构造参数缺失或非法。构造期返回, 服务不启动。
	CodeMisconfigured Code = "misconfigured"
)

// Error 是本包对外的错误类型。消费者用 errors.As 取出 Code 做映射。
type Error struct {
	Code  Code
	Msg   string
	cause error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return string(e.Code) + ": " + e.Msg + ": " + e.cause.Error()
	}
	return string(e.Code) + ": " + e.Msg
}

func (e *Error) Unwrap() error { return e.cause }

func newErr(code Code, msg string) *Error { return &Error{Code: code, Msg: msg} }

func wrapErr(code Code, msg string, cause error) *Error {
	return &Error{Code: code, Msg: msg, cause: cause}
}

// CodeOf 取出 err 携带的 Code; 不是本包的错误则返回空串。
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
