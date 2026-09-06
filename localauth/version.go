package localauth

// Version 是本模块的版本号, 随 tag `localauth/vX.Y.Z` 同步更新。
// 目前只用于对外 HTTP 请求的 User-Agent (见 breach_pwned.go), 让上游能辨认来源。
const Version = "v0.1.1"
