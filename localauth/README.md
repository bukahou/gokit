# localauth

本地密码登录里**除了「密码对不对」之外的所有事**，做成一个不认识任何宿主的 Go 模块：

- 登录：IP / 账号两维失败计数与退避、时序一致（用户不存在也跑等量 bcrypt）、注册准入
- 会话：refresh token 签发 / 轮换 / 重放检测并反击、按设备登出、登出其它设备
- 口令：改密、首次设密、泄露检查（HIBP k-anonymity 或本地词表）、改密后吊销 + 重签当前设备
- 验证码：注册 / 找回口令 / 改邮箱三条编排共用的 6 位码（HMAC 存储、一人一码、一次性消费、发码限流）
- 吊销纪元：改密 / 封禁 / 强制登出对 access token **立即**生效（fail-open、可计数）

```
go get github.com/bukahou/gokit/localauth@localauth/v0.1.0
```

包文档见 `doc.go`；每个决定的来龙去脉见 [`DECISIONS.md`](./DECISIONS.md)；最小接线见 [`example_test.go`](./example_test.go)。

## 宿主要实现什么

模块不碰数据库、不签 token、不发邮件。下面是全部契约；**必选**的是用到对应守卫时必须提供的，其余按需。

| 契约 | 谁用 | 必选 | 宿主实现要点 |
|---|---|---|---|
| `FailureStore` ×2 | `Guard`（IP / 账号各一个）、`VerificationGuard`（地址 / IP 各一个） | ✅ | `Bump` 原子自增；账号维度的键列与用户名列**同排序规则**并在 DDL 显式写 COLLATE；有保留期。用 `storetest.RunFailureStoreTests` 验 |
| `LookupFunc` | `Guard.Login` | ✅ | 按用户名返回 bcrypt 哈希；不存在返回 `found=false`，不要提前返回错误 |
| `ClientIPStrategy` | `Guard` | ✅ | 内置 `TrustDirect()`（不信任转发头）、`TrustCloudflare()`（只信 `CF-Connecting-IP`） |
| `Admission` | `Guard`、`RegistrationGuard` | ✅ | 内置 `AdmitAll()` / `AdmitNone()` / `AdmitEmailDomains(...)`；自定义用 `AdmissionFunc` |
| `Policy` | `Guard` | 可选 | 默认 `DefaultPolicy()`（阈值 + 线性衰减 + 封顶），⛔ 不要做递增延迟 |
| `SessionStore` | `SessionGuard` | ✅ | 参数只有哈希；`Rotate` 原子且区分 `Replayed` / `Revoked`；保留上一个哈希以便反击。用 `storetest.RunSessionStoreTests` 验 |
| `AccountStatusFunc` | `SessionGuard` | ✅ | 刷新时复查账号是否仍允许登录 |
| `CredentialStore` | `PasswordGuard` | ✅ | 空哈希 = 该账号没有口令（纯 OIDC），是合法状态 |
| `AccessTokenIssuer` | `PasswordGuard`、`DeviceReissuer` | 可选 | 改密 / 改邮箱后为当前设备重签 access token；模块不知道密钥与 claims |
| `BreachChecker` | `PasswordPolicy` | ✅ | 内置 `NewPwnedRangeChecker`（HIBP）、`NewLocalBreachChecker`（本地词表）、`NewNoopBreachChecker`（不查，但 `Skipped ≠ Clean`） |
| `VerificationStore` | `VerificationGuard` | ✅ | 一人一码、`BumpAttempts` 原子、`Consume` 一次性。用 `storetest.RunVerificationStoreTests` 验 |
| `MessageSender` | `VerificationGuard` | ✅ | 投递验证码与两类通知；模板、语言、通道全在宿主 |
| `AccountCreator` | `RegistrationGuard` | ✅ | 撞唯一索引时返回 `CodeUsernameTaken` / `CodeEmailTaken`（用 `NewError`），不要原样上抛 |
| `RecoveryAddressResolver` | `RecoveryGuard` | ✅ | **只认本应用验证过的地址**；请求与完成各查一次 |
| `EmailChanger` | `EmailChangeGuard` | ✅ | 验证通过后才写；撞唯一索引同上 |
| `RevocationStore` | `RevocationChecker` | 可选 | 内置 `redisstore.NewRedisRevocationStore` / `NewRedisSentinelRevocationStore`；不接 = 只靠 access TTL 兜底，但每次判定发降级事件 |
| `AuditHook` | 所有守卫 | 可选 | 事件种类是封闭枚举，`AllEventKinds()` 供宿主做穷举映射测试 |

## 最小接线

```go
guard, _ := localauth.New(localauth.TrustDirect(), localauth.AdmitAll(), ipStore, acctStore)
out, err := guard.Login(ctx, clientIP, username, password, lookup)   // out.Allowed

sessions, _ := localauth.NewSessionGuard(sessionStore, statusFn, 30*24*time.Hour)
refresh, rec, _ := sessions.Issue(ctx, localauth.SessionRecord{UserID: id})
rot, err := sessions.Refresh(ctx, refresh)                            // rot.NewRefreshToken

policy := localauth.NewPasswordPolicy(localauth.WithBreachChecker(localauth.NewPwnedRangeChecker()))
passwords, _ := localauth.NewPasswordGuard(credStore, sessions, policy,
    localauth.WithAccessTokenIssuer(issue), localauth.WithPasswordRevoker(revoker))

verif, _ := localauth.NewVerificationGuard(verifStore, mailer, addrStore, ipStore, pepper)
reg, _  := localauth.NewRegistrationGuard(verif, accounts, localauth.AdmitAll(), policy)
rec, _  := localauth.NewRecoveryGuard(verif, resolver, passwords)
ec, _   := localauth.NewEmailChangeGuard(verif, changer, sessions,
    localauth.WithEmailChangeRevoker(revoker), localauth.WithEmailChangeReissuer(localauth.NewDeviceReissuer(sessions, issue)))
```

完整可运行版本在 `example_test.go`（内存存储 + no-op 信使 + no-op 泄露检查）。

## 子包

| 包 | 作用 |
|---|---|
| `redisstore` | `RevocationStore` 的 Redis 实现（单实例 / Sentinel）。放在子包是为了让不用 Redis 的宿主不 import go-redis；go.mod 里仍有它，但不 import 就不会被链接 |
| `storetest` | 三个存储契约的导出一致性测试。大小写折叠那条刻意做成两个可选断言（`AssertKeysShareBucket` / `AssertKeysDistinct`），由宿主按自己库的排序规则选一个调用 |

## 内存实现

`NewMemStore` / `NewSessionMemStore` / `NewVerificationMemStore` 只供**单副本部署与测试**。多副本下每个进程各一份计数，阈值被稀释 N 倍且没有任何症状。它们同时是 `storetest` 的参考实现：契约里的每条断言都先在它们上面成立。

## 测试

```bash
go test ./...                                   # 纯内存, 无外部依赖
LOCALAUTH_TEST_REDIS_URL=redis://localhost:6379/9 go test ./redisstore/ -run 纪元_真Redis
LOCALAUTH_TEST_KILLABLE_REDIS_PORT=6399 go test ./redisstore/ -run 运行期Redis挂掉   # 会真的 kill 那个 Redis
```

## 版本

`v0.1.0`：验收期，API 可改。两家宿主稳定后升 `v1.0.0`。变更记录见 `DECISIONS.md` 末尾。
