# gokit

bukahou 各项目共用的 Go 库。**多模块仓**：每个子目录一个独立 Go module，各自打 tag `<模块>/vX.Y.Z`，互不牵连。

## 模块地图

| 模块 | 存在理由 | 状态 | 谁在用 |
|---|---|---|---|
| [`localauth`](./localauth) | 本地密码登录的全部"密码对不对"之外的事：限流退避、时序一致、会话轮换与重放反击、改密/HIBP、注册/找回/改邮箱编排、吊销纪元。宿主只实现存储与投递契约 | `v0.1.0`（验收期，API 可改；两家宿主稳定后 v1） | geass-v3（宿主） · melete（接入中） |

## 约定

- **一个模块一个 go.mod**，`go get github.com/bukahou/gokit/<模块>@<模块>/vX.Y.Z`
- **CI 逐模块 `GOWORK=off`** 跑 build / vet / gofmt / test（`.github/workflows/ci.yml` 自动发现所有 go.mod）
- 仓根 `go.work` 只为本地开发方便
- ⛔ 模块之间不互相 import 宿主的东西，也不含任何域名 / 内网地址 / 凭据；测试固件里的口令只能是明显占位
- 许可证 Apache-2.0

## 发布一个模块

```bash
git tag localauth/v0.1.1 && git push origin localauth/v0.1.1
```
