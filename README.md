# PPanel-node

A PPanel node server based on xray-core, modified from v2node.  
一个基于xray内核的PPanel节点服务端，修改自v2node

## 软件安装

### 一键安装

```
wget -N https://raw.githubusercontent.com/perfect-panel/PPanel-node/master/scripts/install.sh && bash install.sh
```

## 构建
``` bash
go build -v -o ./output/ppnode -trimpath -ldflags "-s -w -buildid="
```

## Protobuf 面板接口

节点会在拉取配置时通过 `Accept: application/protobuf` 自动协商传输格式。面板返回
Protobuf 时，后续用户列表、在线用户、流量和状态上报都会使用
`application/protobuf`；面板返回 JSON 时，节点继续使用 JSON，无需配置开关。

面板可能提供当前节点版本尚未支持的入站协议。节点会跳过这类协议及其配置，不会因
它们导致其他已支持的协议无法启动。

## TLS 证书

`cert_mode: dns` 和 `cert_mode: http` 使用 ACME 自动签发及续期；`self` 生成本地自签名
证书。自动签发与自签均使用 ECDSA P-256；`file` 从
`/etc/PPanel-node/{协议类型}{服务器 ID}.cer` 和 `.key` 读取已有证书对。
自动续期成功后节点会重载以启用新证书。

自动签发时，建议在本地配置的 `Api` 段填写 `ACMEEmail`，以接收 CA 的证书通知。可选的
`ACMECADirURL` 可用于测试 CA（例如 Let's Encrypt staging 或 Pebble）；首次使用某个 CA
前就应设置该值。

当 `cert_mode: self` 时，节点会将证书 DER 的 SHA-256 指纹编码为小写十六进制，并在后续
节点 API 请求中使用 `X-Node-Certificate-SHA256` Header 上报。面板应以大小写不敏感的
方式比较该十六进制值。

## 开发验证

项目使用 Go 1.27.1，JSON v2 已由标准库默认提供。与 CI 相同的验证命令：

```bash
GOTOOLCHAIN=go1.27.1 go test -race -timeout 5m ./...
GOTOOLCHAIN=go1.27.1 CGO_ENABLED=0 go build -o ./output/ppnode .
```

Android arm64 交叉构建需要额外的链接参数，供 `anet` 访问 Android 网络接口使用的 Go 内部符号：

```bash
GOTOOLCHAIN=go1.27.1 GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -checklinkname=0" -o ./output/ppnode-android .
```

如果 release 部分平台构建失败，可在 Actions 的 **Build and Release → Run workflow** 中填写
已有的 `release_tag`。工作流会构建该标签对应的源码，只上传缺失的 ZIP 和校验文件，保留已有产物。

用户列表流式 JSON 解码的性能基准：

```bash
GOTOOLCHAIN=go1.27.1 go test ./api/panel -run '^$' -bench BenchmarkDecodeUserList -benchmem
```

## 在线设备限制

需要先升级 backend，再升级节点：新增 `GET /v1/server/alivelist` 查询在线 IP 数量，
以及 `POST /v1/server/device` 原子申请设备名额，均支持 JSON/Protobuf 和既有节点鉴权。
旧 backend 缺少接口时节点会明确报错，不会把接口错误当作空在线列表。

设备按 **订阅 ID + 来源 IP** 计数；同 IP 的多条 TCP/UDP 连接、IPv4 映射地址、
跨协议或跨节点连接只占一个全局名额。NAT 后共享公网 IP 的设备会合并计数。
`device_limit = 0` 不限制；有限额订阅的新 IP 需获得 backend 的 Redis 原子准入许可，
避免多个节点同时读取旧人数后一起放行。已存在的 IP 租约可续期，上限针对新 IP 准入。

在线心跳独立于流量上报，间隔不超过 60 秒；持续连接即使没有流量也会续期，短连接至少
上报一次。关闭后的连接不再持续续期，最后一次申请或上报后的名额最多保留 5 分钟，
以兼容同 IP 仍在其他节点使用的情况和节点离线。计数接口失败时保留上一份数据，
用户撤销和限制变更继续同步；准入接口失败时拒绝有限额订阅的新设备，不静默放行。

## 流量与重载

流量通过原子交换取数，未获面板确认的批次会在内存中合并并重试，重载及移除协议时也会保留。
正常退出前会尝试上报剩余批次；进程崩溃或退出时面板仍不可用，不提供磁盘持久化保证。
面板接口没有幂等请求标识，因此响应丢失时重试可能重复计入流量。

面板返回空用户列表时，节点会撤销全部用户。

重载会先准备新用户列表、证书和入站配置，再切换监听。新节点启动失败时恢复缓存的旧配置和用户，
恢复过程不依赖面板；监听切换期间已有连接可能中断。

## Xray 2026-09 升级说明

内核固定在 `wyx2685/xray-core` 的 `e087e74a1bf2`
（`v0.0.0-20260930151924-e087e74a1bf2`）。

- 通过 `go.mod` 的 `godebug multipathtcp=0` 将默认关闭 MPTCP 固化到构建产物中，
  覆盖 Xray 及 pprof 等使用 Go 默认 TCP 监听的路径，无需在部署时额外设置环境变量。
  这是对 [Xray MPTCP 安全公告](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31)
  的应用层缓解；该分支尚未合入官方监听器补丁。在 `GODEBUG` 中将 `multipathtcp` 设为
  `1` 或 `2`，或显式配置 `sockopt.tcpMptcp: true`，仍可覆盖默认值。
  部署时应避免重新开启，并更新宿主机 Linux 内核。
- 适配新版错误 API 和 `FinalMask.ListenPacket`，SS2022 初始化用户使用协议要求的
  16/32 字节密钥，构建入站时不再修改面板提供的服务器密钥。
- TUIC 改用新的原生 QUIC 传输，出站配置中的用户标识使用 `id`。
  上游 TUIC 出站转发仍未实现，不能用于 TUIC 出站中继。
- TUIC 传输模块包含项目内兼容修复，处理认证与首个请求并发时丢失请求的问题，
  升级后继续保留，详见 [兼容模块说明](core/transport/tuic/README.md)。
- 额外的 Hysteria2 UDP 关闭检查发现固定内核 `transport/internet/hysteria/conn.go`
  中 `udpSessionManager.clean/run` 对 `closed` 的读写存在竞态；此上游问题尚未修复。
- 节点内部继续将 REALITY 的 `minClientVer` 显式固定为 `0.0.0`，
  允许旧版本客户端通过最低版本检查；客户端仍需支持对应的协议和加密配置。
- Shadowsocks 的 `none/plain` 和 TLS 的 `allowInsecure` 已被内核移除。
  自签名出站证书应在 `stream_settings` 的 `tlsSettings` 中设置
  `serverName` 与 `pinnedPeerCertSha256`，使用证书 DER 的 SHA-256 十六进制指纹。
  无效出站配置会明确报错，避免静默丢弃出站和路由；重载失败时保留旧服务。
- Freedom 出站的新默认规则屏蔽私网等目的地址。需要访问这些地址时，需在对应出站的
  `settings.finalRules` 中显式配置允许规则；测试仅在本机回环环境中放行测试目标。
