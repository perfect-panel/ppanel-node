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

同一协议实例内，同一订阅/IP 的并发准入合并为一次面板请求。最多同时执行 64 次
申请、容纳 256 个等待连接；超额连接立即拒绝。每次申请最多等待 5 秒（已有更短的
面板超时仍生效），一个等待连接取消不影响其他等待者，全部等待者取消则终止请求。

面板错误或超时会触发该协议实例共享的指数退避，带抖动的等待从 0.5–1 秒增长到
15–30 秒。退避期结束只发出一个探测请求，成功后恢复正常申请；有效的已有租约继续
复用。`Retry-After` 支持秒数和 HTTP 日期，作为等待下限并增加少量抖动，最长接受
24 小时提示。明确的设备名额拒绝按订阅/IP 缓存 1–2 秒，最多保留 4096 项。
失败不会触发单次 HTTP 请求内部的自动重试。

连接热路径只查询当前 IP，其他过期设备记录由在线心跳清理；无面板准入回调的旧式
本地限额模式，仅在新 IP 遇到本地容量上限时补做过期清理。用户更新或撤销会取消旧
身份的在途申请，旧授权结果不能应用到重新添加的用户。设备热路径基准：

```bash
go test ./limiter -run '^$' -bench '^BenchmarkAcquireCachedDevice$' -benchmem
```

## Nowhere（NW3）

Nowhere 使用原生 Go NW3 实现，对齐 Nowhere 3.3.0。
协议模块位于 `pkg/nowhere`，通过本地 Xray 入站适配器复用路由、限速、设备准入、
流量统计及用户撤销；不修改 Xray fork 或全局 Go 模块缓存。来源与许可证见
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

面板必须支持 NW3 下发：`type=nowhere`、`version=3`、`security=tls`、ALPN `nw3`，
`network` 为 `mix`（同端口 TCP/TLS + QUIC）、`tcp` 或 `udp`。`obfs` 默认 `morph`，
可设为 `none`。证书继续使用已有的 `self/file/http/dns` 配置。旧 `now/1` 线协议不兼容。
用户认证字段必须是 32 位小写十六进制文本；新版 backend 会把该协议的订阅 UUID
转换为此格式，节点不自行猜测或转换其他格式的凭据。

支持 TCP 和 UDP（TLS 上使用 UoT，QUIC 上使用 DATAGRAM 分片），无载荷时先返回
setup 结果。认证、连接数和流数量均设有资源上限；用户增删只复制受影响的索引分片，
未变化的用户复用认证材料和候选缓存，撤销会关闭该用户的物理连接及其全部流。
全新来源的密钥识别仍为线性扫描，防扫描预算保持不变；Morph 校验避免逐候选堆分配。
上传和下载均经过套餐速率限制。

UDP 转发仍受当前 Xray 出站实现约束：空 UDP 数据报不会转发，默认 freedom 出站
接收缓冲为 8 KiB；大于此大小的响应可能被截断。这是节点数据平面的边界，NW3
协议核心的分片上限不改变该边界。远程 Egress 扩展未实现。

除根模块测试外，验证协议模块及独立的 Rust 3.3.0 客户端互通：

```bash
(cd pkg/nowhere && go test -race ./...)
NOWHERE_RUST_VECTOR_BINARY=/path/to/nowhere-3.3.0 \
  go test -race ./core -run '^TestNowhereRustInterop$' -count=1 -timeout=3m
```

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
