# naiveproxy + forwardproxy UDP over QUIC 设计

日期：2026-11-02。状态：设计草案，尚未实现或进行网络互通测试。

## 1. 结论与范围

采用 MASQUE CONNECT-UDP（RFC 9298），以 HTTP/3 Extended CONNECT 建立每个目标的隧道，以 HTTP Datagrams / QUIC DATAGRAM（RFC 9297 / RFC 9221）传输 UDP payload。

首期支持：SOCKS5 UDP ASSOCIATE → 单跳 quic:// forwardproxy → UDP 目标；IPv4、IPv6、域名；同一外层 QUIC 连接承载多个目标流。现有 TCP CONNECT 保留。

首期不支持：UDP 多跳、HTTP/2/HTTPS UDP fallback、TUN/透明 UDP、SOCKS UDP 分片、自定义 UDP padding、0-RTT UDP 转发。配置了 upstream 的服务端不得绕过 upstream 直接发送 UDP，应拒绝不支持的组合。客户端不支持的代理链也应显式失败，不得自动直连。

UDP 数据路径使用不可靠 DATAGRAM；不能用普通 CONNECT 内的长度前缀字节流替代，否则会引入可靠流重传与流内队头阻塞。Capsule 是独立的控制/兼容机制，需能解析；首期不启用可靠 DATA capsule 承载业务 UDP 的 fallback。

## 2. 本地源码依据

- naiveproxy：`/Users/eugene/Downloads/naiveproxy`，HEAD `dbbae1f0ca`，Chromium `157.0.8103.30`。
- forwardproxy：实际位于 `/Volumes/ExtendSSD/VibeCoding/forwardproxy`，HEAD `e747854`。用户给出的 `~/Volumns/...` 不存在。
- forwardproxy 根 go.mod 是 Caddy v2.8.4 / quic-go v0.44.0；但 `.github/workflows/build.yml` 使用 `CADDY_VERSION` v2.11.7，并应用两个 Caddy patch。
- `caddy-sing-quic-bbrv1.patch` 指向 sagernet/quic-go v0.61.0-sing-box-mod.9 和 sing-quic v0.7.2 预发布提交。设计应锁定这条实际构建链，而不是按旧 go.mod API 开发。
- 本机仅缓存 sagernet/quic-go mod.7；已用其源码检查 HTTPStreamer、Settingser、Extended CONNECT 的大致接口，但 mod.9 的编译及行为仍须在 P0 核实。

| 位置 | 已核实行为 | 设计影响 |
|---|---|---|
| `src/net/tools/naive/socks5_server_socket.cc` | CMD=0x03 与 BIND 一起被拒绝 | 增加握手结果类型及 UDP association 分支 |
| `naive_proxy.cc` / `naive_connection.cc` | StreamSocket / TCP relay 路径 | UDP 使用独立生命周期对象，不能套字节流 relay |
| `src/net/quic/quic_proxy_datagram_client_socket.{h,cc}` | 已实现 CONNECT-UDP、Context ID=0、收包队列 | 首选复用；Connect 必须经 ConnectViaStream，普通 Connect 是 stub |
| 同上 | Proxy Authentication 仍有 TODO，仅 200 被接受；队列上限 16 | 补充 preemptive auth；服务端返回 200；评估突发丢包 |
| `quic_chromium_client_stream.cc::WriteConnectUdpPayload` | 未协商 H3 Datagram 时丢包但返回 OK；TOO_LARGE 路径 reset stream | 发送前能力/长度检查并修正错误映射 |
| `quic_session_pool.cc::CreateSessionOnProxyStream` | 为代理链内的 QUIC 会话构造 CONNECT-UDP socket | 参考 session/stream 获取流程，不直接调用该函数代理普通应用 UDP |
| `naive_proxy_delegate.cc` | padding 状态按代理缓存，并设置 fastopen | UDP 独立 delegate/状态，避免覆盖 TCP padding 缓存 |
| `forwardproxy.go::ServeHTTP` | 普通 CONNECT 拒绝非空 scheme/path，200 先于 TCP dial | Extended CONNECT 必须提前分流，UDP 不能照搬 Fast Open |
| `forwardproxy.go::dialContextCheckACL` | 只允许 tcp/tcp4/tcp6 | 抽取目标校验逻辑，增加独立 UDP dial |
| `forwardproxy.go::dualStream` | 字节流复制及前 8 段 padding | UDP 完全独立数据面 |

## 3. 拓扑与会话映射

```text
应用
  ├─ SOCKS5 TCP 控制连接 ── naiveproxy association
  └─ SOCKS5 UDP 数据包 ────┤
                           ├─ target A → CONNECT-UDP stream A ─┐
                           └─ target B → CONNECT-UDP stream B ─┤
                                共享一个 HTTP/3 / QUIC 连接    │
                                                              ▼
                                                    Caddy + forwardproxy
                                                      ├─ connected UDP → A
                                                      └─ connected UDP → B
```

association key 是控制连接 ID；flow key 是 `(association ID, 本地 UDP 源 endpoint, ATYP, 规范化目标 host, target port)`。不跨客户端/association 合并目标流，避免回包串流和 NAT 语义变化。

每个目标流对应一个 CONNECT-UDP 请求流和一个服务端 connected UDP socket；同一 SOCKS association 可访问多个目标。Context ID 固定为 0，不能把不同目标塞进自定义 Context ID 而声称是基础 RFC 9298。

## 4. 协议与建立流程

1. 外层使用现有 Chromium QUIC、证书校验、SNI 与 ALPN h3。客户端等待握手确认；禁止首期 UDP early data。
2. 验证服务端 Extended CONNECT 支持及双方 H3_DATAGRAM、QUIC DATAGRAM 能力；等待 SETTINGS 有独立超时，不能把“未收到”当成“不支持”或已成功。
3. 客户端为目标扩展 URI template，保留域名交给服务端解析；按 path segment 编码目标，IPv6 不带方括号并编码冒号；authority 使用代理地址，正确处理代理 IPv6 literal。
4. 发起以下请求（示例）：

```http
:method: CONNECT
:protocol: connect-udp
:scheme: https
:authority: proxy.example:443
:path: /.well-known/masque/udp/dns.example/53/
capsule-protocol: ?1
proxy-authorization: Basic <credentials>
```

5. 服务端沿现有鉴权/探测抵抗路径处理；认证成功后，验证配置、能力、URI、目标端口和 ACL，完成 DNS 与 socket 建立，再响应 `:status=200`、`capsule-protocol=?1` 并 flush。成功只表示愿意转发，不表示 UDP 目标可达。
6. 客户端确认成功和能力后才发送 UDP，握手期间只有有界、带过期时间的小队列。

```text
QUIC DATAGRAM frame payload:
  Quarter Stream ID (QUIC varint)
  Context ID = 0 (QUIC varint)
  原始 UDP payload
```

Quarter Stream ID 由 HTTP/3 层处理。Go `http3.Stream.SendDatagram` 的应用侧 payload 需要携带 Context ID；Chromium `QuicProxyDatagramClientSocket::Write` 已添加 Context ID，不得重复封装。所有长度以实际 API 所处层级计算。

可靠请求流保持打开，用于请求生命周期和 Capsule 解析。未知 capsule 按标准跳过且有资源/时长限制；未知 Context ID 丢弃。首期不发送业务 DATAGRAM capsules；收到该类 capsule 应按确定的兼容策略处理并测试，不能误作裸 UDP，也不能宣称已实现完整可靠 fallback。

## 5. naiveproxy 改动

### 5.1 本地 SOCKS 入口

重构 SOCKS 握手，显式返回 CONNECT / UDP_ASSOCIATE 及请求参数。CONNECT 保持现有 NaiveConnection；UDP 分配 `NaiveUdpAssociation`，负责控制 TCP 和本地 UDP socket。UDP bind 成功才回 REP=0，并返回真实可达的 BND.ADDR/BND.PORT。

首期建议每个 association 独立 UDP 端口，降低客户端区分复杂度。控制连接断开立即关闭关联的全部流。限定 UDP 来源 IP 为控制连接 peer；校验声明的源 endpoint，未指定端口时可在首个合法包固定源端口，避免另一进程抢占/混入。保留现有 SOCKS 用户名密码认证。

解析 `RSV(2) | FRAG(1) | ATYP | DST.ADDR | DST.PORT | DATA`，仅 FRAG=0；支持 domain/IPv4/IPv6，校验地址长度、域名与端口。零长度 UDP payload 是合法数据，不能按 TCP EOF 处理。

回复 SOCKS UDP 包需要来源地址元数据。当前 DatagramClientSocket::GetPeerAddress 返回的是代理 endpoint，不能用它填 SOCKS 回包来源。IP 目标使用目标 IP；域名目标可先返回保留的域名 ATYP，并以客户端兼容测试作为验收门槛。若应用必须看到实际解析 IP，需另行设计目标地址反馈扩展，不能假定 RFC 9298 已提供。

### 5.2 客户端对象

建议新增：

- `socks5_udp_packet.{h,cc}`：独立 packet 编解码。
- `naive_udp_association.{h,cc}`：控制连接、本地收发、目标 flow 表与清理。
- `naive_udp_tunnel.{h,cc}`：获取到代理的 QuicSession/stream、构造 CONNECT-UDP socket、状态机与 MTU 检查。
- `naive_udp_proxy_delegate.{h,cc}`：限定代理 origin 的鉴权；不读写 TCP padding 状态。

复用现有 HttpNetworkSession / QuicSessionPool；key 必须与现有代理会话的 privacy、NAK、证书及 socket tag 语义一致，避免人为创建每目标一条 QUIC 连接。以到代理的直接会话取得 stream，再创建应用 UDP socket；不要调用创建“隧道内 QUIC 会话”的 helper。

从 `proxy_config.auth_store` 显式取正确代理凭据，通过 UDP delegate 加入 Proxy-Authorization；不能假设预填 HttpAuthCache 会解决当前 socket 的鉴权 TODO。首期固定预配置 Basic，不做挑战重试，不把密钥写入 URL path/日志。

补充 socket 生命周期接口：独立的 stream-close/error 通知，pending read 完成，销毁前撤销 visitor/回调，Close 幂等与未连接状态保护。现有 Read 的 0 同时可能是空报文或流关闭，必须消除歧义。禁止把吞掉错误的 Write=OK 当成对端送达。

## 6. forwardproxy / Caddy 改动

### 6.1 Caddy HTTP/3 接入

在实际 Caddy checkout 增加独立 UDP patch，保留既有 BBR 与 idle-timeout patch：

- 创建共享 QUIC listener 的真实 `quic.Config` 启用 DATAGRAM。
- `http3.Server.EnableDatagrams=true`；验证 Extended CONNECT SETTINGS。Caddy 使用外部 listener 时，仅改 http3.Server.QUICConfig 不一定生效。
- 从真实 HTTP/3 ResponseWriter 获取 stream/settings；Caddy 包装器可能不暴露接口，沿 Unwrap 查找或新增窄接口桥接。必须在响应 200 之前确认能取得所需能力。
- 所有 HTTP/3 类型统一使用锁定的 sagernet fork，避免官方 quic-go 与 fork 返回类型不同导致 assertion 失败。
- mod.7 将 Extended CONNECT 的 protocol 写入 `r.Proto`，故不能用 `Header.Get(":protocol")` 判断；锁定 mod.9 后验证并封装为单点 helper。
- H3/QUIC SETTINGS 是连接级能力，按同一 listener 的各站点统一协调，不能等认证后才修改；由 handler 的鉴权和 enable 开关控制是否实际提供 UDP。

HTTP/3 文档接口是参考，不替代实际 fork 编译验证。每个 handler 使用 request stream 的 SendDatagram/ReceiveDatagram，禁止每条隧道自己读取底层 QUIC connection 的 ReceiveDatagram，防止争抢其他流报文。

### 6.2 Handler

在现有鉴权和 probe resistance 之后、普通 CONNECT 的 scheme/path 检查之前识别 connect-udp，并交给 `serveConnectUDP`。其他 Extended CONNECT 不得误走 TCP。

建议新增 `connect_udp.go`、`udp_session.go` 和对应测试，在 `caddyfile.go` / Handler 增加明确的 UDP 配置。认证失败沿既有隐藏页面/next handler 逻辑，避免专有 UDP 错误提前暴露端点。

抽取 `resolveAndAuthorizeTarget(ctx, host, port, networkPolicy)`：保持现有 ACL 优先级；统一规范化域名、IPv4-mapped IPv6 与端口；对最终拨号 IP 校验，并直接拨该 IP，避免校验后重新 DNS。UDP 端口白名单可单独收紧，IP/域名 ACL 复用；不支持 upstream 时在配置校验阶段报错。

使用带取消的 DNS lookup 和 connected UDP socket。记录本次解析选择，不因每个包重新解析/切换目标。UDP dial 成功不是可达性证明，多 IP 自动 fallback 不可照搬 TCP connect 成功判断。

会话至少有：datagram→UDP、UDP→datagram、控制流/Capsule/关闭监听三个逻辑任务。共享取消上下文，任一路终止都关闭 UDP、取消其他阻塞操作并等待回收。用 `r.Context()` 派生，避免复制当前 TCP 路径的 context.Background。takeover 后显式承担 stream 关闭责任。

现有 read idle patch 基于请求 body 活动，DATAGRAM 不一定刷新这个计时器。UDP 会话需依据成功校验的双向业务包更新独立 idle deadline，并验证 Caddy 的硬超时/stream idle 是否会提前关闭。建议默认 idle=120s；到期必须同时关闭 socket 和请求流。

## 7. MTU、拥塞与资源边界

禁止把“QUIC 最小 UDP 包长 1200”当作可承载 1200 字节内层 UDP 的保证。包还包含外层 IP/UDP、QUIC header/AEAD、DATAGRAM frame、Quarter Stream ID 和 Context ID。应用容量取协商值、当前路径/实现限制和对应 API payload budget 的最小值，避免重复扣除头部。

超出可用 DATAGRAM 长度时首期丢弃并计数/本地错误，不分片，不切到可靠流，不关闭健康隧道。修改或包裹 Chromium TOO_LARGE 路径，提供 ERR_MSG_TOO_BIG；两端都需要做。服务端发向目标时按 RFC 设置 DF（平台支持时）并处理 EMSGSIZE，不能依赖 IP 分片。

必须单列验收：内层 QUIC 的 Initial 至少 1200 字节，需要外层路径提供更大的空间。若目标网络无法容纳，不宣称所有 HTTP/3 流量可用；以后可单独评估协商过的 fragmentation 扩展。

所有 UDP 发送受外层 QUIC 拥塞控制，BBRv1 可以沿用但不等于应用无需限速。采用每用户/每 association 的 flow 上限、全局 socket 上限、报文/字节速率限制和有界队列；流 ID/目标快速变化也计入限流。示例起点：每 association 64 flows、建连队列最多 16 包且总计 64KiB，实际根据测试调整；这些是设计建议而非已有参数。

同连接 TCP 和 UDP 共享拥塞窗口：先验证饥饿/公平性，再考虑专用连接池。首期只做有界丢弃和调度，不重传业务 UDP，不以增加 QUIC 并发连接掩盖拥塞问题。

## 8. Padding 与可观察特征

不能复用 NaivePaddingSocket / dualStream 的有状态前若干段 framing：UDP 丢包乱序会破坏这种状态，且附加字节会被标准端点作为业务数据转发。

首期保持 Context 0 的标准 payload。若以后需要 padding，优先研究 QUIC packet PADDING；应用层 padding 必须定义明确扩展并双端协商。扩展 H3 SETTINGS、DATAGRAM 分布和流量时序会改变可观察特征，继续使用 Chromium QUIC 并不证明与普通浏览器流量不可区分，需实测评估。

## 9. 分阶段实施与验收

### P0：锁定依赖与能力 PoC

在 CI 使用的 Caddy v2.11.7 + mod.9 构建环境固定版本，确认 Go toolchain、现有 patch 顺序、DATAGRAM 两层开关、protocol 表示、ResponseWriter 解包、SETTINGS 可见性。做一个认证后的固定目标 UDP echo 请求，确认抓包/qlog 是 DATAGRAM 而不是业务 DATA frame。失败则先完成 Caddy 窄桥接 patch。

### P1：端到端固定目标

实现 server serveConnectUDP、ACL/DNS/socket 生命周期，以及 naive 的 UDP tunnel 工厂和认证。通过 IPv4/IPv6 echo、域名目标、错误凭据、ACL 拒绝、握手取消、SETTINGS 延迟/不支持测试。双方 200 之前不转发应用包。

### P2：SOCKS5 UDP ASSOCIATE

支持多个控制连接、多目标、返回地址、FRAG 拒绝、空 UDP payload、控制连接关闭清理。用真实支持 SOCKS UDP 的客户端和自有协议测试器验证；普通 curl SOCKS 测试通常只能证明 TCP 通路。

### P3：边界与回归

- MTU 边界和超大包：不截断、不意外关闭 tunnel；验证内层 QUIC Initial。
- 注入丢包、乱序、延迟：无业务重传/可靠流队头阻塞；持续 TCP+UDP 公平性。
- 服务端 FIN/RESET、GOAWAY、网络切换、QUIC 断线、DNS 超时、UDP ICMP 错误、空闲到期：资源无泄漏、pending callback 不悬挂。首期断线销毁流并由后续包重建，不重放旧包。
- 多来源攻击、错误 Context ID、畸形 URI/varint/capsule、大长度声明、认证前洪泛：资源有界。
- HTTP/1.1、H2、H3 TCP CONNECT、Naive padding、probe resistance、BBR/idle patch 回归。
- 监控 active associations/flows、认证拒绝、DNS/ACL 拒绝、协商失败、过大丢包、队列丢包、每用户速率、流关闭原因；不记录凭据或 payload。

交付顺序建议：Caddy 能力 patch → forwardproxy UDP handler → naive UDP tunnel → SOCKS5 入口 → 联调回归。每步可独立评审，功能默认关闭。

## 10. 标准与参考

- RFC 9298：https://www.rfc-editor.org/rfc/rfc9298.html
- RFC 9297：https://www.rfc-editor.org/rfc/rfc9297
- RFC 9221：https://www.rfc-editor.org/rfc/rfc9221
- quic-go HTTP Datagrams：https://quic-go.net/docs/http3/datagrams/

本方案选择基础 CONNECT-UDP Context 0 互操作，不默认包含后续可选扩展；实际实现前应核对目标扩展和所锁版本的兼容性。
