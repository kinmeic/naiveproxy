# ZihaoFU245 UDP forks 评估

评估日期：2026-11-08。结论基于下列固定提交的源码审查和隔离测试，不代表端到端性能或生产验证。

- naiveproxy：`ad8a8741573974ec5be25877c5e935f424851bad`，Chromium 150.0.7871.63。
- forwardproxy：`792710f05f1181fb80e459b099e350c4f004f7a6`，依赖 Caddy v2.11.4、x/net v0.57.0。
- 本地目标此前为 Chromium 157，forwardproxy CI 则为 Caddy v2.11.7 + sagernet QUIC 补丁；这些差异须按模块移植，不能整包覆盖。
- 审查副本：`/tmp/udp-fork-review.S3WSNF`。原项目实现未修改。

## 总体判断

这是具备客户端与服务端主路径的实验性 CONNECT-UDP Capsule 实现，明显超过概念性伪代码。但它没有实现 QUIC DATAGRAM 数据面。若目标是兼容 HTTP/2 的 UDP 代理，参考价值较高；若目标是此前设计的不可靠 UDP over QUIC，入口和控制面可借鉴，传输层仍需另做。

```text
这两个 fork：SOCKS UDP → DATAGRAM Capsule → HTTP DATA → 可靠 H2/H3 stream → UDP
此前目标：  SOCKS UDP → HTTP Datagram → QUIC DATAGRAM → UDP
```

Capsule 路径是 RFC 9297 允许的传输形式，本身不等于违规。QUIC STREAM 可靠传输会重传丢失的字节，导致同一目标流后续 UDP 包等待；H2 底层 TCP 丢包还可能影响其他流。不能因承载在 QUIC 上就推断具有 QUIC DATAGRAM 的延迟性质。

因此也需细化此前“必须补 Caddy”的表述：如果选择此处的 Capsule/H3 方案，可以通过普通请求 body/ResponseWriter 工作，无需开启 QUIC DATAGRAM。若坚持此前 DATAGRAM 方案，仍需解决 Caddy listener/server 的能力开关和请求流接口接入。

## 已实现和优点

1. `socks5_udp_packet.cc` 实现 IPv4、IPv6、域名地址编码/解码，检查 RSV、FRAG、长度、端口，拒绝不支持的 SOCKS 分片。
2. `naive_udp_association.cc` 独立拥有控制连接和 UDP socket；检查来源 IP，固定来源 endpoint，每目标建 flow。以 generation 标识异步回调，WeakPtr 和 PostTask 降低回调重入/销毁风险。
3. flow 数量和发送队列均有上限；队列压力下丢弃旧包；有目标空闲和 association 超时，以及 flow lifetime 限制。它们不构成全局或服务端资源配额。
4. `NaiveCapsuleSocket` 是增量解析器，考虑 varint 跨 read、payload 跨 read、partial write、未知 capsule/context；以 0 表示空 UDP 报文，以负错误区分 EOF。客户端正确设置 65527 payload 上限。
5. 通过现有 H2/H3 proxy socket 扩展 Extended CONNECT，保留 HttpAuthController/407 处理路径，比另起一套鉴权更有复用价值；是否实际跨各类认证场景可用，仍需集成测试。
6. 增加 ProxyTunnelType，UDP 不更新 TCP padding 缓存、不使用现有有状态 Naive stream padding；socket pool GroupId 区分 UDP 和 URI template。
7. server 在原鉴权之后分流 connect-udp，沿用 ACL/端口检查；先 DNS/UDP dial 后回复 200，使用 connected socket 过滤回包，upstream 不支持时拒绝，避免无声直连绕路。
8. Go Capsule 实现用 pool 和 header headroom 减少分配、合并 header/payload Write，有 benchmark；新增解析和 H2 Extended CONNECT 测试。

## 问题及优先级

### 高：不具备不可靠 DATAGRAM 数据路径

出处：`naive_connection.cc::DoConnectServerComplete` 建立 NaiveCapsuleSocket；其 Write 调用 StreamSocket::Write。服务端 `masque.go::udpToCapsules` 调用 ResponseWriter.Write/Flush，接收端读 request body。未见用 HTTP/3 Stream.SendDatagram/ReceiveDatagram 传业务的实现。

这是目标范围差异，不能当成局部 bug 修好。DNS、小流量兼容用途可用这种架构；实时交互和内层 QUIC 的丢包表现必须实测。客户端丢弃尚未进入可靠流的旧包，不能取消已进入 QUIC stream 的重传。

### 高：服务端缺少资源与空闲边界

出处：`masque.go::serveConnectUDP` / `relayConnectUDPCapsules`。

没有 UDP 专属 idle deadline、用户/连接/全局 flow 上限或建流速率限制。一个长期开着的请求可保留 UDP socket、goroutine 和 buffer；合法用户或泄露凭据可以绕过客户端本地 flow 限额。未知 capsule 的 uint64 长度是流式跳过，避免按声明长度分配巨量内存是优点，但没有独立时间/字节预算，仍可能长时间占用资源。

这里不能断言完全没有回收：外层 HTTP 超时、连接关闭和请求 body 错误可能回收资源；缺的是本实现可控的 UDP 会话回收保证和服务端配额。

### 高：HTTP/2 私有全局开关的兼容性及并发风险

出处：`extendedconnect.go:15-53`。

`go:linkname` 绑定 x/net/http2 私有 bool，并在注册/清理 handler 时修改。其 mutex 仅保护本插件写侧，x/net/http2 发送 SETTINGS/检查请求时直接读该变量，热重载与现存连接并发时存在数据竞争风险。未进行该竞争的动态复现，结论来自读写代码路径。

任何一个 handler 要求隐藏就会影响进程内所有 H2 服务；隐藏既改变 SETTINGS，也关闭 Extended CONNECT 处理。此副作用已在 README 说明，但不是按站点隔离的配置。私有符号也可能随 x/net 版本变化。

建议不用这段技巧作为长期实现：H3-only 首期无需引入 H2 开关；若要 H2，应使用明确受支持的进程配置或维护可审查的 server 配置补丁。

### 中：MTU 错误、长度及分片策略

出处：`masque.go:24-25,195-229`。

server 将 maxUDPPayloadSize 设成 65535；RFC 9298 Context 0 上限是 65527。客户端值正确，服务端应修正，不能把大 payload 交给 OS 才发现失败。

更实用的问题是平台/地址族/路径限制低于上述协议上限时，`udpConn.Write` 的 EMSGSIZE 会向上传递并终止整个 relay；应该区分“单包太大”与“socket 已不可用”。未见 DF 或同等不分片控制；不能保证符合 RFC 对代理出口禁止新增 IP 分片的要求。

实测：macOS IPv4 loopback，65508 字节 payload 通过 Capsule 长度检查，但 UDP Write 报 message too long，capsulesToUDP 立即退出，其后合法包不再处理。该长度低于 65527，因此不是应按协议 abort 的超协议上限情况。

### 中：截断 Capsule 的 EOF 被当成正常关闭

出处：`masque.go:169-170,181-202` 以及 readQUICVarintWithScratch。

只收 varint 首字节后 EOF、只收到 capsule type 后 EOF、或 DATAGRAM capsule length=0 缺 context，均可能返回可被 errors.Is(err, io.EOF) 匹配的错误；relay 将其作为正常结束。按 RFC 9297 应识别不完整 capsule 为畸形消息。已有 truncated payload 测试没覆盖这些边界。

实测字节 `40`、`00`、`00 00` 均出现上述结果。需要区分 capsule 之间的干净 EOF 与解析过程中的 EOF/无效零长度结构。客户端解析器对这点处理更好。

### 中：迁移面与回归覆盖不足

naive UDP 提交涉及 47 个文件、约 3375 行新增；修改面覆盖 ProxyDelegate、socket pool、ConnectJob、H2/H3 proxy socket，并包含影响一般 QUIC 流的 header/body/FIN 行为改动。它们可能有合理理由，但没有随提交提供对应 C++ 单测，不能把“编译通过”视为异步生命周期正确。

`tools/run-udp-tests.py` 和 `udp-dns-test.py` 是需真实 server 的手工 echo/DNS 工具，并非系统性自动回归。`.github` 未见调用这些 UDP 工具；`tests/basic.py` 新增的是 UDP 配置解析 + TCP 请求检查。Go 侧有解析、H2 握手和基准测试，CI 配置运行 go test -race，但未见真实 H3 CONNECT-UDP 数据闭环测试。

需新增：真实 naive↔Caddy H3/H2 UDP echo；空 payload、来源欺骗、多 association、域名/IPv6；认证拒绝/ACL 拒绝；GOAWAY/RESET/取消/超时；资源回收；受控丢包/拥塞；TCP+UDP 并存和原 padding 回归。

## 借鉴建议

| 模块 | 借鉴程度 | 处理方式 |
|---|---|---|
| SOCKS UDP packet codec | 高 | 小模块移植，补单测/fuzz 和域名规范化 |
| association、flow generation、来源校验 | 高 | 保留模型，替换 transport，补全局限制和生命周期测试 |
| TCP/UDP tunnel type、padding 状态隔离 | 高 | 保留原则，尽量缩小对 Chromium 公共接口的修改 |
| 既有鉴权链路复用 | 高 | 参考设计，适配当前版本并做实际鉴权测试 |
| 服务端分流、ACL、connected UDP | 中高 | 保留框架，修 DNS cancel、idle、配额、DF/EMSGSIZE |
| URI/template 与 Capsule parser | 中 | 作为控制面/可靠 fallback 的基础，修边界与一致性 |
| NaiveCapsuleSocket 业务数据面 | 取决于目标 | 可选兼容后端，不能替代 DATAGRAM 后端 |
| go:linkname H2 全局开关 | 低 | 不直接采用 |
| 一般 QUIC FIN/header 修改 | 待验证 | 分离成小修复，配专门回归后决定 |

不按行数给百分比：对客户端入口和会话管理，较大部分设计可沿用；对 QUIC DATAGRAM、MTU 预算、Caddy 接入和低延迟数据面，当前实现基本没有提供。可将本项目设计收敛为 `UdpTunnel` 抽象，主后端实现 H3 DATAGRAM，可靠 Capsule 后端以后按需求启用，避免为兼容后端扩大首期范围。

## 验证记录

- 下载固定提交并静态检查变更和调用路径。
- 为避免 Caddy 外部依赖下载阻塞，将 Go Capsule/目标解析核心与其原有纯标准库测试隔离运行：7 个 Test 函数及子用例全部通过（没有因此验证 Caddy 集成）。
- 新增两组临时审查测试，分别复现上述 EOF 分类错误及超大 IPv4 包终止 relay。
- 完整 go test ./... 在外部依赖下载阶段未获得结果；没有将它记作通过。
- 未完整构建该 Chromium fork，未运行真实双端互通、网络丢包性能测试或热重载 race 复现。

## 固定源码链接

- [客户端 UDP 提交](https://github.com/ZihaoFU245/naiveproxy/commit/ad8a8741573974ec5be25877c5e935f424851bad)
- [association](https://github.com/ZihaoFU245/naiveproxy/blob/ad8a8741573974ec5be25877c5e935f424851bad/src/net/tools/naive/naive_udp_association.cc)
- [Capsule socket](https://github.com/ZihaoFU245/naiveproxy/blob/ad8a8741573974ec5be25877c5e935f424851bad/src/net/tools/naive/naive_capsule_socket.cc)
- [服务端 MASQUE](https://github.com/ZihaoFU245/forwardproxy/blob/792710f05f1181fb80e459b099e350c4f004f7a6/masque.go)
- [H2 全局开关](https://github.com/ZihaoFU245/forwardproxy/blob/792710f05f1181fb80e459b099e350c4f004f7a6/extendedconnect.go)
- [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298.html)、[RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html)
