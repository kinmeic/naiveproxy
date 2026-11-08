# UDP over QUIC 代码审计与可识别性评估

日期：2026-11-08。范围：`kinmeic/naiveproxy` 和 `kinmeic/forwardproxy` 的
`codex/udp-over-quic` 分支新增 UDP 路径及相关 Caddy patches。审计起点分别为
`d28776d3edd1c078c9818376eeafe2b9546185b7` 和
`a0a598514b7ffb7bd98f6121bcf227a0ba48cae9`。
这是源码检查、针对性回归和本地受控流量观察，不是完整 Chromium/Caddy
依赖审计，也不是公网防火墙识别率测试。

## 已修复问题

| 优先级 | 项目与问题 | 影响与修复 |
| --- | --- | --- |
| P1 | forwardproxy 默认 ACL 遗漏 IPv6 ULA 与 IPv4 link-local | 有效账户可访问服务器可达的 ULA/链路本地目标，包括部分环境的元数据地址。默认 deny 增加 `fc00::/7`、`169.254.0.0/16`；管理员显式 allow 仍优先，TCP/UDP 一致 |
| P2 | 等待客户端 SETTINGS 时未计入 UDP 会话额度 | 已认证客户端可积累最多等待十秒的请求而绕过 UDP admission。额度获取提前到等待之前；取消、超时和能力拒绝均释放额度 |
| P2 | 未知 Context ID 绕过包速率扣减 | 布尔短路跳过 `Allow()`，未知上下文仍可消耗处理资源。所有已解析数据报都扣减共享预算，丢弃计数一致 |
| P2 | 未知/空 Capsule 可持续消耗控制解析资源 | 增加每隧道 100 个 Capsule/s、burst 100 的处理上限；超限关闭隧道。保留 64 KiB 长度上限，截断直接失败 |
| P2 | 空闲检测使用墙上时钟、并发 touch 可时间倒退 | 改成基于 monotonic start 的原子持续时间；CAS 只接受较新的活动时间 |
| P2 | UDP 启用时畸形配置凭据可能触发旧认证函数 panic | Provision 校验配置凭据必须是合法 Base64 Basic `username:password` 且用户名非空；取认证 token 时不再用未检查的数组索引 |
| P3 | 客户端等待 SETTINGS 时反复开启 SEND_REQUEST NetLog 事件 | 新增独立等待状态，轮询间隔由 10 ms 调至 50 ms；ConnectJob 继续限制总连接时间 |
| P3 | SOCKS UDP 源端口绑定依赖建流结果/时序 | 收到首个语法合法且源 IP 匹配的报文即固定源 endpoint，再进入可能同步完成的建流操作 |
| P3 | Capsule 接收路径业务统计遗漏 | 与 QUIC DATAGRAM 共用转发函数，统一发送、丢弃、短写和 MTU 错误处理 |

上述资源类问题主要要求有效代理凭据；没有将其描述为未认证远程代码执行。
源端口固定仍遵循 SOCKS 的首包学习方式：同一客户端 IP 上能抢先发首包的
攻击者仍有竞争机会，绑定本地 SOCKS 监听和访问控制仍有意义。

## 验证

- 本机 Chromium/Naive `ninja ... naive` 编译通过。
- patched Caddy 构建通过；Go UDP 单元/真实 HTTP/3 集成测试 `-race` 通过，
  `go vet ./...` 通过。SETTINGS admission、未知 Context、Capsule 洪泛/截断、
  monotonic timer 回归额外重复五次通过。
- 增加默认 ACL/显式 allow、畸形配置凭据、probe resistance 回归。
  未认证/错误认证/错误认证格式在合法与非法路径下均回到普通站点处理；
  不返回 `Proxy-Authenticate` 或 `Capsule-Protocol`，不分配 UDP 额度。
- 真实 native SOCKS → QUIC → patched Caddy → UDP echo 通过：IPv4、IPv6、
  域名、空数据报、多 association、1200 字节、超大包后恢复、源端口固定，
  以及共享连接上的 TCP padding 共存。
- 原 TCP HTTP 代理回归 28 通过、4 跳过（默认端口用例未运行）。
- 本机 macOS 缺少旧测试要求的 127.x loopback aliases，因此本地 Go race
  运行 UDP 子集。Naive 仓库的 GitHub Actions 在此前运行时被平台以
  “Actions has been disabled for this repository” 拒绝，不能把本地 macOS
  编译当作已完成 Linux/Android 全平台验证。

## 与 HTTPS 对比的结论

“识别是 QUIC”“识别是代理”和“能够阻断”是三个不同目标。

| 基准 | 结论 | 理由 |
| --- | --- | --- |
| 普通 HTTPS over TCP（HTTP/1.1、HTTP/2） | 工程上应按更高的传输分类/阻断风险看待；没有证据表明精确识别为代理的概率更低 | 外层改成 UDP/QUIC，可被独立限速/阻断；本实现没有 UDP 的 TCP 可靠回退，另外还保留包长/时序线索 |
| 普通 HTTPS over QUIC（HTTP/3） | 没有依据判断更低；代理特有的流量形态可能增加统计分类线索，程度尚未量化 | 外层都是 QUIC/H3，不能仅凭 UDP/443 或 DATAGRAM 能力断定是代理；需比较真实浏览器/站点的握手与业务分布 |
| Naive 原 TCP 代理路径 | UDP 路径没有沿用 TCP 的 padding 保护 | 原 TCP padding framer 不能直接用于无状态数据报；当前 UDP 保持 RFC Context 0 原始载荷 |

此处“更高”是可观察面和阻断策略上的工程判断，不是测得的分类准确率。
普通 HTTPS 本身也可按 IP、SNI 或策略阻断；不能推导为 TCP HTTPS 不可识别。

### 没有发现可被旁路直接读取的 CONNECT-UDP 明文标记

CONNECT-UDP 的 `:protocol`、目标 URI、Basic 凭据、HTTP/3 SETTINGS、Context ID
以及 QUIC DATAGRAM 帧内容位于握手后的加密数据中。被动观察者不能直接扫描
`connect-udp` 字符串或 DATAGRAM 帧类型来认出本实现。
这不掩盖 QUIC 协议身份、IP、包长、方向、时间和可关联的连接标识。
[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html#section-5)、
[RFC 9312](https://www.rfc-editor.org/rfc/rfc9312.html#section-3)。

### Initial 和握手指纹仍是观察面

QUIC Initial 的密钥可以从公开信息推导；在没有有效 ECH 保护的情况下，
ClientHello 的 SNI、ALPN 和客户端 transport parameters 可被提取。
服务器 transport parameters 与后续 SETTINGS 不能因此被旁观者直接读取，
但主动建立连接的一方可以看到协商能力。
[RFC 9001 §5.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2)、
[RFC 9312 §3.4](https://www.rfc-editor.org/rfc/rfc9312.html#section-3.4)。

服务器 patch 开启 DATAGRAM 能力会改变其协商行为；合法的 WebTransport/MASQUE
服务也可具备这种能力，不能把它当作本代理独有的签名。客户端当前 QUICHE
`LocalHttpDatagramSupport()` 原本已默认 `kRfc`，本次并非从不支持改成支持。
复用 Chromium 不能证明其握手、参数、连接使用方式和流量分布与普通 Chrome
一致，也不能证明 Go 服务端与任意大型网站的 QUIC 栈一致。

USENIX Security 2025 的公开研究已实测基于 QUIC Initial 中 SNI 的审查，
因此不能假定“QUIC 加密了首包就无法按域名识别”。该论文描述的是其测量
时期的网络，不构成 2026 年任意地区、任意防火墙的覆盖率结论。
[作者公开论文](https://gfw.report/publications/usenixsecurity25/en/)。

### 已观测到包长随载荷变化

一次受控测试在 native 与 patched Caddy 间加入透明 loopback UDP 中继，仅记录
外层 UDP 载荷字节数、方向和相对时间，不读取密钥/明文。在已建立的连接中
间隔 50 ms 顺序发送随机长度 echo；同时运行原有双端回归。

| 内层 UDP 载荷 | 客户端 → 服务端业务包 | 服务端 → 客户端业务包 |
| ---: | ---: | ---: |
| 128 | 153 | 152 |
| 512 | 537 | 536 |
| 1000 | 1025 | 1024 |
| 1200 | 1225 | 1224 |

单位为字节；外层长度不含 IP/UDP 头。同阶段另有小 ACK 和 PMTU 探测包。
本次低负载样本的业务长度呈近似恒定开销关系，说明加密没有隐藏报文尺度。
这些差值不是协议保证，会随 CID、packet number、聚合和路径改变。
DNS、实时通信、游戏或内层 QUIC 的包长/周期可能成为分类输入；这些观察
不足以证明某款防火墙已经能可靠识别本代理，亦不足以量化误报率。

### 主动探测取决于配置

未开启 `probe_resistance` 时，错误认证可返回带代理 realm 的 407，能明确
暴露 HTTP forward proxy；这是已有代理行为，UDP 新增路径也继承它。
开启后未认证请求先进入普通站点；本次回归验证了认证隐藏先于 UDP 能力检查。
普通站点的完整行为、TLS/QUIC 栈、证书、IP 信誉和流量统计仍然可观察。
显式配置的 secret domain 还保留原有隐藏认证页语义。

## 保留限制与后续验证

- UDP padding、流量整形、应用分片、可靠回退未实现；本次没有为了“隐藏”
  往 Context 0 插入私有填充字节，因为这会污染原始 UDP 载荷、破坏互操作。
  标准格式见 [RFC 9298 §5](https://www.rfc-editor.org/rfc/rfc9298.html#section-5)。
- 未进行跨运营商公网审查测试、长时间负载测试、移动端功耗测试、模糊测试，
  也未训练/评估流量分类器。不能给出“不可识别”或风险降低百分比。
- 若以防火墙识别风险作为上线门槛，下一步需要同网络、同服务端、同负载的
  浏览器 HTTPS/TCP、浏览器 HTTP/3 与本实现对照抓包和可复现统计评估，分别
  记录连接成功率、误报/漏报和性能。当前版本应定位为标准 UDP 转发能力，
  不应宣传为比普通 HTTPS 更隐蔽。
