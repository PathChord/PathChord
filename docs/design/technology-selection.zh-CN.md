# PathChord 技术选型

[English](technology-selection.md) | **简体中文**

本文定义选定的技术和实现边界。协议和行为要求由架构及协议文档定义。

## 选定技术

| 领域 | 选择 | 原因 |
|---|---|---|
| 语言 | Rust | 对缓冲区、并发、平台集成和长时间运行的网络服务具有较强控制力 |
| 异步运行时 | Tokio | 异步 I/O、定时器、取消、任务监管以及 Linux/Windows/FreeBSD 支持成熟 |
| 密码学 | 通过 Clatter 使用 `Noise_IK_25519_ChaChaPoly_SHA256`，配合可清零 key/cipher 容器和 Orion SHA-256/HMAC adapter | 直接支持 Noise 模式、为每个 Path 提供独立握手状态、显式 nonce 传输，并可强制清理密钥状态 |
| 对称密码原语 | 通过 Noise 实现使用 ChaCha20-Poly1305 | 与选定的 Noise 模式匹配 |
| 序列化 | 配置和管理 API 模型使用 `serde` | 共享强类型模型，同时不将线协议耦合到文本格式 |
| 线协议帧封装 | 使用 QUIC 风格无符号变长整数的专用 Rust 编解码器 | 协议要求显式帧封装，并且不依赖通用 RPC 模式定义 |
| 配置 | 人工编写的文件使用 YAML，并规范化为强类型 Rust 快照 | 在保持运行时求值强类型的同时提供易读的静态配置 |
| 控制面 | 类型化 command/query service，通过 Unix Socket/Named Pipe 传输带版本的长度分隔 JSON；可选认证 Web Gateway | 保持特权本地管理隔离，同时提供浏览器接入点，且不把运行时状态绑定到单一外部 API 风格 |
| 嵌入式状态 | Egress 授权和持久本地元数据使用 SQLite | 提供原子事务、代次编号并便于检查 |
| 规则 | 启动时编译的专用受限规则语言 | 求值具有确定性且输出模型狭窄；不能任意访问主机 |
| Linux 拦截 | `nix`/`socket2` 加平台专用的 netlink 和 TPROXY 代码 | 能够访问套接字选项和路由原语，同时不隐藏内核行为 |
| Linux TUN | 通过 `PacketDevice` 封装 `tun-rs` 异步包设备，并使用直接的 `smoltcp` reactor | 安全、可替换的设备生命周期以及维护中的 TCP/UDP 状态机 |
| Windows TUN | 通过同一接口封装 `tun-rs` Wintun 包设备，并使用直接的 `smoltcp` reactor | 无需平台专用 TCP 重建的标准 Windows 驱动集成方式 |
| HTTP/SOCKS | 内部协议适配器 | 所需语义较少，并可避免不必要地耦合代理框架 |
| DNS 线协议处理 | 路由 adapter 后使用 `hickory-proto` | 使用成熟的 DNS 解析/编码，同时保持 local、Transit、Egress 和 blocked 路由可替换 |
| 测试 | `cargo test`、确定性模拟传输、属性测试、数据包跟踪和故障注入 | 多路径正确性依赖可复现的丢包、重复、重排序和重启测试 |

调度器使用有效容量加权。配置的关系权重提供基线；Path 报告的容量、拥塞窗口、RTT、抖动和丢包率会调整即时分配。重传复制同时使用 Session 全局预算和可选的逐流量类别预算，其中 Session 预算为硬性上限。

## 架构边界

实现划分为以下 crate 或等效模块：

```text
pathchord-core       protocol types, frame codec, Session, Stream, UDP
pathchord-noise      Noise handshakes and per-Path cryptographic records
pathchord-path       Path lifecycle, loss handling, scheduling, congestion reports
pathchord-policy     configuration snapshots, rule compiler, selectors
pathchord-transit    Transit Proxy adapters and subscription normalization
pathchord-egress     target dialing, Egress status, authorization store
pathchord-ingress    local listeners, transparent interception, process metadata
pathchord-cli        local management API client and operational commands
```

`pathchord-core` 不得依赖 Linux、Windows、FreeBSD、订阅格式或监听器实现。平台适配器通过面向字节传输、本地套接字、目标拨号和进程元数据的窄 trait 进行通信。

## Ingress 控制面和可观测性

Ingress 拥有一个类型化 command/query service，用于节点元数据、订阅、运行时快照、连接视图和结构化事件。权威本地适配器是 Linux 和 FreeBSD 上的 Unix domain socket，或 Windows 上的 Named Pipe，使用协议设计中选定的带版本长度分隔 JSON 封装。

可选 Web Gateway 调用同一个 service，默认关闭，且不能通过 Transit 或数据 Path 访问。选定的内置浏览器适配器使用 REST 资源接口加 Server-Sent Events（SSE）：资源 URL 和 HTTP 状态语义适合 command/query，单向 SSE 更新适合 metric 和事件。也可以在同一个类型化 service 边界后提供 GraphQL 适配器，但必须承担额外的授权、查询成本、缓存和订阅复杂度。类型化 service 拥有内部状态模型，独立于浏览器 API 风格。内置控制台资源嵌入 Rust 二进制，生产环境不需要 Node.js runtime。

节点 tag/label 修改、订阅创建/删除/刷新及其他变更都是带代次检查、幂等和审计的 command。动态快照原子替换；订阅刷新失败时保留最近一次成功快照。观测 provider 发布类型化的节点、Path、Session、Stream、目标连接、订阅和策略 metric。Web Gateway 暴露这些快照和有界事件流；运维人员不能依靠解析日志重建当前状态。

`STATUS_REPORT` 仍然是用于 Egress 准入和健康状态的紧凑认证 data-Path 消息，不是管理 API，也不是 metrics 传输。

## Noise 和记录处理

每个 Path 都拥有独立的 Noise 会话和传输密码状态。记录层必须：

- 在 `PATH_READY` 之前验证 Path 的身份；
- 在 Noise prologue 中绑定已配置的 EgressID，然后在 `SESSION_ATTACH` 之前将经过身份验证的 initiator 密钥映射到已授权的 IngressID；
- 使用显式记录 nonce，避免丢失和乱序导致逐 Path 密码状态失步；
- 由逐 Path 发送端分配出站 nonce，并保留 nonce/密文记录用于重传；
- 在分配内存之前拒绝过大的记录；
- 限制帧明文大小，确保编码后的帧头、载荷和认证标签不超过 Noise 实现的消息上限；
- 只暴露完整的 PathChord 帧；
- 将身份验证失败报告为 Path 故障；
- 绝不跨 Path 重用传输密码状态。

Clatter 拥有 IK 状态机、X25519 私钥/DH 输出容器和传输密码状态，其含密钥容器在 Drop 时清零。SHA-256/HMAC adapter 使用启用清零的 Orion，因此 keyed hash 状态、chaining-key 中间值和 HMAC pad 也会被清理。PathChord 在 teardown 时显式清理仍存活的传输密码，并在 wire profile 中冻结确定性兼容向量。记录层使用有界重放窗口，其大小和保留语义必须兼容 Session 级 ACK 保留及重传行为。

实现不得重用 WireGuard 密钥材料，也不得将 Transit Proxy 视为经过身份验证的对等方。

## 规则引擎选择标准

规则引擎必须是确定的、有界的，并且不能执行 I/O。它可以读取连接上下文、监听器元数据、进程元数据、目标元数据、静态标签和观测状态。它可以输出选择器、tag、label 和流量策略参数，但绝不能输出具体套接字或任意节点对象。

内置规则引擎使用小型原生 AST 编译器。替代的 WASM 或类 eBPF 后端可以实现同一个受限规则接口，但必须保持确定、有界且无 I/O 的求值。该接口定义策略编译与运行时求值之间的边界。

## 配置和热重载

人工编写的配置会被解析为强类型数据，经过验证、规范化并编译为不可变快照。快照替换是原子的。静态 Egress 拓扑和本地密钥材料仍是启动配置；Transit Proxy 数据和编译后的动态规则可以依照配置规则进行热重载。

Egress 授权变更使用 SQLite 事务。运行中的 Egress 进程拥有数据库，并将生成的代次编号发布到其内存授权快照。

## 平台架构

Linux、Windows 和 FreeBSD 共享 HTTP CONNECT 和 SOCKS5 CONNECT/UDP ASSOCIATE adapter。FreeBSD 使用 Unix 本地控制，v1 平台契约禁止其暴露 TPROXY、REDIRECT 或 TUN 监听器。系统代理 mutation 仅限 Windows；Linux 和 FreeBSD 报告激活不受支持。平台无法安全获取的进程元数据保持 unknown。

Linux 通过平台适配器集成 TPROXY、REDIRECT、进程元数据和透明路由。Windows 使用 Wintun，并通过控制面选择监听器来集成系统代理。TUN 适配器只暴露有界 IP 包；单一所有者的 `smoltcp` reactor 持有 `Interface`、`SocketSet`、TCP Listener、UDP socket、计时器和 flow 生命周期，并通过与普通 Listener 相同的 Ingress opener 连接已接受 flow。三个平台复用核心和策略 crate。

一个 Ingress 平台运行时模块统一持有普通 Listener、透明 Listener、策略路由、UDP 适配器和 TUN
reactor 的启动与关闭。启动时先验证所有 Listener，并以一个事务获取资源；任何失败都会回滚已持有路由并
释放已获取设备。一棵取消树监督所有适配器，在恢复路由前 join 它们，因此 CLI 不重复平台生命周期逻辑。

平台适配器负责操作系统专用的打包、服务集成、套接字行为和路由行为。Linux 透明路由支持 IPv4 和 IPv6。Tokio 任务监管和取消必须在 Path 频繁变动时避免任务或资源泄漏。SQLite 事务在并发状态查询和注册操作期间保持授权一致性。帧编解码器依据协议上限约束内存分配，规则编译器保证有界求值成本。

