# PathChord 技术选型

[English](technology-selection.md) | **简体中文**

本文选定初始实现技术。本文有意仅涵盖实现选型；协议和行为要求仍由架构及协议文档定义。

## 推荐基线

| 领域 | 选择 | 原因 |
|---|---|---|
| 语言 | Rust | 对缓冲区、并发、平台集成和长时间运行的网络服务具有较强控制力 |
| 异步运行时 | Tokio | 异步 I/O、定时器、取消、任务监管以及 Windows/Linux 支持成熟 |
| 密码学 | `snow`，使用 `Noise_IK_25519_ChaChaPoly_SHA256` | 直接支持 Noise 模式，并为每个 Path 提供独立的握手状态 |
| 对称密码原语 | 通过 Noise 实现使用 ChaCha20-Poly1305 | 与选定的 Noise 模式匹配 |
| 序列化 | 配置和管理 API 模型使用 `serde` | 共享强类型模型，同时不将线协议耦合到文本格式 |
| 线协议帧封装 | 使用 QUIC 风格无符号变长整数的专用 Rust 编解码器 | 协议要求显式帧封装，并且不依赖通用 RPC 模式定义 |
| 配置 | 人工编写的文件使用 YAML，并规范化为强类型 Rust 快照 | 在保持运行时求值强类型的同时提供易读的静态配置 |
| 控制面 | 类型化 command/query service，通过 Unix Socket/Named Pipe 传输带版本的长度分隔 JSON；可选认证 Web Gateway | 保持特权本地管理隔离，同时提供浏览器接入点，且不把运行时状态绑定到单一外部 API 风格 |
| 嵌入式状态 | Egress 授权和持久本地元数据使用 SQLite | 提供原子事务、代次编号并便于检查 |
| 规则 | 启动时编译的专用受限规则语言 | 求值具有确定性且输出模型狭窄；不能任意访问主机 |
| Linux 拦截 | `nix`/`socket2` 加平台专用的 netlink 和 TPROXY 代码 | 能够访问套接字选项和路由原语，同时不隐藏内核行为 |
| Linux TUN | 通过内部接口封装 `tun` 或等效的操作系统适配器 | 保持 TUN 实现可替换 |
| Windows TUN | 通过同一内部接口封装 Wintun 适配器 | 标准的 Windows TUN 集成方式 |
| HTTP/SOCKS | 内部协议适配器 | 所需语义较少，并可避免不必要地耦合代理框架 |
| 测试 | `cargo test`、确定性模拟传输、属性测试、数据包跟踪和故障注入 | 多路径正确性依赖可复现的丢包、重复、重排序和重启测试 |

调度器使用有效容量加权。配置的关系权重提供基线；Path 报告的容量、拥塞窗口、RTT、抖动和丢包率会调整即时分配。重传复制同时使用 Session 全局预算和可选的逐流量类别预算，其中 Session 预算为硬性上限。

## 架构边界

实现应划分为以下 crate 或等效模块：

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

`pathchord-core` 不得依赖 Linux、Windows、订阅格式或监听器实现。平台适配器通过面向字节传输、本地套接字、目标拨号和进程元数据的窄 trait 进行通信。

## Ingress 控制面和可观测性

Ingress 拥有一个类型化 command/query service，用于节点元数据、订阅、运行时快照、连接视图和结构化事件。权威本地适配器仍然是 Linux Unix domain socket 或 Windows Named Pipe，使用协议设计中选定的带版本长度分隔 JSON 封装。

可选 Web Gateway 调用同一个 service，默认关闭，且不能通过 Transit 或数据 Path 访问。首个浏览器适配器选择 REST 资源接口加 Server-Sent Events（SSE）；如果后续 dashboard 的查询组合确实需要，可再为同一 service 增加 GraphQL 适配器，并承担额外的授权、查询成本和订阅复杂度。REST 或 GraphQL 只是适配器选择，不是内部状态模型。

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

阶段 0 的 `snow` 封装使用显式 nonce 和有界重放窗口，但 `snow` 0.10 不保证清零其拥有的全部私钥、DH 和传输密钥缓冲区。这是已知的非生产限制；正式部署前必须采用支持清零的 resolver 或经过审查的库替代方案。

实现不得重用 WireGuard 密钥材料，也不得将 Transit Proxy 视为经过身份验证的对等方。

## 规则引擎选择标准

规则引擎必须是确定的、有界的，并且不能执行 I/O。它可以读取连接上下文、监听器元数据、进程元数据、目标元数据、静态标签和观测状态。它可以输出选择器、tag、label 和流量策略参数，但绝不能输出具体套接字或任意节点对象。

首个实现应使用小型原生 AST 编译器，而不是嵌入通用脚本语言。如果需要，未来的 WASM 或类 eBPF 后端可以实现相同的受限规则接口。

## 配置和热重载

人工编写的配置会被解析为强类型数据，经过验证、规范化并编译为不可变快照。快照替换是原子的。静态 Egress 拓扑和本地密钥材料仍是启动配置；Transit Proxy 数据和编译后的动态规则可以依照配置规则进行热重载。

Egress 授权变更使用 SQLite 事务。运行中的 Egress 进程拥有数据库，并将生成的代次编号发布到其内存授权快照。

## 平台计划

Linux 是第一个实现目标，因为 TPROXY、REDIRECT、进程元数据和透明路由是核心要求。Windows 支持会复用核心和策略 crate，并增加 Wintun 以及系统代理集成。

第一个里程碑应避免同时实现两个透明拦截平台。在添加 TPROXY 或 TUN 之前，应使用一个本地 SOCKS5 监听器、一个 Transit 适配器、一个 Egress 和一个 TCP Stream 来验证协议。

## 延后验证

推荐采用这些选型，但在将其视为永久决定之前，应使用小型原型进行验证：

- Noise 握手和传输状态（包括所选 resolver）的密钥清零行为；
- Path 频繁变动时的 Tokio 任务和取消结构；
- Wintun 打包和服务集成；
- Linux TPROXY 在 IPv4 和 IPv6 下的行为；
- 并发状态查询和注册操作下的 SQLite 行为；
- 自定义帧编解码器的吞吐量和分配成本；
- 规则编译器延迟和最坏情况求值成本。

阶段 0 的重放窗口有意限制为 64 条记录。在多路径数据面达到生产就绪前，必须验证 Session 级 ACK 保留和重传行为与该上限的协调关系。

