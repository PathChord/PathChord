# PathChord 架构

[English](architecture.md) | **简体中文**

## 1. 范围

PathChord 支持 Linux、Windows 和 FreeBSD。三个平台都必须支持 HTTP CONNECT、SOCKS5 CONNECT 和 SOCKS5 UDP ASSOCIATE 监听器。Linux 支持 TPROXY、REDIRECT，可以支持 TUN；Windows 通过控制面选择监听器来提供 TUN 和系统代理集成。v1 平台契约禁止 FreeBSD 暴露 TPROXY、REDIRECT 或 TUN 监听器。三个平台共享策略、节点、Noise、Session 和多路径核心。

系统支持 TCP、UDP 和独立 DNS。Fake-IP、通用 ICMP 转发、组播代理和任意 IP 隧道不在协议范围内。

## 2. 拓扑

```text
local applications / LAN devices
              |
           Ingress
              |
   +----------+----------+
   |          |          |
Transit A  Transit B  Transit C
   |          |          |
   +----------+----------+
              |
           Egress
              |
           Target
```

首先选择 Egress，随后为该 Egress 准入并调度 Transit Proxy。一个流绝不会跨越多个 Egress 节点。

## 3. 路由模式

- `egress: <id-or-selector>`：Ingress 通过一个或多个 Transit Path 到达选定的 Egress。默认使用多路径聚合。
- `mode: none`：Ingress 选择一个 Transit Proxy，由该代理连接目标。这是普通代理回退模式。
- `proxy: direct`：direct 是一种无需第三方中继、直接建立连接的 Transit Proxy 传输方式。
- 全局回退必须显式配置为 `reject` 或 `direct`。

## 4. 规则阶段

### Egress 阶段

规则按顺序执行。对于新流，首个条件匹配且 Egress 当前可用的规则胜出。可用性是持续维护的运行时状态，而不是在规则匹配期间执行的探测。

如果没有有效的 Egress 规则，则评估普通 Proxy 规则。如果没有普通 Proxy 规则匹配，则执行全局回退。

### Transit 阶段

选择 Egress 后，按顺序评估该 Egress 专用的 Transit Proxy 规则。首个匹配规则决定准入和基础权重。若一个规则匹配多个可用 Proxy，在普通代理模式下可任选其一；节点顺序不具备语义。

在 Egress 模式下，已准入的 Proxy 到 Egress 关系构成多路径候选集。权重作用于整个关系；经由同一 Proxy 的多条 Path 不会成倍增加其配置权重。

## 5. 运行时状态

`connected` 表示至少存在一条经过 Transit Proxy、已经认证且双向连通的 Ingress 到 Egress Path。若不存在 Path，`connected` 为 false。Egress 服务状态还可以是 `up`、`degraded`、`draining` 或 `down`。

- `up`：已连接并满足当前准入要求。
- `degraded`：已连接，但容量、Path 数量或能力要求未满足。
- `draining`：不接受新流；现有流继续排空。
- `down`：不存在双向 Path，或已被管理员显式关闭。

Egress 状态通过现有 Path 上报。Ingress 维护每个 Ingress 到 Egress 关系的状态；Egress 资源指标可以是全局的，并可包含每个 Ingress 的配额或准入限制。

## 6. 故障语义

- Transit Path 故障：移除该 Path；现有 Stream 可以继续通过其他合规 Path 传输。
- 某个流没有合规 Path：终止该流；共享 Session 中的其他流继续运行。
- Egress 故障：双方关闭所有相关 Path、Session、Stream、本地连接以及 Egress 到目标的连接。应用程序必须重试。
- Ingress 或 Egress 任一进程重启都会使相关连接和 Session 失效。
- 目标端的 FIN/RST 会反映给本地应用程序；代理层不会静默重建目标 TCP 连接。

## 7. Session 与 Path

每个活跃的 Ingress 到 Egress 关系对应一个 Session，并且该 Session 与 Egress 严格一一对应。Ingress 上线时会尝试为已配置的 Egress 建立 Session，并在 Egress 在线期间维持这些 Session。Session 是一个 Ingress 与一个 Egress 之间的逻辑通道；业务 Stream 和 UDP 会话复用该通道。Session 不绑定单一物理传输。

每个存活的 Session 至少包含一条处于 `PATH_READY` 状态、双向且长连接的 Path。Session 管理器可以保留一条 Path 数量为零、正在重连的记录，但该记录不能承载业务流量。Path 是 Session 的一条物理中转链路。Ingress 创建、扩展、排空和关闭 Path；Egress 复用相同的 Path 传输返回流量。Stream 独立于 Path 标识，可以随时在 Path 之间迁移。

控制消息具有独立的发送预算。业务流量采用公平调度，并可选用优先级和份额。调度器决定当前可用的哪些 Path 可以承载每个流量类别；Stream 不保留 Path 标识。Session 控制消息可以使用任何未撤销的 Path。

## 8. 动态调度

Egress 上报负载、连接利用率、带宽利用率、活跃 Session、活跃 Stream、活跃目标连接、容量以及建议 Path 数量。Ingress 测量每条 Path 的 RTT、抖动、丢包、乱序、吞吐量和连接建立质量。

Ingress 通过原子运行时快照 provider 发布这些观测数据。该 provider 也提供节点 label/tag、订阅代次、Session、Stream、目标连接和策略状态，供结构化管理查询使用。日志只是补充诊断；当前运行状态和 metric 不得依靠解析日志重建。可选的认证 Web Gateway 可以向前端提供快照和有界变更事件，而权威本地控制 API 仍然位于 Unix socket 或 Named Pipe 上。

有效聚合容量不足时，自动扩缩容会增加 Path；只有在持续出现容量富余后才会谨慎移除 Path。质量下降时会快速减少分配；恢复和缩容过程保持稳定。可以通过增加其他 Path 来补偿质量较差的 Path，但当其新增容量低于自身开销时会将其排除。

订阅配额和流量倍率是可选的参考元数据。它们可以生成标签或影响权重；它们不是硬性限制，也不会直接改变 Egress 连通性。

## 9. 元数据

节点使用相互分离的命名空间：

- `node`：静态标签/标记以及订阅派生的标签/标记。
- `source`：导入的订阅身份和来源元数据。
- `observed`：运行时 Path 质量和健康状态标签。
- `quota`：可选的订阅配额参考信息。
- `billing`：可选的流量倍率参考元数据。
- `admin`：管理状态。

本地覆盖优先于订阅注解。管理员禁用、授权撤销和断开连接等硬状态不能被偏好标签覆盖。

## 10. 入口与 DNS

多个 HTTP/SOCKS 监听器各自具有唯一 ID，并参与策略评估。监听器认证和来源网络限制独立于 Ingress 到 Egress 的 Noise 认证。

Windows 系统代理集成是控制面开关，按 ID 选择一个 HTTP/SOCKS 监听器。Linux 和 FreeBSD 不暴露系统代理激活模式；其监听器及系统代理不受支持的状态仍可通过控制面查看。Linux 和 FreeBSD 的本地控制使用 Unix socket，Windows 使用 Named Pipe。

透明入口不执行域名路由。HTTP/SOCKS 请求显式携带域名，因此可以按域名路由。DNS 独立运行，并选择查询的解析位置：本地、通过 Transit Proxy、通过选定的 Egress，或阻止查询。不使用 Fake-IP 映射。

## 11. 配置生命周期

Egress 拓扑、Egress 公钥和 Ingress 本地私钥属于静态配置，发生变更时需要重启 Ingress。Transit Proxy 列表是运行时数据，从订阅刷新到磁盘缓存并热重载。刷新失败时保留当前列表；订阅中已删除的 Proxy 进入排空状态。

静态规则配置在启动时编译。订阅派生数据和获准的动态规则快照可以在后台编译并原子热重载。运行时分别维护策略、Egress、Proxy、认证和指标快照。Ingress 内部流量绕过自身的透明拦截，以防止形成环路。

Ingress 管理员元数据和订阅操作属于控制面 mutation。它们原子发布新的代次，使用期望代次检查处理并发编辑；刷新失败时保留最近一次成功的订阅快照。Web/API 适配器调用拥有者的类型化 service，不能直接编辑配置文件或缓存。
