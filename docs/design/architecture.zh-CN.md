# PathChord 架构

[English](architecture.md) | **简体中文**

## 1. 范围

PathChord 支持 Linux、Windows 和 FreeBSD。三个平台都必须支持普通 HTTP 转发、HTTP CONNECT、SOCKS4/4a/5 CONNECT 和 SOCKS5 UDP ASSOCIATE 监听器。Linux 支持 TPROXY、REDIRECT，可以支持 TUN；Windows 通过控制面选择监听器来提供 TUN 和系统代理集成。v1 平台契约禁止 FreeBSD 暴露 TPROXY、REDIRECT 或 TUN 监听器。三个平台共享策略、节点、Noise、Session 和多路径核心。

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

首先选择 Egress，随后由该 Egress 的 Ingress 侧 Transit 绑定提供公共候选集和 Session Path 池。一个流绝不会跨越多个 Egress 节点，路由规则也不选择 Transit 或 Path 子集。

## 3. 路由模式

- `egress: <id-or-selector>`：Ingress 通过一个或多个 Transit Path 到达选定的 Egress。默认使用多路径聚合。
- `mode: none`：Ingress 选择一个 Transit Proxy，由该代理连接目标。这是普通代理回退模式。
- `proxy: direct`：direct 是一种无需第三方中继、直接建立连接的 Transit Proxy 传输方式。
- 全局回退必须显式配置为 `reject` 或 `direct`。

## 4. 规则阶段

### Egress 阶段

规则按顺序执行。对于新流，首个条件匹配且 Egress 当前可用的规则胜出。可用性是持续维护的运行时状态，而不是在规则匹配期间执行的探测。

如果没有有效的 Egress 规则，则评估普通 Proxy 规则。如果没有普通 Proxy 规则匹配，则执行全局回退。

### Egress Path 阶段

选择 Egress 后，其 `transit` 绑定根据公共选择器和运行时状态筛选同 namespace 的 Transit Proxy。绑定及其 `trafficPolicyRef` 与 flow 匹配无关。已准入的 Proxy 到 Egress 关系构成多路径候选集。权重作用于整个关系；经由同一 Proxy 的多条 Path 不会成倍增加其配置权重。

## 5. 运行时状态

`connected` 表示当前 Ingress 到 Egress 的 Session 至少存在一条经过
认证且双向就绪的 Transit Proxy Path。它是 Session 关系事实，不是 Egress
全局健康事实。Egress 服务状态还可以是 `up`、`degraded`、`draining` 或
`down`，并通过独立的 `admission_allowed` 表示当前是否接受新的目标连接。

- `up`：已连接并满足当前全局资源和准入要求。
- `degraded`：已连接，但容量、Path、质量或资源要求低于理想状态；可以允许或拒绝新准入。
- `draining`：管理员或生命周期正在排空；拒绝新流并排空现有流。
- `down`：没有就绪 Path、授权失败或管理员显式关闭；关闭相关 Session 和业务资源。

Egress 通过现有 Path 上报聚合资源事实：配置的 wire 容量上限、有效容量、
当前 wire 速率、容量可信度、活跃目标连接数、服务状态和全局准入状态。
Egress 不上报或解释 Ingress 规则。Ingress 拥有每条 Path 的方向性观测和
每个 Session 的聚合 demand。系统不保证跨 Ingress 的公平性。

Egress 资源的 authored 配置只有全局资源上限：wire 带宽上限
(`maxWireBandwidthBps`) 和入站目标连接上限
(`maxInboundTargetConnections`)。Path 安全上限、pending reservation、测得的容量
和准入原因都由运行时拥有；desired Path 数量和 per-Ingress 配额不是配置输入。

## 6. 故障语义

- Transit Path 故障：移除该 Path；现有 Stream 可以继续通过其他合规 Path 传输。
- Egress Session 低于公共可用 Path 最小值：仍有 ready Path 时拒绝新业务，已有流继续运行。
- Egress 故障：双方关闭所有相关 Path、Session、Stream、本地连接以及 Egress 到目标的连接。应用程序必须重试。
- Ingress 或 Egress 任一进程重启都会使相关连接和 Session 失效。
- 目标端的 FIN/RST 会反映给本地应用程序；代理层不会静默重建目标 TCP 连接。

## 7. Session 与 Path

每个活跃的 Ingress 到 Egress 关系对应一个 Session，并且该 Session 与
Egress 严格一一对应。Session 拥有自己的 Path 集合、流控、demand 窗口、
复制记账和生命周期。Session 重连始终创建新的 SessionID，并重置运行时状态。

每个存活的 Session 至少包含一条处于 `PATH_READY` 状态、双向且长连接的
Path。Session 管理器可以保留一条 Path 数量为零、正在重连的记录，但该记录
不能承载业务流量。Transit 关系与 Path 实例分离，因此同一个 Transit Proxy
可以承载多条独立 Path。关系权重只计算一次，再由这些 Path 实例共享该关系分配。

Ingress 创建、扩展、排空和关闭 Path。Stream 和 UDP 会话独立于 Path 标识，
可以在公共 Egress Session 池的 Path 之间迁移。Egress 的
`statusRequirements.minUsablePaths` 是唯一的公共最小值；只有非排空的 ready
Path 计入新业务准入。低于该值时 Session 进入 degraded 但保留已有工作；最后
一条 ready Path 丢失时关闭 Session。

Session 控制和可选额外复制使用协商出的 Session 硬上限。每个发送方在所有 flow
和 Path 之间共享一个 outbound allowance，上下行分别受该标量上限约束。即使
可选复制耗尽，第一份副本和普通可靠重传仍然可用。Egress 执行全局资源上限，并优先保障业务
主流量、普通重传和必要控制流量；它不解释 Ingress 规则，也不承诺跨 Ingress 公平性。
经过认证的 future ACK 属于 Session 信任失败：关闭全部 Path 和业务资源，废弃旧
SessionID，并通过有界退避和断路器使用新的 SessionID 恢复。

## 8. 动态调度

Egress 上报全局资源事实：配置的 wire 容量上限、测得的有效容量、当前
wire 速率、容量状态（`unknown`、`provisional`、`measured` 或 `stale`）、
活跃目标连接数、`admission_allowed` 和稳定的准入原因。`recommendedPathCount`
不是 Egress 契约。

Ingress 使用有界 counter、ACK、heartbeat、数据速率、丢包、重传、RTT、抖动
和拥塞反馈，分别测量每条 Path 的上行和下行状态。它每个 Session 聚合 demand，
不保留无界的 per-Stream 或 per-rule 历史。健康采样和 demand 窗口以低频运行；
数据路径只更新有界 counter。

对于每个 Egress Session，Ingress 根据公共最小值、合规 Transit 关系、聚合方向性
demand、Path 质量和 Egress 硬安全上限计算一个 Path target。物理 Path target
覆盖上行和下行中需求较大的方向。扩容和缩容使用迟滞，检查所有选定排空后仍剩余
的非排空可用 Path，并排除新增容量低于调度开销的候选。

Egress 的有效容量是全局 scheduler/resource 估计值，受配置 wire 上限约束，
并通过 aggregate wire 速率、队列、重传和资源反馈被动计算；空闲吞吐不能伪造
测得容量。Egress 不计算规则级 demand，也不执行跨 Ingress 公平调度。

支持 TLS 的 Transit 适配器默认加载系统根证书。按顺序排列的 `truststore` 来源列表
可以追加本地 PEM/DER 文件；来源无效、过大或不是普通文件时，适配器准备以原子方式失败。
本地控制分别限制前缀读取、payload 读取、dispatch 和响应写入时间。

订阅配额和流量倍率是可选的参考元数据。它们可以生成标签或影响权重；它们不是硬性限制，也不会直接改变 Egress 连通性。

订阅文档规范化独立于节点传输支持。适配器保留类型化连接语义，并在准入前拒绝不支持参数；
请求 TLS 的 HTTP 节点不能变成明文连接。不支持的协议输入在对应的 PathChord 原生适配器完成前
保持不可用，且不拥有 PathChord 授权或 Noise 状态。[Transit Proxy 契约](../../openspec/specs/transit-proxies/spec.zh-CN.md)定义受支持
文档类型、provider 展开及用量事实。

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

多个 HTTP/SOCKS 监听器各自具有唯一 ID，并参与策略评估。`mixed` 监听器在一个 TCP 端点上共用 HTTP 和 SOCKS，两个协议分支保留同一个身份。监听器认证和来源网络限制独立于 Ingress 到 Egress 的 Noise 认证。

普通 HTTP 请求分别独立路由，包括同一个客户端持久连接中发往不同目标的请求。代理凭据保留在本地，按 framing 转发以保留消息边界和流式背压。HTTP CONNECT 和 SOCKS 连接只有在目标准入成功后才成为字节流。请求、认证、升级和 SOCKS 兼容性的细节以[平台与 DNS 规范](../../openspec/specs/platform-and-dns/spec.zh-CN.md#http-和-socks-监听器)为准。

Windows 系统代理集成是控制面开关，按 ID 选择一个 HTTP/SOCKS 或 mixed 监听器。选中 mixed 监听器时，使用共享端点的 HTTP 代理设置。Linux 和 FreeBSD 不暴露系统代理激活模式；其监听器及系统代理不受支持的状态仍可通过控制面查看。Linux 和 FreeBSD 的本地控制使用 Unix socket，Windows 使用 Named Pipe。

透明入口不执行域名路由。HTTP/SOCKS 请求显式携带域名，因此可以按域名路由。DNS 独立运行，并选择查询的解析位置：本地、通过 Transit Proxy、通过选定的 Egress，或阻止查询。不使用 Fake-IP 映射。

## 11. 配置生命周期

一个文件或目录资源集合定义一张资源图。Ingress 按显式命令行来源、环境变量、账号默认值的
优先级选择配置。目录文件按确定顺序加载、统一验证并发布为一个快照；候选失败时保留原图。

Egress 拓扑、Egress 公钥、Transit 绑定、公共 Path 要求、已解析 TrafficPolicy 和 Ingress 本地私钥属于静态配置，发生变更时需要重启 Ingress。Transit Proxy 列表是运行时数据，从订阅刷新到磁盘缓存并热重载。刷新失败时保留当前列表；订阅中已删除的 Proxy 进入排空状态。Egress 容量和全局连接限制是资源上限；期望 Path 数由 Ingress 运行时决定。

静态规则配置在启动时编译。订阅派生数据和获准的动态规则快照可以在后台编译并原子热重载。运行时分别维护策略、Egress、Proxy、认证和指标快照。Ingress 内部流量绕过自身的透明拦截，以防止形成环路。

Ingress 管理员元数据和订阅操作属于控制面 mutation。它们原子发布新的代次，使用期望代次检查处理并发编辑；刷新失败时保留最近一次成功的订阅快照。Web/API 适配器调用拥有者的类型化 service，不能直接编辑配置文件或缓存。
