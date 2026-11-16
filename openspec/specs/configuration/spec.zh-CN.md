# PathChord 配置规范

[English](spec.md) | **简体中文**

## Purpose

定义 PathChord 的声明式资源模型、有序路由决策、不可变运行时快照和动态配置所有权，并与管理编码及 data Path 编码保持独立。

## Requirements

### Requirement: Declarative configuration contract

配置处理必须（SHALL）遵守完整的[详细契约](#detailed-contract)，包括对象模型、示例、监听器引用、命名空间所有权和更新规则。期望配置与只读运行时状态必须（SHALL）保持分离。

#### Scenario: Publish validated desired resources

- **WHEN** 一个配置集合被接受并准备发布
- **THEN** 必须验证其完整对象图并转换成类型化不可变快照，运行时观测通过独立的只读 `status` 视图暴露

### Requirement: Ordered routing and explicit fallback

Ingress 必须（SHALL）先评估有效 Egress 规则，再评估普通 Proxy 规则和必需的全局回退。Egress 规则只能选择 Egress 引用或选择器，或通过 `mode: none` 明确进入普通 Proxy 模式；Transit 选择来自被选 Egress 的绑定。不支持的普通 UDP 路由必须（SHALL）按策略失败，不得绕过为 direct。

#### Scenario: No effective Egress route is selected

- **WHEN** 有序的有效 Egress 规则没有为新 flow 选出可准入路由
- **THEN** Ingress 按顺序评估普通 Proxy 规则，然后应用配置的全局回退

#### Scenario: Different rules select the same Egress

- **WHEN** 两个 flow 匹配不同的 Egress 规则但选择同一个 Egress
- **THEN** 两者都使用该 Egress 的 Session Path 池和 TrafficPolicy，规则不得为它们推导不同的 Transit 候选或 Path 要求

### Requirement: Bounded ordinary Proxy pre-admission failover

普通 Proxy 规则必须（SHALL）在同一策略代次内按稳定的评分和 ID 顺序尝试合格 Transit 节点，最多八次且共享配置的连接超时。适配器返回 stream 或数据报 handle 后，后续失败不得（SHALL NOT）触发替换或重试。

#### Scenario: The preferred ordinary Transit node fails before admission

- **WHEN** 评分最高的合格节点在新 TCP 或 UDP flow 准入前打开失败
- **THEN** Ingress 在有界尝试次数内按编译顺序尝试下一个合格节点，不选择 Direct，也不改变策略代次

### Requirement: Immutable decision generation

新连接必须（SHALL）在规则求值前捕获一个单调编号的快照代次，并在完整 Egress 和 Proxy 决策中使用该代次。现有 Session、Stream 和 Path 必须（SHALL）保留准入时的代次，除非硬撤销或 Egress 故障将其关闭。

#### Scenario: Publish configuration during route evaluation

- **WHEN** 一个连接正在评估路由时发布了新快照
- **THEN** 该连接仍使用已捕获的代次完成 Egress 和 Proxy 选择

### Requirement: Bounded replication policy

每个 Session SHALL 捕获其 Egress 选择的 TrafficPolicy，并在每个发送方向共享一个受协商 Session 上限约束的复制额度。该 Session 中所有 Stream 和 UDP Association 使用同一个不可变策略，不得被规则、flow 或业务类别覆盖。即使引用同一 TrafficPolicy，不同 Session 仍独立记账。

#### Scenario: Two flows use different Egress policies

- **WHEN** 两个 flow 选择具有不同 TrafficPolicy 的 Egress
- **THEN** 每个 flow 使用自身 Session 的策略和共享额度，不改变另一个 Session 的预算

#### Scenario: Two flows use different policies

- **WHEN** 两个 flow 选择具有不同 TrafficPolicy 的 Egress
- **THEN** 每个 flow 使用自身 Session 的策略和共享额度，不改变另一个 Session 的预算

#### Scenario: Unknown traffic class is configured

- **WHEN** 配置包含业务类别引用或已退休的类别策略字段
- **THEN** 验证拒绝该字段，不得使用默认或任意业务类别准入 flow

#### Scenario: Several flows share the replication allowance

- **WHEN** 一个 Session 中的 Stream 和 UDP Association 在同一发送方向并发请求可选副本
- **THEN** 合计记账保持在该方向的 Session 剩余额度内，必要控制预留优先，额度不随 flow 数量倍增

### Requirement: Atomic dynamic updates and draining

订阅和编译规则更新必须（SHALL）原子替换各自快照，刷新或编译失败时必须（SHALL）保留最近一次成功的快照。移除的 Transit Proxy 必须（SHALL）从新选择中排除，现有 Path 则继续排空或失败。

#### Scenario: Remove a Transit Proxy with an existing Path

- **WHEN** 订阅更新移除了一个承载现有 Path 的 Transit Proxy
- **THEN** 该节点进入排空状态并从新选择中排除，现有 Path 保留至排空完成或失败

### Requirement: Owned metadata mutations

管理员 label/tag 编辑必须（SHALL）只修改 `admin.*`，携带期望代次或显式授权的 force capability，并原子发布。运行时观测必须（SHALL）由运行时拥有；已撤销、已禁用或已断开等硬状态必须（SHALL）使节点不具备资格，不受 label 影响。

#### Scenario: Labels are present on a revoked node

- **WHEN** 节点的 label 满足选择器，但其运行时硬状态为已撤销
- **THEN** 选择器不能使该节点具备被选择的资格

### Requirement: Session maintenance per Egress

Ingress 必须（SHALL）为每个已配置 Egress 维护一个 Session 槽位，为后续 Stream 和 UDP Association 复用存活的空闲 Session，并在该 Egress 离线或发生硬故障时销毁 Session 及相关业务连接。

#### Scenario: Egress recovers after hard failure

- **WHEN** Egress 在先前 Session 已因硬故障销毁后重新上线
- **THEN** Ingress 创建新的 Session 和 Path 集合，不得恢复旧 Session

#### Scenario: Egress warms before a business match

- **WHEN** Ingress 启动时 Egress 绑定有效但还没有业务 flow 命中规则
- **THEN** Ingress 可以直接为该 Egress 建立初始 Path，不得为此构造目标、监听器、flow tag 或 geodata 匹配

#### Scenario: Only destination-specific routing rules exist

- **WHEN** Ingress 启动时 Egress 绑定有效但还没有业务 flow 命中规则
- **THEN** Ingress 可以直接为该 Egress 建立初始 Path，不得为此构造目标、监听器、flow tag 或 geodata 匹配

### Requirement: Ingress owns Path target decisions

Ingress SHALL 为每个 Session 根据所选 Egress 最小要求、合规 Transit 关系、聚合方向性 demand、Path 质量和 Egress 硬资源上限计算一个 Path target。路由身份和 flow 匹配不得定义额外 Path target，Egress 不提供或覆盖该决定。

#### Scenario: Egress has no Path recommendation

- **WHEN** Egress 只报告容量和准入状态而不提供 Path 数建议
- **THEN** Ingress 根据 Egress 配置和运行时观测计算一个有界 Session target

### Requirement: Egress Session Path eligibility

同一 Session 中的所有 Stream 和 UDP Association SHALL 共享由 Egress Transit 绑定、Path 认证就绪、健康及生命周期状态定义的 Path 资格。flow 的路由、目标、监听器或业务协议不得缩小 Transit 集合；Egress 协议能力和每个资源的流控仍必须执行。

#### Scenario: Warmup finds an ineligible Transit

- **WHEN** ready Transit adapter 不满足 Egress Transit 绑定
- **THEN** 该 adapter 从 Session 池排除，也不计入 Egress 最小要求

#### Scenario: TCP-only Transit carries Egress UDP

- **WHEN** Transit 提供合规字节流且所选 Egress 支持 UDP
- **THEN** UDP Association 可以使用共享 Path 池，不要求 Transit 自身支持原生 UDP

#### Scenario: One Transit carries several Paths

- **WHEN** 一个合规 Transit 关系承载多个独立认证的 Path
- **THEN** 该关系中非排空的 `ACTIVE` 或 `DEGRADED` Path 可以满足 Egress 最小要求，并共享该关系的配置权重

### Requirement: Resource failure does not fall through silently

当候选 Egress 在准入前以 `RESOURCE_LIMIT` 拒绝打开时，Ingress SHALL 在同一捕获代次中尝试其他合规候选；没有候选成功时返回类型化可重试资源错误，不得静默切换 direct 或无关 Proxy。

#### Scenario: All candidates are saturated

- **WHEN** 所有合规 Egress 候选在 Stream 准入前都返回资源限制
- **THEN** 本地 flow 失败并返回可重试资源错误，不使用未配置的 fallback

### Requirement: Session demand aggregation is bounded

Ingress SHALL 每个 Session 聚合上行和下行 demand，使用有界 counter 和低频窗口。路由身份、policy ID 和业务类别不得划分 Path demand。替换后的 Session 必须从空 counter 和观测开始；不得保留无界 per-flow 历史或将本地策略元数据发送给 Egress。

#### Scenario: A Session reconnects

- **WHEN** 新 SessionID 替换失败 Session
- **THEN** 新 Session 的 demand counter 和 EWMA 从空状态开始，旧值只能作为有界观测保留

#### Scenario: Many matching rules share an Egress

- **WHEN** 多条路由规则将流量发送到同一个 Egress
- **THEN** 这些流量进入同一 Session 的方向性 demand 窗口，不为每条规则分配独立 Path 要求或 demand 历史

### Requirement: Geodata predicates participate in ordered routing

EgressRule 和 ProxyRule 的 flow match SHALL 使用与其余路由决策相同的不可变 geodata 代次，对配置的 geosite 和 geoip 条件求值。这些条件 SHALL 遵循 [geodata 路由契约](../geodata-routing/spec.zh-CN.md)，不改变规则顺序或隐式回退行为，也不得在 Egress 内选择 Transit 关系。

#### Scenario: Hugging Face redirect uses the same Egress policy

- **WHEN** 显式代理 flow 的目标主机名属于已配置的 `huggingface` geosite 集合，包括 CDN 子域名
- **THEN** 匹配的 Egress 规则选择其配置的 Egress，flow 使用该 Egress 的共享 Path 池，无需逐一列出主机名

#### Scenario: GeoIP predicate receives an original destination address

- **WHEN** 以 IP 为目标的 TCP 或 UDP flow 命中具有匹配 geoip 集合的规则
- **THEN** 规则在选择 Egress、Proxy 或配置的回退前，使用已捕获代次对原始目标 IP 求值

#### Scenario: Geodata fact is unavailable

- **WHEN** 规则需要监听器未提供的主机名或 IP
- **THEN** 相应 geodata 条件不匹配，Ingress 继续执行配置的有序规则和回退，不得经其他 DNS 路由解析

## Detailed contract

本文档说明 Kubernetes 风格配置对象和求值顺序。规范性的字段、类型、默认值和验证契约见[版本化配置 schema](../configuration-schema/spec.zh-CN.md)；平台监听器和独立 DNS 见[平台与 DNS 规范](../platform-and-dns/spec.zh-CN.md)。配置使用 `apiVersion: pathchord.io/v1`、`kind`、`metadata` 和 `spec` 对象；多资源通常使用 `kind: List`。下文片段会明确标注是完整对象还是 `spec` 片段。配置适配器必须验证完整对象图，并在发布前将其转换为不可变类型化快照。运行时观测以只读 `status` 视图暴露，不能混入期望的 `spec`。管理操作使用[协议规范](../protocol/spec.zh-CN.md)定义的 JSON 封装；配置 YAML 不作为管理消息或 data Path 的线编码。

### 规范对象集合

配置可以是单个资源文件，也可以是递归载入的资源目录。Ingress 按命令行、环境变量、账号
默认值的优先级选择来源，并统一验证完整资源集合。目录发现、默认路径、限制和重载语义见
[配置来源](../configuration-schema/spec.zh-CN.md#配置来源)。

```yaml
apiVersion: pathchord.io/v1
kind: List
metadata:
  name: default
items:
  - apiVersion: pathchord.io/v1
    kind: Egress
    metadata:
      name: jp-1
      labels:
        region: jp
    spec:
      address: egress.example.net
      port: 443
      publicKey: <curve25519-public-key>
      capabilities:
        tcp: true
        udp: true
      statusRequirements:
        minUsablePaths: 2
      transit:
        require:
          labels:
            region: jp
        reject:
          tags: [quota-exhausted]
      trafficPolicyRef: jp-default
  - apiVersion: pathchord.io/v1
    kind: DNSPolicy
    metadata:
      name: default-dns
    spec:
      defaultRoute: local
      local:
        servers: [192.168.1.1:53]
  - apiVersion: pathchord.io/v1
    kind: FallbackPolicy
    metadata:
      name: default-fallback
    spec:
      action: reject
```

资源引用使用 `metadata.name`（例如 `egressRef: jp-1`），不再使用集合内部的 `id` 字段。控制面发布后生成 `metadata.generation` 和只读 `status`。

### 静态 Egress 拓扑

```yaml
apiVersion: pathchord.io/v1
kind: Egress
metadata:
  name: jp-1
  labels:
    region: jp
    role: egress
spec:
  address: egress.example.net
  port: 443
  publicKey: <curve25519-public-key>
  capabilities:
    tcp: true
    udp: true
```

### 动态 Transit Proxy 数据

节点协议、类型化 `options`、导入格式、凭据边界和提供方用量遵循
[Transit Proxy 契约](../transit-proxies/spec.zh-CN.md)。订阅格式与可执行节点协议是独立能力。

```yaml
apiVersion: pathchord.io/v1
kind: TransitProxy
metadata:
  name: provider-a-node-01
  labels:
    region: jp
    provider: provider-a
spec:
  source:
    type: clash
    subscriptionRef: provider-a
  protocol: socks5
  address: proxy.example.net
  port: 443
  tags: [gaming]
  weight: 100
```

以下是只读运行时 `status` 视图，不是管理员编写的期望 YAML：

```yaml
status:
  observed:
    connected: true
    rttMs: 42
    jitterMs: 5
    lossRate: 0.002
    effectiveCapacityBps: 180000000
  quota:
    remainingRatio: 0.42
    resetAt: 2026-12-01T00:00:00Z
  billing:
    trafficMultiplier: 2.0
```

### 有序 Egress 规则

```yaml
apiVersion: pathchord.io/v1
kind: EgressRule
metadata:
  name: jp-gaming
spec:
  order: 10
  match:
    flowTags: [gaming]
    protocols: [tcp, udp]
  egressRef: jp-1
```

首个条件匹配且选定 Egress 当前可用的规则胜出。Egress 可用性由运行时状态管理器预先计算。Geosite 和 geoip 条件使用 flow 的原始主机名或原始目标 IP 以及不可变的 [geodata 路由](../geodata-routing/spec.zh-CN.md)代次；事实缺失时不匹配，也不触发 DNS。规则只选择 Egress，不选择 Transit 关系、Path 子集、最小数量或 TrafficPolicy。

TrafficPolicy 可以定义多路径调度和复制预算：

```yaml
apiVersion: pathchord.io/v1
kind: TrafficPolicy
metadata:
  name: gaming-default
spec:
  scheduler: effectiveCapacityWeighted
  sessionReplicationBudgetBps: 2000000
  retransmissionReplication: allowed
```

`retransmissionReplication: disabled` 即使配置了正预算也请求零 Session 复制上限；`allowed` 请求策略 bit rate 除以 8 后向下取整的 wire bytes/s，Egress 可以接受更低值。零上限会在两个方向禁用可选业务和控制副本，但保留首份数据、必要控制和普通可靠重传。`TrafficPolicy.classes`、`classReplicationBudgetBps` 和规则级 `trafficClassRef` 已退休。

Session 预算在每个发送方向都是硬上限。同一 Session 的所有 Stream 和 UDP Association 共享 Egress 策略及其额度；路由身份不会划分 demand 或复制记账。Ingress 根据 Egress 最小要求、合规 Transit 关系、聚合方向性 demand、Path 观测和 Egress 全局安全上限计算一个有界 Session Path target。Egress 状态不提供或覆盖 Path 数建议。非排空的 `ACTIVE` 或 `DEGRADED` Path 才计入新业务准入；排空 Path 只完成已有工作。

### 普通 Proxy 规则与回退

选定节点允许 UDP 时，普通路由可以通过 direct、SOCKS5 和 SS 适配器执行原生 UDP。
Egress UDP Session 流量独立于 Transit 节点的原生 UDP 能力。不支持的普通 UDP 路由必须
按策略失败，不得绕过为 direct。

```yaml
apiVersion: pathchord.io/v1
kind: ProxyRule
metadata:
  name: direct-jp
spec:
  order: 30
  match:
    flowTags: [web]
  require:
    labels:
      region: jp
  select: any

---
apiVersion: pathchord.io/v1
kind: FallbackPolicy
metadata:
  name: default-fallback
spec:
  action: reject # or direct
```

选择顺序如下：

```text
ordered effective Egress rules
→ ordered ordinary Proxy rules
→ mandatory global fallback
```

### 监听器

完整监听器 schema（包括 Linux、Windows 和 FreeBSD 都必须支持的普通 HTTP 转发、HTTP CONNECT、
SOCKS4/4a/5 CONNECT 和 SOCKS5 UDP ASSOCIATE、Linux 透明模式和可选 TUN、Windows TUN
及 Windows 控制面的 system-proxy 开关、认证引用、来源限制
以及环路防护）见[平台与 DNS 规范](../platform-and-dns/spec.zh-CN.md)。
`spec.platform` 接受 `linux`、`windows`、`freebsd` 和 `any`；`any` 使用实际主机的平台矩阵。
FreeBSD 拒绝 `tproxy`、`redirect` 和 `tun`。
`spec.type: socks` 是规范名称 `socks5` 的输入别名；规范化输出使用 `socks5`，两个名称都接受
SOCKS4/4a/5。客户端持久连接上的 HTTP 请求分别独立认证和路由。完整的请求 framing、头字段过滤、
升级和版本专用认证契约见链接的平台规范。

```yaml
apiVersion: pathchord.io/v1
kind: Listener
metadata:
  name: lan-socks
spec:
  type: socks5
  bind: 0.0.0.0:1080
  allowedSources: [192.168.1.0/24]
  flowTags: [interactive]
  processMetadata:
    executable: true
  authentication:
    mode: required
    credentialsRef: lan-socks-users
```

规则可以使用 `listener_id`、来源地址、认证身份、进程元数据、协议和目标地址。

DNS 是独立策略。其 `local`、`transit`、`egress` 和 `blocked` 路由、解析器限制、缓存行为、主机名/候选地址
处理以及 Fake-IP 禁止规则在[平台与 DNS 规范](../platform-and-dns/spec.zh-CN.md)中规范定义。

`spec.type: mixed` 为前述 HTTP 和 SOCKS 契约绑定一个 TCP 端口。其 `protocols` 默认值为
`[tcp, udp]`，且必须包含 TCP。SOCKS5 UDP 使用协商的 relay 端点。协议识别和共用认证语义见
[mixed 分流](../platform-and-dns/spec.zh-CN.md#mixed-监听器分流)。

### 运行时快照

配置通过不可变快照进行评估：

```text
Static Egress topology
        +
Dynamic Transit Proxy snapshot
        +
Compiled rule snapshot
        +
Observed node and Egress state
        = effective runtime snapshot
```

每个快照都有一个单调递增的代次。新连接在规则评估开始时捕获一个代次，并在完整的 Egress 和 Proxy 选择过程中使用该快照。除非硬撤销或 Egress 故障将其关闭，否则现有 Session、Stream 和 Path 会继续使用准入时的代次。

规则评估只生成策略数据：

```yaml
decision:
  egressSelector: { labels: { region: jp } }
  proxySelector: { tags: [gaming] }
  trafficPolicyRef: gaming-default
```

规则不会嵌入具体的动态 Proxy 标识。调度器根据当前运行时状态解析选择器，并应用健康状态、容量、权重、配额元数据和 Path 策略。

### 标签和标记命名空间

内部节点模型使用带命名空间的属性：

```text
node.*      static identity and protocol attributes
admin.*     local administrator annotations
source.*    subscription source and imported metadata
observed.*  runtime measurements and derived state
quota.*     optional provider quota metadata
billing.*   optional provider billing metadata
```

本地管理员属性覆盖导入的来源属性。观测属性由运行时管理，不能被订阅数据覆盖。无论标签如何，已撤销、已禁用或已断开连接等运行时硬状态始终排除相应节点。

### 动态更新规则

- 静态 Egress 拓扑、Transit 绑定、公共 Path 要求以及引用的已解析 TrafficPolicy 的规范化值变化需要重启 Ingress。
- Transit Proxy 订阅更新以原子方式替换动态快照。
- 订阅刷新失败时保留上一次成功的快照。
- 已移除的 Transit Proxy 进入排空状态，并从新的选择中排除。
- 使用已移除 Transit Proxy 的现有 Path 会保留到排空完成或发生故障。
- 在 Egress 绑定不变时，Transit 成员变化可以动态发布，并排空被移除的关系。
- 已编译规则以原子方式替换；编译失败时保留上一个规则快照。
- 运行时观测独立于配置代次更新。

Ingress 管理员 label/tag 编辑属于控制面动态 mutation，只能更新 `admin.*` 命名空间，必须携带期望代次（或显式授权的 force capability），并原子发布新的快照。它们不能覆盖 `source.*`、`observed.*` 或 `quota.*` 值。

订阅是控制面资源，支持创建、删除、启用/禁用和手动刷新。刷新基于当前订阅 revision 执行；成功时发布一个新的动态代次，失败时保留最近一次成功的节点快照。删除会将订阅从后续刷新中移除，并排空仅由该来源导入的节点。每个 mutation 按 actor 和 request ID 幂等，并产生审计事件。

控制面为节点、Path、Session、Stream、目标连接、订阅和策略代次提供结构化快照及有界变更事件。这些视图是前端和 metrics endpoint 的数据源；日志不是权威状态存储。

### Session 维护

Ingress 为每个已配置 Egress 维护一个 Session 槽位，并可以在任何业务 flow 命中规则前根据 Egress 绑定预热该槽位。Session 捕获一个不可变 TrafficPolicy 和协商的复制上限，拥有一个公共 Path 池；空闲时由后续 Stream、UDP Association 以及经 Egress 路由的 DNS 复用。当 Session 低于公共可用 Path 最小值但仍有 ready Path 时，进入 degraded 并拒绝新业务；最后一个 ready Path 丢失或 Egress 发生硬故障时，销毁 Session 和相关业务连接。Egress 再次上线后，Ingress 创建新的 Session 和 Path 集合。
