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

Ingress 必须（SHALL）先评估有效 Egress 规则，再评估普通 Proxy 规则和必需的全局回退。有序 Egress 和 Transit 规则必须（SHALL）选择首个可准入的匹配，不支持的普通 UDP 路由必须（SHALL）按策略失败，不得绕过为 direct。

#### Scenario: No effective Egress route is selected

- **WHEN** 有序的有效 Egress 规则没有为新 flow 选出可准入路由
- **THEN** Ingress 按顺序评估普通 Proxy 规则，然后应用配置的全局回退

### Requirement: Immutable decision generation

新连接必须（SHALL）在规则求值前捕获一个单调编号的快照代次，并在完整 Egress 和 Proxy 决策中使用该代次。现有 Session、Stream 和 Path 必须（SHALL）保留准入时的代次，除非硬撤销或 Egress 故障将其关闭。

#### Scenario: Publish configuration during route evaluation

- **WHEN** 一个连接正在评估路由时发布了新快照
- **THEN** 该连接仍使用已捕获的代次完成 Egress 和 Proxy 选择

### Requirement: Bounded replication policy

Session 复制预算必须（SHALL）是硬上限；类别预算不得（SHALL NOT）超过 Session 的剩余预算。`trafficClassRef` 必须（SHALL）解析到所选 TrafficPolicy 中的类别；缺少引用时必须（SHALL）使用默认类别。

#### Scenario: Unknown traffic class is configured

- **WHEN** TransitRule 引用了其所选 TrafficPolicy 中不存在的类别
- **THEN** 验证必须拒绝该引用，不得以任意类别准入该 flow

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
  requirements:
    minUsablePaths: 1
```

首个条件匹配且 Egress 当前可用的规则胜出。Egress 可用性由运行时状态管理器预先计算。

### Egress 专用 Proxy 规则

```yaml
apiVersion: pathchord.io/v1
kind: TransitRule
metadata:
  name: jp-1-gaming
spec:
  order: 20
  egressRef: jp-1
  match:
    flowTags: [gaming]
  require:
    labels:
      region: jp
    capabilities: [udp]
  reject:
    tags: [quota-exhausted]
  weight: 100
  trafficPolicyRef: gaming-default
```

规则按顺序执行。首个匹配规则决定准入和关系的基础权重。

流量策略可以定义多路径调度和复制预算；`TransitRule.spec.trafficClassRef` 可以将准入 flow 分配到所选策略的类别，未知引用必须拒绝，缺少引用时使用默认类别：

```yaml
apiVersion: pathchord.io/v1
kind: TrafficPolicy
metadata:
  name: gaming-default
spec:
  scheduler: effectiveCapacityWeighted
  sessionReplicationBudgetBps: 2000000
  classReplicationBudgetBps: 1000000
  retransmissionReplication: allowed
```

Session 预算是硬性上限。流量类别预算可以减少该类别的分配量，但不能超过 Session 的剩余预算。

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

- 静态 Egress 拓扑变更需要重启 Ingress。
- Transit Proxy 订阅更新以原子方式替换动态快照。
- 订阅刷新失败时保留上一次成功的快照。
- 已移除的 Transit Proxy 进入排空状态，并从新的选择中排除。
- 使用已移除 Transit Proxy 的现有 Path 会保留到排空完成或发生故障。
- 已编译规则以原子方式替换；编译失败时保留上一个规则快照。
- 运行时观测独立于配置代次更新。

Ingress 管理员 label/tag 编辑属于控制面动态 mutation，只能更新 `admin.*` 命名空间，必须携带期望代次（或显式授权的 force capability），并原子发布新的快照。它们不能覆盖 `source.*`、`observed.*` 或 `quota.*` 值。

订阅是控制面资源，支持创建、删除、启用/禁用和手动刷新。刷新基于当前订阅 revision 执行；成功时发布一个新的动态代次，失败时保留最近一次成功的节点快照。删除会将订阅从后续刷新中移除，并排空仅由该来源导入的节点。每个 mutation 按 actor 和 request ID 幂等，并产生审计事件。

控制面为节点、Path、Session、Stream、目标连接、订阅和策略代次提供结构化快照及有界变更事件。这些视图是前端和 metrics endpoint 的数据源；日志不是权威状态存储。

### Session 维护

Ingress 为每个已配置的 Egress 维护一个 Session 槽位。Ingress 启动时，会尝试为当前有效状态为在线的 Egress 建立 Session。Session 在空闲期间保持存活，并由后续 Stream 和 UDP Association 复用。当 Egress 离线或进入硬故障状态时，其 Session 和所有相关业务连接都会被销毁。Egress 再次上线后，Ingress 会创建新的 Session 和 Path 集合。
