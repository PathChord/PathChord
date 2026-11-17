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

Ingress SHALL 为每个已配置 Egress 维护一个 Session 槽位；即使没有业务连接，也尽力维持其请求的可用 Path 基线；存活的空闲 Session 供后续 Stream 和 UDP Association 复用；当该 Egress 离线或发生硬故障时销毁 Session 及相关业务连接。只要达到公共最小值，基线缺口本身 SHALL NOT 使服务降级或拒绝准入。

#### Scenario: Egress recovers after hard failure

- **WHEN** Egress 在先前 Session 已因硬故障销毁后重新上线
- **THEN** Ingress 创建新的 Session 和 Path 集合，不得恢复旧 Session

#### Scenario: Egress warms before a business match

- **WHEN** Ingress 启动时 Egress 绑定有效但还没有业务 flow 命中规则
- **THEN** Ingress 可以直接为该 Egress 建立初始 Path，不得为此构造目标、监听器、flow tag 或 geodata 匹配

#### Scenario: Only destination-specific routing rules exist

- **WHEN** Ingress 启动时 Egress 绑定有效但还没有业务 flow 命中规则
- **THEN** Ingress 可以直接为该 Egress 建立初始 Path，不得为此构造目标、监听器、flow tag 或 geodata 匹配

#### Scenario: An idle Egress has an unmet usable-Path baseline

- **WHEN** 合格 Egress 没有业务连接，且可用 Path 数低于有效基线
- **THEN** Ingress 进行有界的后台建连，尽力达到该基线，无需等待路由命中

#### Scenario: The minimum is met while the baseline is short

- **WHEN** 公共最小值为 1，请求基线为 3，且仍有 2 条可用 Path
- **THEN** Ingress 继续尽力恢复基线，不会只因缺少第三条 Path 而降级或拒绝新业务

#### Detailed contract

Egress 的 `pathPool.minUsablePaths` 是基于数量的公共准入最小值。
`pathPool.targetUsablePaths` 是请求的稳态可用 Path 基线；省略时解析为 minimum 加一，
显式目标不再额外增加备用 Path。该基线属于 Ingress 侧 Egress 配置，不是 EgressService
建议值，也不是路由规则要求。

维护过程独立于监听器、业务规则命中、活动 Stream、UDP Association 和 DNS 流量，按运行时
上限尽力建立 Path，并遵循现有的退避、资格、授权、容量、增量开销和生命周期守卫。候选不可用
或建连失败不得导致无界重试、隐式 Direct 路由或切换到其他 Egress。

基线缺口表示期望状态，不得单独改变服务健康、准入许可或公共最小值。现有能力、授权、资源、
新鲜度和硬故障检查独立生效。低于公共最小值仍会拒绝新业务，但保留剩余 ready Path 上的现有
工作；最后一条 ready Path 丢失时退休 Session。

### Requirement: Ingress owns Path target decisions

Ingress SHALL 为每个 Session 根据 Egress 请求的可用 Path 基线和最小值、合规 Transit 关系、聚合方向性 demand、Path 质量及硬资源上限，计算一个有界的 Path target。路由身份和 flow 匹配不得定义额外 Path target，Egress 建议不得覆盖该决定。容量驱动扩张可以超过基线；需求降低后，Path SHALL 逐步排空并收缩至有效基线。

#### Scenario: Egress has no Path recommendation

- **WHEN** Egress 只报告容量和准入状态而不提供 Path 数建议
- **THEN** Ingress 根据 Egress 配置和运行时观测计算一个有界 Session target

#### Scenario: An omitted baseline preserves the default reserve

- **WHEN** Egress 设置 minimum 为 2 并省略 target
- **THEN** 应用运行时上限前，请求基线为 3

#### Scenario: An explicit baseline adds no hidden reserve

- **WHEN** Egress 显式设置 minimum 为 1、target 为 3
- **THEN** 请求基线恰好为 3，而不是 4

#### Scenario: Capacity demand exceeds the baseline

- **WHEN** 新鲜方向性需求需要 5 条可用 Path，请求基线为 3，且运行时上限允许 5
- **THEN** Ingress 可在现有扩容守卫下向 5 扩张，不把基线当成最大值

#### Scenario: An expanded Session becomes idle

- **WHEN** 扩大的 Session 需求降低，并且剩余容量持续超过稳定窗口
- **THEN** Ingress 在现有冷却和排空守卫下逐步向有效基线排空富余 Path，不保留历史需求峰值

#### Detailed contract

令 `R` 为 Egress 配置解析出的请求基线，`H` 为当前硬运行时 Path 上限。有效基线为
`B = min(R, H)`。当前物理 target 覆盖有效基线和上行/下行容量需求中的较大值，并受 `H` 限制。
target 根据当前观测重新计算，不得变成历史最大负载的单调记录。未知需求仍为 unknown，不得伪造成
测量零值或无界需求。

硬上限阻止达到请求基线时，必须保留并暴露请求值。运行时限幅不得改写配置或降低公共准入最小值。
若 `H` 无法满足最小值，沿用现有 minimum 缺口和准入语义。

计划性缩容必须保留有效基线与公共最小值，同时允许独立的硬故障和生命周期转换。缩容应缓慢、
使用滞回且先排空；不得只为达到空闲基线而中断已接受流量。扩张、排空和恢复共享同一合格 Session
Path 池及一份不可变 TrafficPolicy。

### Requirement: Egress Session Path eligibility

同一 Session 中的所有 Stream 和 UDP Association SHALL 共享由 Egress Transit 绑定、Path 认证就绪、健康及生命周期状态定义的 Path 资格。flow 的路由、目标、监听器或业务协议不得缩小 Transit 集合；Egress 协议能力和每个资源的流控仍必须执行。只有合格、已认证、非排空的可用 Path 才计入最小值和基线。

#### Scenario: Warmup finds an ineligible Transit

- **WHEN** ready Transit adapter 不满足 Egress Transit 绑定
- **THEN** 该 adapter 从 Session 池排除，也不计入 Egress 最小要求

#### Scenario: TCP-only Transit carries Egress UDP

- **WHEN** Transit 提供合规字节流且所选 Egress 支持 UDP
- **THEN** UDP Association 可以使用共享 Path 池，不要求 Transit 自身支持原生 UDP

#### Scenario: One Transit carries several Paths

- **WHEN** 一个合规 Transit 关系承载多个独立认证的 Path
- **THEN** 该关系中非排空的 `ACTIVE` 或 `DEGRADED` Path 可以满足 Egress 最小要求，并共享该关系的配置权重

#### Scenario: A draining Path does not satisfy the baseline

- **WHEN** Session 有两条合格、已认证且可用的 Path，另有一条 Path 正在排空
- **THEN** 最小值和基线的可用数量为 2，维护不得将排空 Path 用于支持另一条计划性排空

#### Detailed contract

准入、基线维护和计划缩容共用同一数量定义：处于 `ACTIVE` 或 `DEGRADED`、符合资格、已独立
认证且未排空的 ready Path 数。连接中、关闭、失败、不合格和排空的 Path SHALL NOT 满足任一门槛。
多条独立认证 Path 即使共享同一个 Transit 关系仍可计数；关系配置权重仍由其全部 Path 共享，不因
Path 数量而倍增。

旧 `statusRequirements.capabilities` 要求保留为原生配置中的
`admission.requiredCapabilities`。键名迁移 SHALL NOT 弱化能力检查、身份绑定或授权。

### Requirement: Resource failure does not fall through silently

当候选 Egress 在准入前以 `RESOURCE_LIMIT` 拒绝打开时，Ingress SHALL 在同一捕获代次中尝试其他合规候选；没有候选成功时返回类型化可重试资源错误，不得静默切换 direct 或无关 Proxy。

#### Scenario: All candidates are saturated

- **WHEN** 所有合规 Egress 候选在 Stream 准入前都返回资源限制
- **THEN** 本地 flow 失败并返回可重试资源错误，不使用未配置的 fallback

### Requirement: Session demand aggregation is bounded

Ingress SHALL 每个 Session 聚合上行和下行 demand，使用有界 counter 和低频窗口。路由身份、policy ID 和业务类别不得划分 Path demand。替换后的 Session 必须从空 counter 和观测开始，同时保留配置的 Egress 基线；不得保留无界 per-flow 历史或将本地策略元数据发送给 Egress。

#### Scenario: A Session reconnects

- **WHEN** 新 SessionID 替换失败 Session
- **THEN** 新 Session 的 demand counter 和 EWMA 从空状态开始，旧值只能作为有界观测保留

#### Scenario: Many matching rules share an Egress

- **WHEN** 多条路由规则将流量发送到同一个 Egress
- **THEN** 这些流量进入同一 Session 的方向性 demand 窗口，不为每条规则分配独立 Path 要求或 demand 历史

#### Scenario: A replacement Session restores its configured baseline

- **WHEN** 请求基线为 3、此前因需求扩张到 6 条 Path 的 Session 被替换
- **THEN** 新 Session 保留基线 3，应用当前硬上限，并从新 demand 状态开始，不继承旧 target 6

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

### Requirement: Egress Paths select endpoint candidates independently

对于一个配置的 Egress，Ingress SHALL 维护一个 Session Path 池，并在每条 Path 建立时选择一个规范化
endpoint。选择必须是确定且有界的，不得为每个 endpoint 创建独立 Session、策略或 Egress identity。

#### Scenario: One Session uses IPv4 and IPv6 endpoints

- **WHEN** Egress 拥有不同地址族的 ready endpoint，且 Session 需要多条 Path
- **THEN** 不同 Path 可以通过不同候选连接，同时仍属于同一个认证 Session Path 池

#### Scenario: Endpoint candidate order is reused

- **WHEN** Path 建立从有序 endpoint 列表开始
- **THEN** cursor 和有界回绕保留配置顺序，不会无限重试单个候选

### Requirement: Endpoint attempts use one static bounded sequence

每次 Egress Path 建立 SHALL 从该 Egress 的 endpoint 选择 cursor 开始，使用一个共享截止时间，按顺序循环访问规范化候选且每个候选最多一次。成功准入或候选耗尽后 SHALL 前移 cursor；endpoint failover 仅适用于 Path 准入前。

#### Scenario: A Path sequence reaches a successful candidate

- **WHEN** 一个候选连接成功且 Noise 准入达到 ready
- **THEN** Path 记录该候选并前移 cursor，后续 Stream 或 UDP 重试不会更改 Path 的传输连接

#### Scenario: A Path sequence is exhausted

- **WHEN** 所有候选均在 ready 前失败或超时
- **THEN** 操作返回现有类型化 Path 连接失败，不延长截止时间，也不绕过 Egress Transit binding 和 TrafficPolicy

### Requirement: Endpoint failure uses bounded pre-admission failover

Path 达到认证 ready 前，Ingress SHALL 在 Path 连接截止时间和有限尝试次数内尝试合规 Egress endpoint。
所有候选失败时，Path 尝试 SHALL 返回类型化连接失败，不得选择 Direct、无关 Egress 或普通 Proxy 路由。

#### Scenario: The preferred endpoint is unavailable

- **WHEN** 第一个 endpoint 在 Noise 准入完成前失败且仍有其他候选
- **THEN** Ingress 在同一个有界 Path 建立操作中尝试下一个候选

#### Scenario: All endpoint candidates fail

- **WHEN** 所有候选在 Path 准入前失败
- **THEN** Egress Path 尝试返回规范化 Egress/Transit 连接错误，不创建目标 Stream 或 UDP Association

### Requirement: Established Paths retain endpoint ownership

Path 达到 ready 后 SHALL 保留其 endpoint 候选，直到 Path 排空或失败。endpoint 故障只影响使用该候选的
Path，不得通过静默更换对端 socket 迁移已建立 Path。

#### Scenario: One endpoint fails while another Path is ready

- **WHEN** 使用一个 endpoint 的 Path 传输失败，而使用另一个 endpoint 的非排空 ready Path 仍存在
- **THEN** Session 按现有最小值保持可用，只有失败 Path 进入恢复或替换

#### Scenario: A Path endpoint is drained

- **WHEN** 管理员在下一份静态配置中移除 endpoint，或对该 endpoint 发起管理排空
- **THEN** 新 Path 排除该 endpoint，现有 Path 按正常 Path 排空截止时间再关闭

### Requirement: Hostname candidates preserve family and port semantics

Egress endpoint 主机名 SHALL 由所选 Transit Adapter 按配置端口解析；同一主机名的 IPv4/IPv6 结果只是
该端口的候选。不同端口必须使用不同 endpoint 表达，不能从 DNS 地址记录推断端口。

#### Scenario: One hostname returns A and AAAA records

- **WHEN** 一个主机名候选在 7443 端口返回 IPv4 和 IPv6 地址
- **THEN** 适配器可以在有界尝试中选择任一地址族，Egress identity 保持不变

#### Scenario: IPv4 and IPv6 use different ports

- **WHEN** IPv4 使用 7443 端口而 IPv6 使用 8443 端口
- **THEN** Ingress 将它们视为两个显式候选，Path 可以独立选择任一候选

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
      endpoints:
        - host: egress-v4.example.net
          port: 7443
        - host: egress-v6.example.net
          port: 8443
        - host: egress.example.net
          port: 443
      publicKey: <curve25519-public-key>
      capabilities:
        tcp: true
        udp: true
      pathPool:
        minUsablePaths: 2
        targetUsablePaths: 3
      admission:
        requiredCapabilities: [tcp]
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
  endpoints:
    - host: egress-v4.example.net
      port: 7443
    - host: egress-v6.example.net
      port: 8443
    - host: egress.example.net
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
  host: proxy.example.net
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

Session 预算在每个发送方向都是硬上限。同一 Session 的所有 Stream 和 UDP Association 共享 Egress 策略及其额度；路由身份不会划分 demand 或复制记账。Ingress 根据有效配置基线和当前上行/下行容量需求，在硬运行时上限内计算 Session Path target。负载需求可使 target 超过基线；缩容必须渐进并遵循排空守卫。Egress 状态不提供或覆盖 Path 数建议。只有合格且非排空的 `ACTIVE` 或 `DEGRADED` Path 才计入准入和基线；排空 Path 只完成已有工作。只要达到公共准入最小值，基线缺口本身不会使服务降级或拒绝业务。

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

- 静态 Egress 拓扑、Path-pool 数量、准入要求、Transit 绑定以及引用的已解析 TrafficPolicy 的规范化值变化需要重启 Ingress。
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

Ingress 为每个已配置 Egress 维护一个 Session 槽位，可以在任何业务 flow 命中规则前预热或补充其绑定对应的 Path。Session 捕获一个不可变 TrafficPolicy 和协商的复制上限，拥有一个公共 Path 池；空闲时由后续 Stream、UDP Association 以及经 Egress 路由的 DNS 复用。Ingress 尽力维持有效基线（请求目标与硬运行时上限中的较小值）；请求目标默认为公共最小值加一，显式目标不额外增加备用 Path。只要达到公共最小值，基线缺口本身不会使服务降级或拒绝新业务。低于最小值时，若仍有 ready Path，则拒绝新业务；最后一个 ready Path 丢失或 Egress 发生硬故障时，销毁 Session 和相关业务连接。Egress 再次上线后，Ingress 创建新的 Session 和 Path 集合，并恢复配置基线，不继承旧的负载扩张目标。

容量驱动的扩张可以超过基线。需求降低后，Ingress 根据当前方向需求重算目标，并在容量、生命周期和排空守卫下逐步将多余 Path 收缩到有效基线。基线补充有界运行，且不依赖业务路由规则命中。
