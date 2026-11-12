# PathChord 配置规范

[English](configuration.md) | **简体中文**

本文档定义下列 YAML 示例所表示的配置模型。配置适配器验证人工编写的 YAML，并在发布前将其转换为类型化配置快照。这些片段定义模型语义，但不构成完整的序列化 schema；版本化 schema 定义可接受字段、默认值、未知字段处理和验证规则。运行时观测与管理员配置分开维护。管理操作使用[协议规范](protocol.zh-CN.md)定义的 JSON 封装；配置 YAML 不作为管理消息或 data Path 的线编码。

## 静态 Egress 拓扑

```yaml
egresses:
  - id: jp-1
    address: egress.example.net
    port: 443
    public_key: <curve25519-public-key>
    labels:
      region: jp
      role: egress
    capabilities:
      tcp: true
      udp: true
```

## 动态 Transit Proxy 数据

```yaml
transit_proxies:
  - id: provider-a-node-01
    source:
      type: clash
      subscription: provider-a
    protocol: vless
    address: proxy.example.net
    port: 443
    labels:
      region: jp
      provider: provider-a
    tags: [gaming]
    weight: 100
```

运行时字段单独维护：

```yaml
observed:
  connected: true
  rtt_ms: 42
  jitter_ms: 5
  loss_rate: 0.002
  effective_capacity_bps: 180000000
quota:
  remaining_ratio: 0.42
  reset_at: 2026-12-01T00:00:00Z
billing:
  traffic_multiplier: 2.0
```

## 有序 Egress 规则

```yaml
egress_rules:
  - id: jp-gaming
    match:
      flow_tags: [gaming]
      protocol: [tcp, udp]
    egress: jp-1
    requirements:
      min_usable_paths: 1
```

首个条件匹配且 Egress 当前可用的规则胜出。Egress 可用性由运行时状态管理器预先计算。

## Egress 专用 Proxy 规则

```yaml
transit_rules:
  - id: jp-1-gaming
    egress: jp-1
    match:
      flow_tags: [gaming]
    require:
      labels:
        region: jp
      capabilities: [udp]
    reject:
      tags: [quota-exhausted]
    weight: 100
    traffic_policy: gaming-default
```

规则按顺序执行。首个匹配规则决定准入和关系的基础权重。

流量策略可以定义多路径调度和复制预算：

```yaml
traffic_policies:
  gaming-default:
    scheduler: effective_capacity_weighted
    session_replication_budget_bps: 2000000
    class_replication_budget_bps: 1000000
    retransmission_replication: allowed
```

Session 预算是硬性上限。流量类别预算可以减少该类别的分配量，但不能超过 Session 的剩余预算。

## 普通 Proxy 规则与回退

```yaml
proxy_rules:
  - id: direct-jp
    match:
      flow_tags: [web]
    require:
      labels:
        region: jp
    select: any

fallback:
  action: reject # or direct
```

选择顺序如下：

```text
ordered effective Egress rules
→ ordered ordinary Proxy rules
→ mandatory global fallback
```

## 监听器

```yaml
listeners:
  - id: lan-socks
    type: socks5
    bind: 0.0.0.0:1080
    allowed_sources: [192.168.1.0/24]
    authentication: required

  - id: local-http
    type: http
    bind: 127.0.0.1:8080
    authentication: disabled
```

规则可以使用 `listener_id`、来源地址、认证身份、进程元数据、协议和目标地址。

## 运行时快照

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
  egress_selector: { labels: { region: jp } }
  proxy_selector: { tags: [gaming] }
  traffic_policy: gaming-default
```

规则不会嵌入具体的动态 Proxy 标识。调度器根据当前运行时状态解析选择器，并应用健康状态、容量、权重、配额元数据和 Path 策略。

## 标签和标记命名空间

内部节点模型使用带命名空间的属性：

```text
node.*      static identity and protocol attributes
admin.*     local administrator annotations
source.*    subscription source and imported metadata
observed.*  runtime measurements and derived state
quota.*     optional provider quota metadata
```

本地管理员属性覆盖导入的来源属性。观测属性由运行时管理，不能被订阅数据覆盖。无论标签如何，已撤销、已禁用或已断开连接等运行时硬状态始终排除相应节点。

## 动态更新规则

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

## Session 维护

Ingress 为每个已配置的 Egress 维护一个 Session 槽位。Ingress 启动时，会尝试为当前有效状态为在线的 Egress 建立 Session。Session 在空闲期间保持存活，并由后续 Stream 和 UDP Association 复用。当 Egress 离线或进入硬故障状态时，其 Session 和所有相关业务连接都会被销毁。Egress 再次上线后，Ingress 会创建新的 Session 和 Path 集合。
