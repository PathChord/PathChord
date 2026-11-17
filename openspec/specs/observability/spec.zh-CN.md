# Ingress 可观测性规范

[English](spec.md) | **简体中文**

## Purpose

定义结构化运行快照、指标、事件、新鲜度、资源边界和隐私规则，并使其独立于日志及经过认证的数据 Path 状态报告。

## Requirements

### Requirement: Detailed observability contract

观测服务 SHALL 遵循下文完整详细契约，包括快照 schema、指标字段与类型、事件注册表、单位、限制和健康语义。这些要求和场景补充这些定义，而不替代它们。

#### Scenario: Snapshot generation identity

- **WHEN** `GET /api/v1/metrics/snapshot` 返回快照
- **THEN** `snapshot_generation` 和 `observed_generation` 标识同一观测快照，并包含捕获时间和新鲜度。

### Requirement: Structured state independent of logs

运行时生产者 SHALL 通过有界提供器发布类型化的策略、Session、Path、Stream、目标连接、订阅、授权和监听器观测。禁用日志时，必需运行状态 SHALL 仍可查询；提供器 SHALL NOT 通过解析日志重建主要状态，也不得以数据 Path 的 `STATUS_REPORT` 替代本地观测。

#### Scenario: Logging is disabled

- **WHEN** 控制平面可用且日志被禁用
- **THEN** 必需生命周期状态、代次、观测、清理影响和资源限制条件仍可通过结构化查询获得。

### Requirement: Freshness and independent health states

快照 SHALL 区分新鲜测量、过期观测和不可用生产者。停止更新或过期的生产者 SHALL NOT 呈现为当前测得的零值。控制平面健康、运行时快照新鲜度和数据 Path 连通性 SHALL 保持为独立值；过期 Egress 报告 SHALL 阻止新准入，除非策略明确允许降级运行。

快照和经过认证的状态报告 SHALL 区分配置容量、有效容量、当前 wire 速率、容量可信度、服务状态和新准入状态。心跳仍健康时，过期 Egress 报告 SHALL 阻止新准入，同时保留已有工作。

#### Scenario: Status is stale but the Path is alive

- **WHEN** 心跳仍新鲜，但最新 Egress 状态超过本地新鲜度限制
- **THEN** 观测标记为 stale，拒绝新的业务准入，已有工作不能仅因报告过期而变成硬失败

#### Scenario: Egress report exceeds its freshness threshold

- **WHEN** 最新的经过认证 Egress 报告超过配置的新鲜度阈值
- **THEN** 其观测标记为 `stale`，不解释为零负载，且除非策略明确允许降级运行，否则不允许新准入。

### Requirement: Egress status is global and policy-free

Egress status SHALL 只描述跨所有配置 listener endpoint 聚合的全局 Egress 资源事实，不得包含路由规则、Egress Transit selector、TrafficPolicy identity、业务类别策略或 Ingress demand 元数据。Path-local 质量观测由 Ingress 从本地 Path 流量和控制反馈推导并拥有。

#### Scenario: Egress reports shared capacity

- **WHEN** 一个 Egress 服务多个 Ingress Session
- **THEN** status 报告聚合 wire 速率、容量、活跃目标连接、服务状态和全局准入状态，不暴露规则信息

#### Scenario: Egress has multiple listener endpoints

- **WHEN** 一个 Egress 通过多个配置 listener 为 Path 服务
- **THEN** 容量、目标连接数、授权影响和准入状态只作为 Egress 聚合事实报告一次，不按 listener 复制或分区

### Requirement: Local observations identify bounded Egress endpoints

授权的本地运行视图 SHALL 暴露有界的规范化 endpoint 清单及每条 Path 选择的 endpoint。endpoint 观测 SHALL 使用稳定有界的 ordinal 或 ID，保留 `configured`、`available`、`degraded`、`draining`、`failed` 或 `unknown` 之一及类型化原因和有界计数，不得成为无界指标标签。

#### Scenario: Inspect Egress endpoint inventory

- **WHEN** 授权运维人员查询 Egress 或 Session 资源
- **THEN** 响应报告配置 endpoint 数量及每个 endpoint 的有界状态，同时脱敏凭据和含秘密配置

#### Scenario: Inspect a Path's selected endpoint

- **WHEN** 授权运维人员查询 ready、draining 或 failed Path
- **THEN** 响应标识该 Path 使用的规范 endpoint ordinal，不声称使用了其他 endpoint

#### Scenario: An endpoint has repeated failures

- **WHEN** 一个 endpoint 累积有界连接或 listener 故障
- **THEN** 本地观测暴露类型化故障状态和有界计数，不改变 Egress 聚合容量，也不创建新 Egress identity

### Requirement: Endpoint details stay out of wire status and metric labels

endpoint 级本地观测 SHALL 不把原始 endpoint 主机名、端口或失败文本加入 Prometheus 标签集合或认证
`STATUS_REPORT` 布局。聚合 Egress 健康和容量继续使用现有有界字段。

#### Scenario: Prometheus metrics are rendered

- **WHEN** 指标端点渲染含多个 endpoint 的 Egress
- **THEN** 只输出有界的 Egress 聚合 gauge，不为每个 endpoint 主机名或端口创建无界标签值

#### Scenario: An authenticated peer receives Egress status

- **WHEN** Ingress 通过 Path 收到认证的 Egress 状态报告
- **THEN** 报告保持现有聚合 wire 布局，不泄露 Egress listener 清单

### Requirement: Capacity state is explicit

观测 SHALL 暴露配置容量、有效容量、当前 wire 速率以及 `unknown`、`provisional`、`measured` 或 `stale` 容量状态。unknown 不得序列化为零测量。

#### Scenario: Provisional scheduling is active

- **WHEN** Egress 只有配置硬上限而没有稳定的有效容量测量
- **THEN** 观测标记为 provisional，Ingress 可以把配置上限作为临时调度上限

### Requirement: Admission state is explicit

Egress 观测 SHALL 独立暴露 `admission_allowed` 和稳定、非敏感的 `admission_reason`。资源耗尽应表现为 degraded 且拒绝准入，而不是隐式 down。

#### Scenario: Target connection resources are exhausted

- **WHEN** 活跃连接和 pending reservation 达到 Egress 全局上限
- **THEN** 报告 `admission_allowed=false` 和资源限制原因，同时保留现有连接可查询

### Requirement: Directional Path observations remain Ingress-owned

Ingress SHALL 发布有界的上行/下行 Path 观测，并在 Egress 绑定下用于 Session 级调度和自动扩缩容；Egress status 不得复制这些 Path-local 观测成为第二权威来源。规则身份或业务类别不得划分公共 Path target。

#### Scenario: Path capacity is asymmetric

- **WHEN** 一条 Path 的上行和下行观测不同
- **THEN** Ingress 保留分离的方向值，并按需求较大方向计算物理 Path target

### Requirement: Session Path-pool observations

Session 观测 SHALL 标识所属 Egress、公共最小值、请求基线、受限后的有效基线、当前按 demand 得出的 target、实际 ready/usable 数量、类型化 target shortfall、合规 Transit 数量、不可变策略、方向性 demand 和复制额度。这些字段 SHALL 遵循现有授权、代次、基数和 unknown 规则，不为每条规则或业务类别分配观测。基线 shortfall 单独 SHALL NOT 改变健康状态或准入。

#### Scenario: Different routing rules use one Egress

- **WHEN** 多条路由规则选择的 flow 共享一个 Session
- **THEN** 查询暴露一个 Session 池 target、一个策略快照和聚合 demand，而不是规则级 target 或策略

#### Scenario: The minimum cannot be met

- **WHEN** 至少有一条认证 ready Path，但非排空可用 Path 低于最小值，或协商上限阻止达到最小值
- **THEN** 观测同时展示最小值、有界 target、ready count、usable count 和类型化准入/短缺原因；只要仍有 ready Path 且无其他硬故障，保持 degraded

#### Scenario: A measurement is not available

- **WHEN** Session 尚未接受复制协商，或聚合 demand 窗口没有权威样本
- **THEN** 对应字段返回 null 或显式 unknown，不伪造 measured zero

#### Scenario: Runtime ceiling clamps the baseline

- **WHEN** 请求基线为六、硬运行时上限为四且有四条 Path 可用
- **THEN** 请求基线仍为六，有效基线为四，target shortfall 为二，原因是 `runtime_limit`；基线 shortfall 单独不降级健康状态或拒绝准入

#### Scenario: Partial baseline recovery remains healthy

- **WHEN** 最小值为一、请求基线为三、有两条 Path 可用且有界后台恢复正在进行
- **THEN** 观测保留最小值、请求/有效基线和实际计数，报告 shortfall 为一及其主导类型化原因，且该 shortfall 单独不导致 degraded 或拒绝准入

#### Scenario: Load expansion does not change the configured baseline

- **WHEN** 请求和有效基线都是三，而当前方向性 demand 在运行时上限内需要五条 Path
- **THEN** 观测中的两个基线仍为三，`target_path_count` 表示当前有界 demand target 五

#### Scenario: A Session exceeds its idle baseline

- **WHEN** 请求基线为三且有五条 Path 可用
- **THEN** `target_shortfall` 为零、`target_shortfall_reason` 为 null，即使 demand 或渐进排空使实际数量暂时高于基线

#### Scenario: Several shortfall causes apply

- **WHEN** 基线 shortfall 同时存在多个已注册原因
- **THEN** 观测按已文档化的优先级选择确定的主导原因，不随 producer 或 adapter 改变

#### Scenario: Prometheus reads live Path-planning totals

- **WHEN** 已授权客户端读取 `/metrics`
- **THEN** 四个 Path-planning gauge 对同一份 live Session 快照求和，不加新标签，live 集合为空时为零，不包含已退役 Session 历史，也不表示生命周期计数器

### Requirement: Authorized bounded aggregate metrics

Web Gateway SHALL 以规定的 Prometheus 文本格式提供 `/metrics`，并与 JSON 指标查询使用相同的认证、Origin 和 `metrics:read` 边界。聚合指标 SHALL 使用有界标签域、声明其类型并区分当前 gauge 与历史 counter；缺失事实 SHALL NOT 被伪造。

#### Scenario: Prometheus reads the current snapshot

- **WHEN** 已授权客户端请求 `/metrics`
- **THEN** 响应读取同一规范快照，报告不带目标地址或用户控制标签的当前聚合 gauge，且不把这些 gauge 作为生命周期总量。

### Requirement: Ordered recoverable event streams

SSE 事件 SHALL 使用规范类型化事件注册表、进程内顺序、有界重放和客户端预算，并与快照查询使用相同授权和脱敏规则。`Last-Event-ID` SHALL 重放仍保留的事件，或在新增量前建立完整快照。

#### Scenario: Requested replay is outside the retained buffer

- **WHEN** SSE 客户端提供的 `Last-Event-ID` 无法从有界缓冲区重放
- **THEN** 服务在后续增量前发送完整快照事件。

### Requirement: Redaction before serialization

观测响应、事件和审计 SHALL 在序列化前应用 actor-capability 脱敏。它们 SHALL 排除私钥、握手材料、bearer 和订阅凭据、签名订阅 URL、密文及载荷字节；目标和进程详情 SHALL 遵循详细契约中的按角色隐私规则。

#### Scenario: Role lacks target-detail access

- **WHEN** 为不需要目标主机名或进程元数据的角色序列化观测
- **THEN** 这些详情在序列化前脱敏，而不是仅由前端代码隐藏。

## Detailed contract

Ingress 可观测性是本地控制平面的结构化查询和事件接口。日志只是补充；运维人员需要的
状态或指标不得仅存在于日志文本中。

### 与数据 Path 分离

`STATUS_REPORT` 是经过认证的数据 Path 消息。其线编码由[线协议 profile](../wire-profile/spec.zh-CN.md)
定义；语义字段是 Session 准入和调度所需的最少 Egress 信息。它不是管理 API、浏览器 API，
也不能替代本地指标。

可观测性提供器从策略、Session、Path、目标连接、订阅和授权组件读取类型化快照。它不得
解析日志来重建主要状态。运行时生产者通过一个有界提供器发布数据，该提供器独立于外部 API
适配器和日志后端。

### 快照模型

`GET /api/v1/metrics/snapshot` 返回包含控制面通用响应元数据的时点文档：

```json
{
  "api_version": "1",
  "request_id": "01JEXAMPLE",
  "observed_generation": {"scope": "observation", "value": 42},
  "snapshot_generation": 42,
  "captured_at": "2026-11-12T00:00:00Z",
  "freshness": "fresh",
  "ingress": {"state": "running", "uptime_seconds": 3600},
  "system_proxy": {"enabled": false, "listener_id": null, "platform_effect": "disabled"},
  "egress": {"configured": 3, "up": 2, "degraded": 1, "draining": 0, "down": 0},
  "egress_reports": [{
    "egress_id": "jp-1",
    "state": "up",
    "load_ratio": 0.42,
    "connection_utilization_ratio": 0.35,
    "bandwidth_utilization_ratio": 0.51,
    "active_sessions": 2,
    "active_streams": 12,
    "active_target_connections": 16,
    "configured_capacity_bps": 180000000,
    "effective_capacity_bps": 150000000,
    "current_wire_rate_bps": 92000000,
    "replication_allowance_bps": 12000000,
    "capacity_state": "measured",
    "admission_allowed": true,
    "admission_reason": "none",
    "status_report_age_ms": 120
  }],
  "sessions": {"configured": 3, "active": 2, "degraded": 1, "draining": 0},
  "paths": {"ready": 2, "draining": 0, "failed": 1},
  "streams": {"open": 12, "half_closed": 2, "reset": 1},
  "udp": {"associations": 4},
  "connections": {"targets": 16},
  "policy": {"generation": 18},
  "subscriptions": {"configured": 2, "healthy": 2}
}
```

`load_ratio`、利用率和丢包率是 `[0, 1]` 中的数值；容量字段是无符号比特率；计数
是非负整数；`status_report_age_ms` 是最新认证报告的年龄。报告超过配置的新鲜度阈值时，
相应 Egress 观测必须标记为 `stale`，不能当作当前零负载。名称表示单调性的计数器在单个
进程生命周期内必须单调；仪表值可以双向变化。本响应中的 `snapshot_generation` 与
`observed_generation` 标识同一个观测快照。
`system_proxy.platform_effect` 的值为 `disabled`、`applied` 或 `unsupported`；系统代理激活仅限 Windows，
因此 Linux 和 FreeBSD 的系统代理状态查询必须返回 `enabled: false` 和 `platform_effect: unsupported`。
其启用和关闭操作返回 `UNSUPPORTED_OPERATION`。

结构化下钻资源如下：

```text
GET /api/v1/nodes
GET /api/v1/sessions
GET /api/v1/sessions/{session_id}
GET /api/v1/connections
GET /api/v1/listeners
GET /api/v1/authorizations
GET /api/v1/system-proxy
GET /api/v1/metrics/paths
GET /api/v1/metrics/streams
```

每个查询返回类型化字段、稳定资源 ID 和通用响应元数据。列表使用控制面规范定义的有界
分页、过滤和排序合同。

### 节点与 Path 指标

节点视图组合保持所有权分离的字段：

```text
node.id, node.protocol, node.endpoint
source.subscription, source.imported_at
admin.labels, admin.tags
observed.connected, observed.state, observed.freshness
observed.rtt_ms, observed.jitter_ms, observed.loss_rate
observed.throughput_bps, observed.effective_capacity_bps
quota.remaining_ratio, quota.reset_at
```

每个 Path 视图暴露：

```text
path_id, session_id, egress_id, transit_proxy_id
state, ready_since, last_change_at, freshness
frame_sent, frame_received, frame_lost, frame_duplicate
rtt_ms, jitter_ms, loss_rate, reorder_count
throughput_bps, congestion_window, available_capacity_bps
control_pending, control_retransmissions
```

Path、Session 和 Transit Proxy ID 是基数有界的标签。原始 Transit 凭据、包含机密的代理 URL、
Noise 密钥和密文绝不作为指标字段。

### Session、Stream 与连接指标

Session 视图暴露：

```text
session_id, ingress_id, egress_id, state, freshness
admission_generation, created_at, last_change_at
ready_path_count, active_streams, active_udp_associations
control_pending, control_acked, control_retransmissions
close_reason, reconnect_attempts
minimum_usable_paths, target_path_count, usable_path_count
requested_target_usable_paths, effective_target_usable_paths
target_shortfall, target_shortfall_reason
eligible_transit_count, traffic_policy_id, traffic_policy_generation
demand_upstream_bps, demand_downstream_bps
replication_cap_bps, replication_upstream_used_bps, replication_downstream_used_bps
```

`requested_target_usable_paths` 是显式 target，或最小值加一的解析默认值，且在运行时截断前保留；它使用无符号 64 位值，以容纳最大 32 位最小值再加一。有效 target 受硬运行时 Path 上限限制，`target_path_count` 从有效基线和当前方向性 demand 重新计算，不保留历史峰值。live Session 的基线 shortfall 为 `max(requested_target_usable_paths - usable_path_count, 0)`；它不表示 demand target 的 shortfall，也不会单独影响健康或准入。没有 live Session 的已配置 Egress 不会生成虚假的认证 Session 行。

| 字段 | 类型与含义 |
| --- | --- |
| `minimum_usable_paths` | 配置的准入最小值 |
| `requested_target_usable_paths` | 截断前解析的请求基线，无符号 64 位 `1..=4294967296` |
| `effective_target_usable_paths` | 按当前硬运行时上限限制后的请求基线 |
| `target_path_count` | 当前 demand 得出的物理 Path target，受硬上限约束且重新计算，不保留历史峰值 |
| `ready_path_count` | 按生命周期语义认证完成的 ready Path 数 |
| `usable_path_count` | 合格、认证完成且非排空的 `ACTIVE` 或 `DEGRADED` Path 数 |
| `target_shortfall` | 不发生无符号下溢地计算 `max(requested_target_usable_paths - usable_path_count, 0)` |
| `target_shortfall_reason` | shortfall 为零时为 null，否则为下表中的主导原因 |

shortfall 大于零时，按以下顺序选择第一个适用原因：

| 优先级 | 原因 | 适用情况 |
| --- | --- | --- |
| 1 | `runtime_limit` | 当前硬 Path 上限低于请求基线 |
| 2 | `admission_blocked` | 独立的 Egress 准入约束阻止建立 Path |
| 3 | `no_eligible_transit` | Egress 绑定没有合格 Transit 候选 |
| 4 | `connect_failed` | 最近一次有界建连失败，包括其重试退避期 |
| 5 | `recovering` | shortfall 仍在且前述原因均不适用 |

Stream 视图暴露：

```text
stream_id, session_id, state, direction_state
target_kind, target_port, admitted_generation
bytes_sent, bytes_received, bytes_acked
reorder_buffer_bytes, receive_window, retransmissions
opened_at, closed_at, close_reason
```

目标连接视图暴露稳定的本地连接 ID、SessionID 和 StreamID、生命周期状态、字节计数器、
时间信息和规范化关闭原因。已授权的本地管理员可以获得原始主机名；原始凭据、包含机密的
URL 和载荷字节绝不得返回。

### 调度和 STATUS_REPORT 观测

观测提供器必须保留调度器所需的 Egress 字段：负载、连接利用率、带宽利用率、活跃
Session/Stream/目标连接数量、配置/有效/当前容量、容量状态、复制 allowance、准入状态/原因
和报告新鲜度。不得发布建议 Path 数量或 per-Ingress 配额。Ingress 的 Path 观测必须分别包含
上行和下行 RTT、抖动、丢包、乱序、吞吐量、有效容量和连接建立质量。

观测提供器还必须暴露一个 Session 池最小值、请求/有效基线、当前有界 demand target、ready/usable 数量、
baseline shortfall 及主导原因、合规关系、捕获的策略身份和代次、聚合上下行 demand 以及协商上限。
baseline shortfall 单独不得改变服务健康、Session 状态或准入权限；它对比请求基线与 usable Path，
与增大的负载 target 相互独立。上行用量来自本地发送方权威记账；下行用量在没有
权威 Session 级生产者时返回 null。全局 Egress replication allowance 不能替代它。调度器使用这些类型化字段，不能使用人类可读日志。报告过期时，除非策略明确允许降级运行，
否则 Egress 必须从新的准入中移除。质量下降时快速减少分配；恢复和缩容遵循状态机的排空及
稳定化规则。当 Path 因新增容量低于自身开销而被排除时，观测 API 必须暴露原因。

### 计数器、仪表值和直方图

Web Gateway 通过 `GET /metrics` 提供 Prometheus text format 0.0.4，使用
`Content-Type: text/plain; version=0.0.4; charset=utf-8`。它与 JSON metric 查询使用相同的
认证、Origin 限制和 `metrics:read` 授权，不是独立特权或未认证的监听器。响应读取同一份
规范观测快照，并提供以下聚合 gauge，不带用户控制或目标地址标签：

```text
pathchord_active_sessions
pathchord_ready_paths
pathchord_active_streams
pathchord_target_connections
pathchord_observed_nodes
pathchord_observed_connections
pathchord_observation_generation
pathchord_session_requested_target_usable_paths
pathchord_session_effective_target_usable_paths
pathchord_session_target_paths
pathchord_session_target_shortfall
```

这些值描述快照当前状态，不得表示为历史事件 counter 或生命周期总量；不得伪造缺失的快照
事实。高基数连接详情保留在经过授权的资源查询中。提供方 quota、到期时间和显式计费元数据
遵循[Transit Proxy 用量契约](../transit-proxies/spec.zh-CN.md#提供方用量元数据)。

四个 Path-planning gauge 对同一份当前 live Session 快照求和，排除 closed/retired Session 历史；live 集合为空时为零。它们表示当前状态而非生命周期计数器，不增加标签。Egress 不推荐 Path 数；Ingress 所有请求基线和当前 demand target。这些值属于本地观测，不会加入认证的 Egress `STATUS_REPORT`。


服务应提供以下指标族：

```text
pathchord_sessions_total
pathchord_session_closes_total{reason}
pathchord_paths_total{state}
pathchord_streams_total{state}
pathchord_udp_associations_total{state}
pathchord_target_connections_total{result}
pathchord_frames_total{direction, result}
pathchord_control_retransmissions_total{direction}
pathchord_bytes_total{direction}
pathchord_path_rtt_ms
pathchord_path_jitter_ms
pathchord_path_loss_ratio
pathchord_path_capacity_bps
pathchord_egress_load_ratio
pathchord_egress_connection_utilization_ratio
pathchord_egress_bandwidth_utilization_ratio
pathchord_stream_reorder_bytes
```

直方图必须在其适配器 schema 中定义单位和桶边界。每个指标族必须声明自己是计数器、仪表值
还是直方图。

### 基数控制

指标标签必须来自有界域。原始主机名、URL、RequestID、StreamID、进程命令行、错误消息或
任意管理员标记不得作为无界聚合标签。高基数详情应位于分页资源查询或采样事件中。

服务必须限制跟踪资源数量、每客户端事件积压、不同 label/tag 键和值，以及每资源历史记录。
达到上限时报告带原因的类型化 `degraded` 观测，只丢弃可选历史，绝不丢弃当前生命周期状态
或安全决策所需计数器。

### 事件和实时更新

选定的 REST 适配器通过 SSE 提供 `GET /api/v1/events`。每个事件包含 `id`、`type`、
`generation`、`emitted_at`、`resource_type`、`resource_id` 和类型化 `payload`。`generation`
使用与响应元数据相同的 `{scope,value}` 形式；资源载荷可以另外携带自身的 `revision`。

规范事件注册表为：

```text
metrics.snapshot
node.changed
path.changed
session.changed
stream.changed
connection.changed
subscription.changed
authorization.changed
system_proxy.changed
audit.notice
```

事件在每个 Ingress 进程内有序。`Last-Event-ID` 要么从有界缓冲区重放，要么先发送完整快照
事件再发送新增量。事件载荷使用与时点查询相同的授权和脱敏规则。`subscription.refresh` 不
是独立事件类型；刷新结果通过带类型化结果的 `subscription.changed` 表示。

### 脱敏与隐私

暴露 Web Gateway 前，可观测性层必须定义脱敏：

- 绝不暴露私钥、Noise 握手材料、持有者令牌、订阅凭据、签名订阅 URL、密文或载荷；
- 对不需要的角色脱敏目标主机名和进程元数据；
- 规范化错误，移除文件系统路径和对端任意文本；
- 审计记录不得包含完整请求正文和机密。

脱敏属于 actor capability 配置的一部分，并在序列化前执行，而不是只在前端代码中执行。

### 健康状态和新鲜度

每个快照报告捕获时间和新鲜度。停止更新的运行时生产者标记为 `stale` 或 `unavailable`，
绝不能呈现为当前零值。阈值属于配置，但 `stale` 必须与测量值为零区分开。

本地控制平面暴露相互独立的健康值：

```text
control_plane: running | degraded | stopped
runtime_snapshot: fresh | stale | unavailable
data_path_summary: connected | degraded | down
```

这些值不可互换。健康的控制平面可以报告 Egress down，而 Egress 已连接也不代表 Web Gateway
可用。

### 禁止仅依赖日志

以下内容必须作为结构化数据可查询：当前 Session、Path、Stream、UDP 和目标连接状态；策略、
订阅、观测和授权代次；节点 label/tag 和运行时观测；控制重传计数和队列；授权清理影响；
监听器清单以及系统代理选择/效果；
资源限制或生产者过期条件。禁用日志不得导致控制面 API 无法回答这些查询。
