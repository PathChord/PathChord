# PathChord 状态机规范

[English](spec.md) | **简体中文**

## Purpose

定义 Egress 关系、Path、Session、TCP Stream、UDP Association、订阅、授权和系统代理状态的可观察生命周期、转换所有权、准入守卫、资源清理、重试及调度控制。

## Requirements

### Requirement: Complete lifecycle and admission contract

生命周期所有者 SHALL 执行[详细契约](#detailed-contract)中的全部状态图、守卫、动作、失败原因、定时器和重试规则。Path SHALL 仅在完成认证、身份/授权检查、能力协商和限制协商后成为 ready；内部连接中或已关闭的记录 SHALL NOT 暴露为可用资源。

#### Scenario: Path has not completed admission

- **WHEN** Path 尚未完成 `PATH_READY` 要求的检查和协商
- **THEN** 不将它报告为 ready，也不允许其承载业务流量

### Requirement: Draining and terminal Session cleanup

排空中的 Path 和 Session SHALL 拒绝新业务工作，并按其截止时间保留已有工作。最后一条 ready Path 丢失、整个 Egress runtime 重启或硬故障、授权失败时 SHALL 关闭受影响的 Session 资源并废弃旧 SessionID。单个配置 Egress endpoint 故障或排空时，只影响使用该 endpoint 的 Path，只要仍有其他 endpoint 支持的 ready Path 就保持关系可用。

#### Scenario: Only draining Paths remain

- **WHEN** Session 仍包含 ready 的 draining Path，但没有 `ACTIVE` 或 `DEGRADED` Path
- **THEN** 已有工作可以完成，但新的 Stream 和 UDP Association 被拒绝

#### Scenario: Last ready Path disappears

- **WHEN** Session 失去最后一条 ready Path
- **THEN** 关闭业务资源、废弃 SessionID，后续任何 Session 都使用新 SessionID

#### Scenario: One configured endpoint fails

- **WHEN** 一个 listener 或传输 endpoint 故障，但另一个 endpoint 支持的 Path 仍为 `ACTIVE` 或 `DEGRADED`
- **THEN** 只有使用故障 endpoint 的 Path 进入失败或替换，Session 保持存活，健康 Path 上的已有业务继续保留

#### Scenario: The whole Egress runtime restarts

- **WHEN** 所有配置的 Egress listener 及共享 runtime 重启或失去授权状态
- **THEN** 受影响 Session 按现有端点重启规则关闭，恢复时创建新的 SessionID

### Requirement: Stream and association resource ownership

打开中的 TCP Stream SHALL 使用一个幂等 RequestID，并最多创建一条目标连接；FIN SHALL 排在前置字节之后，RST SHALL 丢弃待处理字节。已打开的 UDP Association SHALL 恰好拥有一个 Egress 端套接字上下文，保留数据报边界，并在规定的关闭转换中释放套接字。

#### Scenario: UDP drain deadline is reached

- **WHEN** 排空中的 UDP Association 到达截止时间
- **THEN** 在截止时间关闭套接字，不等待尚未完成的排队数据报，且不再准入新数据报

### Requirement: Atomic subscription refresh and failure retention

订阅刷新 SHALL 针对当前 revision 求值，并原子发布成功的动态代次。刷新失败时 SHALL 保留最近一次成功的节点快照、记录类型化失败并使用有界退避；禁用或删除的来源 SHALL 遵循规定的刷新和排空规则。

#### Scenario: Subscription refresh fails

- **WHEN** 已启用订阅的当前刷新失败
- **THEN** 最近一次成功的快照保持可用，记录类型化失败，并按有界退避重试

### Requirement: Authorization transitions affect all matching resources

禁用和撤销的授权记录 SHALL 立即拒绝新握手并终止所有匹配的存活资源。撤销 SHALL 是该记录身份的终态；重新启用禁用记录时 SHALL 使用新代次，不能复活旧 Session。

#### Scenario: Disabled authorization is re-enabled

- **WHEN** 禁用的授权通过新代次变为 `ENABLED`
- **THEN** 可以准入新 Session，但不恢复旧 SessionID

### Requirement: Platform scoped system-proxy restoration

系统代理所有者 SHALL 验证 Windows Listener，保存精确的旧设置，使重复选择保持幂等，并在失败时保留恢复状态。Linux 和 FreeBSD 上的 mutation SHALL 返回 `UNSUPPORTED_OPERATION`，其状态查询报告不支持的平台效果。

#### Scenario: Windows proxy restoration fails

- **WHEN** 禁用已应用的 Windows 系统代理时无法恢复保存的值
- **THEN** 开关进入 `FAILED`，保留保存的值，且不报告 `DISABLED`

### Requirement: Bounded scheduling and autoscaling guards

调度 SHALL 保留一个不可变的 Egress Session 策略快照、有界公平服务、关系及方向性质量权重和按发送方共享的复制记账。自动扩缩容 SHALL 使用一个 Session Path target，并执行规定的滞回、公共最小值保留、排空动作、新增容量排除及计数器重置规则。

#### Scenario: Autoscaler scales a Path in

- **WHEN** 容量富余持续达到配置的非零缩容窗口，移除所有选中的排空候选后仍保留合规可用 Path 且满足 Egress 最小值
- **THEN** 选中的 Path 在移除前进入 `DRAINING`，并保留规定的滞回和预算守卫

#### Scenario: A draining Path cannot justify another drain

- **WHEN** 公共最小值为 2、已有 2 条可用 Path，且另有 1 条 Path 正在排空
- **THEN** owner 拒绝排空任一可用 Path，并在检查最小值时扣除并发选中的排空候选

### Requirement: One owner validates lifecycle transitions

一个 Session/Path lifecycle owner SHALL 校验每个 Path 和 Session 转换、更新状态并发出转换事件。协议处理器、调度器和控制适配器 SHALL 通过该 owner 请求转换，不得直接修改生命周期状态。

#### Scenario: A peer requests an invalid transition

- **WHEN** 对端消息试图将 draining Session 恢复为 active
- **THEN** owner 拒绝请求、保持当前状态，并发出类型化诊断

### Requirement: Service state and admission state are independent

Egress service state SHALL 表示生命周期和健康；独立的 admission state SHALL 表示是否接受新的目标连接。`degraded` 可以允许或拒绝新工作；`draining` 和 `down` 必须拒绝，`down` 还必须关闭相关资源。

#### Scenario: Capacity is exhausted while a Session remains healthy

- **WHEN** Egress 有 ready Path 但没有目标连接余量
- **THEN** 报告 `service_state=degraded`、`admission_allowed=false`，保留已有工作，并对新打开返回类型化资源限制结果

### Requirement: Reconnected Sessions start fresh

Session 因 Egress 故障、Path 丢失、授权失败或协议信任失败关闭时，替代 Session SHALL 使用新的 SessionID，捕获配置的 Egress 策略，并重置聚合 demand、Path target、复制用量和生命周期观测。

#### Scenario: Egress recovers after Session closure

- **WHEN** Ingress 重新连接同一配置 Egress
- **THEN** 新 Session 从 Egress 最小值和新鲜观测开始，不复用旧 Session 状态

### Requirement: Egress Session Path pool lifecycle

Ingress Session owner SHALL 为一个 Egress 关系维护一个认证的公共 Path 池，不依赖命中的路由规则。扩展和排空必须保持公共资格及硬安全上限。低于公共最小值时拒绝新业务但不能仅因短缺关闭已有工作；最后一条 ready Path 丢失时废弃 Session。

#### Scenario: Ready Paths fall below the configured minimum

- **WHEN** Egress 要求两条可用 Path，但故障后只剩一条认证且非排空的 ready Path
- **THEN** Session 进入 degraded，拒绝新的 Stream 和 UDP Association，已有工作可继续使用剩余 Path，并进行有界恢复尝试

#### Scenario: Only draining Paths remain

- **WHEN** Session 只剩认证的 draining Path
- **THEN** 已有工作遵循排空截止时间，新业务被拒绝，排空 Path 不计入新准入最小值

#### Scenario: Last ready Path is lost

- **WHEN** 公共池最后一条 ready Path 失败
- **THEN** 关闭所有相关业务资源，废弃的 SessionID 不得复用

### Requirement: Endpoint failure preserves shared lifecycle ownership

endpoint 级 Path 故障 SHALL 由现有 Session/Path lifecycle owner 处理。endpoint 选择、listener accept loop 和 endpoint 健康观测 SHALL 通过 owner 请求转换，不得直接修改 Session 或 Path 状态。替代 Path SHALL 使用新的 PathID，整个 Egress runtime 重启仍属于 Session 重启。

#### Scenario: A failed endpoint is replaced

- **WHEN** 有界恢复通过另一个配置 endpoint 建立替代 Path
- **THEN** lifecycle owner 按当前 Session 状态记录新 Path，不复用已废弃的 PathID

#### Scenario: All endpoint-backed Paths are draining

- **WHEN** 每一条 ready Path 都关联到正在排空或已失败的 endpoint
- **THEN** Session 拒绝新业务准入并遵循正常排空或最后 ready Path 转换，不把仅配置存在的 endpoint 当作 ready

### Requirement: Directional Path capacity drives scaling

Ingress SHALL 分别维护上行和下行 Path 观测。双向 Session target SHALL 覆盖两个方向需求中较大的一个，各方向调度使用自身输入。

#### Scenario: Downstream is the bottleneck

- **WHEN** 上行需求适合一条 Path 而下行需求需要三条
- **THEN** 物理 Path target 至少为三，且上下行调度分别使用各自观测

### Requirement: Autoscaling remains bounded and low-frequency

Path 健康采样和 Session demand 聚合 SHALL 使用有界 counter 和低频窗口。自动扩缩容 SHALL 对扩容和缩容使用独立滞回，计划缩容保留 Egress 公共最小值，并排除新增容量低于调度开销的候选。

#### Scenario: Unknown capacity at startup

- **WHEN** Session 尚未收集足够新鲜的有效容量测量
- **THEN** Ingress 使用配置 Egress 上限作为临时调度上限，标记 provisional，不创建无界额外 Path

## Detailed contract

本文档定义可观察的生命周期状态，以及使状态转换有效的守卫和动作。管理器MAY 在内部
保留连接中或已关闭阶段的记录，但MUST NOT 将该记录暴露为可用的 Session、Path、Stream 或
Association。

本文档中的 **MUST**、**MUST NOT**、**SHOULD**、**SHOULD NOT** 和 **MAY** 按照
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) 与 [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
解释；只有英文大写形式具有规范性效力。

### 共享规则

`PATH_READY` 是协议准入点。只有在 Noise 身份认证、身份/授权检查、能力协商和限制协商
全部成功后，Path 才是 **ready**。`ACTIVE` 和 `DEGRADED` Path 属于 ready 状态；
`DRAINING` 仍经过认证，MAY 完成已有工作，但不能准入新的业务工作。

协议层面的存活 Session MUST 至少包含一条 ready Path，包括 draining Path。只有包含至少一条
`ACTIVE` 或 `DEGRADED` Path 的 Session 才能准入新的 Stream 或 UDP Association。仅有 draining
Path 的 Session 属于关闭中的 Session，MUST 拒绝新的业务操作。

每个转换只有一个拥有者：Ingress Session manager 拥有 Session 和 Path 的准入；Egress 拥有
目标连接和授权影响；Stream 或 Association 所有者拥有字节/数据报完成。对端消息MAY 请求
转换，但拥有者MUST 先验证守卫。

### Egress 关系和服务状态

关系状态图如下：

```text
CONFIGURED → CONNECTING → CONNECTED
CONNECTING → DOWN
CONNECTED → DEGRADED
DEGRADED → CONNECTED
CONNECTED/DEGRADED → DRAINING
CONNECTED/DEGRADED/DRAINING → DOWN
DOWN → CONNECTING
```

`CONNECTED` 表示 `connected=true`：至少存在一条经过身份认证、双向连通且 ready 的 Path。
对外报告的服务状态按下表推导：

| 服务状态 | 守卫 |
|---|---|
| `up` | `connected=true`、未排空且满足当前所有准入要求 |
| `degraded` | `connected=true`、未排空，但容量、Path 数量或能力要求未满足 |
| `draining` | 管理排空生效；拒绝新流并完成已有工作 |
| `down` | 没有 ready Path，或处于管理员关闭/授权失败状态 |

`CONNECTED` 和 `DEGRADED` 是关系管理器状态；`up` 和 `degraded` 是服务状态值。`DOWN`
MUST 关闭相关 Session、Stream、UDP Association、本地连接和 Egress 目标连接。配置和授权允许
时，管理器MAY 使用有界指数退避重试 `DOWN → CONNECTING`。

Egress authored resource limit 只有全局 aggregate wire capacity 和全局入站目标连接容量。
pending target dial 在拨号前预留 slot，并在成功、失败、超时或 reset 时释放。资源耗尽报告
degraded、拒绝准入和稳定的 `RESOURCE_LIMIT`/connection-limit 原因，不关闭已有工作。

### Path

```text
DISCOVERED → PROBING → ACTIVE
PROBING → FAILED
ACTIVE ↔ DEGRADED
ACTIVE/DEGRADED → DRAINING → CLOSED
ACTIVE/DEGRADED → FAILED → CLOSED
PROBING/FAILED → CLOSED
```

`ACTIVE` 表示 Path 已达到 `PATH_READY` 并可承载新的业务流量。`DEGRADED` 仍是 ready，但因
质量或容量低于策略而减少分配。`DRAINING` 停止新的准入，在确认或排空截止时间前保留已有
工作，随后进入 `CLOSED`。身份认证失败、nonce/replay 违规或授权 disable/revoke 都是
`FAILED` 转换，MUST NOT 单独改写为目标错误。

Path 所有者MUST 为每次状态转换发出变更事件。质量采样MAY 导致 `ACTIVE ↔ DEGRADED`；恢复
分配MUST 由调度器稳定化。达到排空截止时间或发生传输故障时，即使仍有未完成工作也MUST 关闭。

### Session

```text
CONFIGURED → CONNECTING → ACTIVE
ACTIVE ↔ DEGRADED
ACTIVE/DEGRADED → DRAINING
CONNECTING → CLOSED
CONFIGURED → CLOSED
ACTIVE/DEGRADED/DRAINING → CLOSED
```

`ACTIVE` 要求至少一条 `ACTIVE` 或 `DEGRADED` Path，并允许新的业务操作。`DEGRADED` 至少有
一条 ready Path，但当前容量、Path 数量或能力要求未满足。`DRAINING` 拒绝新的 Stream 和
Association，并等待已有工作；MAY 包含 ready 的 draining Path。最后一条 ready Path 丢失时，
协议 Session 永久关闭，关闭所有业务资源，废弃 SessionID；若允许，管理器MAY 使用新的
SessionID 创建新的 `CONFIGURED` 记录。

端点重启、Egress 硬故障或授权 disable/revoke 会关闭 Session 和所有相关目标资源。端点重启
和授权失败MUST NOT 自动恢复旧 SessionID。心跳及其确认属于 Path 本地消息。Session 控制重传
使用 ready 且符合策略的 Path，并由 Session 控制序列去重。

认证的 future Stream ACK 若覆盖本地已发送区间集合之外的字节，属于 Session 信任失败，而不是
单独的 Path 故障。owner 关闭全部 Path 和业务资源、废弃 SessionID，并允许使用新 SessionID
进行有界恢复；窗口内重复信任失败会打开断路器，但不会自动撤销授权。

### TCP Stream

```text
NEW → OPENING → OPEN
NEW/OPENING → CLOSED
NEW/OPENING → RESET
OPEN → HALF_CLOSED_LOCAL
OPEN → HALF_CLOSED_REMOTE
HALF_CLOSED_LOCAL/HALF_CLOSED_REMOTE → CLOSED
HALF_CLOSED_LOCAL/HALF_CLOSED_REMOTE → RESET
OPEN → RESET
```

`OPENING` 拥有一个幂等 RequestID，最多创建一条目标连接。目标拨号成功后进入 `OPEN`；策略、
Egress 或目标失败进入带规范化错误的 `RESET` 或 `CLOSED`。FIN 在方向上的前置字节之后有序
到达，只改变该方向；RST 丢弃待处理字节并关闭目标连接。Stream 在整个生命周期内绑定其
Egress 和 Session，但数据MAY 在符合要求的 Path 之间迁移。

### UDP Association

```text
NEW → OPENING → OPEN
NEW/OPENING → CLOSED
NEW/OPENING → RESET
OPEN → DRAINING → CLOSED
OPEN → RESET
```

`OPEN` Association 恰好拥有一个 Egress 端套接字上下文。数据报保留边界，聚合层不可靠重传。
`DRAINING` 拒绝新数据报，允许已接受的数据报过期或完成，并在截止时间关闭套接字。Session
关闭、目标故障、端点重启以及授权 disable/revoke 都会关闭 Association 并释放套接字上下文。

### 订阅刷新

```text
DISABLED → ENABLED
ENABLED → REFRESHING
REFRESHING → ENABLED
REFRESHING → FAILED
FAILED → REFRESHING
ENABLED → DISABLED
ENABLED/DISABLED/FAILED → DELETED
```

`REFRESHING` 针对当前订阅 revision 求值。成功时原子发布一个动态代次并回到 `ENABLED`；
失败时保留最近一次成功的节点快照，记录类型化失败，并在有界退避后重试。`DISABLED` 订阅
不刷新。删除会从后续刷新中移除来源，并排空仅由该来源导入的节点。

文档获取/解析失败必须与单节点失败区分。有效兄弟节点可以发布，无效或不支持节点则保留可见、
不可选状态和脱敏诊断。有界 provider 展开可以在其他 provider 成功时保留失败 provider 的
上一批节点。缓存重载必须保留这些失败状态；[Transit Proxy 契约](../transit-proxies/spec.zh-CN.md)
定义规范化、验证和元数据所有权。

### 授权记录

```text
PENDING → ENABLED
PENDING → DISABLED
PENDING → REVOKED
ENABLED → DISABLED
ENABLED → REVOKED
DISABLED → ENABLED
DISABLED → REVOKED
```

`PENDING` 仅用于验证后的代次提交期间。`ENABLED` 允许新 Path。`DISABLED` 和 `REVOKED` 都会
立即拒绝新的握手，并终止所有匹配的存活 Path、Session、Stream、UDP Association 和 Egress
目标连接。`REVOKED` 对该记录身份是终态，MUST 重新注册；`DISABLED` MAY 通过新代次恢复为
`ENABLED`，但不会复活旧 SessionID。

### Windows 系统代理开关

该开关由控制面拥有，独立于 Listener 生命周期：

```text
DISABLED → APPLYING
APPLYING → APPLIED
APPLYING → FAILED
APPLIED → RESTORING → DISABLED
APPLIED → FAILED
FAILED → APPLYING
```

`APPLYING` MUST 验证请求的 `listener_id` 在 Windows 上解析为 HTTP、SOCKS 或 Mixed Listener。对已选择的
同一 Listener 重复启用MUST 幂等，返回当前已应用状态，MUST NOT 重新覆盖已保存值。`APPLIED` MUST 记录
环境变量和操作系统代理的精确旧值。Disable MUST 恢复这些值；恢复失败进入 `FAILED`，保留已保存值，
且MUST NOT 报告为 `DISABLED`。Linux 和 FreeBSD 对 enable/disable MUST 返回 `UNSUPPORTED_OPERATION`，MUST NOT 进入此状态机。
其 `system_proxy.get` 响应 MUST 返回 `enabled: false` 和 `platform_effect: unsupported`。
每次转换都发出 `system_proxy.changed`，包含 Listener ID、平台效果以及错误/恢复状态。

### 调度和自动扩缩容守卫

每个准入的 Stream 和 UDP Association 使用其 Egress Session 捕获的不可变 TrafficPolicy 快照。
业务类别的 priority/share 不再是公开配置面；调度器提供有界公平服务，并在有待发送的 Stream 之间轮询。
Stream 只有在其排队 DATA 已发送并确认后才能发出 FIN；已关闭 Stream 的观测可以保留在有界的近期历史中。

对于每条符合条件的 Path，调度器计算：

```text
score(path) = relationship_weight
              × billing_multiplier
              × advertised_effective_capacity
              × quality_factor
```

`quality_factor` 是由拥塞窗口、RTT、抖动、丢包和乱序推导出的有界值。具体系数属于配置，但MUST
单调，即质量变差不能提高 Path 评分。同一关系的多条 Path 在分配关系权重后再按 Path 评分分配。
必要控制和普通重传优先于可选业务复制；每个发送方的可选副本 MUST NOT 超过其剩余 outbound Session allowance，
上下行分别受同一已接受的标量上限约束。

自动扩缩容MUST 使用滞回：只有当聚合容量低于需求或 Session target 超过活跃数量，并持续达到配置的
连续采样窗口时才能增加 Path；只有当容量富余持续达到另一个非零窗口，且移除所有选中排空候选后剩余的
非排空可用 Path 仍满足公共 Egress 最小值时才能移除 Path。缩容前MUST 进入 `DRAINING`。当新增容量低于
调度开销时MUST 排除 Path，并在观测中暴露原因。
状态变化或探测失败后MUST 重置反向计数器。阈值和窗口MAY 配置，但这些守卫、滞回、排空动作和预算计费规则
具有规范性。

### 转换影响和失败原因

| 触发条件 | REQUIRED 守卫和动作 |
|---|---|
| Noise/attach 成功 | 身份、EgressID、能力和限制匹配；创建或加入一个 Session 并发出 `PATH_READY` |
| 最后一条 ready Path 丢失 | 关闭业务资源、废弃 SessionID、发出 `session.changed`，并在允许时调度新记录 |
| Path 排空 | 不接受新工作；在截止时间前完成已确认工作，然后关闭 |
| Egress 离线或端点重启 | 关闭所有相关资源，不复用旧 SessionID |
| 授权 disable/revoke | 原子发布授权代次，拒绝新握手，关闭所有匹配的存量资源 |
| 订阅刷新失败 | 保留最近成功快照，带失败发出 `subscription.changed`，用有界退避重试 |
| 资源达到上限 | 按资源类别拒绝新操作或施加背压；绝不静默丢弃已接受的 TCP 字节 |

关闭原因使用稳定标识符：`last_path_lost`、`egress_unavailable`、`endpoint_restart`、
`authorization_disabled`、`authorization_revoked`、`drain_deadline`、`target_failure`、
`local_policy`、`path_failure` 和 `resource_limit`。每个关闭事件包含原因及触发它的代次。

### 定时器和重试

握手、attach、目标打开、心跳、排空、订阅刷新和控制重传定时器都是有界配置值。超时MUST
产生类型化失败并执行状态转换，MUST NOT 留下半开资源。重试使用带抖动的有界指数退避，成功
转换后重置；端点重启或授权撤销终态后禁止继续重试。
