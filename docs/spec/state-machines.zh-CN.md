# PathChord 状态机规范

[English](state-machines.md) | **简体中文**

本文档定义可观察的生命周期状态，以及使状态转换有效的守卫和动作。管理器可以在内部
保留连接中或已关闭阶段的记录，但不得将该记录暴露为可用的 Session、Path、Stream 或
Association。

本文档中的 **MUST**、**MUST NOT**、**SHOULD**、**SHOULD NOT** 和 **MAY** 按照
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) 与 [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
解释；只有英文大写形式具有规范性效力。

## 共享规则

`PATH_READY` 是协议准入点。只有在 Noise 身份认证、身份/授权检查、能力协商和限制协商
全部成功后，Path 才是 **ready**。`ACTIVE` 和 `DEGRADED` Path 属于 ready 状态；
`DRAINING` 仍经过认证，可以完成已有工作，但不能准入新的业务工作。

协议层面的存活 Session 必须至少包含一条 ready Path，包括 draining Path。只有包含至少一条
`ACTIVE` 或 `DEGRADED` Path 的 Session 才能准入新的 Stream 或 UDP Association。仅有 draining
Path 的 Session 属于关闭中的 Session，必须拒绝新的业务操作。

每个转换只有一个拥有者：Ingress Session manager 拥有 Session 和 Path 的准入；Egress 拥有
目标连接和授权影响；Stream 或 Association 所有者拥有字节/数据报完成。对端消息可以请求
转换，但拥有者必须先验证守卫。

## Egress 关系和服务状态

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
必须关闭相关 Session、Stream、UDP Association、本地连接和 Egress 目标连接。配置和授权允许
时，管理器可以使用有界指数退避重试 `DOWN → CONNECTING`。

## Path

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
`FAILED` 转换，不得单独改写为目标错误。

Path 所有者必须为每次状态转换发出变更事件。质量采样可以导致 `ACTIVE ↔ DEGRADED`；恢复
分配必须由调度器稳定化。达到排空截止时间或发生传输故障时，即使仍有未完成工作也必须关闭。

## Session

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
Association，并等待已有工作；可以包含 ready 的 draining Path。最后一条 ready Path 丢失时，
协议 Session 永久关闭，关闭所有业务资源，废弃 SessionID；若允许，管理器可以使用新的
SessionID 创建新的 `CONFIGURED` 记录。

端点重启、Egress 硬故障或授权 disable/revoke 会关闭 Session 和所有相关目标资源。端点重启
和授权失败不得自动恢复旧 SessionID。心跳和控制重传使用任意 ready 且未撤销的 Path，并由
Session 控制序列去重。

## TCP Stream

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
Egress 和 Session，但数据可以在符合要求的 Path 之间迁移。

## UDP Association

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

## 订阅刷新

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

## 授权记录

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
目标连接。`REVOKED` 对该记录身份是终态，必须重新注册；`DISABLED` 可以通过新代次恢复为
`ENABLED`，但不会复活旧 SessionID。

## 转换影响和失败原因

| 触发条件 | 必需守卫和动作 |
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

## 定时器和重试

握手、attach、目标打开、心跳、排空、订阅刷新和控制重传定时器都是有界配置值。超时必须
产生类型化失败并执行状态转换，不得留下半开资源。重试使用带抖动的有界指数退避，成功
转换后重置；端点重启或授权撤销终态后禁止继续重试。
