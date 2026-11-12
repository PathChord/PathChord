# PathChord 状态机

[English](state-machines.md) | **简体中文**

## Egress 关系

```text
CONFIGURED → CONNECTING → CONNECTED
CONNECTED → DEGRADED
DEGRADED → CONNECTED
CONNECTED/DEGRADED → DRAINING
CONNECTED/DEGRADED/DRAINING → DOWN
DOWN → CONNECTING
```

`CONNECTED` 要求至少有一个经过身份验证的双向 Path。`DEGRADED` 要求至少有一个 Path，但当前容量、路径数量或能力要求未得到满足。`DOWN` 会关闭所有相关连接。

## Path

```text
DISCOVERED → PROBING → ACTIVE → DRAINING → CLOSED
PROBING → FAILED
ACTIVE → DEGRADED → ACTIVE
ACTIVE → FAILED → CLOSED
```

新探测到的 Path 会立即按其配置权重加入，不设预热阶段。质量下降时会迅速减少分配。恢复过程会经过稳定化处理。缩容使用排空机制。

## Stream

```text
NEW → OPENING → OPEN
OPEN → HALF_CLOSED_LOCAL
OPEN → HALF_CLOSED_REMOTE
HALF_CLOSED_* → CLOSED
OPEN → RESET
```

Stream 始终绑定到其 Egress。它可以在 Session 内符合要求的 Path 之间迁移。如果符合要求的 Path 集合变为空，则重置该 Stream，并关闭关联的目标连接。

## Session

```text
CONFIGURED → CONNECTING → ACTIVE
ACTIVE → DEGRADED
ACTIVE → DRAINING
DEGRADED → CONNECTING
DRAINING → CLOSED
CONNECTING → CLOSED
ACTIVE → CLOSED
```

一个 Session 由一个 Ingress 和一个 Egress 共享，并且要求至少有一个活跃 Path。Ingress 启动时会尝试为已配置的 Egress 创建 Session；只要 Egress 保持在线，就会维持空闲 Session。最后一个 Path 丢失后，从协议角度看，旧 Session 将被永久关闭；业务 Stream 会立即关闭，Session 管理器可以使用新的 SessionID 创建新 Session。Egress 离线、端点重启、授权撤销或硬故障都会关闭 Session 及相关目标连接。端点重启后不会恢复该 Session。控制消息和心跳使用当前可用的 Path，并通过 Session 控制序列号去重。
