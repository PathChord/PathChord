# PathChord 设计审查

[English](design-review.md) | **简体中文**

本审查对架构、协议、配置、状态机、实现和技术选型文档进行比较。

## 审查状态

本次审查发现的 Session 生命周期、控制 ACK、标识符、DNS 和命名问题已经修订到主要设计文档中。其余条目属于实现规范，必须在构建相应子系统之前完成。

## 实现前必须修复

### 1. Session 基数与 Path 基数冲突

架构文档目前称一个 Session 包含“零条或多条” Path，而协议不变量规定一个存活的 Session 始终至少有一条处于 `PATH_READY` 状态的 Path。预期规则应为：

- 建立连接期间，内部可以存在 Session 记录；
- 存活或可用的 Session 必须至少有一条 `PATH_READY` Path；
- 业务 Stream 只能使用可用的 Session；
- 失去最后一条 Path 时关闭业务 Stream，并将 Session 转入重连状态；
- 从协议角度看，处于重连状态的记录不是存活的 Session。

所有文档中的表述都应保持一致。

### 2. 最后一条 Path 的行为存在两种描述

部分章节称最后一条 Path 消失后立即终止 Session，其他章节则称 Session 转入 `CONNECTING`，并且可以创建替代 Session。这些行为应分为两个层次：

- 协议层：`SESSION_CLOSE` 是最终状态，旧 Session ID 不得复用；
- Ingress Session 管理器：关闭后，可以为同一个 Egress 创建新的 Session。

这样既能维持“没有 Path 就没有 Session”的不变量，也允许自动恢复。

### 3. 有损 Path 上的控制消息可靠性不完整

控制消息默认会复制发送，但确认和重传规则尚未明确。设计需要 Session 级控制 ACK 或累计已应用序列报告。所有副本都丢失时，仅靠复制无法保证交付。

建议规则：每条控制消息都保留到对端确认；ACK 报告最高连续已应用序列，并为依赖项报告选择性区间。

### 4. 帧完整性和丢失模型需要明确边界

协议面向字节，但完整帧是最小交付单元。适配器契约必须明确：有损字节流适配器负责帧恢复，还是由 Path 帧层负责。建议边界为：

- 适配器交付完整且已认证的记录；
- 记录丢失、重复和乱序均可见；
- 不完整记录在适配器或记录解码器内部丢弃；
- Session 可靠性机制绝不处理不完整字节。

### 5. Session 控制序列的生命周期未定义

`control_seqno` 的作用域必须限定在一个 Session 内，并且不得在该 Session 内复用。新 Session 获得新的随机 SessionID 和新的序列空间，无需持久化序列。

## 缺失的重要规范

### 6. Stream ID 和请求 ID 分配

文档定义了这些标识符，但没有定义分配方向、位宽或冲突处理。建议默认值为：

- StreamID：每个方向各自分配的 62 位单调递增计数器；
- RequestID：128 位随机值；
- SessionID 和 PathID：128 位随机值；
- 在存活的 Session 内绝不复用 ID。

### 7. ACK 和重传职责

设计应明确哪个端点负责重传计时器、如何处理重复 ACK，以及未确认区间何时过期。建议模型是由发送方持有重传状态、接收方生成 ACK 区间，并使用有界重传队列。

### 8. 目标连接和 DNS 时机

协议尚未规定 Egress 在 `STREAM_OPEN` 中接收主机名、解析后的地址，还是二者都接收。这会影响 DNS 策略以及 IPv4/IPv6 选择。建议在原始主机名可用时携带该主机名，并由选定的 Egress 应用其配置的 DNS 策略。

### 9. 管理 API 结构

传输方式已经选定，但请求/响应操作尚未定义。API 仍需定义操作名称、响应封装结构、代次冲突处理、状态输出和授权错误码。

### 10. 资源耗尽行为

文档提到了硬限制，但尚未将其映射为协议行为。每项限制都需要明确响应：拒绝新 Stream、施加背压、排空 Path 或关闭 Session。

## 文档一致性问题

- CLI 示例使用 `anasto`，但项目名称是 PathChord。
- 架构文档称“Stream 数据只能使用该 Stream 获准使用的 Path”，而当前设计规定 Path 对 Stream 透明。这里应描述调度器资格，而不是由 Stream 持有的 Path 状态。
- 协议同时使用 `SESSION_ATTACH_ACK` 和 `SESSION_ATTACH_OK`；应选定一个名称。
- 协议先列出 `DATA`、`ACK` 和 `WINDOW_UPDATE`，后续章节又使用 `STREAM_DATA`、`STREAM_ACK` 和 `STREAM_WINDOW`；应以后者作为规范名称。
- 状态机对 Egress 使用 `CONNECTED`/`DOWN`，对 Session 使用 `ACTIVE`/`CLOSED`，但没有交叉引用表。

## 可以保留到实现阶段再决定的事项

- Rust crate 的确切版本；
- SQLite 数据库模式中的索引；
- Tokio 任务拓扑；
- TPROXY 和 Wintun 封装细节；
- 探测间隔和自动伸缩常量，前提是先固定指标语义。
