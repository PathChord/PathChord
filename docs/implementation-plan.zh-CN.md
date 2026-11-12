# PathChord 实施计划

[English](implementation-plan.md) | **简体中文**

## 阶段 0：协议和测试夹具

- 冻结帧和状态机规范。
- 为 Noise 握手和帧封装定义确定性测试向量。
- 定义 HTTP、SOCKS、TUN、TCP 和 UDP 的错误映射。
- 构建用于故障注入的模拟 Transit 传输和模拟 Egress。

## 阶段 1：单路径 Egress

- Ingress/Egress Noise 连接。
- Session 附加和状态报告。
- 一个 TCP Stream 和一个 UDP 会话。
- 正确实现 FIN/RST、半关闭、重置和重启语义。

## 阶段 2：适配器

- Linux HTTP/SOCKS。
- Linux TPROXY/REDIRECT。
- Windows TUN。
- Windows 系统代理集成。
- 内部出站环路防护。

## 阶段 3：动态数据和规则

- 静态 Egress 拓扑。
- 订阅缓存以及 Clash/SIP008 规范化。
- 基于名称的标记（tag）/标签（label）注解。
- 编译后的有序 Egress 和 Proxy 规则。
- 运行时快照和监听器 ID。

## 阶段 4：多路径

- 每个 Proxy 和 Egress 使用多个 Path。
- Stream 偏移量、ACK 范围、重排序和跨 Path 重传。
- Egress 下行调度。
- 排空和逐 Stream 的路径准入。

## 阶段 5：观测和自动伸缩

- 观测 Path 的 RTT、抖动、丢包率和吞吐量。
- Egress 状态报告和逐 Ingress 限制。
- 有效容量计算。
- 激进的路径准入、质量下降时快速降低分配、稳定化恢复和谨慎缩容。
- 配额和流量倍率元数据。

## 阶段 6：控制和运维

- 在两端手动注册公钥。
- 动态 Egress 授权列表。
- 状态和诊断 CLI。
- 崩溃清理和网络恢复。
- 兼容性、重启、网络分区、代理删除和配额测试。

## 延后决定的实现选型

该设计尚未选定实现语言、Noise 库、规则虚拟机、控制平面编码、数据库格式、代理适配器库、精确探测间隔、缓冲区大小或自动伸缩器常量。
