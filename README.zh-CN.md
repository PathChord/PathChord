# PathChord

[English](README.md) | **简体中文**

一款由 Ingress、Transit Proxy 和 Egress 组成的自适应多路径代理。

PathChord 为本地应用程序提供常规代理语义，同时在 Ingress 与选定的 Egress 之间维护多条可替换的中转路径。

## 状态

目前处于设计阶段。本仓库包含架构和协议设计基线；实现选型尚未全部冻结。

## 术语

- **Ingress**：本地流量入口和策略引擎。
- **Transit Proxy**：用于到达 Egress、但不受 PathChord 控制的代理传输。
- **Egress**：受控的逻辑网络接口和最终流量出口。
- **Session**：一个 Ingress 与一个 Egress 之间共享的逻辑会话。
- **Path**：经由一个 Transit Proxy 承载的长连接双向通道。
- **Stream**：通过一个 Session 承载的逻辑 TCP 字节流。

## 设计文档

- [架构](docs/architecture.zh-CN.md)
- [协议](docs/protocol.zh-CN.md)
- [配置模型](docs/configuration.zh-CN.md)
- [状态机](docs/state-machines.zh-CN.md)
- [实现计划](docs/implementation-plan.zh-CN.md)
- [技术选型](docs/technology-selection.zh-CN.md)
- [设计审查](docs/design-review.zh-CN.md)

## 计划中的命令

```text
pathchord ingress
pathchord egress
pathchord status
pathchord enroll
```
