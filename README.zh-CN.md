# PathChord

[English](README.md) | **简体中文**

一款由 Ingress、Transit Proxy 和 Egress 组成的自适应多路径代理。

PathChord 为本地应用程序提供常规代理语义，同时在 Ingress 与选定的 Egress 之间维护多条可替换的中转路径。

## 状态

目前处于初始实现阶段。本仓库包含设计基线、阶段 0 协议/传输原语、阶段 1A TCP 单 Path 实施范围与临时线协议契约，以及 core reliability/control-service 基础。代理数据面和 Web Gateway 适配器尚未实现。

## 术语

- **Ingress**：本地流量入口和策略引擎。
- **Transit Proxy**：用于到达 Egress、但不受 PathChord 控制的代理传输。
- **Egress**：受控的逻辑网络接口和最终流量出口。
- **Session**：一个 Ingress 与一个 Egress 之间共享的逻辑会话。
- **Path**：经由一个 Transit Proxy 承载的长连接双向通道。
- **Stream**：通过一个 Session 承载的逻辑 TCP 字节流。

## 文档

设计文档只描述预期架构和长期设计决策；规范文档定义最终行为与格式契约。实现状态、实施顺序、阶段范围和验收跟踪只放在 `docs/progress/`（或上方的仓库状态摘要）中。
设计和规范文档均同时提供英文与简体中文版本；进度文档以英文作为唯一维护源。

### 设计

- [架构](docs/design/architecture.zh-CN.md)
- [技术选型](docs/design/technology-selection.zh-CN.md)

### 规范

- [协议](docs/spec/protocol.zh-CN.md)
- [配置模型](docs/spec/configuration.zh-CN.md)
- [状态机](docs/spec/state-machines.zh-CN.md)
- [Ingress 控制面](docs/spec/ingress-control-plane.zh-CN.md)
- [Ingress 可观测性](docs/spec/observability.zh-CN.md)

### 实施进度

- [实现状态](docs/progress/status.md)
- [实施计划](docs/progress/implementation-plan.md)
- [设计审查记录](docs/progress/design-review.md)
- [阶段 1 单 Path 范围](docs/progress/phase-1-single-path.md)
- [阶段 1 临时线协议契约](docs/progress/phase-1-wire.md)
- [阶段 1 验收跟踪](docs/progress/phase-1-acceptance.md)

## 命令界面

```text
pathchord ingress
pathchord egress
pathchord status
pathchord enroll
```

目前可通过命令树查看规划中的界面；在对应实现阶段完成前，运行操作命令会返回明确的初始化阶段错误。

## 开发

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo run -p pathchord-cli -- --help
```

工作区在 dev/test profile 中关闭 rustc 增量产物，以便已配置的 `RUSTC_WRAPPER=sccache` 复用完整编译单元。仓库不强制机器专属 wrapper；是否使用 sccache 由本地 Cargo 配置决定。
