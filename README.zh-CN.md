# PathChord

[English](README.md) | **简体中文**

一款由 Ingress、Transit Proxy 和 Egress 组成的自适应多路径代理。

PathChord 为本地应用程序提供常规代理语义，同时在 Ingress 与选定的 Egress 之间维护多条可替换的中转路径。

## 状态

目前处于初始实现阶段。本仓库包含设计基线、阶段 0 协议/传输原语，以及阶段 1A TCP 单路径规范和 core reliability/control-service 基础。代理数据面和 Web Gateway 适配器尚未实现。

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
- [阶段 1 规范](docs/spec/phase-1-single-path.md)
- [阶段 1 线协议契约](docs/spec/phase-1-wire.md)
- [阶段 1 验收标准](docs/spec/phase-1-acceptance.md)
- [Ingress 控制面](docs/spec/ingress-control-plane.md)
- [Ingress 可观测性](docs/spec/observability.md)

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
