# PathChord

[English](README.md) | **简体中文**

一款由 Ingress、Transit Proxy 和 Egress 组成的自适应多路径代理。

PathChord 为本地应用程序提供常规代理语义，同时在 Ingress 与选定的 Egress 之间维护多条可替换的中转路径。

## 状态

本仓库包含设计基线、`wire-profile-v1` 协议契约、Kubernetes 风格配置契约，以及可运行的 Rust 实现。Ingress 可以绑定 HTTP、SOCKS5、Linux 透明模式和 TUN 监听器，维护持久化控制状态，刷新由订阅提供的 Transit Proxy，并通过经过认证的 Session/Path 运行时承载 TCP/UDP 流量。Egress 提供经过认证的 Path 监听器和授权控制面；可选的 REST/SSE Web Gateway 由两个控制面共享。

当前工作优先完善 Linux、Windows 和 FreeBSD 上的普通 HTTP 转发、CONNECT、SOCKS4/4a/5、Linux 透明接管与 TUN 监听器。HTTP 使用消息编解码器处理流式正文、持久连接请求和 Upgrade；SOCKS5 还提供 UDP ASSOCIATE。监听器名称 `socks` 可作为规范名称 `socks5` 的别名。`type: mixed` 在一个 TCP 端口上提供 HTTP 和 SOCKS，并通过协商的 relay 端点提供 SOCKS5 UDP ASSOCIATE。FreeBSD 已有显式代理监听器的平台校验和 Unix 本地控制接口，目标编译和 CLI 链接已通过，原生主机验证仍待完成。通用监听器回归测试由现有 Rust CI 任务执行。透明 TCP/UDP 接管与 TUN 数据包流已经接入相同的策略和 Session/Path 数据面。特权主机路由、真实 TUN 设备 smoke 以及平台打包验证仍是单独的验收步骤。Linux TPROXY 还接受 `backend: ebpf` 以启用绑定接口的 TC classifier；普通 `tproxy` 后端仍是默认和回退路径。平台验证、共享运行时缺口及后续适配器工作见[实施计划](docs/progress/implementation-plan.md)。

节点导入支持自动识别、Clash/Mihomo provider、SIP008、URI/Base64 列表、sing-box JSON，以及
所支持的 Surge/Quantumult X/Loon 节点行。原生传输支持类型化 TLS 设置、VLESS/Trojan 的
TCP/TLS/WebSocket 传输、VLESS + REALITY、带 AEAD 正文记录和单目标 UDP 的 VMess TCP/TLS/
WebSocket、AnyTLS TCP 与 UDP-over-TCP、带 Salamander 和端口跳转的原生 Hysteria2 TCP/UDP，
以及带 heartbeat 和可选 0-RTT 的 TUIC TCP/UDP。direct/SOCKS5/Shadowsocks UDP（包括 SS2022）
仍可用。未支持的协议和参数保持为明确诊断。精确的兼容边界见
[Transit Proxy 与订阅契约](docs/spec/transit-proxies.zh-CN.md)，可运行配置见
[部署指南](docs/spec/deployment.zh-CN.md)。

## 术语

- **Ingress**：本地流量入口和策略引擎。
- **Transit Proxy**：用于到达 Egress、但不受 PathChord 控制的代理传输。
- **Egress**：受控的逻辑网络接口和最终流量出口。
- **Session**：一个 Ingress 与一个 Egress 之间共享的逻辑会话。
- **Path**：经由一个 Transit Proxy 承载的长连接双向通道。
- **Stream**：通过一个 Session 承载的逻辑 TCP 字节流。

## 文档

设计文档只描述预期架构和长期设计决策；规范文档定义最终行为与格式契约。维护中的进度文档只描述当前实现状态和有效的实施计划；已经被替代的过程历史保留在 Git 历史中。
设计和规范文档均同时提供英文与简体中文版本；进度文档以英文作为唯一维护源。

### 设计

- [架构](docs/design/architecture.zh-CN.md)
- [技术选型](docs/design/technology-selection.zh-CN.md)

### 规范

- [协议](docs/spec/protocol.zh-CN.md)
- [v1 线协议 profile](docs/spec/wire-profile.zh-CN.md)
- [配置模型](docs/spec/configuration.zh-CN.md)
- [配置 schema](docs/spec/configuration-schema.zh-CN.md)
- [平台与 DNS](docs/spec/platform-and-dns.zh-CN.md)
- [状态机](docs/spec/state-machines.zh-CN.md)
- [Ingress 控制面](docs/spec/ingress-control-plane.zh-CN.md)
- [Ingress 可观测性](docs/spec/observability.zh-CN.md)
- [Transit Proxy 与订阅](docs/spec/transit-proxies.zh-CN.md)
- [部署与本地操作](docs/spec/deployment.zh-CN.md)

### 实施进度

- [实现状态](docs/progress/status.md)
- [实施计划](docs/progress/implementation-plan.md)

## 命令界面

Ingress 为普通用户默认加载 `~/.config/pathchord`，为 root/服务账号默认加载 `/etc/pathchord`。
`--config-dir` 将目录中的 YAML/YML/JSON 资源递归载入并统一验证。优先级为命令行，
然后是 `PATHCHORD_CONFIG`/`PATHCHORD_CONFIG_DIR`，最后是账号默认值。

```text
pathchord ingress
pathchord ingress --config-dir /path/to/conf.d
pathchord egress
pathchord status
pathchord enroll
```

在 Unix 上，`ingress` 命令会启动配置的监听器、持久化本地控制 socket、订阅
worker 和请求的 Web Gateway。`egress` 会启动经过认证的 Path 监听器和授权
控制 socket；`status`、`system-proxy` 与 `enroll` 通过对应的本地控制端点工作。
只有在策略没有 Egress/Transit 路由且显式选择 direct fallback 时，才会使用 direct
target bridge。

## 软件包

[`packaging/`](packaging/README.md) 下提供 Debian（`.deb`）、Alpine（`.apk`）、
Arch Linux（`.pkg.tar.*`）、FreeBSD（`.pkg`）和 Windows NSIS（`.exe`）的原生
打包配方。每个软件包都包含 `pathchord(1)` 手册页、服务定义和仅监听回环地址的
配置模板。先构建 release 二进制，再使用 `make -C packaging` 选择软件包目标；
软件包指南说明所需的原生构建工具以及交叉编译产物覆盖方式。

## 开发

开发使用固定版本的 Rust 1.100.0 工具链，并包含 rustfmt 和 Clippy。

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo run -p pathchord-cli -- --help
```

工作区在 dev/test profile 中关闭 rustc 增量产物，以便已配置的 `RUSTC_WRAPPER=sccache` 复用完整编译单元。仓库不强制机器专属 wrapper；是否使用 sccache 由本地 Cargo 配置决定。
