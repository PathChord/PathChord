# PathChord

[English](README.md) | **简体中文**

一款由 Ingress、Transit Proxy 和 Egress 组成的自适应多路径代理。

PathChord 为本地应用程序提供常规代理语义，同时在 Ingress 与选定的 Egress 之间维护多条可替换的中转路径。

## 状态

本仓库包含设计基线、`wire-profile-v1` 协议契约、Kubernetes 风格配置契约，以及可运行的 Rust 实现。Ingress 可以绑定 HTTP、SOCKS5、Linux 透明模式和 TUN 监听器，维护持久化控制状态，刷新由订阅提供的 Transit Proxy，并通过经过认证的 Session/Path 运行时承载 TCP/UDP 流量。Egress 提供经过认证的 Path 监听器和授权控制面；可选的 REST/SSE Web Gateway 由两个控制面共享。

当前工作优先完善 Linux、Windows 和 FreeBSD 上的普通 HTTP 转发、CONNECT、SOCKS4/4a/5、Linux 透明接管与 TUN 监听器。HTTP 使用消息编解码器处理流式正文、持久连接请求和 Upgrade；SOCKS5 还提供 UDP ASSOCIATE。监听器名称 `socks` 可作为规范名称 `socks5` 的别名。`type: mixed` 在一个 TCP 端口上提供 HTTP 和 SOCKS，并通过协商的 relay 端点提供 SOCKS5 UDP ASSOCIATE。Windows 和 FreeBSD 的显式监听器与本地控制已通过各自记录的原生 QEMU 验证矩阵。通用监听器回归测试由现有 Rust CI 任务执行。透明 TCP/UDP 接管与 TUN 数据包流已经接入相同的策略和 Session/Path 数据面。Linux 特权路由、真实 TUN 设备与可选 eBPF 检查具有独立的 QEMU 主机证据。原生平台和软件包结果、主机版本及验证边界记录在下方链接的实现状态中。Linux TPROXY 还接受 `backend: ebpf` 以启用绑定接口的 TC classifier；普通 `tproxy` 后端仍是默认和回退路径。平台验证、共享运行时缺口及后续适配器工作见[进行中的 OpenSpec 变更](#进行中的变更)；已记录的能力和验证依据见[实现状态](openspec/implementation-status.md)。

节点导入支持自动识别、Clash/Mihomo provider、SIP008、URI/Base64 列表、sing-box JSON，以及
所支持的 Surge/Quantumult X/Loon 节点行。原生传输支持类型化 TLS 设置、VLESS/Trojan 的
TCP/TLS/WebSocket/HTTPUpgrade 传输、VLESS + REALITY 和 XTLS Vision flow、带 AEAD 或 AES-128-CFB 正文记录和单目标 UDP 的 VMess TCP/TLS/
WebSocket/HTTPUpgrade、AnyTLS TCP 与 UDP-over-TCP、带 Salamander 和端口跳转的原生 Hysteria2 TCP/UDP，
以及带 heartbeat 的 TUIC TCP/UDP。原生 h2mux、yamux 和 smux 支持满足条件的 Shadowsocks、VLESS、
VMess 和 Trojan 节点。smux FIN 遵循对端的整流关闭语义，不具备 TCP 半关闭兼容性。
direct/SOCKS5/Shadowsocks UDP（包括 SS2022）
仍可用。REALITY 适配器支持 dae Chrome 133、iOS 14、Safari 16、Edge 85、QQ 11.1 和 Firefox 120 指纹；
其他不支持的参数会产生单独诊断。
精确的兼容边界见
[Transit Proxy 与订阅契约](openspec/specs/transit-proxies/spec.zh-CN.md)，可运行配置见
[部署指南](docs/guides/deployment.zh-CN.md)。

## 术语

- **Ingress**：本地流量入口和策略引擎。
- **Transit Proxy**：用于到达 Egress、但不受 PathChord 控制的代理传输。
- **Egress**：受控的逻辑网络接口和最终流量出口。
- **Session**：一个 Ingress 与一个 Egress 之间共享的逻辑会话。
- **Path**：经由一个 Transit Proxy 承载的长连接双向通道。
- **Stream**：通过一个 Session 承载的逻辑 TCP 字节流。

## 文档

`docs/` 存放设计文档和面向用户的使用指南；行为契约、实现状态和变更跟踪由 OpenSpec 管理。
每份内容只有一个维护位置：指南链接到精确契约，不复制规范 schema；待办放在变更任务中，
不另设平行实施计划。设计、指南和能力规范均有英文与简体中文版本；规划产物和实现状态快照使用英文。

### 用户指南

- [配置指南](docs/guides/configuration.zh-CN.md)
- [部署与本地操作](docs/guides/deployment.zh-CN.md)
- [原生软件包](packaging/README.md)
- [监控部署](monitoring/README.md)

### 设计

- [架构](docs/design/architecture.zh-CN.md)
- [技术选型](docs/design/technology-selection.zh-CN.md)

### 能力规范

- [协议](openspec/specs/protocol/spec.zh-CN.md)
- [v1 线协议 profile](openspec/specs/wire-profile/spec.zh-CN.md)
- [配置模型](openspec/specs/configuration/spec.zh-CN.md)
- [配置 schema](openspec/specs/configuration-schema/spec.zh-CN.md)
- [平台与 DNS](openspec/specs/platform-and-dns/spec.zh-CN.md)
- [状态机](openspec/specs/state-machines/spec.zh-CN.md)
- [Ingress 控制面](openspec/specs/ingress-control-plane/spec.zh-CN.md)
- [Ingress 可观测性](openspec/specs/observability/spec.zh-CN.md)
- [Transit Proxy 与订阅](openspec/specs/transit-proxies/spec.zh-CN.md)
- [部署行为](openspec/specs/deployment/spec.zh-CN.md)

### 实现与验证依据

- [实现与验证状态](openspec/implementation-status.md)

### 进行中的变更

OpenSpec 当前没有进行中的变更。已完成的工作见[变更归档](openspec/changes/archive/)。

## OpenSpec 工作流

使用 OpenSpec 查看已有契约和当前变更：

```sh
openspec list --specs
openspec list
openspec status --change organize-documentation-with-openspec
openspec validate --all --strict --no-interactive
```

使用 `openspec new change <name>` 创建范围明确的变更，然后编写提案、设计和任务清单。
改变行为时，在 `specs/<capability>/spec.md` 中编写英文规范增量；只实现、验证或整理已有
契约的工作，在 `.openspec.yaml` 中使用 `skip_specs: true`。
[OpenSpec 项目配置](openspec/config.yaml)记录各类产物的规则。

实现并验证任务，同时保持实现状态快照准确。使用 `openspec archive <name>` 归档前，
同步英文主规范、完整技术契约、对应中文规范，以及受影响的设计和用户文档。
已完成变更的历史保存在 `openspec/changes/archive/`。

## 命令界面

软件包部署在每台设备上选择一个角色：客户端使用 `pathchord-ingressd`，落地主机使用
`pathchord-egressd`。各角色包都包含 `pathchordctl`，Unix 上使用本机的 `pathchord` 服务账号。

`pathchord-ingressd` 为普通用户默认加载 `~/.config/pathchord/ingress`，为软件包服务账号默认加载
`/etc/pathchord/ingress`。Egress 使用独立的 `~/.config/pathchord/egress` 或
`/etc/pathchord/egress`。`--config-dir` 将目录中的 YAML/YML/JSON 资源递归载入并统一验证。
优先级为命令行，然后是 `PATHCHORD_CONFIG`/`PATHCHORD_CONFIG_DIR`，最后是角色默认值。

```text
pathchord-ingressd
pathchord-ingressd --config-dir /path/to/ingress
pathchord-egressd --config-dir /path/to/egress
pathchordctl status
pathchordctl enroll list
```

在 Unix 上，`pathchord-ingressd` 会启动配置的监听器、持久化本地控制 socket、订阅
worker 和请求的 Web Gateway。`pathchord-egressd` 会启动经过认证的 Path 监听器和授权
控制 socket；`pathchordctl` 通过对应的本地控制端点查询和修改服务。
只有在策略没有 Egress/Transit 路由且显式选择 direct fallback 时，才会使用 direct
target bridge。

## 软件包

[`packaging/`](packaging/README.md) 下提供 Debian（`.deb`）、Alpine（`.apk`）、
Arch Linux（`.pkg.tar.*`）、FreeBSD（`.pkg`）和 Windows NSIS（`.exe`）的原生
打包配方。每台机器只安装一个角色包；每个包只包含所选 daemon、`pathchordctl`、对应
服务定义和角色配置。两种角色包互斥，切换角色前需显式移除现有包。构建所选 daemon 和
`pathchordctl`，并在 `make -C packaging` 中选择 `ROLE=ingress` 或 `ROLE=egress`；
软件包指南说明所需的原生构建工具以及预编译产物覆盖方式。

## 开发

开发使用固定版本的 Rust 1.100.0 工具链，并包含 rustfmt 和 Clippy。

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo run -p pathchordctl -- --help
```

工作区在 dev/test profile 中关闭 rustc 增量产物，以便已配置的 `RUSTC_WRAPPER=sccache` 复用完整编译单元。仓库不强制机器专属 wrapper；是否使用 sccache 由本地 Cargo 配置决定。
