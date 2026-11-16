# PathChord 部署与本地操作

[English](spec.md) | **简体中文**

## Purpose

定义 Ingress 和 Egress 的服务启动、配置选择、平台前提条件、显式身份登记、私有凭据、受保护管理接口及关停行为。

设置命令和示例见[部署使用指南](../../../docs/guides/deployment.zh-CN.md)。

## Requirements

### Requirement: Independent service processes and explicit proxy operation

Ingress 和 Egress SHALL 通过独立服务调用运行，各自使用角色专用可执行文件，拥有独立进程和本地管理端点。`pathchordctl` SHALL 是两者的管理客户端。普通显式 HTTP/SOCKS 代理操作 SHALL NOT 要求流量拦截或 TUN 权限。监听器协议行为 SHALL 遵循[平台契约](../platform-and-dns/spec.zh-CN.md#http-和-socks-监听器)。

#### Scenario: Dedicated service executable selection

- **WHEN** 软件包启动 Ingress 或 Egress 服务
- **THEN** 它直接调用对应的 `pathchord-ingressd` 或 `pathchord-egressd`，不通过共享服务子命令选择角色。

#### Scenario: Ordinary local proxy setup

- **WHEN** 使用随项目提供的直接路由 Mixed 监听器示例
- **THEN** 监听器在 `127.0.0.1:7890` 提供 HTTP 和 SOCKS，限制为回环访问，且不需要流量拦截或 TUN 权限。

#### Scenario: Unix local control endpoint defaults

- **WHEN** 普通 Unix 账号启动 Ingress，且没有显式指定控制 socket
- **THEN** 运行目录可用时端点为 `$XDG_RUNTIME_DIR/pathchord/ingress.sock`，否则为 `~/.config/pathchord/ingress.sock`；root 和软件包服务账号使用 `/run/pathchord/ingress.sock`，并在启动前创建运行目录。Ingress 配置默认位于对应的 `ingress` 目录。

#### Scenario: Explicit enrollment socket selection

- **WHEN** 登记客户端选择控制端点
- **THEN** `pathchordctl enroll` 默认使用对应的本地 `egress.sock` 端点，显式指定的 socket 优先；该端点属于 Egress 服务所在机器。Egress 配置默认位于对应的 `egress` 目录。

### Requirement: Role-specific service artifact boundaries

Ingress 服务可执行文件 SHALL 包含其声明的本地监听器、Transit Proxy、订阅、DNS 和透明/TUN 平台行为。Egress 服务可执行文件 SHALL 提供认证的 Path/Session 转发、TCP/UDP 目标连接、授权和全局资源保护，且不要求 Ingress listener、Transit Proxy、订阅、TUN 或 eBPF 运行时组件。

#### Scenario: Egress starts without Ingress platform privileges

- **WHEN** Egress 在没有 TUN 访问权且没有 `CAP_NET_ADMIN` 或 `CAP_NET_RAW` 的主机上启动
- **THEN** 它可以绑定配置的 Path listener、打开授权库，并在普通目标转发前提满足时接受已显式登记的 Ingress Session。

#### Scenario: Dedicated management client

- **WHEN** 操作者使用 `pathchordctl` 查询状态或执行登记
- **THEN** 客户端连接选定的本地控制端点而不启动任一服务，并保留版本化 control envelope 和代次检查。

### Requirement: Explicit configuration-source precedence

Ingress SHALL 遵循[配置来源契约](../configuration-schema/spec.zh-CN.md#配置来源)，优先选择命令行，其次环境变量，最后账号默认值。递归载入的 YAML/YML/JSON 文件 SHALL 组成一张资源图统一验证；重载 SHALL 原子替换完整有效资源图，并在失败时保留旧图。私有凭据、密钥 JSON 和服务数据 SHALL 保持在该资源树之外。

#### Scenario: Command line overrides the environment

- **WHEN** 已设置 `PATHCHORD_CONFIG_DIR`，且 Ingress 通过显式 `--config` 文件启动
- **THEN** 选择命令行文件作为配置来源。

#### Scenario: Account configuration defaults

- **WHEN** 既没有选择命令行来源，也没有选择配置环境变量
- **THEN** Ingress 为普通账号加载 `~/.config/pathchord/ingress`，为软件包服务账号加载 `/etc/pathchord/ingress`；Egress 使用对应的 `egress` 目录。

#### Scenario: Source options conflict

- **WHEN** 同时提供 `--config`/`-c` 和 `--config-dir`/`-C`，或在没有命令行来源时设置多个非空配置环境变量
- **THEN** 来源选择失败，不合并相互竞争的配置来源。

#### Scenario: Reload candidate is invalid

- **WHEN** 变化后的资源树不能组成有效的完整资源图
- **THEN** 运行中的服务保留先前资源图。

### Requirement: Privileged setup preserves routing ownership

透明和 TUN 操作 SHALL 遵循[平台契约](../platform-and-dns/spec.zh-CN.md)，要求创建 socket/设备及管理自身路由所需的权限。管理员的 packet-filter 规则和主机路由 SHALL 与 PathChord 记录在 journal 中的策略路由区分；清理 SHALL 仅删除仍与 journal 匹配的对象。受保护端点 SHALL 旁路接管，FreeBSD SHALL 拒绝透明和 TUN 监听器。

#### Scenario: Transparent route no longer matches its journal

- **WHEN** 清理时策略路由对象不再与 PathChord 所有权 journal 匹配
- **THEN** PathChord 不删除该对象。

#### Scenario: Administrator configures transparent packet delivery

- **WHEN** 管理员拥有的 packet-filter 规则把流量发送到 Linux TPROXY 监听器
- **THEN** 这些规则使用该监听器的 bind 地址、mark 和策略路由表；服务要求 root 或等效的透明 socket 与网络管理能力，例如 `CAP_NET_ADMIN` 和 `CAP_NET_RAW`。

#### Scenario: Optional eBPF backend prerequisites

- **WHEN** Linux 监听器选择 `backend: ebpf`
- **THEN** 构建要求 `clang`，运行要求 `bpftool`、`tc`、BPF/BTF 内核支持、网络管理权限、显式选定的 ingress 接口及 `allowedSources`；普通 TPROXY 后端是缺少这些能力的主机可显式选择的替代方案。

### Requirement: Explicit identities and Egress enrollment

每个服务 SHALL 在本地保留其私有身份，密钥生成 SHALL 只打印公钥。Egress 登记 SHALL 绑定 Ingress 公钥、规范 Egress 身份和期望授权代次。跨机器操作 SHALL 使用可达 Egress 地址，并保留显式核验的密钥与规范 Egress ID。更改 Transit 传输 SHALL 保留端到端 Noise 和登记语义。

#### Scenario: Enrollment after the initial authorization generation

- **WHEN** 操作者在授权数据库初始代次之后修改授权
- **THEN** 登记使用观测到的代次，不假定代次为 0。

#### Scenario: UDP capability follows the selected route

- **WHEN** UDP 使用经过认证的 Egress 路由
- **THEN** 它要求 Egress UDP 能力及 TCP Transit Path；普通第三方 UDP 路由还要求所选节点具有原生 UDP 支持，具体由[Transit 适配器契约](../transit-proxies/spec.zh-CN.md#udp-路由边界)定义。

### Requirement: Private credentials and protected service lifecycle

监听器和节点秘密 SHALL 是 `--credentials-dir` 下以不透明 `credentialsRef` 值命名的私有 JSON 文档，且 SHALL NOT 提交到仓库。本地控制 SHALL 使用 Unix 所有权/权限或 Windows Named Pipe ACL。显式启用的 Web Gateway SHALL 共用[控制服务](../ingress-control-plane/spec.zh-CN.md)的认证和 capability 边界。服务 SHALL 负责清理任务/连接，并在重载时报告仅启动时配置变更所需的重启。

#### Scenario: Required listener credentials meet SOCKS4

- **WHEN** 监听器要求包含 `username` 和 `password` 的 Basic 或 SOCKS5 凭据文档，且客户端尝试 SOCKS4 或 SOCKS4a
- **THEN** 监听器拒绝连接，不绕过必需凭据。

#### Scenario: Prometheus retains management authorization

- **WHEN** 通过显式启用的 Web Gateway 请求 `/metrics`
- **THEN** 请求与管理指标查询使用相同的 bearer 认证、Origin 检查和 `metrics:read` capability；配置的 `--web-token-file` 提供 bearer token。

#### Scenario: Service shutdown

- **WHEN** 服务收到 Ctrl-C 或 Unix 上的 SIGTERM
- **THEN** 它关停自己拥有的任务和连接。

#### Scenario: Startup-only configuration change

- **WHEN** 重载报告身份、监听器拓扑或其他仅启动时配置变更需要重启
- **THEN** 必须重启服务才能应用该变更；其他持久配置变更遵循重载契约。
