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

### Requirement: Single-role package deployment

每次软件包安装 SHALL 选择且仅选择一个服务角色，只安装该角色的 daemon、`pathchordctl`、配置和服务定义。Unix 软件包 SHALL 使用本机不可登录的 `pathchord` 账号。相反角色的软件包 SHALL 互斥。角色替换 SHALL 显式执行，软件包生命周期操作 SHALL 保留操作者的配置、身份和授权数据。

#### Scenario: Selected role package payload

- **WHEN** 操作者安装 Ingress 或 Egress 角色软件包
- **THEN** 软件包提供所选 daemon、`pathchordctl`、配置和服务，且不包含另一个角色的 daemon、默认配置或服务定义。

#### Scenario: Opposite role package conflict

- **WHEN** 一个角色的软件包已经安装，操作者尝试安装相反角色
- **THEN** 安装在修改服务注册、配置、私有状态或控制端点前被拒绝；切换角色需要显式移除并替换。

#### Scenario: Single-role Unix service identity

- **WHEN** Unix 角色软件包准备服务身份和私有路径
- **THEN** 所选服务以本机不可登录的 `pathchord` 账号运行，只创建其角色目录，私有文件和控制端点拒绝未授权本地访问。

#### Scenario: Role package lifecycle preserves private state

- **WHEN** 所选角色软件包升级、回滚或移除
- **THEN** 保留操作者配置、身份和授权数据，不隐式启用另一个角色，也不把保留的身份数据自动用作另一个角色的身份。

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

### Requirement: Dedicated management client

`pathchordctl` 必须为 Ingress 和 Egress 提供面向资源的本地管理界面。标准查询使用
`get` 和 `describe`，授权变更归入 `enroll`。过渡期间继续接受已有状态和授权命令。
客户端保留版本化的控制信封、操作者能力和代次检查。

#### Scenario: Canonical status command

- **WHEN** 操作者运行 `pathchordctl get status`
- **THEN** 客户端向自动发现或由 `--socket` 指定的 Ingress 端点发送状态请求，并按所选格式输出

#### Scenario: Compatibility status command

- **WHEN** 操作者运行 `pathchordctl status`
- **THEN** 客户端执行与 `pathchordctl get status` 相同的操作和端点选择

#### Scenario: Enrollment resource commands

- **WHEN** 操作者查询授权或执行 `enroll` 变更
- **THEN** 客户端使用本地 Egress 授权端点，保留已有授权操作和代次前置条件，并按所选格式输出

#### Scenario: Enrollment resolves omitted arguments

- **WHEN** Egress 授权变更省略预期代次，或 `enroll add` 省略 Egress ID
- **THEN** 客户端从所选 Egress 端点读取省略值并向同一端点发送变更。代次冲突会报告当前代次，由操作者重新发起

#### Scenario: Confirm destructive authorization changes

- **WHEN** 操作者撤销或删除授权
- **THEN** 客户端在发送请求前要求交互确认或显式传入 `--yes`

#### Scenario: Configure an enrolled peer on Ingress

- **WHEN** Ingress 操作者使用 `config create` 或 `config patch` 配置已核验的 Egress ID、公钥和可达端点
- **THEN** 客户端校验完整 Ingress 资源图，更新本地受管 `Egress` YAML，并在拓扑变化时提示重启。通过 Egress 管理接口写入授权

### Requirement: Local control endpoint discovery

省略 `--socket` 时，客户端必须按角色依次尝试已配置的 `controlSocket` 和标准端点，
对候选去重，并在发送变更前选定端点。Windows 继续使用默认命名管道。
显式 `--socket` 跳过发现。

#### Scenario: Packaged runtime socket is found automatically

- **WHEN** 已安装的 daemon 监听 `/run/pathchord/ingress.sock`，且未显式指定 socket
- **THEN** `pathchordctl get status` 连接到该端点

#### Scenario: Standard Unix candidates are searched

- **WHEN** 在 Unix 上省略 `--socket`
- **THEN** 客户端依次检查适用的 `$XDG_RUNTIME_DIR/pathchord/<role>.sock`、`$HOME/.config/pathchord/<role>.sock`、`/run/pathchord/<role>.sock` 和 `/var/run/pathchord/<role>.sock`，并去重

#### Scenario: FreeBSD runtime alias is found automatically

- **WHEN** daemon 监听 `/var/run/pathchord/egress.sock`，且未显式指定 socket
- **THEN** 授权命令在前序候选后尝试该端点并连接

#### Scenario: Candidate failure continues discovery

- **WHEN** 候选无法连接或未通过只读探测
- **THEN** 客户端记录失败并尝试下一个候选

#### Scenario: Mutation response is lost

- **WHEN** 变更请求可能已发送，但响应无法读取
- **THEN** 客户端报告结果未知，不向其他候选重发

#### Scenario: Discovery failure is actionable

- **WHEN** 全部候选均不可用
- **THEN** 客户端以非零状态退出，并在 stderr 报告角色、检查过的候选及相关传输错误

### Requirement: Human and structured output modes

`pathchordctl` 必须支持全局 `--output` 和 `-o`，取值为 `human`、`json` 和
`yaml`。默认 `human` 展示主要状态或授权字段。显式选择 JSON 或 YAML 时，
stdout 必须包含表达相同响应数据的一个机器可读文档。

#### Scenario: Status defaults to human output

- **WHEN** 操作者运行 `pathchordctl get status` 且省略 `-o`
- **THEN** stdout 显示人类可读的状态

#### Scenario: JSON output is explicit

- **WHEN** 操作者运行 `pathchordctl get status -o json`
- **THEN** stdout 输出一个格式化的有效 JSON 文档，诊断写入 stderr

#### Scenario: YAML output is explicit

- **WHEN** 操作者运行 `pathchordctl get enrollments --output yaml`
- **THEN** stdout 输出表达响应的一个有效 YAML 文档

#### Scenario: Structured response error

- **WHEN** 已选择结构化输出，且本地服务返回类型化错误
- **THEN** 客户端以非零状态退出，并在 stdout 输出所选格式的稳定错误文档

### Requirement: Unified role configuration layout

Ingress、Egress 和 `pathchordctl` 必须对配置资源、运行 socket、状态及私有凭据使用统一的角色路径模型。

#### Scenario: Regular-user paths

- **WHEN** 普通 Unix 账号使用默认值
- **THEN** 资源位于 `~/.config/pathchord/{ingress,egress}`，socket 位于
  `$XDG_RUNTIME_DIR/pathchord`，状态位于 `~/.local/state/pathchord/{ingress,egress}`

#### Scenario: Packaged service paths

- **WHEN** 软件包服务账号使用默认值
- **THEN** 资源位于 `/etc/pathchord/{ingress,egress}`，socket 位于
  `/run/pathchord`，状态位于 `/var/lib/pathchord/{ingress,egress}`

#### Scenario: No working-directory state fallback

- **WHEN** 省略显式状态路径
- **THEN** daemon 从角色路径模型解析状态路径，当前工作目录不参与默认路径选择

### Requirement: Configuration lifecycle commands

`pathchordctl` 必须提供按角色操作的 `config init`、`validate`、`paths` 和 `view`。

#### Scenario: Role initialization

- **WHEN** 操作者运行 `config init --role ingress` 或 `--role egress`
- **THEN** 客户端创建缺失目录和模板，询问是否生成缺失身份，并保持现有远端授权

#### Scenario: Development initialization

- **WHEN** 操作者运行 `config init --both`
- **THEN** 客户端创建两套角色目录并标明同机开发用途

#### Scenario: Configuration validation

- **WHEN** 操作者运行 `config validate`
- **THEN** 客户端校验所选完整资源图并报告来源、资源、路径和字段诊断，整个流程可离线执行

#### Scenario: Effective paths are inspectable

- **WHEN** 操作者运行 `config paths`
- **THEN** 客户端报告有效路径、路径来源或优先级、角色及相关文件权限

### Requirement: Configuration-first startup overrides

资源必须作为启动配置主来源。CLI 覆写只用于来源、socket、日志或调试，以及显式临时身份。

#### Scenario: Resource values are effective defaults

- **WHEN** 资源值和对应默认值同时存在
- **THEN** 使用资源值，并在有效视图中标明来源

#### Scenario: Temporary identity override

- **WHEN** 操作者显式提供临时身份覆写
- **THEN** 临时身份在该次调用中优先，原有资源文件保持原值

### Requirement: Effective configuration secret handling

`config view` 必须默认脱敏，仅允许在交互式终端中显式显示敏感值。

#### Scenario: Default configuration view is redacted

- **WHEN** 操作者运行 `config view` 且省略显示敏感值的选项
- **THEN** 省略或遮盖敏感值和私有身份材料

#### Scenario: Secret reveal requires an interactive terminal

- **WHEN** 操作者运行 `config view --reveal-secrets`
- **THEN** 客户端只接受交互式终端中的人类可读输出，拒绝重定向和 JSON/YAML，始终排除私有身份材料

### Requirement: Declarative resource editing

资源编辑命令必须先校验完整资源图，再更新受管 YAML。运行状态由 daemon 管理。

#### Scenario: Create a managed resource

- **WHEN** 操作者对目录来源运行 `config create`，且候选有效
- **THEN** 校验完整候选后原子更新 `managed.yaml`，并报告文件变更和重启或重载要求

#### Scenario: Patch or delete a resource

- **WHEN** 操作者按资源身份运行 `config patch` 或 `config delete`
- **THEN** 客户端修改 `managed.yaml` 中的对应资源，拒绝未解析引用和重复资源，校验失败时保留原文件

#### Scenario: Single-file source is read-only for resource editing

- **WHEN** 操作者尝试编辑单文件配置来源
- **THEN** 客户端拒绝编辑，并提示先迁移到目录来源

### Requirement: User-resource adoption

客户端必须支持将用户手写资源显式迁移到受管 YAML，并保留来源中的其他内容。

#### Scenario: Adopt one resource

- **WHEN** 操作者运行 `config adopt <kind>/<name>`
- **THEN** 客户端预览受管文件的新增内容和来源文件的移除内容，经二次确认和完整校验后提交两项变更

#### Scenario: Adopt all resources from one file

- **WHEN** 操作者运行 `config adopt --all-from <file>`
- **THEN** 客户端预览全部选中资源，经显式确认后迁移到 `managed.yaml`

#### Scenario: Adoption preserves source organization

- **WHEN** 从手写文件迁移选中资源
- **THEN** 仅移除相应资源，保留无关文档、注释和空来源文件

#### Scenario: Adoption failure is atomic

- **WHEN** 校验、权限、来源指纹或替换检查失败
- **THEN** 客户端报告失败的检查项，保留受管文件和来源文件的原内容

#### Scenario: Interrupted adoption is recovered

- **WHEN** 迁移在替换文件时中断
- **THEN** 下次 PathChord 读取或编辑前，恢复迁移前或迁移后的完整资源包

### Requirement: Static configuration activation reporting

配置编辑必须分别报告期望文件的变更和运行时生效要求。重启由操作者发起。

#### Scenario: Static Egress edit

- **WHEN** 通过受管资源编辑 Egress 启动字段
- **THEN** 校验后更新文件，保留当前运行配置并报告 `restart required`

#### Scenario: Ingress dynamic edit

- **WHEN** 修改可动态生效的 Ingress 资源
- **THEN** Ingress 可通过现有重载流程发布候选。静态修改仍需重启

#### Scenario: Egress watcher observes an edit

- **WHEN** 运行中的 Egress 检测到来源变化
- **THEN** Egress 标记需要重启，并继续使用当前运行配置

### Requirement: Egress resource editing boundary

Egress 配置编辑必须只操作唯一的 `EgressService`。Egress 授权由控制接口管理。

#### Scenario: Minimal EgressService edit

- **WHEN** 操作者创建或编辑含一个 `EgressService` 且声明 `bind` 或 `binds` 的配置
- **THEN** 客户端接受有效资源图，从角色默认值解析省略的服务身份和私有文件路径，并报告重启状态

#### Scenario: Second EgressService is rejected

- **WHEN** 所选来源已包含一个 `EgressService`，操作者尝试添加第二个
- **THEN** 客户端拒绝编辑并保留受管文件

#### Scenario: Last EgressService cannot be deleted

- **WHEN** 操作者尝试删除来源中唯一的 `EgressService`
- **THEN** 客户端拒绝会导致配置失效的删除

#### Scenario: Egress edit does not use control protocol

- **WHEN** 操作者编辑 Egress 监听、身份路径、资源上限、DNS 设置或 Web 配置
- **THEN** 客户端在本地更新 YAML，整个操作可离线执行，并报告 `restart required`

#### Scenario: Authorization remains a control operation

- **WHEN** 操作者登记、启用、禁用、撤销或删除 Ingress 授权
- **THEN** `pathchordctl` 使用现有 Egress 控制操作。授权记录由数据库持有
