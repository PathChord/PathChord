# PathChord 部署与本地操作

[English](deployment.md) | **简体中文**

本指南介绍本地代理设置、Linux 特权监听器，以及 Ingress/Egress 的显式登记。请先阅读[配置指南](configuration.zh-CN.md)以选择资源和路由。服务行为要求由[部署规范](../../openspec/specs/deployment/spec.zh-CN.md)定义。

发布提供 `pathchord-ingressd`、`pathchord-egressd` 和 `pathchordctl`。每个服务可执行文件
拥有独立进程。普通示例使用显式代理监听器，不需要流量拦截或 TUN 权限。Linux 透明代理和 TUN 示例
单独提供，需要下面描述的平台权限和路由设置。

## 配置目录与覆写

没有显式配置选项时，Ingress 为普通账号加载 `~/.config/pathchord/ingress`，为软件包服务账号加载
`/etc/pathchord/ingress`。Egress 使用独立的 `~/.config/pathchord/egress` 或
`/etc/pathchord/egress`。显式命令行来源覆盖环境变量，环境变量覆盖角色默认值。例如：

```sh
pathchord-ingressd
PATHCHORD_CONFIG_DIR=/opt/pathchord/ingress pathchord-ingressd
pathchord-ingressd --config-dir /opt/pathchord/ingress
pathchord-ingressd --config /opt/pathchord/single.yaml
```

`PATHCHORD_CONFIG` 也接受文件或目录。未指定命令行来源时，只能设置一个非空配置环境变量。
`--config`/`-c` 与 `--config-dir`/`-C` 互斥。精确的账号分类和优先级由
[配置来源契约](../../openspec/specs/configuration-schema/spec.zh-CN.md#配置来源)定义。

可以把资源拆到所选树中的 `.yaml`、`.yml` 或 `.json` 文件，子目录也会载入。所有资源组成一张
经过统一验证的资源图，因此 Listener、DNSPolicy、FallbackPolicy、节点和路由规则可以放在
不同文件中。私钥/凭据 JSON 和 `--data-dir` 应放在该树外。文件新增、修改、删除和重命名后，
只在完整资源图有效时原子替换；候选失败时保留原配置。

## 本地显式代理

构建可执行文件并运行直接路由示例：

```sh
cargo build --locked --release --bin pathchord-ingressd --bin pathchord-egressd --bin pathchordctl
./target/release/pathchord-ingressd --config examples/ingress-direct.yaml
```

普通 Unix 用户从 `~/.config/pathchord/<role>` 读取资源，默认状态位于
`~/.local/state/pathchord/<role>`。socket 默认位于 `$XDG_RUNTIME_DIR/pathchord`，
缺少运行目录时使用 `~/.config/pathchord`。服务账号默认使用 `/etc/pathchord/<role>`、
`/run/pathchord` 和 `/var/lib/pathchord/<role>`，FreeBSD 的运行和状态目录分别位于
`/var/run` 和 `/var/db`。软件包还可在服务定义中显式指定现有路径。

`pathchordctl` 优先使用显式 `--socket`，随后尝试角色配置中的 `controlSocket`，
再依次搜索适用的 XDG 运行目录、用户配置目录、`/run/pathchord` 和 `/var/run/pathchord`。
`get status` 默认查询 Ingress，`enroll` 查询或修改 Egress 授权。
终端默认显示人类可读结果，脚本可用 `-o json` 或 `-o yaml`。

Mixed 监听器绑定 `127.0.0.1:7890`。无认证示例限制在回环地址。应用可以对同一个地址选择
HTTP 或 SOCKS：

```sh
curl -x http://127.0.0.1:7890 https://example.com
curl -x socks5h://127.0.0.1:7890 https://example.com
```

直接路由示例把流量直接发送到目标。订阅示例使用普通第三方 Proxy 路由，并明确拒绝没有可用
匹配节点的 flow。使用前必须替换其 provider URL：

```sh
pathchord-ingressd --config examples/ingress-subscriptions.yaml
```

## 软件包服务账号与权限

每台机器只安装一个角色：Ingress 客户端使用 `pathchord-ingressd`，Egress 落地机使用
`pathchord-egressd`。每个软件包只包含本角色 daemon、`pathchordctl`、配置模板和对应服务。
安装相反角色时，会在更改现有服务或私有状态之前拒绝操作。更换角色应显式卸载当前包后
再安装另一角色；升级、回滚和卸载保留用户配置及私钥。

构建原生软件包时，默认从当前源码根目录的 `Cargo.toml` 读取版本。CI 可以设置
`PATHCHORD_VERSION` 覆盖软件包版本。用法见[打包说明](../../packaging/README.md#package-version)。

两个 Unix 安装配置都使用本机非登录账号 `pathchord`，只创建所选角色的私有根。
状态目录权限为 `0700`，控制锁权限为 `0600`。配置目录由 `root:pathchord` 拥有，
权限为 `0750`。运行目录和控制 socket 由 `pathchord:pathchord` 拥有，权限分别为
`0750` 和 `0660`。`pathchord` 组成员获得本机服务管理权限。Linux 上执行
`sudo usermod -aG pathchord USER`，FreeBSD 上执行 `sudo pw groupmod pathchord -m USER`。
加入组的用户需要重新登录，再运行 `pathchordctl`。
Ingress 凭据位于资源树外的 `/var/lib/pathchord-ingress/credentials`；FreeBSD 使用
`/var/db/pathchord-ingress/credentials`。

systemd 服务限制设备访问。Ingress 默认不授予 capability。Linux Egress 软件包授予
`CAP_NET_BIND_SERVICE`，使服务可以绑定 TCP 443 等特权 Path 监听端口。
仅在配置透明/TUN listener 时，才把
`/usr/share/pathchord/systemd/transparent.conf` 安装为
`/etc/systemd/system/pathchord-ingressd.service.d/transparent.conf` 并重启 Ingress。
使用 eBPF 时另加相邻的 `ebpf.conf`，预先挂载 bpffs 并准备所需内核与工具。
[软件包说明](../../packaging/README.md#service-isolation-and-optional-ingress-privileges)
介绍了 Alpine OpenRC 的 capability 配置。Egress 使用普通 socket 转发流量，无需 TUN
设备或网络管理 capability。

Windows 只安装所选角色服务定义，把本角色配置、数据、凭据和日志权限限制为其虚拟服务
账号、SYSTEM 和 Administrators。使用 Windows TUN 前，应为所选 Ingress 账号准备原生
设备权限。普通显式代理 listener 不需要管理员服务账号。

## Linux 透明代理与 TUN 监听器

[`ingress-tproxy.yaml`](../../examples/ingress-tproxy.yaml) 示例在 Linux 上启动
`0.0.0.0:15001` 的 TPROXY TCP/UDP 接管，使用包标记 `1` 和策略路由表 `100`。把流量发送到
监听器并设置标记的主机 packet-filter 规则仍由管理员负责，必须使用相同的 bind 地址、标记和
路由表。PathChord 只拥有匹配的策略路由对象，并且只删除仍与其 journal 匹配的对象。服务需要
创建透明 socket 和管理路由所需的权限，例如 root 或等效的 `CAP_NET_ADMIN` 与 `CAP_NET_RAW`。

[`ingress-tproxy-ebpf.yaml`](../../examples/ingress-tproxy-ebpf.yaml) 示例选择
`backend: ebpf`，并把一个 Linux TC classifier 挂载到管理员指定的 `lan0` ingress 接口。它只为
TCP/UDP 数据包设置现有 TPROXY 策略路由所需的标记；透明 listener、原目标处理、UDP association
以及 Path/Session 策略仍在用户态完成。eBPF 后端构建时需要 `clang`，运行时需要 `bpftool`、`tc`、
BPF/BTF 内核支持和网络管理特权。该后端刻意绑定单个接口并要求 `allowedSources`；主机无法提供这些
能力时应使用普通 TPROXY 后端。

[`ingress-tun.yaml`](../../examples/ingress-tun.yaml) 示例创建名为 `PathChord`、地址为
`198.18.0.1/30`、MTU 为 1500 的 TUN 接口，并通过相同的策略和 fallback 路由承载 TCP 与 UDP
数据包。运行 Ingress 的账号必须有权限创建和配置 TUN 设备。把所需的主机路由添加到该接口，
并在把主机流量导入之前保留规范中描述的受保护端点旁路。FreeBSD 拒绝透明监听器和 TUN；
Windows 通过原生适配器提供 TUN 支持。

显式指定任一示例启动，避免特权配置被账号默认配置意外加载：

```sh
sudo ./target/release/pathchord-ingressd --config examples/ingress-tproxy.yaml
sudo ./target/release/pathchord-ingressd --config examples/ingress-tun.yaml
```

TPROXY 和 TUN 监听器接收 IP flow，因此路由匹配原始 IP 地址、端口、协议和可用的进程元数据。
原始数据包不包含 hostname 时，要求域名的策略条件不会匹配。

未实现的 Transit 协议和参数会保持为类型化节点诊断，直到对应的 PathChord 原生适配器完成。
PathChord 不启动或嵌入外部代理进程作为兼容后端。见
[Transit Proxy 契约](../../openspec/specs/transit-proxies/spec.zh-CN.md)。

## Ingress 与 Egress 登记

在各自对应的机器上生成私有身份。命令只打印公钥；私有文件必须保留在其所有者本地：

```sh
pathchordctl keygen --identity-file ingress.key.json
pathchordctl keygen --identity-file egress.key.json
```

在独立终端中启动 Egress。Unix 控制 socket 位于 Egress 本机：

```sh
pathchord-egressd --egress-id exit --identity egress.key.json \
  --bind 127.0.0.1:9443 --control-socket /tmp/pathchord-egress.sock
```

一个 Egress 进程拥有多个公共 Path listener 时，可以重复使用 `--bind`。相同的列表也可以在
`EgressService` 中写成 `spec.binds`。Ingress 使用一份 Egress 资源及有序的 `spec.endpoints` 列表，
表达不同的 IPv4、IPv6、域名或端口候选。所有项都使用相同、已经核验的 Egress ID 和公钥。
部署单个端点时，在 Egress 上指定一个 `--bind`，在 Ingress 的 `Egress` 资源中使用
`spec.host` 和 `spec.port`。

在 Egress 主机上登记独立核验过的 Ingress 公钥。CLI 从所选服务读取 Egress ID 和当前授权代次。
也可以显式传入 `--egress-id` 和 `--expected-generation`。代次冲突后请先检查再重试。
撤销和删除会要求确认。无人值守时可传入 `--yes`。

```sh
pathchordctl --socket /tmp/pathchord-egress.sock enroll add \
  --ingress-id entry --public-key INGRESS_PUBLIC_KEY
```

在 Ingress 主机上，把 [ingress-egress.yaml](../../examples/ingress-egress.yaml) 复制为
`ingress.yaml`，将 `REPLACE_WITH_EGRESS_PUBLIC_KEY` 替换为独立核验过的 Egress 公钥。
上面的回环部署只需保留 `127.0.0.1:9443` 端点。跨机器部署时，设置可达的 Egress 监听地址和
对应端点，并保留相同的 Egress ID 和已核验的公钥。在独立终端中验证完整配置文件并启动 Ingress。

```sh
pathchordctl --config ingress.yaml config validate
pathchord-ingressd --socket /tmp/pathchord-ingress.sock \
  --ingress-id entry --identity ingress.key.json \
  --config ingress.yaml
```

另开终端，在 Ingress 主机上查看服务状态，在 Egress 主机上查看登记列表。

```sh
pathchordctl --socket /tmp/pathchord-ingress.sock get status
pathchordctl --socket /tmp/pathchord-egress.sock enroll list
```

示例的 `direct-path` 是到经过认证的 Egress 的直接传输。将它替换为 HTTP、HTTPS、SOCKS5、
Shadowsocks Transit 时，只改变传输，端到端 Noise 和显式登记契约保持一致。
经由 Egress 的 UDP flow 要求 Egress 具有 UDP 能力，并具有 TCP Transit Path；普通第三方 UDP
路由还要求所选节点自身支持原生 UDP。

## 凭据、管理与关停

监听器和节点秘密存储在 `--credentials-dir` 指定目录的私有 JSON 文件中，文件以不透明的
`credentialsRef` 值命名。Basic 或 SOCKS5 凭据文档包含 `username` 和 `password`，不得提交到
仓库。要求监听器认证时必须拒绝 SOCKS4/4a。

Unix socket 的所有权/权限和 Windows Named Pipe ACL 保护本地管理接口。Socket 路径位于服务
所在机器。Windows 对应控制端点使用 Named Pipe 名称。Web Gateway 通过 `--web-bind` 显式
启用，并共用本地 dispatcher；配置的 `--web-token-file` 提供 bearer token。Prometheus 在
`/metrics` 抓取，使用相同的认证、Origin 检查和 `metrics:read` 能力。
Path pool gauge 汇总 live Session 的请求/有效空闲基线、当前需求目标和基线缺口。具体字段和
指标语义见[可观测性契约](../../openspec/specs/observability/spec.zh-CN.md)。

每个服务接受 Ctrl-C 关停，在 Unix 上也接受 SIGTERM，并拥有任务和连接清理责任。持久配置变更遵循重载契约；身份、
监听器拓扑和其他只在启动时加载的设置，在重载响应明确要求时需要重启服务。
