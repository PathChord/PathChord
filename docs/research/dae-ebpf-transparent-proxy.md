# dae 透明代理与 eBPF 后端评估

本文基于 dae 官方仓库提交
[`460cec77f4365abfd9ea6fae04b66466dd4861cb`](https://github.com/daeuniverse/dae/tree/460cec77f4365abfd9ea6fae04b66466dd4861cb)
以及 Linux 内核提交
[`97d73c8251226cf27cc6656b4c542869bb8c69fa`](https://github.com/torvalds/linux/tree/97d73c8251226cf27cc6656b4c542869bb8c69fa)。
Linux 源码定位使用固定提交，避免把当前分支审计结果绑定到未来变更。

## 结论

dae 的透明代理可以使用 eBPF，而且官方实现已经这样做：主数据路径是绑定网络设备的 TC eBPF 程序，负责在进入 TCP/IP 协议栈前分类、重定向和维护回程状态。cgroup eBPF 在 dae 中主要记录本机进程与 socket 的关联；`sk_lookup`、`sk_skb` 等程序不是 dae 透明拦截的唯一基础。

PathChord 可以增加 Linux 专用的 eBPF 透明后端，但不应把它作为跨平台基线，也不应直接替换现有 socket/路由后端。建议先保留现有 Linux TPROXY、Windows/FreeBSD 平台路径，在显式 Linux feature flag 下增加可回退的 TC eBPF 加速路径；只有在真实主机上完成内核矩阵、路由回程、reload、故障恢复和资源边界验证后，才考虑把它提升为默认实现。

这个建议的原因是 eBPF 不会消除透明代理的用户态职责：PathChord 仍需要透明 TCP/UDP listener、原目标地址提取、策略路由、保护端点、UDP association 生命周期，以及失败时的可恢复清理。dae 的实现也保留了这些层次。

## dae 的实际 hook 和包路径

dae 官方工作原理文档直接说明，它把 eBPF 程序加载到 Linux TC hook，在 TCP/IP 协议栈之前分流：

- [dae `docs/en/how-it-works.md` 第 5–10 行](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/docs/en/how-it-works.md#L5-L10)说明主 hook 是 TC，接收和发送方向分别位于协议栈两侧。
- 同一文档[第 102–121 行](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/docs/en/how-it-works.md#L102-L121)说明 TC 程序把流量送往 dae 的 TPROXY listener 或直接放行。LAN ingress 和 WAN egress 保留 IP 目标地址、端口和校验和，只修改 Ethernet 目的 MAC、记录 `redirect_track`、设置 `skb->cb[0] = TPROXY_MARK`，再用 `bpf_redirect` 把未改写的 IP 包送入 `dae0`。
- `dae0peer` ingress 丢弃没有该 cb 标记的包，设置 `skb->mark = 0x8000000`，再由 `fwmark 0x8000000/0x8000000 table 2023` 的本地路由把包送到 loopback。对 UDP datagram 和 TCP SYN，eBPF 调用 `bpf_sk_assign` 选择 listener；已建立 TCP 依靠本地路由进入 socket。
- 回包由 `dae0` ingress 根据 `redirect_track` 恢复原始 Ethernet 地址，并使用原接口重定向；WAN 回程使用 `BPF_F_INGRESS`。这说明回程绑定是显式状态，而不是只靠一次 socket lookup。

dae 的 C 程序把这些角色落实为多个 TC section：[LAN ingress `tc/lan_ingress_l2/l3`](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/kern/tproxy.c#L3300-L3310)、[WAN egress `tc/wan_egress_l2/l3`](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/kern/tproxy.c#L3930-L3940)、[WAN ingress](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/kern/tproxy.c#L3432-L3442)、[LAN egress](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/kern/tproxy.c#L2910-L2920)，以及合并角色的 [`wan_lan_ingress` 和 `lan_wan_egress`](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/kern/tproxy.c#L3444-L3490)。回程入口是 [`tc/dae0peer_ingress`](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/kern/tproxy.c#L3971-L3995) 和 [`tc/dae0_ingress`](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/kern/tproxy.c#L4131-L4170)。

TCX 可用时 dae 优先使用 TCX，旧内核则回退到经典 cls_bpf/netlink filter：[官方 hook 管理代码](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/tc_hook_set.go#L95-L121)和[经典回退路径](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/tc_hook_set.go#L180-L216)。主机接口和 `dae0`/`dae0peer` 的绑定由 [`bindLan`](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/control_plane_core_bind.go#L217-L297)、[`bindWan`](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/control_plane_core_bind.go#L555-L628) 和 [`bindDaens`](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/control_plane_core_bind.go#L631-L675) 分阶段安装。

### cgroup hook 的作用边界

dae 的 `cgroup/sock_create`、`sock_release`、`connect4/6`、`sendmsg4/6` section 位于 [`tproxy.c` 第 4300 行附近](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/kern/tproxy.c#L4300-L4348)。它们写入 socket cookie 到 PID/进程名的映射，供 TC 路由规则使用；它们不是 LAN 设备流量的包重定向 hook。dae 的工作原理文档也把进程名来源描述为 cgroupv2 上的 `socket`、`connect` 和 `sendmsg` 调用[第 18–24 行](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/docs/en/how-it-works.md#L18-L24)。

dae 还提供可选的 [`sk_skb/tcp_offload_redirect`](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/kern/tproxy.c#L4350-L4421) socket-map TCP relay offload，但该路径是用户态已注册 relay socket 对之后的优化，不是透明拦截的前置条件。

## 原目标地址、TCP/UDP 和回程

### TCP

dae 在 TPROXY listener 上设置透明 socket 选项，并把 TCP listener 的 `LocalAddr()` 当作原目标地址。官方代码位置如下：

- [`sockopt.go` 第 43–84 行](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/component/outbound/dialer/sockopt.go#L43-L84)设置 `IP_TRANSPARENT`/`IPV6_TRANSPARENT`、`IP_RECVORIGDSTADDR`/`IPV6_RECVORIGDSTADDR` 以及相关 socket 选项。
- [`tcp.go` 第 130–156 行](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/tcp.go#L130-L156)从监听连接取得 `RemoteAddr` 和 `LocalAddr`，随后进入路由决策。

这条路径没有依赖 `SO_ORIGINAL_DST` 作为 TPROXY 的唯一接口：透明 TCP socket 直接以本地地址获得目标，而 REDIRECT 模式才使用原目标 socket option。

### UDP

UDP listener 从接收消息的 ancillary data 中读取真实目标地址：

- [`utils.go` 第 231–272 行](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/utils.go#L231-L272)解析 IPv4/IPv6 `IP_RECVORIGDSTADDR` 控制消息。
- [`control_plane.go` 第 2688–2696 行](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/control_plane.go#L2688-L2696)把该目标作为 `realDst` 进入 UDP 路由、嗅探和 association 处理。

因此，eBPF 负责把 datagram 送到正确的 UDP listener，但不会自动替用户态保存原目标、划分 association 或完成回包语义。

### Linux 内核 hook 的限制

Linux 官方 `sk_lookup` 文档说明，`BPF_PROG_TYPE_SK_LOOKUP` 在 transport layer 为本地包查找 TCP listener 或未连接 UDP socket 时运行，并可通过 `bpf_sk_assign()` 选择 socket：[第 7–15 行](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/Documentation/bpf/prog_sk_lookup.rst#L7-L15)、[第 46–63 行](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/Documentation/bpf/prog_sk_lookup.rst#L46-L63)。同一文档明确说明，已建立 TCP 和已连接 UDP 不再触发该 hook。因此，PathChord 不能只做 `sk_lookup` 就覆盖透明代理的完整生命周期。

内核 UAPI 也明确区分两种 `bpf_sk_assign`：

- TC ingress 版本要求配合路由配置把 skb 送到 socket，并且只在 TC ingress 有效；见 [`include/uapi/linux/bpf.h` 第 4595–4621 行](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/include/uapi/linux/bpf.h#L4595-L4621)。
- `sk_lookup` 版本只能选择兼容的 TCP listener 或未连接 UDP socket，L4 protocol 必须精确匹配；见[第 4623–4640 行](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/include/uapi/linux/bpf.h#L4623-L4640)。

TC 的 `bpf_redirect` 可以把 skb 送到另一网络设备，`BPF_F_INGRESS` 选择目标设备的 ingress 方向；见[内核 helper 文档](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/include/uapi/linux/bpf.h#L2492-L2513)。dae 的 `dae0` 回程正是利用这个语义。

## 路由、namespace 和权限边界

dae 把数据路径放进 `daens` network namespace，用 `dae0`/`dae0peer` netkit 或 veth 对连接主机与 namespace。namespace 内建立 local default route，并用 fwmark 规则把包送入 TPROXY listener：[路由和 namespace 建立代码](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/netns_utils.go#L477-L639)。相关 sysctl 包括 `rp_filter=0`、`arp_filter=0`、`accept_local=1` 和 forwarding：[配置代码](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/netns_utils.go#L824-L868)。官方排障文档确认，被劫持的包不会经过主机 INPUT，而是在 dae namespace 和接口间转发：[troubleshooting.md 第 62–70 行](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/docs/en/troubleshooting.md#L62-L70)。

dae 的 direct 路径不做 SNAT；官方工作原理文档明确提示 side-router 场景可能出现非对称回程：[第 141–173 行](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/docs/en/how-it-works.md#L141-L173)。PathChord 的 eBPF 后端若覆盖 LAN/WAN 转发，也必须明确是否保留源地址、谁负责回程以及 firewall/conntrack 如何观察这些包。

权限不能只抽象成“加载一段 BPF 程序”。Linux 内核当前源码把 `SCHED_CLS`、`SK_SKB`、`CGROUP_SOCK_ADDR` 等网络程序列为需要 network-admin 能力的类型，并在加载时分别检查 `CAP_BPF` 与 `CAP_NET_ADMIN`：[kernel/bpf/syscall.c 第 2878–2905 行](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/kernel/bpf/syscall.c#L2878-L2905)、[第 2995–3026 行](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/kernel/bpf/syscall.c#L2995-L3026)。`bpf_capable()` 以 `CAP_BPF` 或 `CAP_SYS_ADMIN` 满足 BPF 能力，`bpf_net_capable()` 以 `CAP_NET_ADMIN` 或 `CAP_SYS_ADMIN` 满足网络能力：[include/linux/capability.h 第 195–203 行](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/include/linux/capability.h#L195-L203)、[include/linux/bpf.h 第 3777–3780 行](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/include/linux/bpf.h#L3777-L3780)。此外，创建 network namespace、netkit/veth、TC link、路由和 sysctl 还有独立的系统权限边界。

dae 官方没有声明一组经过最小化验证的 capability 列表：其 systemd 服务使用 [`User=root`](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/install/dae.service)，Docker 示例使用 [`privileged: true`、host network 和 `/sys` 挂载](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/docker-compose.yml)。因此，PathChord 设计文档应把上面的 capability 视为内核操作推导出的权限要求，不应声称它们是 dae 官方公布的最小清单。

## 内核版本和配置约束

dae 官方安装文档要求 Linux kernel 5.17 或更高，并列出 BPF、BPF syscall/JIT、cgroup、KPROBES、NET ingress/egress、cls_bpf、TC action、BPF stream parser、BTF 等配置：[README 第 5–55 行](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/docs/en/README.md#L5-L55)。其理由之一是 eBPF 路由使用 `bpf_loop`：[工作原理文档第 39–43 行](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/docs/en/how-it-works.md#L39-L43)。

dae 还在源码中区分可选能力：TCX 需要较新的内核，netkit 和 `bpf_redirect_peer` 有更高版本或修复要求；因此不能把“支持 eBPF”简化成一个布尔平台条件。主程序在加载时检查这些能力：[control plane 的能力检查](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/control_plane.go#L390-L427)；版本常量和回退边界见[`common/consts/ebpf.go`](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/common/consts/ebpf.go#L83-L105)。

Linux 官方程序类型表也显示这些能力属于不同 attach family：cgroup socket-address、TC `SCHED_CLS`、`SK_LOOKUP` 和 `SK_SKB` 是不同的程序类型与 attach section，不能互换：[program types 表第 26–49 行](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/Documentation/bpf/libbpf/program_types.rst#L26-L49)、[第 154–183 行](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/Documentation/bpf/libbpf/program_types.rst#L154-L183)。

## 与 PathChord 当前实现的对应关系

PathChord 已经具备 eBPF 后端所需的多个用户态接口，这支持“可选后端”方向，但也说明直接改成 eBPF 并不能删掉现有层：

| 责任 | PathChord 当前定位 | 与 dae/eBPF 的关系 |
| --- | --- | --- |
| TCP 透明 listener | [`LinuxTransparentTcpListener::bind`](../../crates/pathchord-ingress/src/linux_transparent.rs#L38-L89) 设置 TPROXY 的 `IP_TRANSPARENT`，并在 [`original_destination`](../../crates/pathchord-ingress/src/linux_transparent.rs#L97-L115) 使用 TPROXY 的 `local_addr` | 可继续复用；TC eBPF 只把包送到 listener，不替代 accept/flow context。 |
| UDP 原目标 | [`LinuxTproxyUdpSocket::bind`](../../crates/pathchord-ingress/src/linux_tproxy_udp.rs#L110-L137) 设置透明 UDP socket；[`receive_ready`](../../crates/pathchord-ingress/src/linux_tproxy_udp.rs#L140-L195) 解析 IPv4/IPv6 original-destination cmsg | 与 dae 的 UDP OOB 方案相同，eBPF 仍需要把 datagram 正确送到该 socket。 |
| mark/rule/table | [`LinuxTransparentRouteManager::apply`](../../crates/pathchord-ingress/src/linux_routing.rs#L183-L221) 预检、写 journal、安装 rule/route；[`restore`](../../crates/pathchord-ingress/src/linux_routing.rs#L223-L300) 负责恢复 | eBPF TC 路径仍需要 fwmark/local route；若采用 dae 的 netns/veth 方案，还会新增接口和回程状态管理。 |
| 平台隔离 | [`IngressPlatformFactories`](../../crates/pathchord-ingress/src/platform_runtime.rs#L154-L182) 将 TUN、路由、透明 UDP 等平台能力注入 | `LinuxEbpfInterception` 仅作为 Linux 平台 owner，而不是把 eBPF 放进跨平台核心。 |
| TUN | [`TunFlowRuntime`](../../crates/pathchord-ingress/src/tun_netstack.rs#L119-L218) 使用 smoltcp 从 TUN 包重建 TCP/UDP flow | eBPF TC 重定向不能替代 TUN 的 IP stack；两者应保持独立。 |

当前仓库的架构约束也要求保留 Windows/FreeBSD 的显式 listener 路径；因此 eBPF 只能是 Linux 平台实现，而不能成为 `pathchord-core` 的通用抽象。相关平台能力判断见[`validate_listener_platforms`](../../crates/pathchord-ingress/src/platform_runtime.rs#L869-L887)。

## 是否应采用 eBPF 后端

### 推荐方案

1. 保留现有 socket/route 后端作为 Linux 默认和回退路径，继续复用透明 TCP/UDP listener、原目标提取、policy engine、UDP association 和 route journal。
2. 新增 Linux 专用、显式启用的 TC eBPF 后端。第一版只负责稳定的 L3/L4 分类、受保护端点绕过、TCP SYN/UDP datagram 到 listener 的 redirect/assign，以及必要的 per-flow map；不要一开始把所有路由表达式、嗅探、TCP relay offload 都搬进 BPF。
3. 把 eBPF 能力探测拆成独立状态：`BPF syscall`、TC/TCX 或 classic cls_bpf、`bpf_sk_assign`、BTF/CO-RE、可选 netkit，以及所需 capability。任何一项不满足都返回 typed diagnostic 并回退。
4. 先覆盖 host-local TPROXY，再评估 LAN/WAN 转发。若要复制 dae 的 side-router 路径，必须另外实现 interface/MAC/tuple reply tracking、`BPF_F_INGRESS` 回送、namespace/veth 生命周期以及和 conntrack/firewall 的兼容性。
5. 在真实 Linux 主机验证 IPv4/IPv6 TCP/UDP、已建立连接、DNS、源限制、protected endpoint、reload、异常退出、route journal 恢复、map 满载和内核版本矩阵后，才考虑把 eBPF 设为某些 Linux profile 的默认后端。

### 不推荐的方案

- 不要只实现 `sk_lookup`：它看不到已建立 TCP 和已连接 UDP，且无法取代 TC 前置分类、原目标保存和回程绑定。
- 不要把 cgroup connect/sendmsg 当作 LAN 透明代理：这些 hook 适合本机 socket 元数据，不覆盖经过主机转发的设备流量。
- 不要把 `bpf_sk_assign` 当作完整代理：内核 helper 要求配合路由，且只选择兼容 listener；策略决策、目标地址和业务 Stream/Datagram 生命周期仍在用户态。
- 不要把 dae 的 netkit/veth/MAC 回程方案直接复制到所有平台。Windows 和 FreeBSD 没有对应的 Linux TC/cgroup/netns ABI，应继续使用平台原生 listener/redirect 实现。

因此，PathChord 采用 eBPF 的正确边界是“Linux 上可回退的透明数据路径加速器”，而不是“用 eBPF 重新实现整个透明代理或整个 PathChord runtime”。

## 关键来源索引

- dae 官方透明代理说明：[how-it-works.md](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/docs/en/how-it-works.md)
- dae 官方 kernel 要求：[docs/en/README.md](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/docs/en/README.md)
- dae TC/eBPF 程序：[control/kern/tproxy.c](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/kern/tproxy.c)
- dae hook 安装：[control_plane_core_bind.go](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/control_plane_core_bind.go)、[tc_hook_set.go](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/tc_hook_set.go)
- dae namespace/路由：[netns_utils.go](https://github.com/daeuniverse/dae/blob/460cec77f4365abfd9ea6fae04b66466dd4861cb/control/netns_utils.go)
- Linux `sk_lookup`：[Documentation/bpf/prog_sk_lookup.rst](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/Documentation/bpf/prog_sk_lookup.rst)
- Linux BPF helper/UAPI：[include/uapi/linux/bpf.h](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/include/uapi/linux/bpf.h)
- Linux program types：[Documentation/bpf/libbpf/program_types.rst](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/Documentation/bpf/libbpf/program_types.rst)
- Linux BPF capability checks：[kernel/bpf/syscall.c](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/kernel/bpf/syscall.c)、[include/linux/capability.h](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/include/linux/capability.h)、[include/linux/bpf.h](https://github.com/torvalds/linux/blob/97d73c8251226cf27cc6656b4c542869bb8c69fa/include/linux/bpf.h)
