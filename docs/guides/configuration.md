# Configuration guide

**English** | [简体中文](configuration.zh-CN.md)

Start with the example closest to your routing goal, then split it into files if that makes it easier to maintain. This guide explains the configuration workflow; the authoritative fields, defaults, and validation rules are in the [configuration schema](../../openspec/specs/configuration-schema/spec.md).

## Choose a starting example

| Goal | Example | What to change |
| --- | --- | --- |
| Local HTTP/SOCKS proxy with direct target connections | [ingress-direct.yaml](../../examples/ingress-direct.yaml) | The Mixed listener binds `127.0.0.1:7890`; DNS uses the configured local resolver and unmatched traffic goes direct. |
| Ordinary proxy nodes from a subscription | [ingress-subscriptions.yaml](../../examples/ingress-subscriptions.yaml) | Replace the provider URL. The ProxyRule selects an available node; the fallback rejects unmatched traffic. |
| Forward through an enrolled Egress | [ingress-egress.yaml](../../examples/ingress-egress.yaml) | Set the Egress address and verified public key, then complete enrollment using the [deployment guide](deployment.md). |
| Linux transparent TCP/UDP interception | [ingress-tproxy.yaml](../../examples/ingress-tproxy.yaml) | Review the listener address, packet mark, routing table, and host packet-filter setup. |
| Linux interception with the optional eBPF classifier | [ingress-tproxy-ebpf.yaml](../../examples/ingress-tproxy-ebpf.yaml) | Replace `lan0` and `192.168.1.0/24` with the actual ingress interface and allowed source network. |
| TCP/UDP flows from a TUN interface | [ingress-tun.yaml](../../examples/ingress-tun.yaml) | Review the interface name, `198.18.0.1/30` address, platform support, and host routes. |

Transparent and TUN examples need platform privileges and host routing setup. The [deployment guide](deployment.md) covers those prerequisites, service startup, and enrollment commands. FreeBSD supports explicit HTTP, SOCKS, and Mixed listeners; transparent and TUN listeners are outside its platform contract.

## Select a configuration source

With `pathchord` on `PATH`, run one of these commands. Example paths are relative to the repository root; replace the directory placeholder with your own resource directory.

```sh
pathchord ingress --config examples/ingress-direct.yaml
pathchord ingress --config-dir /path/to/conf.d
PATHCHORD_CONFIG_DIR=/path/to/conf.d pathchord ingress
pathchord ingress
```

Source selection follows this order:

1. Explicit `--config` (`-c`) or `--config-dir` (`-C`). Choose one: `--config` accepts a file or directory, while `--config-dir` requires a directory. An explicit command-line source overrides configuration environment variables, including a conflict between them.
2. Non-empty `PATHCHORD_CONFIG` or `PATHCHORD_CONFIG_DIR`, with the same file/directory meanings. Set only one when no explicit source is supplied.
3. The account default: `~/.config/pathchord` for a regular user, or `/etc/pathchord` for root/service accounts. There is no working-directory configuration fallback. The [source-selection contract](../../openspec/specs/configuration-schema/spec.md#configuration-sources) defines account classification and home-directory resolution.

Native service packages may select a configuration directory explicitly in their service command; check the installed service definition when editing a packaged deployment.

## Build one resource graph

A single file can contain several YAML documents separated by `---`, as the examples do. A directory can hold the same resources in separate `.yaml`, `.yml`, and `.json` files, including subdirectories. All those files form one configuration, so use a separate directory for each complete deployment rather than placing several complete examples together.

The basic direct example has three resources:

- `Listener` chooses how applications enter PathChord. The example's `mixed` listener accepts HTTP and SOCKS on one TCP endpoint; SOCKS5 UDP uses its negotiated relay endpoint. Keep its loopback bind for local applications, or configure appropriate source restrictions and authentication before exposing it to other hosts.
- `DNSPolicy` chooses how DNS queries reach their resolver. It is independent of ordinary connection routing. Change `local.servers` to use your own resolver; the [platform and DNS contract](../../openspec/specs/platform-and-dns/spec.md#dns-configuration) explains the other routes.
- `FallbackPolicy` decides what happens after no earlier route wins. Use `direct` for an intentional direct fallback or `reject` to refuse unmatched flows.

Add `Subscription` and `ProxyRule` resources for ordinary third-party proxy routing backed by a subscription. Add `Egress`, `EgressRule`, `TransitRule`, and a suitable `TrafficPolicy` for a controlled Egress route. Routing considers effective Egress rules first, then ordinary Proxy rules, then the global fallback. See the [configuration model](../../openspec/specs/configuration/spec.md) for these relationships and the [Transit Proxy contract](../../openspec/specs/transit-proxies/spec.md) for supported node options and subscription formats.

Resources refer to one another by `metadata.name` within their namespace. Names and explicit rule order determine the graph; filenames do not provide override layers. Duplicate resource identities or unresolved references reject the candidate configuration. Keep exactly one `DNSPolicy` and one `FallbackPolicy` across the whole graph.

## Keep credentials separate

Store private identities, node/listener credential JSON, subscription caches, and the service data directory outside the resource tree. The directory loader also reads JSON, so placing a private JSON document among configuration resources can make the bundle invalid. Use opaque `credentialsRef` values to refer to the local credential store. Keep passwords and subscription tokens out of committed examples; treat provider URLs that contain credentials as private configuration.

The [deployment guide](deployment.md) explains credential-file setup. The [Transit Proxy contract](../../openspec/specs/transit-proxies/spec.md) defines which adapter consumes each option and how unsupported nodes are reported. Check individual node diagnostics after importing a subscription; an imported protocol name alone does not establish that the node is usable.

## Reload configuration and handle failures

The service watches additions, edits, removals, and renames in a selected resource directory and validates the entire candidate before publishing it. Atomic file replacement is supported. If parsing, graph validation, rule compilation, persistence, or cache writing fails, the last successful configuration remains active; inspect structured status for the failure, fix the candidate, and let it reload.

Subscription nodes, compiled dynamic rules, administrator labels/tags, and DNS runtime health can update dynamically. Changes to static Egress topology, local private keys, listener bind settings, or platform routing settings require a service restart. Moving unchanged resources between files does not change their identity or require restart. New flows use a single published generation for their complete route decision; existing resources follow their admission and normal drain/failure rules.

Management changes to a declared subscription remain effective across reload and restart while its declaration is unchanged. Editing or removing the declaration applies the corresponding new desired state. The [reload contract](../../openspec/specs/configuration-schema/spec.md#snapshot-publication-and-reload) provides the exact publication and ownership rules.
