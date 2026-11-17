# Configuration guide

**English** | [简体中文](configuration.zh-CN.md)

Start with the example closest to your routing goal, then split it into files if that makes it easier to maintain. This guide explains the configuration workflow; the authoritative fields, defaults, and validation rules are in the [configuration schema](../../openspec/specs/configuration-schema/spec.md).

## Choose a starting example

| Goal | Example | What to change |
| --- | --- | --- |
| Local HTTP/SOCKS proxy with direct target connections | [ingress-direct.yaml](../../examples/ingress-direct.yaml) | The Mixed listener binds `127.0.0.1:7890`; DNS uses the configured local resolver and unmatched traffic goes direct. |
| Ordinary proxy nodes from a subscription | [ingress-subscriptions.yaml](../../examples/ingress-subscriptions.yaml) | Replace the provider URL. The ProxyRule selects an available node; the fallback rejects unmatched traffic. |
| Forward through an enrolled Egress | [ingress-egress.yaml](../../examples/ingress-egress.yaml) | Set the Egress address and verified public key, then complete enrollment using the [deployment guide](deployment.md). |
| Egress service limits and private paths | [egress-service.yaml](../../examples/egress-service.yaml) | Use this source only with `pathchord-egressd`; keep the referenced identity and database outside the resource tree. |
| Linux transparent TCP/UDP interception | [ingress-tproxy.yaml](../../examples/ingress-tproxy.yaml) | Review the listener address, packet mark, routing table, and host packet-filter setup. |
| Linux interception with the optional eBPF classifier | [ingress-tproxy-ebpf.yaml](../../examples/ingress-tproxy-ebpf.yaml) | Replace `lan0` and `192.168.1.0/24` with the actual ingress interface and allowed source network. |
| TCP/UDP flows from a TUN interface | [ingress-tun.yaml](../../examples/ingress-tun.yaml) | Review the interface name, `198.18.0.1/30` address, platform support, and host routes. |

Transparent and TUN examples need platform privileges and host routing setup. The [deployment guide](deployment.md) covers those prerequisites, service startup, and enrollment commands. FreeBSD supports explicit HTTP, SOCKS, and Mixed listeners; transparent and TUN listeners are outside its platform contract.

## Select a configuration source

With the role executables on `PATH`, run one of these commands. Example paths are relative to the repository root; replace the directory placeholder with your own resource directory.

```sh
pathchord-ingressd --config examples/ingress-direct.yaml
pathchord-ingressd --config-dir /path/to/ingress
PATHCHORD_CONFIG_DIR=/path/to/ingress pathchord-ingressd
pathchord-egressd --config examples/egress-service.yaml
```

Source selection follows this order:

1. Explicit `--config` (`-c`) or `--config-dir` (`-C`). Choose one: `--config` accepts a file or directory, while `--config-dir` requires a directory. An explicit command-line source overrides configuration environment variables, including a conflict between them.
2. Non-empty `PATHCHORD_CONFIG` or `PATHCHORD_CONFIG_DIR`, with the same file/directory meanings. Set only one when no explicit source is supplied.
3. The role account default: `~/.config/pathchord/ingress` or `/etc/pathchord/ingress` for Ingress, and `~/.config/pathchord/egress` or `/etc/pathchord/egress` for Egress. There is no working-directory configuration fallback. The [source-selection contract](../../openspec/specs/configuration-schema/spec.md#configuration-sources) defines account classification and home-directory resolution.

Native service packages may select a configuration directory explicitly in their service command; check the installed service definition when editing a packaged deployment.

## Build one resource graph

A single file can contain several YAML documents separated by `---`, as the examples do. A directory can hold the same resources in separate `.yaml`, `.yml`, and `.json` files, including subdirectories. All those files form one configuration, so use a separate directory for each complete deployment rather than placing several complete examples together.

The basic direct example has three resources:

- `Listener` chooses how applications enter PathChord. The example's `mixed` listener accepts HTTP and SOCKS on one TCP endpoint; SOCKS5 UDP uses its negotiated relay endpoint. Keep its loopback bind for local applications, or configure appropriate source restrictions and authentication before exposing it to other hosts.
- `DNSPolicy` chooses how DNS queries reach their resolver. It is independent of ordinary connection routing. Change `local.servers` to use your own resolver; the [platform and DNS contract](../../openspec/specs/platform-and-dns/spec.md#dns-configuration) explains the other routes.
- `FallbackPolicy` decides what happens after no earlier route wins. Use `direct` for an intentional direct fallback or `reject` to refuse unmatched flows.

Add `Subscription` and `ProxyRule` resources for ordinary third-party proxy routing backed by a subscription. Add `Egress`, `EgressRule`, a common `transit` binding, and a suitable `TrafficPolicy` for a controlled Egress route. Routing considers effective Egress rules first, then ordinary Proxy rules, then the global fallback. Every flow selecting one Egress shares that Egress's Session Path pool and TrafficPolicy. See the [configuration model](../../openspec/specs/configuration/spec.md) for these relationships and the [Transit Proxy contract](../../openspec/specs/transit-proxies/spec.md) for supported node options and subscription formats.

Resources refer to one another by `metadata.name` within their namespace. Names and explicit rule order determine the graph; filenames do not provide override layers. Duplicate resource identities or unresolved references reject the candidate configuration. Keep exactly one `DNSPolicy` and one `FallbackPolicy` across the whole graph.

## Route with geosite and geoip sets

Geosite and geoip use operator-provided V2Fly databases. Obtain a pinned
`dlc.dat` release from [domain-list-community](https://github.com/v2fly/domain-list-community/releases)
and `geoip.dat` from [v2fly/geoip](https://github.com/v2fly/geoip/releases).
Download each file and the corresponding `*.sha256sum` from the same release,
then verify it with `sha256sum -c` in the download directory. Place the verified
`.dat` files where the Ingress service account can read them. Keep a copy of
the previous verified versions for rollback. PathChord reads local files; it
does not download or update these databases automatically.

For example, replace the tag placeholders with selected release tags and run
the following in a private staging directory:

```sh
site_tag=REPLACE_WITH_DOMAIN_LIST_RELEASE_TAG
ip_tag=REPLACE_WITH_GEOIP_RELEASE_TAG
curl -fsSLO "https://github.com/v2fly/domain-list-community/releases/download/${site_tag}/dlc.dat"
curl -fsSLO "https://github.com/v2fly/domain-list-community/releases/download/${site_tag}/dlc.dat.sha256sum"
curl -fsSLO "https://github.com/v2fly/geoip/releases/download/${ip_tag}/geoip.dat"
curl -fsSLO "https://github.com/v2fly/geoip/releases/download/${ip_tag}/geoip.dat.sha256sum"
sha256sum -c dlc.dat.sha256sum
sha256sum -c geoip.dat.sha256sum
```

Add the following resources and rules to a complete bundle that already defines
the Egress `egress-jp-1`, its common Transit binding, and its TrafficPolicy:

```yaml
apiVersion: pathchord.io/v1
kind: GeoSiteDatabase
metadata: {name: sites}
spec: {path: /var/lib/pathchord/geodata/dlc.dat}
---
apiVersion: pathchord.io/v1
kind: GeoIpDatabase
metadata: {name: addresses}
spec: {path: /var/lib/pathchord/geodata/geoip.dat}
---
apiVersion: pathchord.io/v1
kind: EgressRule
metadata: {name: huggingface-egress}
spec:
  order: 10
  match:
    targetGeoSites: [huggingface]
  egressRef: egress-jp-1
---
apiVersion: pathchord.io/v1
kind: EgressRule
metadata: {name: geoip-example}
spec:
  order: 20
  match:
    targetGeoIps: [cn]
  egressRef: egress-jp-1
```

The first rule covers names in the upstream `huggingface` set, including
subdomains of `hf.co` such as `us.aws.cdn.hf.co`. The second rule is an example
for an IP-targeted flow; choose the set and Egress that fit your policy. Each
database belongs to the same namespace as the rules that use it. Geosite can
also select an attribute with `set@attribute`, for example `google@ads` when
that attribute exists in the verified database. See the
[geodata contract](../../openspec/specs/geodata-routing/spec.md) for matching
types and the [configuration schema](../../openspec/specs/configuration-schema/spec.md#geodata-databases)
for limits and field rules.

The explicit forms `geosite:huggingface` and `geoip:cn` are also accepted in
their respective fields; they refer to the same sets as the short names above.

Geosite uses the original hostname supplied by the listener. GeoIP uses the
original destination IP, such as the address of a transparent flow. A request
that supplies only a hostname does not acquire a GeoIP match through a DNS
lookup; a flow that supplies only an IP does not acquire a geosite match.
Values within one match field are alternatives, while different populated match
fields are combined. Use separate ordered rules when either a hostname set or
an IP set should select the route. `targetHosts` retains exact-match behavior.

Keep database files outside a scanned configuration directory or use an
unscanned extension such as `.dat`. Resolve relative database paths against the
selected configuration file's parent or selected configuration directory.
For an update, download and verify the new release separately, then atomically
replace the configured file. Ingress validates the full candidate before
publishing rules and data together. If validation fails, inspect reload status;
the previous generation remains active. To roll back, atomically restore the
previous verified file and the matching configuration, then verify reload
status and the selected route.

## Keep credentials separate

Store private identities, node/listener credential JSON, subscription caches, and the service data directory outside the resource tree. The directory loader also reads JSON, so placing a private JSON document among configuration resources can make the bundle invalid. Use opaque `credentialsRef` values to refer to the local credential store. Keep passwords and subscription tokens out of committed examples; treat provider URLs that contain credentials as private configuration.

Subscription servers may return different formats for different HTTP clients.
Set the optional `spec.source.userAgent` on a Subscription to the value your
provider expects; it defaults to `clash.meta`. Changing it triggers a new
source refresh and prevents reuse of cached content fetched with another value.

The [deployment guide](deployment.md) explains credential-file setup. The [Transit Proxy contract](../../openspec/specs/transit-proxies/spec.md) defines which adapter consumes each option and how unsupported nodes are reported. Check individual node diagnostics after importing a subscription; an imported protocol name alone does not establish that the node is usable.

For Hysteria2 Gecko, optional private credential fields
`gecko_min_packet_size` and `gecko_max_packet_size` select the long-header
fragment padding range; omitted or zero values use 512 and 1200 bytes. The
peer must accept the chosen wire size. In local tests, sing-box 1.14.4 peers
could exchange fixed 1452-byte Gecko packets but their 2048-byte setting did
not complete a handshake; an independent sing-quic relay did accept 2048.
The chosen size must also fit the network path. On Linux, PathChord's QUIC
socket disables IP fragmentation; with a 1500-byte MTU and no additional
encapsulation, UDP payloads above 1472 bytes over IPv4 or 1452 bytes over IPv6
do not fit. Such Gecko fragments can be dropped and appear as a handshake
timeout. Tunnels or smaller path MTUs can require lower settings. The local
2048-byte relay test used loopback and does not verify a 1500-byte path.

For SOCKS5 or Shadowsocks UDP-over-TCP, set `spec.options.udpOverTcpVersion` to `1` or
`2`; omit it for the adapter's ordinary UDP transport. When an imported Clash
node enables UDP-over-TCP without a version it uses v1; an imported sing-box
node uses v2. Ensure UDP is enabled on the node. For VMess, `spec.options.vmess.globalPadding` and
`authenticatedLength` enable the corresponding AEAD framing options. A Meek
node uses `spec.options.transport.type: meek` and a private `meek_url` field in
its credential JSON. An HTTP CONNECT request path likewise belongs in the
private `http_path` credential field. Keep these URLs and paths out of public
resource documents.

To use native multiplexing for a Shadowsocks, VLESS, VMess, or Trojan node,
set `spec.options.multiplex.enabled: true` and select `h2mux`, `yamux`, or `smux` in
`spec.options.multiplex.protocol`; omission selects `h2mux`. Multiplex cannot
be combined with explicit `packetEncoding` or `udpOverTcpVersion`; set
`spec.options.multiplex.padding: true` when the peer requires sing-mux padding.
An unavailable combination is reported in the node diagnostic. Imported
Clash/Mihomo and sing-box VLESS nodes normally default to XUDP, but when they
enable multiplex its UDP framing is used. For an authored VLESS node without
multiplex, omitting `packetEncoding` selects plain VLESS UDP, or XUDP when a
Vision flow is set. Vision cannot use `packetaddr`; use the
`xtls-rprx-vision-udp443` flow when the node must carry UDP to port 443.
If a multiplexed UDP association closes before the peer confirms it, close
reports an error even though a sent datagram may already have arrived.

Use `smux` only when its full-close behavior fits the application: a FIN does
not provide a reliable TCP write-half close, and a response sent by the target
after that FIN may not arrive. Each smux session supports up to 256 streams and
has separate 4 MiB receive and transmit queue budgets. A slow receiver can be
closed with a resource error and FIN to keep other streams moving. An active
stream on a stalled carrier needs cancellation by its caller or a higher-level
timeout. After the last stream is released, pending I/O shares a ten-second
drain deadline. See the
[Transit Proxy contract](../../openspec/specs/transit-proxies/spec.md) for
the full limits and failure behavior.

For Hysteria2, `up_mbps` and `down_mbps` are optional nonnegative integer Mbps
fields in the private credential. `down_mbps` is a receive-rate hint that the
server can ignore. The upload setting participates in authentication: with
`up_mbps: 10`, a numeric server response of zero selects a 10 Mbps Brutal
target, while a positive response selects the smaller rate. If `up_mbps` is
omitted or zero, the client uses BBR even when the server supplies a positive
rate. The client's BBR is also used when the server responds `auto`, regardless
of `up_mbps`.

Trojan-Go share links are normalized to the native Trojan adapter. Original/TCP,
WebSocket, gRPC and HTTPUpgrade forms are supported within the tested option
set. WebSocket SS encryption uses private `trojan_go_ss_method` and
`trojan_go_ss_password` credentials and supports AES-128-GCM, AES-256-GCM and
ChaCha20-IETF-Poly1305. Original/TCP with this encryption remains unavailable:
the reference Trojan-Go server's HTTP request sniffing can wait indefinitely on
short encrypted streams. Unsupported combinations remain unavailable with a
diagnostic.

Brutal compensates for packet loss and can pace ordinary QUIC data up to 1.25
times its target. PTO probes and ACK-only packets can bypass pacing, and bursts
and outer-protocol overhead add further traffic. The setting is therefore
neither a strict physical bandwidth cap nor a guaranteed throughput; very
short RTTs and ACK timing can also reduce the achieved rate. See the
[Transit Proxy contract](../../openspec/specs/transit-proxies/spec.md) for the
complete negotiation rules and option boundaries.

## Configure Egress resource ceilings

An Egress source contains exactly one `EgressService`; it does not include
Ingress listeners, Transit Proxies, subscriptions, routing rules, DNS,
fallback, or geodata resources. Use [egress-service.yaml](../../examples/egress-service.yaml)
as the starting point. An `EgressService` authors only the global resource limits
`maxWireBandwidthBps` and `maxInboundTargetConnections`. The Egress runtime
computes its Path safety ceiling and pending reservations from these limits and
the local profile. A Path pool belongs to the Ingress-side `Egress` resource:
`pathPool.minUsablePaths` controls new-business admission, while
`pathPool.targetUsablePaths` is the best-effort baseline to maintain even when
no business connection is open. If the target is omitted, it defaults to the
minimum plus one. Set it explicitly to the total idle Path count you want; an
explicit value does not add another spare. Missing the target alone does not
degrade service or deny new flows while the minimum is met. Capacity demand may
expand above the target, and gradual scale-in returns to the baseline after
load falls. `admission.requiredCapabilities` carries common Egress capability
requirements. `EgressService` does not accept an Ingress Path target.

`EgressService` Web Gateway settings, when needed, are grouped under `web`:

```yaml
web:
  bind: 127.0.0.1:9090
  tokenFile: ../secrets/web.token
  allowedOrigins: [https://admin.example.net]
  protectedTransport: true
```

The Web Gateway remains disabled when `web` is omitted. Keep its token file
outside the configuration tree. Existing CLI options such as
`--web-token-file` continue to override the matching nested setting.

STATUS_REPORT exposes configured/effective/current capacity, capacity
confidence, admission state, and the current replication allowance; it does
not expose Ingress Path targets or rule/TrafficClass metadata.

An EgressService may use `binds` for multiple public Path listeners, including
IPv4 and IPv6 addresses on different ports. The older singular `bind` remains
valid as a one-listener shorthand. On the Ingress side, use `endpoints` when
one Egress ID has several reachable names or ports; each entry contains a
`host` and `port`. A single Egress endpoint uses the same `host`/`port` fields.
Keep the Egress ID, identity, public key, and authorization database the same
across every bind and endpoint. Endpoint topology is startup configuration
and changes require a restart.

### Migrate retired native keys

The canonical native schema has no compatibility reader. Rename authored
resources before starting or reloading with the new version; any retired key
rejects the complete candidate, including when paired with its replacement.
The exact paths, bounds, and replacement diagnostics are defined in the
[configuration schema](../../openspec/specs/configuration-schema/spec.md)
and [Transit Proxy contract](../../openspec/specs/transit-proxies/spec.md).

| Old native field | Canonical field |
| --- | --- |
| Egress `statusRequirements.minUsablePaths` | `pathPool.minUsablePaths` |
| Egress `statusRequirements.capabilities` | `admission.requiredCapabilities` |
| Egress `address` | `host` |
| Egress `endpoints[].address` | `endpoints[].host` |
| TransitProxy `address` | `host` |
| EgressService `webBind` | `web.bind` |
| EgressService `webTokenFile` | `web.tokenFile` |
| EgressService `webOrigins` | `web.allowedOrigins` |
| EgressService `webProtectedTransport` | `web.protectedTransport` |
| TransitProxy `options.transport.host` | `options.transport.hosts` |
| TransitProxy `options.transport.maxEarlyData` | `options.transport.maxEarlyDataBytes` |
| TransitProxy `options.tls.certificate` | `options.tls.certificates` |
| TransitProxy `options.tls.clientCertificate` | `options.tls.clientCertificates` |
| TransitProxy `options.tls.fingerprint` | `options.tls.clientHelloFingerprint` |
| TransitProxy `options.udpOverTcp` | `options.udpOverTcpVersion` |

Update only PathChord-authored resource keys. Clash, sing-box, and share-link
documents keep their source spellings and are normalized by the importer;
private credential JSON, HTTP header names, Listener interface addresses,
CLI flags, and protocol identifiers have separate contracts.

TLS-capable Transit nodes use system roots by default. Set the ordered
`truststore` list to `system` and/or local PEM/DER files when custom roots are
needed. Relative files resolve from the selected configuration source. An
empty list deliberately disables trust anchors, and `insecure: true` is the
only certificate-verification bypass. Invalid, oversized, directory, or bad
symlink sources reject the node instead of downgrading its transport.

## Reload configuration and handle failures

The service watches additions, edits, removals, and renames in a selected resource directory and validates the entire candidate before publishing it. Atomic file replacement is supported. If parsing, graph validation, rule compilation, persistence, or cache writing fails, the last successful configuration remains active; inspect structured status for the failure, fix the candidate, and let it reload.

Subscription nodes, compiled dynamic rules, administrator labels/tags, and DNS runtime health can update dynamically. Changes to static Egress topology, its Transit binding, Path-pool counts, admission capabilities, resolved TrafficPolicy, local private keys, listener bind settings, or platform routing settings require a service restart. Moving unchanged resources between files does not change their identity or require restart. New flows use a single published generation for their complete route decision; existing resources follow their admission and normal drain/failure rules.

Management changes to a declared subscription remain effective across reload and restart while its declaration is unchanged. Editing or removing the declaration applies the corresponding new desired state. The [reload contract](../../openspec/specs/configuration-schema/spec.md#snapshot-publication-and-reload) provides the exact publication and ownership rules.
