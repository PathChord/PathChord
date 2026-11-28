# PathChord

**English** | [简体中文](README.zh-CN.md)

Adaptive multipath proxy with Ingress, Transit Proxy, and Egress.

PathChord provides ordinary proxy semantics to local applications while maintaining multiple replaceable transit paths between an Ingress and a selected Egress.

## Status

The repository contains the design baseline, the `wire-profile-v1` protocol
contract, Kubernetes-style configuration contracts, and a runnable Rust
implementation. Ingress can bind HTTP, SOCKS5, Linux transparent, and TUN
listeners, maintain durable control state, refresh subscription-backed Transit
Proxies, and route TCP/UDP flows through authenticated Session/Path runtimes.
Egress exposes the authenticated Path listener and authorization control plane;
the optional REST/SSE Web Gateway is shared by both control planes.

Linux, Windows, and FreeBSD support explicit HTTP, SOCKS4/4a/5 and Mixed
listeners. HTTP supports forwarding, CONNECT, streaming bodies, persistent
requests and Upgrade. SOCKS5 supports UDP ASSOCIATE. The `socks` spelling is
an alias for `socks5`. Use `type: mixed` to serve HTTP and SOCKS on one TCP
port. Explicit listeners and local control passed native QEMU tests on Windows
and FreeBSD.

On Linux, TPROXY, REDIRECT and TUN passed privileged QEMU tests, including
real TUN devices and optional eBPF interception. TPROXY defaults to the
`tproxy` backend and also supports `backend: ebpf` on a selected interface.
FreeBSD rejects transparent and TUN listeners. Windows has a TUN adapter,
with Wintun packaging and native TUN validation still pending. See the
[implementation status](openspec/implementation-status.md) for host versions,
package results and validation limits.

Node imports support automatic detection, Clash/Mihomo providers, SIP008,
URI/Base64 lists, sing-box JSON, and supported Surge/Quantumult X/Loon node
lines. Native transports support typed TLS settings, VLESS/Trojan TCP/TLS/
WebSocket and HTTPUpgrade transports, VLESS + REALITY and XTLS Vision flows, VMess TCP/TLS/WebSocket/HTTPUpgrade with AEAD or AES-128-CFB body
records and single-target UDP, AnyTLS TCP plus UDP-over-TCP framing, native
Hysteria2 TCP/UDP with Salamander and port hopping, and TUIC TCP/UDP with
heartbeats. Native h2mux, yamux and smux support eligible Shadowsocks, VLESS,
VMess, and Trojan nodes. smux FIN follows the peer's full-close semantics and
does not provide TCP half-close compatibility. Direct/SOCKS5/Shadowsocks UDP,
including SS2022, remain available. The REALITY adapter supports dae Chrome 133, iOS 14,
Safari 16, Edge 85, QQ 11.1 and Firefox 120 fingerprints;
other unsupported options produce individual diagnostics. See the
[Transit Proxy and subscription contract](openspec/specs/transit-proxies/spec.md) for
the exact compatibility boundaries and [deployment guide](docs/guides/deployment.md)
for runnable configurations.

## Terminology

- **Ingress**: local traffic entry point and policy engine.
- **Transit Proxy**: an uncontrolled proxy transport used to reach an Egress.
- **Egress**: a controlled logical network interface and final traffic exit.
- **Session**: shared logical session between one Ingress and one Egress.
- **Path**: a long-lived bidirectional connection carried by one Transit Proxy.
- **Stream**: a logical TCP byte stream carried over one Session.

## Documentation

`docs/` contains design documents and user guides. OpenSpec owns the behavior
contracts, implementation status, and change tracking. Each document has one
maintained home: guides link to exact contracts rather than duplicating their
schemas, and pending work lives in change tasks rather than a parallel plan.
Designs, guides, and capability specs have English and Simplified Chinese
versions; planning artifacts and the implementation-status snapshot use English.

### User guides

- [Configuration guide](docs/guides/configuration.md)
- [Deployment and local operation](docs/guides/deployment.md)
- [Runtime observability and diagnostics](docs/guides/observability.md)
- [Native packages](packaging/README.md)
- [Monitoring deployment](monitoring/README.md)

### Design

- [Architecture](docs/design/architecture.md)
- [Technology selection](docs/design/technology-selection.md)

### Capability specifications

- [Protocol](openspec/specs/protocol/spec.md)
- [Wire profile v1](openspec/specs/wire-profile/spec.md)
- [Configuration model](openspec/specs/configuration/spec.md)
- [Configuration schema](openspec/specs/configuration-schema/spec.md)
- [Geosite and GeoIP routing](openspec/specs/geodata-routing/spec.md)
- [Platform and DNS](openspec/specs/platform-and-dns/spec.md)
- [State machines](openspec/specs/state-machines/spec.md)
- [Ingress control plane](openspec/specs/ingress-control-plane/spec.md)
- [Ingress observability](openspec/specs/observability/spec.md)
- [Transit Proxies and subscriptions](openspec/specs/transit-proxies/spec.md)
- [Deployment behavior](openspec/specs/deployment/spec.md)

### Implementation evidence

- [Implementation and validation status](openspec/implementation-status.md)

### Active changes

Run `openspec list` to see active changes. Completed proposals, tasks and
research are in the [change archive](openspec/changes/archive/).

## OpenSpec workflow

Use OpenSpec to discover the existing contracts and current changes:

```sh
openspec list --specs
openspec list
openspec validate --all --strict --no-interactive
```

Start a focused change with `openspec new change <name>`. Use that same name
with `openspec status --change <name>` to check the proposal, design, and
task checklist as you write them. Changes to behavior include canonical
English deltas under `specs/<capability>/spec.md`; work that only implements,
validates, or reorganizes an existing contract uses `skip_specs: true` in
`.openspec.yaml`. The [OpenSpec project configuration](openspec/config.yaml)
records the artifact rules.

Implement and verify the tracked tasks, keeping the implementation-status
snapshot accurate. Before archiving with `openspec archive <name>`, synchronize
the main English specs, their complete technical contracts, matching Chinese
specs, and affected design/user documents. Completed change history belongs in
`openspec/changes/archive/`.

## Command surface

Packaged deployments select one role per device: `pathchord-ingressd` on a
client or `pathchord-egressd` on an exit host. Each role package includes
`pathchordctl` and uses the local `pathchord` service account on Unix.

`pathchord-ingressd` defaults to `~/.config/pathchord/ingress` for regular users
and `/etc/pathchord/ingress` for packaged services. `--config-dir` loads
YAML/YML/JSON resources recursively as one validated bundle. Egress uses a
separate `EgressService` source under `~/.config/pathchord/egress` or
`/etc/pathchord/egress`. Selection priority is command line, then
`PATHCHORD_CONFIG`/`PATHCHORD_CONFIG_DIR`, then the role account default.

```text
pathchord-ingressd
pathchord-ingressd --config-dir /path/to/ingress
pathchord-egressd --config-dir /path/to/egress
pathchordctl get status
pathchordctl get status -o json
pathchordctl enroll list
```

`pathchord-ingressd` starts configured listeners, the durable local control
socket, the subscription worker, and any requested Web Gateway.
`pathchord-egressd` starts the authenticated Path listener and authorization
control socket. `pathchordctl` queries or mutates either endpoint. The direct
target bridge remains available only for an explicit policy with no
Egress/Transit route.

## Packages

Native package recipes are kept under [`packaging/`](packaging/README.md) for
Debian (`.deb`), Alpine (`.apk`), Arch Linux (`.pkg.tar.*`), FreeBSD (`.pkg`),
and Windows NSIS (`.exe`). A machine installs one role package: each carries
only its selected daemon, `pathchordctl`, matching service definition and
role-specific configuration. Role packages are mutually exclusive; remove the
installed role explicitly before switching. Published releases and nightly
builds attach the available native packages alongside the binary archives and a
shared `SHA256SUMS` file. Build the selected daemon together with
`pathchordctl` and select `ROLE=ingress` or `ROLE=egress` with `make -C
packaging`; the package guide documents native host tools and precompiled
artifact overrides.

## Development

Development and CI use Rust 1.100.1 with rustfmt and Clippy. The workspace
requires Rust 1.100.0 or later.

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo run -p pathchordctl -- --help
```

Run the documentation checks from the repository root. The example check uses
Cargo to run `pathchordctl`.

```sh
npx --yes markdownlint-cli2@0.24.2
python3 scripts/check-doc-contracts.py
python3 scripts/check-doc-examples.py
openspec validate --all --strict --no-interactive
```

The [repository guidelines](AGENTS.md#build-test-and-development-commands) explain
how to mark complete YAML examples for validation.

The workspace disables rustc incremental artifacts in dev/test profiles so a configured `RUSTC_WRAPPER=sccache` can reuse complete compilation units. The repository does not require a machine-specific wrapper; local Cargo configuration decides whether sccache is available.
