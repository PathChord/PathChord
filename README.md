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

Current work prioritizes HTTP CONNECT and SOCKS5 on Linux and Windows, with
FreeBSD under assessment for the same explicit listeners and Unix local
control. FreeBSD has no recorded target build or native host validation.
Transparent interception and TUN work follow this listener baseline. See the
[implementation plan](docs/progress/implementation-plan.md) for platform
validation, shared runtime gaps, and subsequent adapter work.

## Terminology

- **Ingress**: local traffic entry point and policy engine.
- **Transit Proxy**: an uncontrolled proxy transport used to reach an Egress.
- **Egress**: a controlled logical network interface and final traffic exit.
- **Session**: shared logical session between one Ingress and one Egress.
- **Path**: a long-lived bidirectional connection carried by one Transit Proxy.
- **Stream**: a logical TCP byte stream carried over one Session.

## Documentation

Design documents describe the intended architecture and durable decisions.
Specifications define the final behavioral and format contracts. The maintained
progress documents contain only current implementation status and the active
implementation plan; superseded process history is kept in Git history.
Every design and specification document is available in both English and
Simplified Chinese. Progress documents use English as their single maintained
source.

### Design

- [Architecture](docs/design/architecture.md)
- [Technology selection](docs/design/technology-selection.md)

### Specifications

- [Protocol](docs/spec/protocol.md)
- [Wire profile v1](docs/spec/wire-profile.md)
- [Configuration model](docs/spec/configuration.md)
- [Configuration schema](docs/spec/configuration-schema.md)
- [Platform and DNS](docs/spec/platform-and-dns.md)
- [State machines](docs/spec/state-machines.md)
- [Ingress control plane](docs/spec/ingress-control-plane.md)
- [Ingress observability](docs/spec/observability.md)

### Progress

- [Implementation status](docs/progress/status.md)
- [Implementation plan](docs/progress/implementation-plan.md)

## Command surface

```text
pathchord ingress
pathchord egress
pathchord status
pathchord enroll
```

On Unix, the `ingress` command starts configured listeners, the durable local
control socket, the subscription worker, and any requested Web Gateway.
`egress` starts the authenticated Path listener and authorization control
socket; `status`, `system-proxy`, and `enroll` use the corresponding local
control endpoint. The direct target bridge remains available only for an
explicit policy with no Egress/Transit route.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo run -p pathchord-cli -- --help
```

The workspace disables rustc incremental artifacts in dev/test profiles so a configured `RUSTC_WRAPPER=sccache` can reuse complete compilation units. The repository does not require a machine-specific wrapper; local Cargo configuration decides whether sccache is available.
