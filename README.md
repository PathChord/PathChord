# PathChord

**English** | [简体中文](README.zh-CN.md)

Adaptive multipath proxy with Ingress, Transit Proxy, and Egress.

PathChord provides ordinary proxy semantics to local applications while maintaining multiple replaceable transit paths between an Ingress and a selected Egress.

## Status

Initial implementation. The repository contains the design baseline, Phase 0
protocol/transport primitives, the Phase 1A TCP single-path implementation
scope and provisional wire contract, and core reliability/control-service
foundations. The proxy data plane and Web Gateway adapters are not implemented
yet.

## Terminology

- **Ingress**: local traffic entry point and policy engine.
- **Transit Proxy**: an uncontrolled proxy transport used to reach an Egress.
- **Egress**: a controlled logical network interface and final traffic exit.
- **Session**: shared logical session between one Ingress and one Egress.
- **Path**: a long-lived bidirectional connection carried by one Transit Proxy.
- **Stream**: a logical TCP byte stream carried over one Session.

## Documentation

Design documents describe the intended architecture and durable decisions.
Specifications define the final behavioral and format contracts. Implementation
status, sequencing, phase scope, and acceptance tracking live only under
`docs/progress/` (or in the repository status summary above).
Every design and specification document is available in both English and
Simplified Chinese. Progress documents use English as their single maintained
source.

### Design

- [Architecture](docs/design/architecture.md)
- [Technology selection](docs/design/technology-selection.md)

### Specifications

- [Protocol](docs/spec/protocol.md)
- [Configuration model](docs/spec/configuration.md)
- [State machines](docs/spec/state-machines.md)
- [Ingress control plane](docs/spec/ingress-control-plane.md)
- [Ingress observability](docs/spec/observability.md)

### Progress

- [Implementation status](docs/progress/status.md)
- [Implementation plan](docs/progress/implementation-plan.md)
- [Design review record](docs/progress/design-review.md)
- [Phase 1 single-path scope](docs/progress/phase-1-single-path.md)
- [Phase 1 provisional wire contract](docs/progress/phase-1-wire.md)
- [Phase 1 acceptance tracking](docs/progress/phase-1-acceptance.md)

## Command surface

```text
pathchord ingress
pathchord egress
pathchord status
pathchord enroll
```

The command tree is available for interface discovery, but operational commands currently return a bootstrap error until their implementation phase is complete.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo run -p pathchord-cli -- --help
```

The workspace disables rustc incremental artifacts in dev/test profiles so a configured `RUSTC_WRAPPER=sccache` can reuse complete compilation units. The repository does not require a machine-specific wrapper; local Cargo configuration decides whether sccache is available.
