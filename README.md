# PathChord

**English** | [简体中文](README.zh-CN.md)

Adaptive multipath proxy with Ingress, Transit Proxy, and Egress.

PathChord provides ordinary proxy semantics to local applications while maintaining multiple replaceable transit paths between an Ingress and a selected Egress.

## Status

Initial implementation. The repository contains the design baseline and a Phase 0 Rust workspace for protocol primitives, per-Path Noise experiments, and deterministic transport fixtures. The proxy data plane is not implemented yet.

## Terminology

- **Ingress**: local traffic entry point and policy engine.
- **Transit Proxy**: an uncontrolled proxy transport used to reach an Egress.
- **Egress**: a controlled logical network interface and final traffic exit.
- **Session**: shared logical session between one Ingress and one Egress.
- **Path**: a long-lived bidirectional connection carried by one Transit Proxy.
- **Stream**: a logical TCP byte stream carried over one Session.

## Design documents

- [Architecture](docs/architecture.md)
- [Protocol](docs/protocol.md)
- [Configuration model](docs/configuration.md)
- [State machines](docs/state-machines.md)
- [Implementation plan](docs/implementation-plan.md)
- [Technology selection](docs/technology-selection.md)
- [Design review](docs/design-review.md)

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
