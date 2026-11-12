# PathChord implementation status

Status snapshot: 2026-11-12.

This document records the repository's implementation state. It is intentionally
separate from `docs/design/`, which describes the intended architecture, and
`docs/spec/`, which describes the final behavioral contracts.

## Available foundations

- The Cargo workspace and the `pathchord-core`, `pathchord-noise`,
  `pathchord-path`, `pathchord-policy`, `pathchord-transit`, `pathchord-egress`,
  `pathchord-ingress`, and `pathchord-cli` crates exist.
- Phase 0 protocol, framing, Noise-record, state-machine, policy-snapshot,
  deterministic Transit, target-dialing, and fault-injection primitives have
  unit and property-test coverage.
- Phase 1A TCP single-Path reliability and control-service foundations exist.
  The transport-neutral Ingress command/query service currently provides
  bounded in-memory snapshots, mutations, idempotency, generation checks,
  subscription refresh state, observations, and events.
- Kubernetes-style `pathchord.io/v1` YAML parsing now validates strict resource
  envelopes, multi-document/List input, DNS prerequisites, rule ordering, and
  converts desired objects into the existing immutable policy snapshot model.
- Ingress control state now exposes typed Listener inventory and the Windows-only
  system-proxy switch contract with idempotent enable/disable transitions and
  structured events. Platform-side Windows environment/OS proxy mutation is
  still an adapter integration task.
- The local control protocol now has canonical length-prefixed JSON framing,
  typed request/response envelopes, a Unix-domain server, a transport-neutral
  dispatcher for status/listener/system-proxy operations, and a Unix CLI client.
  Named Pipe transport and the actual Windows OS proxy side-effect adapter are
  still pending.
- The CLI implements Unix `status`, `system-proxy`, and `ingress --config`
  requests through the local control socket; `egress` and `enroll` remain
  placeholders.
- HTTP CONNECT and SOCKS5 CONNECT inbound adapters now parse bounded local
  handshakes into typed `ConnectionContext` values, including domain/IPv4/IPv6
  targets, optional SOCKS username/password identity, and deterministic failure
  replies. Target dialing and Stream creation remain separate integration work.
- Egress now includes a concrete Tokio TCP `TargetConnector` that tries explicit
  address candidates, falls back to hostname resolution, supports an optional
  connect timeout, and preserves typed target validation failures.

## Missing operational integration

- CLI `egress` and `enroll` commands still return the bootstrap error; `ingress`
  currently starts the local control server and does not yet start traffic
  listeners.
- TPROXY, TUN, Windows system-proxy OS side effects, and production Transit
  adapters are not implemented; HTTP/SOCKS handshake adapters are now present
  but are not connected to target dialing or the data plane.
- The end-to-end proxy data plane is not operational.
- Named Pipe transport, persistent authorization and metadata stores,
  subscription worker, REST/SSE Web Gateway, and frontend are not integrated.
- Multipath scheduling and production cross-Path retransmission remain outside
  the implemented slice; v1 UDP and Path lifecycle payload codecs are present
  as protocol primitives but are not integrated into the data plane.

The staged implementation sequence is tracked in
[the implementation plan](implementation-plan.md). Phase-specific scope,
temporary wire fixtures, and acceptance tracking are recorded in the other
documents in this directory.

## Known implementation constraints

- The current `snow` 0.10 wrapper uses explicit nonces and a 64-record replay
  window. `snow` does not guarantee zeroization of every private-key, DH, and
  traffic-key buffer it owns. A zeroizing resolver or reviewed replacement is
  required before production deployment.
- Session ACK retention and retransmission behavior still need validation
  against the 64-record replay-window bound.
- The final-state Kubernetes-style `pathchord.io/v1` configuration contract is
  now parsed by `pathchord-policy`, including strict envelopes, List and
  multi-document input, DNS prerequisites, rule ordering, listener shorthand,
  and conversion into immutable policy snapshots.
- The final-state `wire-profile-v1` registry and canonical EgressID prologue
  are defined by `docs/spec/wire-profile.md`. The Phase 1 fixture remains a
  historical implementation record and is not the final wire contract.
- Ingress now has typed Listener inventory and a Windows-only system-proxy
  control-state boundary with idempotent transitions and events. Real Windows
  environment-variable/OS proxy mutation remains a platform adapter task.

## Open validation work

- Noise handshake and transport-state zeroization, including the selected
  resolver.
- Tokio supervision and cancellation under Path churn.
- Wintun packaging and Windows service integration.
- Linux TPROXY behavior for IPv4 and IPv6.
- SQLite behavior during concurrent queries and enrollment operations.
- Frame-codec throughput and allocation cost.
- Rule-compiler latency and worst-case evaluation cost.
