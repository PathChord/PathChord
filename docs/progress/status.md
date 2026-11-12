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
- The CLI command tree exposes `ingress`, `egress`, `status`, and `enroll` for
  interface discovery.

## Missing operational integration

- CLI operational commands still return the bootstrap error.
- SOCKS, HTTP, TPROXY, TUN, Windows system-proxy, and production Transit
  adapters are not implemented.
- The end-to-end proxy data plane is not operational.
- The local length-prefixed JSON adapter, persistent authorization and metadata
  stores, subscription worker, REST/SSE Web Gateway, and frontend are not
  integrated.
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
- The final-state `schema_version: 1` configuration contract is defined by
  `docs/spec/configuration-schema.md` and the platform/DNS contract. The
  implementation still needs to replace its bootstrap parser with that schema.
- The final-state `wire-profile-v1` registry and canonical EgressID prologue
  are defined by `docs/spec/wire-profile.md`. The Phase 1 fixture remains a
  historical implementation record and is not the final wire contract.

## Open validation work

- Noise handshake and transport-state zeroization, including the selected
  resolver.
- Tokio supervision and cancellation under Path churn.
- Wintun packaging and Windows service integration.
- Linux TPROXY behavior for IPv4 and IPv6.
- SQLite behavior during concurrent queries and enrollment operations.
- Frame-codec throughput and allocation cost.
- Rule-compiler latency and worst-case evaluation cost.
