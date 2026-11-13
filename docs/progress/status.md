# PathChord implementation status

Status snapshot: 2026-11-13.

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
- Ingress now provides a transport-neutral direct TCP flow bridge with an
  injected target-dialer trait, bidirectional copy/half-close propagation, byte
  counters, and deterministic dial/copy failure tests.
- Ingress now provides a bounded listener runtime that supervises HTTP CONNECT
  and SOCKS5 listeners, classifies malformed handshakes as per-connection
  rejections, exposes bound addresses/events, and shuts down listener and flow
  tasks together. The CLI wires this runtime to the concrete TCP target
  connector for a direct local-listener-to-target bootstrap path.
- `pathchord-path` now provides a deterministic single-Path admission harness:
  Noise IK, EgressID prologue validation, `PATH_HELLO`, `SESSION_ATTACH`,
  authorization generation/key checks, capability negotiation, `PATH_READY`
  limits, and typed attach rejection. It remains an in-memory protocol harness
  for the live adapter boundary rather than a socket-owning Path runtime.
- Configuration validation now enforces the documented resource-name, bounded
  map, Egress key/capability, Transit adapter, subscription URL/refresh/cache,
  DNS route/limit, listener platform, rule catch-all, and proxy-action rules.
- Listener `allowedSources` now remains attached to the runtime descriptor,
  appears in listener inventory, defaults loopback socket binds to the local
  host CIDR, and is enforced before target dialing with a typed policy-rejection
  event.
- The single-Path harness now carries `STREAM_OPEN` over the authenticated Path
  to an injected opener, validates `STREAM_OPEN_OK`/`STREAM_OPEN_ERR`, and
  preserves RequestID/StreamID idempotency and conflict rules.
- `pathchord-path` now also has a bounded `NoiseRecordStream` byte adapter;
  it segments the wire-profile record envelope, authenticates complete frames,
  and has a duplex integration test. `pathchord-transit` provides a bounded
  direct TCP adapter at the byte-transport boundary.
- `pathchord-path` now provides transport-neutral Ingress/Egress Path session
  owners for one `STREAM_OPEN` exchange. They run over the record adapter,
  invoke the injected Egress opener, and are covered by a cross-crate
  FakeEgress integration test.
- The local dispatcher now exposes typed read models for nodes, sessions,
  connections, subscriptions, metrics, and events, and `listeners.list`
  validates bounded pagination/filter/sort queries. Supplied configuration
  generation preconditions are checked for system-proxy mutations.
- The Windows control transport now has a Tokio Named Pipe implementation and
  the Windows target compiles; Windows ACL hardening and real system-proxy OS
  side effects still require Windows-host validation.
- The local listener list query now validates pagination/filter/sort fields,
  returns deterministic pages, and system-proxy mutations honor supplied
  configuration generation preconditions.

## Missing operational integration

- CLI `egress` and `enroll` commands still return the bootstrap error; on Unix,
  `ingress` starts the local control server together with configured HTTP/SOCKS
  traffic listeners and the bounded direct TCP bridge.
- TPROXY, TUN, Windows system-proxy OS side effects, and production Transit
  adapters are not implemented; the direct bootstrap bridge does not create
  PathChord Sessions or Paths and therefore is not the full multipath data
  plane.
- The single-Path admission harness is not yet wired to a Transit byte/record
  loop or Session manager; its Stream opener is still an injected
  transport-neutral boundary. A cross-crate test now routes `STREAM_OPEN`
  through `FakeEgress` and verifies target-dial idempotency.
- The direct Transit, record, and single-Stream session owners are not yet
  connected to the CLI listener runtime or a reconnecting production Session
  manager; CLI ingress still uses the bootstrap direct target bridge.
- The Session/Path end-to-end proxy data plane is not operational.
- Named Pipe transport, persistent authorization and metadata stores,
  subscription worker, REST/SSE Web Gateway, and frontend are not integrated.
- Multipath scheduling and production cross-Path retransmission remain outside
  the implemented slice; v1 UDP and Path lifecycle payload codecs are present
  as protocol primitives but are not integrated into the data plane.

The active implementation sequence is tracked in the
[implementation plan](implementation-plan.md). Superseded phase scopes,
temporary wire fixtures, reviews, and acceptance records are not maintained in
this directory; Git history is the historical record.

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
  are defined by `docs/spec/wire-profile.md`.
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
