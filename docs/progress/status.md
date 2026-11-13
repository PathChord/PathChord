# PathChord implementation status

Status snapshot: 2026-11-13.

This document records the current implementation and validation state. Final
architecture and behavioral contracts remain under `docs/design/` and
`docs/spec/`.

## Implemented

- The eight-crate Rust workspace builds on Linux and cross-checks for Windows
  GNU. Core frame/message codecs, state machines, bounded reliability buffers,
  wire vectors, and UDP/Path lifecycle payloads are implemented.
- Noise IK uses Clatter zeroizing key and cipher containers with an Orion
  SHA-256/HMAC adapter. Static, ephemeral, chaining, and traffic-key owners
  have explicit cleanup paths. Frozen vectors preserve the previous wire bytes.
- Async role-separated Path admission performs Noise IK, `PATH_HELLO`,
  `SESSION_ATTACH`, authorization lookup, capability negotiation, and
  `PATH_READY` over a real byte stream.
- The Session runtime supports TCP and UDP Streams, multiple Paths, per-Stream
  eligible Path sets, DATA/ACK/WINDOW/FIN/RST, bounded reordering and buffers,
  Path drain/close, bounded timer retransmission, cross-Path re-framing, and
  supervised shutdown.
- Ingress has HTTP CONNECT, SOCKS5 CONNECT and UDP ASSOCIATE, Linux REDIRECT
  and TPROXY adapters, transparent UDP, a direct smoltcp TUN reactor, process
  metadata lookup, listener flow tags, listener-local Basic/username-password
  verification, and protected endpoint replacement.
- `IngressPlatformRuntime` is the all-or-nothing platform owner for TCP,
  transparent UDP, TUN, route journals, cancellation, rollback, and task join.
  The CLI starts it instead of assembling only the direct bootstrap listener
  runtime.
- `IngressDataPlane` compiles/evaluates ordered policy, creates authenticated
  Egress Sessions through Transit adapters, exposes TCP/UDP openers, maintains
  Path slots, applies selected TrafficPolicy replication/retransmission
  budgets, exports path-quality/session/stream observations, and publishes DNS
  protected endpoints.
- Egress has a real TCP Path listener, authorization-backed admission, target
  Stream/UDP forwarding, multiple Path attachment, global status inputs,
  authorization reconciliation, cleanup barriers, and bounded supervision.
- Policy parsing preserves subscriptions, DNSPolicy, opaque credential
  references, listener platform/protocol/process fields, and flow tags.
  `CompiledPolicy` evaluates Egress, Transit, ordinary Proxy, and fallback
  routes without I/O.
- Transit adapters include direct TCP, HTTP CONNECT, HTTPS CONNECT over
  rustls, SOCKS5, and Shadowsocks. Credential files are bounded, permission
  checked, symlink/TOCTOU checked, redacted, and zeroized. VLESS, VMess, and
  XTLS are rejected as typed unavailable adapters until their missing transport
  schema and interoperability evidence exist.
- Subscription refresh supports Clash/SIP008 normalization, bounded fetch and
  retry, atomic private cache, last-good retention, dynamic-node draining, and
  runtime adapter publication. Control-plane subscription mutations persist the
  complete source/refresh/cache model.
- DNSRuntime supports local, Transit, Egress, and blocked routes, Hickory
  parsing, same-upstream TCP fallback for truncated UDP replies, positive and
  negative TTL cache, inflight/size/time limits, protected endpoint output,
  and Session UDP integration.
- Local control uses one canonical management envelope over Unix socket and
  Windows Named Pipe. The server has bounded supervised concurrency, owner /
  Administrators / SYSTEM Named Pipe ACLs, and remote-client rejection.
  Egress enrollment and authorization mutations are transactional, durable,
  generation checked, audited, idempotent, and cleanup-aware.
- Ingress control state uses SQLite transactions, durable audit/idempotency,
  node/subscription snapshots, refresh queues, and notify-based configuration
  reload with atomic compiled-policy replacement and restart-required checks.
- The optional authenticated REST/SSE Web Gateway and embedded operations
  console use the same dispatcher as local control. It has bounded requests,
  SSE replay/backpressure, bearer/origin checks, target redaction, and the
  documented query/mutation registry. Egress authorization routes are mounted
  only on the Egress-owned dispatcher; Ingress intentionally omits them.

## Remaining validation or external work

- Windows registry, WinINet refresh, Named Pipe ACL, Wintun packaging, and
  crash recovery still need validation on a real Windows host. Cross-compiling
  and fake adapters are not equivalent to host evidence.
- Linux TPROXY mark/routing behavior, IPv4/IPv6 transparent UDP, and TUN
  integration need privileged host validation. Route ownership journals are
  designed to fail closed and never remove foreign rules.
- VLESS/VMess/XTLS remain outside the built-in adapter set. Enabling them needs
  explicit UUID/flow/outer-transport/TLS-Reality configuration and upstream
  interoperability fixtures.
- Process metadata providers are best-effort and represent missing facts as
  unknown; platform-specific coverage still needs host matrices.
- Subscription provider quotas, billing metadata, long-running refresh soak
  tests, production dashboards, and deployed metric export remain to be
  exercised against real infrastructure.
- TrafficPolicy replication budgets and retransmission mode are applied by the
  Session runtime; class priority/share scheduling remains represented in the
  policy model but still needs runtime validation and tuning.

## Validation evidence

The current workspace passes:

```text
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo check --locked --workspace --all-targets --target x86_64-pc-windows-gnu
cargo audit
git diff --check
```

The full workspace test run covers protocol, policy, Noise, Path, Transit,
Ingress, Egress, CLI, real loopback Egress/Ingress TCP and UDP paths, platform
fakes, route rollback, TUN packet flows, Web REST/SSE, persistence, reload,
subscription normalization, and fault/retransmission cases. `cargo audit`
currently reports no advisories; the dependency graph excludes the previously
unmaintained `paste` path from the TUN adapter feature set.
