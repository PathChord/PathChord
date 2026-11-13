# PathChord implementation status

Status snapshot: 2026-11-13.

This document records the current implementation and validation state. Final
architecture and behavioral contracts remain under `docs/design/` and
`docs/spec/`.

## Current focus

Active work prioritizes HTTP CONNECT and SOCKS5 CONNECT/UDP ASSOCIATE on
Linux and Windows, with FreeBSD under assessment as an additional target for
the same explicit listeners and Unix local control. FreeBSD support has not
been established by a target build or native host tests.

TPROXY, REDIRECT, transparent UDP interception, TUN integration, privileged
routing validation, and Wintun packaging follow the explicit-listener
baseline. Existing transparent/TUN modules remain implementation facts below;
they are outside the active acceptance scope. SOCKS5 UDP forwarding remains
in the current scope.

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

## Remaining explicit-listener work

- Linux and Windows HTTP/SOCKS5 need end-to-end and long-running validation of
  authentication, source restrictions, TCP/UDP forwarding, DNS, bounded
  resources, shutdown, reload, and local control. Existing automated loopback
  tests are recorded below; they do not establish native Windows coverage.
- Windows registry, WinINet refresh, Named Pipe ACL, and system-proxy crash
  recovery still need validation on a real Windows host. Cross-compiling and
  fake adapters are not equivalent to host evidence.
- FreeBSD is a candidate target. The listener schema currently accepts only
  `any`, `linux`, and `windows`; the CLI treats every non-Windows platform as
  Linux for system-proxy reporting. Unix local-control code offers a reuse
  point. The unconditional `tun-rs` dependency and the `notify` watcher have
  FreeBSD support in their cached source; this does not establish a working
  PathChord build. Native dependencies, configuration watching, SQLite,
  credential/socket permissions, and signal behavior still need target-build
  and native-host validation.
- Process metadata is best-effort: Linux has a procfs provider; other platforms
  currently report unknown. Windows and FreeBSD native process discovery is
  an additional capability, not a prerequisite for explicit listeners.
- Long-running failure/restart tests and real subscription refresh soak tests
  remain to be exercised through the explicit listeners.

## Shared implementation gaps

- TrafficPolicy replication budgets and retransmission mode are applied by the
  Session runtime. Class priority/share fields are parsed into the policy
  model but are not consumed by runtime class scheduling.
- Subscription quota, reset-time, and billing multiplier fields exist in the
  observation model, but provider metadata ingestion, runtime publication, and
  end-to-end consumption are not connected.
- JSON metric queries, SSE, and the embedded console exist. Production metric
  export and deployed monitoring dashboards remain to be integrated.

## Deferred work

- Linux TPROXY mark/routing behavior, IPv4/IPv6 transparent UDP, and TUN
  integration need privileged host validation after the explicit-listener
  baseline. Route ownership journals are designed to fail closed and never
  remove foreign rules. Wintun packaging and native TUN validation are also
  deferred.
- VLESS/VMess/XTLS remain outside the built-in adapter set. Enabling them needs
  explicit UUID/flow/outer-transport/TLS-Reality configuration and upstream
  interoperability fixtures.

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
