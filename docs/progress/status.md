# PathChord implementation status

Status snapshot: 2026-11-13.

This document records the current implementation and validation state. Final
architecture and behavioral contracts remain under `docs/design/` and
`docs/spec/`.

## Current focus

Active work prioritizes HTTP forwarding/CONNECT, SOCKS4/4a/5 CONNECT, SOCKS5
UDP ASSOCIATE, and same-port Mixed listeners on Linux, Windows, and FreeBSD.
FreeBSD explicit-listener configuration, native process metadata, platform
identity, and Unix local control are integrated. FreeBSD x86_64 target
compilation and CLI linking pass; native host tests remain outstanding.
Portable listener regressions run in the existing Rust CI job.

TPROXY, REDIRECT, transparent UDP interception, TUN integration, privileged
routing validation, and Wintun packaging follow the explicit-listener
baseline. Existing transparent/TUN modules remain implementation facts below;
they are outside the active acceptance scope. SOCKS5 UDP forwarding remains
in the current scope.

## Implemented

- Ingress accepts a single file or recursively loaded YAML/YML/JSON directory.
  CLI source options override `PATHCHORD_CONFIG`/`PATHCHORD_CONFIG_DIR`, which
  override `~/.config/pathchord` or `/etc/pathchord` for root/service accounts.
  Files form one validated graph with global references and duplicate checks.
  Directory changes and atomic replacement reload the complete candidate;
  invalid candidates retain the last good snapshot.

- The eight-crate Rust workspace builds on Linux and cross-checks for Windows
  GNU and FreeBSD x86_64. Core frame/message codecs, state machines, bounded
  reliability buffers, wire vectors, and UDP/Path lifecycle payloads are
  implemented.
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
- Ingress has ordinary HTTP forwarding and CONNECT, SOCKS4/4a/5 CONNECT,
  SOCKS5 UDP ASSOCIATE, Linux REDIRECT
  and TPROXY adapters, transparent UDP, a direct smoltcp TUN reactor, process
  metadata lookup, listener flow tags, listener-local Basic/username-password
  verification, and protected endpoint replacement.
- HTTP forwarding uses Hyper's HTTP/1 codec for bounded headers, streaming
  bodies, request-by-request authentication and routing, hop-header and trailer
  filtering, redirects, and validated Upgrade. Each ordinary request opens its
  selected flow independently; HTTPS is carried through CONNECT. SOCKS4/4a are
  refused when password authentication is required. The `socks` input alias
  normalizes and serializes to `socks5`.
- Mixed listeners serve HTTP and SOCKS4/4a/5 on one TCP endpoint, preserve the
  detected first byte, and reuse listener credentials, flow context, and
  SOCKS5 UDP relay ownership. Idle and incomplete handshakes are cancelled on
  shutdown without waiting for the platform deadline. Mixed listeners are
  available in configuration, inventory queries, the console, and Windows
  system-proxy selection, where the shared endpoint uses HTTP settings.
- `IngressPlatformRuntime` is the all-or-nothing platform owner for TCP,
  transparent UDP, TUN, route journals, cancellation, rollback, and task join.
  The CLI starts it instead of assembling only the direct bootstrap listener
  runtime.
- `IngressDataPlane` compiles/evaluates ordered policy, creates authenticated
  Egress Sessions through Transit adapters, exposes TCP/UDP openers, maintains
  Path slots, applies selected TrafficPolicy replication/retransmission
  budgets, exports path-quality/session/individual Stream observations, and
  publishes DNS protected endpoints. TrafficPolicy class priority/share
  scheduling is negotiated in both directions with bounded priority, weighted
  fairness, and class-aware TCP/UDP queues.
- Static policy reload prepares every changed Transit adapter before a
  transactional runtime/control-plane commit. Failed preparation or durable
  control reconciliation retains the previous generation; changed Paths drain
  under a bounded retirement task while existing Streams continue.
- Explicit NodeProbePolicy configuration performs bounded TCP connect probes
  only to its configured target. Observations expose adapter readiness, state,
  latency, jitter, loss, and typed failures without fabricating throughput or
  capacity. Probing is disabled by default.
- Egress has a real TCP Path listener, authorization-backed admission, target
  Stream/UDP forwarding, multiple Path attachment, global status inputs,
  authorization reconciliation, cleanup barriers, and bounded supervision.
- Ingress and Egress consume the same file/directory resource bundle. Egress
  selects one EgressService resource, resolves relative paths from its source,
  and applies command-line, environment, then account-default precedence while
  retaining complete legacy CLI-only startup when the default bundle is absent.
- Policy parsing preserves subscriptions, DNSPolicy, opaque credential
  references, listener platform/protocol/process fields, and flow tags.
  `CompiledPolicy` evaluates Egress, Transit, ordinary Proxy, and fallback
  routes without I/O.
- Transit adapters include direct TCP, HTTP CONNECT, HTTPS CONNECT over
  rustls, SOCKS5, and Shadowsocks, with direct/SOCKS5/SS UDP and SS2022.
  Typed TLS settings include SNI, ALPN, custom CA, explicit insecure, and
  client-certificate/key references. HTTP custom headers are validated. Unknown
  credentials/options are rejected instead of ignored; TLS options cannot
  silently become plaintext. Credential files retain bounded, private,
  symlink/TOCTOU-checked, redacted handling.
- Native Rust VLESS and Trojan adapters support TCP, TLS, WebSocket, and WSS
  combinations with real protocol-peer TCP and UDP interoperability
  coverage. Native VMess supports plain TCP with AES-128-GCM and `alter_id: 0`
  with a real protocol interoperability fixture. Native Hysteria2 now covers
  QUIC/TLS, HTTP/3 authentication, TCP relay, and UDP relay with a real peer
  fixture; Salamander/Gecko obfs and port hopping remain unimplemented. Native
  TUIC now covers QUIC/TLS-exporter TCP CONNECT with a peer fixture; UDP/0-RTT,
  Reality, and SSR remain unimplemented or explicitly unavailable.
- AnyTLS has a native TLS/session adapter with bounded frame/authentication
  codec, settings, SYN/SYNACK, PUSH/FIN, heartbeat handling, and a sing-box
  protocol-peer interoperability fixture.
- Reality has a bounded pure-Rust wire/crypto codec with unit vectors; its
  custom TLS ClientHello and native handshake seam remain unregistered. The
  rustls X25519 provider seam is now isolated for that future handshake.
- Imported complete sing-box documents are retained as opaque unavailable-node
  diagnostics. PathChord does not start or embed a compatibility process.
- Subscription refresh supports automatic detection, Clash/Mihomo, SIP008
  arrays and object wrappers, URI/Base64 lists, sing-box document syntax, and
  supported Surge/Quantumult X/Loon node lines. Complete imported external
  documents remain unavailable diagnostics. HTTP provider references
  are bounded by depth/count/aggregate bytes and propagate bearer credentials
  only to the same origin. Individual invalid nodes retain sanitized
  diagnostics; malformed documents and failed providers retain applicable
  last-good data. Cache, draining, controls, and reload preserve diagnostics.
- Subscription usage is collected from `Subscription-Userinfo`; an explicit
  `PathChord-Traffic-Multiplier` extension supplies billing metadata. Cache,
  node queries, the console, and Path economics consume the metadata. Unknown
  statistics stay unknown; expiry is not a quota reset timestamp.
- `/metrics` exposes bounded aggregate Prometheus gauges for runtime, node
  health, Path quality, and observed Stream byte/retransmission totals through
  the optional Web Gateway's existing authentication, Origin, and capability
  checks. JSON metric queries and SSE remain available.
- DNSRuntime supports local, Transit, Egress, and blocked routes, Hickory
  parsing, same-upstream TCP fallback for truncated UDP replies, positive and
  negative TTL cache, inflight/size/time limits, protected endpoint output,
  and Session UDP integration.
- Local control uses one canonical management envelope over Unix socket and
  Windows Named Pipe. The server has bounded supervised concurrency, owner /
  Administrators / SYSTEM Named Pipe ACLs, and remote-client rejection.
  Egress enrollment and authorization mutations are transactional, durable,
  generation checked, audited, idempotent, and cleanup-aware.
- FreeBSD listener configuration accepts HTTP forwarding/CONNECT and
  SOCKS4/4a/5 CONNECT plus SOCKS5 UDP ASSOCIATE with `platform: freebsd` or
  host-resolved `any`. Configuration and
  runtime preflight reject FreeBSD TPROXY, REDIRECT, and TUN before resource
  creation. The CLI and default dispatcher identify FreeBSD separately from
  Linux; system-proxy mutations return `UNSUPPORTED_OPERATION`, and status
  reports `platform_effect: unsupported`. The native `tun-rs` device dependency
  is excluded from FreeBSD builds.
- Ingress control state uses SQLite transactions, durable audit/idempotency,
  node/subscription snapshots, refresh queues, and notify-based configuration
  reload with atomic compiled-policy replacement and restart-required checks.
- The optional authenticated REST/SSE Web Gateway and embedded operations
  console use the same dispatcher as local control. It has bounded requests,
  SSE replay/backpressure, bearer/origin checks, target redaction, and the
  documented query/mutation registry. Egress authorization routes are mounted
  only on the Egress-owned dispatcher; Ingress intentionally omits them.

## Remaining explicit-listener work

- The deployment guide and example configurations cover direct,
  subscription, and authenticated Egress use. Separate CLI-process smoke
  validation covers key generation, enrollment, HTTP Transit, Mixed HTTP, and
  Session UDP forwarding. Cross-machine and long-running deployment evidence
  remains to be gathered.
- Linux, Windows, and FreeBSD HTTP/SOCKS5 need end-to-end and long-running
  validation of authentication, source restrictions, TCP/UDP forwarding, DNS, bounded
  resources, shutdown, reload, and local control. Existing automated loopback
  tests are recorded below; they do not establish native Windows or FreeBSD
  coverage.
- Windows registry, WinINet refresh, Named Pipe ACL, and system-proxy crash
  recovery still need validation on a real Windows host. Cross-compiling and
  fake adapters are not equivalent to host evidence.
- FreeBSD native dependencies, configuration watching, SQLite,
  credential/socket permissions, and signal behavior need native-host
  validation. A cross-compiled target check is distinct from executing the
  workspace tests on FreeBSD; native FreeBSD execution remains a separate host
  validation item.
- Process metadata is best-effort: Linux uses bounded procfs reads and Windows
  and FreeBSD use the safe `netsock` native IP Helper/libprocstat provider.
  Process IDs and executable names are returned where permissions allow;
  user/group identifiers remain unknown when the platform API does not expose
  them.
- Long-running failure/restart tests and real subscription refresh soak tests
  remain to be exercised through the explicit listeners.

## Shared implementation gaps

- Native Windows/FreeBSD runtime matrices, provider soak tests, external
  monitoring deployment, and a broad real-provider protocol/parameter matrix
  remain validation work. Hysteria2, TUIC, Reality, SSR, and other unregistered
  protocols stay explicitly
  unavailable until native wire and interoperability evidence exists.
  Third-party policy groups, rules, and scripts are not imported as PathChord
  policy.

## Deferred work

- Linux TPROXY mark/routing behavior, IPv4/IPv6 transparent UDP, and TUN
  integration need privileged host validation after the explicit-listener
  baseline. Route ownership journals are designed to fail closed and never
  remove foreign rules. Wintun packaging and native TUN validation are also
  deferred.
- Protocols outside the registered native set remain
  unavailable with node diagnostics. Further native implementations need
  protocol-specific interoperability fixtures.

## Validation evidence

Recorded passing checks include:

```text
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo check --locked --workspace --all-targets --target x86_64-pc-windows-gnu
cargo check --locked --workspace --all-targets --target x86_64-unknown-freebsd
cargo build --locked -p pathchord-cli --target x86_64-unknown-freebsd
git diff --check
```

The full workspace test run covers protocol, policy, Noise, Path, Transit,
Ingress, Egress, CLI, real loopback Egress/Ingress TCP and UDP paths, platform
fakes, route rollback, TUN packet flows, Web REST/SSE, persistence, reload,
subscription normalization, and fault/retransmission cases. The dependency
graph excludes the previously unmaintained `paste` path from the TUN adapter
feature set.

The Linux workspace run passes every non-ignored workspace test. The Transit
unit set reports 75 passed and 2 ignored without an external proxy executable.
The ignored tests use independent reference peers when explicitly requested.
The portable
explicit-listener integration
test binds listeners for the actual host platform and checks HTTP
CONNECT, SOCKS5 CONNECT, SOCKS5 UDP ASSOCIATE, TCP half-close, and cancellation
with an open UDP control connection.

HTTP proxy socket tests additionally cover ordinary GET and streaming POST,
per-request routing and authentication, header/trailer filtering, redirects,
early responses, ambiguous framing closure, Upgrade protocol selection and
buffered bytes, and cancellation of an unfinished upstream response. SOCKS
compatibility tests cover SOCKS4/4a forwarding, delayed success, bounded
malformed input, and refusal to bypass required password authentication.

Mixed listener tests exercise all supported HTTP/SOCKS TCP protocols on one
address, coalesced handshake/application bytes, common credentials and flow
context, source/protocol rejection, SOCKS5 UDP forwarding while other clients
are idle, and bounded shutdown with open handshakes and a UDP control socket.

The final run includes explicit key generation/enrollment with separate
Ingress and Egress CLI processes, an HTTP Transit, HTTP forwarding, and Session
UDP. Transit coverage includes TLS CA/SNI and mutual authentication, classic
and 2022 SS TCP/UDP, native SOCKS5 UDP/control lifetime, provider expansion and
credential boundaries, strict import diagnostics, usage/cache restoration,
strict protocol-parameter validation, node queries, and authenticated Prometheus
export. Reference-peer interoperability tests are run explicitly when their
peer fixture is available; the normal Rust CI does not require an external
proxy executable.

Configuration-source coverage includes recursive split-resource loading,
cross-file references, duplicate rejection, account defaults and override
precedence, bounded discovery/reads, directory add/update/rename/remove,
atomic file/root replacement, invalid-candidate retention, and no restart for
unchanged resources moved between files. The CLI process smoke test uses a
directory bundle while conflicting environment sources are present, proving
the command-line override is effective.

The FreeBSD target check and CLI build use Zig 0.17.1 C/C++ compiler and archiver
wrappers with the official FreeBSD 15.1 SDK, including the bundled SQLite and
crypto dependencies. The resulting x86_64 ELF uses `/libexec/ld-elf.so.1` and
links against `libthr.so.3` and `libc.so.7`. This validates target compilation
and linking; it does not execute FreeBSD tests. Native FreeBSD validation
remains pending a host run.
