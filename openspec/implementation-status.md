# PathChord implementation status

Status snapshot: 2026-11-14.

This document records the current implementation and validation state. Final
architecture remains under `docs/design/`; behavioral contracts live under
`openspec/specs/`. User configuration and operation guides live under
`docs/guides/`. Pending actions are tracked in the [active changes](changes/);
this snapshot records evidence rather than a second implementation plan.

## Current focus

Active work prioritizes HTTP forwarding/CONNECT, SOCKS4/4a/5 CONNECT, SOCKS5
UDP ASSOCIATE, and same-port Mixed listeners on Linux, Windows, and FreeBSD.
FreeBSD explicit-listener configuration, native process metadata, platform
identity, and Unix local control are integrated. FreeBSD x86_64 target
compilation and CLI linking pass; native host tests remain outstanding.
Portable listener regressions run in the existing Rust CI job.

TPROXY, REDIRECT, transparent UDP interception, and TUN integration are wired
into the Ingress platform runtime with configuration, rollback, protected
endpoint handling, source restrictions, and bounded TCP/UDP flow supervision.
Privileged route/TUN host validation and Wintun packaging remain separate
acceptance work. SOCKS5 UDP forwarding remains in the current scope.

## Implemented

- Ingress accepts a single file or recursively loaded YAML/YML/JSON directory.
  CLI source options override `PATHCHORD_CONFIG`/`PATHCHORD_CONFIG_DIR`, which
  override `~/.config/pathchord` or `/etc/pathchord` for root/service accounts.
  Files form one validated graph with global references and duplicate checks.
  Directory changes and atomic replacement reload the complete candidate;
  invalid candidates retain the last good snapshot.
  Resource identities and references retain their namespace through policy,
  DNS, subscriptions, credentials, runtime slots, reload, and management views.
  Wire Egress identities and TrafficClass names use canonical resource names;
  opaque credential references retain their original values. Supplied inactive
  DNS routes are validated without panicking, capability booleans default
  independently, and omitted rule matches express catch-all intent.
  Owner journal/pin components use stable bounded digests where needed, and
  identities that cannot fit management bounds are rejected before publication.
  Long subscription names preserve independent generated-node ownership, while
  older cache IDs remain readable and drain on the next successful refresh.

- The eight-crate Rust workspace uses the pinned Rust 1.100.0 toolchain,
  builds on Linux, and cross-checks for Windows GNU and FreeBSD x86_64.
  Core frame/message codecs, state machines, bounded reliability buffers,
  wire vectors, and UDP/Path lifecycle payloads are implemented.
- Native package recipes cover Debian, Alpine, Arch Linux, FreeBSD, and
  Windows NSIS. They share the `pathchord(1)` manual and loopback-only default
  configuration template; Linux and Alpine service definitions use
  `/etc/pathchord`, the FreeBSD port uses `/usr/local/etc/pathchord`, and
  packaged Windows services use `%ProgramData%\PathChord\config`. Package
  assembly remains host-tool and native-service validation work.
- Noise IK uses Clatter zeroizing key and cipher containers with an Orion
  SHA-256/HMAC adapter. Static, ephemeral, chaining, and traffic-key owners
  have explicit cleanup paths. Frozen vectors preserve the previous wire bytes.
- Async role-separated Path admission performs Noise IK, `PATH_HELLO`,
  `SESSION_ATTACH`, authorization lookup, capability negotiation, and
  `PATH_READY` over a real byte stream. Egress bounds the complete admission
  exchange to ten seconds by default, with an explicit positive runtime override
  capped at sixty seconds. Timeout and authorization cleanup release its permit.
  Both peers retain the complete known capability intersection and enforce TCP,
  UDP, and TrafficClass admission; subsequent Paths must match the Session set.
  Capability selection uses the already registered `PATH_READY_CAPABILITIES`
  message. Update both endpoints together: older implementations can reject that
  message without the class bit or omit required selections in plain `PATH_READY`.
- The Session runtime supports TCP and UDP Streams, multiple Paths, per-Stream
  eligible Path sets, DATA/ACK/WINDOW/FIN/RST, bounded reordering and buffers,
  Path drain/close, bounded timer retransmission, cross-Path re-framing, and
  supervised shutdown. Session control messages use a separate ordered,
  acknowledged and retransmitted envelope. Duplicate or stale authenticated
  records are dropped without failing the Path, and UDP close drains accepted
  queued datagrams within a deadline. The Session control envelope changes the
  v1 wire exchange: Ingress and Egress must run matching revisions.
  Authenticated malformed payloads fail only their owning Path, Egress target
  I/O errors retain `TARGET_FAILURE`, received drain deadlines close expired
  Paths, and Stream open RequestIDs use operating-system random 128-bit values
  while semantic retransmissions retain the original identifier.
- Ingress has ordinary HTTP forwarding and CONNECT, SOCKS4/4a/5 CONNECT,
  SOCKS5 UDP ASSOCIATE, Linux REDIRECT
  and TPROXY adapters, transparent UDP, a direct smoltcp TUN reactor, process
  metadata lookup, listener flow tags, listener-local Basic/username-password
  verification, and protected endpoint replacement.
- Linux TPROXY listeners accept `backend: tproxy` (the default) or the
  interface-bound `backend: ebpf` classifier. The eBPF path embeds a TC object,
  pins/configures its mark map through `bpftool`, attaches with `tc`, and
  removes its filter, qdisc ownership, pins, and policy routes on shutdown.
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
  `EgressService.spec.remoteDnsOnly` selects Egress system resolution for
  supplied hostnames without trusting accompanying Ingress address candidates.
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
  coverage. VLESS + REALITY uses the local rustls ClientHello callback, X25519
  proof, and certificate proof verifier. Native VMess supports TCP, TLS,
  WebSocket/WSS, AES-128-GCM or ChaCha20-Poly1305 body records, single-target
  UDP, and `alter_id: 0`; plain TCP and TLS/WebSocket AES paths have real peer
  fixtures. Native Hysteria2 covers QUIC/TLS, HTTP/3 authentication, TCP/UDP
  relay, Salamander, and bounded server-port rotation with a real peer fixture.
  Native TUIC covers QUIC/TLS-exporter TCP CONNECT, UDP DATAGRAM relay,
  heartbeat, and optional 0-RTT setup with a real TCP/UDP peer fixture.
- AnyTLS has a native TLS/session adapter with bounded frame/authentication
  codec, settings, SYN/SYNACK, PUSH/FIN, heartbeat handling, bounded
  UDP-over-TCP framing, and a sing-box TCP/UDP protocol-peer interoperability
  fixture.
- Reality has a bounded pure-Rust wire/crypto codec and a local rustls patch
  for the ClientHello proof callback and X25519 secret seam. The VLESS +
  REALITY adapter is registered; construction/proof tests and a local decoy
  sing-box Reality/VLESS peer fixture pass.
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
  Root fetches, provider expansion, and retries share one 4 MiB body budget;
  interrupted and cancelled downloads retain their consumed allowance.
  Conflicting credential aliases produce unavailable-node diagnostics.
  Native Hysteria2 and TUIC honor explicit UDP enablement and disablement.
- Subscription usage is collected from `Subscription-Userinfo`; an explicit
  `PathChord-Traffic-Multiplier` extension supplies billing metadata. Cache,
  node queries, the console, and Path economics consume the metadata. Unknown
  statistics stay unknown; expiry is not a quota reset timestamp.
  Malformed optional total/expiry values do not erase valid upload/download
  counts. Explicit billing multipliers remain available independently of usage,
  and missing usage counts are null rather than fabricated zeroes.
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
  Ingress exposes listener and resource events, authenticated Egress reports,
  subscription refresh state, structured reload diagnostics, and replayable
  management responses. Subscription URLs are redacted in read views.
  SSE rejects missing capabilities before opening the stream and closes failed
  gap recovery without publishing a partial snapshot or advancing its cursor.
- Connection observations preserve every admitted live record and keep at most
  1,024 terminal history records. At the 16,384-record safety bound, only terminal
  history is evicted; fixed resource-limit reasons remain queryable as degraded
  observation state. HTTP, SOCKS, and Mixed runtimes share a platform admission
  allowance in addition to their local limits, so connection churn cannot
  exhaust history and terminate Ingress.

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
- Linux transparent TCP/UDP and TUN need privileged host smoke validation of
  `ip` rule/table ownership, IPv4/IPv6 interception, real `/dev/net/tun`
  operation, host routes, and cleanup after restart. Fake route/device tests
  cover rollback and packet semantics but do not establish that host evidence.
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

- A Session containing flows admitted by different TrafficPolicies uses the
  most restrictive budget observed during that Session; it does not restore a
  larger budget after a flow ends. Egress does not yet receive a negotiated
  replication budget, so it suppresses extra copies while retaining ordinary
  reliable retransmission. Independent class budgets across multiple active
  policies and bidirectional budget negotiation need further implementation.
- Congestion-window, incremental-capacity, and scheduling-overhead measurements
  are optional scheduler inputs. No platform source supplies them by default;
  they remain unknown rather than being inferred from idle throughput.
- Some management detail fields, including listener-independent connection
  timing, Path admission timestamps and Transit identity, Session admission
  timestamps have no runtime producer. The API exposes unavailable values as
  null; they still need typed producers before the full observability contract
  is met.
- Subscription enable/disable/delete and source replacement use a control/data
  plane visibility barrier. Successful mutations block new selection before the
  worker drains old imported nodes; stale refreshes and publications are
  rejected by the control generation and full source specification. The worker
  still performs physical draining asynchronously, and an update that changes
  a source with an in-use node may wait for that node before promoting the new
  adapter. SSE recovery snapshots are assembled from bounded resource queries
  rather than a single atomic cross-resource transaction.
- Native Windows/FreeBSD runtime matrices, provider soak tests, external
  monitoring deployment, and a broad real-provider protocol/parameter matrix
  remain validation work. SSR and other unregistered protocols stay explicitly
  unavailable. Cross-machine Reality and long-running protocol soak evidence
  remain validation work.
  Third-party policy groups, rules, and scripts are not imported as PathChord
  policy.

## Deferred work

- Linux TPROXY mark/routing behavior, IPv4/IPv6 transparent UDP, and TUN
  integration are implemented, but privileged host validation remains
  deferred. Route ownership journals are designed to fail closed and never
  remove foreign rules. Wintun packaging and native Windows TUN validation are
  also deferred.
- An optional Linux eBPF interception backend is implemented as an explicit,
  interface-bound TC classifier switch. The ordinary TPROXY backend remains
  the supported fallback; root-level kernel/privilege smoke and failure
  recovery validation remain outstanding. The staged decision and prerequisites
  are recorded in [the dae/eBPF research note](changes/validate-native-platforms/research/dae-ebpf-transparent-proxy.md).
- Protocols outside the registered native set remain
  unavailable with node diagnostics. Further native implementations need
  protocol-specific interoperability fixtures.

## Validation evidence

The [specification-alignment repair](changes/fix-spec-alignment-findings/) adds
regressions for connection churn beyond 16,384 completions, shared admission
across HTTP/SOCKS/Mixed runtimes, typed history limits, SSE authorization and
failed gap recovery, namespace-isolated configuration/selection/cache/control,
bounded owner filenames, invalid DNS reload recovery, admission timeouts at
five handshake stages, malformed authenticated frames with a surviving Path
and Stream, capability negotiation and TCP/UDP admission, target failure
classification, drain deadlines, random RequestID replay, native UDP options,
credential aliases, failed provider budgets, and independently optional usage
facts. These are local deterministic or loopback checks; they do not establish
new native-host, cross-machine, or prolonged-soak evidence.

The repair workspace run passes 671 tests with zero failures and ten existing
external-peer tests ignored. A separate CLI-process check completes 16,500
loopback CONNECT flows while Ingress remains running, then shuts it down
normally. Workspace Clippy and formatting checks pass. All-target workspace
checks pass for Windows GNU and FreeBSD x86_64; the FreeBSD check uses the
existing SDK/compiler wrappers described below and does not execute native
FreeBSD tests. Strict OpenSpec validation passes all sixteen current items,
and local documentation links, anchors, and bilingual structural identities
pass validation.

Recorded passing checks include:

```text
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo test --locked -p netlink-packet-utils
cargo deny --all-features --locked check advisories
cargo check --locked --workspace --all-targets --target x86_64-pc-windows-gnu
cargo check --locked --workspace --all-targets --target x86_64-unknown-freebsd
cargo build --locked -p pathchord-cli --target x86_64-unknown-freebsd
git diff --check
```

The full workspace test run covers protocol, policy, Noise, Path, Transit,
Ingress, Egress, CLI, real loopback Egress/Ingress TCP and UDP paths, platform
fakes, route rollback, TUN packet flows, Web REST/SSE, persistence, reload,
subscription normalization, and fault/retransmission cases. The dependency
graph contains no `paste` package. A local `netlink-packet-utils` 0.5.2
compatibility patch aliases the maintained `pastey` macro crate for the
Netlink dependencies of `netsock`; the upstream Rust source and public API
are preserved. CI tests the exported buffer macros separately, and
`cargo-deny` 0.20.2 passes the same advisory check used by GitHub Actions.

Cargo 1.100 reports an unused `netsock` dependency on Linux because the native
provider uses it only on non-Linux platforms. Its dependency declaration stays
unconditional: restricting it to non-Linux targets makes
`cargo test --locked -p netlink-packet-utils` panic inside Cargo's feature
resolver when selecting the inactive compatibility patch. The existing CI
package test remains enabled.

The Linux workspace run passes every non-ignored workspace test. The normal
Transit unit run does not require an external proxy executable and leaves the
reference-peer tests ignored. With
`PATHCHORD_TEST_SING_BOX` pointing to the external sing-box 1.14.4 binary,
`scripts/test-with-sing-box.sh` ran all seven ignored protocol tests
successfully: VLESS/Trojan, VMess TCP/TLS/WebSocket/UDP, AnyTLS TCP/UDP,
Hysteria2 TCP, TUIC TCP, and Reality/VLESS. The binary is a test-only peer and
is not part of the PathChord runtime or dependency graph. Each fixture starts
sing-box with an inbound server and exercises the PathChord native Transit
adapter as the client; the compatibility direction is intentional.
The external-core fixture covers native Shadowsocks, VMess, VLESS, and Trojan
server compatibility with Mihomo 1.19.34, Xray 26.11.9, and V2Fly 5.53.0.
Mihomo additionally covers AnyTLS, Hysteria2, and TUIC server compatibility;
those protocols are not registered as Xray/V2Fly server protocols in their
respective test matrices. Each core is launched as the server and the matching
PathChord native Transit adapter is the client under test. All matrix entries
pass when the corresponding `PATHCHORD_TEST_MIHOMO`, `PATHCHORD_TEST_XRAY`, or
`PATHCHORD_TEST_V2FLY` variable is supplied.
The external-core cases are ignored in standard workspace runs and execute
explicitly in the CI core matrix. Mihomo readiness waits for a post-up marker
written after its tunnel accepts traffic; an open TCP listener alone is not
sufficient. A non-ignored Unix regression checks that an open port cannot
bypass that marker.
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
crypto dependencies. Both pass with Rust 1.100.0. The resulting x86_64 ELF
uses `/libexec/ld-elf.so.1` and links against `libprocstat.so.1`, `libthr.so.3`,
`libc.so.7`, and `libutil.so.10`. This validates target compilation and
linking; it does not execute FreeBSD tests. Native FreeBSD validation remains
pending a host run.

The default Linux environment does not select the SDK wrappers. A plain
FreeBSD workspace check invokes the host GCC for `aws-lc-sys` and fails with
`unknown type name 'pthread_rwlock_t'`. A minimal Rust binary also fails to
link with the host linker because it cannot find `-lexecinfo`. The Rust target
standard library alone does not supply a FreeBSD C compiler, headers, startup
objects, or system libraries.

The local Zig and FreeBSD SDK are already present; the missing setup is
target-specific compiler, archiver, and linker selection. Cross builds need
`CC_x86_64_unknown_freebsd`, `CXX_x86_64_unknown_freebsd`,
`AR_x86_64_unknown_freebsd`, and
`CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_LINKER` to select wrappers that use the
same FreeBSD sysroot. The linker wrapper must preserve host build-library
search directories passed by Cargo rather than resolving them inside the
sysroot, and must not bind those directories to one checkout or target folder.
