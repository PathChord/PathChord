# PathChord implementation status

Status snapshot: 2026-11-18.

This document records the current implementation and validation state. Final
architecture remains under `docs/design/`; behavioral contracts live under
`openspec/specs/`. User configuration and operation guides live under
`docs/guides/`. Pending actions are tracked in the [active changes](changes/);
this snapshot records evidence rather than a second implementation plan.

The multi-endpoint Egress change is implemented in the local runtime. Egress
Service accepts ordered `binds` with the singular `bind` shorthand, and the
Ingress Egress resource accepts ordered `endpoints` with the legacy
`address`/`port` shorthand. One Egress identity, authorization store, Session
pool, wire budget, and target-connection limit are shared across listeners;
each Path selects and retains its endpoint with bounded pre-admission failover.
Local control observations expose bounded listener and endpoint ordinals while
the authenticated `STATUS_REPORT` remains aggregate and unchanged. Linux
loopback evidence covers IPv4, IPv6, hostname candidates, different ports,
HTTP CONNECT, and UDP. Windows and FreeBSD native suite and host integration
results are recorded below, separately from cross-build and deployed evidence.

The [pathchordctl interaction redesign](changes/redesign-pathchordctl-interaction/)
adds role-aware source and socket resolution, human and structured output, and
local configuration inspection and managed YAML editing. The enrollment CLI
uses Egress authorization preconditions while Ingress edits its local Egress
resource. Linux verification includes the workspace suite, a two-process
TCP/UDP loopback fixture, and interrupted adoption recovery. Windows GNU
cross-checks for the CLI and Egress compile their platform-specific paths.
Native package lifecycle and deployed interoperability evidence are recorded
separately.

## Current focus

The [geosite and geoip routing change](changes/archive/2026-11-17-support-geosite-geoip-routing/)
adds local V2Fly geodata databases, named-set rule matching and atomic dataset
reload. Deterministic tests cover domain types, attributes, IPv4/IPv6, invalid
inputs and retained generations. Official domain-list-community release
`20261116002619` and v2fly/geoip release `202611080027` were verified against
their published checksums; each set compiled independently. On the authorized
`egress-jp-1` test host, a local Ingress routed the Hugging Face origin and CDN
through `geosite:huggingface` and downloaded a 1 MiB range with HTTP 206; a
separate `geoip:au` IP request reached Egress and returned HTTP 301. Both used
the two subscription sources, at least three Paths at admission, and a local
HTTP proxy. An earlier run with an older diagnostic Egress stopped after a
partial range and did not expose the Session termination reason; the repeat
with the updated Egress completed while Paths were replaced. See the change's
research record for dataset hashes. These bounded tests are not prolonged
throughput or native-platform evidence.

The unreleased v1 session/resource contract is now implemented through the
wire, lifecycle, scheduling, Egress-resource, TLS, and local-control slices.
The implementation uses the finalized v1 registry without PathRebind or
TrafficClass wire extensions; Session attachment negotiates a mandatory
replication cap, ACKs are checked against emitted intervals, and a validated
future ACK closes the whole Session before fresh-Session recovery. Lifecycle
events are owned by the Session/Path owner, Transit relationships can carry
multiple independent Paths, rule demand is bounded and EWMA-sampled, and
candidate failover stops at target admission. Egress target reservations,
global capacity/admission status, actual global wire-budget enforcement with
residual optional replication, resource-limit errors, passive capacity
confidence, truststore source validation, and local-control stage deadlines
are present in the local implementation.

The [configuration and Path-target change](changes/archive/2026-11-17-unify-configuration-and-add-path-targets/)
is implemented in this worktree. Ingress Egress resources now place the
count-based admission minimum in `pathPool.minUsablePaths`, keep common Egress
capability requirements in `admission.requiredCapabilities`, and optionally
set `pathPool.targetUsablePaths`. An omitted target resolves to minimum plus
one; an explicit target is used as written. Ingress keeps the bounded baseline
warm without business connections, permits capacity demand to expand above it,
and slowly drains surplus back toward the baseline. A shortfall above the
admission minimum is visible without changing admission or service state.

The public resource API remains `pathchord.io/v1` with an intentional native
configuration break: retired endpoint, Path-pool, EgressService Web, and
Transit option keys fail with `CONFIG_RETIRED_FIELD` and a canonical replacement
path. Native endpoints use `host`; EgressService Web options are grouped under
`web`; Transit option lists, byte limits, UDP-over-TCP versions, and ClientHello
profiles use explicit canonical names. Foreign subscription syntax and private
credential JSON remain unchanged. Normalized Transit caches use version 3;
older or retired-option caches are rejected before node publication and
refreshed under the configured subscription source and its existing budgets.

Authorized Session queries, events, snapshots, and aggregate Prometheus gauges
distinguish requested/effective baselines, the current demand target, usable
Paths, and baseline shortfall with a bounded reason. English and Chinese main
specifications and user guides have been reconciled with the completed change;
the archived planning artifacts preserve its migration table and verification
checklist.

The evidence below remains local Linux build/test evidence unless a section
explicitly names a native host, external peer, cross-machine run, or soak.

The role service artifacts remain separate in source:
`pathchord-ingressd`, `pathchord-egressd`, and `pathchordctl` build as separate
targets. The shared configuration and control crates are independent of the
Ingress runtime; Egress configuration accepts exactly one EgressService and
Egress dependency inspection excludes Ingress and Transit runtime crates. The
supported packaged deployment selects one role per device and uses one local
Unix `pathchord` service account. Mutually exclusive role packages and native
service lifecycles have passed on Debian, Alpine, Arch Linux, FreeBSD and
Windows; each payload contains only its selected daemon and `pathchordctl`, and
an opposite-role install is rejected before state changes. The
[single-role package report](changes/archive/2026-11-18-validate-native-packages/research/2026-11-17-single-role-packages.md)
records the Unix package hosts; the
[final Windows package report](changes/archive/2026-11-18-validate-native-packages/research/2026-11-18-windows-package-final.md)
records both Windows role profiles and their service identities.

The scheduling slice now has deterministic coverage for independent mixed-flow
replication budgets, reserved control/retransmission priority, directional
autoscale inputs, rule-union Path planning, and Egress capacity hysteresis.
Egress target opens (TCP and UDP) share one bounded active-plus-pending
reservation pool; local control saturation returns a typed resource-limit
response. Relative truststore sources are resolved from the selected config
source and all TLS-capable adapters consume the resolved truststore.

The typed observation slice now publishes Session creation/change timestamps,
UDP and pending-control counts, Path Egress/Transit identity, directional Path
throughput, available capacity, and control retransmission fields where the
runtime owns those facts. Admission-generation and Path-ready timestamps remain
explicitly null because no authoritative producer owns those values yet. SSE
recovery retries bounded resource snapshots when their observation generations
do not match; the resource queries are still not one cross-resource atomic
transaction.

The Egress-scoped Path selection change is implemented in the local runtime.
Ingress configuration now requires an Egress-owned Transit binding and one
TrafficPolicy reference; EgressRule matching selects only the Egress, while
warmup and autoscaling maintain one Session Path pool with one common minimum.
Legacy TransitRule, EgressRule Path requirements, TrafficPolicy classes,
classReplicationBudgetBps, and trafficClassRef are rejected by the authored
configuration schema. The attachment replication request is derived from the
captured Egress policy (disabled requests zero; enabled converts bits per
second to wire bytes per second), and later Paths retain the Session policy.
Stream/UDP opens encode an empty eligible-Path list; canonical non-empty legacy
lists are rejected before target dialing with `LOCAL_POLICY`, while opaque
cancel and control sequencing remain available. Session observations expose
the Egress minimum, bounded target, usable Path count, eligible Transit count,
policy identity, and nullable directional demand/replication fields. Changes
to an Egress binding or referenced policy require restart; dynamic Transit
membership continues to drain removed Paths.

Local validation for this change includes policy/configuration unit tests,
Path runtime alignment tests, Ingress reload and Session tests, the CLI
multi-process HTTP/UDP smoke test, the complete locked workspace test suite,
formatting, Clippy, strict OpenSpec validation, and documentation diff/link
checks. Native-platform, external-peer, and production probe calibration
evidence remain separate and are not inferred from these local checks.

Earlier local validation of the v1 contract, before the current uncommitted
proxy-compatibility work:

- `cargo fmt --all -- --check` passed.
- Locked workspace Clippy with `-D warnings` passed; on Linux Cargo reports
  `netsock` as unused even though the Windows and FreeBSD metadata providers
  use it under platform-specific compilation.
- `cargo test --locked --workspace --all-targets` passed. The seven external
  core/peer interoperability tests remain explicitly ignored unless their
  external binaries are supplied.
- `openspec validate --all --strict --no-interactive`, `git diff --check`, and
  the repository heading/bilingual documentation audit passed.
- Native Windows execution and prolonged soak were unverified at this earlier
  validation point. Privileged Linux, native FreeBSD, the completed Windows
  host matrix and the later provider soak are now documented in the dated
  evidence below; external-peer and cross-machine claims remain limited to
  their separately identified runs.

The explicit-listener runtime prioritizes HTTP forwarding/CONNECT,
SOCKS4/4a/5 CONNECT, SOCKS5 UDP ASSOCIATE, and same-port Mixed listeners.
FreeBSD configuration, native process metadata, platform identity and Unix
local control have passed their FreeBSD 15.1 native QEMU test run below. The
Windows 11 native suite, registry recovery and regular-user/service control
acceptance also pass. Portable listener regressions run in the existing Rust CI
job.

TPROXY, REDIRECT, transparent UDP interception, and TUN integration are wired
into the Ingress platform runtime with configuration, rollback, protected
endpoint handling, source restrictions, and bounded TCP/UDP flow supervision.
Privileged route/TUN host validation and Wintun packaging remain separate
acceptance work. SOCKS5 UDP forwarding remains in the current scope.

## Implemented

- Ingress and Egress share JSON logging from FATAL through TRACE via
  `PATHCHORD_LOG_LEVEL`, with INFO as the default. TRACE includes frame metadata, carrier write outcomes,
  scheduling, retransmissions and flow control. Ingress Path observations retain
  the selected Transit Proxy display name, source, protocol and Egress endpoint
  index. A local two-process TCP echo through an HTTP Transit fixture matched
  the Egress write and Ingress receive by Session, Path and frame sequence, and
  verified that the echo payload was absent from both logs.


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
- Native single-role package recipes cover Debian, Alpine, Arch Linux, FreeBSD,
  and Windows NSIS. Linux packages use `/etc/pathchord`, FreeBSD uses
  `/usr/local/etc/pathchord`, and Windows uses `%ProgramData%\PathChord\config`.
  Debian/Alpine/Arch/FreeBSD and Windows role payloads and lifecycle tests pass;
  the Windows result covers both roles, virtual service SIDs, private ACLs,
  Named Pipe control, opposite-role rejection, upgrade, rollback, uninstall and
  explicit replacement in the QEMU guest.
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
- The Session runtime supports TCP and UDP Streams, multiple Paths, a common
  Egress Session Path pool, DATA/ACK/WINDOW/FIN/RST, bounded reordering and buffers,
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
  Existing TCP and UDP traffic, retransmissions, and required controls can use
  live Paths even when status is stale or denies new admission; new opens still
  require an admissible Path. Strict initial admission waits at most three
  seconds for the first status, then rejects if it is unavailable. Local Noise
  Session tests cover both existing protocols, denied opens, lost-data
  retransmission, and admission recovery; a separate drain-deadline regression
  keeps a second Path alive across health ticks.
  Every new Stream and UDP Association uses the common Session pool in both
  directions. A Path failure can therefore move an admitted flow to another
  ready Path without changing its Egress or target socket. The configured
  `minUsablePaths` is an Egress Session minimum: below it, new admission is
  denied while existing work remains when another ready Path exists; loss of
  the last ready Path closes the Session. Planned scale-in counts only usable
  non-draining Paths after all selected drain candidates.
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
  Egress-owned Path slots, applies one Session TrafficPolicy replication
  allowance per sending direction, exports path-quality/session/individual
  Stream observations, and publishes DNS protected endpoints. Internal queue
  fairness and bounded priority remain, but business traffic-class settings
  are not part of the authored policy or observation surface.
- Static policy reload prepares every changed Transit adapter before a
  transactional runtime/control-plane commit. Failed preparation or durable
  control reconciliation retains the previous generation; changed Paths drain
  under a bounded retirement task while existing Streams continue.
- Explicit NodeProbePolicy configuration performs bounded TCP connect probes
  only to its configured target. Observations expose adapter readiness, state,
  latency, jitter, loss, and typed failures without fabricating throughput or
  capacity. Source disablement, deletion or replacement cancels its queued or
  active probes; admission is rechecked before dialing and publishing results.
  Local regressions cover queued and active cancellation while other sources
  and static nodes continue. Probing is disabled by default.
- Egress has a real TCP Path listener, authorization-backed admission, target
  Stream/UDP forwarding, multiple Path attachment, global status inputs,
  authorization reconciliation, cleanup barriers, and bounded supervision.
  `EgressService.spec.remoteDnsOnly` selects Egress system resolution for
  supplied hostnames without trusting accompanying Ingress address candidates.
  Wire-rate samples use at least one-second windows and become zero after an
  empty window. Expired capacity remains stale and blocks new admission while
  Streams or target connections are active. Once both are idle, the expired
  estimate is discarded and capacity returns to unknown, allowing a new Path
  to start collecting evidence. A deterministic local regression ages a real
  Egress's sample after a Noise Session and echo, then verifies a second Session
  and echo; separate tests cover active-work staleness and idle rate decay.
- Ingress and Egress use role-specific service artifacts and roots. Ingress
  consumes the complete policy resource graph from its Ingress source;
  Egress consumes exactly one EgressService from its Egress source and reports
  restart-required when the startup source changes without replacing the active
  runtime. `pathchordctl` owns status, enrollment, key generation, and local
  control operations. The unreleased multi-call service binary is no longer a
  package target.
- Policy parsing preserves subscriptions, DNSPolicy, opaque credential
  references, listener platform/protocol/process fields, and flow tags.
  `CompiledPolicy` evaluates Egress, Transit, ordinary Proxy, and fallback
  routes without I/O.
- Transit adapters include direct TCP, HTTP CONNECT, HTTPS CONNECT over
  rustls, SOCKS5, and Shadowsocks, with direct/SOCKS5/SS UDP, SS2022 and
  selected legacy stream methods. Explicit `none`/`plain` modes are available;
  other unsupported methods and plugins remain unavailable.
  Typed TLS settings include SNI, ALPN, custom CA, explicit insecure, and
  client-certificate/key references. HTTP custom headers are validated. Unknown
  credentials/options are rejected instead of ignored; TLS options cannot
  silently become plaintext. Credential files retain bounded, private,
  symlink/TOCTOU-checked, redacted handling.
- SOCKS5 supports UDP-over-TCP v1/v2, including through its configured TLS
  stream. HTTP CONNECT consumes its optional request path from private
  credentials and validates Host overrides. VMess supports AEAD global padding
  and authenticated length. VLESS/VMess Meek uses a private HTTPS URL; Meek
  local write shutdown does not signal an end-of-stream to its remote peer.
- Native `h2mux`, `yamux` and `smux` wrap SS, VLESS, VMess and Trojan with bounded
  connection pooling, optional sing-mux padding and TCP/UDP streams. Multiplex
  carries its own UDP frames; explicit packet-encoding or UDP-over-TCP
  combinations remain unavailable. A smux session supports at most 256 streams,
  separate 4 MiB receive and transmit queue budgets, a 256 KiB per-stream
  receive budget, and bounded frame counts. Receive pressure isolates the
  selected stream with an error and FIN so other streams can progress.
  Stalled buffered carrier I/O on active streams needs cancellation by the
  caller or a higher-level timeout. Pending I/O after the final stream release
  shares a ten-second drain deadline.
  smux FIN follows the peer's full-close behavior and does not guarantee a
  delayed response after local write shutdown.
- Shadowsocks also supports UDP-over-TCP v1/v2, including over its configured
  TCP plugin. An independent sing-box server verified AES-128-GCM and
  AES-192-GCM with IPv4/IPv6 and repeated 4096-byte UDP payloads; subscription
  normalization preserves sing-box and Clash version defaults separately.
- Shadowsocks supports SIP004 `aes-192-gcm` and legacy `xchacha20` over TCP
  and UDP, including native simple-obfs HTTP/TLS for their TCP connections;
  UDP uses Shadowsocks datagrams without the TCP plugin unless UDP-over-TCP is
  configured. These two methods use
  a per-adapter window of 4096 recent outgoing and incoming salts or IVs to
  reject repeats while retained. Legacy stream encryption, including
  `xchacha20`, does not authenticate payloads.
- Shadowsocks supports native `v2ray-plugin` WebSocket with optional TLS,
  default single-stream mux or `mux=0`. UDP uses native Shadowsocks unless
  UDP-over-TCP is configured through the plugin.
  Other plugin transports and mux counts remain unavailable.
- Native Rust VLESS and Trojan adapters support TCP, TLS, WebSocket, WSS,
  HTTP/HTTP2, gRPC, HTTPUpgrade and QUIC
  combinations with real protocol-peer TCP and UDP interoperability
  coverage. Trojan-Go share links cover original/TCP, WebSocket, gRPC and
  HTTPUpgrade aliases; its WebSocket Shadowsocks layer covers AES-128-GCM,
  AES-256-GCM and ChaCha20-IETF-Poly1305. Original/TCP plus that layer remains
  unavailable because short-stream HTTP sniffing in the reference server is
  unreliable. VLESS + REALITY uses the local rustls ClientHello callback, X25519
  proof and certificate proof verifier. Both registered Vision flow names use
  bounded framing and independent DIRECT transitions in both directions. Vision
  uses XUDP without multiplex and the selected multiplex UDP framing otherwise.
  Clash and sing-box VLESS imports with omitted packet encoding default to XUDP
  unless multiplex is enabled; authored VLESS without Vision or multiplex
  defaults to ordinary VLESS UDP. Vision rejects packetaddr, and explicit packet
  encoding is incompatible with multiplex.
  REALITY supports dae/uTLS Chrome 133, iOS 14, Safari 16, Edge 85, QQ 11.1 and Firefox 120 fingerprints;
  Chrome can switch between classic and hybrid key shares after a verified
  decoy. Ordinary TLS also supports Android 11 OkHttp for TLS 1.2 without ALPN;
  its REALITY, Vision and ALPN-dependent transport combinations are rejected.
  The 360 profile and other unimplemented fingerprints remain unavailable.
  Native VMess supports TCP, TLS,
  WebSocket/WSS, HTTP/HTTP2, gRPC, HTTPUpgrade and QUIC,
  AES-128-GCM, ChaCha20-Poly1305 or AES-128-CFB body records,
  explicit `none`/`zero` plaintext bodies, single-target UDP with XUDP or
  packetaddr encodings, and positive legacy `alter_id` values up to 65,535;
  plain TCP and TLS/WebSocket AES paths have real peer
  fixtures. Native Hysteria2 covers QUIC/TLS, HTTP/3 authentication, TCP/UDP
  relay to IPv4 and IPv6 targets, bounded UDP fragmentation and reassembly,
  Salamander, Gecko with configurable padding sizes, bounded server-port rotation and a
  `down_mbps` server hint, and negotiated BBR or Brutal upload congestion
  control. The server may ignore the download hint. A server response of
  `auto` selects BBR regardless of `up_mbps`; numeric zero selects the local
  upload rate, while a positive response selects the smaller of the server
  value and the local rate. An absent or zero `up_mbps` retains BBR. Brutal
  compensates for loss; PTO probes and ACK-only packets may bypass pacing, so
  the target is not a strict physical bandwidth cap. The
  [Brutal pacing investigation](changes/archive/2026-11-17-support-sing-box-dae-transit-protocols/research/2026-11-16-hysteria2-brutal-pacing.md)
  records the narrowly patched Quinn hooks, validation and limits.
  Native TUIC covers QUIC/TLS-exporter TCP CONNECT, UDP DATAGRAM and
  QUIC-stream relay or UDP-over-stream, cubic/NewReno/BBR congestion control and heartbeat with a
  real TCP/UDP peer fixture. Hysteria2 and TUIC reject TLS fingerprints
  until QUIC-specific profiles are implemented. TUIC 0-RTT remains unavailable until exporter
  authentication and rejected early-data recovery are implemented safely.
- AnyTLS has a native TLS/session adapter with bounded frame/authentication
  codec, settings, SYN/SYNACK, PUSH/FIN, heartbeat handling, bounded
  UDP-over-TCP framing, and a sing-box TCP/UDP protocol-peer interoperability
  fixture.
- Reality has a bounded pure-Rust wire/crypto codec and a local rustls patch
  for the ClientHello proof callback and X25519 secret seam. The VLESS +
  REALITY adapter is registered; construction/proof tests and a local decoy
  sing-box Reality/VLESS peer fixture pass.
- Supported sing-box proxy definitions normalize to native adapters. Documents
  with unsupported fields remain private unavailable-node diagnostics, and
  policy selectors are not imported as nodes. PathChord does not start or
  embed a compatibility process.
- Subscription refresh supports automatic detection, Clash/Mihomo, SIP008
  arrays and object wrappers, URI/Base64 lists, sing-box document syntax, and
  supported Surge/Quantumult X/Loon node lines. Unrepresentable external
  documents remain unavailable diagnostics. HTTP provider references
  are bounded by depth/count/aggregate bytes and propagate bearer credentials
  only to the same origin. Individual invalid nodes retain sanitized
  diagnostics; malformed documents and failed providers retain applicable
  last-good data. Cache, draining, controls, and reload preserve diagnostics.
  A per-subscription User-Agent is configurable through YAML and control API,
  defaults to `clash.meta`, and is shared with referenced HTTP providers.
  Effective UA participates in the private cache and refresh source identity;
  caches predating UA binding are rejected, while old declaration ownership
  decisions remain compatible. Concurrent local HTTP and restart tests cover
  these boundaries.
  Root fetches, provider expansion, and retries share one 4 MiB body budget;
  interrupted and cancelled downloads retain their consumed allowance.
  Conflicting credential aliases produce unavailable-node diagnostics.
  Native Hysteria2 and TUIC honor explicit UDP enablement and disablement.
  Imported and restored nodes remain pending until the configured registry
  builds and prepares their exact adapter within a timeout. The resulting
  admission is bound to the source, complete configuration, private
  credentials, and snapshot generation; its capabilities reflect the adapter
  and explicit UDP settings. Cache loads do not inherit old admissions, and
  source disablement or replacement revokes even cloned admissions. Queued and
  in-flight node probes are cancelled when source visibility is withdrawn;
  stale results cannot publish and unrelated probes continue. Registration
  conflicts and preparation failures produce sanitized diagnostics. When a
  refresh replaces credentials, old Paths stop accepting new streams while
  established streams can drain for up to five seconds. Local tests exercise
  cache revalidation with a changed backend, overlapping refreshes, credential
  replacement, timeout and cancellation, registration conflicts, and source
  fencing. Local HTTP CONNECT and Noise/Egress exchanges cover failed-refresh
  recovery and replacement Path retirement. Preparation validates the adapter
  locally; it does not establish that a provider node is reachable.
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
  Session UDP forwarding. A 300-second explicit-listener failure/restart soak
  and the selected cross-machine protocol matrix both passed; neither represents
  production WAN performance or deployment evidence.
- Native Windows 11 Pro 26H2 QEMU coverage passed 52 staged executable groups:
  1,075 tests passed, zero failed, 117 external-peer/explicit host child-entry
  fixtures were ignored, and no executable timed out. HTTP/CONNECT,
  SOCKS4/4a/5, Mixed and SOCKS5 UDP exercised native Windows sockets, including
  authentication, IPv4/IPv6/domain resolution, bounded resources and shutdown.
  Three formerly unstable ordering/timeout/watcher cases also passed ten
  repeats each. The [current Windows report](changes/archive/2026-11-18-validate-native-platforms/research/2026-11-18-windows-fix-validation.md)
  records source/artifact hashes and the reusable prepared snapshot; the
  [first failed run](changes/archive/2026-11-18-validate-native-platforms/research/2026-11-17-windows-qemu-validation.md)
  remains historical evidence.
- Linux TPROXY/REDIRECT/TUN and optional TC/eBPF ownership, IPv4/IPv6 forwarding,
  rollback, crash recovery, foreign-object preservation and fallback passed a
  disposable native-kernel QEMU matrix; see the evidence below. The development
  host kernel could not run the full matrix because its nft TPROXY module does
  not match the running kernel.
- Windows Secure Boot and TPM readiness were verified before the cold snapshot.
  The explicit native WinINet host fixture now passes apply/refresh, exact
  prior registry type/byte restoration, absent-value restoration, forced-kill
  journal recovery and restart. The saved `REG_EXPAND_SZ` type is reapplied
  after WinINet notification before deleting the journal. The ordinary-user
  Named Pipe ACL and host watcher phase also passed using an SCM-launched
  nonadministrator Users account: the daemon owner SID matched the owner-token
  probe, administrators retained access, an unrelated ordinary user was
  denied, and valid, invalid, in-place and atomic configuration changes had the
  expected visibility.
- The FreeBSD 15.1 QEMU guest completed the native listener/control workspace
  suite and selected-role Egress permission/signal checks. Both FreeBSD role
  packages also passed native `pkg` creation, service, upgrade, rollback,
  uninstall and explicit replacement checks; see the single-role package report.
- Process metadata is best-effort: Linux uses bounded procfs reads and the
  non-Linux platforms use the safe `netsock` native socket/process providers.
  Process IDs and executable names are returned where permissions allow;
  user/group identifiers remain unknown when the platform API does not expose
  them.
- A 300-second explicit-listener Path/provider failure and restart soak passed;
  the exact matrix and resource peaks are recorded below.

## Shared implementation gaps

- A Session containing flows admitted by different TrafficPolicies keeps an
  independent bounded replication budget per Stream/Association while the
  negotiated Session replication cap remains the hard ceiling. Required
  control and ordinary retransmission reserve the aggregate wire budget before
  optional copies; aggregate Egress wire accounting still needs prolonged load
  evidence and cross-machine validation.
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
- Production monitoring rollout and probe/autoscaler calibration remain
  validation work. Quantumult X provider validation falls outside the
  v0.1.0 acceptance matrix. The Windows native platform and package matrices are
  complete for the recorded Windows build and fixture versions.
  SSR, SOCKS4/4a outbound and other unregistered protocols stay explicitly
  unavailable. The QEMU
  cross-machine adapter matrix is complete for its selected peer, protocol and
  network conditions; it is not WAN or production deployment evidence.
- The authenticated Prometheus endpoint exports aggregate Egress configured,
  effective, current-wire-rate, replication-allowance, denied-admission, and
  stale-report gauges from the same observation snapshot. The local Docker
  deployment under `monitoring/` now runs Prometheus and Grafana with a bearer
  token scrape, recording rule, alert rules, provisioned datasource, and
  dashboard. `scripts/monitoring-smoke.sh` performs a real scrape and checks
  the Prometheus and Grafana APIs; snapshot byte totals remain declared gauges,
  not lifetime counters.
- The local Docker deployment baseline records the default Path autoscaler
  values (`min=1`, `max=4`, scale-out 8000 bp, scale-in 3500 bp, samples
  3/3/6, cooldown 30 s) and NodeProbePolicy defaults (30 s interval, 5 s
  timeout, concurrency 8, window 32, batch 128). The smoke uses a smaller
  one-second probe policy, observes a real `up` RTT sample, and verifies the
  authenticated observation snapshot. These are deployment regression values,
  explicitly not production capacity or SLO measurements.
  The loopback probe reported `0 ms` after integer-millisecond rounding; this
  confirms probe publication and has no WAN latency meaning. All seven
  deterministic autoscaler tests pass.
  Third-party policy groups, rules, and scripts are not imported as PathChord
  policy.

## Deferred work

- Linux transparent and TUN forwarding, TC/eBPF interception, route ownership,
  foreign mark/filter preservation, crash recovery and ordinary TPROXY fallback
  have passed the disposable QEMU kernel matrix. Route cleanup remains journal
  owned. Wintun packaging and native Windows TUN validation are deferred.
- Protocols outside the registered native set remain
  unavailable with node diagnostics. Further native implementations need
  protocol-specific interoperability fixtures.

## Validation evidence

On 2026-11-23, the Transit subscription test suite passed 96 tests on Linux,
including import replay of six sanitized excerpts from one supplied
subscription. The excerpts cover inline Clash, versioned SIP008, sing-box,
Base64 URI lists, Surge and Loon. The supplied endpoint returned HTTP 403 for
Quantumult X. A fixture based on the Mihomo documentation exercises HTTP
provider expansion and credential origin boundaries. Separate provider tests
exercise fetch budgets. See the
[provider acceptance matrix](changes/archive/2026-11-23-validate-provider-and-runtime-reliability/research/2026-11-17-acceptance-matrix.md#supplied-subscription-probe).

Privileged Linux platform validation completed on 2026-11-17 in Alpine 3.24.4,
x86_64 QEMU/KVM with Linux `6.18.63-0-virt`, iproute2/TC 7.0.0, nftables 1.1.6
and bpftool 7.8.0. The final run passed 21/21 result groups, including TPROXY
IPv4/IPv6 TCP and 4096-byte UDP, REDIRECT IPv4/IPv6 TCP with explicit UDP
rejection, real TUN IPv4/IPv6 TCP half-close and fragmented UDP, route journal
rollback/recovery, eBPF IPv4/IPv6 forwarding, foreign-mark preservation, pin
ownership, crash/restart cleanup, occupied-priority rejection and explicit
TPROXY fallback. Guest namespaces were removed after the run. The development
host kernel is `7.2.15-zen1-1-zen` and lacks a matching `nft_tproxy` module, so
the full privileged matrix ran against the guest kernel and did not modify host
routes or firewall state.

Reproduction: `cargo build --locked --release --target x86_64-unknown-linux-musl --bin pathchord-ingressd --bin pathchordctl`, then
`python3 scripts/test-qemu-linux-platforms.py --cache /data/pathchord-qemu/linux-rootfs --output /data/pathchord-qemu/runs/linux-platforms --apk-address 146.75.114.132`.
The source revision was `9caf37278a61e28c6c5c1669eb793eb2b5ba33df` with a
dirty worktree. The Ingress binary SHA-256 was
`186a5dd8c8f47336ed72a6d7ce30b2f622bd50e627b66d3f42d8ab90ae9db647`. Exact
guest/tool versions, all result groups and source/APK/log/pcap hashes are in
[the machine-readable manifest](changes/archive/2026-11-18-validate-native-platforms/research/2026-11-17-linux-kernel-validation.json);
full behavior and implementation findings are in the adjacent Markdown record.

The explicit-listener reliability soak ran for 300.24 seconds over 12 cycles,
with eight injected failure classes repeated 12 times each. It completed 3,122
Path and 5,877 provider 8192-byte echo exchanges. All 577 Path and 122 provider
interruptions occurred during intentionally destructive churn/restart/revoke
or node-drain windows; retained-provider, parse/DNS/reload and stable windows
had no extra failures. Peak file descriptors were 17/20/18 and RSS was
17.1/50.1/52.0 MiB for Egress/Path-Ingress/provider processes. Detailed
per-cycle evidence and its limits are in the
[runtime reliability report](changes/archive/2026-11-23-validate-provider-and-runtime-reliability/research/2026-11-17-runtime-reliability.md).

Native FreeBSD validation completed on 2026-11-17 in FreeBSD 15.1-RELEASE,
amd64, under QEMU/KVM. The 51 native test executables passed 1,083 tests with
zero failures and 118 external-peer tests ignored. The suite includes native
dependencies, SQLite, HTTP/CONNECT, SOCKS4/4a/5, Mixed, UDP, authentication,
IPv4/IPv6, configuration watching, process metadata, control and shutdown. It
ran as the selected non-login `pathchord` account. A separate live Egress check
verified `0600` identity, SQLite database and control socket ownership/modes,
normal SIGTERM exit and socket removal. Source revision:
`9caf37278a61e28c6c5c1669eb793eb2b5ba33df`. The full per-executable, binary,
SDK, image and toolchain evidence is recorded in the
[FreeBSD validation manifest](changes/archive/2026-11-18-validate-native-platforms/research/2026-11-17-freebsd-native-validation.json).
The cached image for this run came from the official FreeBSD mirror and its
published SHA-256; `scripts/qemu_freebsd.py` now defaults future downloads to
the user-recommended CERNET mirror.

The FreeBSD run exposed and fixed a Kqueue watcher gap: writes made in place
were not observed when only the parent directory was monitored. The Ingress
watcher now observes source files and rearms file watches after atomic
replacement. Native tests cover in-place configuration/geodata changes and
file deletion/recreation.

Cross-machine Transit interoperability completed on 2026-11-17 between two
independent Alpine 3.24.4 QEMU guests, each running Linux `6.18.63-0-virt` on
the private socket-backed Ethernet network. The PathChord musl client talked to
the independent sing-box 1.14.4 server. Twenty positive cases covered VLESS
REALITY Vision, Hysteria2, TUIC, AnyTLS and VMess with IPv4/IPv6 peer endpoints,
IPv4/IPv6 targets, and baseline plus 10 ms one-way `netem` delay. Each case
verified 262,142 TCP echo bytes and 18,892 UDP echo bytes. Two negative cases
verified that unsupported VLESS gRPC parameters remain unavailable and retired
SSR does not register. The command, guest boot IDs, peer/client hashes,
source hashes and raw result hash are in the
[cross-machine protocol manifest](changes/archive/2026-11-23-validate-provider-and-runtime-reliability/research/2026-11-17-cross-kernel-protocol-validation.json).
This is isolated virtual-network evidence, not a real WAN or deployed-peer
result. The provider/import format matrix still lacks retained, anonymized
source-provenance examples for every document family; see the provider
[acceptance matrix](changes/archive/2026-11-23-validate-provider-and-runtime-reliability/research/2026-11-17-acceptance-matrix.md).

Single-role package and service lifecycle acceptance passed on Debian 12,
Alpine 3.24.4, Arch Linux and FreeBSD 15.1 for both Ingress and Egress
profiles. Each package contains only the selected daemon and `pathchordctl`,
uses one local non-login Unix `pathchord` account, and rejects the opposite role
without stopping or changing the installed service. Native lifecycle tests
covered service start/control, active upgrade, rollback, uninstall, explicit
role replacement, and sentinel configuration/identity/authorization retention.
FreeBSD Egress also verified a real enrollment record across restart and
preserved the actual identity/SQLite hashes on removal. Windows NSIS/PowerShell
native lifecycle acceptance passed for both roles in the prepared QEMU overlay;
the repaired helper and installer completed the full upgrade/rollback/uninstall
and role-replacement matrix. The historical first exit-code-2 run remains in
the [first Windows QEMU package report](changes/archive/2026-11-18-validate-native-packages/research/2026-11-17-windows-qemu-package-validation.md),
and the passing evidence is in the [final Windows package report](changes/archive/2026-11-18-validate-native-packages/research/2026-11-18-windows-package-final.md).
The [single-role package report](changes/archive/2026-11-18-validate-native-packages/research/2026-11-17-single-role-packages.md)
links the non-Windows per-profile evidence under `/data/pathchord-qemu/runs/native-packages/`.
The package fixture versions 0.1.0/0.1.1 use identical tested binaries and do
not establish cross-protocol-version or database-schema migration.

The current Linux workspace quality run on 2026-11-18 passed
`cargo fmt --all -- --check`,
`cargo clippy --locked --workspace --all-targets -- -D warnings`,
`cargo build --locked --workspace --bins`, and
`cargo test --locked --workspace --all-targets` (1,108 passed, zero failed,
118 ignored). Standard workspace runs keep
external peer cases ignored unless their pinned server binaries are provided;
the native peer matrices above were run separately. Clippy reports the existing
unused `netsock` manifest dependency warning.

The native platform, native package, and provider/runtime reliability
validation changes are archived. The mutually exclusive single-role package
model uses one Unix service account. The 2026-11-18 GitHub CI evidence includes
the dependency-advisory and external-core jobs. The local Docker monitoring
deployment is recorded separately below.

The [specification-alignment repair](changes/archive/2026-11-17-fix-spec-alignment-findings/) adds
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

A prior repair workspace run passed 671 tests with zero failures and ten existing
external-peer tests ignored. A separate CLI-process check completes 16,500
loopback CONNECT flows while Ingress remains running, then shuts it down
normally. Workspace Clippy and formatting checks pass. All-target workspace
checks passed for Windows GNU and FreeBSD x86_64; the FreeBSD check used the
existing SDK/compiler wrappers described below and does not execute native
FreeBSD tests. That prior repair run's strict OpenSpec validation passed all 23
items, and its local documentation links, anchors, and bilingual structural
identities passed validation.

The 2026-11-17 protocol acceptance rerun passed the applicable independent
peers and local control paths. sing-box 1.14.4 passed the native AnyTLS,
Hysteria2, TUIC, Reality/VLESS, VMess, HTTP, HTTPUpgrade, gRPC, WebSocket
early-data, QUIC, SOCKS5 UDP-over-TCP, Shadowsocks UDP-over-TCP, VLESS
packetaddr, multiplex, padding, and TLS-fingerprint cases. Mihomo 1.19.34,
Xray 26.11.9, and V2Fly 5.53.0 passed the external-core cases; Xray Vision and
gRPC, V2Fly Meek and legacy VMess `alter_id`, and the corresponding TCP/UDP
flows were exercised. Trojan-Go 0.10.6 passed original/WebSocket, encrypted
WebSocket, gRPC and HTTPUpgrade cases. v2ray-plugin 1.3.2 passed WebSocket/TLS,
mux, UDP-over-TCP, wrong-password, and TLS/path rejection cases. Upstream
simple-obfs HTTP/TLS passed with AES-256-GCM, and an independent sing-box
AES-192-GCM server passed the custom cipher TCP/UDP obfs case.

Subscription import, provider expansion, cache fencing, prepared-adapter
selection, credential redaction, Ingress subscription control, CLI observation,
and restart tests passed. A sing-box `detour`/route reference remains
unavailable with its private document retained and no direct fallback. This
is the deliberate proxy-chain boundary for the current change; PathChord does
not resolve third-party route graphs.

Earlier recorded checks include:

```text
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo deny --all-features --locked check advisories
cargo check --locked --workspace --all-targets --target x86_64-pc-windows-gnu
cargo check --locked --workspace --all-targets --target x86_64-unknown-freebsd
cargo build --locked --bin pathchord-ingressd --bin pathchord-egressd --bin pathchordctl --target x86_64-unknown-freebsd
git diff --check
```

The full workspace test run covers protocol, policy, Noise, Path, Transit,
Ingress, Egress, CLI, real loopback Egress/Ingress TCP and UDP paths, platform
fakes, route rollback, TUN packet flows, Web REST/SSE, persistence, reload,
subscription normalization, and fault/retransmission cases. The dependency
graph contains no `paste` package. `netsock` 0.9.0 uses the updated Netlink
dependency line directly, so PathChord no longer carries a local
`netlink-packet-utils` compatibility patch. `cargo-deny` 0.20.2 passes the
same advisory check used by GitHub Actions.

Cargo 1.100 reports an unused `netsock` dependency on Linux because the native
provider uses it only on non-Linux platforms. Its dependency declaration stays
unconditional. The current `netsock` dependency is selected only for the
non-Linux native process metadata provider.

The Linux workspace run passes every non-ignored workspace test. The normal
Transit unit run does not require an external proxy executable and leaves the
reference-peer tests ignored. With
`PATHCHORD_TEST_SING_BOX` pointing to the external sing-box 1.14.4 binary,
`scripts/test-with-sing-box.sh` ran all seven ignored protocol tests
successfully: VLESS/Trojan, VMess TCP/TLS/WebSocket/UDP, AnyTLS TCP/UDP,
Hysteria2 TCP, TUIC TCP, and Reality/VLESS. The Reality/VLESS fixture now uses
the `xtls-rprx-vision` flow and passes. The binary is a test-only peer and
is not part of the PathChord runtime or dependency graph. Each fixture starts
sing-box with an inbound server and exercises the PathChord native Transit
adapter as the client; the compatibility direction is intentional.
The worktree's Xray 26.11.9 Vision fixture passed twelve cases, including both
flow names, large bidirectional TCP, multiple XUDP datagrams, the UDP/443
switch and real inner TLS with DIRECT in both directions. A fragmented TLS 1.3
case checks the client DIRECT command at the peer, and a TLS 1.2 case verifies
that the client retains the outer TLS transport.
Xray Vision interoperability also verifies the initial VLESS request and
outbound TLS ClientHello share a padded outer TLS record. A server-first idle
case verifies the bounded empty-padding frame, including when the caller does
not poll the returned connection.
REALITY Chrome 133 was compared with dae's uTLS 1.8.2 ClientHello and tested
locally against Xray 26.11.9 and sing-box 1.14.4, including both key shares,
concurrency, trusted-decoy retry boundaries and Brotli decompression. One
Xray decoy retry timed out in a combined run; eight single and five combined
subsequent runs passed, and the original timeout remains unexplained.
The iOS 14, Safari 16, Edge 85 and QQ 11.1 ClientHellos were compared with
dae/uTLS and exercised against a local sing-box REALITY server. Their classic
X25519 shares cannot authenticate to Xray 26.11.9, which requires a hybrid
share; the Xray fixture confirms the adapter stops at the trusted decoy and
sends it no VLESS data. QQ and Chrome explicitly reject their respective ALPS
responses, as verified by a synthetic OpenSSL peer. Ordinary TLS supports
P-256/P-384 HelloRetryRequest; REALITY rejects that retry explicitly.
Firefox 120 was compared with dae/uTLS, tested against sing-box REALITY and
ordinary TLS peers, and exercised both independent key shares. OpenSSL tested
directional record-size limits and invalid extension handling. Xray's hybrid
share requirement and sing-box's P-256 REALITY decoy path reject safely without
forwarding VLESS data. Some sing-box REALITY handshakes timed out. A captured
failure and a controlled test established one cause: sing-box 1.14.4 waits
when the decoy's third TLS record is exactly 512 bytes. With the same
certificate and key, a valid 513-byte record completes the handshake and Vision
round trip. The ordinary fixture uses a longer test certificate, and a separate
boundary regression preserves this peer limitation. Whether a given real
server's decoy produces the affected record layout is not established; see the
[decoy record investigation](changes/archive/2026-11-17-support-sing-box-dae-transit-protocols/research/reality-decoy-record-boundary.md).
Android 11's TLS 1.2 ClientHello was compared with dae/uTLS and exercised
against sing-box and Xray over VLESS TCP/UDP. TLS 1.3-only peers and selections
of advertised but unsupported legacy ciphers fail explicitly.
The sing-box Hysteria2 fixture exchanged fragmented 4096-byte UDP datagrams in
both directions and exercised TCP and UDP IPv6 targets.
Custom Gecko packet sizes from 700 through 1452 bytes passed against a local
sing-box 1.14.4 server. A 2048-byte setting passed TCP and UDP with an
independent sing-quic Gecko relay in front of a plain Hysteria2 server. The
sing-box 1.14.4 client and server both timed out when configured for fixed
2048-byte Gecko packets; its QUIC receive buffer is 1452 bytes, so this peer
combination cannot establish a successful 2048-byte interoperability claim.
An independent sing-box 1.14.4 matrix exercised Hysteria2 numeric and `auto`
upload negotiation, TCP and UDP with Salamander and Gecko, and UDP across two
port-hopping relays with BBR and Brutal. With a local relay adding 10 ms in
each direction, a 512 KiB upload at a negotiated 1 Mbps took 4.22 seconds
without injected loss and 4.29 seconds with controlled loss and reordering;
the latter observed 40 QUIC losses and delivered the full payload. At roughly
0.4 ms RTT, the corresponding loopback transfer took about 9.4 seconds, showing
that the window and ACK timing can limit throughput at very short RTTs. These
are local measurements, not WAN or deployed performance evidence. A separate
copy of the patched Quinn crate passed 305 upstream library tests and two
additional delayed ACK/loss switch tests; the sing-box TUIC fixture also
passed with cubic, NewReno and BBR. See the
[Brutal pacing investigation](changes/archive/2026-11-17-support-sing-box-dae-transit-protocols/research/2026-11-16-hysteria2-brutal-pacing.md)
for the setup and its limits. A controller switch without a later application
write and live QUIC path migration/reset have not been independently verified.
The sing-box HTTP transport fixture covers VLESS and VMess over HTTP/1.1 and
TLS/HTTP2, and Trojan over TLS/HTTP2, with large TCP and repeated UDP payloads.
It also rejects incorrect paths and Host values; separate local peer tests
verify request headers, coalesced bytes and HTTP/2 rejection.
The sing-box V2Ray QUIC fixture covers VLESS, VMess and Trojan TCP/UDP,
half-close, custom ALPN and TLS rejection cases. Local QUIC tests also cover
connection reuse, cancellation, IPv6, address fallback and reconnection.
SOCKS5 UDP-over-TCP v1/v2 completed authenticated TCP and UDP against sing-box,
including IPv6, TLS and certificate rejection. Standard HTTP CONNECT passed
sing-box; the optional path and Host override passed an independent Go peer,
while sing-box's inbound cannot route its own path-form CONNECT. VMess AEAD
padding and authenticated-length combinations passed TCP/UDP against
sing-box. V2Fly Meek passed VLESS/VMess TCP/UDP over HTTP/1.1 and HTTP/2.
VMess XUDP and packetaddr passed sing-box TCP and IPv4/IPv6 UDP tests across
the supported body security modes and AEAD framing options. XUDP also retained
remote DNS for hostname targets; packetaddr rejects hostname targets.
VLESS packetaddr also passed sing-box TCP and IPv4/IPv6 UDP over plain, TLS
and non-Vision REALITY. Xray 26.11.9 did not respond to its packetaddr UDP
requests; Vision with packetaddr is rejected during preparation.
h2mux and yamux passed independent sing-box SS, VLESS, VMess and Trojan TCP/UDP
tests, including both Vision flow variants, connection reuse, isolated stream
errors, UDP close and existing-stream draining after subscription revocation.
Four additional sing-box cases exercised required multiplex padding for both
protocols across those nodes and reuse; local tests cover padding
fragmentation, cancellation, truncated frames, bounded records and independent
read/write wakeups. Vision tests separately cover request, DIRECT and raw
transport wakeups, cancellation and errors after a frame is accepted.
Six additional smux cases passed against sing-box 1.14.4, covering SS, VLESS,
VMess and Trojan TCP/UDP, both Vision flow variants, padding, connection reuse,
and an existing stream after subscription revocation. The FIN case confirmed
that a target's response after receiving EOF was not delivered, so the result
does not establish TCP half-close compatibility. Local smux tests cover receive
budget isolation and partial-allocation accounting, cancellation, stalled and
slow buffered I/O, and the shared deadline after the last stream is released.
The local Ingress fetched the supplied provider using `clash.meta` and imported
32 VLESS nodes with no configuration diagnostics. Eight different servers were
then checked anonymously: seven returned a trusted decoy certificate without
a matching REALITY proof and one failed TLS; the same eight nodes produced no
HTTP response through Xray. A locally built Ingress established one direct
IPv6 Path to the existing `egress-jp-1` and received HTTP 200 through it. With
the same temporary enrollment and subscription nodes as Transit, all 32 nodes
imported but no Path became ready within 50 seconds. The temporary authorization
was removed; the existing authorization and Egress identity remain intact.
This does not establish a working provider-to-Egress Path or identify why those
nodes did not authenticate.
On 2026-11-16, a newly built local Ingress reached the existing Egress TCP
listener over IPv6 but did not establish a Path. A direct admission probe sent
the first Noise handshake and received a reset before any response. SSH local
forwarding was disabled on the VPS, so attempts to compare isolated Egress
processes through an SSH tunnel were inconclusive. The Egress public identity
file matched its private key; temporary authorizations and isolated servers
were removed. The cause is not established. A separate current-code local IPv6
Egress fixture completed the Noise Session and TCP echo. After the local idle
capacity fix, a locally built and signed Alpine APK was installed in an
isolated root on the VPS. Its packaged Egress was then started with the
existing identity and configuration: a local Ingress established a direct
IPv6 Noise Path and reached the VPS loopback SSH service. A second admission
also succeeded after more than ten seconds of idle time. The tested packaged
binary was promoted to the existing Egress executable path, and the temporary
root, test keys, package and authorizations were removed. An Egress-specific
OpenRC service was then started and enabled in the default runlevel; a further
direct IPv6 Path and SSH target exchange succeeded under that service. The
pre-existing unrelated OpenRC definition remains stopped. Subsequent attempts
through the configured public IPv4 `49742 -> 7443` mapping did not increase
the Egress listener's accepted-connection count; a VPS-local IPv4 connection
to port 7443 did. This is a mapping/network observation, not a protocol
interoperability result.
The current locally built Ingress also reached the VPS loopback SSH service
through a local independent sing-box Shadowsocks Transit and an IPv6 Noise
Path to the deployed Egress. The temporary enrollment was removed and the
existing authorization records were preserved. This exercises the Transit
and Egress chain without relying on provider node availability. Both the local
Linux development build and the locally cross-built x86_64 musl release build
passed this chain. A new temporary-key APK containing that musl build was
signature-verified and installed in a local Alpine 3.24 container, including
the service account, default configuration, both OpenRC scripts and manpage;
packaged Ingress and Egress also passed OpenRC start, control status and stop
after waiting for their sockets. This new package was not installed on the
VPS; the previous packaged Egress binary remains deployed there.
The final local validation APK is
`dist/alpine-final-validation-20261116/pathchord-0.1.0-r0.apk` with SHA-256
`e50ead1acd5eec89252186fc9a0c1092cee83452ad789b7387cb03b9339c9be7`; its
temporary signing key is not a release signing identity.
Both providers were also fetched through `clash.meta`, `sing-box`, and `v2rayN`
User-Agents. Each response imported the expected 32 or 65 proxy nodes without
configuration diagnostics; this is import evidence and does not prove network
connectivity. A first per-node local ordinary-proxy run, before the subsequent
ECH GREASE fix, obtained HTTPS 2xx through 54 of 97 Clash nodes using PathChord
and 39 using Mihomo; successful sets differed. After ECH GREASE and SCT
handling were corrected, a repeat against the same target returned HTTPS 2xx
through 76/97 nodes (15/32 from the first provider and 61/65 from the second).
Mihomo returned 2xx through 39/97 in that run; results differ by node and do
not establish that the remaining servers are all available. The four second
provider failures were three Shadowsocks nodes and one Hysteria2 node.
An additional no-Egress UDP run used SOCKS5 UDP ASSOCIATE and non-DNS STUN
transaction validation: PathChord received matching responses from 49 of 94
UDP-enabled nodes and Mihomo from 31; three Shadowsocks nodes had UDP
disabled and were skipped. Timeouts do not establish whether a node, target,
network route or client is responsible, so unresolved nodes remain under
investigation rather than being counted as protocol successes.
The x86_64 musl release binary and a locally signed Alpine APK were built on the
development host. Alpine 3.24.4 containers verified signature, install,
service-account creation, OpenRC start/stop and control sockets. The final APK
was also signature-verified and installed into a temporary isolated Alpine root
on `egress-jp-1`; its separate loopback Egress started and answered status.
The isolated root and uploaded package were removed, and the existing Egress
continued to run. This is package-host smoke evidence, not an upgrade/rollback
test or a successful provider-to-Egress Path. The temporary signing key is not
a release signing identity.
An independent local Shadowsocks-compatible server verified 15 legacy stream
methods with large TCP transfers and UDP; sing-box 1.14.4 verified `none`,
`plain`, three classic AEAD and three SS2022 methods. These are test-only
servers, and the unsupported legacy cipher and plugin matrix remains open.
An additional sing-box 1.14.4 matrix verified TCP and repeated UDP for `none`,
AES-128/192/256-GCM, ChaCha20-IETF-Poly1305, XChaCha20-IETF-Poly1305 and all
three supported SS2022 methods. A separate Mihomo 1.19.34 fixture verified
`xchacha20` TCP and UDP. The two newly added methods also completed TCP
exchanges through upstream simple-obfs 0.0.5 HTTP and TLS servers to their
respective independent Shadowsocks servers; UDP bypasses the TCP plugin.
The AES-192-GCM peer rejected a wrong password for both TCP and UDP. Local
fault tests exercised authentication failure, reflection and replay rejection,
fragmentation, cancelled short writes and TCP half-close. In a separate
upstream `obfs-local` plus `obfs-server` 0.0.5 test, the backend observed EOF
but its subsequent response did not return; the PathChord stream and adapter
half-close tests use peers that preserve the opposite direction.
The original v2ray-plugin server at commit `7d70ea7` passed eight SIP003 and
Clash WebSocket/TLS/mux combinations with large TCP and repeated UDP traffic,
plus credential, certificate and request rejection tests. Its reference
client/server combination does not return responses after TCP half-close; with
mux enabled the backend did not observe EOF in that test.
The worktree HTTPUpgrade fixture passed sing-box 1.14.4 VLESS and VMess over
plaintext and TLS and Trojan over TLS, including bidirectional large TCP and
UDP traffic and rejected Host/path cases.
WebSocket early data passes a sing-box 1.14.4 matrix for VLESS/VMess over
WS/WSS and Trojan over WSS, using path and header forms, large TCP writes and
UDP. The sing-box Trojan inbound rejects early-data limits below its 56-byte
password digest read; that peer-specific limitation remains visible.
VMess with AES-128-GCM, ChaCha20-Poly1305, AES-128-CFB, `none`, and `zero`
bodies passed 50 KB TCP and repeated UDP echo up to 4096 bytes against
sing-box 1.14.4; AES-128-CFB also passed TCP and UDP over WSS. VMess AEAD
response headers use AES-128-GCM regardless of the body method. UDP receive
preserves partially read response headers and frames across cancellation;
CFB matches the NIST CFB128 vector and rejects a corrupt record checksum.
Positive legacy VMess `alter_id` values 1 and 4 passed sing-box 1.14.4 and
V2Fly 5.53.0 TCP/UDP peers across the supported body modes. Response
authentication, continuous legacy CFB state and malformed-response errors have
deterministic regressions. A V2Fly 2048-byte UDP response remains peer-limited
in the recorded fixture, while 1024-byte bidirectional traffic passed.
The TUIC fixture also verifies both UDP relay modes with cubic, NewReno and
BBR against sing-box 1.14.4, including 4096-byte UDP packets fragmented and
reassembled in native DATAGRAM mode. Its distinct `udp_over_stream` extension
also passed TCP and IPv4/IPv6 UDP against sing-box, which accepts up to 16,384
bytes in this mode and closes the stream on a 16,385-byte packet. A controlled
QUIC peer verified the protocol's full 65,535-byte limit without truncation.
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

The current FreeBSD cross build exported headers and libraries from the native
FreeBSD 15.1 guest to `/data/pathchord-qemu/freebsd-build/sysroot`, then used
Clang/Clang++ and LLD 23 with Rust 1.100.0 to build all workspace targets and
test executables. The resulting executables were uploaded back to that FreeBSD
guest and ran as `pathchord`; native results and artifact hashes are in the
[FreeBSD validation manifest](changes/archive/2026-11-18-validate-native-platforms/research/2026-11-17-freebsd-native-validation.json).
The plain host GCC/LLD target failure described in older validation notes still
applies when target-specific SDK wrappers are not selected; Rust's target
standard library alone does not supply system headers or libraries.
