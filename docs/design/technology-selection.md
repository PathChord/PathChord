# PathChord technology selection

**English** | [简体中文](technology-selection.zh-CN.md)

This document defines the selected technologies and implementation boundaries. Protocol and behavioral requirements are defined in the architecture and protocol documents.

## Selected technologies

| Area | Selection | Reason |
|---|---|---|
| Language | Rust | Strong control over buffers, concurrency, platform integration, and long-lived networking services |
| Async runtime | Tokio | Mature async I/O, timers, cancellation, task supervision, and Linux/Windows/FreeBSD support |
| Cryptography | `Noise_IK_25519_ChaChaPoly_SHA256` through Clatter, with zeroizing key/cipher containers and an Orion SHA-256/HMAC adapter | Direct Noise pattern support, independent handshake state per Path, explicit-nonce transport, and enforceable secret-state cleanup |
| Symmetric primitives | ChaCha20-Poly1305 through the Noise implementation | Matches the selected Noise pattern |
| Serialization | `serde` for configuration and management API models | Shared typed models without coupling the wire protocol to a text format |
| Wire framing | Dedicated Rust codec using QUIC-style unsigned varints | Protocol requires explicit framing and does not depend on a general RPC schema |
| Configuration | YAML for human-authored files, normalized into typed Rust snapshots | Readable static configuration while keeping runtime evaluation typed |
| Control plane | Typed command/query service with versioned length-delimited JSON over Unix Socket/Named Pipe; optional authenticated web gateway | Keeps privileged local administration isolated while providing a browser integration point without coupling runtime state to one external API style |
| Embedded state | SQLite for Egress authorization and durable local metadata | Atomic transactions, generation numbers, and easy inspection |
| Rules | Dedicated restricted rule language compiled at startup | Deterministic evaluation and a narrow output model; no arbitrary host access |
| Linux interception | `nix`/`socket2` plus platform-specific netlink and TPROXY code | Access to socket options and routing primitives without hiding kernel behavior |
| Linux TUN | `tun-rs` async packet device behind `PacketDevice`, with a direct `smoltcp` reactor | Safe replaceable device lifecycle and a maintained TCP/UDP state machine |
| Windows TUN | `tun-rs` Wintun packet device behind the same interface and direct `smoltcp` reactor | Standard Windows driver integration without platform-specific TCP reconstruction |
| HTTP/SOCKS | Hyper HTTP/1 message codec with internal HTTP routing and SOCKS4/4a/5 adapters | Maintained HTTP parsing, message framing, streaming backpressure, and explicit policy/authentication boundaries |
| DNS wire handling | `hickory-proto` behind route adapters | Mature DNS parsing/encoding while keeping local, Transit, Egress, and blocked routing replaceable |
| Testing | `cargo test`, deterministic fake transports, property tests, packet traces, and fault injection | Multipath correctness depends on reproducible loss, duplication, reordering, and restart tests |

The scheduler uses effective-capacity weighting. Configured relationship weights provide the baseline; Path-reported capacity, congestion window, RTT, jitter, and loss adjust the instantaneous allocation. Retransmission replication uses both a Session-wide budget and optional per-traffic-class budgets, with the Session budget as the hard upper bound.

## Architecture boundaries

The implementation is divided into crates or equivalent modules:

```text
pathchord-core       protocol types, frame codec, Session, Stream, UDP
pathchord-noise      Noise handshakes and per-Path cryptographic records
pathchord-path       Path lifecycle, loss handling, scheduling, congestion reports
pathchord-policy     configuration snapshots, rule compiler, selectors
pathchord-transit    Transit Proxy adapters and subscription normalization
pathchord-egress     target dialing, Egress status, authorization store
pathchord-ingress    local listeners, transparent interception, process metadata
pathchord-cli        local management API client and operational commands
```

`pathchord-core` must not depend on Linux, Windows, FreeBSD, subscription formats, or listener implementations. Platform adapters communicate through narrow traits for byte transport, local sockets, target dialing, and process metadata.

## Ingress control plane and observability

Ingress owns a typed command/query service for mutable node metadata,
subscriptions, runtime snapshots, connection views, and structured events. The
authoritative local adapter is a Unix domain socket on Linux and FreeBSD or a
Named Pipe on Windows, using the versioned length-delimited JSON envelope
selected by the protocol design.

An optional Web Gateway calls the same service. It is disabled by default and
is not reachable through Transit or data Paths. The selected built-in browser
adapter uses REST resources plus Server-Sent Events (SSE): resource URLs and
HTTP status semantics fit commands and queries, while one-way SSE updates fit
metrics and events. A GraphQL adapter is permitted behind the same typed service
boundary, but carries additional authorization, query-cost, caching, and
subscription complexity. The typed service owns the internal state model
independently of the browser API style.
The built-in console assets are embedded into the Rust binary and require no
Node.js runtime in production.

Node label/tag edits, subscription create/delete/refresh, and other mutations
are generation-checked, idempotent, audited commands. Dynamic snapshots replace
atomically; a failed subscription refresh retains the last successful snapshot.
The observation provider publishes typed node, Path, Session, Stream, target
connection, subscription, and policy metrics. The Web Gateway exposes those
snapshots and bounded event streams; operators must not reconstruct current
state by parsing logs.

`STATUS_REPORT` remains a compact authenticated data-Path message for Egress
admission and health. It is not the management API or the metrics transport.

## Noise and record handling

Each Path owns an independent Noise session and transport cipher state. The record layer must:

- authenticate the Path before `PATH_READY`;
- bind the configured EgressID in the Noise prologue, then map the authenticated initiator key to an authorized IngressID before `SESSION_ATTACH`;
- use explicit record nonces so loss and reordering do not desynchronize the per-Path cipher;
- allocate outbound nonces inside the per-Path sender and retain sealed nonce/ciphertext records for retransmission;
- reject oversized records before allocation;
- cap frame plaintext so the encoded header, payload, and authentication tag fit the Noise implementation's message limit;
- expose complete PathChord frames only;
- report authentication failure as a Path failure;
- never reuse transport cipher state across Paths.

Clatter owns the IK state machine, X25519 secret/DH-output containers, and transport cipher states. Its secret-bearing containers zeroize on drop. The SHA-256/HMAC adapter uses Orion with zeroization enabled so keyed hash state, chaining-key intermediates, and HMAC pads are cleared as well. PathChord explicitly clears live transport ciphers on teardown and freezes deterministic compatibility vectors in the wire profile. The record layer uses a bounded replay window whose size and retention semantics accommodate Session-level ACK retention and retransmission behavior.

The implementation must not reuse WireGuard key material or treat the Transit Proxy as an authenticated peer.

## Rule engine selection criteria

The rule engine must be deterministic, bounded, and unable to perform I/O. It may read a connection context, listener metadata, process metadata, target metadata, static labels, and observed state. It may output selectors, tags, labels, and traffic policy parameters, but never a concrete socket or arbitrary node object.

The built-in rule engine uses a small native AST compiler. An alternative WASM
or eBPF-like backend may implement the same restricted rule interface, but it
must preserve deterministic, bounded, I/O-free evaluation. The interface
defines the boundary between policy compilation and runtime evaluation.

## Configuration and hot reload

Human configuration is parsed into typed data, validated, normalized, and compiled into an immutable snapshot. Snapshot replacement is atomic. Static Egress topology and local key material remain startup configuration; Transit Proxy data and compiled dynamic rules may be hot reloaded according to the configuration rules.

SQLite transactions are used for Egress authorization changes. The running Egress process owns the database and publishes the resulting generation to its in-memory authorization snapshot.

## Platform architecture

A mixed TCP listener selects HTTP or SOCKS without consuming the first byte,
then reuses the existing protocol codecs, credential verifier, flow openers,
and supervision. Its SOCKS5 UDP Associations retain the same bounded relay
lifecycle as a dedicated SOCKS listener.

Linux, Windows, and FreeBSD share ordinary HTTP forwarding, HTTP CONNECT, SOCKS4/4a/5 CONNECT, and SOCKS5 UDP ASSOCIATE adapters. HTTP message framing uses Hyper while each ordinary request uses the same TCP flow opener and policy engine as other local flows. The canonical `socks5` configuration name accepts `socks` as an input alias and all three SOCKS versions. The [platform and DNS specification](../spec/platform-and-dns.md#http-and-socks-listeners) owns protocol behavior. FreeBSD uses Unix local control and MUST NOT expose TPROXY, REDIRECT, or TUN listeners in the v1 platform contract. System-proxy mutations are Windows-only; Linux and FreeBSD report unsupported activation. Process metadata that a platform cannot safely obtain remains unknown.

Linux integrates TPROXY, REDIRECT, process metadata, and transparent routing through platform adapters. Windows uses Wintun and system-proxy integration selected through the control plane. TUN adapters expose bounded IP packets only; one single-owner `smoltcp` reactor owns `Interface`, `SocketSet`, TCP listeners, UDP sockets, timers, and flow lifecycle and connects accepted flows through the same Ingress openers as ordinary listeners. All three platforms reuse the core and policy crates.

One Ingress platform-runtime module owns startup and shutdown across ordinary
listeners, transparent listeners, policy routing, UDP adapters, and TUN
reactors. Startup validates every Listener and acquires resources as one
transaction; any failure rolls back already-owned routes and drops acquired
devices. One cancellation tree supervises every adapter and joins them before
route restoration, so the CLI does not reproduce platform lifecycle logic.

Platform adapters own operating-system-specific packaging, service integration, socket behavior, and routing behavior. Linux transparent routing supports IPv4 and IPv6. Tokio task supervision and cancellation must handle Path churn without leaking tasks or resources. SQLite transactions preserve authorization consistency during concurrent status queries and enrollment operations. The frame codec bounds allocation by protocol limits, and the rule compiler enforces bounded evaluation cost.

