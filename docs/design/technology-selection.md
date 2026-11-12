# PathChord technology selection

**English** | [简体中文](technology-selection.zh-CN.md)

This document defines the selected technologies and implementation boundaries. Protocol and behavioral requirements are defined in the architecture and protocol documents.

## Selected technologies

| Area | Selection | Reason |
|---|---|---|
| Language | Rust | Strong control over buffers, concurrency, platform integration, and long-lived networking services |
| Async runtime | Tokio | Mature async I/O, timers, cancellation, task supervision, and Windows/Linux support |
| Cryptography | `Noise_IK_25519_ChaChaPoly_SHA256` behind a replaceable crypto interface; `snow` with a reviewed zeroizing resolver where it satisfies the security requirements | Direct Noise pattern support, independent handshake state per Path, and enforceable secret-state cleanup |
| Symmetric primitives | ChaCha20-Poly1305 through the Noise implementation | Matches the selected Noise pattern |
| Serialization | `serde` for configuration and management API models | Shared typed models without coupling the wire protocol to a text format |
| Wire framing | Dedicated Rust codec using QUIC-style unsigned varints | Protocol requires explicit framing and does not depend on a general RPC schema |
| Configuration | YAML for human-authored files, normalized into typed Rust snapshots | Readable static configuration while keeping runtime evaluation typed |
| Control plane | Typed command/query service with versioned length-delimited JSON over Unix Socket/Named Pipe; optional authenticated web gateway | Keeps privileged local administration isolated while providing a browser integration point without coupling runtime state to one external API style |
| Embedded state | SQLite for Egress authorization and durable local metadata | Atomic transactions, generation numbers, and easy inspection |
| Rules | Dedicated restricted rule language compiled at startup | Deterministic evaluation and a narrow output model; no arbitrary host access |
| Linux interception | `nix`/`socket2` plus platform-specific netlink and TPROXY code | Access to socket options and routing primitives without hiding kernel behavior |
| Linux TUN | `tun` or equivalent OS adapter behind an internal interface | Keeps TUN implementation replaceable |
| Windows TUN | Wintun adapter behind the same internal interface | Standard Windows TUN integration |
| HTTP/SOCKS | Internal protocol adapters | Required semantics are small and avoid unnecessary proxy-framework coupling |
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

`pathchord-core` must not depend on Linux, Windows, subscription formats, or listener implementations. Platform adapters communicate through narrow traits for byte transport, local sockets, target dialing, and process metadata.

## Ingress control plane and observability

Ingress owns a typed command/query service for mutable node metadata,
subscriptions, runtime snapshots, connection views, and structured events. The
authoritative local adapter remains a Unix domain socket on Linux or a Named
Pipe on Windows, using the versioned length-delimited JSON envelope selected by
the protocol design.

An optional Web Gateway calls the same service. It is disabled by default and
is not reachable through Transit or data Paths. The selected built-in browser
adapter uses REST resources plus Server-Sent Events (SSE): resource URLs and
HTTP status semantics fit commands and queries, while one-way SSE updates fit
metrics and events. A GraphQL adapter is permitted behind the same typed service
boundary, but carries additional authorization, query-cost, caching, and
subscription complexity. The typed service owns the internal state model
independently of the browser API style.

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

The Noise implementation must zeroize all private-key, DH, and traffic-key buffers it owns, including resolver-owned state. The record layer uses a bounded replay window whose size and retention semantics accommodate Session-level ACK retention and retransmission behavior.

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

Linux integrates TPROXY, REDIRECT, process metadata, and transparent routing through platform adapters. Windows uses Wintun and system-proxy integration selected through the control plane. Both platforms reuse the core and policy crates.

Platform adapters own operating-system-specific packaging, service integration, socket behavior, and routing behavior. Linux transparent routing supports IPv4 and IPv6. Tokio task supervision and cancellation must handle Path churn without leaking tasks or resources. SQLite transactions preserve authorization consistency during concurrent status queries and enrollment operations. The frame codec bounds allocation by protocol limits, and the rule compiler enforces bounded evaluation cost.

