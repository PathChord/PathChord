# PathChord Technology Selection

**English** | [简体中文](technology-selection.zh-CN.md)

This document selects the initial implementation technologies. It is intentionally limited to implementation choices; protocol and behavioral requirements remain defined in the architecture and protocol documents.

## Recommended baseline

| Area | Selection | Reason |
|---|---|---|
| Language | Rust | Strong control over buffers, concurrency, platform integration, and long-lived networking services |
| Async runtime | Tokio | Mature async I/O, timers, cancellation, task supervision, and Windows/Linux support |
| Cryptography | `snow` with `Noise_IK_25519_ChaChaPoly_SHA256` | Direct Noise pattern support and independent handshake state per Path |
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

The implementation should be divided into crates or equivalent modules:

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
is not reachable through Transit or data Paths. The first browser adapter is
REST resources plus Server-Sent Events (SSE); a later GraphQL adapter may serve
the same typed service if dashboard query composition justifies its additional
authorization, query-cost, and subscription complexity. REST or GraphQL is an
adapter choice, not the internal state model.

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

The Phase-0 `snow` wrapper uses explicit nonces and a bounded replay window, but `snow` 0.10 does not guarantee zeroization of every private/DH and traffic-key buffer it owns. This is a known non-production limitation; a zeroizing resolver or reviewed library replacement is required before deployment.

The implementation must not reuse WireGuard key material or treat the Transit Proxy as an authenticated peer.

## Rule engine selection criteria

The rule engine must be deterministic, bounded, and unable to perform I/O. It may read a connection context, listener metadata, process metadata, target metadata, static labels, and observed state. It may output selectors, tags, labels, and traffic policy parameters, but never a concrete socket or arbitrary node object.

The first implementation should use a small native AST compiler rather than embedding a general scripting language. A future WASM or eBPF-like backend can implement the same restricted rule interface if needed.

## Configuration and hot reload

Human configuration is parsed into typed data, validated, normalized, and compiled into an immutable snapshot. Snapshot replacement is atomic. Static Egress topology and local key material remain startup configuration; Transit Proxy data and compiled dynamic rules may be hot reloaded according to the configuration rules.

SQLite transactions are used for Egress authorization changes. The running Egress process owns the database and publishes the resulting generation to its in-memory authorization snapshot.

## Platform plan

Linux is the first implementation target because TPROXY, REDIRECT, process metadata, and transparent routing are central requirements. Windows support reuses the core and policy crates and adds Wintun plus system-proxy integration.

The first milestone should avoid implementing both transparent interception platforms. It should validate the protocol with a local SOCKS5 listener, one Transit adapter, one Egress, and one TCP Stream before adding TPROXY or TUN.

## Deferred validation

These choices are recommended but should be verified by a small prototype before being treated as permanent:

- zeroization of Noise handshake and transport state, including the selected resolver;
- Tokio task and cancellation structure under Path churn;
- Wintun packaging and service integration;
- Linux TPROXY behavior with IPv4 and IPv6;
- SQLite behavior under concurrent status and enrollment operations;
- throughput and allocation cost of the custom frame codec;
- rule compiler latency and worst-case evaluation cost.

The Phase-0 replay window is intentionally bounded to 64 records. Session-level
ACK retention and retransmission behavior must be validated against that bound
before the multipath data plane is considered production-ready.

