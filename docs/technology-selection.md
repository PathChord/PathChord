# PathChord Technology Selection

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
| Local management API | Versioned binary or length-delimited JSON messages over Unix Socket/Named Pipe | Local-only administration and stable CLI/API boundary |
| Embedded state | SQLite for Egress authorization and durable local metadata | Atomic transactions, generation numbers, and easy inspection |
| Rules | Dedicated restricted rule language compiled at startup | Deterministic evaluation and a narrow output model; no arbitrary host access |
| Linux interception | `nix`/`socket2` plus platform-specific netlink and TPROXY code | Access to socket options and routing primitives without hiding kernel behavior |
| Linux TUN | `tun` or equivalent OS adapter behind an internal interface | Keeps TUN implementation replaceable |
| Windows TUN | Wintun adapter behind the same internal interface | Standard Windows TUN integration |
| HTTP/SOCKS | Internal protocol adapters | Required semantics are small and avoid unnecessary proxy-framework coupling |
| Testing | `cargo test`, deterministic fake transports, property tests, packet traces, and fault injection | Multipath correctness depends on reproducible loss, duplication, reordering, and restart tests |

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

## Noise and record handling

Each Path owns an independent Noise session and transport cipher state. The record layer must:

- authenticate the Path before `PATH_READY`;
- bind the authenticated static keys to IngressID and EgressID;
- reject oversized records before allocation;
- expose complete PathChord frames only;
- report authentication failure as a Path failure;
- never reuse transport cipher state across Paths.

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

- exact Noise library API and key persistence behavior;
- Tokio task and cancellation structure under Path churn;
- Wintun packaging and service integration;
- Linux TPROXY behavior with IPv4 and IPv6;
- SQLite behavior under concurrent status and enrollment operations;
- throughput and allocation cost of the custom frame codec;
- rule compiler latency and worst-case evaluation cost.

