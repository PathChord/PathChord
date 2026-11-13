# PathChord implementation plan

This document tracks the remaining implementation and validation sequence.
Final-state requirements remain under `docs/design/` and `docs/spec/`.

## Current focus

Prioritize HTTP forwarding/CONNECT, SOCKS4/4a/5, and same-port mixed listeners
on Linux, Windows, and FreeBSD. SOCKS5 UDP includes ordinary native Proxy and
direct forwarding as well as Session UDP through a controlled Egress.
Transparent interception and TUN work follow this explicit-listener baseline.

| Platform | Explicit listeners | Local control | Remaining platform validation |
| --- | --- | --- | --- |
| Linux | HTTP, SOCKS, mixed | Unix socket | Cross-machine and long-running failure/provider tests. |
| Windows | HTTP, SOCKS, mixed | Named Pipe | Native forwarding, ACLs, configuration watcher, and system-proxy recovery. |
| FreeBSD | HTTP, SOCKS, mixed | Unix socket | Native forwarding, SQLite/socket permissions, watcher, and signals. |

The [Transit Proxy contract](../spec/transit-proxies.md) owns the exact native
and optional engine parameter/format boundaries. The
[deployment guide](../spec/deployment.md) and `examples/` provide direct,
subscription, and enrolled Egress entry points. Portable regressions run in
the existing Rust CI job; target compilation/linking and native host execution
are recorded separately in [status](status.md).

## Rust outbound backend selection

Primary-source review selected the following Rust options for native protocol
coverage. The pinned source and crate metadata are kept here so protocol
availability is decided from an embeddable API, license, target matrix, and
interoperability path rather than crate names alone.

| Backend | Evidence | Adoption decision |
| --- | --- | --- |
| `trojan-proto` 0.18.0 | Apache/MIT-compatible Trojan wire parser/encoder; only `bytes`-scale protocol dependency and public request/UDP codecs; crate source is at [crates.io](https://crates.io/crates/trojan-proto/0.18.0) | Adopted for the native Trojan adapter; existing rustls/Tokio transport owns TLS and lifecycle. |
| Native VMess codec | The VMess AEAD header, KDF, FNV checksum, AES-128-GCM record framing, and response framing use pure Rust dependencies; behavior was cross-checked against shoes/meow-rs tests and an independent protocol fixture. | Adopted for plain TCP plus AES-128-GCM and `alter_id: 0`; TLS, WebSocket, mux, and UDP remain to be implemented natively. |
| `rsteria2` 0.1.1 | MIT, async Tokio/Quinn Hysteria2 client; public `connect`, `HysteriaClient::tcp_connect`, and UDP session APIs; [source](https://github.com/trustrusty/rsteria2/tree/9d5f582ac0ba6eb7f8e7aa417b4221d22596c3e2) | Candidate for the next native Hysteria2 adapter; requires a QUIC feature boundary and live server fixtures. |
| `anytls` 0.5.4 | MIT, public async `Client`, `create_stream`, and runtime session APIs; [source](https://github.com/ssrlive/anytls-rs/tree/bdc27d093bc32f52ddf5bba73147e226b156075d) | Candidate for a native AnyTLS adapter; client API is embeddable, but its TLS/session ownership must be isolated and tested. |
| `ssr-client-rs` 0.1.1 | GPL-3-or-later, public `SsrClient`/`SsrSession`, TCP and UDP relay modules; [source](https://github.com/liangzhaoyuan12/ssr-client-rs/tree/9a04b30493d074719a9f2d2672ef6748fb4e4f39) | Rejected for the supported protocol set; SSR is intentionally retired as an outdated protocol. |
| `eggress-outbound` 1.0.12 | MIT/Apache-2.0, explicit listener-free `OutboundConnector`, TCP and optional UDP; [source](https://github.com/eggstack/eggress/tree/ba64e166474ede7caeba736a885322323d965911) | Not adopted; it is a complete outbound backend and includes retired SSR support. |
| `leaf` 0.1.2 | Apache-2.0, VLESS/VMess/Trojan/Reality modules, but the public API is a complete runtime/config/session application and Reality uses a git rustls fork; [source](https://github.com/eycorsican/leaf/tree/f10e4eb7f081cd54c20f14f89382e4c315e3fe72) | Do not embed directly without a substantial isolation layer; use its wire tests as reference and prefer smaller protocol crates. |
| `shoes` 0.3.7 | MIT, broad VLESS/VMess/Trojan/Hysteria2/TUIC/AnyTLS/Reality/WireGuard implementation, but it is a `publish = false` application with a large runtime and platform glue; [source](https://github.com/cfal/shoes/tree/cf27c458419b03a2e6c4455a323a1273daf4747a) | Do not link or embed it. Its interoperability fixtures and protocol behavior are reference material only. |
| `meow-rs` 0.29.0 | MIT, focused `meow-proxy` protocol crate with VMess, Hysteria2, AnyTLS, VLESS, Trojan, and mux implementations; current VMess/Hysteria2 features use vendored BoringSSL and Hysteria2 uses quiche; [source](https://github.com/meow-rs/meow-rs/tree/3f71788389cf7a75d5e495f510d3ce1fa5410ec0) | Use its VMess KDF/body/header tests and Hysteria2/AnyTLS interoperability cases as reference. Do not link or embed the crate: BoringSSL/quiche build and transport ownership would violate the current rustls, FreeBSD, and narrow-adapter boundaries. |
| TUIC reference | The protocol repository states there is no official implementation; current Rust client uses git-pinned Wind/Quiche forks rather than crates.io; [source](https://github.com/Itsusinn/tuic/tree/5dc6b5358be70d82c7396a5bc6ee58a938642439) | No small stable native dependency is suitable; implement the protocol layer in PathChord before registration. |

No maintained Rust library found in this review provides a small, stable,
cross-platform SSR+VLESS+Reality+Hysteria2+TUIC client API as one unit.
The native path therefore uses focused Trojan, VLESS, and plain-TCP VMess wire
adapters and keeps unsupported protocols as explicit unavailable protocols.
The native adapters must pass loopback interoperability fixtures against
independent protocol peers before being marked available. No compatibility
process is started or embedded. Unregistered SSR remains an explicitly unavailable protocol
until its wire and obfuscation implementation is complete.

## Current sequence

1. Complete native Windows and FreeBSD explicit-listener validation. Cover
   authentication, source restrictions, IPv4/IPv6 and domain targets, DNS,
   reload, bounded resources, shutdown, and local management. Validate Windows
   Named Pipe ACLs, WinINet refresh, and crash recovery on a real host.
2. Exercise real provider exports across URI/Base64, Clash HTTP providers,
   SIP008, sing-box document syntax, and supported text node formats. Extend interoperability
   fixtures for the remaining protocol/TLS/Reality/transport combinations;
   unsupported options must remain
   explicit per-node diagnostics.
3. Run long-lived failure and restart tests for Path churn, authorization
   revoke, provider failures, node draining, DNS route failure, configuration
   reload. Verify cache and accounting
   metadata remain consistent without leaking credentials.
4. Extend native protocol coverage one protocol at a time. Hysteria2, TUIC,
   Reality, and SSR require pure-Rust or narrowly isolated protocol layers,
   exact parameter validation, and independent interoperability fixtures before
   native registration. Keep incomplete coverage explicitly unavailable.
   A pure-Rust AnyTLS frame/authentication codec now exists as an unregistered
   protocol layer; it must gain TLS/session handshake, SYN/SYNACK, settings,
   padding lifecycle, and sing-box interoperability before registration.
   Hysteria2 and Reality wire/crypto codecs follow the same rule: codec tests
   alone do not register a transport adapter; QUIC/TLS ownership and peer
   interoperability must be proven first.
   Hysteria2 now has an unregistered pure-Rust wire layer for QUIC varints,
   TCP/UDP relay messages, auth bounds, and Salamander obfuscation; the QUIC
   and HTTP/3 session driver remains to be implemented natively.
5. Connect the Prometheus endpoint and structured observations to deployed
   monitoring, alerts, and dashboards. Keep live gauges distinct from
   historical counters, and measure production probe/autoscaler constants.

## Deferred work

- TPROXY, REDIRECT, transparent UDP interception, and TUN integration follow
  explicit-listener validation. Privileged route validation, journal recovery,
  and Wintun packaging are outside the active acceptance scope.
- Additional FreeBSD transparent interception or TUN support needs a separate
  platform assessment.
- Further native protocol implementations need maintained libraries and
  protocol-specific interoperability evidence. SSR and unregistered protocols
  remain explicitly unavailable. Third-party policy groups, routes, scripts,
  external detour graphs, and local-file providers are outside node import.
