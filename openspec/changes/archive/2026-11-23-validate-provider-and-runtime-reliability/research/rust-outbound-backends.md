# Rust outbound backend research

Evidence snapshot preserved during the documentation migration: 2026-11-14.
This is a non-normative source comparison, not a fresh upstream version audit or
a protocol roadmap. Availability and validation evidence belong in
[implementation status](../../../../implementation-status.md); behavior belongs in the
[Transit Proxy specification](../../../../specs/transit-proxies/spec.md).
SSR remains retired regardless of the capabilities of any reference library.

## Source comparison

Primary-source review selected the following Rust options for native protocol
coverage. The pinned source and crate metadata are kept here so protocol
availability is decided from an embeddable API, license, target matrix, and
interoperability path rather than crate names alone.

| Backend | Evidence | Adoption decision |
| --- | --- | --- |
| `trojan-proto` 0.18.0 | Apache/MIT-compatible Trojan wire parser/encoder; only `bytes`-scale protocol dependency and public request/UDP codecs; crate source is at [crates.io](https://crates.io/crates/trojan-proto/0.18.0) | Adopted for the native Trojan adapter; existing rustls/Tokio transport owns TLS and lifecycle. |
| Native VMess codec | The VMess AEAD header, KDF, FNV checksum, AES-128-GCM/ChaCha20-Poly1305 record framing, response framing, TLS/WS transport, and single-target UDP use pure Rust dependencies; behavior was cross-checked against shoes/meow-rs tests and independent peer fixtures. | Adopted for TCP/TLS/WebSocket/WSS, AEAD body ciphers, UDP, and `alter_id: 0`; mux remains unavailable. |
| Native Hysteria2 driver | Pure Rust Quinn 0.11 + h3 0.0.8 primitives; QUIC/TLS, HTTP/3 `/auth`, TCP bidi relay, UDP DATAGRAM, Salamander obfs, bounded response-header parsing, and bounded server-port rotation; independent peer fixture passes. | Adopted for native TCP/UDP relay. Unsupported obfuscation extensions remain typed diagnostics. |
| `rsteria2` 0.1.1 | MIT, async Tokio/Quinn Hysteria2 client; public `connect`, `HysteriaClient::tcp_connect`, and UDP session APIs; [source](https://github.com/trustrusty/rsteria2/tree/9d5f582ac0ba6eb7f8e7aa417b4221d22596c3e2) | Reference only; no full backend is embedded. |
| `anytls` 0.5.4 | MIT, public async `Client`, `create_stream`, and runtime session APIs; [source](https://github.com/ssrlive/anytls-rs/tree/bdc27d093bc32f52ddf5bba73147e226b156075d) | Reference only; PathChord uses its own native AnyTLS frame/session implementation and does not embed the crate. |
| `ssr-client-rs` 0.1.1 | GPL-3-or-later, public `SsrClient`/`SsrSession`, TCP and UDP relay modules; [source](https://github.com/liangzhaoyuan12/ssr-client-rs/tree/9a04b30493d074719a9f2d2672ef6748fb4e4f39) | Rejected for the supported protocol set; SSR is intentionally retired as an outdated protocol. |
| `eggress-outbound` 1.0.12 | MIT/Apache-2.0, explicit listener-free `OutboundConnector`, TCP and optional UDP; [source](https://github.com/eggstack/eggress/tree/ba64e166474ede7caeba736a885322323d965911) | Not adopted; it is a complete outbound backend and includes retired SSR support. |
| `leaf` 0.1.2 | Apache-2.0, VLESS/VMess/Trojan/Reality modules, but the public API is a complete runtime/config/session application and Reality uses a git rustls fork; [source](https://github.com/eycorsican/leaf/tree/f10e4eb7f081cd54c20f14f89382e4c315e3fe72) | Do not embed directly without a substantial isolation layer; use its wire tests as reference and prefer smaller protocol crates. |
| `shoes` 0.3.7 | MIT, broad VLESS/VMess/Trojan/Hysteria2/TUIC/AnyTLS/Reality/WireGuard implementation, but it is a `publish = false` application with a large runtime and platform glue; [source](https://github.com/cfal/shoes/tree/cf27c458419b03a2e6c4455a323a1273daf4747a) | Do not link or embed it. Its interoperability fixtures and protocol behavior are reference material only. |
| `meow-rs` 0.29.0 | MIT, focused `meow-proxy` protocol crate with VMess, Hysteria2, AnyTLS, VLESS, Trojan, and mux implementations; current VMess/Hysteria2 features use vendored BoringSSL and Hysteria2 uses quiche; [source](https://github.com/meow-rs/meow-rs/tree/3f71788389cf7a75d5e495f510d3ce1fa5410ec0) | Use its VMess KDF/body/header tests and Hysteria2/AnyTLS interoperability cases as reference. Do not link or embed the crate: BoringSSL/quiche build and transport ownership would violate the current rustls, FreeBSD, and narrow-adapter boundaries. |
| Native TUIC driver | Pure Rust Quinn TLS exporter, Authenticate/Connect command flow, TCP relay, UDP DATAGRAM, heartbeat, optional 0-RTT setup, and independent sing-box peer fixture. | Adopted for native TCP/UDP relay; replay-sensitive 0-RTT remains opt-in. |
| TUIC reference | The protocol repository states there is no official implementation; current Rust client uses git-pinned Wind/Quiche forks rather than crates.io; [source](https://github.com/Itsusinn/tuic/tree/5dc6b5358be70d82c7396a5bc6ee58a938642439) | Reference only; no complete backend is embedded. |

No maintained Rust library found in this review provides a small, stable,
cross-platform SSR+VLESS+Reality+Hysteria2+TUIC client API as one unit.
The native path therefore uses focused Trojan, VLESS/REALITY, VMess, AnyTLS,
Hysteria2, and TUIC wire adapters and keeps unsupported protocols as explicit
unavailable protocols.
The native adapters must pass loopback interoperability fixtures against
independent protocol peers before being marked available. No compatibility
process is started or embedded. SSR remains explicitly retired; unregistered protocols remain unavailable.
