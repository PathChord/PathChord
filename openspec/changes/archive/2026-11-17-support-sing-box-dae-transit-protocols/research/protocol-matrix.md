# Existing Transit protocol compatibility matrix

This is a non-normative source inventory, recorded on 2026-11-15 for this
change. It covers the protocol families already backed by PathChord Transit
adapters. The source comparison uses sing-box **1.14.4** at
`c005f35300ce76427dc285481ec5695f5b179cd2` and dae **2.1.2** at
`460cec77f4365abfd9ea6fae04b66466dd4861cb`. dae replaces its outbound module
with `github.com/olicesx/outbound` at `cc86ced2e683`; its actual dialers must
therefore be inspected alongside the dae protocol table.

Sources: [sing-box outbound registry](https://github.com/SagerNet/sing-box/blob/v1.14.4/include/registry.go#L80-L105),
[dae protocol table](https://github.com/daeuniverse/dae/blob/v2.1.2/docs/en/proxy-protocols.md#L3-L17),
and [dae dependency replacement](https://github.com/daeuniverse/dae/blob/v2.1.2/go.mod#L136).
The PathChord observations below are a snapshot of the working implementation,
including work in progress; the adapter registry and validation code remain the
authoritative source for the current checkout. A registered adapter or parsed
option alone is not evidence of interoperability with every upstream variant.

| Protocol family | Selected upstream behavior | PathChord implementation and notable gaps |
| --- | --- | --- |
| HTTP / HTTPS CONNECT | sing-box exposes CONNECT, Basic authentication, optional TLS, request path and headers; dae supports HTTP and HTTPS. [sing-box options](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/simple.go), [dae dialer](https://github.com/olicesx/outbound/blob/cc86ced2e683/dialer/http/http.go) | Native HTTP/1.1 CONNECT, proxy authentication, private request path, headers and TLS are implemented; the adapter does not provide UDP. |
| SOCKS5 | Both upstreams provide SOCKS5. sing-box exposes authentication, UDP-over-TCP and network selection. [sing-box options](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/simple.go), [dae dialer](https://github.com/olicesx/outbound/blob/cc86ced2e683/dialer/socks/socks.go) | Native CONNECT, UDP ASSOCIATE and UDP-over-TCP v1/v2, username/password and optional TLS exist. UDP-over-TCP is carried inside the configured TCP/TLS stream; plaintext UDP is never substituted for a TLS control connection. |
| Shadowsocks | sing-box lists AEAD, 2022 and legacy stream methods, plugins, UDP-over-TCP and multiplex. dae lists AEAD and stream ciphers and uses SIP003 plugins including simple-obfs and ShadowTLS. [sing-box options](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/shadowsocks.go), [dae dialer and methods](https://github.com/olicesx/outbound/blob/cc86ced2e683/dialer/shadowsocks/shadowsocks.go) | The adapter uses `shadowsocks-rust` for supported AEAD, 2022 and legacy methods and implements `aes-192-gcm` and `xchacha20` natively for TCP/UDP. sing-box 1.14.4 verified the former; Mihomo 1.19.34 verified the latter. Native simple-obfs, v2ray-plugin WebSocket/TLS and bounded h2mux/yamux/smux with optional padding cover TCP; UDP uses native datagrams, UDP-over-TCP or mux. smux has full-close FIN semantics rather than complete TCP half-close. `xchacha20` is an unauthenticated stream cipher. These two methods reject salt/IV repeats retained in a per-adapter, nonpersistent 4096-entry window. Other dae legacy methods, v2ray-plugin transports and multi-stream mux counts, and ShadowTLS remain unavailable. |
| VMess | sing-box exposes `auto`, `none`, `zero`, `aes-128-cfb`, `aes-128-gcm` and `chacha20-poly1305`, `alter_id`, global padding, authenticated length, packet encodings and V2Ray transports. dae explicitly restricts VMess to AEAD and `alterID=0`. [sing-box options](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/vmess.go), [dae dialer](https://github.com/olicesx/outbound/blob/cc86ced2e683/dialer/v2ray/v2ray.go) | Native positive `alter_id` legacy HMAC-MD5/AES-128-CFB headers (bounded to 65,535), authenticated `alter_id=0`, AES-128-GCM, ChaCha20-Poly1305, AES-128-CFB and explicit `none`/`zero` bodies, AEAD global padding and authenticated length, TCP/UDP, XUDP, packetaddr and shared transports exist. V2Fly's 2048-byte UDP response case remains peer-limited in the recorded fixture; other transport combinations remain open. |
| VLESS / XTLS | Both upstreams support VLESS and Vision-related flows. REALITY and Vision are VLESS transport/flow combinations, not independent protocol families. [sing-box options](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/vless.go), [dae VLESS transport](https://github.com/olicesx/outbound/blob/cc86ced2e683/dialer/v2ray/v2ray.go), [dae Vision notes](https://github.com/daeuniverse/dae/blob/v2.1.2/docs/en/proxy-protocols.md#vless-with-xtls-vision-and-malformed-serverhello) | Native VLESS and REALITY adapters implement both Vision flow names, XUDP and directional DIRECT. The worktree supports the dae/uTLS Chrome 133, iOS 14, Safari 16, Edge 85, QQ 11.1 and Firefox 120 REALITY profiles, and Android 11 for ordinary TLS 1.2 without ALPN. The 360 profile, other fingerprints and some transport and packet options remain unavailable. |
| Trojan | Both upstreams provide Trojan. dae also accepts the Trojan-go link and transport variants, with optional Shadowsocks encryption. [sing-box options](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/trojan.go), [dae Trojan-go dialer](https://github.com/olicesx/outbound/blob/cc86ced2e683/dialer/trojan/trojan.go) | Native Trojan and imported Trojan-Go original/TCP, WebSocket, gRPC and HTTPUpgrade aliases are supported. Trojan-Go WebSocket SS encryption supports AES-128-GCM, AES-256-GCM and ChaCha20-IETF-Poly1305 with a native Trojan-Go stream layer. Original/TCP SS is explicitly unavailable because the reference server's short-stream HTTP sniffing is unreliable; other Trojan-Go options remain diagnostic-gated. |
| Hysteria2 | Both upstreams support Hysteria2. sing-box exposes Salamander and Gecko, port hopping, rates, BBR controls and additional QUIC/realm options. [sing-box options](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/hysteria2.go), [dae dialer](https://github.com/olicesx/outbound/blob/cc86ced2e683/dialer/hysteria2/hysteria2.go) | Native QUIC/TLS, authentication, TCP/UDP, Salamander, configurable Gecko padding sizes, bounded port hopping, client receive-rate hints and negotiated BBR/Brutal upload control exist. The server may ignore the download hint; `auto` and a zero local upload rate select BBR, numeric zero uses a nonzero local rate and a positive numeric response selects the smaller rate. Brutal loss compensation can pace ordinary QUIC data up to 1.25 times the target; PTO probes and ACK-only packets may bypass pacing, and burst and outer overhead add traffic. This is not a strict physical cap. Remaining congestion and advanced QUIC options remain open. |
| TUIC | Both upstreams support TUIC v5. sing-box exposes `cubic`, `new_reno`, `bbr`, UDP relay modes, UDP-over-stream, 0-RTT and heartbeat options. [sing-box options](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/tuic.go), [dae dialer](https://github.com/olicesx/outbound/blob/cc86ced2e683/dialer/tuic/tuic.go) | Native QUIC/TLS, UUID/password, TCP/UDP and heartbeat exist. The worktree supports all three named congestion controllers, native DATAGRAM and QUIC-stream UDP relay, and UDP-over-stream; 0-RTT and other upstream options remain unavailable. |
| AnyTLS | Both upstreams support AnyTLS; sing-box exposes session idle controls and client metadata. [sing-box options](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/anytls.go), [dae dialer](https://github.com/olicesx/outbound/blob/cc86ced2e683/dialer/anytls/anytls.go) | Native TLS authentication and TCP/UDP framing exist. Session pooling, idle controls and client metadata require a separate audit rather than being inferred from the protocol name. |

## Shared combinations and validation

Hysteria2's numeric and `auto` negotiation matrix, TCP/UDP, Salamander, Gecko
and port hopping were exercised with an independent sing-box 1.14.4 server on
the local host. A controlled 1 Mbps relay test transferred 512 KiB in 4.22 s
without induced loss and 4.29 s with loss and reordering; a no-delay loopback
case took about 9.4 s at approximately 0.4 ms RTT. These measurements are not
WAN or deployed performance evidence. See the
[Brutal pacing investigation](2026-11-16-hysteria2-brutal-pacing.md) for the
test setup, Quinn patch and limits.

sing-box defines HTTP, WebSocket, QUIC, gRPC and HTTPUpgrade as V2Ray
transports; dae also lists Meek in its VMess/VLESS transport support.
[sing-box transport options](https://github.com/SagerNet/sing-box/blob/v1.14.4/option/v2ray_transport.go)
and the [dae protocol table](https://github.com/daeuniverse/dae/blob/v2.1.2/docs/en/proxy-protocols.md#L3-L17)
identify the upstream vocabulary. PathChord's
[shared transport validation](../../../../../crates/pathchord-transit/src/native_transport.rs)
currently handles TCP, HTTP, HTTPUpgrade, gRPC, QUIC, Meek and WebSocket including
bounded early data; it rejects unsupported transport and dial options. The
registry applies eligible multiplex options through a separate adapter. Its
[TLS configuration](../../../../../crates/pathchord-transit/src/tls.rs) rejects
fingerprint settings that it cannot honor. A combination is supported only
when each relevant adapter, transport, TLS option, importer and credential
path consumes it and the independent peer verifies it.

The native multiplex adapter supports h2mux, yamux and smux with optional
sing-mux padding. Independent local sing-box 1.14.4 tests covered smux over SS,
VLESS, VMess and Trojan, including both Vision flows, TCP/UDP, padding,
connection reuse, source revocation, and FIN behavior. A response produced
after target EOF did not return in the smux FIN test; this is not evidence of
TCP half-close support. smux bounds each session to 256 streams and separate
4 MiB receive/transmit queues; receive pressure isolates selected streams.
Active stalled carrier I/O needs caller cancellation or a higher-level timeout;
after the last stream release, pending I/O shares a ten-second drain deadline. See the
[smux investigation](smux-and-padding.md) for framing, further limits and
the distinction between the peer tests and open validation.

The [adapter registry](../../../../../crates/pathchord-transit/src/adapter_registry.rs)
shows which families can be built; the individual adapters define their
parameter checks and TCP/UDP capabilities. The
[implementation status](../../../../implementation-status.md) records existing
test evidence and its limits. External-core fixtures are explicitly invoked
test peers and must not become runtime, source or release dependencies.
