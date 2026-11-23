# Provider and native peer acceptance matrix

This is a non-normative inventory for `validate-provider-and-runtime-reliability`,
recorded on 2026-11-17. It makes the inherited phrase "remaining combinations"
finite by using the supported contract and the completed
[native compatibility change](../../2026-11-17-support-sing-box-dae-transit-protocols/tasks.md).
Expected rejection is a matrix outcome, not an unbounded promise to implement
every option exposed by another application. A new protocol or behavior still
requires a separate delta. See the authoritative
[Transit Proxy contract](../../../../specs/transit-proxies/spec.md).

## Provider source provenance

| Document family | Existing deterministic coverage | Real-provider evidence retained in the repository | Remaining acceptance |
| --- | --- | --- | --- |
| URI and Base64 URI lists | Common schemes, percent encoding, plain/Base64 forms, valid/invalid siblings, strict parameters | Sanitized Base64 export from the supplied endpoint | Replay the captured Base64 wrapper |
| Clash/Mihomo and referenced HTTP providers | Recursive expansion, depth/reference/body budgets, interrupted downloads and credential origin checks | Sanitized provider export plus a reference based on the Mihomo documentation | Scripted fetches exercise expansion and credential origins |
| SIP008 array and versioned `servers` wrapper | Both forms normalize SS nodes | Sanitized versioned export with three placeholder server records | Replay the versioned export |
| sing-box node documents | Native normalization, unsupported document diagnostics and exclusion of selectors | Sanitized outbounds from the supplied endpoint | Replay the proxy and non-proxy records |
| Surge text nodes | Supported node/proxy-section forms and authentication/TLS vectors | Sanitized proxy lines from the supplied endpoint | Replay diagnostics for unsupported options |
| Quantumult X text nodes | Outside the v0.1.0 acceptance matrix | The supplied endpoint returned HTTP 403 | No successful response required for this acceptance run |
| Loon text nodes | Supported forms, positional credentials and obfs parameters | Sanitized proxy lines from the supplied endpoint | Replay diagnostics for unsupported options |

The deterministic cases are in
[subscription import tests](../../../../../crates/pathchord-transit/src/subscription_import/tests.rs)
and [provider tests](../../../../../crates/pathchord-transit/src/subscription_providers/tests.rs).
The new [local reliability harness](../../../../../scripts/test-runtime-reliability.py)
uses generated localhost credentials and provider documents. Its successful
sibling, retired-SSR diagnostic, redaction, cache, accounting, live-refresh and
failure checks are **synthetic local evidence**. They do not fill the real
source-provenance column. The supplied samples and Clash HTTP provider
fixture based on the Mihomo documentation complete the scoped provider evidence for this change.

## Supplied subscription probe

On 2026-11-23, provider responses for `clash.meta`, `Shadowsocks`,
`sing-box`, `Mihomo`, `v2rayN`, `Surge`, and `Loon` supplied the
[redacted test excerpts](../../../../../crates/pathchord-transit/tests/fixtures/provider-samples/README.md).
The SIP008 response had three placeholder server records. The sing-box response
had 76 outbounds, and the two identical Base64 responses contained 65 URI
entries each. Quantumult X returned HTTP 403. The Clash response supplied
inline proxies. The local HTTP-provider fixture follows the Mihomo documentation.

The importer tests replay the captured excerpts with placeholder connection
details. The local HTTP User-Agent regression uses independent constructed
responses to exercise concurrent format selection and mixed node outcomes.

## Independent peer scope

The prior compatibility change completed the native implementation slices and
the [status snapshot](../../../../implementation-status.md) records its 2026-11-17
acceptance run. The following is the explicit scope for task 1.2. Re-running it
on the implementation revision confirms current evidence; inventing another
unspecified cross-product of options does not expand this acceptance scope.

| Supported combination | Independent server peer and executable fixture | Explicit boundary |
| --- | --- | --- |
| HTTP/HTTPS CONNECT, authentication, SNI/CA, private path and Host options | sing-box 1.14.4; independent Go peer in `http_connect_external` | HTTP CONNECT does not advertise native UDP; sing-box inbound's path-form CONNECT limitation remains visible |
| SOCKS5 TCP/UDP, credentials and UoT v1/v2 including TLS | sing-box; `socks5_uot_external` and library adapter tests | TLS control cannot downgrade to unauthenticated plaintext UDP |
| SS classic AEAD, SS2022, supported legacy methods, custom AES-192-GCM/xchacha20 | sing-box, Mihomo 1.19.34 and independent stream server; `external_core_servers`, `shadowsocks_stream_external` | Unsupported legacy ciphers remain unavailable; a registered method is not evidence of every plugin combination |
| SS simple-obfs and v2ray-plugin WS/TLS/mux; native UDP and UoT | Original simple-obfs/v2ray-plugin; `shadowsocks_obfs`, `shadowsocks_v2ray_plugin`, `shadowsocks_uot_external` | No plugin process enters the product runtime; reference half-close limitations are retained |
| VMess AEAD and supported positive `alter_id`, AES-GCM/ChaCha/CFB/none/zero bodies, AEAD padding/authenticated length, TCP/UDP and packet encodings | sing-box, Mihomo, Xray 26.11.9, V2Fly 5.53.0; library peers and `external_core_servers` | V2Fly's recorded 2048-byte response limitation is not a successful full-size UDP claim |
| VLESS TCP/TLS, REALITY, both Vision flow names and XUDP | sing-box and Xray; library REALITY peers, `vision_external`, `tls_fingerprint_external` | Fingerprints are profile-specific; Xray hybrid-share and trusted-decoy boundaries are enforced |
| VLESS/VMess/Trojan HTTP, WS/WSS early data, HTTPUpgrade, gRPC and V2Ray QUIC | sing-box, Xray where supported; corresponding `*_external` integration tests | Only the applicable protocol/transport/TLS combinations are asserted; invalid Host/path/certificate cases reject |
| VLESS/VMess Meek over HTTP/1.1 and HTTP/2 | V2Fly; `meek_external` | Remote FIN is not advertised where the reference transport does not provide it |
| SS/VLESS/VMess/Trojan h2mux/yamux/smux with optional padding, reuse and source revocation | sing-box; `sing_mux_external` | smux's full-close FIN is not complete TCP half-close; stream/session queue limits and idle drain deadline apply |
| Trojan and supported Trojan-Go original/WS/gRPC/HTTPUpgrade; WS SS encryption | sing-box, Mihomo, Xray, V2Fly, Trojan-Go 0.10.6; `external_core_servers`, `trojan_go_external` | Original/TCP Trojan-Go SS encryption and other unimplemented options remain diagnostic-gated |
| Hysteria2 TLS/auth, TCP/UDP, Salamander/Gecko, fragmented UDP, hopping, BBR/Brutal negotiation | sing-box; library peers and `hysteria2_hopping_external`; independent Gecko relay for large padding | QUIC fingerprints are unavailable; peer 1452-byte receive-buffer limitation and non-strict pacing semantics remain explicit |
| TUIC v5 TCP/UDP, native DATAGRAM and stream relay, cubic/NewReno/BBR, UoT-over-stream | sing-box and Mihomo; library peers, `external_core_servers`, `tuic_udp_over_stream_external`, `tuic_lifecycle` | 0-RTT and QUIC fingerprints remain unavailable; peer and protocol packet limits are distinguished |
| AnyTLS TCP/UDP framing, authentication and bounded session behavior | sing-box and Mihomo; library peers and `external_core_servers` | Unsupported client metadata/session options require diagnostics, not silent acceptance |

For all rows, unsupported parameter combinations, malformed nodes, proxy chains,
retired SSR, unregistered protocols and unconsumed credential fields remain
unavailable. Their negative tests are part of acceptance. Xray and V2Fly are not
used as fake AnyTLS/Hysteria2/TUIC servers when they do not provide those native
server protocols. All peer binaries are test-only; the native adapters and their
Cargo dependencies remain the product implementation.

## Reproducible peer commands

Use locally available binaries of the recorded versions. These are local peer
checks; the QEMU network matrix and process soak have separate evidence files.

```sh
PATHCHORD_TEST_SING_BOX=/tmp/pathchord-outbound-20261117/sing-box \
  scripts/test-with-sing-box.sh
PATHCHORD_TEST_CORE_KIND=mihomo \
  PATHCHORD_TEST_MIHOMO=/tmp/pathchord-outbound-20261117/mihomo \
  scripts/test-with-external-core.sh
PATHCHORD_TEST_CORE_KIND=xray \
  PATHCHORD_TEST_XRAY=/tmp/pathchord-outbound-20261117/xray \
  scripts/test-with-external-core.sh
PATHCHORD_TEST_CORE_KIND=v2fly \
  PATHCHORD_TEST_V2FLY=/tmp/v2fly-5.53.0/v2ray \
  scripts/test-with-external-core.sh
cargo test --locked -p pathchord-transit --lib subscription::providers::tests
cargo test --locked -p pathchord-transit --lib subscription::import::tests
```

The shell entry points deliberately select ignored fixtures belonging to each
available peer. The fixture's versioned protocol checks and explicitly
unavailable combinations define the observed result. The normal workspace test
run alone does not execute this independent peer matrix.
