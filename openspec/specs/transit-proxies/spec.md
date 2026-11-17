# Transit Proxy adapters and subscription formats

**English** | [简体中文](spec.zh-CN.md)

## Purpose

Define native Transit Proxy eligibility, typed connection parameters, private credentials, subscription normalization, bounded provider expansion, accounting metadata, and ordinary versus Egress UDP boundaries.

## Requirements

### Requirement: Detailed Transit Proxy contract

Transit adapters and subscription processing SHALL conform to the complete detailed contract below, including protocol matrices, option and credential fields, source aliases, bounds, cache behavior, and UDP semantics. The requirements and scenarios supplement rather than replace those definitions; inbound listener support SHALL NOT imply outbound node support.

#### Scenario: Inbound protocol has no outbound adapter

- **WHEN** a `socks4` or `socks4a` outbound node is imported
- **THEN** it remains unavailable with a typed diagnostic even though local listeners support those protocols.

#### Scenario: Canonical native option names are authored

- **WHEN** a native TransitProxy uses `hosts`, `maxEarlyDataBytes`, `certificates`, `clientCertificates`, `clientHelloFingerprint`, or `udpOverTcpVersion` in its documented option object
- **THEN** parsing retains each field's documented type, value, and list order and passes it to the selected adapter without changing its connection semantics

#### Scenario: A retired native option name is authored

- **WHEN** a native TransitProxy uses any retired option path in the migration table, including an empty or default-valued field
- **THEN** complete-bundle validation rejects the candidate with a bounded `CONFIG_RETIRED_FIELD` diagnostic identifying the resource, exact authored field path, and canonical replacement without exposing values

#### Scenario: Retired and canonical native names are combined

- **WHEN** one native TransitProxy contains both a retired option name and its canonical replacement
- **THEN** validation rejects the complete candidate instead of merging the values, choosing a winner, or treating the retired name as an alias

#### Scenario: Certificate pins and ClientHello profiles are configured together

- **WHEN** native TLS configuration contains `certificateSha256` and `clientHelloFingerprint`
- **THEN** the certificate pin remains mandatory and the ClientHello profile independently selects the supported impersonation behavior

#### Scenario: A supported foreign node uses its original option names

- **WHEN** a Clash, sing-box, or share-link node supplies supported foreign TLS, HTTP Host, early-data, or UDP-over-TCP parameters using that source's documented spelling
- **THEN** import accepts and normalizes those fields into the canonical native model without requiring the foreign document to adopt native field names

#### Scenario: Foreign or private data contains a matching field name

- **WHEN** an HTTP header, private credential field, or retained complete foreign document contains a name matching a retired native option field
- **THEN** native-key validation does not rewrite or reject that data solely because its name matches a retired native field

### Requirement: Native compatibility for existing proxy protocols

Transit SHALL provide native support only for the protocol and option combinations marked supported in the detailed adapter matrix. Supported provider nodes SHALL preserve authentication, transport, security, and datagram semantics; unsupported or incomplete combinations remain unavailable with a typed diagnostic.

#### Scenario: A supported provider node uses a native adapter

- **WHEN** a provider supplies a node with a protocol and option combination listed as supported
- **THEN** Transit normalizes and prepares the corresponding native adapter without launching an external proxy core, preserving the documented connection semantics

#### Scenario: A combination cannot be represented safely

- **WHEN** a node contains an unsupported or incomplete connection-option combination
- **THEN** it remains unavailable with a redacted diagnostic, and no downgraded route is used

### Requirement: VLESS Vision flow and datagrams

VLESS Vision SHALL preserve each direction's framing transitions over direct TLS 1.3 or REALITY, using XUDP without multiplex and the selected multiplex framing when enabled. The `-udp443` flow SHALL additionally allow UDP to port 443.

#### Scenario: Vision datagrams to port 443

- **WHEN** a Vision node opens UDP to port 443
- **THEN** the request succeeds only for `xtls-rprx-vision-udp443` and carries the base Vision flow name on the wire

#### Scenario: Peer switches a Vision direction to direct copy

- **WHEN** a peer sends a valid Vision DIRECT transition after its framed content
- **THEN** the receiver delivers buffered plaintext and subsequent raw bytes in order without exposing the outer TLS record stream

### Requirement: Bounded smux sessions

smux sessions SHALL enforce the detailed per-session and per-stream resource
bounds, isolate receive-overloaded streams, and preserve the documented FIN and
carrier lifetime semantics.

#### Scenario: A smux stream exceeds its receive budget

- **WHEN** a smux stream exceeds its receive budget or is selected for isolation under the shared receive budget
- **THEN** that stream reports a resource error and schedules FIN, while the session continues processing other streams

#### Scenario: The last smux stream is released

- **WHEN** the last stream handle in a smux session is released while carrier I/O is pending
- **THEN** pending I/O shares one ten-second drain deadline; opening a new stream cancels that deadline

#### Scenario: A target responds after smux FIN

- **WHEN** a target sends a response after receiving smux FIN for a request
- **THEN** the client does not promise TCP half-close behavior or that the later response will arrive

### Requirement: Hysteria2 negotiated congestion control

Hysteria2 SHALL send the configured receive-rate hint and select its upload
congestion control after authentication according to the peer's response and
the configured upload rate, as specified in the detailed contract. A zero
effective target or an `auto` response SHALL use BBR; a positive effective
target SHALL use Brutal pacing and loss compensation.

#### Scenario: The peer requests automatic congestion control

- **WHEN** the authenticated Hysteria2 peer responds with `Hysteria-CC-RX: auto`
- **THEN** the client uses BBR even when a nonzero `up_mbps` is configured

#### Scenario: The peer supplies a numeric receive rate

- **WHEN** the peer responds with a numeric receive rate and the client has a nonzero `up_mbps`
- **THEN** the client uses the configured upload rate for a zero response or the smaller nonzero rate for a positive response

#### Scenario: No upload rate is configured

- **WHEN** `up_mbps` is absent or zero and the peer responds with a numeric receive rate
- **THEN** the client uses BBR, including when the peer's numeric rate is positive

### Requirement: Validate native parameters without downgrade

A native TLS-capable adapter SHALL load system roots by default, apply the configured ordered truststore source list, and fail preparation when any source cannot be read or parsed. TLS verification SHALL remain enabled unless an explicit insecure option is selected, and validation failure SHALL NOT fall back to plaintext or another protocol.

#### Scenario: Intrinsic TLS has no explicit TLS block

- **WHEN** a Hysteria2, TUIC, AnyTLS, or other intrinsically TLS node omits explicit TLS options
- **THEN** the adapter still uses system roots by default and performs certificate validation

#### Scenario: Requested TLS configuration fails

- **WHEN** validation of a node's requested TLS configuration fails
- **THEN** the node is rejected or remains unavailable with a typed diagnostic, and no plaintext or direct fallback is selected

### Requirement: Bounded imports and source-bound caches

Subscription processing SHALL normalize only supported node definitions, preserve valid siblings alongside individual diagnostics, retain the previous successful snapshot for malformed documents, and enforce the detailed node and byte limits. Private caches SHALL retain options and diagnostics and SHALL be bound to source type, URL, credential reference and effective User-Agent; unverified caches SHALL NOT publish, and replaced-source nodes SHALL drain rather than accept new flows.

#### Scenario: One imported node is invalid

- **WHEN** a valid subscription document contains an invalid or unsupported node alongside valid nodes
- **THEN** valid siblings are retained and the invalid node remains unselectable with a stable sanitized diagnostic.

#### Scenario: Subscription source changes

- **WHEN** the subscription's source type, URL, credential reference or effective User-Agent changes
- **THEN** nodes belonging to the previous source enter draining and cannot be selected for new flows.

#### Scenario: Canonical native options survive a source-bound cache roundtrip

- **WHEN** a verified source-bound cache is written and loaded with canonical native options
- **THEN** option values, credentials, diagnostics, source identity, and fresh adapter-preparation requirements are preserved

#### Scenario: A cache uses an incompatible normalized option schema

- **WHEN** a cache has an older normalized-option schema version or contains retired normalized native option fields
- **THEN** cache loading returns a bounded sanitized `cache_incompatible` diagnostic, publishes no nodes from that cache, and allows only bounded authenticated refresh under the current configured source

#### Scenario: An incompatible cache is found while valid nodes are active

- **WHEN** an incompatible cache is encountered and an independently valid active snapshot still satisfies the current source and lifecycle decisions
- **THEN** that active snapshot may remain available during bounded refresh, without treating the incompatible cache as validation or reviving retired nodes

#### Scenario: A cold start has an incompatible cache and no source connection

- **WHEN** no independently valid active snapshot exists, the cache is incompatible, and the configured source cannot be refreshed
- **THEN** no nodes are published from that cache and the subscription remains unavailable with typed cache and refresh diagnostics

#### Scenario: A cache conflicts with subscription lifecycle decisions

- **WHEN** a subscription is disabled, deleted, source-replaced, or subject to a persisted node tombstone before cache loading or refresh publication completes
- **THEN** the current lifecycle decision suppresses the affected publication and no incompatible cache, stale refresh, or retained snapshot resurrects the retired node

### Requirement: Node probe revocation follows source visibility

When Ingress applies a subscription disable, deletion, or source replacement,
it SHALL cancel queued and in-flight probes for affected nodes and SHALL NOT
publish observations from a revoked admission. Unrelated node probes SHALL
continue independently.

#### Scenario: Subscription changes while a probe is queued

- **WHEN** Ingress disables, deletes, or replaces the source of a queued or in-flight node probe
- **THEN** that probe is cancelled, stale results are not published, and unrelated probes can continue

### Requirement: Bounded provider expansion and credential origins

HTTP(S) provider expansion SHALL enforce at most 32 references, depth 3, and an aggregate 4 MiB body budget per refresh, reject local file/path providers, and report provider failures without discarding unrelated successful providers. Root bearer credentials SHALL be inherited only within the same URL origin, including across redirects; provider identity SHALL participate in stable node identity.

#### Scenario: Provider crosses a credential origin

- **WHEN** a provider reference or redirect targets an origin different from the root subscription
- **THEN** that origin does not receive the root bearer credential.

### Requirement: Explicit optional provider accounting

Provider usage and traffic multipliers SHALL follow the detailed parsing, bounds, persistence, and unknown-value semantics. Expiry SHALL NOT be interpreted as a quota-reset cycle, and missing or invalid metadata SHALL NOT fabricate zero capacity or become a hard connectivity limit. Valid metadata may affect selection weights but SHALL NOT override authorization, health, or explicit policy.

#### Scenario: Accounting metadata is absent

- **WHEN** a provider omits optional quota or multiplier metadata
- **THEN** those facts remain unknown and do not become fabricated zero capacity or a hard connectivity failure.

### Requirement: Separate native UDP from Egress Session datagrams

Ordinary UDP routes SHALL require the selected adapter's supported native UDP behavior and SHALL fail with a typed route error when unsupported. UDP node disable, SOCKS5 relay validation and control-connection ownership, and TLS downgrade prohibitions SHALL follow the detailed contract. Egress UDP Sessions carried by byte-stream Transit Paths SHALL NOT require native UDP support from the third-party node.

#### Scenario: Egress UDP uses a TCP or TLS Transit Path

- **WHEN** an Egress UDP Session is carried over an eligible TCP or TLS Transit Path
- **THEN** lack of native UDP support in that Transit node does not by itself reject the Session datagrams.

### Requirement: Truststore source lists are atomic

An adapter SHALL process truststore sources as one atomic set. Sources SHALL be `system` or local PEM/DER certificate files; relative paths SHALL resolve from the selected configuration source, symlink targets SHALL be regular files, and any invalid source SHALL reject the adapter candidate.

#### Scenario: One source in a list is invalid

- **WHEN** one configured truststore source is unreadable, oversized, malformed, or contains no valid certificate
- **THEN** adapter preparation fails closed without silently removing the invalid source or restoring system roots

### Requirement: Explicit insecure verification is separate

An adapter SHALL skip certificate verification only when its TLS options explicitly request insecure verification. An empty truststore without that option SHALL fail closed, and a TLS failure SHALL never downgrade to plaintext.

#### Scenario: Custom roots do not validate the peer

- **WHEN** a node uses a custom truststore and the peer certificate is not anchored by it
- **THEN** the TLS connection fails with a typed adapter error and does not retry as plaintext or insecure TLS

### Requirement: Subscription User-Agent identifies source content

Subscription HTTP requests SHALL use the configured per-source User-Agent, or `clash.meta` when it is absent. Root and nested provider requests SHALL carry the same value. Changing the effective User-Agent SHALL invalidate source-bound caches and stale refresh candidates without weakening credential origin or fetch-budget boundaries.

#### Scenario: A subscription changes its User-Agent

- **WHEN** a subscription's effective User-Agent changes
- **THEN** old-source nodes drain and cached or in-flight content obtained using the previous value cannot publish as the new source

## Detailed contract

This document defines node connection semantics, subscription normalization,
provider expansion, and accounting metadata. The [configuration schema](../configuration-schema/spec.md)
defines resource envelopes; the [platform specification](../platform-and-dns/spec.md)
defines local HTTP, SOCKS, and Mixed listeners. Inbound protocol support MUST
NOT be interpreted as support for the same outbound node protocol.

### Adapter selection and failure

| Node protocol | Native transport | Other parameters |
| --- | --- | --- |
| `direct` | TCP and UDP | Extended dialer options |
| `http`, `https` | HTTP/1 CONNECT, Basic authentication, validated extra headers; HTTPS uses TLS | Supported extended node options |
| `socks5` | CONNECT, username/password, UDP ASSOCIATE or UDP-over-TCP v1/v2; optional TLS | Supported extended node options |
| `ss` | TCP/UDP with AEAD, SS2022, selected legacy stream ciphers, explicit `none`/`plain`, UDP-over-TCP v1/v2, and native simple-obfs or v2ray-plugin WebSocket for TCP | Unsupported ciphers, plugins and plugin parameters produce unavailable diagnostics |
| `socks4`, `socks4a` | No native outbound adapter | CONNECT |
| `vless` | TCP, TLS, WebSocket/WSS, HTTP, HTTPUpgrade, gRPC, QUIC and Meek byte transports with typed TLS/transport validation | Extended transport and flow options |
| `vmess` | TCP, TLS, WebSocket/WSS, HTTP, HTTPUpgrade, gRPC, QUIC, Meek, AES-128-GCM, ChaCha20-Poly1305 or AES-128-CFB body records, explicit `none`/`zero` plaintext bodies, single-target UDP, bounded legacy or AEAD `alter_id` headers | Supported multiplex and extended options are validated as described below |
| `trojan` | TLS-wrapped TCP, WebSocket/WSS, HTTP, HTTPUpgrade, gRPC and QUIC byte transports, plus supported Trojan-Go share links with original/TCP and WebSocket, gRPC and HTTPUpgrade aliases | Trojan-Go original/TCP with SS encryption is unavailable because the reference server's request sniffing is not reliable for short encrypted streams; unsupported Trojan-Go options produce typed diagnostics |
| `anytls` | TLS stream, authentication, settings, SYN/SYNACK, PUSH/FIN, heartbeat frames, and bounded UDP-over-TCP datagrams | Multiplexed session options outside the native frame contract |
| `hysteria2` | Native QUIC/TLS + HTTP/3 authentication, TCP/UDP relay to IPv4 or IPv6 targets, bounded UDP fragmentation and reassembly, Salamander, Gecko or un-obfuscated transport, bounded server-port hopping, and negotiated BBR/Brutal rates | TLS fingerprints and other unsupported extended options |
| `tuic` | Native QUIC/TLS-exporter TCP CONNECT, native DATAGRAM, QUIC-stream UDP relay or UDP-over-stream, cubic/NewReno/BBR congestion control and heartbeat | TLS fingerprints, 0-RTT and other unsupported extended options |
| `vless` + `tls.reality` | Native VLESS over REALITY TLS with X25519 ClientHello proof, certificate proof validation and dae Chrome 133, iOS 14, Safari 16, Edge 85, QQ 11.1 and Firefox 120 fingerprint profiles | Other fingerprints, certificate pins, custom trust roots and unsupported outer transports produce typed unavailable diagnostics |
| `xtls` | Alias for VLESS with an explicit registered XTLS Vision flow; normalized to `vless` before adapter selection | Missing or unsupported XTLS flow produces a typed diagnostic |
| `hysteria`, `ssh`, `shadowtls` | No native adapter | Typed unavailable diagnostic |
| `wireguard` | No native adapter | Complete userspace WireGuard endpoint document |
| `snell` | No native adapter | Typed unavailable diagnostic |
| `ssr` and unregistered protocols | Unavailable | Explicitly unavailable |

Protocol names alone MUST NOT mark a node usable. Native adapters validate
consumed parameters before runtime publication. Unsupported parameters and
unimplemented protocols MUST produce typed, redacted diagnostics. A failed TLS
or transport configuration MUST NOT fall back to plaintext or direct.

Native VLESS and Trojan adapters reject unsupported flow, multiplex, packet,
and transport options before opening a socket. Native VMess accepts positive
`alter_id` legacy HMAC-MD5/AES-128-CFB headers as well as AEAD headers,
AEAD body ciphers, AES-128-CFB with continuous stream state and per-record
FNV-1a checksums, or explicitly configured `none`/`zero` plaintext bodies;
`alter_id` is bounded to `0..=65535`. Native h2mux, yamux and smux are available as described below. Its AEAD response header uses
AES-128-GCM independently of the selected body cipher. A VLESS node
with either `xtls-rprx-vision` or `xtls-rprx-vision-udp443` uses Vision over
direct TLS 1.3 or REALITY. Without multiplex, Vision datagrams use XUDP; with
supported multiplex they use its UDP framing. Only the latter flow allows UDP
to port 443; both send `xtls-rprx-vision` on the wire. XUDP datagrams are
bounded to 8192 bytes. An unavailable fingerprint is not approximated by a
different ClientHello. A protocol row in this table never makes an unsupported
parameter set selectable.
The first Vision request and first outbound frame share a padded outer TLS
record when data arrives promptly. An idle connection emits a padded empty
frame after a bounded delay; a complete CONTINUE frame followed by EOF is a
valid stream end.

VMess `globalPadding` and `authenticatedLength` are accepted only with an
AEAD body cipher. The authenticated-length wire format derives both directional
length keys and nonce sequences from the request key and IV; peers therefore
reuse a key/nonce across directions. Each direction MUST stop before its own
record counter wraps.
VMess supports `packetEncoding: xudp` and `packetaddr`; packetaddr requires an
IP destination. Returned packet addresses are checked against the bound
destination, with a resolved IP accepted for an XUDP hostname target only
when its port matches.
VLESS also supports `packetaddr` for IP destinations over plain TCP, TLS or
REALITY without Vision. `packetaddr` with either Vision flow is rejected during
adapter preparation. Explicit packet encoding is also incompatible with
multiplex; supported multiplex uses its own datagram framing.

For REALITY, `clientHelloFingerprint: chrome` selects the dae 2.1.2 Chrome 133 profile.
It initially attempts the classic X25519 form, remembers a successful form,
and retries the other form only after a complete TLS handshake authenticates a trusted decoy certificate. It
never sends VLESS data to the decoy. TLS 1.2, HelloRetryRequest, resumption,
real ECH and a server ALPS response are unavailable in this profile.
`clientHelloFingerprint: ios`, `safari`, `edge` and `qq` select dae's iOS 14, Safari 16,
Edge 85 and QQ 11.1 profiles respectively, using their original X25519 key
share. `clientHelloFingerprint: firefox` selects dae's Firefox 120 profile with separate
X25519 and P-256 key shares. The peer's `record_size_limit` constrains outgoing
TLS records independently of the client's advertised receive limit, without
increasing a stricter local limit. A QQ server ALPS response is rejected
explicitly. Ordinary TLS also supports these profiles with the configured
certificate checks. `clientHelloFingerprint: android` selects dae/uTLS Android 11 OkHttp
for ordinary TLS 1.2 without ALPN; REALITY, Vision and transports requiring
ALPN are unavailable with this profile. The 360 profile is unavailable because
its advertised cipher suites have no supported implementation in this TLS
backend; it MUST NOT be substituted with another profile.

Gecko accepts `gecko_min_packet_size` and `gecko_max_packet_size` as integer
on-wire padding targets. Each omitted or zero value independently defaults to
512 or 1200 bytes, respectively; the resulting range MUST satisfy
`1 <= min <= max <= 2048`. These fields require Gecko. The targets apply to
fragmented long-header packets including the Salamander salt; short-header
packets are not padded, and a fragment already larger than the maximum is
sent without extra padding. sing-box's nested `obfs.min_packet_size` and
`obfs.max_packet_size` normalize to these fields.

Hysteria2 `up_mbps` and `down_mbps` are optional nonnegative integer Mbps values;
invalid values and values whose conversion to bytes per second overflows are
rejected at preparation. Each Mbps is 125,000 bytes per second. Omitted values
are zero. `down_mbps` is sent as the client's receive-rate hint in the request
`Hysteria-CC-RX`; zero means unknown, and the server may ignore the hint.

The client uses BBR for the QUIC handshake. After authentication, a response
`Hysteria-CC-RX: auto` keeps BBR regardless of `up_mbps`. For a numeric
response, zero selects the configured `up_mbps`; a positive response selects
the smaller of that value and the configured `up_mbps`. A zero resulting target
keeps BBR, including when `up_mbps` is absent or zero and the server returns a
positive numeric value. A positive target selects Brutal for that connection.

Brutal uses the recent acknowledged-packet ratio over five second-indexed
slots. Fewer than 50 acknowledged and lost packets yield a ratio of one;
otherwise the ratio is clamped to at least 0.8. Its pacing rate is the target
divided by that ratio and its congestion window is twice the product of that
rate and the smoothed RTT. Before an RTT sample the window is 10,240 bytes;
afterwards it is at least one byte. The pacer's token-bucket capacity is the
larger of ten maximum-sized datagrams and four milliseconds of pacing budget.
Loss compensation can therefore raise the normal paced QUIC rate to 1.25 times
the target. PTO loss probes and ACK-only packets can bypass pacing; MTU and
path-validation probes may also be sent outside it. These exceptions, bursts,
retransmissions, and UDP/IP or obfuscation overhead mean the target is not a
strict physical bandwidth cap or a throughput guarantee.

Shadowsocks supports SIP004 `aes-192-gcm` for TCP and UDP. The accepted legacy
stream methods are AES-128/192/256 CTR, CFB and OFB, Camellia-128/192/256 CFB,
RC4, RC4-MD5, ChaCha20-IETF and `xchacha20`. Legacy stream methods do not
authenticate their payloads. `none` and `plain` explicitly select the
unencrypted Shadowsocks wire mode; they do not use a password. A nonempty
password with either method is rejected rather than discarded. Other
unsupported stream methods are unavailable.

For `aes-192-gcm` and `xchacha20`, each adapter instance retains a bounded
window of 4096 recently used outbound and inbound salts or IVs across TCP and
UDP, rejecting repeats still in that window. This window is not persistent;
in particular, it does not provide payload authentication for `xchacha20`.

The native Shadowsocks `v2ray-plugin` adapter supports SIP003 and Clash
WebSocket options, optional TLS, Host, path, validated headers, configured
certificate and pin checks, and the default single-stream mux or explicit
`mux=0`. UDP uses the Shadowsocks datagram transport unless UDP-over-TCP
is explicitly selected, in which case it traverses the configured TCP plugin.
Unsupported mux counts, transport modes and unconsumed options are rejected.

### Typed connection options

`TransitProxy.spec.options` defaults to an empty object. Field names use
camelCase. Unknown fields are configuration errors; imported unknown fields
are retained as unavailable-node diagnostics rather than silently ignored.

| Field | Default and meaning |
| --- | --- |
| `tls` | absent; TLS object with `enabled`, `serverName`, `insecure`, ordered `truststore`, `alpn`, `certificates`, `certificateSha256`, `clientCertificates`, `clientKeyField`, `clientHelloFingerprint`, `reality` |
| `transport` | absent; object with `type`, `path`, `hosts`, `headers`, `serviceName`, `maxEarlyDataBytes`, `earlyDataHeaderName` |
| `headers` | `{}`; non-secret HTTP CONNECT headers |
| `udp` | absent; use adapter capability; `false` disables ordinary UDP forwarding |
| `udpOverTcpVersion` | absent; SOCKS5 or Shadowsocks UDP-over-TCP version `1` or `2`; incompatible with `udp: false` |
| `vmess` | absent; `globalPadding` and `authenticatedLength` booleans, both default `false` |
| `multiplex` | absent; object with `enabled`, `protocol`, `maxConnections`, `minStreams`, `maxStreams`, `padding` |
| `tcpFastOpen` | absent; optional boolean |
| `bindInterface` | absent; optional local interface name |
| `routingMark` | absent; optional unsigned 32-bit routing mark |
| `packetEncoding` | absent; `xudp` or `packetaddr` |

These PathChord-owned native option names are canonical and have no aliases.
The selected adapter MUST reject unsupported combinations or cardinality
rather than discard fields. Retired names MUST fail with bounded
`CONFIG_RETIRED_FIELD` diagnostics naming the field and replacement; unknown
fields remain invalid, and key names are not recursively rewritten.

| Retired native field | Canonical field |
| --- | --- |
| `transport.host` | `transport.hosts` |
| `transport.maxEarlyData` | `transport.maxEarlyDataBytes` |
| `tls.certificate` | `tls.certificates` |
| `tls.clientCertificate` | `tls.clientCertificates` |
| `tls.fingerprint` | `tls.clientHelloFingerprint` |
| `udpOverTcp` | `udpOverTcpVersion` |

`hosts` is an ordered list of up to 16 nonempty HTTP Host overrides, each at
most 255 bytes; an adapter may support fewer entries and rejects unsupported
cardinality. `certificates` and `clientCertificates` are each ordered lists
of up to 16 inline PEM values, each at most 65,536 bytes. The former adds
trust anchors; the latter forms the client-authentication chain.
`maxEarlyDataBytes` is an integer byte limit in `0..=65536`.
`udpOverTcpVersion` is an optional integer version `1` or `2`, not an
enable flag.

TLS booleans default to `false`; the truststore defaults to `["system"]` and
`certificates`, `clientCertificates`, and `alpn` default to empty lists. Each truststore source is `system` or
a local PEM/DER file. Relative paths resolve from the selected configuration
source, absolute paths are allowed, symlink targets must be regular files, and
an empty list means no trust anchors. Any invalid, oversized, or malformed
source rejects the adapter atomically. `insecure` is the only verification
bypass and MUST be explicit.
`https` implies enabled TLS. A Clash HTTP node with `tls: true` normalizes to
HTTPS CONNECT. `serverName` overrides certificate/SNI identity independently
of the connection address. Native HTTPS CONNECT permits HTTP/1.1 ALPN.
`certificates` contains inline PEM trust anchors added to the configured
truststore; `clientCertificates` contains the inline client-authentication
chain. Client private keys are resolved only from the opaque credential
document field named by `clientKeyField`. TLS settings
with disabled TLS are invalid unless the object is entirely default-valued.
`certificateSha256` is the hexadecimal SHA-256 of a DER certificate; a leaf
match authenticates the leaf, and a matched intermediate anchors normal chain,
name and time validation. The pin remains mandatory when `insecure: true`.
Reality uses `publicKey` and `shortId`; `clientHelloFingerprint` requires an
adapter that implements the requested ClientHello profile. `insecure` is an explicit certificate-verification option,
never a fallback after validation failure.

Transport `type` is `tcp`, `ws`, `grpc`, `http`, `httpupgrade`, `quic`, `meek`,
or `xhttp`; accepting the type in the model does not imply native support. Plain
TCP cannot carry HTTP transport parameters. The `http` transport supports a
path, at most one Host and validated headers for VLESS, VMess and Trojan. It
uses HTTP/1.1 PUT without TLS and HTTP/2 PUT with TLS and `h2` ALPN; the peer
response must have status 200. The default path is `/`; without a configured
Host, plaintext uses the endpoint host and TLS uses `www.example.com`.
Conflicting Host values, multiple host overrides, service-name or early-data options,
and framing-controlled headers are rejected. Trojan still requires TLS.
The V2Ray `quic` transport requires TLS for VLESS, VMess and Trojan; it uses
`h3` ALPN when no ALPN is configured and preserves explicit ALPN values. It
rejects REALITY, Vision, ClientHello fingerprints and other unconsumed
transport parameters rather than silently changing them.
Meek is available for VLESS and VMess over HTTPS. Its full URL, including any
query, is stored in private `meek_url` credentials; public path, Host and
header transport options are rejected. Meek's local write shutdown does not
signal an end-of-stream to the remote endpoint.
HTTPUpgrade supports its path, Host and validated headers over TCP or TLS.
WebSocket early data sends up to
`maxEarlyDataBytes` bytes from the first write as unpadded Base64URL in the path or
the specified `earlyDataHeaderName`, with remaining bytes sent in binary frames.
Path early data with an unrelated query is unavailable. WebSocket Host
overrides map to the transport's `Host` header. Conflicting aliases or Host
values are rejected. Multiplex booleans default to `false`. Native `h2mux`,
`yamux`, and `smux` support SS, VLESS, VMess and Trojan with optional sing-mux padding;
omitted protocol selects `h2mux`. `maxConnections` is at most 256, `minStreams` requires
`maxConnections`, and `maxStreams` is exclusive with both; stream limits are
at most 4096 for h2mux and 256 for yamux or smux. With neither connection nor stream
limits configured, an idle connection may be reused while an active one causes
a new connection. Combinations of multiplex with explicit packet encoding or
UDP-over-TCP are unavailable rather than silently ignored.

Each smux session supports at most 256 logical streams, including streams
being closed, and separately bounds queued receive payload and transmit wire
frames to 4 MiB each. It also bounds reception to 256 KiB per stream and 1024
queued frames per session, and transmission to 512 queued frames per session.
Receive payload remains charged until its complete frame allocation is
released; these queue budgets are not a bound on total process memory. If a
stream exceeds its receive limit, or shared receive pressure selects it for
isolation, the session discards its buffered data, returns a resource error to
that stream and schedules FIN. It continues consuming and discarding later data for
that stream so other streams can progress.

The adapter cannot observe every byte of progress inside a buffered carrier.
Pending carrier I/O with an active stream therefore has no smux-driver
no-progress deadline; the caller or a higher-level timeout must cancel stalled
work. After the last stream handle is released, pending I/O shares one absolute ten-second drain
deadline across the session's reader and writer. A new stream cancels that
deadline; expiration terminates the session. An otherwise idle pooled session
can remain available until normal pool reclamation. smux v1 FIN follows the
reference peer's full-close semantics: after a peer FIN, reads drain already
buffered data and further writes fail. A local FIN does not guarantee that a
response produced after the target sees EOF can be delivered; smux MUST NOT be
advertised as supporting full TCP half-close compatibility.

With multiplex padding enabled, the physical connection starts with sing-mux
version `1`, protocol `0` for smux, `1` for yamux or `2` for h2mux, padding flag `1`, a
big-endian `u16` padding length, and that many padding bytes. The first 16
records in each direction carry a big-endian `u16` content length, a
big-endian `u16` padding length, the content, and the padding. Subsequent
bytes in that direction are unframed by this padding layer. The client chooses
256–767 padding bytes per emitted padded record; truncated records are errors.
If a multiplexed UDP association closes before the peer supplies its success
status, close reports an unconfirmed response rather than success. A datagram
may already have reached the destination; the adapter MUST NOT replay it.

Native adapter credential fields are protocol-specific. HTTP/SOCKS use
`username` and `password`; SS uses `cipher`, `password` and supported plugin
fields. Unsupported plugin fields produce diagnostics. Extra credential
keys MUST NOT be silently discarded. Sensitive headers, private keys, passwords, UUIDs, and complete
imported documents remain private credential data, never administrator labels
or public node diagnostics.

Typed protocol nodes use these private credential fields; fields absent from a
row are rejected instead of being guessed or discarded. The native adapter
performs final protocol validation.

| Protocol | Private credential fields |
| --- | --- |
| `http`, `https` | `username`, `password`, optional private `http_path` |
| `socks5` | `username`, `password` |
| `vless`, `xtls` | `uuid`, `flow`, `meek_url` when using Meek |
| `vmess` | `uuid`, `security` or equivalent `cipher`, `alter_id`, `meek_url` when using Meek |
| `trojan`, `anytls` | `password`; Trojan-Go SS encryption additionally uses private `trojan_go_ss_method` and `trojan_go_ss_password` fields |
| `hysteria` | `auth` or `password`, `up_mbps`, `down_mbps`, `obfs`, `server_ports`, `hop_interval` |
| `hysteria2` | `password` or equivalent `auth`, `obfs`, `obfs_password`, `gecko_min_packet_size`, `gecko_max_packet_size`, `server_ports`, `hop_interval`, `up_mbps`, `down_mbps` |
| `tuic` | `uuid`, `password`, `congestion_control`, `udp_relay_mode`, `heartbeat`, `zero_rtt_handshake`, `udp_over_stream` |
| `ssh` | `username`, `password`, `private_key`, `private_key_passphrase`, `host_key` |
| `shadowtls` | `password`, `version` |
| `snell` | `psk` or equivalent `password`, `userkey`, `version` |

`clientKeyField` adds its referenced private field to the permitted set.
Conflicting aliases are invalid. Further protocol fields remain unavailable
until the corresponding native adapter supports them.

Foreign document syntax and private credential JSON retain their source
spellings. Supported Clash `client-fingerprint` and sing-box
`tls.utls.fingerprint` normalize to native `tls.clientHelloFingerprint`;
Clash certificate `fingerprint` normalizes to the distinct
`tls.certificateSha256`. Foreign Host, early-data and UDP-over-TCP keys
continue to normalize through their source adapters. Native-key validation
MUST NOT rewrite HTTP header names, protocol identifiers, private credential
fields, or complete imported documents merely because a key matches a retired
native path.

Representable sing-box proxy nodes are normalized to native options and
credentials. A node with unrepresentable fields retains its complete private
`sing_box_outbound` document and remains unavailable with a diagnostic;
selector, URL-test, direct and block entries are not imported as proxy nodes.
Imported documents cannot become an implicit process launch or direct fallback.
The SS adapter implements simple-obfs `obfs`, `obfs-local` and `simple-obfs`
HTTP/TLS modes and v2ray-plugin WebSocket modes natively; UDP uses ordinary
Shadowsocks datagrams unless UDP-over-TCP is explicitly enabled. Other plugins
and unsupported options remain unavailable.
PathChord does not execute plugin processes.

### Subscription document families

| `source.type` | Accepted document family |
| --- | --- |
| `auto` | Detect the supported families below |
| `clash` | Clash/Mihomo `proxies` and HTTP `proxy-providers` |
| `sip008` | SS JSON array or versioned object containing `servers` |
| `uri` | Plain or Base64-encoded share-link lists; percent-encoded URI fields; VMess JSON and legacy/SIP002 SS forms |
| `sing_box` | Native-supported sing-box node definitions; unsupported documents remain private unavailable diagnostics |
| `surge`, `quantumult`, `loon` | Supported node-list and proxy-section forms |
| `static` | Administrator-authored nodes; no remote subscription refresh |

Input aliases normalize as follows: `mihomo` to `clash`; `base64` and `v2ray`
to `uri`; `sing-box` and `singbox` to `sing_box`; `quantumult_x` and
`quantumult-x` to `quantumult`. Import normalizes node definitions, not another
tool's routing rules, groups, scripts, or complete application configuration.
Recognizing a share-link format MUST NOT imply its node protocol is usable.
Clash VLESS with omitted or empty `packet-encoding` and sing-box VLESS with
omitted `packet_encoding` default to XUDP unless multiplex is enabled, in which
case its UDP framing is used. An explicit empty sing-box value requests ordinary
VLESS UDP when neither Vision nor multiplex is enabled; multiplex instead uses
its own framing. Vision with an explicit empty value remains unavailable. For
an authored native VLESS node without multiplex, omitted `packetEncoding`
selects ordinary VLESS UDP without Vision and XUDP with Vision. V2Ray URI
`pinSHA256` maps to `certificateSha256`, `mport` maps to the Hysteria2 port
range, and equal `sni`/`servername` aliases are accepted. Conflicting aliases
are invalid. The default REALITY `spx=/` does not alter the proxy handshake;
custom spider paths remain unavailable rather than being ignored.

Malformed documents retain the previous successful snapshot. A malformed,
unsupported, or unavailable individual node MUST NOT discard valid sibling
nodes. It remains unselectable with a stable error code, field names, and a
sanitized message. Raw node text, URLs containing secrets, and credential
values MUST NOT appear in diagnostics. Private caches preserve options and
diagnostics; reload MUST NOT turn an invalid or unsupported cached node into
a usable node. Node count is bounded by 10,000 and document bytes by 4 MiB.

Cached nodes MUST be bound to the subscription's source type, URL,
credential reference, and effective User-Agent; a cache whose source cannot be verified MUST NOT be
published. When any of these source fields changes, nodes from the previous
source enter draining and MUST NOT be selected for new flows. Source URLs and
credential values MUST NOT be exposed through the cache's source identifier.
The root request and all referenced HTTP providers use the same effective
User-Agent, defaulting to `clash.meta` when none is configured. A cache from a
previous version that did not bind a User-Agent cannot establish that source
identity and MUST NOT publish.

Source-bound normalized-node caches use envelope version `3` and the
canonical native option names. A version-2 normalized cache or a cache
containing any retired native option path is incompatible: it MUST return a
bounded sanitized `cache_incompatible` diagnostic and publish no nodes from
that cache. A loader MUST NOT install native aliases, discard fields,
substitute defaults, partially decode nodes, or guess private credential
content to keep an incompatible cache usable. Version-1 caches remain
unverified and MUST NOT publish.

When an incompatible cache is rejected, an independently valid active
snapshot for the current source and lifecycle may remain available while the
configured source undergoes its existing bounded authenticated refresh. On a
cold offline start with no such snapshot, the subscription remains
unavailable. Refresh MUST preserve credential-origin and fetch-budget
boundaries and pass normal normalization, validation and adapter preparation
before publication. Disabled, deleted, source-replaced and tombstoned nodes
MUST NOT be revived by cache load, retained snapshots or stale refresh work.

### HTTP provider expansion

Provider references may recursively fetch HTTP(S) node documents with at most
32 references, depth 3, and an aggregate 4 MiB body budget per refresh. URLs
must be credential-free; local file/path providers are rejected. Cycles,
unsupported provider types, fetch errors, malformed documents, and budget
exhaustion produce provider diagnostics. An unsuccessful provider refresh
retains its previous successful nodes while unrelated successful providers
can publish their new data.

The root subscription's bearer credential may be inherited only by a provider
with the same URL origin. A cross-origin provider MUST NOT receive it.
Redirect handling MUST preserve this credential boundary. Provider identities
participate in stable node IDs so equal display names from independent
providers do not overwrite each other.

### Provider accounting metadata

`Subscription-Userinfo` may report unsigned `upload`, `download`, `total`, and
`expire` values. Upload/download are required for a valid usage observation;
missing or malformed optional values are unknown. Remaining bytes are
`max(total - upload - download, 0)`; the ratio is unknown when total is absent
or zero. `expire` is an expiry timestamp, not evidence of a quota reset cycle.

`PathChord-Traffic-Multiplier` is an explicit optional decimal with at most
four fractional digits, in `0.0001..=100`. No multiplier is inferred from a
node name, URL, consumed traffic, or remaining quota. Missing/invalid metadata
MUST NOT become fabricated zero capacity or a hard connectivity limit.
Observations and private caches retain these provider facts across refresh
and reload. Valid quota/multiplier facts may reweight selection and Path
economics; they do not override authorization, health, or explicit policy.

### UDP routing boundaries

Ordinary direct, SOCKS5, and SS routes can use native UDP forwarding, including
SS2022 datagram session state. SOCKS5 relay replies are validated and its TCP
control connection remains owned until association close. Disabling node UDP
prevents new ordinary UDP associations. SOCKS and Shadowsocks UDP-over-TCP
carry datagrams inside the configured proxy TCP stream, including TLS or a
TCP plugin when configured.
A TLS SOCKS node cannot silently send plaintext UDP; an unsupported `udp: true`
combination is rejected.
TUIC `udp_over_stream` uses UoT v2 over its authenticated QUIC stream and
cannot be combined with an explicit `udp_relay_mode`. Its peer may impose a
smaller packet limit than the protocol's 65,535-byte maximum; packets MUST NOT
be silently truncated.

UDP through a PathChord Egress remains Session datagrams carried inside its
selected byte-stream Transit Paths. That capability is independent of whether
the third-party node has native UDP. Native UDP support MUST NOT be required
merely to carry an Egress UDP Session over a TCP/TLS Path. Unsupported ordinary
UDP routes return a typed route failure rather than bypassing policy.
