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

### Requirement: Validate native parameters without downgrade

A node SHALL become eligible only after its selected native adapter validates the complete consumed parameter set. Unknown or unsupported parameters SHALL produce the specified configuration error or sanitized unavailable-node diagnostic. TLS and transport validation failures SHALL NOT cause plaintext, direct, plugin-process, or external compatibility-process fallback; sensitive options and complete imported documents SHALL remain private credential data.

#### Scenario: Requested TLS configuration fails

- **WHEN** validation of a node's requested TLS configuration fails
- **THEN** the node is rejected or remains unavailable with a typed diagnostic, and no plaintext or direct fallback is selected.

### Requirement: Bounded imports and source-bound caches

Subscription processing SHALL normalize only supported node definitions, preserve valid siblings alongside individual diagnostics, retain the previous successful snapshot for malformed documents, and enforce the detailed node and byte limits. Private caches SHALL retain options and diagnostics and SHALL be bound to source type, URL, and credential reference; unverified caches SHALL NOT publish, and replaced-source nodes SHALL drain rather than accept new flows.

#### Scenario: One imported node is invalid

- **WHEN** a valid subscription document contains an invalid or unsupported node alongside valid nodes
- **THEN** valid siblings are retained and the invalid node remains unselectable with a stable sanitized diagnostic.

#### Scenario: Subscription source changes

- **WHEN** the subscription's source type, URL, or credential reference changes
- **THEN** nodes belonging to the previous source enter draining and cannot be selected for new flows.

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
| `socks5` | CONNECT, username/password, UDP ASSOCIATE; optional TLS for TCP | Supported extended node options |
| `ss` | TCP/UDP with AEAD and SS2022 ciphers; legacy stream ciphers are rejected | Native AEAD/SS2022 options; `obfs-local`, `v2ray-plugin`, and other plugin parameters produce unavailable diagnostics |
| `socks4`, `socks4a` | No native outbound adapter | CONNECT |
| `vless` | TCP, TLS, WebSocket, and WSS byte transports with typed TLS/transport validation | Extended transport and flow options |
| `vmess` | TCP, TLS, WebSocket/WSS, AES-128-GCM or ChaCha20-Poly1305 body records, single-target UDP, `alter_id: 0` | mux, legacy non-AEAD security, and other unsupported extended options |
| `trojan` | TLS-wrapped TCP, WebSocket, and WSS byte transports | Extended transport options |
| `anytls` | TLS stream, authentication, settings, SYN/SYNACK, PUSH/FIN, heartbeat frames, and bounded UDP-over-TCP datagrams | Multiplexed session options outside the native frame contract |
| `hysteria2` | Native QUIC/TLS + HTTP/3 authentication, TCP/UDP relay, Salamander or un-obfuscated transport, and bounded server-port hopping | Bandwidth limit fields, Gecko-specific obfuscation, and other unsupported extended options |
| `tuic` | Native QUIC/TLS-exporter TCP CONNECT, UDP DATAGRAM relay, heartbeat, and optional replay-sensitive 0-RTT | Unsupported congestion controllers, UDP-over-stream, and other extended options |
| `vless` + `tls.reality` | Native VLESS over REALITY TLS with X25519 ClientHello proof and certificate proof validation | Vision flow and unsupported outer transports |
| `xtls`, `hysteria`, `ssh`, `shadowtls` | No native adapter | Typed unavailable diagnostic |
| `wireguard` | No native adapter | Complete userspace WireGuard endpoint document |
| `snell` | No native adapter | Typed unavailable diagnostic |
| `ssr` and unregistered protocols | Unavailable | Explicitly unavailable |

Protocol names alone MUST NOT mark a node usable. Native adapters validate
consumed parameters before runtime publication. Unsupported parameters and
unimplemented protocols MUST produce typed, redacted diagnostics. A failed TLS
or transport configuration MUST NOT fall back to plaintext or direct.

Native VLESS and Trojan adapters reject unsupported flow, multiplex, packet,
and transport options before opening a socket. Native VMess accepts only
AEAD body ciphers and `alter_id: 0`; mux remains unavailable. REALITY requires
the native ClientHello proof callback and does not enable Vision flow by itself.
A protocol row in this table never makes an unsupported parameter set selectable.

### Typed connection options

`TransitProxy.spec.options` defaults to an empty object. Field names use
camelCase. Unknown fields are configuration errors; imported unknown fields
are retained as unavailable-node diagnostics rather than silently ignored.

| Field | Default and meaning |
| --- | --- |
| `tls` | absent; TLS object with `enabled`, `serverName`, `insecure`, `alpn`, `certificate`, `clientCertificate`, `clientKeyField`, `fingerprint`, `reality` |
| `transport` | absent; object with `type`, `path`, `host`, `headers`, `serviceName`, `maxEarlyData`, `earlyDataHeaderName` |
| `headers` | `{}`; non-secret HTTP CONNECT headers |
| `udp` | absent; use adapter capability; `false` disables ordinary UDP forwarding |
| `multiplex` | absent; object with `enabled`, `protocol`, `maxConnections`, `minStreams`, `maxStreams`, `padding` |
| `tcpFastOpen` | absent; optional boolean |
| `bindInterface` | absent; optional local interface name |
| `routingMark` | absent; optional unsigned 32-bit routing mark |
| `packetEncoding` | absent; `xudp` or `packetaddr` |

TLS booleans default to `false`; certificate/ALPN lists default to empty.
`https` implies enabled TLS. A Clash HTTP node with `tls: true` normalizes to
HTTPS CONNECT. `serverName` overrides certificate/SNI identity independently
of the connection address. Native HTTPS CONNECT permits HTTP/1.1 ALPN.
Certificate values are inline PEM; client private keys are resolved only from
the opaque credential document field named by `clientKeyField`. TLS settings
with disabled TLS are invalid unless the object is entirely default-valued.
Reality uses `publicKey` and `shortId`; fingerprint/Reality options require the
native Reality adapter. `insecure` is an explicit certificate-verification option,
never a fallback after validation failure.

Transport `type` is `tcp`, `ws`, `grpc`, `http`, `httpupgrade`, `quic`, or
`xhttp`; accepting the type in the model does not imply native support. Plain
TCP cannot carry HTTP transport parameters. WebSocket Host
overrides map to the transport's `Host` header. Conflicting aliases or Host
values are rejected. Multiplex booleans default to `false`; its protocol is
`smux`, `yamux`, or `h2mux`. Unsupported combinations fail validation.

Native adapter credential fields are protocol-specific. HTTP/SOCKS use
`username` and `password`; SS uses `cipher` and `password`. The native adapter
rejects SS plugin fields and reports diagnostics. Extra credential
keys MUST NOT be silently discarded. Sensitive headers, private keys, passwords, UUIDs, and complete
imported documents remain private credential data, never administrator labels
or public node diagnostics.

Typed protocol nodes use these private credential fields; fields absent from a
row are rejected instead of being guessed or discarded. The native adapter
performs final protocol validation.

| Protocol | Private credential fields |
| --- | --- |
| `vless`, `xtls` | `uuid`, `flow` |
| `vmess` | `uuid`, `security` or equivalent `cipher`, `alter_id` |
| `trojan`, `anytls` | `password` |
| `hysteria` | `auth` or `password`, `up_mbps`, `down_mbps`, `obfs`, `server_ports`, `hop_interval` |
| `hysteria2` | `password`, `obfs`, `obfs_password`, `server_ports`, `hop_interval` |
| `tuic` | `uuid`, `password`, `congestion_control`, `udp_relay_mode`, `heartbeat`, `zero_rtt_handshake`, `udp_over_stream` |
| `ssh` | `username`, `password`, `private_key`, `private_key_passphrase`, `host_key` |
| `shadowtls` | `password`, `version` |
| `snell` | `psk` or equivalent `password`, `userkey`, `version` |

`clientKeyField` adds its referenced private field to the permitted set.
Conflicting aliases are invalid. Further protocol fields remain unavailable
until the corresponding native adapter supports them.

The credential field `sing_box_outbound` is retained as an imported opaque
document for diagnostics, but it has no native adapter and is not executable
by PathChord. Imported documents cannot become an implicit process launch or
direct fallback. SS plugin fields are retained for diagnostics and rejected by
the native adapter; PathChord does not execute plugin processes or provide an
implicit wrapper.

### Subscription document families

| `source.type` | Accepted document family |
| --- | --- |
| `auto` | Detect the supported families below |
| `clash` | Clash/Mihomo `proxies` and HTTP `proxy-providers` |
| `sip008` | SS JSON array or versioned object containing `servers` |
| `uri` | Plain or Base64-encoded share-link lists; percent-encoded URI fields; VMess JSON and legacy/SIP002 SS forms |
| `sing_box` | Imported sing-box node documents retained as unavailable diagnostics |
| `surge`, `quantumult`, `loon` | Supported node-list and proxy-section forms |
| `static` | Administrator-authored nodes; no remote subscription refresh |

Input aliases normalize as follows: `mihomo` to `clash`; `base64` and `v2ray`
to `uri`; `sing-box` and `singbox` to `sing_box`; `quantumult_x` and
`quantumult-x` to `quantumult`. Import normalizes node definitions, not another
tool's routing rules, groups, scripts, or complete application configuration.
Recognizing a share-link format MUST NOT imply its node protocol is usable.

Malformed documents retain the previous successful snapshot. A malformed,
unsupported, or unavailable individual node MUST NOT discard valid sibling
nodes. It remains unselectable with a stable error code, field names, and a
sanitized message. Raw node text, URLs containing secrets, and credential
values MUST NOT appear in diagnostics. Private caches preserve options and
diagnostics; reload MUST NOT turn an invalid or unsupported cached node into
a usable node. Node count is bounded by 10,000 and document bytes by 4 MiB.

Cached nodes MUST be bound to the subscription's source type, URL, and
credential reference; a cache whose source cannot be verified MUST NOT be
published. When any of these source fields changes, nodes from the previous
source enter draining and MUST NOT be selected for new flows. Source URLs and
credential values MUST NOT be exposed through the cache's source identifier.

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
prevents new ordinary UDP associations. A TLS SOCKS node cannot silently send
plaintext UDP; an unsupported `udp: true` combination is rejected.

UDP through a PathChord Egress remains Session datagrams carried inside its
selected byte-stream Transit Paths. That capability is independent of whether
the third-party node has native UDP. Native UDP support MUST NOT be required
merely to carry an Egress UDP Session over a TCP/TLS Path. Unsupported ordinary
UDP routes return a typed route failure rather than bypassing policy.
