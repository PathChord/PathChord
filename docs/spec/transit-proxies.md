# Transit Proxy adapters and subscription formats

**English** | [简体中文](transit-proxies.zh-CN.md)

This document defines node connection semantics, subscription normalization,
provider expansion, and accounting metadata. The [configuration schema](configuration-schema.md)
defines resource envelopes; the [platform specification](platform-and-dns.md)
defines local HTTP, SOCKS, and Mixed listeners. Inbound protocol support MUST
NOT be interpreted as support for the same outbound node protocol.

## Adapter selection and failure

| Node protocol | Native transport | Optional sing-box 1.14.4 engine |
| --- | --- | --- |
| `direct` | TCP and UDP | Extended dialer options |
| `http`, `https` | HTTP/1 CONNECT, Basic authentication, validated extra headers; HTTPS uses TLS | Supported extended node options |
| `socks5` | CONNECT, username/password, UDP ASSOCIATE; optional TLS for TCP | Supported extended node options |
| `ss` | TCP/UDP; enabled classic AEAD, legacy stream, extra AEAD, and SS2022 ciphers | Built-in `obfs-local` and `v2ray-plugin` wrappers and supported extended options |
| `socks4`, `socks4a` | No native outbound adapter | CONNECT |
| `vless`, `vmess`, `xtls`, `trojan`, `hysteria`, `hysteria2`, `tuic`, `ssh`, `shadowtls`, `anytls` | No native adapter | Engine schema and transport validation are required |
| `wireguard` | No native adapter | Complete userspace WireGuard endpoint document |
| `snell` | No native adapter | Engine-supported versions 4 and 6 |
| `ssr` and unregistered protocols | Unavailable | Explicitly unavailable unless a matching adapter is registered |

The engine is an explicitly configured local executable, pinned to sing-box
1.14.4. Protocol names alone MUST NOT mark a node usable. Native adapters
validate consumed parameters; engine nodes MUST pass bounded version and
configuration checks before runtime publication. Unsupported parameters and
missing engine support MUST produce typed, redacted diagnostics. A failed
TLS or transport configuration MUST NOT fall back to plaintext or direct.

The optional engine owns a private loopback SOCKS endpoint with random
authentication. Node configuration is provided over stdin, not credential
arguments or a world-readable file. Engine output MUST NOT expose secrets.
Startup and readiness are bounded. The engine process is shared by its node's
connections, remains alive while those connections own it, and is killed and
reaped after its last owner disappears. Engine state directories are private.

## Typed connection options

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
Reality uses `publicKey` and `shortId`; fingerprint/Reality options require a
compatible engine. `insecure` is an explicit certificate-verification option,
never a fallback after validation failure.

Transport `type` is `tcp`, `ws`, `grpc`, `http`, `httpupgrade`, `quic`, or
`xhttp`; accepting the type in the model does not imply the chosen engine
supports it. Plain TCP cannot carry HTTP transport parameters. WebSocket Host
overrides map to the transport's `Host` header. Conflicting aliases or Host
values are rejected. Multiplex booleans default to `false`; its protocol is
`smux`, `yamux`, or `h2mux`. Unsupported combinations fail validation.

Native adapter credential fields are protocol-specific. HTTP/SOCKS use
`username` and `password`; SS uses `cipher` and `password`, with plugin fields
only on a compatible engine path. Extra credential keys MUST NOT be silently
discarded. Sensitive headers, private keys, passwords, UUIDs, and complete
engine documents remain private credential data, never administrator labels
or public node diagnostics.

Typed engine nodes use these private credential fields; fields absent from a
row are rejected instead of being guessed or discarded. The selected engine
performs final protocol/version validation.

| Protocol | Private credential fields |
| --- | --- |
| `vless`, `xtls` | `uuid`, `flow` |
| `vmess` | `uuid`, `security` or equivalent `cipher`, `alter_id` |
| `trojan`, `anytls` | `password` |
| `hysteria` | `auth` or `password`, `up_mbps`, `down_mbps`, `obfs`, `server_ports`, `hop_interval` |
| `hysteria2` | `password`, `up_mbps`, `down_mbps`, `obfs`, `obfs_password`, `server_ports`, `hop_interval` |
| `tuic` | `uuid`, `password`, `congestion_control`, `udp_relay_mode`, `heartbeat`, `zero_rtt_handshake`, `udp_over_stream` |
| `ssh` | `username`, `password`, `private_key`, `private_key_passphrase`, `host_key` |
| `shadowtls` | `password`, `version` |
| `snell` | `psk` or equivalent `password`, `userkey`, `version` |

`clientKeyField` adds its referenced private field to the permitted set.
Conflicting aliases are invalid. Further engine fields require a complete
engine node document, which preserves its own schema without reducing it to
the typed credential subset.

The credential field `sing_box_outbound` carries one complete engine node
document. It is authoritative and MUST NOT be combined with separate node
options or derived credential fields. Its type and endpoint must match the
normalized node. Unknown engine fields reach the engine validator unchanged.
Imported documents cannot reference local files, commands, external detours,
or a system WireGuard interface; inline credentials and userspace networking
are required. Network transport paths remain valid. SS plugin names are
limited to the registered built-in wrappers; arbitrary plugin execution is
not a node capability.

## Subscription document families

| `source.type` | Accepted document family |
| --- | --- |
| `auto` | Detect the supported families below |
| `clash` | Clash/Mihomo `proxies` and HTTP `proxy-providers` |
| `sip008` | SS JSON array or versioned object containing `servers` |
| `uri` | Plain or Base64-encoded share-link lists; percent-encoded URI fields; VMess JSON and legacy/SIP002 SS forms |
| `sing_box` | sing-box node documents with complete private outbound parameters |
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

## HTTP provider expansion

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

## Provider accounting metadata

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

## UDP routing boundaries

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
