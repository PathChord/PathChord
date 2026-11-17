# Transit Proxy configuration delta

## MODIFIED Requirements

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

#### Detailed contract

##### Canonical native option names

The native `TransitProxy.spec.options` schema MUST use the following names.
Paths in this table are relative to `TransitProxy.spec`. This table is the
Transit option subset of the [canonical native migration table](../configuration-schema/spec.md#canonical-native-naming-and-field-migration).

| Retired native path | Canonical native path | Preserved meaning |
|---|---|---|
| `options.transport.host` | `options.transport.hosts` | ordered HTTP Host override list |
| `options.transport.maxEarlyData` | `options.transport.maxEarlyDataBytes` | byte limit with the existing bound |
| `options.tls.certificate` | `options.tls.certificates` | inline additional trust anchors |
| `options.tls.clientCertificate` | `options.tls.clientCertificates` | inline client certificate chain |
| `options.tls.fingerprint` | `options.tls.clientHelloFingerprint` | ClientHello impersonation profile |
| `options.udpOverTcp` | `options.udpOverTcpVersion` | explicit supported wire version |

The resource API remains `pathchord.io/v1`. Every retired native option key
MUST be rejected, including empty/default values and simultaneous retired and
canonical forms. It MUST NOT become an alias, fallback, or merge input.
`CONFIG_RETIRED_FIELD` diagnostics MUST identify the resource, exact authored
field path, and replacement path without exposing values. Invalid candidates
MUST retain the complete last good configuration under atomic publication.
Unknown fields remain invalid; recursive key conversion is forbidden.

The renamed collection fields retain their existing list shape and declared
order. `transport.hosts` permits at most 16 bounded nonempty strings, each at
most 255 bytes; a selected adapter MAY support fewer hosts and MUST reject
unsupported cardinality rather than discard elements. Both TLS certificate
lists permit at most 16 inline PEM strings, each at most 65,536 bytes.
`maxEarlyDataBytes` is an optional integer byte count in `0..=65536`, without
rate or unit conversion. `udpOverTcpVersion` remains an optional integer `1`
or `2`, not an enable flag; combining it with `udp: false` is invalid.

`tls.certificates` adds trust anchors to the configured truststore; it is not
the peer certificate pin. `tls.clientCertificates` supplies the client-auth
chain and retains its private-key reference through `clientKeyField`.
`clientHelloFingerprint` selects only a supported ClientHello profile;
`certificateSha256` remains the independent certificate pin. Renaming these
fields MUST NOT relax TLS verification, pin validation, adapter capability
checks, or rejection of unconsumed parameters.

##### Typed connection options

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

TLS booleans default to `false`; the truststore defaults to `["system"]` and
certificate/ALPN lists default to empty. Each truststore source is `system` or
a local PEM/DER file. Relative paths resolve from the selected configuration
source, absolute paths are allowed, symlink targets must be regular files, and
an empty list means no trust anchors. Any invalid, oversized, or malformed
source rejects the adapter atomically. `insecure` is the only verification
bypass and MUST be explicit.
`https` implies enabled TLS. A Clash HTTP node with `tls: true` normalizes to
HTTPS CONNECT. `serverName` overrides certificate/SNI identity independently
of the connection address. Native HTTPS CONNECT permits HTTP/1.1 ALPN.
Certificate values are inline PEM; client private keys are resolved only from
the opaque credential document field named by `clientKeyField`. TLS settings
with disabled TLS are invalid unless the object is entirely default-valued.
`certificateSha256` is the hexadecimal SHA-256 of a DER certificate; a leaf
match authenticates the leaf, and a matched intermediate anchors normal chain,
name and time validation. The pin remains mandatory when `insecure: true`.
Reality uses `publicKey` and `shortId`; a fingerprint requires an adapter
that implements the requested ClientHello profile. `insecure` is an explicit certificate-verification option,
never a fallback after validation failure.

Transport `type` is `tcp`, `ws`, `grpc`, `http`, `httpupgrade`, `quic`, `meek`,
or `xhttp`; accepting the type in the model does not imply native support. Plain
TCP cannot carry HTTP transport parameters. The `http` transport supports a
path, at most one Host and validated headers for VLESS, VMess and Trojan. It
uses HTTP/1.1 PUT without TLS and HTTP/2 PUT with TLS and `h2` ALPN; the peer
response must have status 200. The default path is `/`; without a configured
Host, plaintext uses the endpoint host and TLS uses `www.example.com`.
Conflicting Host values, multiple hosts, service-name or early-data options,
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

##### ClientHello profile names

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

##### Private data and foreign input boundaries

Native adapter credential fields remain protocol-specific and retain their
existing private JSON format, permitted-field registry, and validation.
`clientKeyField` adds its referenced private field to that permitted set.
Sensitive headers, private keys, passwords, UUIDs, and complete imported
documents remain private credential data, never administrator labels or public
node diagnostics. Extra credential keys MUST NOT be silently discarded, and
conflicting credential aliases remain invalid.

Foreign document syntax MUST remain unchanged. For example, supported Clash
`client-fingerprint` and sing-box `tls.utls.fingerprint` normalize to native
`tls.clientHelloFingerprint`; Clash certificate `fingerprint` continues to
normalize to the distinct `tls.certificateSha256`. Supported foreign transport
Host, early-data and UDP-over-TCP fields MUST retain their existing defaults,
conflict checks, and wire semantics when normalized. HTTP header keys,
protocol identifiers, private credential keys and complete foreign documents
MUST NOT be renamed by native-field validation.

Representable sing-box proxy nodes continue to normalize to native options
and credentials. A node with unrepresentable fields retains its complete
private `sing_box_outbound` document and remains unavailable with a diagnostic;
selector, URL-test, direct and block entries are not imported as proxy nodes.
Imported documents MUST NOT become an implicit process launch or direct
fallback. The SS adapter retains its native simple-obfs and v2ray-plugin
WebSocket support; unsupported plugins and unconsumed options remain
unavailable. PathChord does not execute plugin processes.

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

#### Detailed contract

##### Canonical normalized-option cache schema

Normalized-node caches written for this schema MUST use cache envelope version
`3` and encode native options with the canonical field names above. Cache
versioning is independent of the unchanged `pathchord.io/v1` resource API and
the unchanged private credential JSON format. A previous normalized-option
cache version, retired option field, or unsupported normalized schema MUST
produce `cache_incompatible`, without publishing any portion of that cache.
The diagnostic MUST be bounded and sanitized; raw cached content, credential
values, and secret-bearing URLs MUST NOT be returned.

A loader MUST NOT keep an incompatible cache usable by installing public
native aliases, silently discarding option fields, substituting defaults,
partially decoding nodes, or guessing credential contents. It MUST preserve
only an independently valid active snapshot whose source identity and current
subscription lifecycle remain valid. Cold startup with no such snapshot and
no successful refresh leaves the affected subscription unavailable.

Bounded refresh MUST use the current configured source type, URL, credential
reference and effective User-Agent. It MUST preserve authenticated fetch
behavior, source-bound cache checks, credential-origin boundaries, the
existing aggregate byte/provider/depth budgets, and bounded retry/backoff.
Fresh content MUST pass normal normalization, validation and adapter
preparation before nodes become selectable. Malformed or unavailable nodes
retain sanitized diagnostics and MUST NOT cause valid siblings to be dropped.

Cache invalidation and refresh MUST preserve disable, deletion, source
replacement, revocation and persisted tombstone decisions. Neither retained
active nodes nor an in-flight refresh may bypass those decisions. An old
cache without a verifiable source identity MUST NOT publish, and an
incompatible-cache diagnostic MUST NOT clear independently valid private
credential storage or authorization state.
