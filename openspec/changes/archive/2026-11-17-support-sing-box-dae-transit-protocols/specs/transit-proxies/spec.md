# Transit Proxy compatibility delta

## ADDED Requirements

### Requirement: Native compatibility for existing proxy protocols

Transit SHALL support the connection parameters implemented by sing-box
1.14.4 and dae 2.1.2 for HTTP/HTTPS, SOCKS5, Shadowsocks, VMess, VLESS,
Trojan, Hysteria2, TUIC and AnyTLS, except combinations that require a
separately excluded protocol or endpoint. Each imported node SHALL retain its
authentication, transport, security and datagram semantics without
introducing an external proxy core.

#### Scenario: A supported provider node uses a native adapter

- **WHEN** a provider supplies a node with a supported protocol and parameter combination
- **THEN** Ingress can select the matching native adapter and establish the requested TCP or UDP flow without silently changing those parameters

#### Scenario: A combination cannot be represented safely

- **WHEN** a node contains a connection option that its selected native adapter cannot consume
- **THEN** the node remains unavailable with a redacted diagnostic and no downgraded route is used

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

### Requirement: VLESS Vision flow and datagrams

VLESS Vision SHALL preserve each direction's framing transitions over direct
TLS 1.3 or REALITY. Without multiplex it SHALL use XUDP for datagrams; with a
supported multiplex transport it SHALL use that transport's datagram framing.
Both registered Vision flow variants SHALL encode the base Vision flow on the
wire; the `-udp443` variant SHALL additionally allow UDP to port 443.

#### Scenario: Vision datagrams to port 443

- **WHEN** a Vision node opens UDP to port 443
- **THEN** the request succeeds only for `xtls-rprx-vision-udp443` and carries the base flow name on the wire

#### Scenario: Peer switches a Vision direction to direct copy

- **WHEN** a peer sends a valid Vision DIRECT transition after its framed content
- **THEN** the receiver delivers buffered plaintext and subsequent raw bytes in order without exposing the outer TLS record stream

### Requirement: Node probe revocation follows source visibility

When Ingress applies a subscription disable, deletion, or source replacement,
it SHALL cancel queued and in-flight probes for affected nodes and SHALL NOT
publish observations from a revoked admission. Unrelated node probes SHALL
continue independently.

#### Scenario: Subscription changes while a probe is queued

- **WHEN** Ingress disables, deletes, or replaces the source of a queued or in-flight node probe
- **THEN** that probe is cancelled, stale results are not published, and unrelated probes can continue

## MODIFIED Requirements

### Requirement: Bounded imports and source-bound caches

Subscription processing SHALL normalize only supported node definitions, preserve valid siblings alongside individual diagnostics, retain the previous successful snapshot for malformed documents, and enforce the detailed node and byte limits. Private caches SHALL retain options and diagnostics and SHALL be bound to source type, URL, credential reference and effective User-Agent; unverified caches SHALL NOT publish, and replaced-source nodes SHALL drain rather than accept new flows.

#### Scenario: One imported node is invalid

- **WHEN** a valid subscription document contains an invalid or unsupported node alongside valid nodes
- **THEN** valid siblings are retained and the invalid node remains unselectable with a stable sanitized diagnostic.

#### Scenario: Subscription source changes

- **WHEN** the subscription's source type, URL, credential reference or effective User-Agent changes
- **THEN** nodes belonging to the previous source enter draining and cannot be selected for new flows.

### Requirement: Subscription User-Agent identifies source content

Subscription HTTP requests SHALL use the configured per-source User-Agent,
or `clash.meta` when it is absent. Root and nested provider requests SHALL
carry the same value. Changing the effective User-Agent SHALL invalidate
source-bound caches and stale refresh candidates without weakening credential
origin or fetch-budget boundaries.

#### Scenario: A subscription changes its User-Agent

- **WHEN** a subscription's effective User-Agent changes
- **THEN** old-source nodes drain and cached or in-flight content obtained using the previous value cannot publish as the new source
