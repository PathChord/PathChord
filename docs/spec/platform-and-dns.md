# PathChord platform and DNS specification

**English** | [简体中文](platform-and-dns.zh-CN.md)

This document defines the platform-specific `Listener` and `DNSPolicy` object
contracts referenced by the [configuration schema](configuration-schema.md).
Each object uses `apiVersion: pathchord.io/v1`, `kind`, `metadata.name`, and
`spec`; runtime health is a read-only `status` field.
Platform adapters expose the same policy context and failure classes on Linux,
Windows, and FreeBSD; they do not change the PathChord Session or wire protocol.

## Platform matrix

| Listener type | Linux | Windows | FreeBSD | Address semantics |
|---|---|---|---|---|
| `http` | MUST | MUST | MUST | explicit HTTP host or address |
| `socks5` | MUST | MUST | MUST | explicit SOCKS4/4a/5 host or address |
| `mixed` | MUST | MUST | MUST | HTTP and SOCKS on one TCP listener |
| `tproxy` | MUST | MUST NOT | MUST NOT | transparent TCP/UDP IP flow |
| `redirect` | MUST | MUST NOT | MUST NOT | transparent TCP flow |
| `tun` | MAY | MUST | MUST NOT | IP packets through a TUN adapter |

An unsupported type/platform combination is a configuration error. A platform
adapter MUST report an unavailable listener as a typed local failure and MUST
NOT silently replace it with another listener type.
The HTTP/SOCKS requirements include ordinary HTTP forwarding, HTTP CONNECT,
SOCKS4/4a/5 CONNECT, and SOCKS5 UDP ASSOCIATE on all three platforms. FreeBSD v1
supports the explicit `http`, `socks5`, and `mixed` listener types. `socks` is an
input alias for `socks5`; normalized configuration and serialization use
`socks5`. This name does not restrict the accepted SOCKS protocol version.

## Common listener schema

Every listener has this shape:

```yaml
apiVersion: pathchord.io/v1
kind: Listener
metadata:
  name: lan-socks
spec:
  type: socks5
  platform: linux
  bind: 0.0.0.0:1080
  allowedSources: [192.168.1.0/24]
  flowTags: [interactive]
  processMetadata:
    executable: true
    user: true
    group: true
  authentication:
    mode: required
    credentialsRef: lan-socks-users
```

`metadata.name` is the unique configuration identity. `spec.type` is one of the matrix values and
`spec.platform` is `linux`, `windows`, `freebsd`, or `any` (default `any`). An
explicit platform MUST match the actual host. `any` selects the actual host's
matrix column; it MUST NOT bypass type/platform validation. `spec.bind` is a socket
address and is required for `http`, `socks5`, `mixed`, `tproxy`, and `redirect`; it is
forbidden for `tun`. System-proxy integration is controlled at runtime by the
Windows-only control-plane switch and does not add a Listener type. `spec.allowedSources` is a list of at most
256 CIDRs and defaults to the local host only for a loopback bind, or to an
empty list meaning “all source addresses” for an explicitly non-loopback
listener. Administrators SHOULD use an explicit list for non-loopback binds.

`spec.flowTags` is an optional set of at most 256 bounded identifiers. The
static tags are copied into every TCP or UDP flow accepted by the listener and
are available to `FlowMatch.flowTags`; they are not inferred from protocol
headers or mutable at flow time. Each tag uses the same identifier grammar as
other configuration tags. `spec.processMetadata` is an optional object with
boolean `executable`, `user`, and `group` fields; an empty object is invalid.
The selected platform provider may return only the requested facts. Missing,
permission-denied, or unsupported process data is unknown and never implicitly
matches a process rule. Process discovery is bounded, read-only, and never
executes a shell command. FreeBSD listeners use the same unknown-value semantics
when native process discovery is unavailable.

The following is a `spec.authentication` fragment; it is not a standalone
resource object. `spec.authentication` is either the scalar `disabled` or a mapping:

```yaml
authentication:
  mode: required # disabled | required
  credentialsRef: listener-users
```

`credentialsRef` is required when `mode: required`, is resolved only through
the local secret store, and is never sent over a data Path or returned by the
control API. Listener authentication is independent of Ingress-to-Egress Noise
authentication. Authentication failure is `LOCAL_POLICY` and MUST close or
reject only the affected local connection.

The optional `processMetadata` block requests executable, user, or process
group metadata for policy evaluation. Missing metadata is represented as
unknown; it MUST NOT be fabricated from a log line or cause an implicit allow.

## HTTP and SOCKS listeners

HTTP and SOCKS listeners terminate the local proxy protocol and pass the
explicit hostname, address candidates, and port to policy evaluation. They may
route by hostname because the request carries it. A failed protocol handshake,
malformed request head or target, unsupported command, or failed listener
authentication returns the adapter's normal local error and MUST NOT create a
Session or target connection for the rejected request. Invalid body framing
may be discovered after a target flow has opened; it MUST fail the affected
flow and close the affected connection without requiring the complete body to
be buffered before opening. The source identity is the accepted socket peer;
`X-Forwarded-For` and other client-authored forwarding headers MUST NOT replace
it.

HTTP forwarding, HTTP CONNECT, and SOCKS4/4a/5 CONNECT use the TCP Stream
contract. SOCKS5 UDP ASSOCIATE uses the UDP Association contract and preserves
datagram boundaries. The listener MUST preserve the original hostname even
when it also resolves local candidates. It MUST NOT resolve a name merely to
bypass a configured DNS route.

### HTTP request routing and framing

An HTTP listener accepts HTTP/1.0 and HTTP/1.1 requests. CONNECT uses an
authority target with an explicit non-zero port. Ordinary forwarding requires
an absolute-form `http://` URI with a valid hostname or IP literal; an omitted
port means 80. The target MUST NOT contain user information or a fragment.
Origin-form targets and absolute-form `https://` URIs are rejected; HTTPS uses
CONNECT. The adapter MUST derive the policy target and forwarded `Host` from
the same URI authority, convert the target to origin-form while preserving the
path and query, and pass each ordinary request through the TCP flow opener and
policy evaluation independently. A persistent client connection MUST NOT bind
later requests to the first request's target, Session, or Egress.

Each request header block, including its request line, is limited to 16 KiB.
Ordinary requests accept at most 128 header fields. Invalid framing,
conflicting `Content-Length` values, malformed targets, and exceeded
header limits are rejected. Ordinary requests carrying both `Content-Length` and valid
`Transfer-Encoding` use the transfer coding; the adapter MUST remove
`Content-Length` and MUST NOT forward both fields unchanged. It MUST close the
client connection after that response and MUST NOT accept another pipelined
request from that connection. A maintained HTTP
message codec parses and re-encodes request and response framing, including
chunked bodies, instead of treating the remainder of a client connection as
one unbounded request. Bodies are streamed with backpressure; uploads and
responses MUST NOT require buffering the complete body. Early upstream
responses MUST NOT deadlock an unfinished upload or turn unread request bytes
into a subsequent request.

HTTP/1.1 connections support sequential requests unless connection tokens or
message framing require closure. HTTP/1.0 requests close after the response.
`Proxy-Connection` tokens are recognized for client compatibility; token names
are case-insensitive, and `close` prevents reuse. Each response completes its
message body before another request is dispatched. Redirect responses are
returned to the client unchanged in meaning; the proxy MUST NOT follow them.

### HTTP authentication and header handling

An HTTP listener with required authentication accepts exactly one
`Proxy-Authorization: Basic` header per request, including each request on a
persistent connection. The decoded value is a non-empty `username:password`
pair and is checked by the listener-local verifier resolved from
`credentialsRef`; success publishes the verified username as that request's
authentication identity. A missing, duplicate, malformed, or rejected
credential returns `407 Proxy Authentication Required` with a Basic
`Proxy-Authenticate` challenge and closes the affected connection.

Forwarded ordinary request headers and response headers MUST remove
proxy credentials and hop-by-hop fields, including `Proxy-Authorization`,
`Proxy-Authenticate`, `Proxy-Connection`, `Connection`, fields named by
`Connection` tokens, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, and
`Upgrade`. Message framing headers required on the next hop are generated by
the HTTP codec. The original `Trailer` declaration MUST be replaced with a
declaration containing only allowed trailer field names, or removed if that
set is empty. Both trailer declarations and trailer frames MUST discard proxy
credentials, authentication, framing, hop-by-hop, and `Connection`-nominated
fields. Safe end-to-end trailers such as `Digest` and `X-Checksum` MUST be
preserved. Within ordinary header blocks, end-to-end fields such as an origin
server's `Authorization` are preserved unless explicitly named as hop-by-hop
fields. Neither adapter logs, inventories, or returns credential values.

Upgrade requests retain only the fields required for the validated upgrade
handshake, after removing proxy credentials and other hop-by-hop fields. The
adapter forwards the real upstream response. A client MAY offer a list of
upgrade protocols; an upstream `101` selecting one offered protocol is valid.
The adapter switches to a bidirectional byte tunnel only after a valid upstream
`101 Switching Protocols`, preserving
already-buffered bytes in both directions. A rejected upgrade remains an HTTP
response. CONNECT similarly returns success only after the selected TCP flow
has opened; target or policy failure MUST NOT produce a success response.

Malformed requests return `400 Bad Request`; exceeded header limits MAY return
`400 Bad Request` or `431 Request Header Fields Too Large`. Policy denial returns
`403 Forbidden`; authentication failure returns `407 Proxy Authentication Required`;
target/transport failure returns `502 Bad Gateway`; and unavailable routes,
Sessions, or resource budgets return `503 Service Unavailable`. The adapter
MUST NOT emit a second response after response headers have already been sent;
a subsequent framing or transport failure closes the affected connection.

### SOCKS versions and authentication

The canonical `socks5` listener accepts SOCKS4, SOCKS4a, and SOCKS5 on its
configured TCP socket. SOCKS4/4a support CONNECT only. SOCKS4 addresses are IPv4;
`0.0.0.X` with non-zero `X` selects SOCKS4a and requires a following domain.
The user ID and domain are NUL-terminated and each is limited to 255 bytes. An
empty domain or zero target port is invalid. An unverified user ID MUST NOT
become an authenticated identity. SOCKS4/4a carry no password and MUST be
rejected with reply code 91 when listener authentication is required; they
MUST NOT downgrade or bypass the configured verifier. Success uses reply code
90 only after the selected target flow opens. BIND and other unsupported
commands use reply code 91.

SOCKS5 supports CONNECT and UDP ASSOCIATE with IPv4, IPv6, or domain targets.
A listener with required authentication selects the username/password method
and rejects negotiation unless the same listener-local verifier accepts both
fields. A client with no acceptable method receives `0xff`; BIND and other
unsupported commands receive reply code `0x07`. SOCKS5 authentication failure
closes the connection and MUST NOT open a target flow.

### SOCKS5 UDP lifecycle

The SOCKS5 UDP relay accepts datagrams only from the peer IP address of the TCP
control connection. A valid non-zero client port in the UDP ASSOCIATE request
pins the exact source endpoint immediately; otherwise the first accepted
datagram pins the source endpoint for the rest of the association. Datagrams
from any other endpoint are rejected. The RFC 1928 reserved field and `FRAG`
field MUST both be zero. A non-zero `FRAG` is rejected explicitly; PathChord
does not reassemble SOCKS5 UDP fragments.

The number of concurrent clients and per-client target associations, each
target queue, and association idle lifetime are bounded. Completion or failure
of a target UDP flow removes that target association so a later datagram may
open a new flow to the same target. Closing the TCP control connection cancels
its UDP associations. Shutdown cancels and joins the control and target tasks
within the configured shutdown timeout.

### Mixed listener dispatch

A `mixed` listener binds one TCP endpoint and detects the protocol separately
for each accepted connection. A first byte of `0x04` or `0x05` selects SOCKS;
other bytes enter the HTTP parser. Detection MUST NOT consume the byte or lose
already-buffered request or application data. The selected parser applies the
HTTP and SOCKS contracts above. Invalid input MUST NOT fall back to a direct
target connection. Waiting for a client's first byte or handshake MUST NOT
block admission of other clients, and cancellation MUST close pending clients.

The default `protocols` are `[tcp, udp]`. TCP is required; `[tcp]` disables
SOCKS5 UDP ASSOCIATE. HTTP and all SOCKS versions share the configured listener
ID, credentials, source restrictions, flow tags, and process metadata policy.
Required authentication uses HTTP Basic or SOCKS5 username/password according
to the detected protocol; SOCKS4/4a MUST remain rejected. The protocol choice
MUST NOT bypass authentication or create a different listener identity.
SOCKS5 UDP uses the relay endpoint negotiated by UDP ASSOCIATE; the TCP port
does not accept raw UDP datagrams or perform UDP protocol detection.

```yaml
apiVersion: pathchord.io/v1
kind: Listener
metadata:
  name: local-mixed
spec:
  type: mixed
  platform: any
  bind: 127.0.0.1:7890
  protocols: [tcp, udp]
  authentication: disabled
```

Windows system-proxy selection MAY reference a mixed listener. It applies
HTTP proxy settings for the shared endpoint; SOCKS clients can use the same
TCP address explicitly.

### Compatibility references

The reference behavior is grounded in the stable sing-box
[HTTP options](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/inbound/http.md)
and [SOCKS options](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/inbound/socks.md),
with its pinned sing
[HTTP handler](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/protocol/http/handshake.go)
and [SOCKS handler](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/protocol/socks/handshake.go).
The requirements above own PathChord's authentication, source identity,
framing, and failure behavior. The
[mixed inbound](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/inbound/mixed.md)
is a reference for shared-port HTTP/SOCKS admission. TLS termination is a
separate listener feature and does not alter this contract.

## Linux transparent listeners

### TPROXY

```yaml
apiVersion: pathchord.io/v1
kind: Listener
metadata:
  name: lan-tproxy
spec:
  type: tproxy
  platform: linux
  bind: 0.0.0.0:15001
  allowedSources: [192.168.1.0/24]
  mark: 0x1
  routeTable: 100
  protocols: [tcp, udp]
```

`spec.mark` is an unsigned 32-bit packet mark and `spec.routeTable` is an integer in
`1..=4294967295`; both are required for `tproxy`. The adapter preserves the
original destination address and port and uses the kernel's transparent socket
metadata. TCP and UDP are admitted independently according to `protocols`,
which defaults to `[tcp, udp]`.

When PathChord manages policy routing, it MUST use a dedicated rule priority,
route protocol, and table ownership tuple for both IPv4 and IPv6. Before adding
rules or routes it snapshots all four target slots and atomically writes a
recovery journal. Recovery deletes only objects that still exactly match the
journaled mark, table, priority, protocol, address family, local route, and
loopback device; a changed or pre-existing object is an ownership conflict and
MUST NOT be deleted.

### REDIRECT

```yaml
apiVersion: pathchord.io/v1
kind: Listener
metadata:
  name: lan-redirect
spec:
  type: redirect
  platform: linux
  bind: 0.0.0.0:15002
  allowedSources: [192.168.1.0/24]
  protocols: [tcp]
```

`redirect` supports TCP only and MUST obtain the original destination from the
platform socket metadata. If the original destination is unavailable, the
connection fails with `LOCAL_POLICY`; the adapter MUST NOT treat the listener
address as the target.

Transparent listeners do not perform domain routing. An IP-only flow is matched
using its address, port, protocol, and available process metadata. If a policy
requires a hostname that is not present, the condition does not match.

## Windows TUN and system-proxy switch

System proxy is a control-plane switch, not a Listener kind. Enabling it MUST
name an existing HTTP or SOCKS Listener by ID:

```text
POST /api/v1/system-proxy/enable
{"listener_id":"local-http"}
```

The control plane MUST reject enable and disable on Linux and FreeBSD with
`UNSUPPORTED_OPERATION`, and MUST reject a missing,
unknown, TUN, TPROXY, REDIRECT, or otherwise incompatible listener reference on
Windows. When disabled, no environment or operating-system proxy setting is
changed. Windows MUST apply the referenced
listener to the `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` environment
variables (and their lowercase aliases where supported) and to the Windows
operating-system proxy configuration. It MUST restore the exact previous
values on disable or shutdown.
Before changing any value, the adapter MUST atomically persist a restoration
journal containing the previous value's presence, registry type, and bytes.
Normal disable removes the journal only after every value is restored. Startup
MUST restore a leftover journal before accepting another system-proxy mutation,
so process termination between apply and disable does not make the proxy state
permanent.
After apply or restoration, the adapter MUST trigger the WinINet settings-change
and refresh notifications. A registry write without a successful notification
is reported as a typed platform failure and is rolled back.
The Windows local-control Named Pipe MUST reject remote clients. Its DACL MUST
grant full access only to the creating object owner, local Administrators, and
SYSTEM; it MUST NOT rely on the permissive default Named Pipe descriptor.
Linux and FreeBSD operators MUST use ordinary listener resources and control-plane
queries to inspect available listeners. Their `system_proxy.get` response MUST
report `enabled: false` and `platform_effect: unsupported`; both platforms
MUST NOT expose a system-proxy activation state. Local control uses a Unix
domain socket on Linux and FreeBSD.

```yaml
apiVersion: pathchord.io/v1
kind: Listener
metadata:
  name: windows-tun
spec:
  type: tun
  platform: windows
  interface: PathChord
  address: 198.18.0.1/30
  mtu: 1500
  protocols: [tcp, udp]
```

`tun.interface` is an adapter name, `tun.address` is an IPv4 or IPv6 prefix,
and `tun.mtu` is in `576..=65535` (default `1500`). A TUN listener accepts IP
packets and exposes TCP/UDP flows through the same policy context; unsupported
IP protocols are rejected because arbitrary IP tunneling is outside the
PathChord data-plane contract.

One reactor exclusively owns the userspace TCP/IP `Interface`, socket set, and
timers. TCP listeners are replenished after acceptance; each accepted stream is
connected to the ordinary TCP flow opener with bounded buffers and correct
FIN, half-close, reset, and idle-timeout behavior. UDP associations preserve
each datagram boundary and use the ordinary UDP flow opener. Packet queues,
socket buffers, flow counts, and association counts are bounded. Protected
destinations are rejected before socket creation, and shutdown closes flow
channels and joins every supervised task.

Failure to restore Windows proxy settings is reported as a typed platform health
error and MUST be visible in structured status. It MUST NOT be hidden in logs.

## Loop prevention and protected destinations

Every platform adapter MUST bypass its own transparent interception for:

- the Ingress Unix socket or Named Pipe and Web Gateway listener;
- configured Transit Proxy endpoints;
- configured Egress endpoints;
- configured DNS upstream endpoints;
- platform control traffic required to maintain those connections.

The bypass set is derived from the published static and dynamic snapshots and
is replaced atomically with them. A rule cannot route protected control traffic
back through the same Ingress. If an endpoint cannot be excluded without
creating a loop, the affected listener enters `degraded` and new flows fail
with `LOCAL_POLICY`; existing control connections are not silently re-routed.

## DNS configuration

DNS is a separate policy and does not create a Fake-IP mapping. The schema is:

```yaml
apiVersion: pathchord.io/v1
kind: DNSPolicy
metadata:
  name: default-dns
spec:
  defaultRoute: local # local | transit | egress | blocked
  local:
    servers: [192.168.1.1:53, "[2001:db8::53]:53"]
  transit:
    proxySelector: {tags: [dns]}
    servers: [1.1.1.1:53]
  egress:
    egressSelector: {labels: {region: jp}}
    servers: ["[2606:4700:4700::1111]:53"]
  blockedResponse: refused # nxdomain | refused | servfail
  timeoutSeconds: 5
  maxInflight: 1024
  cache:
    enabled: true
    maxEntries: 100000
    maxTtlSeconds: 86400
```

`defaultRoute` defaults to `local`. `local.servers` is required when the
route is `local`; each endpoint uses port 53 unless a port is supplied.
`transit.proxySelector` and `transit.servers` are required for `transit`, and
`egress.egressSelector` and `egress.servers` are required for `egress`. These
server endpoints remain the DNS targets while the selected route determines how
they are reached. `blockedResponse` defaults to `refused`.
`timeoutSeconds` is in `1..=60` and defaults to `5`; `maxInflight` is in
`1..=100000` and defaults to `1024`; cache `maxEntries` is in `0..=1000000`
and defaults to `100000`, while `maxTtlSeconds` is in `1..=604800` and
defaults to `86400`. Cache entries are advisory and never override a hard
blocked route.

The local adapter sends UDP first and MUST retry the same upstream over DNS
TCP when a valid response has `TC=1`; it MUST NOT change routes during that
retry. Positive cache lifetime is the minimum answer TTL. Negative `NXDOMAIN`
and empty `NOERROR` responses are cached only when an SOA is present, using the
minimum of the SOA record TTL and SOA MINIMUM. All cached lifetimes are capped
by `maxTtlSeconds`; zero-TTL and signed responses are not reused.

The four routes have these semantics:

| Route | Behavior |
|---|---|
| `local` | send the DNS query to configured local resolvers |
| `transit` | send the query through one admitted Transit Proxy; no Egress Session is created |
| `egress` | send the query through the selected Egress Session and its DNS policy |
| `blocked` | do not send a query; return `blockedResponse` |

Queries are matched by the DNS policy before any ordinary flow rule. A route
failure returns a typed DNS failure (`timeout`, `unavailable`, or `blocked`)
and MUST NOT silently fall through to another route. Schema version 1 has no
implicit DNS fallback; only the configured route is attempted.

Every UDP flow whose target port is 53 enters the DNS runtime before the
ordinary UDP flow opener, whether it originated from SOCKS5 UDP ASSOCIATE,
TPROXY, or TUN. A blocked policy response is returned exactly as configured.
After a syntactically valid query has been accepted, resolver timeout,
unavailability, capacity, or protocol failure produces a DNS `SERVFAIL`
response that preserves the request identifier. A malformed DNS query fails
the affected UDP flow with a typed protocol error. A port-53 flow MUST NOT be
delegated to the ordinary UDP opener after any DNS outcome; non-port-53 flows
continue through that opener normally.

## Hostnames and address candidates

For HTTP/SOCKS requests and `STREAM_OPEN`/`UDP_OPEN`, the original hostname is
retained when supplied. Resolved address candidates are optional and are tried
according to the selected Egress DNS policy; candidates do not override a
policy that requires remote resolution. A request with neither a hostname nor
an address candidate is invalid. A port of zero is invalid.

DNS responses never synthesize Fake-IP addresses. A caller that requires a
literal IP must supply it explicitly or receive a typed resolution failure.
IPv4 and IPv6 selection is capability-aware: an address family not supported by
the selected listener, Transit Proxy, or Egress is skipped, and exhaustion of
all candidates returns `TARGET_FAILURE`.

## Reload and failure behavior

Listener bind/routing settings and the DNS route topology are startup fields;
changing them requires restart. Resolver health, cache contents, subscription
nodes, and runtime route availability are dynamic observations and may update
without replacing the static listener configuration.

A listener that loses its platform resource stops admitting new connections and
reports `degraded`; existing Sessions continue under their normal failure
rules. A DNS route or resolver that becomes unavailable does not change the
configured route. All limits are enforced before allocation, and resource
exhaustion returns a typed local/resource error rather than silently dropping
TCP bytes or creating an untracked flow.

