# PathChord platform and DNS specification

**English** | [简体中文](platform-and-dns.zh-CN.md)

This document defines the platform-specific `Listener` and `DNSPolicy` object
contracts referenced by the [configuration schema](configuration-schema.md).
Each object uses `apiVersion: pathchord.io/v1`, `kind`, `metadata.name`, and
`spec`; runtime health is a read-only `status` field.
Platform adapters expose the same policy context and failure classes on Linux
and Windows; they do not change the PathChord Session or wire protocol.

## Platform matrix

| Listener type | Linux | Windows | Address semantics |
|---|---|---|---|
| `http` | MUST | MUST | explicit HTTP host or address |
| `socks5` | MUST | MUST | explicit SOCKS5 host or address |
| `tproxy` | MUST | MUST NOT | transparent TCP/UDP IP flow |
| `redirect` | MUST | MUST NOT | transparent TCP flow |
| `tun` | MAY | MUST | IP packets through a TUN adapter |

An unsupported type/platform combination is a configuration error. A platform
adapter MUST report an unavailable listener as a typed local failure and MUST
not silently replace it with another listener type.

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
`spec.platform` is `linux`, `windows`, or `any` (default `any`). `spec.bind` is a socket
address and is required for `http`, `socks5`, `tproxy`, and `redirect`; it is
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
executes a shell command.

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
route by hostname because the request carries it. A malformed request,
unsupported command, or failed listener authentication returns the adapter's
normal local error and MUST NOT create a Session or target connection.

HTTP CONNECT and SOCKS5 CONNECT use the TCP Stream contract. SOCKS5 UDP
ASSOCIATE uses the UDP Association contract and preserves datagram boundaries.
The listener MUST preserve the original hostname even when it also resolves
local candidates. It MUST NOT resolve a name merely to bypass a configured
DNS route.

An HTTP listener with required authentication accepts exactly one
`Proxy-Authorization: Basic` header within the bounded CONNECT header block.
The decoded value is a non-empty `username:password` pair and is checked by the
listener-local verifier resolved from `credentialsRef`; success publishes the
username as the authentication identity. A missing, duplicate, malformed, or
rejected credential returns `407 Proxy Authentication Required` with a Basic
`Proxy-Authenticate` challenge and closes that connection. The complete HTTP
request header block is limited to 16 KiB, including the request line. A SOCKS5
listener with required authentication selects the username/password method and
rejects the negotiation unless the same listener-local verifier accepts both
fields. Neither adapter logs, inventories, or returns credential values.

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
open a new flow to the same target. Shutdown cancels and joins the control and
target tasks within the configured shutdown timeout.

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

The control plane MUST reject the operation on Linux, and MUST reject a missing,
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
Linux operators MUST use ordinary listener resources and control-plane queries
to inspect available listeners; Linux MUST NOT expose a system-proxy activation
state.

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

