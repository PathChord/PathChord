# PathChord architecture

**English** | [简体中文](architecture.zh-CN.md)

## 1. Scope

PathChord supports Linux, Windows, and FreeBSD. All three platforms MUST support ordinary HTTP forwarding, HTTP CONNECT, SOCKS4/4a/5 CONNECT, and SOCKS5 UDP ASSOCIATE listeners. Linux supports TPROXY and REDIRECT and MAY support TUN; Windows supports TUN and system-proxy integration through a control-plane listener selection. FreeBSD MUST NOT expose TPROXY, REDIRECT, or TUN listeners in the v1 platform contract. All three platforms share the policy, node, Noise, Session, and multipath cores.

The system supports TCP, UDP, and independent DNS. Fake-IP, general ICMP forwarding, multicast proxying, and arbitrary IP tunneling are outside the protocol scope.

## 2. Topology

```text
local applications / LAN devices
              |
           Ingress
              |
   +----------+----------+
   |          |          |
Transit A  Transit B  Transit C
   |          |          |
   +----------+----------+
              |
           Egress
              |
           Target
```

The Egress is selected first. Its Ingress-side Transit binding then supplies one
common candidate set and one Session Path pool. A flow never spans multiple
Egress nodes, and routing rules do not select a Transit or Path subset.

## 3. Routing modes

- `egress: <id-or-selector>`: Ingress reaches the selected Egress through one or more Transit Paths. Multipath aggregation is the default.
- `mode: none`: Ingress selects one Transit Proxy and that proxy connects to the target. This is the ordinary-proxy fallback mode.
- `proxy: direct`: direct is a Transit Proxy transport that connects without a third-party relay.
- Global fallback must be explicitly configured as `reject` or `direct`.

## 4. Rule phases

### Egress phase

Rules are ordered. For a new flow, the first rule whose conditions match and whose Egress is currently usable wins. Usability is a continuously maintained runtime state, not a probe performed during rule matching.

If no Egress rule is effective, evaluate ordinary Proxy rules. If no ordinary Proxy rule matches, execute the global fallback.

### Egress Path phase

After an Egress is selected, its `transit` binding filters same-namespace
Transit Proxies by the configured common selectors and runtime state. The
binding and its `trafficPolicyRef` are independent of flow matches. Admitted
Proxy-to-Egress relationships form the multipath candidate set. Weights apply
to the relationship as a whole; multiple Paths through one Proxy do not
multiply its configured weight.

## 5. Runtime state

`connected` means that the current Ingress-to-Egress Session has at least one
authenticated, bidirectional ready Path through a Transit Proxy. It is a
Session relationship fact, not a global Egress health fact. Egress service state
can additionally be `up`, `degraded`, `draining`, or `down`, and a separate
`admission_allowed` value states whether new target connections are accepted.

- `up`: connected and meeting the current global resource and admission requirements.
- `degraded`: connected, but capacity, Path, quality, or resource requirements are below the ideal state; admission may remain allowed or may be denied.
- `draining`: administrative or lifecycle drain; new flows are denied and existing flows drain.
- `down`: no ready Path, authorization failure, or explicit administrative shutdown; related Sessions and business resources close.

Egress reports aggregate resource facts over existing Paths: configured and
effective wire capacity, current wire rate, active target connections, capacity
confidence, service state, and global admission state. It does not report or
evaluate Ingress rules. Ingress owns per-Path directional observations and
per-Session aggregate demand. Cross-Ingress fairness is not guaranteed.

The authored Egress resource has only global resource ceilings: the configured
wire bandwidth cap (`maxWireBandwidthBps`) and maximum inbound target
connections (`maxInboundTargetConnections`). Path safety ceilings, pending
reservations, measured capacity, and admission reason are runtime-owned facts;
desired Path counts and per-Ingress quotas are not configuration inputs.

## 6. Failure semantics

- Transit Path failure: remove that Path; existing Streams may continue over other compliant Paths.
- Egress Session below its common usable-Path minimum: deny new business admission while ready Paths remain; existing flows continue.
- Egress failure: both sides close all related Paths, Sessions, Streams, local connections, and Egress-to-target connections. The application must retry.
- Either Ingress or Egress process restart invalidates related connections and Sessions.
- Target FIN/RST is reflected to the local application; the proxy layer does not silently recreate the target TCP connection.

## 7. Sessions and Paths

One Session exists for each active Ingress-to-Egress relationship and has a
strict one-to-one relationship with that Egress. A Session owns its own Path
set, flow control, demand windows, replication accounting, and lifecycle. A
Session reconnect always creates a new SessionID and resets its runtime state.

Each live Session contains at least one `PATH_READY` bidirectional, long-lived
Path. The Session manager may retain a reconnecting record with zero Paths, but
that record cannot carry business traffic. A Transit relationship is separate
from its Path instances, so one Transit Proxy may carry multiple independent
Paths. Relationship weight is applied once before those Path instances share
the relationship allocation.

Ingress creates, expands, drains, and closes Paths. Streams and UDP
Associations are independent of Path identity and may migrate within the
common Egress Session pool. The Egress `statusRequirements.minUsablePaths` is
the single configured common minimum; only non-draining ready Paths count for
new admission. A Session below that minimum is degraded while existing work
continues; losing the last ready Path closes the Session.

Session control and optional extra replication use the negotiated Session hard
cap. Each sender shares one outbound allowance across all flows and Paths; the
two directions are bounded independently. The first copy and ordinary reliable
retransmissions remain available when optional replication is exhausted. Egress applies global resource limits
and strict priority for primary traffic, ordinary retransmission, and required
control; it does not interpret Ingress rules or promise cross-Ingress fairness.
An authenticated future ACK is a Session trust failure: every Path and business
resource is closed, the SessionID is retired, and recovery uses a fresh SessionID
with bounded backoff and circuit breaking.

## 8. Dynamic scheduling

Egress reports global resource facts: configured wire hard capacity, measured
effective capacity, current wire rate, capacity state (`unknown`, `provisional`,
`measured`, or `stale`), active target connections, `admission_allowed`, and a
stable admission reason. `recommendedPathCount` is not an Egress contract.

Ingress measures each Path independently in the upstream and downstream
directions using bounded counters, ACKs, heartbeat timing, data rate, loss,
retransmission, RTT, jitter, and congestion feedback. It aggregates demand once
per Session without retaining unbounded per-Stream or per-rule history. Health
sampling and demand windows are low-frequency; the data path only performs
bounded counter updates.

For each Egress Session, Ingress computes one Path target from the common
minimum, eligible Transit relationships, aggregate directional demand, Path
quality, and the Egress hard safety ceiling. The physical Path target covers
the larger upstream/downstream requirement. Scale-out and scale-in use
hysteresis, count only usable non-draining Paths after all selected drains,
and exclude candidates whose incremental capacity is below scheduling overhead.

Egress's effective capacity is a global scheduler/resource estimate. It is
bounded by the configured wire cap and is derived passively from aggregate
wire rate, queues, retransmission, and resource feedback; idle throughput does
not fabricate a measured capacity. Egress does not perform rule-level demand
calculation or cross-Ingress fairness.

TLS-capable Transit adapters load system roots by default. An ordered
`truststore` source list may add local PEM/DER files; invalid, oversized, or
non-regular sources fail adapter preparation atomically. Local control bounds
prefix read, payload read, dispatch, and response write independently.

Subscription quota and traffic multiplier are optional reference metadata. They may produce tags or affect weight; they are not hard limits and do not directly change Egress connectivity.

Subscription document normalization is independent of node transport support.
Adapters preserve typed connection semantics and reject unsupported parameters
before admission; an HTTP node that requests TLS cannot become a plaintext
connection. Unsupported protocol inputs remain unavailable until a native
PathChord adapter is implemented and do not own PathChord authorization or Noise state. The
[Transit Proxy contract](../../openspec/specs/transit-proxies/spec.md) defines supported document
families, private engine ownership, provider expansion, and accounting facts.

## 9. Metadata

Nodes have separated namespaces:

- `node`: static and subscription-derived labels/tags.
- `source`: imported subscription identity and source metadata.
- `observed`: runtime path quality and health labels.
- `quota`: optional subscription quota reference.
- `billing`: optional traffic-multiplier reference metadata.
- `admin`: administrative state.

Local overrides take precedence over subscription annotations. Hard states such as administrative disable, authorization revocation, and disconnection cannot be overridden by preference tags.

## 10. Entry points and DNS

Multiple HTTP/SOCKS listeners have unique IDs and participate in policy evaluation. A `mixed` listener shares one TCP endpoint between HTTP and SOCKS and retains one identity across both protocol branches. Listener authentication and source-network restrictions are independent of Ingress-to-Egress Noise authentication.

Ordinary HTTP requests are routed independently, including requests to different targets on one persistent client connection. Proxy credentials remain local, and framing-aware forwarding preserves message boundaries and streaming backpressure. HTTP CONNECT and SOCKS connections become byte streams only after target admission succeeds. The [platform and DNS specification](../../openspec/specs/platform-and-dns/spec.md#http-and-socks-listeners) owns request, authentication, upgrade, and SOCKS compatibility details.

Windows system-proxy integration is a control-plane switch that selects one HTTP/SOCKS or mixed listener by ID. A selected mixed listener uses HTTP proxy settings for its shared endpoint. Linux and FreeBSD do not expose a system-proxy activation mode; their listeners and unsupported system-proxy status remain inspectable through the control plane. Local control uses Unix sockets on Linux and FreeBSD and a Named Pipe on Windows.

Transparent entry does not perform domain routing. HTTP/SOCKS requests may route by domain because they carry the domain explicitly. DNS is independent and selects where a query is resolved: local, through a Transit Proxy, through the selected Egress, or blocked. No Fake-IP mapping is used.

## 11. Configuration lifecycle

A single file or directory bundle defines one resource graph. Ingress chooses
an explicit command-line source before environment configuration and account
defaults. Directory files are loaded deterministically, validated together,
and published as one snapshot; failed candidates retain the prior graph.

Egress topology, Egress public keys, Transit bindings, common Path requirements,
resolved TrafficPolicies, and Ingress local private keys are static and require
Ingress restart when changed. Transit Proxy lists are runtime data, refreshed
from subscriptions into a disk cache and hot-reloaded. Failed refreshes keep the
current list; deleted subscription Proxies drain. Egress capacity and global
connection limits are resource ceilings; desired Path counts remain Ingress
runtime decisions.

Static rule configuration is compiled at startup. Subscription-derived data and
approved dynamic rule snapshots may be compiled off-thread and hot-reloaded
atomically. The runtime maintains separate policy, Egress, Proxy,
authentication, and metrics snapshots. Ingress internal traffic bypasses its own
transparent interception to prevent loops.

Ingress administrator metadata and subscription operations are control-plane
mutations. They publish new generations atomically, use expected-generation
checks for concurrent edits, and retain the last successful subscription
snapshot after a failed refresh. Web/API adapters call the owning typed service
and never edit configuration files or caches directly.

## 12. Service artifacts

PathChord publishes three executables in one versioned release bundle:
`pathchord-ingressd` owns local listeners, Transit Proxy adapters,
subscriptions, DNS, policy, and transparent/TUN platform integration;
`pathchord-egressd` owns authenticated Path admission, target TCP/UDP
forwarding, authorization, and global resource limits; `pathchordctl` is the
role-neutral local management client. The service binaries run as separate
processes and use separate control sockets, identities, credentials, and state
roots. The management client never starts a service.

Ingress reads its complete policy resource graph from the Ingress source root.
Egress reads exactly one `EgressService` from its Egress source root and does
not load listener, Transit Proxy, subscription, routing, DNS, fallback, or
geodata resources. Egress has no TUN, TPROXY, eBPF, or system-proxy runtime
dependency and is packaged without network-administration capabilities. A
change to Egress startup fields is reported as restart required while the
active runtime keeps its original configuration.
