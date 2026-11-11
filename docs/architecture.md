# PathChord Architecture

## 1. Scope

PathChord supports Linux and Windows. Linux supports TPROXY, REDIRECT, and HTTP/SOCKS listeners. Windows supports TUN and system-proxy integration. Both platforms share the policy, node, Noise, Session, and multipath cores.

The system supports TCP, UDP, and independent DNS in the first scope. Fake-IP, general ICMP forwarding, multicast proxying, and arbitrary IP tunneling are out of scope for the first protocol baseline.

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

The Egress is selected first. Transit Proxies are then admitted and scheduled for that Egress. A flow never spans multiple Egress nodes.

## 3. Routing modes

- `egress: <id-or-selector>`: Ingress reaches the selected Egress through one or more Transit Paths. Multipath aggregation is the default.
- `egress: none`: Ingress selects one Transit Proxy and that proxy connects to the target. This is the ordinary-proxy fallback mode.
- `proxy: direct`: direct is a Transit Proxy transport that connects without a third-party relay.
- Global fallback must be explicitly configured as `reject` or `direct`.

## 4. Rule phases

### Egress phase

Rules are ordered. For a new flow, the first rule whose conditions match and whose Egress is currently usable wins. Usability is a continuously maintained runtime state, not a probe performed during rule matching.

If no Egress rule is effective, evaluate ordinary Proxy rules. If no ordinary Proxy rule matches, execute the global fallback.

### Transit phase

After an Egress is selected, evaluate the Egress-specific Transit Proxy rules in order. The first matching rule determines admission and base weight. A rule matching multiple usable Proxies may select any one for ordinary proxy mode; node order is not meaningful.

For Egress mode, the admitted Proxy-to-Egress relationships form the multipath candidate set. Weights apply to the relationship as a whole; multiple Paths through one Proxy do not multiply its configured weight.

## 5. Runtime state

`connected` means that at least one authenticated, bidirectional Ingress-to-Egress Path exists through a Transit Proxy. If no Path exists, `connected` is false. Egress service state can additionally be `up`, `degraded`, `draining`, or `down`.

- `up`: connected and meets current admission requirements.
- `degraded`: connected, but capacity, path count, or capability requirements are not met.
- `draining`: no new flows; existing flows drain.
- `down`: no bidirectional Path or explicit administrative shutdown.

Egress status is reported over existing Paths. Ingress maintains per-Ingress-to-Egress state; Egress resource metrics may be global and may include per-Ingress quotas or admission limits.

## 6. Failure semantics

- Transit Path failure: remove that Path; existing Streams may continue over other compliant Paths.
- No compliant Path for one flow: terminate that flow; other flows in the shared Session continue.
- Egress failure: both sides close all related Paths, Sessions, Streams, local connections, and Egress-to-target connections. The application must retry.
- Either Ingress or Egress process restart invalidates related connections and Sessions.
- Target FIN/RST is reflected to the local application; the proxy layer does not silently recreate the target TCP connection.

## 7. Sessions and Paths

One Ingress and one selected Egress share a Session. Multiple Streams and UDP sessions may use it. Ingress creates, expands, drains, and closes bidirectional long-lived Paths. Egress reuses those Paths for return traffic.

Control messages have an independent sending budget. Business traffic is fairly scheduled, with optional priority and shares. Stream data can only use Paths admitted for that stream; Session control can use any non-revoked Path.

## 8. Dynamic scheduling

Egress reports load, connection utilization, bandwidth utilization, active sessions, active Streams, active target connections, capacity, and a recommended Path count. Ingress measures per-Path RTT, jitter, loss, reordering, throughput, and connection establishment quality.

Autoscaling adds Paths when effective aggregate capacity is insufficient and removes Paths cautiously after sustained surplus. Quality degradation reduces allocation quickly; recovery and scale-in are stabilized. A poor Path may be compensated by adding other Paths, but is excluded when its additional capacity is lower than its overhead.

Subscription quota and traffic multiplier are optional reference metadata. They may produce tags or affect weight; they are not hard limits and do not directly change Egress connectivity.

## 9. Metadata

Nodes have separated namespaces:

- `node`: static and subscription-derived labels/tags.
- `observed`: runtime path quality and health labels.
- `quota`: optional subscription quota reference.
- `admin`: administrative state.

Local overrides take precedence over subscription annotations. Hard states such as administrative disable, authorization revocation, and disconnection cannot be overridden by preference tags.

## 10. Entry points and DNS

Multiple HTTP/SOCKS listeners have unique IDs and participate in policy evaluation. Listener authentication and source-network restrictions are independent of Ingress-to-Egress Noise authentication.

Transparent entry does not perform domain routing. HTTP/SOCKS requests may route by domain because they carry the domain explicitly. DNS is independent and selects where a query is resolved: local, through a Transit Proxy, through the selected Egress, or blocked. No Fake-IP mapping is used.

## 11. Configuration lifecycle

Egress topology, Egress public keys, and Ingress local private keys are static and require Ingress restart when changed. Transit Proxy lists are runtime data, refreshed from subscriptions into a disk cache and hot-reloaded. Failed refreshes keep the current list; deleted subscription Proxies drain.

Rules are compiled at startup. The runtime maintains separate policy, Egress, Proxy, authentication, and metrics snapshots. Ingress internal traffic bypasses its own transparent interception to prevent loops.
