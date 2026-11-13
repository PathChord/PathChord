# PathChord state-machine specification

**English** | [简体中文](state-machines.zh-CN.md)

This document defines externally observable lifecycle states and the guards and
actions that make a transition valid. A manager MAY keep an internal record in a
connecting or closed phase, but it MUST NOT expose that record as a usable
Session, Path, Stream, or association.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in
this document are to be interpreted as described by [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174). They have normative
force only when written in uppercase.

## Shared rules

`PATH_READY` is the protocol admission point. A Path is **ready** only after
Noise authentication, identity/authorization checks, capability negotiation,
and limit negotiation have succeeded. `ACTIVE` and `DEGRADED` Path states are
ready states; `DRAINING` is still authenticated and MAY finish existing work,
but it is not eligible for new business work.

A protocol-live Session MUST contain at least one ready Path, including a
draining Path. A Session MAY admit a new Stream or UDP Association only when it
contains at least one `ACTIVE` or `DEGRADED` Path. A Session with only draining
Paths is a closing Session and MUST reject new business operations.

Every transition has one owner. The Ingress Session manager owns Session and
Path admission; the Egress owns target and authorization effects; the Stream or
association owner owns byte/datagram completion. A peer message can request a
transition, but the owner validates its guard before applying the action.

## Egress relationship and service state

The relationship state graph is:

```text
CONFIGURED → CONNECTING → CONNECTED
CONNECTING → DOWN
CONNECTED → DEGRADED
DEGRADED → CONNECTED
CONNECTED/DEGRADED → DRAINING
CONNECTED/DEGRADED/DRAINING → DOWN
DOWN → CONNECTING
```

`CONNECTED` means `connected=true`: at least one authenticated,
bidirectional, ready Path exists. The externally reported service state is
derived as follows:

| Service state | Guard |
|---|---|
| `up` | `connected=true`, not draining, and all current admission requirements are met |
| `degraded` | `connected=true`, not draining, but capacity, Path count, or capability requirements are not met |
| `draining` | administrative drain is active; new flows are rejected while existing work finishes |
| `down` | no ready Path or administrative shutdown/authorization failure is active |

`CONNECTED` and `DEGRADED` are relationship-manager states; `up` and
`degraded` are service-state values. `DOWN` always closes related Sessions,
Streams, UDP Associations, local connections, and Egress target connections.
The manager MAY retry `DOWN → CONNECTING` with bounded exponential backoff
when configuration and authorization permit it.

## Path

```text
DISCOVERED → PROBING → ACTIVE
PROBING → FAILED
ACTIVE ↔ DEGRADED
ACTIVE/DEGRADED → DRAINING → CLOSED
ACTIVE/DEGRADED → FAILED → CLOSED
PROBING/FAILED → CLOSED
```

`ACTIVE` means the Path has reached `PATH_READY` and is eligible for new
business traffic. `DEGRADED` remains ready but receives reduced allocation
because its quality or capacity is below policy. `DRAINING` stops new
admission, retains existing work until acknowledged or a drain deadline, and
then becomes `CLOSED`. A loss of authentication, a nonce/replay violation, or
an authorization disable/revoke is a `FAILED` transition and does not become a
target error by itself.

The Path owner MUST emit a change event for every state transition. A quality
sample MAY move `ACTIVE ↔ DEGRADED`; recovery allocation MUST be stabilized by
the scheduler. A drain deadline or transport failure closes the Path even when
outstanding work remains.

## Session

```text
CONFIGURED → CONNECTING → ACTIVE
ACTIVE ↔ DEGRADED
ACTIVE/DEGRADED → DRAINING
CONNECTING → CLOSED
CONFIGURED → CLOSED
ACTIVE/DEGRADED/DRAINING → CLOSED
```

`ACTIVE` requires at least one `ACTIVE` or `DEGRADED` Path and permits new
business operations. `DEGRADED` has at least one ready Path but fails a current
capacity, Path-count, or capability requirement. `DRAINING` rejects new
Streams and associations and waits for existing work; it MAY contain ready
draining Paths. Losing the last ready Path closes the protocol Session
permanently, closes all business resources, retires the SessionID, and permits
the manager to create a new `CONFIGURED` record with a new SessionID.

Endpoint restart, Egress hard failure, or authorization disable/revoke closes
the Session and all related target resources. Endpoint restart and
authorization failure MUST NOT automatically resume the old SessionID.
Heartbeat and control retransmission use any ready, non-revoked Path and are
deduplicated by the Session control sequence.

## TCP Stream

```text
NEW → OPENING → OPEN
NEW/OPENING → CLOSED
NEW/OPENING → RESET
OPEN → HALF_CLOSED_LOCAL
OPEN → HALF_CLOSED_REMOTE
HALF_CLOSED_LOCAL/HALF_CLOSED_REMOTE → CLOSED
HALF_CLOSED_LOCAL/HALF_CLOSED_REMOTE → RESET
OPEN → RESET
```

`OPENING` owns one idempotent RequestID and creates at most one target
connection. A successful target dial enters `OPEN`; a policy, Egress, or target
failure enters `RESET` or `CLOSED` with a normalized error. FIN is ordered
after preceding bytes and changes only its direction. RST discards pending
bytes and closes the target connection. A Stream remains bound to its Egress
and Session while its data MAY move between eligible Paths.

## UDP Association

```text
NEW → OPENING → OPEN
NEW/OPENING → CLOSED
NEW/OPENING → RESET
OPEN → DRAINING → CLOSED
OPEN → RESET
```

An `OPEN` association owns exactly one Egress-side socket context. Datagrams
preserve boundaries and are not reliably retransmitted by the aggregation
layer. `DRAINING` rejects new datagrams, allows already accepted datagrams to
expire or complete, and closes the socket at its deadline. Session close,
target failure, endpoint restart, and authorization disable/revoke close the
association and release the socket context.

## Subscription refresh

```text
DISABLED → ENABLED
ENABLED → REFRESHING
REFRESHING → ENABLED
REFRESHING → FAILED
FAILED → REFRESHING
ENABLED → DISABLED
ENABLED/DISABLED/FAILED → DELETED
```

`REFRESHING` evaluates the current subscription revision. Success atomically
publishes one dynamic generation and returns to `ENABLED`; failure retains the
last successful node snapshot, records a typed failure, and uses bounded
backoff before retry. `DISABLED` subscriptions do not refresh. Deletion
removes the source from future refreshes and drains nodes imported solely from
that source.

## Authorization record

```text
PENDING → ENABLED
PENDING → DISABLED
PENDING → REVOKED
ENABLED → DISABLED
ENABLED → REVOKED
DISABLED → ENABLED
DISABLED → REVOKED
```

`PENDING` is used only while a validated generation is being committed. An
`ENABLED` record permits new Paths. Both `DISABLED` and `REVOKED` immediately
reject new handshakes and terminate every matching live Path, Session, Stream,
UDP Association, and Egress-to-target connection. `REVOKED` is terminal for
the record identity; a new enrollment record is REQUIRED. `DISABLED` MAY be
returned to `ENABLED` through a new generation, which permits new Sessions but
does not resurrect an old SessionID.

## Windows system-proxy switch

The switch is owned by the control plane and is independent of Listener
lifecycle:

```text
DISABLED → APPLYING
APPLYING → APPLIED
APPLYING → FAILED
APPLIED → RESTORING → DISABLED
APPLIED → FAILED
FAILED → APPLYING
```

`APPLYING` MUST verify that the requested `listener_id` resolves to an HTTP, SOCKS, or Mixed Listener on Windows. Enabling the already-selected listener is idempotent
and MUST return the current applied state without rewriting saved values.
`APPLIED` MUST record the exact previous environment and operating-system proxy
values. Disable MUST restore those values; a restore failure enters `FAILED`,
retains the saved values, and MUST NOT report `DISABLED`. Linux and FreeBSD MUST reject
enable/disable as `UNSUPPORTED_OPERATION` and MUST NOT enter this state machine.
Their `system_proxy.get` response MUST report `enabled: false` and
`platform_effect: unsupported`.
Every transition emits `system_proxy.changed` with the listener ID, platform
effect, and error or restoration state.

## Scheduler and autoscaling guards

For each eligible Path, the scheduler computes:

```text
score(path) = relationship_weight
              × billing_multiplier
              × advertised_effective_capacity
              × quality_factor
```

`quality_factor` is bounded and derived from congestion window, RTT, jitter,
loss, and reordering. Its coefficients are configuration, but it MUST be
monotonic so worse quality cannot increase a Path score. A relationship's
weight is shared by all its Paths before Path scores distribute that share.
Control traffic is reserved first and charged to the Session replication
budget; business replication MUST NOT consume more than the remaining budget.

The autoscaler MUST use hysteresis: it MAY add a Path only after aggregate
capacity is below demand (or the Egress recommendation exceeds active count)
for a configured consecutive sample window; it MAY remove a Path only after
surplus persists for a separate non-zero window and another compliant Path
remains. Scale-in MUST enter `DRAINING` first. A Path MUST be excluded when
incremental capacity is below scheduling overhead, with the reason exposed in
observations. Opposite-direction counters MUST reset after a state change or
failed probe. Thresholds and windows MAY be configured, but these guards,
hysteresis, drain action, and budget accounting are normative.

## Transition effects and failure reasons

| Trigger | Required guard and action |
|---|---|
| Noise/attach success | identity, EgressID, capability, and limits match; create or join one Session and emit `PATH_READY` |
| Last ready Path lost | close business resources, retire SessionID, emit `session.changed`, schedule a new record if allowed |
| Path drain | no new work on that Path; finish acknowledged work until deadline, then close |
| Egress offline or endpoint restart | close all related resources; do not reuse the old SessionID |
| Authorization disable/revoke | atomically publish the authorization generation, reject new handshakes, close all matching live resources |
| Subscription refresh failure | retain last successful snapshot, emit `subscription.changed` with failure, retry with bounded backoff |
| Resource limit | reject the new operation or apply backpressure according to its resource class; never silently drop accepted TCP bytes |

Close reasons are stable identifiers: `last_path_lost`, `egress_unavailable`,
`endpoint_restart`, `authorization_disabled`, `authorization_revoked`,
`drain_deadline`, `target_failure`, `local_policy`, `path_failure`, and
`resource_limit`. Every close event includes the reason and the generation that
caused it.

## Timers and retries

Handshake, attach, target-open, heartbeat, drain, subscription refresh, and
control retransmission timers are bounded configuration values. A timeout MUST
produce a typed failure and a state transition; it MUST NOT leave a half-open
resource. Retries use bounded exponential backoff with jitter, reset after a
successful transition, and are suppressed after endpoint restart or terminal
authorization revocation.
