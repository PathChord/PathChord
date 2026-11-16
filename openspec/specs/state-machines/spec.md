# PathChord state-machine specification

**English** | [简体中文](spec.zh-CN.md)

## Purpose

Define externally observable lifecycle states, transition ownership, admission guards, resource cleanup, retries, and scheduler controls for Egress relationships, Paths, Sessions, TCP Streams, UDP Associations, subscriptions, authorizations, and system-proxy state.

## Requirements

### Requirement: Complete lifecycle and admission contract

Lifecycle owners SHALL enforce all state graphs, guards, actions, failure reasons, timers, and retry rules in the [detailed contract](#detailed-contract). A Path SHALL become ready only after authentication, identity/authorization checks, capability negotiation, and limit negotiation; internal connecting or closed records SHALL NOT be exposed as usable resources.

#### Scenario: Path has not completed admission

- **WHEN** a Path has not completed the checks and negotiation required for `PATH_READY`
- **THEN** it is not reported as ready or admitted for business traffic

### Requirement: Draining and terminal Session cleanup

Draining Paths and Sessions SHALL reject new business work while retaining existing work according to their deadlines. Losing the last ready Path, whole-Egress runtime restart or hard failure, or authorization failure SHALL close affected Session resources and retire the old SessionID. Failure or administrative drain of one configured Egress endpoint SHALL only affect Paths using that endpoint while another ready endpoint-backed Path remains eligible.

#### Scenario: Only draining Paths remain

- **WHEN** a Session contains ready draining Paths but no `ACTIVE` or `DEGRADED` Path
- **THEN** existing work may finish while new Streams and UDP Associations are rejected

#### Scenario: Last ready Path disappears

- **WHEN** the Session loses its last ready Path
- **THEN** business resources close, the SessionID is retired, and any later Session uses a new SessionID

#### Scenario: One configured endpoint fails

- **WHEN** a listener or transport endpoint fails while another endpoint-backed Path remains `ACTIVE` or `DEGRADED`
- **THEN** only Paths using the failed endpoint enter failure or replacement, the Session remains alive, and existing business work on healthy Paths is retained

#### Scenario: The whole Egress runtime restarts

- **WHEN** all configured Egress listeners and the shared runtime restart or lose authorization state
- **THEN** the affected Session closes according to the existing endpoint-restart rule and recovery creates a fresh SessionID

### Requirement: Stream and association resource ownership

An opening TCP Stream SHALL use one idempotent RequestID and create at most one target connection; FIN SHALL follow preceding bytes and RST SHALL discard pending bytes. An open UDP Association SHALL own exactly one Egress-side socket context, retain datagram boundaries, and release its socket on its documented close transitions.

#### Scenario: UDP drain deadline is reached

- **WHEN** a draining UDP Association reaches its deadline
- **THEN** its socket closes at the deadline without waiting for unfinished queued datagrams, and no new datagrams are admitted

### Requirement: Atomic subscription refresh and failure retention

Subscription refresh SHALL evaluate the current revision and atomically publish successful dynamic generations. Refresh failure SHALL retain the last successful node snapshot, record a typed failure, and use bounded backoff; disabled or deleted sources SHALL obey their documented refresh and drain rules.

#### Scenario: Subscription refresh fails

- **WHEN** an enabled subscription's current refresh fails
- **THEN** the last successful snapshot remains available, a typed failure is recorded, and retry follows bounded backoff

### Requirement: Authorization transitions affect all matching resources

Disabled and revoked authorization records SHALL immediately reject new handshakes and terminate all matching live resources. Revocation SHALL be terminal for the record identity; re-enabling a disabled record SHALL require a new generation without resurrecting old Sessions.

#### Scenario: Disabled authorization is re-enabled

- **WHEN** a disabled authorization becomes `ENABLED` through a new generation
- **THEN** new Sessions can be admitted but an old SessionID is not restored

### Requirement: Platform scoped system-proxy restoration

The system-proxy owner SHALL validate the Windows listener, preserve exact previous settings, make repeated selection idempotent, and retain restoration state on failure. Linux and FreeBSD mutations SHALL return `UNSUPPORTED_OPERATION` while their state queries report an unsupported platform effect.

#### Scenario: Windows proxy restoration fails

- **WHEN** disabling an applied Windows system proxy cannot restore the saved values
- **THEN** the switch enters `FAILED`, keeps the saved values, and does not report `DISABLED`

### Requirement: Bounded scheduling and autoscaling guards

Scheduling SHALL preserve one immutable Egress Session policy snapshot, bounded fair service, relationship and directional quality weighting, and per-sender shared replication accounting. Autoscaling SHALL apply one Session Path target with the documented hysteresis, common-minimum retention, drain action, incremental-capacity exclusion, and counter resets.

#### Scenario: Autoscaler scales a Path in

- **WHEN** surplus persists for the configured non-zero scale-in window and removing every selected drain candidate leaves another compliant usable Path and the Egress minimum
- **THEN** the selected Path enters `DRAINING` before removal, preserving the documented hysteresis and budget guards

#### Scenario: A draining Path cannot justify another drain

- **WHEN** the common minimum is two, two Paths are usable, and one additional Path is already draining
- **THEN** the owner rejects a planned drain of either usable Path and subtracts concurrently selected drain candidates when checking the minimum

### Requirement: One owner validates lifecycle transitions

One Session/Path lifecycle owner SHALL validate every Path and Session transition, update the state, and emit its transition event. Protocol handlers, schedulers, and control adapters SHALL request transitions through that owner and SHALL NOT mutate lifecycle state directly.

#### Scenario: A peer requests an invalid transition

- **WHEN** a peer message would move a draining Session back to active
- **THEN** the lifecycle owner rejects the request, preserves the current state, and emits a typed diagnostic rather than applying a direct assignment

### Requirement: Service state and admission state are independent

The Egress service state SHALL express lifecycle and health, while a separate admission state SHALL express whether new target connections are currently accepted. `degraded` MAY allow or deny new work; `draining` and `down` SHALL deny it, with `down` closing related resources.

#### Scenario: Capacity is exhausted while a Session remains healthy

- **WHEN** Egress has ready Paths but no target-connection headroom
- **THEN** it reports `service_state=degraded` and `admission_allowed=false`, retains existing work, and returns a typed resource-limit result for new opens

### Requirement: Reconnected Sessions start fresh

When a Session closes because of Egress failure, Path loss, authorization failure, or protocol trust failure, the replacement Session SHALL use a new SessionID, capture the configured Egress policy, and reset aggregate demand, Path targets, replication usage, and lifecycle observations.

#### Scenario: Egress recovers after Session closure

- **WHEN** Ingress reconnects to the same configured Egress after the old Session was retired
- **THEN** the new Session starts from its Egress minimum and fresh observations and does not reuse old Session state

### Requirement: Egress Session Path pool lifecycle

The Ingress Session owner SHALL maintain one authenticated Path pool for an Egress relationship, independently of matched routing rules. Planned expansion and draining SHALL preserve common eligibility and hard safety ceilings. Falling below the common minimum SHALL deny new business admission without closing existing work solely for that shortfall; losing the last ready Path SHALL retire the Session.

#### Scenario: Ready Paths fall below the configured minimum

- **WHEN** an Egress requires two usable Paths and a failure leaves one authenticated non-draining ready Path
- **THEN** the Session is degraded, new Streams and UDP Associations are denied, existing work can continue on the remaining Path, and bounded recovery attempts restore the common minimum

#### Scenario: Only draining Paths remain

- **WHEN** a Session has only authenticated draining Paths
- **THEN** existing work follows drain deadlines, new business admission is denied, and no draining Path counts toward the minimum for new admission

#### Scenario: Last ready Path is lost

- **WHEN** the last ready Path in the common pool fails
- **THEN** all related business resources close and the retired SessionID is not reused

### Requirement: Endpoint failure preserves shared lifecycle ownership

Endpoint-specific Path failure SHALL be processed by the existing Session/Path lifecycle owner. Endpoint selection, listener accept loops, and endpoint health observations SHALL request transitions through that owner and SHALL not mutate Session or Path state directly. A replacement Path SHALL use a new PathID, while a whole Egress runtime restart remains a Session restart.

#### Scenario: A failed endpoint is replaced

- **WHEN** bounded recovery establishes a replacement Path through another configured endpoint
- **THEN** the lifecycle owner records the new Path under the existing Session or a fresh Session as required by the current Session state, with no reuse of a retired PathID

#### Scenario: All endpoint-backed Paths are draining

- **WHEN** every ready Path is associated with an endpoint that is draining or failed
- **THEN** the Session denies new business admission and follows the normal drain or last-ready-Path transition instead of treating a merely configured endpoint as ready

### Requirement: Directional Path capacity drives scaling

Ingress SHALL maintain upstream and downstream Path observations separately. A bidirectional Session target SHALL cover the larger of the direction-specific Path requirements, while each direction SHALL use its own scheduler inputs.

#### Scenario: Downstream is the bottleneck

- **WHEN** upstream demand fits one Path but downstream demand requires three
- **THEN** the physical Path target is at least three and the upstream and downstream schedulers use their respective observations

### Requirement: Autoscaling remains bounded and low-frequency

Path health sampling and Session demand aggregation SHALL use bounded counters and low-frequency windows. Autoscaling SHALL use independent hysteresis for scale-out and scale-in, preserve the common Egress minimum during planned scale-in, and exclude a candidate whose incremental capacity is below its scheduling overhead.

#### Scenario: Unknown capacity at startup

- **WHEN** a Session has not collected enough fresh measurements for effective capacity
- **THEN** Ingress uses the configured Egress cap as a provisional scheduling ceiling, marks the observation provisional, and does not create unbounded extra Paths

## Detailed contract

This document defines externally observable lifecycle states and the guards and
actions that make a transition valid. A manager MAY keep an internal record in a
connecting or closed phase, but it MUST NOT expose that record as a usable
Session, Path, Stream, or association.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in
this document are to be interpreted as described by [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174). They have normative
force only when written in uppercase.

### Shared rules

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

### Egress relationship and service state

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

Egress authored resource limits are global aggregate wire capacity and global
inbound target-connection capacity. Pending target dials reserve a slot before
the dial and release it on success, failure, timeout, or reset. Resource
exhaustion reports degraded service with denied admission and a stable
`RESOURCE_LIMIT`/connection-limit reason; it does not close existing work.

### Path

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

### Session

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
Heartbeats and their acknowledgements are Path-local. Session control
retransmissions use ready, policy-compliant Paths and are deduplicated by the
Session control sequence.

An authenticated future Stream ACK that covers bytes outside the locally
emitted interval set is a Session trust failure, not an isolated Path failure.
The owner closes every Path and business resource, retires the SessionID, and
permits bounded recovery with a new SessionID. Repeated trust failures within
the configured window open a circuit breaker without automatically revoking
authorization.

### TCP Stream

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

### UDP Association

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

### Subscription refresh

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

Document fetch/parse failures and individual node failures are distinct.
Valid siblings may publish while invalid or unsupported nodes remain visible
and unselectable with redacted diagnostics. Bounded provider expansion may
retain failed providers' prior nodes while other providers succeed. Cache
reload preserves these failure states; the [Transit Proxy contract](../transit-proxies/spec.md)
defines normalization, validation, and metadata ownership.

### Authorization record

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

### Windows system-proxy switch

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

### Scheduler and autoscaling guards

Each admitted Stream and UDP Association uses the immutable TrafficPolicy
snapshot captured by its Egress Session. Business-class priority/share is not a
public configuration surface. The scheduler gives bounded fair service and
rotates among backlogged Streams. A Stream's FIN is emitted only after its
queued DATA is sent and acknowledged; a closed Stream observation may remain in
the bounded recent history.

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
Required control and ordinary retransmission are reserved before optional
business replication. Each sender's optional copies MUST NOT consume more than
the remaining outbound Session allowance; upstream and downstream are bounded
independently by the accepted scalar cap.

The autoscaler MUST use hysteresis: it MAY add a Path only after aggregate
capacity is below demand or the Session target exceeds active count for a
configured consecutive sample window; it MAY remove a Path only after surplus
persists for a separate non-zero window and the remaining non-draining usable
Paths still meet the common Egress minimum after all selected drain candidates
are removed. Scale-in MUST enter `DRAINING` first. A Path MUST be excluded when
incremental capacity is below scheduling overhead, with the reason exposed in
observations. Opposite-direction counters MUST reset after a state change or
failed probe. Thresholds and windows MAY be configured, but these guards,
hysteresis, drain action, and budget accounting are normative.

### Transition effects and failure reasons

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

### Timers and retries

Handshake, attach, target-open, heartbeat, drain, subscription refresh, and
control retransmission timers are bounded configuration values. A timeout MUST
produce a typed failure and a state transition; it MUST NOT leave a half-open
resource. Retries use bounded exponential backoff with jitter, reset after a
successful transition, and are suppressed after endpoint restart or terminal
authorization revocation.
