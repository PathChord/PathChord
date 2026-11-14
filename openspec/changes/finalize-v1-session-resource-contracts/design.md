# Design

## Context

PathChord has not released a first wire-compatible implementation, so the v1
profile and configuration schema can be corrected directly. The current
runtime already has the required crates and local test seams, but policy,
Session/Path lifecycle, Egress resource accounting, and status reporting still
own overlapping decisions. The current `complete-scheduling-and-observability`
change carries earlier conservative work with `skip_specs: true`; this change
supersedes that scope for the normative v1 behavior selected here.

## Goals / Non-Goals

**Goals:**

- Make v1 wire, configuration, state-machine, and observability contracts agree.
- Keep all rule and policy interpretation in Ingress.
- Keep Egress a small, resource-aware forwarding service with global limits and
  Path/Session state, without cross-Ingress fairness or rule knowledge.
- Support multiple Path instances through one Transit relationship and compute
  rule-specific Path targets in Ingress.
- Preserve ordinary reliable TCP retransmission while bounding optional
  replication and control copies.
- Make capacity, admission, trust failure, and restart semantics explicit and
  testable.
- Keep the data hot path bounded; perform demand aggregation and autoscaling in
  low-frequency maintenance work.

**Non-Goals:**

- Backward compatibility with an older PathChord release.
- Sending EgressRule, TransitRule, TrafficPolicy, rule demand, or TrafficClass
  metadata to Egress.
- Cross-Ingress bandwidth fairness or per-Ingress Egress quotas.
- Synthetic bandwidth probes.
- Transparent target-connection recreation after an admitted Session fails.

## Decisions

### 1. v1 wire is corrected in place

The project has no released peer that requires compatibility. Remove the
unregistered PathRebind and TrafficClass frames directly from v1. Add mandatory
Session replication-cap fields to `SESSION_ATTACH` and `SESSION_ATTACH_OK`, and
replace the ambiguous status capacity/recommendation fields with explicit
capacity and admission fields. Freeze the resulting registry and vectors before
implementation.

### 2. Ingress owns policy; Egress owns resources

Ingress evaluates rules, assigns Session-scoped rule/policy/class keys, chooses
eligible Transit relationships, computes per-direction Path targets, and owns
per-flow replication budgets. Egress receives only the opaque Session hard cap
and the narrow scheduler/resource fields required by the protocol. Egress never
evaluates a selector or stores a rule identifier.

The Egress user configuration contains the aggregate wire hard cap and global
inbound target-connection cap. The desired Path count, per-Ingress quota,
`recommendedPathCount`, `maxStreamsPerIngress`, and public `maxConcurrentPaths`
are removed. Egress derives an internal static Path safety ceiling from profile
limits and local resources and exposes it read-only.

### 3. Session and Path ownership is centralized

Create one lifecycle owner around `PathSet`/Session state. It validates every
transition, emits the transition event, and exposes immutable snapshots. The
Session actor, protocol handlers, scheduler, and control adapters submit
requests to this owner instead of assigning `PathState` or `SessionState`.

Model a Transit relationship separately from each Path instance:

```text
TransitRelationship
  adapter, relationship weight, policy eligibility

PathInstance
  PathID, relationship ID, directional health, state, economics
```

The same relationship may own multiple Paths. A relationship's weight is applied
once before its Path instances distribute the relationship share.

### 4. Rule-specific Path targets share a physical PathSet

For each captured policy generation, Ingress builds rule-specific eligible
relationship sets. Each active rule gets a bounded demand counter keyed by
`(SessionID, EgressRule, TrafficPolicy, TrafficClass-local key)`, but no per-flow
history. A Session actor updates local byte counters in the hot path; a
maintenance task rotates counters and updates EWMA demand at low frequency.

Each rule computes its own minimum and demand-derived target. The physical
PathSet satisfies the union of those requirements and reuses a Path only when it
is eligible for the rule. The target is bounded by the Egress safety ceiling and
the available compliant relationships.

Upstream and downstream capacity are measured separately. A bidirectional
physical target covers the larger directional requirement, while each scheduler
uses its own direction's observations.

### 5. Egress capacity has hard, measured, and current values

Egress enforces a global wire token bucket using the configured hard cap. It
passively measures sustainable aggregate capacity from scheduler feedback,
queue/backpressure, retransmission, and Path state; it does not send synthetic
probes. The measured value is bounded by the configured cap and updated with
fast degradation/slow recovery hysteresis.

Status reports carry global values only:

```text
configured_capacity_bps
effective_capacity_bps
current_wire_rate_bps
capacity_state = unknown | provisional | measured | stale
admission_allowed
admission_reason
```

Ingress derives Path-local directional metrics from its own ACK, heartbeat,
data, and retransmission observations. Egress may keep per-Path counters
internally, but they are not a second wire authority.

### 6. Admission and failure are separate from health

`service_state` describes Egress lifecycle/health. `admission_allowed` describes
whether new target connections are accepted. A saturated Egress can be
`degraded` with admission denied while existing connections continue. `down`
is a hard failure and closes related Sessions and business resources.

The global target-connection cap counts active Egress-to-target connections.
Pending target dials reserve a slot before dialing and are separately bounded.
Reservation release is atomic on success, failure, timeout, or Stream reset.
Resource exhaustion returns `RESOURCE_LIMIT`; target dial errors return
`TARGET_FAILURE`; Path/Session failures retain their own classes.

### 7. Replication is negotiated, locally policy-controlled, and globally bounded

Ingress sends a requested Session replication cap in `SESSION_ATTACH`. Egress
returns the accepted effective cap in `SESSION_ATTACH_OK`; it may lower the
request. The Session cap is a hard ceiling shared by all Paths. Per-flow and
class budgets are local Ingress policy values, and the wire carries no policy
identity.

The Egress scheduler gives primary business traffic, ordinary retransmission,
and required control priority. Extra replicas consume only residual global
capacity. The current Egress global replication allowance is reported in the
global status report and may shrink or recover without renegotiating the hard
Session cap. The first copy and ordinary reliable retransmission remain
available when optional replication is exhausted.

### 8. Session trust failure is stronger than Path failure

Ingress validates ACK ranges against its emitted interval set. A future ACK
after local frontier validation is a Session trust failure: close all Paths,
retire the SessionID, record a sanitized diagnostic, and reconnect with a new
SessionID after bounded backoff. Three failures in the configured window open a
circuit breaker; authorization is not automatically revoked by one failure.

Business candidate failover is allowed only before `STREAM_OPEN`/`UDP_OPEN`
admission. Once a target connection exists, Session failure closes it and the
application retries.

### 9. TLS and local control are explicit and bounded

TLS truststore sources default to `["system"]` and may include local PEM/DER
files. Relative paths resolve from the selected configuration source; absolute
paths are allowed; symlinks are allowed only when their startup target is a
regular file. Any invalid source rejects the adapter candidate. An empty list
means no trust anchors; `insecure` is a separate explicit verifier bypass.

Local control bounds prefix read, payload read, dispatch, and response write.
Timeouts release permits and publish sanitized diagnostics without mutating
state.

## Risks / Trade-offs

- [Risk] Removing provisional v1 frames and TrafficClass wire messages changes
  the current in-tree codec surface. → Update all golden vectors and fixtures
  in the same implementation slice; no compatibility adapter is retained.
- [Risk] Egress has no cross-Ingress fairness. → Document best-effort global
  contention, enforce the global hard cap, and expose global load/admission so
  each Ingress can back off without pretending to own a reserved share.
- [Risk] Passive effective-capacity measurement is unknown at low load. → Use
  configured capacity as a provisional scheduling ceiling, mark confidence, and
  never infer capacity from idle throughput.
- [Risk] Rule-specific Path targets can grow state in Ingress. → Bound rule and
  class keys by the validated configuration, keep counters Session-local, and
  run EWMA/autoscale outside the data hot path.
- [Risk] Session trust failures can cause reconnect loops. → Use bounded
  exponential backoff and a circuit breaker; retain authorization unless an
  independent authorization event occurs.
- [Risk] Truststore source mistakes can make a node unavailable. → Fail closed,
  report a typed adapter diagnostic, and retain the previous good adapter during
  runtime preparation.

## Migration Plan

1. Update the English delta specs and bilingual durable design documents before
   changing code. Keep the existing v1 compatibility vectors as the baseline,
   then replace them with the finalized vectors in one coordinated change.
2. Implement core wire/message changes and lifecycle-owner seams first. Run
   focused codec, state, ACK, and Session trust tests before integrating policy.
3. Implement Ingress relationship/PathSet, rule demand aggregation, candidate
   admission, per-direction observations, and low-frequency autoscaling.
4. Implement Egress global capacity/admission accounting, pending reservations,
   status production, and opaque Session budget enforcement.
5. Update configuration parsing, truststore construction, local-control
   deadlines, CLI wiring, guides, and implementation evidence.
6. Run local unit/loopback checks, strict OpenSpec and bilingual documentation
   checks, then keep native-host, cross-machine, and long-running evidence
   separate. Rollback before release is a source/configuration revision because
   no older wire implementation is supported.
