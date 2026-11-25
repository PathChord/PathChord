# Runtime observability design

## Context

The current observation provider already publishes live resources, Path quality,
Path-pool planning, and aggregate gauges. Ingress can associate a Path with a
Transit Proxy. Egress can report its local endpoint and Session activity.
Runtime termination paths currently remove live evidence, and optional
management detail varies across deployed builds. This change extends the
existing observation model and adapters. [Proposal](proposal.md)

## Goals

An operator can follow a failed flow across stages, identify the first locally
observed failure on either host, inspect queue and scheduling pressure at that
time, and tell whether evidence is missing or stale. The same workflow applies
to incidents that fail before admission and those that fail after data flows.

## Decisions

### Capture evidence at its owner

Map typed outcomes where the owning component still has the relevant context.
Use listener and flow dispatch for acceptance and policy, DNS adapters for
resolution, subscription management for fetch and adapter preparation, Path
dial and admission for carrier and authentication, and lifecycle owners for
terminal events. Instrument Egress target open and stream I/O at the connector
and bridge. Record resource saturation at the corresponding reservation owner.

Capture the original trigger before cancelling sibling tasks or removing live
state. Distinguish carrier EOF, local write and read errors, local timeouts,
protocol errors, and cascading Session cleanup. Attribute a write failure to
the actual Path used by the scheduler or retransmission. Preserve byte
direction, first and last progress timestamps, flow control availability,
and queue depth where the producer owns them. For scheduler decisions, capture
the selected Path and bounded summaries of eligible and excluded candidates,
including status freshness and capacity inputs at decision time.

### Keep identifiers and time comparable

Join admitted records by Egress, Session and Path IDs or by Session and
Stream IDs. Resolve Transit identity from the Ingress record. Link local
pre-admission attempts and retries through a local correlation ID. Include a
process-instance identifier in diagnostic cursor scope. Wall-clock time
locates evidence on the other host.
Each role reports independently observed evidence.

### Preserve evidence through failure and saturation

Publish lightweight typed records to the existing observation provider.
Allocate bounded recent histories independent of the live resource tables.
Prioritize terminal and failure evidence over routine samples. Coalescing
may summarize repeated stage failures without individual resource identities.
Count any omitted individual termination records as producer loss. Keep terminal
counters at the producer so delayed collection or history eviction does not
erase totals. Budget optional capture separately and expose lost records and
stale producers. Use the existing event adapter and cursor recovery semantics.

### Make collection practical in deployed services

Expose a common role-local command group through `pathchordctl`. Reuse the
shared dispatcher for management operations and Web Gateway reads. Scope
capture to selected stages and optionally a local resource ID, permit one
active capture per process, cap duration at 15 minutes, and show expiration,
sampling settings, and drops. Record start and stop audit events. A capture
uses in-memory samples and expires on process restart. Use the existing
authenticated Prometheus endpoint for aggregates. Ship troubleshooting
examples for local access with the Web Gateway disabled and for authorized
scraping with it enabled.

## Risks and trade-offs

- Sampling can miss a transient scheduler decision. Preserve attempt failures
  and terminal reasons in baseline history and expose capture drop counts.
- Clock offsets can obscure which host observed failure first. Present
  process ordering alongside timestamps and show peer evidence independently.
- High-rate sampling adds CPU and memory pressure. Keep fast-path publication
  bounded, compare disabled and active capture under load, and report evidence
  loss under saturation.
- Raw transport diagnostics can contain provider or target details. Map errors
  at the owner, apply existing capability-based redaction, and inspect every
  exported surface for secret leakage.

## Rollout and verification

Add instrumentation and role-local reads first, then connect capture controls,
event replay, CLI and monitoring. Use package-level smoke checks on supported
roles and retain distinct evidence for local fault injection, native package
checks, and deployed tests. Validate a sustained range transfer and a controlled
interruption with a known failure trigger. Use the captures to reconstruct the
first termination, any failover and the final outcome. [Observability delta](specs/observability/spec.md)

## Proposed detailed contract

Merge these schemas, registries, and limits into the canonical observability
Detailed contract when syncing the change.

### Termination records and correlation

Each record contains `session_id`, `path_id`, `egress_id`, `role`,
`observed_at` in UTC, terminal `state`, and `reason`. Ingress includes
`transit_proxy_id` when known. Optional diagnostics include `write_elapsed_ms`
for the terminating write and `heartbeat_age_ms` when sampled. Unavailable
values are represented as null or omitted. The role-local order follows the
event cursor. Cross-host timestamps are subject to clock skew.

The closed reason registry is `write_timeout`, `write_error`, `read_error`,
`peer_eof`, `heartbeat_timeout`, `protocol_error`, `drained`,
`administrative_close`, `session_closed`, and `unknown`. Reasons describe
local observations. Paths removed as a consequence of Session closure use
`session_closed` when no Path-specific trigger initiated the transition.

Use `path.changed` for terminal events. Recent records expire after 15 minutes
or when evicted from a 1,024-record buffer per process, whichever occurs first.
Queries support bounded pagination and Session and Path ID filters. The
existing replay and snapshot recovery rules apply separately to the event
buffer. History is process-local. Apply the baseline authorization and
redaction rules, including removal of arbitrary error text and secrets.

The counter family is `pathchord_path_terminations_total{reason}`. Counters
reset on process restart and contain only registry values as labels.

### Runtime stages and fields

A stage record contains the common event metadata, role, stage, outcome
(`success`, `failure`, `timeout`, `cancelled`, `skipped`), a reason code
when applicable and elapsed milliseconds for timed operations. Each stage
uses a closed reason registry defined before implementation. Management
responses identify the observation producer and freshness. Related IDs
are included when available. A local attempt ID links retries and stages
that precede admission. Admitted peers correlate using authenticated
Session, Path, and Stream IDs. Local flow, attempt, and target connection IDs
are role-local. Each retry retains its own outcome. Unobserved peer state
is unknown.

| Stage families | Required drill-down when observed |
| --- | --- |
| Listener and platform | Listener ID, accepted protocol, authentication or parse outcome, bind and platform state |
| Policy and DNS | Effective generation, matched rule ID, route or fallback result, resolver route, cache outcome and address family |
| Configuration, enrollment and subscriptions | Activation or reload outcome, generation, authorization outcome, refresh and cache outcome, adapter eligibility |
| Transit and Path establishment | Opaque Transit ID where owned, protocol, endpoint index and family, dial, proxy handshake, Noise and attachment outcomes, retry and backoff |
| Session and Path lifecycle | Previous and current state, termination reason, peer evidence if available, heartbeat and status ages, reconnect outcome |
| Scheduling and flow control | Direction, eligible Path count, chosen Path and exclusion reasons in capture, available capacity, Path-pool targets, queue and window pressure, retransmission and replanning outcomes |
| Stream and target I/O | TCP or UDP, open and connect outcomes, directional bytes and last progress age, half-close, FIN/RST or association expiry, local termination trigger |
| Resources and supervision | Limit kind, usage and limit when measurable, rejection or saturation, degraded producer and dropped observations |

A bounded recent record query supports role-local stable ordering and filters
for stage, outcome, Session ID and Path ID. Successful high-frequency actions
are available as aggregates and sampled capture observations. Retain
baseline failure and lifecycle evidence independently of detailed capture.
When retention or producer loss limits coverage, expose a gap or a dropped
count. Capture uses a separate bounded buffer, an explicit scope and
duration, and excludes payloads, keys, credentials, raw peer errors and
signed URLs. Capture omits raw target details by default.

### Aggregate diagnostics

Export `pathchord_runtime_stage_operations_total{stage,outcome}`,
`pathchord_runtime_stage_duration_seconds{stage}` as a histogram with
buckets at 0.005, 0.025, 0.1, 0.5, 1, 3, 6, 15, and 60 seconds plus
`+Inf`, and `pathchord_diagnostic_records_dropped_total{source}` with
`source` limited to `producer`, `history`, and `capture`. Stage labels
come from the stage families above using fixed identifiers. Keep resource
identities and endpoint addresses in authorized drill-down. Counters are
process-lifetime and distinct from current snapshot gauges. Publish snapshots
from the canonical observation generation and apply metric and replay
authorization consistently.

### Measurement boundaries and producer coverage

Identify the build and role alongside a process-instance ID generated at
startup, process start time in UTC, and the current observation generation.
Report producer state as `fresh`, `stale`, or `unavailable`, together with its
last capture time and a bounded reason where known. Use null for unavailable
measurements and numeric zero for a measured zero. Export
`pathchord_observation_process_start_time_seconds` as an unlabeled gauge.
Use monotonic time for intra-process waits and elapsed measurements.

Report application pending bytes, Stream and Session window credit, Path write
elapsed time and last progress age as separate measurements. Any OS socket
queue sample is optional, has its own source and sampling time, and describes
only the local socket. Include the operation direction and resource ID in
structured detail. Capture the configured deadline and the observed error
class at the boundary that owns either measurement.

### Retention, gaps, and export coverage

Report the process instance and oldest and newest retained cursor with history
responses. Distinguish time expiration, capacity eviction, producer loss,
capture loss, and different process instances where the service can detect
them. Keep intentional filtering and sampling visible as coverage metadata.
Reserve the observation loss counters for actual capacity or publication
loss. Capture scope, sampling settings, and budgets determine which records
can be expected during an incident.

Produce a versioned JSON export from each role's existing authorized local
queries. Include build and process identity, collection start and end,
requested and retained ranges, live snapshot generation, history cursor range,
gap reasons, truncation, and redacted records. Capture the snapshot and history
watermarks at collection start and report gaps if records expire during the
read. Apply bounded time range, record count, and byte limits before writing
output. Validate exports separately from live replay and compare records
offline using the same authenticated identifiers available in ordinary queries.
