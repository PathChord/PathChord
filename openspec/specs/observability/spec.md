# Ingress observability specification

**English** | [简体中文](spec.zh-CN.md)

## Purpose

Define structured operational snapshots, metrics, events, freshness, resource bounds, and privacy rules independently of logs and the authenticated data-Path status report.

## Requirements

### Requirement: Detailed observability contract

The observation service SHALL conform to the complete detailed contract below, including snapshot schemas, metric fields and types, event registries, units, limits, and health semantics. The requirements and scenarios supplement rather than replace those definitions.

#### Scenario: Snapshot generation identity

- **WHEN** `GET /api/v1/metrics/snapshot` returns a snapshot
- **THEN** `snapshot_generation` and `observed_generation` identify that same observation snapshot, with capture time and freshness included.

### Requirement: Structured state independent of logs

Runtime producers SHALL publish typed policy, Session, Path, Stream, target-connection, subscription, authorization, and listener observations through a bounded provider. Required operational state SHALL remain queryable when logs are disabled; the provider SHALL NOT reconstruct primary state by parsing logs or replace local observations with data-Path `STATUS_REPORT`.

#### Scenario: Logging is disabled

- **WHEN** logging is disabled while the control plane is available
- **THEN** required lifecycle state, generations, observations, cleanup effects, and resource-limit conditions remain available as structured queries.

### Requirement: Freshness and independent health states

Snapshots and authenticated status reports SHALL distinguish configured capacity, effective capacity, current wire rate, capacity confidence, service state, and new-admission state. Stale Egress reports SHALL exclude new admission while preserving existing work when heartbeat liveness remains healthy.

#### Scenario: Status is stale but the Path is alive

- **WHEN** heartbeat liveness is fresh but the newest Egress status exceeds the local freshness limit
- **THEN** the observation is marked stale, new business admission is denied, and existing work is not converted to a hard failure solely by report age

#### Scenario: Egress report exceeds its freshness threshold

- **WHEN** the newest authenticated Egress report is older than the configured freshness threshold
- **THEN** its observation is marked `stale`, is not interpreted as zero load, and does not permit new admission unless policy explicitly allows degraded operation

### Requirement: Authorized bounded aggregate metrics

The Web Gateway SHALL expose `/metrics` using the specified Prometheus text format and the same authentication, Origin, and `metrics:read` boundary as JSON metric queries. Aggregate metrics SHALL use bounded label domains, declare their types, and retain the distinction between current gauges and historical counters; absent facts SHALL NOT be fabricated.

#### Scenario: Prometheus reads the current snapshot

- **WHEN** an authorized client requests `/metrics`
- **THEN** the response reads one canonical snapshot, reports its current aggregate gauges without target-address or user-controlled labels, and does not present those gauges as lifetime totals.

### Requirement: Ordered recoverable event streams

SSE events SHALL use the canonical typed event registry, per-process ordering, bounded replay and client budgets, and the same authorization and redaction rules as snapshot queries. `Last-Event-ID` SHALL replay retained events or establish a complete snapshot before new deltas.

#### Scenario: Requested replay is outside the retained buffer

- **WHEN** an SSE client supplies a `Last-Event-ID` that cannot be replayed from the bounded buffer
- **THEN** the service sends a complete snapshot event before subsequent deltas.

### Requirement: Redaction before serialization

Observation responses, events, and audits SHALL apply actor-capability redaction before serialization. They SHALL exclude private keys, handshake material, bearer and subscription credentials, signed subscription URLs, ciphertext, and payload bytes; target and process details SHALL follow the detailed role-based privacy rules.

#### Scenario: Role lacks target-detail access

- **WHEN** an observation is serialized for a role that does not need target hostnames or process metadata
- **THEN** those details are redacted before serialization rather than being hidden only by frontend code.

### Requirement: Egress status is global and policy-free

Egress status reports SHALL describe global Egress resource facts aggregated across all configured listener endpoints and SHALL NOT contain routing rules, Egress Transit selectors, TrafficPolicy identity, business-class policy, or Ingress demand metadata. Path-local quality observations SHALL be owned by Ingress and derived from local Path traffic and control feedback.

#### Scenario: Egress reports shared capacity

- **WHEN** an Egress serves multiple Ingress Sessions
- **THEN** its status reports aggregate wire rate, capacity, active target connections, service state, and global admission state without exposing per-rule information

#### Scenario: Egress has multiple listener endpoints

- **WHEN** an Egress serves Paths through multiple configured listeners
- **THEN** capacity, target-connection counts, authorization effects, and admission state are reported once for the Egress and are not multiplied or partitioned by listener

### Requirement: Local observations identify bounded Egress endpoints

Authorized local operational views SHALL expose a bounded normalized endpoint inventory and the endpoint candidate selected by each Path. Endpoint observations SHALL use stable bounded endpoint ordinals or IDs, retain one of `configured`, `available`, `degraded`, `draining`, `failed`, or `unknown` with typed reasons and bounded counters, and SHALL not become unbounded metric labels.

#### Scenario: Inspect Egress endpoint inventory

- **WHEN** an authorized operator queries the Egress or Session resources
- **THEN** the response reports the configured endpoint count and each endpoint's bounded state, while redacting credentials and secret-bearing configuration

#### Scenario: Inspect a Path's selected endpoint

- **WHEN** an authorized operator queries a ready, draining, or failed Path
- **THEN** the response identifies the normalized endpoint ordinal used by that Path and does not claim that another endpoint was used

#### Scenario: An endpoint has repeated failures

- **WHEN** one endpoint accumulates bounded connection or listener failures
- **THEN** local observations expose its typed failure state and bounded counters without changing the aggregate Egress capacity or inventing a new Egress identity

### Requirement: Endpoint details stay out of wire status and metric labels

Endpoint-specific local observations SHALL not add raw endpoint hostnames, ports, or failure text to Prometheus label sets or the authenticated `STATUS_REPORT` layout. Aggregate Egress health and capacity SHALL remain available through their existing bounded fields.

#### Scenario: Prometheus metrics are rendered

- **WHEN** the metrics endpoint renders an Egress with multiple configured endpoints
- **THEN** it emits only bounded aggregate Egress gauges and does not create one unbounded label value per endpoint hostname or port

#### Scenario: An authenticated peer receives Egress status

- **WHEN** an Ingress receives the authenticated Egress status report over a Path
- **THEN** the report keeps the existing aggregate wire layout and does not disclose the Egress listener inventory

### Requirement: Capacity state is explicit

Observations SHALL expose configured capacity, effective capacity, current wire rate, and a capacity state of `unknown`, `provisional`, `measured`, or `stale`. Unknown values SHALL remain unknown and SHALL NOT be serialized as zero measurements.

#### Scenario: Provisional scheduling is active

- **WHEN** Egress has only its configured hard cap and no stable measured effective capacity
- **THEN** the observation marks capacity provisional, and Ingress may use the configured cap as a provisional scheduling ceiling

### Requirement: Admission state is explicit

Egress observations SHALL expose `admission_allowed` and a stable non-sensitive `admission_reason` independently of `service_state`. Resource exhaustion SHALL be observable as a degraded service with denied admission rather than as an implicit down state.

#### Scenario: Target connection resources are exhausted

- **WHEN** active connections and pending reservations reach the global Egress limit
- **THEN** observations report `admission_allowed=false` with a resource-limit reason while existing connections remain queryable

### Requirement: Directional Path observations remain Ingress-owned

Ingress SHALL publish bounded upstream and downstream Path observations and SHALL use them for Session-scoped scheduling and autoscaling under the Egress binding. Egress status SHALL not duplicate those Path-local observations as a second authoritative source. Rule identity or business class SHALL NOT partition the common Path target.

#### Scenario: Path capacity is asymmetric

- **WHEN** upstream and downstream observations differ for one Path
- **THEN** Ingress retains separate directional values and computes the physical Path target from the larger directional requirement

### Requirement: Session Path-pool observations

Session observations SHALL identify the owning Egress, common minimum, current target, eligible Transit count, immutable policy snapshot, aggregate directional demand, and negotiated per-sender replication allowance. These fields SHALL follow existing authorization, generation, cardinality, and unknown-value rules without allocating per-rule or per-business-class observations.

#### Scenario: Different routing rules use one Egress

- **WHEN** flows selected by several routing rules share a Session
- **THEN** queries expose one Session pool target, one policy snapshot, and aggregate directional demand rather than separate rule-specific targets or policies

#### Scenario: The minimum cannot be met

- **WHEN** at least one authenticated ready Path remains but usable non-draining Paths are below the minimum, or a negotiated ceiling prevents reaching that minimum
- **THEN** observations show the minimum, bounded target, ready count, usable count, and a typed admission or shortfall reason, retaining degraded service while a ready Path remains and no separate hard failure occurs

#### Scenario: A measurement is not available

- **WHEN** a Session has no accepted replication negotiation or an aggregate demand window has no authoritative sample
- **THEN** the corresponding field is null or explicitly unknown rather than a fabricated measured zero

## Detailed contract

Ingress observability is the structured query and event surface for the local
control plane. Logs are supplementary; a state or metric required by an
operator MUST NOT exist only in log text.

### Separation from the data Path

`STATUS_REPORT` is an authenticated data-Path message. Its wire encoding is
defined by the [wire profile](../wire-profile/spec.md); its semantic fields are the
minimum Egress facts needed for Session admission and scheduling. It is not the
management API, browser API, or replacement for local metrics.

The observability provider reads typed snapshots from policy, Session, Path,
target-connection, subscription, and authorization components. It MUST NOT
parse logs to reconstruct primary state. Runtime producers publish through one
bounded provider independent of the external API adapter or log backend.

### Snapshot model

`GET /api/v1/metrics/snapshot` returns a point-in-time document with the common
control-plane response metadata:

```json
{
  "api_version": "1",
  "request_id": "01JEXAMPLE",
  "observed_generation": {"scope": "observation", "value": 42},
  "snapshot_generation": 42,
  "captured_at": "2026-11-12T00:00:00Z",
  "freshness": "fresh",
  "ingress": {"state": "running", "uptime_seconds": 3600},
  "system_proxy": {"enabled": false, "listener_id": null, "platform_effect": "disabled"},
  "egress": {"configured": 3, "up": 2, "degraded": 1, "draining": 0, "down": 0},
  "egress_reports": [{
    "egress_id": "jp-1",
    "state": "up",
    "load_ratio": 0.42,
    "connection_utilization_ratio": 0.35,
    "bandwidth_utilization_ratio": 0.51,
    "active_sessions": 2,
    "active_streams": 12,
    "active_target_connections": 16,
    "configured_capacity_bps": 180000000,
    "effective_capacity_bps": 150000000,
    "current_wire_rate_bps": 92000000,
    "replication_allowance_bps": 12000000,
    "capacity_state": "measured",
    "admission_allowed": true,
    "admission_reason": "none",
    "status_report_age_ms": 120
  }],
  "sessions": {"configured": 3, "active": 2, "degraded": 1, "draining": 0},
  "paths": {"ready": 2, "draining": 0, "failed": 1},
  "streams": {"open": 12, "half_closed": 2, "reset": 1},
  "udp": {"associations": 4},
  "connections": {"targets": 16},
  "policy": {"generation": 18},
  "subscriptions": {"configured": 2, "healthy": 2}
}
```

`load_ratio`, utilization ratios, and loss ratios are numbers in `[0, 1]`;
capacity fields are unsigned bit rates; counts are non-negative integers; and
`status_report_age_ms` is the age of the newest authenticated report. A report
older than the configured freshness threshold MUST make the corresponding
Egress observation `stale` and MUST NOT be treated as current zero load.
Counters are monotonic for one process where their names imply monotonicity;
gauges may move in either direction. `snapshot_generation` and
`observed_generation` identify the same observation snapshot in this response.
`system_proxy.platform_effect` is `disabled`, `applied`, or `unsupported`;
Linux and FreeBSD MUST report `enabled: false` and `platform_effect: unsupported`
in system-proxy state queries because activation is Windows-only. Their enable
and disable operations return `UNSUPPORTED_OPERATION`.

Structured drill-down resources are:

```text
GET /api/v1/nodes
GET /api/v1/sessions
GET /api/v1/sessions/{session_id}
GET /api/v1/connections
GET /api/v1/listeners
GET /api/v1/authorizations
GET /api/v1/system-proxy
GET /api/v1/metrics/paths
GET /api/v1/metrics/streams
```

Every query returns typed fields, a stable resource ID, and the common response
metadata. Lists use the bounded pagination, filtering, and sorting contract in
the control-plane specification.

### Node and Path metrics

Node views combine ownership-separated fields:

```text
node.id, node.protocol, node.endpoint
source.subscription, source.imported_at
admin.labels, admin.tags
observed.connected, observed.state, observed.freshness
observed.rtt_ms, observed.jitter_ms, observed.loss_rate
observed.throughput_bps, observed.effective_capacity_bps
quota.remaining_ratio, quota.reset_at
```

Per-Path views expose:

```text
path_id, session_id, egress_id, transit_proxy_id
state, ready_since, last_change_at, freshness
frame_sent, frame_received, frame_lost, frame_duplicate
rtt_ms, jitter_ms, loss_rate, reorder_count
throughput_bps, congestion_window, available_capacity_bps
control_pending, control_retransmissions
```

Path, Session, and Transit Proxy IDs are bounded-cardinality labels. Raw Transit
credentials, secret-bearing proxy URLs, Noise keys, and ciphertext are never
metric fields.

### Session, Stream, and connection metrics

Session views expose:

```text
session_id, ingress_id, egress_id, state, freshness
admission_generation, created_at, last_change_at
ready_path_count, active_streams, active_udp_associations
control_pending, control_acked, control_retransmissions
close_reason, reconnect_attempts
minimum_usable_paths, target_path_count, usable_path_count
eligible_transit_count, traffic_policy_id, traffic_policy_generation
demand_upstream_bps, demand_downstream_bps
replication_cap_bps, replication_upstream_used_bps, replication_downstream_used_bps
```

Stream views expose:

```text
stream_id, session_id, state, direction_state
target_kind, target_port, admitted_generation
bytes_sent, bytes_received, bytes_acked
reorder_buffer_bytes, receive_window, retransmissions
opened_at, closed_at, close_reason
```

Target connection views expose a stable local connection ID, SessionID and
StreamID, lifecycle state, byte counters, timing, and normalized close reason.
An authorized local administrator MAY receive the original hostname; raw
credentials, secret-bearing URLs, and payload bytes MUST never be returned.

### Scheduler and STATUS_REPORT observations

The observation provider MUST retain the Egress fields needed by the scheduler:
load, connection utilization, bandwidth utilization, active Session/Stream/
target-connection counts, configured/effective/current capacity, capacity state,
replication allowance, admission state/reason, and report freshness. It MUST NOT
publish a recommended Path count or per-Ingress quota. Ingress Path observations
MUST include separate upstream/downstream RTT, jitter, loss, reordering,
throughput, effective capacity, and connection-establishment quality.

The observation provider MUST also expose one Session pool minimum, bounded
target, ready/usable counts, eligible relationships, captured policy identity
and generation, aggregate upstream/downstream demand, and negotiated cap.
Upstream usage is authoritative local sender accounting; downstream usage is
null unless an authoritative Session-scoped producer exists. The global Egress
replication allowance is not a substitute. The scheduler uses the typed fields, not human-readable log text. A stale report
removes the Egress from new admission unless policy explicitly permits degraded
operation. Quality degradation reduces allocation quickly; recovery and scale-in
use the state-machine drain and stabilization rules. The observation API MUST
expose the reason when a Path is excluded because its incremental capacity is
less than its overhead.

### Counters, gauges, and histograms

The Web Gateway exposes `GET /metrics` as Prometheus text format 0.0.4 with
`Content-Type: text/plain; version=0.0.4; charset=utf-8`. It uses the same
authentication, Origin restrictions, and `metrics:read` authorization as JSON
metric queries; it is not a separately privileged or unauthenticated listener.
The response reads one canonical observation snapshot and provides these
aggregate gauges without user-controlled or target-address labels:

```text
pathchord_active_sessions
pathchord_ready_paths
pathchord_active_streams
pathchord_target_connections
pathchord_observed_nodes
pathchord_observed_connections
pathchord_observation_generation
```

These values describe current snapshot state. They MUST NOT be presented as
historical event counters or lifetime totals; absent snapshot facts are not
fabricated. High-cardinality connection details remain in authorized resource
queries. Provider quota, expiry, and explicit billing metadata follow the
[Transit Proxy accounting contract](../transit-proxies/spec.md#provider-accounting-metadata).

The service SHOULD provide these metric families:

```text
pathchord_sessions_total
pathchord_session_closes_total{reason}
pathchord_paths_total{state}
pathchord_streams_total{state}
pathchord_udp_associations_total{state}
pathchord_target_connections_total{result}
pathchord_frames_total{direction, result}
pathchord_control_retransmissions_total{direction}
pathchord_bytes_total{direction}
pathchord_path_rtt_ms
pathchord_path_jitter_ms
pathchord_path_loss_ratio
pathchord_path_capacity_bps
pathchord_egress_load_ratio
pathchord_egress_connection_utilization_ratio
pathchord_egress_bandwidth_utilization_ratio
pathchord_egress_recommended_paths
pathchord_stream_reorder_bytes
```

Histograms MUST define units and bucket boundaries in their adapter schema. A
metric family MUST declare whether it is a counter, gauge, or histogram.

### Cardinality controls

Metric labels MUST come from bounded domains. Raw hostname, URL, RequestID,
StreamID, process command line, error message, or arbitrary administrator tag
MUST NOT be an unbounded aggregate label. High-cardinality details belong in
paginated resource queries or sampled events.

The service MUST bound tracked resources, event backlog per client, distinct
label/tag keys and values, and per-resource history. At a limit it reports a
typed `degraded` observation with a reason and drops only optional history; it
never drops current lifecycle state or counters required for safety decisions.

### Events and live updates

`GET /api/v1/events` uses SSE in the selected REST adapter. Every event contains
`id`, `type`, `generation`, `emitted_at`, `resource_type`, `resource_id`, and a
typed `payload`. `generation` uses the same `{scope,value}` form as response
metadata; a resource payload MAY additionally carry its own `revision`.

The canonical event registry is:

```text
metrics.snapshot
node.changed
path.changed
session.changed
stream.changed
connection.changed
subscription.changed
authorization.changed
system_proxy.changed
audit.notice
```

Events are ordered per Ingress process. `Last-Event-ID` either replays from the
bounded buffer or causes a complete snapshot event before new deltas. Event
payloads use the same authorization and redaction rules as point-in-time
queries. `subscription.refresh` is not a separate event type; refresh outcomes
are represented by `subscription.changed` with a typed result.

### Redaction and privacy

Before a Web Gateway is exposed, the observability layer MUST define redaction:

- never expose private keys, Noise handshake material, bearer tokens,
  subscription credentials, signed subscription URLs, ciphertext, or payloads;
- redact target hostnames and process metadata for roles that do not need them;
- normalize errors, removing filesystem paths and peer-provided arbitrary text;
- keep audit records free of complete request bodies and secrets.

Redaction is part of actor capability configuration and is applied before
serialization, not only in frontend code.

### Health and freshness

Every snapshot reports capture time and freshness. A runtime producer that stops
updating is marked `stale` or `unavailable`, never presented as a current zero.
Thresholds are configuration values, but stale MUST be distinguishable from a
measured zero.

The local control plane exposes independent health values:

```text
control_plane: running | degraded | stopped
runtime_snapshot: fresh | stale | unavailable
data_path_summary: connected | degraded | down
```

These values are not interchangeable. A healthy control plane may report a down
Egress, and a connected Egress does not imply that the Web Gateway is available.

### No-log-only requirement

The following MUST be queryable as structured data: current Session, Path,
Stream, UDP, and target-connection state; policy, subscription, observation,
and authorization generations; node labels/tags and runtime observations;
listener inventory and system-proxy selection/effect;
control retransmission counts and queues; authorization cleanup effects; and
resource-limit or stale-producer conditions. Disabling logs MUST NOT make the
control-plane API unable to answer these queries.
