# Ingress observability specification

**English** | [简体中文](observability.zh-CN.md)

Ingress observability is the structured query and event surface for the local
control plane. Logs are supplementary; a state or metric required by an
operator MUST NOT exist only in log text.

## Separation from the data Path

`STATUS_REPORT` is an authenticated data-Path message. Its wire encoding is
defined by the [wire profile](wire-profile.md); its semantic fields are the
minimum Egress facts needed for Session admission and scheduling. It is not the
management API, browser API, or replacement for local metrics.

The observability provider reads typed snapshots from policy, Session, Path,
target-connection, subscription, and authorization components. It MUST NOT
parse logs to reconstruct primary state. Runtime producers publish through one
bounded provider independent of the external API adapter or log backend.

## Snapshot model

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
    "capacity_bps": 180000000,
    "recommended_path_count": 2,
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
`capacity_bps` is an unsigned bit rate; counts are non-negative integers; and
`status_report_age_ms` is the age of the newest authenticated report. A report
older than the configured freshness threshold MUST make the corresponding
Egress observation `stale` and MUST NOT be treated as current zero load.
Counters are monotonic for one process where their names imply monotonicity;
gauges may move in either direction. `snapshot_generation` and
`observed_generation` identify the same observation snapshot in this response.
`system_proxy.platform_effect` is `disabled`, `applied`, or `unsupported`;
Linux MUST report `unsupported` for activation because system-proxy control is
Windows-only.

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

## Node and Path metrics

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

## Session, Stream, and connection metrics

Session views expose:

```text
session_id, ingress_id, egress_id, state, freshness
admission_generation, created_at, last_change_at
ready_path_count, active_streams, active_udp_associations
control_pending, control_acked, control_retransmissions
close_reason, reconnect_attempts
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

## Scheduler and STATUS_REPORT observations

The observation provider MUST retain the Egress fields needed by the scheduler:
load, connection utilization, bandwidth utilization, active Session/Stream/
target-connection counts, aggregate capacity, recommended Path count, and report
freshness. Ingress Path observations MUST include RTT, jitter, loss, reordering,
throughput, effective capacity, and connection-establishment quality.

The scheduler uses the typed fields, not human-readable log text. A stale report
removes the Egress from new admission unless policy explicitly permits degraded
operation. Quality degradation reduces allocation quickly; recovery and scale-in
use the state-machine drain and stabilization rules. The observation API MUST
expose the reason when a Path is excluded because its incremental capacity is
less than its overhead.

## Counters, gauges, and histograms

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
pathchord_bytes_total{direction, class}
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

## Cardinality controls

Metric labels MUST come from bounded domains. Raw hostname, URL, RequestID,
StreamID, process command line, error message, or arbitrary administrator tag
MUST NOT be an unbounded aggregate label. High-cardinality details belong in
paginated resource queries or sampled events.

The service MUST bound tracked resources, event backlog per client, distinct
label/tag keys and values, and per-resource history. At a limit it reports a
typed `degraded` observation with a reason and drops only optional history; it
never drops current lifecycle state or counters required for safety decisions.

## Events and live updates

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

## Redaction and privacy

Before a Web Gateway is exposed, the observability layer MUST define redaction:

- never expose private keys, Noise handshake material, bearer tokens,
  subscription credentials, signed subscription URLs, ciphertext, or payloads;
- redact target hostnames and process metadata for roles that do not need them;
- normalize errors, removing filesystem paths and peer-provided arbitrary text;
- keep audit records free of complete request bodies and secrets.

Redaction is part of actor capability configuration and is applied before
serialization, not only in frontend code.

## Health and freshness

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

## No-log-only requirement

The following MUST be queryable as structured data: current Session, Path,
Stream, UDP, and target-connection state; policy, subscription, observation,
and authorization generations; node labels/tags and runtime observations;
listener inventory and system-proxy selection/effect;
control retransmission counts and queues; authorization cleanup effects; and
resource-limit or stale-producer conditions. Disabling logs MUST NOT make the
control-plane API unable to answer these queries.
