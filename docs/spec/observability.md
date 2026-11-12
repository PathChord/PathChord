# Ingress observability specification

**English** | [简体中文](observability.zh-CN.md)

Ingress observability is a structured query and event surface for the local
control plane. It is designed for a web dashboard, CLI diagnostics, automated
health checks, and incident analysis. Logs are supplementary; a metric or state
that operators need to query MUST NOT exist only in log text.

## Separation from the data Path

`STATUS_REPORT` is a data-Path protocol message. It communicates the minimum
Egress capacity and health facts needed for Session admission and scheduling.
It is not the management API, not a browser API, and not a replacement for
local metrics.

The observability service runs beside the Ingress runtime and reads typed
snapshots from the policy, Session, Path, target-connection, subscription, and
authorization components. It MUST NOT parse logs to reconstruct primary state.

Ingress exposes a bounded typed snapshot/event provider. Runtime producers
publish structured observations through this provider, and external adapters
read its snapshots and events. The provider contract is independent of the
external API adapter and log backend.

## Snapshot model

`GET /api/v1/metrics/snapshot` returns a point-in-time document:

```json
{
  "api_version": "1",
  "snapshot_generation": 42,
  "captured_at": "2026-11-12T00:00:00Z",
  "ingress": {"state": "running", "uptime_seconds": 3600},
  "sessions": {"configured": 3, "active": 2, "degraded": 1},
  "paths": {"ready": 2, "draining": 0, "failed": 1},
  "streams": {"open": 12, "half_closed": 2, "reset": 1},
  "udp": {"associations": 4},
  "connections": {"targets": 16},
  "policy": {"generation": 18},
  "subscriptions": {"configured": 2, "healthy": 2}
}
```

The exact JSON names are an adapter contract, not a wire-Path format. Every
snapshot has a generation and capture timestamp. Counters MUST be monotonic for
the lifetime of one process where their names imply monotonicity; gauges MAY go
up or down.

Structured resource views provide drill-down:

```text
GET /api/v1/nodes
GET /api/v1/sessions
GET /api/v1/sessions/{session_id}
GET /api/v1/connections
GET /api/v1/metrics/paths
GET /api/v1/metrics/streams
```

A query MUST return typed fields and a stable resource ID. It MUST NOT require a
client to parse a human-readable status string.

## Node and Path metrics

Node views combine static identity, imported source data, administrator labels,
and runtime observations without merging ownership:

```text
node.id, node.protocol, node.endpoint
source.subscription, source.imported_at
admin.labels, admin.tags
observed.connected, observed.rtt_ms, observed.jitter_ms
observed.loss_rate, observed.throughput_bps
observed.effective_capacity_bps, observed.state
quota.remaining_ratio, quota.reset_at
```

Per-Path views expose:

```text
path_id, session_id, egress_id, transit_proxy_id
state, ready_since, last_change_at
frame_sent, frame_received, frame_lost, frame_duplicate
rtt_ms, jitter_ms, loss_rate, reorder_count
throughput_bps, congestion_window, available_capacity_bps
control_pending, control_retransmissions
```

Path IDs, Session IDs, and Transit Proxy IDs are bounded-cardinality labels. Raw
Transit credentials, proxy URLs containing secrets, Noise keys, and ciphertext
are never metrics fields.

## Session, Stream, and connection metrics

Session views expose:

```text
session_id, ingress_id, egress_id, state
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
The original hostname MAY be shown to an authorized local administrator, but
raw credentials, full URLs with embedded secrets, and payload bytes MUST never
be returned. For unprivileged web roles, hostnames SHOULD be truncated or
hashed according to the configured redaction policy.

## Counters, gauges, and histograms

The observability service SHOULD provide these metric families:

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
pathchord_stream_reorder_bytes
```

Histograms MUST define units and bucket boundaries in their adapter schema.
Ratios are numeric values in `[0, 1]`; byte and bit rates use explicit `_bytes`
or `_bps` suffixes. A metric family MUST document whether it is a counter,
gauge, or histogram.

## Cardinality controls

Metrics labels MUST be selected from bounded domains. Do not use raw hostname,
URL, RequestID, StreamID, process command line, error message, or arbitrary
administrator tag as an unbounded metric label. High-cardinality details belong
in paginated resource queries or sampled events, not aggregate metric labels.

The service MUST enforce limits on:

- number of tracked nodes, Paths, Sessions, Streams, and target connections;
- retained event backlog per client;
- distinct label/tag keys and values;
- per-resource history retained for charts.

When a limit is reached, the snapshot reports a typed `degraded` observation
with a reason and drops only optional history, never the current lifecycle state
or counters required for safety decisions.

## Events and live updates

`GET /api/v1/events` uses SSE in the selected REST + SSE web adapter. Every event
includes:

```text
id, type, generation, emitted_at, resource_type, resource_id, payload
```

Required event types are:

```text
metrics.snapshot
node.changed
path.changed
session.changed
stream.changed
connection.changed
subscription.changed
authorization.changed
audit.notice
```

Events are ordered per Ingress process. A reconnecting client supplies
`Last-Event-ID`; the server either replays from its bounded event buffer or sends
a new complete snapshot followed by new events. Event payloads use the same
authorization and redaction rules as point-in-time queries.

## Redaction and privacy

The observability layer MUST define redaction before exposing a web gateway:

- never expose private keys, Noise handshake material, or bearer tokens;
- never expose subscription credentials or signed subscription URLs;
- never expose ciphertext or application payload bytes;
- redact target hostnames and process metadata for roles that do not need them;
- normalize error messages before returning them, removing filesystem paths and
  peer-provided arbitrary text where possible;
- keep audit records free of complete request bodies and secrets.

The redaction policy is part of the actor capability configuration and is applied
before serialization, not only in frontend JavaScript.

## Health and freshness

Every snapshot reports capture time and freshness. If a runtime producer stops
updating, the observability service reports the producer as stale instead of
presenting the last value as current. Suggested thresholds are implementation
configuration, but stale state MUST be distinguishable from a measured zero.

The local control plane exposes service health separately from Egress data-Path
health:

```text
control_plane: running | degraded | stopped
runtime_snapshot: fresh | stale | unavailable
data_path_summary: connected | degraded | down
```

These values are not interchangeable. A healthy local control plane can report a
down Egress, and a connected Egress does not imply that the web gateway is
available.

## No-log-only requirement

The following must be queryable as structured data and must not be available only
in logs:

- current Session, Path, Stream, UDP, and target-connection state;
- policy and subscription generations;
- node labels/tags and runtime observations;
- control retransmission counts and pending queues;
- authorization state and revocation effects;
- resource-limit and stale-producer conditions.

Logs MAY provide explanations and sampled traces, but deleting or disabling logs
MUST NOT make the control-plane API unable to answer these operational queries.
