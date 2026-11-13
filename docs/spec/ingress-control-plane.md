# Ingress control plane specification

**English** | [简体中文](ingress-control-plane.zh-CN.md)

This document defines the local control plane used to operate Ingress and the
optional web gateway used by a frontend. It is separate from the PathChord data
Path. All adapters call the same typed command/query service; they MUST NOT edit
configuration files, subscription caches, or databases directly.

## Architecture and envelope

```text
pathchord CLI --------------------+
                                   |
optional authenticated web gateway +--> typed Ingress command/query service
                                   |             |
Unix socket / named pipe ----------+             +--> atomic snapshots
                                                 +--> subscription workers
                                                 +--> authorization/policy store
                                                 +--> metrics registry
```

The required privileged local adapter is a Unix domain socket on Linux and
FreeBSD and a Named Pipe on Windows. The operating-system owner/ACL is the first
authorization boundary. The optional Web Gateway is a separate process/task
boundary, disabled by default, and MUST NOT be reachable through a Transit
Proxy or Egress data Path. A non-loopback bind additionally requires explicit
configuration, a protected channel, strong authentication, an origin allowlist,
rate limits, redaction, and an administrator-visible audit record.
The selected gateway binds loopback by default. A non-loopback bind MUST require
an explicit protected-transport assertion, a bearer token of at least 32 bytes,
and a non-empty exact origin allowlist. Static console assets do not grant API
access; every REST and SSE request passes the same actor/capability checks as the
local adapter.

The local protocol is a length-prefixed UTF-8 JSON envelope. The length is one
canonical unsigned QUIC-style varint and counts the UTF-8 bytes of exactly one
JSON object. The maximum envelope is 1 MiB; a zero length, truncated prefix,
non-canonical varint, trailing bytes, or a larger object is rejected before
JSON allocation.

Every request has this shape:

```json
{
  "api_version": "1",
  "operation": "nodes.patch_labels",
  "request_id": "01JEXAMPLE",
  "actor": {"id": "local-admin", "capabilities": ["nodes:write"]},
  "expected_generation": {"scope": "configuration", "value": 12},
  "body": {"node_id": "provider-a-node-01", "set": {"admin.region": "jp"}, "remove": []}
}
```

Every response has `api_version`, the echoed `request_id`, a boolean `ok`, and
`observed_generation`. Success responses contain `result`; failures contain a
typed `error` object with `code`, safe `message`, and typed `details`:

```json
{
  "api_version": "1",
  "request_id": "01JEXAMPLE",
  "ok": false,
  "observed_generation": {"scope": "configuration", "value": 12},
  "error": {"code": "GENERATION_CONFLICT", "message": "generation mismatch", "details": {"expected": 11, "current": 12}}
}
```

`observed_generation` is the observation-provider generation captured for the
response. Resources expose their owning `generation` or `revision` as well.
Mutation preconditions use the explicit scope/value object and never infer a
scope from an integer.

## Resource model and queries

Stable opaque IDs are used for resources. List endpoints support bounded
`page_size` (default 100, maximum 1000), opaque `page_token`, a typed `filter`,
and a bounded `sort` field with an explicit ascending/descending direction.
Unknown filters, sort fields, and query parameters are rejected. A list result
contains `items`, `next_page_token` (null at end), and the response metadata.

The common list query grammar is:

```text
page_size   unsigned integer, 1..=1000; default 100
page_token  opaque token returned by the previous response
filter      registered typed filter object
sort        registered field name
direction   asc | desc; default asc
```

Unknown query keys, filter keys, sort fields, invalid tokens, and out-of-range
page sizes MUST return `VALIDATION_FAILED`. Resource responses MUST use typed
fields and include the owning generation or revision. The registered resource
fields are:

```text
status:         ingress.state, control_plane.state, runtime_snapshot.state,
                data_path_summary, configuration_generation, observation_generation
listeners:      id, kind, platform, bind, allowed_sources, authentication,
                state, generation, status.reason
sessions:       session_id, egress_id, state, ready_path_count,
                admission_generation, close_reason, created_at, last_change_at
connections:    connection_id, session_id, stream_id, listener_id, protocol,
                target_kind, state, bytes_sent, bytes_received, close_reason
subscriptions:  id, source_type, enabled, revision, state, last_refresh_at,
                next_refresh_at, imported_node_count, last_error
authorizations: ingress_id, egress_id, public_key, state, generation,
                active_path_count, active_session_count
system-proxy:   enabled, listener_id, platform_effect, environment_applied,
                operating_system_applied, restoration_state, error
```

Redacted values MUST be represented as `null` with a typed redaction reason.

Registered filter keys are bounded and resource-specific:

```text
nodes:          namespace, state, label.<key>, source.subscription
listeners:      kind, platform, state
sessions:       egress_id, state, admission_generation
connections:    listener_id, protocol, state, session_id
subscriptions:  enabled, state, source_type
authorizations: ingress_id, egress_id, state
paths/streams:  state, session_id, egress_id
```

Filter values use exact string, boolean, numeric equality, or registered
prefix matching; arbitrary expressions and unbounded regular expressions are
not part of the API. Sort fields are the stable fields shown for the resource
and MUST have a deterministic tie-break by opaque resource ID.

The REST query resources are:

```text
GET /api/v1/status
GET /api/v1/nodes
GET /api/v1/nodes/{node_id}
GET /api/v1/sessions
GET /api/v1/sessions/{session_id}
GET /api/v1/connections
GET /api/v1/listeners
GET /api/v1/subscriptions
GET /api/v1/authorizations
GET /api/v1/authorizations/{ingress_id}
GET /api/v1/system-proxy
GET /api/v1/metrics/snapshot
GET /api/v1/metrics/paths
GET /api/v1/metrics/streams
GET /api/v1/events (SSE)
```

Node responses preserve ownership namespaces:

```text
node.*       static identity and protocol attributes
source.*     imported subscription attributes
admin.*      local administrator labels/tags
observed.*   runtime-owned health and quality values
quota.*      provider quota metadata
```

Clients MUST NOT write `source.*`, `observed.*`, `quota.*`, or hard state
fields through label/tag operations. Hard states are typed values, not
overridable preference tags.

## Operation registry

The following operation names are normative; REST adapters map their resources
to the same operations:

```text
status.get
nodes.list             nodes.get
nodes.patch_labels     nodes.patch_tags
sessions.list          sessions.get
connections.list
listeners.list
subscriptions.list     subscriptions.create
subscriptions.delete   subscriptions.enable
subscriptions.disable  subscriptions.refresh
authorizations.list    authorizations.get
authorizations.enroll  authorizations.enable
authorizations.disable authorizations.revoke
authorizations.delete
metrics.snapshot       metrics.paths
metrics.streams         events.subscribe
system_proxy.get        system_proxy.enable
system_proxy.disable
```

Node patch bodies are complete operations, not arbitrary JSON merge patches:

```json
{
  "node_id": "provider-a-node-01",
  "set": {"admin.region": "jp"},
  "remove": ["admin.temporary"]
}
```

Subscription create/refresh bodies contain a source reference, validation
policy, enabled state, and current revision. A successful refresh publishes one
dynamic configuration generation; a failed refresh retains the last successful
snapshot and returns a typed failure. Delete drains nodes imported solely from
the source.

The canonical `subscriptions.create` body is:

```json
{
  "id": "provider-a",
  "display_name": "Provider A",
  "enabled": true,
  "source": {
    "type": "clash",
    "url": "https://example.invalid/subscription",
    "credentials_ref": "provider-a-token"
  },
  "refresh": {
    "interval_seconds": 3600,
    "timeout_seconds": 30,
    "max_attempts": 3,
    "backoff_seconds": 5
  },
  "cache": {
    "path": "provider-a.snapshot",
    "max_age_seconds": 86400
  }
}
```

`source.type` MUST be `static`, `clash`, or `sip008`; `source.url` MUST be an
HTTP(S) URL without embedded credentials; and `credentials_ref` MUST be an
opaque reference rather than a secret value. Refresh and cache fields use the
same bounds as the configuration schema. `cache` MAY be null. The list read
model returns these fields, but never resolves or returns the referenced secret.

The system-proxy switch is a runtime control-plane mutation, not a YAML
resource. `system_proxy.enable` MUST include `listener_id`, which MUST resolve
to an HTTP, SOCKS, or Mixed Listener. Windows applies that listener to environment and
operating-system proxy settings; `system_proxy.disable` restores the previous
values. Linux and FreeBSD return `UNSUPPORTED_OPERATION` for both activation
and disable and continue to expose ordinary listeners through `nodes` and status.

```text
GET  /api/v1/system-proxy
POST /api/v1/system-proxy/enable
     {"listener_id":"local-http"}
POST /api/v1/system-proxy/disable
```

The response and `system_proxy.changed` event include `enabled`, the selected
`listener_id` when present, platform effect, and restoration/error state. On
Linux and FreeBSD, `GET` returns `enabled: false` with `platform_effect: unsupported`.

Mutation success responses use this shape:

```json
{
  "api_version": "1",
  "request_id": "01JEXAMPLE",
  "ok": true,
  "observed_generation": {"scope": "observation", "value": 42},
  "result": {
    "applied_generation": {"scope": "configuration", "value": 13},
    "resource": {"id": "local-http", "state": "active"},
    "cleanup": {"paths": 0, "sessions": 0, "streams": 0, "target_connections": 0}
  }
}
```

Authorization and system-proxy mutations MUST include `cleanup` with non-negative
counts, including zeroes when no resources were affected.

Authorization operations use the Egress-owned store:

```text
POST   /api/v1/authorizations
POST   /api/v1/authorizations/{ingress_id}/enable
POST   /api/v1/authorizations/{ingress_id}/disable
POST   /api/v1/authorizations/{ingress_id}/revoke
DELETE /api/v1/authorizations/{ingress_id}
```

These REST routes are mounted only when the Web Gateway is attached to the
Egress authorization dispatcher. An Ingress Web Gateway deliberately omits
`/api/v1/authorizations*`; authorization remains an Egress-local operation and
must not be presented as an Ingress capability.

An enrollment body contains `ingress_id`, a 32-byte public key encoded as
lowercase base64url without padding, the canonical `egress_id`, optional admin
labels/limits, and `expected_generation`. Enable permits new Paths. Disable
and revoke both immediately reject new handshakes and terminate matching live
Paths, Sessions, Streams, UDP Associations, and Egress target connections.
Revoke is terminal for that record identity; delete removes the record only
after its live-resource cleanup has completed. Every authorization mutation
returns the applied generation, effective state, and a cleanup summary.

## Generation, idempotency, and errors

Mutable generations have one of three scopes: `configuration` for static and
dynamic policy snapshots, `observation` for runtime snapshots, and
`authorization` for the Egress authorization store. A mutation MUST carry an
`expected_generation` for its owning scope, or an explicitly authorized
`force` capability. A conflict publishes no partial change.

All mutations are idempotent by `(actor.id, request_id)`. Replaying the same
request returns the original response. Reusing a request ID with a different
canonical request body returns `IDEMPOTENCY_CONFLICT`. Idempotency records are
retained until the owning generation is superseded and for at least 24 hours,
whichever is longer.

Stable error codes are:

```text
MALFORMED_REQUEST       invalid envelope or JSON
AUTHENTICATION_REQUIRED missing or invalid actor authentication
CAPABILITY_DENIED       actor lacks the required capability
VALIDATION_FAILED       typed field or policy validation failed
NOT_FOUND               resource does not exist
GENERATION_CONFLICT     expected generation is stale
IDEMPOTENCY_CONFLICT    request ID was reused with a different body
RESOURCE_LIMIT          a bounded service resource was exhausted
PERSISTENCE_UNAVAILABLE durable store or audit sink is unavailable
UNSUPPORTED_OPERATION   operation or API version is not supported
```

REST maps these to `400`, `401/403`, `404`, `409`, `429`, and `500/503` as
appropriate. Local callers receive the same typed code. Error messages are
diagnostic only and never contain secrets, filesystem paths, peer-provided
arbitrary text, or complete request bodies.

## Authentication and audit

The local socket/pipe uses OS ownership and ACLs as the primary boundary. The
service assigns an actor and capabilities for every request. Standard
capabilities are `status:read`, `metrics:read`, `nodes:read`, `nodes:write`,
`listeners:read`, `subscriptions:write`, `authorization:write`, and
`system_proxy:write`.

Every mutation and authentication failure emits an audit event containing:

```text
event_id, timestamp, actor_id, source, operation, request_id,
target_resource, expected_generation, applied_generation, result, reason
```

Audit records contain identifiers and outcome metadata, not secrets or complete
request bodies. Authorization mutations fail closed if a durable audit write
cannot be completed; non-sensitive metadata operations report degraded status.

## Resource limits

The local service and Web Gateway MUST bound concurrent requests per actor and
globally, envelope/request/response sizes, refresh frequency and worker count,
SSE connections and replay backlog, page size, and label/tag cardinality and
key/value lengths. A limit breach returns `RESOURCE_LIMIT`/HTTP `429`, includes
a retry hint, and publishes no mutation.

## REST and SSE contract

REST uses JSON only for control-plane payloads. Status mapping is:

```text
200/201  successful query or mutation
400      malformed request or validation failure
401/403  authentication or capability failure
404      unknown resource
409      generation or idempotency conflict
429      rate/resource limit
500/503  unavailable persistence, audit, or service dependency
```

The canonical SSE event registry is shared with the observability
specification:

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

Each event contains `id`, `type`, `generation`, `emitted_at`, `resource_type`,
`resource_id`, and a typed `payload`. `generation` uses the same
`{scope,value}` form as response metadata; a resource payload MAY additionally
carry its own `revision`. Events are ordered per Ingress process.
`Last-Event-ID` either replays from the bounded buffer or causes a complete
snapshot event before new deltas. Query and event payloads use the same actor
authorization and redaction policy.
SSE connections use a separate bounded client budget. Producers MUST apply
backpressure rather than enqueue an unbounded per-client event stream, and MUST
send periodic comment heartbeats so dead clients release their budget.

## Explicit boundaries

The control plane does not replace data-Path `STATUS_REPORT`. That message is
used for Path/Session admission and remote health; local status and metrics are
structured views owned by the control service. Clients never edit a database,
configuration file, or subscription cache directly.

This document's operation registry is the authoritative management operation
set. The protocol specification defines only the transport boundary and
envelope; it does not define a second, smaller operation set.
