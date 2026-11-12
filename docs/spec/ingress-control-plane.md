# Ingress control plane specification

This document defines the local control plane used to operate Ingress and the
optional web gateway used by a frontend. It is separate from the PathChord data
Path. It covers node label/tag edits, subscription lifecycle operations, manual
refresh, and structured node/connection queries.

The control plane is an adapter over a typed internal command/query service. A
CLI, a local web gateway, and future automation clients use the same service;
they MUST NOT edit configuration files, caches, or databases directly.

The Phase-1 foundation provides this service as a bounded in-memory component;
the local JSON adapter, persistence, subscription worker, and Web Gateway are
separate follow-up integrations over the same interface.

## Architecture

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

The privileged local adapter is:

```text
Linux    Unix domain socket
Windows  named pipe
```

The operating-system owner/ACL of the socket or pipe is the first authorization
boundary. The local protocol uses the existing length-prefixed UTF-8 JSON
envelope with API version, operation name, request ID, and typed body.

The web gateway is optional and MUST be a separate process/task boundary from
the data Path. It MAY bind to loopback by default. If it binds beyond loopback,
it MUST require explicit configuration, TLS or an equivalent protected channel,
strong authentication, an origin allowlist, and an administrator-visible audit
record for the exposure.

The web gateway calls the same typed service as the CLI. It MUST NOT expose the
Unix socket or named pipe directly to a browser, and it MUST NOT be reachable
through a Transit Proxy or Egress data Path.

Phase 1 requires only the local Unix socket/named-pipe adapter. The web gateway
is an optional follow-up adapter once the local command/query service and its
redaction, audit, and generation semantics are stable.

## API adapter choice

The first web adapter is REST plus Server-Sent Events (SSE):

| Option | Strengths | Costs | Decision |
|---|---|---|---|
| REST + SSE | Simple resource URLs, native HTTP caching/status codes, easy CLI and browser tooling, one-way live updates fit metrics/events | Separate endpoint types and some client-side composition | **First future web adapter** |
| GraphQL queries/mutations + subscriptions | Flexible frontend selection sets, one schema for varied views, fewer round trips for dashboards | More complex authorization, subscription lifecycle, caching, persisted-query and DoS controls | Defer until multiple clients prove the need |

GraphQL is not prohibited. A later adapter MAY map the same typed command/query
service to GraphQL queries, mutations, and subscriptions. The internal service
and generation semantics MUST remain independent of the external adapter.

## Resource model

All responses include `api_version`, `request_id`, and `observed_generation`.
Resources use stable opaque IDs and expose a `generation` or `revision` where
updates can race.

Phase 1 resources are:

```text
GET  /api/v1/status
GET  /api/v1/nodes
GET  /api/v1/nodes/{node_id}
GET  /api/v1/sessions
GET  /api/v1/sessions/{session_id}
GET  /api/v1/connections
GET  /api/v1/subscriptions
GET  /api/v1/metrics/snapshot
GET  /api/v1/events              (SSE)
```

Node responses separate namespaces and ownership:

```text
node.*       static identity and protocol attributes
source.*     imported subscription attributes
admin.*      local administrator labels/tags
observed.*   runtime-owned health and quality values
quota.*      provider quota metadata
```

The API MUST preserve the distinction between imported, administrator-owned,
and runtime-owned data. A client cannot write `observed.*` or `quota.*` through
the label mutation endpoint. Hard states such as revoked, disabled, or
disconnected are returned as typed state, not as an overridable preference tag.

## Commands and mutations

Mutations are commands submitted to the typed service. Each command carries a
client `request_id`, actor identity, and optional expected generation.

Node metadata:

```text
PATCH /api/v1/nodes/{node_id}/labels
PATCH /api/v1/nodes/{node_id}/tags
```

The body contains a complete operation, not an arbitrary JSON merge:

```json
{
  "expected_generation": 12,
  "set": {"admin.region": "jp"},
  "remove": ["admin.temporary"]
}
```

Setting an imported or runtime namespace is rejected. A successful mutation
atomically publishes a new snapshot generation and returns the changed fields.

Subscription lifecycle:

```text
POST   /api/v1/subscriptions
DELETE /api/v1/subscriptions/{subscription_id}
POST   /api/v1/subscriptions/{subscription_id}/refresh
```

`POST /subscriptions` creates a disabled-or-enabled subscription according to
the request, validates its source and policy, and publishes one generation.
Delete removes the subscription from future refreshes and moves its imported
nodes into the documented draining behavior. Refresh is explicit and MAY also
be scheduled by the worker; a failed refresh retains the last successful
snapshot.

All mutations are idempotent by `(actor_id, request_id)`. Replaying an identical
request returns the original result. Reusing a request ID with a different body
is rejected. A mutation that changes an authorization or hard runtime state MUST
return the resulting state and the affected Session/Path cleanup summary.

## Generation and concurrency

Every mutable snapshot has a monotonically increasing generation. A command that
changes a snapshot MUST include either:

- `expected_generation`, which must equal the currently published generation; or
- an explicit `force` capability granted only to an authorized administrator.

An expected-generation mismatch returns HTTP `409 Conflict` in REST and a
typed `GENERATION_CONFLICT` error in the local JSON protocol. The response
contains current generation, requested generation, and a fresh resource summary.
No partial mutation is published on conflict, validation failure, or persistence
failure.

Static Egress topology and local key material remain restart-required. Dynamic
Transit data, administrator labels/tags, and compiled policy snapshots publish
atomically. Existing Sessions retain their admission generation except for hard
revocation or Egress failure.

## Authentication and audit

The local socket/pipe uses OS ownership and ACLs as the primary authorization
boundary. The service still assigns an actor identity and capability set to each
request. Suggested capabilities are:

```text
status:read
metrics:read
nodes:read
nodes:write
subscriptions:write
authorization:write
```

The web gateway MUST require an authenticated administrator session. A browser
session MUST use CSRF protection for mutations, an origin allowlist, bounded
request bodies, and strict content types. Tokens, private keys, subscription
URLs, raw authorization records, and unredacted target data MUST NOT appear in
responses, SSE events, or audit records.

Every mutation and authentication failure produces a structured audit event:

```text
event_id, timestamp, actor_id, source, operation, request_id,
target_resource, expected_generation, applied_generation, result, reason
```

Audit records contain identifiers and outcome metadata, not secrets or complete
request bodies. Audit writes SHOULD be durable before a successful mutation
response; if the audit sink is unavailable, the service follows an explicit
fail-closed policy for authorization mutations and reports degraded status for
non-sensitive metadata operations.

## Rate and resource limits

The gateway and local service MUST bound:

- concurrent requests per actor and globally;
- request body and response sizes;
- subscription refresh frequency and concurrent refresh workers;
- SSE connections, event backlog, and per-client replay window;
- node label/tag cardinality and key/value lengths.

Rate-limit responses use HTTP `429` with a retry hint. Local callers receive a
typed `RESOURCE_LIMIT` error. A limit breach MUST NOT mutate a snapshot or
silently drop a successful command.

## REST and SSE conventions

REST uses JSON for control-plane payloads only. The data Path remains the
dedicated binary frame protocol. REST status mapping is:

```text
200/201  successful query or mutation
400      malformed request or validation failure
401/403  authentication or capability failure
404      unknown resource
409      generation or idempotency conflict
429      rate/resource limit
500/503  unavailable persistence or service dependency
```

SSE starts with a snapshot event and then emits ordered events with an event ID
and generation. A client reconnects with `Last-Event-ID`; if the replay window
does not contain that event, the server sends a fresh snapshot before deltas.
Events are typed (`node.changed`, `subscription.refresh`, `session.changed`,
`connection.changed`, `metrics.snapshot`, `audit.notice`) and are redacted for
the requesting actor.

## Explicit boundaries

The control plane does not replace data-Path `STATUS_REPORT`. `STATUS_REPORT` is
a compact Egress-to-Ingress protocol message used for Path/session admission and
remote health. Control-plane status and metrics are local structured views that
may combine runtime observations, policy generations, subscription state, and
connection details. They must not be tunneled through or inferred solely from
data-Path messages.
