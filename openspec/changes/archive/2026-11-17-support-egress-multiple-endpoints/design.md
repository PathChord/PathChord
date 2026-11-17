# Design

## Context

See [proposal.md](proposal.md) for the motivation and user-visible scope. The
current Egress runtime owns one `TcpListener` and one `SocketAddr`; its
authorization snapshot binds one Egress ID to one public key. The Ingress
policy model likewise stores one Egress `Endpoint`, and Path establishment
passes that endpoint directly to the selected Transit Adapter. The existing
Session, Path, Noise, authorization, and aggregate Egress resource-limit
contracts are already shared across multiple Paths and Sessions.

The change must preserve that identity and resource ownership while adding
multiple transport attachment points. It must also preserve the current
singular configuration forms for existing deployments and keep the wire
protocol unchanged.

## Goals / Non-Goals

**Goals:**

- Normalize one EgressService into an ordered, bounded set of public listener
  binds and one Ingress Egress into an ordered, bounded set of reachability
  candidates.
- Make all Egress listeners feed one runtime so authorization generations,
  Session/Path state, wire budgets, and target-connection limits remain global.
- Select an endpoint independently for each Path with one bounded deadline and
  bounded candidate attempts, while retaining the selected endpoint for the
  lifetime of that Path.
- Keep singular `bind` and `address`/`port` configurations equivalent to
  one-element lists and reject ambiguous mixed forms.
- Provide bounded local endpoint and Path-selection observations without
  changing `STATUS_REPORT` or introducing high-cardinality metric labels.
- Keep endpoint topology static and restart-required, with atomic validation
  and no partially published listener set.

**Non-Goals:**

- Changing the Noise prologue, Egress ID, public-key authorization, Path,
  Session, Stream, UDP, or `STATUS_REPORT` wire layouts.
- Discovering endpoint ports through DNS SRV, URL records, or remote Egress
  advertisements; ports remain explicit configuration values.
- Migrating an already admitted Path or Stream to a different TCP connection.
- Creating independent Egress identities, policy snapshots, quotas, or
  authorization stores for individual listeners.
- Replacing Transit Adapter DNS behavior with a new global resolver or forcing
  every adapter to expose resolved A/AAAA addresses to Ingress.

## Decisions

### One shared Egress runtime owns all binds

`EgressNode` will hold a bounded ordered collection of listener sockets and a
matching collection of endpoint ordinals. Startup binds every socket before
the node is returned. Each listener acceptor submits `(endpoint_index, stream)`
to the shared path-admission supervisor; all accepted streams use the existing
authorization snapshot, Path semaphore, runtime map, target semaphore, status
provider, and wire budget.

At runtime, an acceptor failure records the affected endpoint as failed and
stops accepting on that socket while other acceptors continue. Shutdown joins
all acceptors and Path tasks. A bind failure during startup drops the sockets
already opened and returns one typed startup error, so the service never
advertises a partial initial topology.

This is preferred over one independent `EgressNode` per port because separate
nodes would split global limits, status, authorization cleanup, and Session
resource ownership. It also avoids relying on platform-specific dual-stack or
`SO_REUSEPORT` behavior.

### Use plural fields with singular compatibility shorthands

The typed policy model will add `binds: Vec<SocketAddr>` to the Egress service
configuration and `endpoints: Vec<Endpoint>` to the Ingress Egress model. The
deserializers retain the existing singular fields as mutually exclusive
shorthands and normalize them before validation and fingerprinting:

- `bind` becomes `binds = [bind]` when `binds` is absent.
- `address` plus `port` becomes `endpoints = [{address, port}]` when
  `endpoints` is absent.
- Supplying both singular and plural forms is a validation error.
- Lists are bounded at 32 entries, preserve order, and reject duplicate
  normalized values.

The CLI keeps `--bind` as a repeatable option so existing invocations remain
valid and multiple binds can be supplied without inventing a second flag. The
resolved service configuration carries the normalized list, while the default
bind still supplies one element when neither form is authored.

### Select an endpoint per Path, not per Session

`SessionSlot` will keep one endpoint cursor and bounded endpoint observations.
When a new Path is needed, it snapshots the endpoint list and starts at the
cursor, visiting each candidate at most once with wraparound. Each candidate
attempt receives the remaining Path connection deadline; the complete sequence
cannot extend that deadline. A successful authenticated Path records its
endpoint index and advances the cursor. A failed sequence advances the cursor
past the attempted range and returns the existing typed Path connection error.

The selected candidate is passed to the Transit Adapter as its hostname and
port. The adapter remains responsible for resolving a hostname and trying its
A/AAAA results. This preserves adapter-specific TLS, proxy, and DNS semantics,
while explicit candidates represent different ports. A Path that has been
admitted never swaps its socket to another candidate; recovery creates a new
PathID and may select a different endpoint.

This is preferred over selecting one endpoint for the whole Session because it
allows concurrent Paths to use IPv4, IPv6, and domain endpoints and lets one
failed public entry point drain without taking down healthy Paths.

### Keep identity and resource accounting independent from endpoint address

The Noise prologue continues to use the canonical Egress ID and the responder
key remains the Egress identity. The authorization store is opened once and
validated against that same pair. Endpoint index is runtime metadata only; it
is never put into the prologue, authorization key, Session identity, or Path
wire record.

All listeners share the existing Egress path-admission semaphore, target
connection semaphore, wire budget, authorization cleanup, and status provider.
Endpoint-specific failure counters are separate observations, while capacity,
admission, and target counts remain aggregate Egress values.

### Keep endpoint details local to operational views

Ingress Path resources and Egress local runtime resources will carry a bounded
endpoint ordinal. The normalized endpoint inventory can be returned to an
authorized local operator under existing redaction rules. Prometheus output
continues to use aggregate Egress gauges without endpoint hostname or port
labels, and authenticated `STATUS_REPORT` remains unchanged.

The ordinal is assigned from the normalized configuration generation, so it is
stable while that topology is active. Reordering or changing the endpoint list
requires restart and may assign new ordinals, which is reported as a static
topology change rather than an in-place endpoint mutation.

### Alternatives considered

- **Separate Egress resource IDs for each endpoint:** rejected because it
  creates separate Session pools and identities and prevents the requested
  one-ID behavior.
- **External DNS or TCP load balancer only:** useful as a deployment
  workaround, but it cannot provide PathChord endpoint health, different
  explicit ports in one topology, or per-Path endpoint observations.
- **A single wildcard or dual-stack socket:** insufficient for different
  ports and varies by operating-system dual-stack defaults.
- **Advertise endpoint lists over the wire:** rejected because reachability is
  local Ingress configuration, and changing the wire contract is unnecessary
  for shared Egress identity.

## Risks / Trade-offs

- [OS dual-stack bind behavior] Binding `[::]:port` may consume the IPv4 port
  on some hosts. → Attempt every bind explicitly, fail atomically on conflict,
  and document explicit IPv4/IPv6 binds for portable deployments.
- [Endpoint list increases connection-attempt work] A failed Path could try up
  to 32 candidates. → Bound the list, share one deadline, attempt each
  candidate at most once per Path admission, and retain the existing Path
  admission semaphore.
- [Transit adapters resolve hostnames differently] Some adapters resolve the
  Egress hostname locally while others pass it through a proxy. → Keep endpoint
  host/port opaque to Ingress and retain adapter ownership of resolution; test
  direct, HTTP CONNECT, SOCKS5, and relevant native adapters separately.
- [A listener can fail after startup] One public endpoint may stop accepting
  while the process remains healthy. → Track per-endpoint failed/draining
  state, keep other acceptors running, and make Session state depend on ready
  Paths rather than listener presence alone.
- [Endpoint observations can become high cardinality] Hostnames and failure
  text are operator-sensitive and unsuitable as metric labels. → Use bounded
  endpoint ordinals and typed reasons in local views, aggregate metrics, and
  keep wire status endpoint-agnostic.
- [Static topology changes require coordinated restart] Adding a port is not a
  hot reload. → Validate the complete candidate before publication, report
  restart required, and retain the running topology until the service restarts.

## Migration Plan

1. Deploy the implementation with existing singular `bind` and
   `address`/`port` configuration. The normalized runtime must be behaviorally
   identical to the current one-listener/one-endpoint service.
2. Add extra Egress binds and matching Ingress endpoint candidates in a
   controlled configuration generation. Keep the same Egress ID, keypair,
   public key, authorization database, Transit binding, and TrafficPolicy.
3. Restart Egress first so every configured public bind is available, then
   restart Ingress so its static endpoint topology is captured. Validate local
   endpoint inventory and Path observations before routing production traffic.
4. To roll back, remove the plural fields, restore the singular forms, and
   restart both roles. Authorization data and the Egress identity remain the
   same throughout the rollback.

## Open Questions

None. The endpoint cardinality, compatibility normalization, selection scope,
identity ownership, and observability boundaries are fixed by the proposal and
delta specifications.
