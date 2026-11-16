# Proposal

## Why

An Egress currently exposes one public Path listener and each Ingress-side
`Egress` resource carries one `address`/`port` pair. A DNS name can resolve to
both IPv4 and IPv6 addresses when they use the same port, but the configuration
cannot express different ports, multiple public names, or independent endpoint
failover under one Egress identity. This makes dual-stack deployments,
port-specific firewall exposure, and migrations between public entry points
depend on an external TCP fan-in layer.

## What Changes

- Extend `EgressService` to configure multiple public Path listener binds in one
  Egress process. All binds share the same Egress identity, authorization store,
  Session/Path runtime, aggregate wire budget, and target-connection limit.
- Extend the Ingress-side `Egress` topology to contain an ordered, bounded list
  of endpoint candidates. Each candidate may use an IP literal or hostname and
  its own port, so one Egress ID can be reached through IPv4, IPv6, and named
  endpoints with different ports.
- Preserve the existing singular `bind` and `address`/`port` forms as
  one-element shorthand. Supplying a singular form together with its plural
  form is invalid; normalization produces one canonical endpoint list.
- Let each Path select and retain its own Egress endpoint. Candidate failure is
  retried within bounded connection admission limits, while an established
  Path remains associated with the endpoint it used until it drains or fails.
- Bind all configured Egress listeners as one startup transaction. A partial
  listener set is not published when any bind fails, and listener-topology
  changes remain restart-required static configuration.
- Keep the existing Noise identity and per-Path authentication contract. The
  listener address, port, or hostname does not create a new Egress identity or
  bypass authorization.
- Expose bounded endpoint-count, endpoint-selection, and endpoint-failure
  observations through the local operational views without adding endpoint
  details to Prometheus labels or the authenticated wire status layout.
- Add configuration examples, bilingual capability-spec deltas, migration
  guidance, deterministic endpoint failover tests, multi-bind tests, and
  IPv4/IPv6/domain endpoint coverage.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `configuration-schema`: add plural Egress service binds and Ingress Egress
  endpoint candidates, including normalization, bounds, uniqueness, and
  restart/failure semantics.
- `configuration`: define endpoint candidate selection per Path while keeping
  one Session Path pool and one Egress identity.
- `state-machines`: distinguish failure of one configured endpoint from loss of
  the whole Egress relationship and preserve existing Session retirement rules.
- `observability`: expose bounded endpoint-aware runtime observations while
  preserving global Egress status and privacy/cardinality constraints.

## Impact

The change affects `pathchord-policy` configuration models and validation,
`pathchord-config` service parsing, the Egress daemon's listener ownership and
accept loop, Ingress `SessionSlot` Path dialing and retry state, endpoint-aware
control-plane views, examples, and the English/Chinese configuration,
configuration-schema, state-machine, and observability contracts. The Noise,
Session, Path, Stream, and authorization wire layouts remain unchanged.
