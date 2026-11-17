# Proposal

## Why

Path selection currently depends on flow-matched TransitRules and per-EgressRule Path requirements, so one Session must reconcile several candidate sets, minimums, and traffic policies. Routing should select an Egress, while that Egress's Ingress-side configuration supplies one shared Path pool and one TrafficPolicy for all of its business traffic.

## What changes

- **BREAKING**: Retire TransitRule resources and EgressRule `requirements`. Egress rules retain flow matching and Egress selection but cannot select Transit nodes, Path subsets, or traffic policies.
- Add an explicit `Egress.spec.transit` binding and a required `trafficPolicyRef`; use the existing `statusRequirements.minUsablePaths` as the single Egress Path admission minimum. Transit selection, warmup, and Path counts no longer depend on a business-flow match.
- Maintain one Path pool per Ingress-to-Egress Session. Aggregate upstream and downstream demand at Session scope, preserving bounded sampling, hysteresis, relationship weighting, draining, and hard resource ceilings.
- **BREAKING**: Use one immutable TrafficPolicy snapshot per Session and a shared replication allowance per sending direction across its flows and Paths. Retire public traffic-class selection and class policy fields rather than accepting inactive configuration.
- Treat the Egress Path binding and its resolved TrafficPolicy definition as startup configuration. Subscription and node-metadata updates continue to replace candidate snapshots dynamically and drain removed Paths.
- **BREAKING**: Retain the existing Session-control wire layout but require new Stream and UDP opens to use the whole Session Path pool. Explicit per-flow eligible-Path lists are rejected before target admission; opaque cancellation and control sequencing remain supported.
- Publish Session-level pool, policy, demand, and replication observations, and remove business traffic-class fields from observations.
- Reconcile the canonical detailed contracts, paired English/Chinese specifications, architecture, configuration guides, and examples during implementation.

## Capabilities

### New capabilities

None. This change simplifies existing routing, Session, and scheduling contracts.

### Modified capabilities

- `configuration`: Egress-only route decisions, shared Path eligibility, unconditional Egress warmup, Session demand, and one TrafficPolicy per Egress.
- `configuration-schema`: Egress Transit binding and policy reference, retired routing/class fields, complete-bundle validation, and restart-required policy changes.
- `state-machines`: One Session Path target and replication policy, aggregate directional demand, and degraded admission below the Egress minimum.
- `protocol`: Common Session Path eligibility, shared replication accounting, and reliable control without per-flow Path restrictions.
- `wire-profile`: Whole-pool semantics and explicit rejection of non-empty eligible-Path lists, preserving registered layouts and identifiers.
- `observability`: Session Path-pool and uniform-policy observations in place of rule/class scheduling state.

## Impact

The affected Rust areas are `pathchord-policy` resource parsing, validation and compilation; `pathchord-ingress` Session warmup, route admission, reload checks and autoscaling; `pathchord-path` scheduling, replication and control eligibility; and Egress handling of Session control. The CLI, Web Gateway and observation producers must expose the resulting typed model consistently. No new transport backend, external dependency, enrollment mechanism, or wire field is required.

Existing configurations require explicit migration. This change must not guess a merged Transit binding when old flow-specific rules disagree. Ordinary Proxy routing, explicit global fallback, native UDP boundaries, authorization, independent per-Path Noise state, and pre-admission-only Egress failover remain required.

The completed per-policy/class work in `complete-scheduling-and-observability` is historical implementation evidence, not the target model for this change; its remaining deployed-monitoring tasks remain separate. This proposal does not complete those tasks or the external-protocol validation changes.
