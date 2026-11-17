# Design

## Context

The [status snapshot](../../implementation-status.md#shared-implementation-gaps) records Session-wide strictest-seen budgets, suppressed Egress extra copies, optional measurements without default producers, and null management detail fields. The [state-machine contract](../../specs/state-machines/spec.md#scheduler-and-autoscaling-guards) and [observability contract](../../specs/observability/spec.md) define the intended behavior.

## Goals / non-goals

Complete existing budget, typed-observation and monitoring contracts. Do not invent idle-throughput estimates for congestion window, marginal capacity or scheduling overhead. Preserve null/unknown fields when a source cannot measure them.

## Decisions

Implement independently accounted policy/class budgets and lifecycle release, including reserved control traffic. Coordinate the Egress limit before permitting additional copies; ordinary reliability retransmission must continue under conservative limits. If coordination requires a wire extension not already specified, remove skip_specs and author protocol/wire-profile/state-machine deltas before coding that extension.

Add typed producers for listener-independent timing, Path/Session admission timestamps, Transit identity and compiled source namespace where the runtime can supply them. Review recovery snapshot consistency at the same service boundary. Export through the existing authenticated observation/Prometheus surface, then connect deployed monitoring, alerts and dashboards. Measure probe/autoscaler constants on the deployment rather than promoting local fixture values.

For this validation run, the user-authorized local Docker Compose monitoring
stack is the deployed target. Its scrape, alert, dashboard, and probe results
are recorded as deployment evidence and remain explicitly separate from a
production capacity or SLO claim.

## Risks / trade-offs

- Relaxing Session-wide limits too early can exceed a policy → retain conservative replication until both directions enforce the agreed limit.
- Synthetic measurements imply false capacity → leave unsupported measurements unknown and test missing-value paths.
- Dashboard setup is not endpoint correctness → retain separate local regression and deployed monitoring evidence.
