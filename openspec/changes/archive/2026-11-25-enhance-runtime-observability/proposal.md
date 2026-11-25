# Enhance runtime observability

## Why

A deployed model transfer repeatedly lost Paths while the two services exposed aggregate state and the remote TCP send queue showed pending data. Diagnosis across future incidents needs evidence that follows work from listener and policy selection through Transit, Session, and target I/O, including setup failures and the decisions made during recovery.

## What changes

- Correlate typed lifecycle and failure observations across Ingress and Egress using existing Session, Path, and Stream identifiers.
- Add bounded drill-down for listener acceptance, policy and DNS, subscription and adapter preparation, Transit and Path establishment, Session and scheduling, target TCP/UDP, and service resource limits.
- Make recent diagnostics and live snapshots available via role-local management. Use the Web Gateway for authorized event replay and Prometheus for bounded counters and latency distributions.
- Provide opt-in, time-limited diagnostic capture for intermittent incidents and a troubleshooting workflow that works with ordinary deployed packages.
- Expose producer coverage, replay gaps, and process identity so operators can interpret partial histories and counter resets.
- Attribute stalled progress to the measured queue or flow-control boundary and provide a bounded, redacted diagnostic export for offline comparison.

## Capabilities

### Modified capabilities

- `observability` gains staged diagnostic records, cross-role correlation, retention, capture controls, and aggregate metrics.
- `ingress-control-plane` defines authorized diagnostic queries and capture control for Ingress and Egress.
- `deployment` defines discoverable command-line access to those operations on deployed services.

## Impact

Ingress and Egress runtimes, Transit adapters, the Session runtime, local control, Web Gateway, CLI, and monitoring are affected. The change uses existing authenticated wire identifiers and local instrumentation.
