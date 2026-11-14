# Tasks

These pending tasks were carried over from the implementation plan during the
2026-11-14 documentation migration; their presence supplies no completion evidence.

## 1. Scheduling and accounting

- [ ] 1.1 Implement independent per-policy/class replication accounting and budget release across flow lifecycles; add deterministic mixed-policy tests proving reserved control traffic and business copies stay within limits.
- [ ] 1.2 Coordinate the Egress replication limit before enabling extra copies, adding normative deltas first if a wire extension is required; verify bidirectional budget enforcement and conservative behavior with absent or mismatched support.
- [ ] 1.3 Connect congestion-window, marginal-capacity and scheduling-overhead measurements only from transports that expose them; verify unknown values stay unknown and autoscaling respects hysteresis and draining guards.

## 2. Typed observations and monitoring

- [ ] 2.1 Supply available typed timing, Path/Session admission, Transit identity and source-namespace producers; verify management/observation regressions and explicit nulls for unavailable fields against the existing contract.
- [ ] 2.2 Check bounded SSE recovery snapshots against control-generation consistency requirements; verify gaps/resync behavior with concurrent mutations and document any unresolved consistency limitation.
- [ ] 2.3 Connect authenticated Prometheus and structured observations to deployed monitoring, alerts and dashboards; verify live gauges remain distinct from historical counters with a real scrape and alert/dashboard smoke test.
- [ ] 2.4 Measure production probe/autoscaler constants and record local regression versus deployed evidence in openspec/implementation-status.md; verify no fixture constant is presented as a production measurement.
