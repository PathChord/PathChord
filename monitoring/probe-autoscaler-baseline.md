# Local deployment baseline

This file records the constants and evidence from the local Docker monitoring
deployment. It is deployment evidence for regression and smoke testing; it is
not a production capacity measurement.

The Docker smoke ran on 2026-11-17 with Prometheus `v2.55.1` and Grafana
`11.3.0`. It observed `up=1`, loaded the recording and alerting rules, found
the provisioned Grafana datasource and dashboard, and observed a firing
`PathChordMetricsMissing` alert after stopping the PathChord process. The local
TCP probe reached its loopback target and reported `0 ms`; integer millisecond
rounding makes this a sub-millisecond loopback result, not a network latency
estimate.

The Path autoscaler defaults are:

| Constant | Value |
| --- | ---: |
| `min_paths` | `1` |
| `max_paths` | `4` (Ingress Session slots raise this to at most `8`) |
| scale-out utilization | `8000` basis points |
| scale-in utilization | `3500` basis points |
| scale-out samples | `3` |
| recovery samples | `3` |
| scale-in samples | `6` |
| scale-in cooldown | `30000 ms` |
| maximum autoscaler decision frequency | `1` per `5000 ms` |

The `NodeProbePolicy` defaults are interval `30 s`, timeout `5 s`, maximum
concurrency `8`, window size `32`, and batch size `128`. The monitoring smoke
uses a deliberately smaller local policy (`1 s`, `1 s`, concurrency `1`, window
`4`, batch `1`) so a probe transition is visible during the short run.

Deterministic autoscaler regressions passed the scale-out, scale-in, recovery,
capacity-overhead exclusion, reset, and reserve-target cases. The smoke also
checks the authenticated Prometheus scrape, unauthorized rejection, live gauge
types, recording rule, an actually firing alert, Grafana datasource, provisioned
dashboard, and the probe observation after the local target accepts TCP
connections.
