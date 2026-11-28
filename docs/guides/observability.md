# Runtime observability

[简体中文](observability.zh-CN.md)

Use an actor with `metrics:read` to query diagnostics over the local control
socket. The response includes the process instance, retained Path termination
records, reason counters, and producer loss counters. On the Ingress host, run
the following commands to view diagnostics and export a bounded, redacted JSON
snapshot. These examples use the packaged Linux socket paths. Substitute the
configured socket if your deployment uses a different path.

```sh
pathchordctl --socket /run/pathchord/ingress.sock get diagnostics -o json
pathchordctl --socket /run/pathchord/ingress.sock export-diagnostics --output ingress-diagnostics.json
```

On the Egress host, export its snapshot using the Egress control socket.

```sh
pathchordctl --socket /run/pathchord/egress.sock export-diagnostics --output egress-diagnostics.json
```

In the exported files, the Ingress records are under
`response.result.diagnostics.records` and the Egress records are under
`response.result.path_diagnostics.records`. Match admitted Path records by
`ids.session_id` and `ids.path_id` to see the trigger each role observed.

When a record list is empty, inspect `expired`, `evicted`, and `producer_drops`.
A nonzero value means the absence of a record does not prove that the stage
was never reached. Prometheus exposes `pathchord_path_terminations_total` and
`pathchord_diagnostic_records_dropped_total` when the authenticated Web
Gateway is enabled.

## Detailed service logs

The service reads `PATHCHORD_LOG_LEVEL` at startup. It defaults to `info`.
Each level includes the levels above it in the table.

| Level | Events |
| --- | --- |
| `fatal` | Startup or runtime failures that make the service exit unsuccessfully |
| `error` | Listener failures and failed Sessions |
| `warn` | Path failures, failed connection or admission attempts, DNS and Stream I/O failures, retained subscription data after a failed refresh, and log queue loss |
| `info` | Service readiness and shutdown, listener start and stop, and orderly Session and Path closure |
| `debug` | Routing decisions, connection lifecycle, successful admission and target setup, and routine DNS and subscription outcomes |
| `trace` | Frame metadata, carrier writes, scheduling, retransmission, flow control, and DNS cache outcomes |
| `off` | Disables service log output |

For systemd, set
`Environment=PATHCHORD_LOG_LEVEL=trace` in a `[Service]` drop-in and
read the journal with `journalctl -u pathchord-ingressd -f` or
`journalctl -u pathchord-egressd -f`. For OpenRC, put
`export PATHCHORD_LOG_LEVEL=trace` in the corresponding
`/etc/conf.d/pathchord-ingressd` or `/etc/conf.d/pathchord-egressd`
and read the role-specific `service.log`.

DEBUG records listener, policy and DNS outcomes, subscription refreshes,
Path establishment and termination, and Stream connect and close events.
TRACE also records frame numbers and types, data offsets and byte counts,
ACK ranges, scheduler choices, retransmissions, flow-control limits, and
carrier write timings and outcomes. Correlate the two services using the
Session and Path IDs. Ingress includes the Transit Proxy ID, display name,
subscription ID, protocol, and chosen Egress endpoint index when available.
Egress can identify its local listener index.

JSON records go to stderr. The process exposes `log_drops` in its diagnostic
summary and emits `diagnostic_log_loss` when the sink can report queue loss.
The service's log manager controls retention. Detailed logs contain metadata
and omit credentials, keys, payload bytes, and raw peer error text.
