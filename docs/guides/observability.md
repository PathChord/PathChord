# Runtime observability

[简体中文](observability.zh-CN.md)

PathChord exposes live runtime state through the local control socket. Use
pathchordctl get diagnostics -o json with an actor that has metrics:read.
The response includes the process instance, retained Path termination records,
reason counters, and producer loss counters.

Use pathchordctl export-diagnostics --output /path/to/diagnostics.json to
write a bounded, redacted JSON snapshot for offline comparison. Collect one
file from Ingress and one from Egress, then correlate admitted records by
session_id and path_id. Each role reports its own observed trigger.

When a record list is empty, inspect expired, evicted, and producer_drops.
A nonzero value means the absence of a record does not prove that the stage
was never reached. Prometheus exposes pathchord_path_terminations_total and
pathchord_diagnostic_records_dropped_total when the authenticated Web
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
