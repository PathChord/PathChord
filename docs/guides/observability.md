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
