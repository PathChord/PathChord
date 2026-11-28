# PathChord monitoring deployment

This directory contains a small Prometheus and Grafana deployment for the
authenticated PathChord Web Gateway. It is intended for local Docker evidence
and for adapting the same scrape and alert rules to an operator's monitoring
environment.

The stack expects a PathChord Web Gateway on host port `18090` with a bearer
token in the state directory. The PathChord process reads a private `token`
file; Prometheus reads a same-value `prometheus.token` copy for `/metrics`.
Grafana uses the provisioned Prometheus datasource and dashboard. The current
snapshot gauges and bounded observation totals are shown separately. The
`stream_bytes_*` values are snapshot gauges, not lifetime counters.

Run the complete local deployment smoke from the repository root:

```sh
scripts/monitoring-smoke.sh
```

The smoke starts `pathchord-ingressd` with `monitoring/ingress.yaml`, starts
Prometheus and Grafana with Docker Compose, waits for the target scrape, checks
Prometheus rules and queries, checks the Grafana health/datasource/dashboard
APIs, and waits for the configured local TCP probe to produce an observation.

When upgrading a deployment that uses the Grafana 11 data volume, back up
the Grafana database before starting Grafana 13. Grafana migrates dashboards
and folders to unified storage on startup. Restoring that backup lets you
roll back to Grafana 11. [Grafana migration guide](https://grafana.com/docs/grafana/latest/upgrade-guide/upgrade-v13/upgrade-v13.0/#unified-storage-for-folders-and-dashboards)

For an interactive stack, create a state directory containing a token, then
start the stack after starting PathChord with the same token:

```sh
umask 077
state_dir=$(mktemp -d /tmp/pathchord-monitoring.XXXXXX)
head -c 32 /dev/urandom | base64 | tr -d '\n' > "$state_dir/token"
cp "$state_dir/token" "$state_dir/prometheus.token"
chmod 0644 "$state_dir/prometheus.token"
PATHCHORD_MONITORING_STATE="$state_dir" docker compose -f monitoring/docker-compose.yml up -d
```

Prometheus is available at `http://127.0.0.1:19090` and Grafana at
`http://127.0.0.1:13000` with the local smoke credentials. Do not reuse those
credentials outside the local deployment.
