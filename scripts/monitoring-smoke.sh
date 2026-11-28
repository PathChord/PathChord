#!/bin/sh
set -eu

root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
state_dir=$(mktemp -d "${TMPDIR:-/tmp}/pathchord-monitoring.XXXXXX")
compose_project="pathchord-monitoring-$(printf '%s' "${state_dir##*pathchord-monitoring.}" | tr '[:upper:]' '[:lower:]')"
ingress_pid=''
target_pid=''

start_ingress() {
	"$root_dir/target/debug/pathchord-ingressd" \
		--socket "$state_dir/ingress.sock" \
		--ingress-id monitoring \
		--config "$root_dir/monitoring/ingress.yaml" \
		--data-dir "$state_dir/data" \
		--credentials-dir "$state_dir/secrets" \
		--web-bind 0.0.0.0:18090 \
		--web-token-file "$state_dir/token" \
		--web-origin http://localhost \
		--web-protected-transport \
		>>"$state_dir/ingress.log" 2>&1 &
	ingress_pid=$!
}

cleanup() {
	COMPOSE_PROJECT_NAME="$compose_project" PATHCHORD_MONITORING_STATE="$state_dir" docker compose -f "$root_dir/monitoring/docker-compose.yml" down --volumes --remove-orphans >/dev/null 2>&1 || true
	[ -z "$ingress_pid" ] || kill "$ingress_pid" 2>/dev/null || true
	[ -z "$target_pid" ] || kill "$target_pid" 2>/dev/null || true
	[ -z "$ingress_pid" ] || wait "$ingress_pid" 2>/dev/null || true
	[ -z "$target_pid" ] || wait "$target_pid" 2>/dev/null || true
	python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1], ignore_errors=True)' "$state_dir"
}
trap cleanup EXIT HUP INT TERM

umask 077
mkdir -p "$state_dir/data" "$state_dir/secrets"
head -c 32 /dev/urandom | base64 | tr -d '\n' > "$state_dir/token"
cp "$state_dir/token" "$state_dir/prometheus.token"
chmod 0644 "$state_dir/prometheus.token"

if [ ! -x "$root_dir/target/debug/pathchord-ingressd" ]; then
	cargo build --locked -p pathchord-ingressd
fi

python3 - <<'PY'
import socket

for port in (13000, 18081, 18090, 19090):
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
            sock.listen()
        except OSError:
            raise SystemExit(f"monitoring smoke requires free loopback port {port}")
PY

python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 18081)); s.listen(); [s.accept()[0].close() for _ in iter(int, 1)]' >"$state_dir/target.log" 2>&1 &
target_pid=$!

start_ingress

token=$(cat "$state_dir/token")
for _ in $(seq 1 120); do
	if curl --fail --silent -H "Authorization: Bearer $token" http://127.0.0.1:18090/metrics >/dev/null 2>&1; then
		break
	fi
	sleep 0.1
done
unauthorized_status=$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:18090/metrics)
[ "$unauthorized_status" = 401 ]
curl --fail --silent --show-error -H "Authorization: Bearer $token" http://127.0.0.1:18090/metrics > "$state_dir/direct.metrics"
grep -q '^# TYPE pathchord_active_sessions gauge$' "$state_dir/direct.metrics"
grep -q '^# TYPE pathchord_stream_bytes_sent gauge$' "$state_dir/direct.metrics"
if grep -q '^# TYPE pathchord_stream_bytes_sent counter$' "$state_dir/direct.metrics"; then
	echo 'snapshot byte totals were incorrectly exported as counters' >&2
	exit 1
fi

COMPOSE_PROJECT_NAME="$compose_project" PATHCHORD_MONITORING_STATE="$state_dir" docker compose -f "$root_dir/monitoring/docker-compose.yml" up -d >/dev/null

for _ in $(seq 1 120); do
	if curl --fail --silent http://127.0.0.1:19090/-/ready >/dev/null 2>&1; then
		break
	fi
	sleep 0.25
done
curl --fail --silent http://127.0.0.1:19090/-/ready >/dev/null

COMPOSE_PROJECT_NAME="$compose_project" PATHCHORD_MONITORING_STATE="$state_dir" docker compose -f "$root_dir/monitoring/docker-compose.yml" exec -T prometheus promtool check config /etc/prometheus/prometheus.yml >/dev/null
COMPOSE_PROJECT_NAME="$compose_project" PATHCHORD_MONITORING_STATE="$state_dir" docker compose -f "$root_dir/monitoring/docker-compose.yml" exec -T prometheus promtool check rules /etc/prometheus/rules/pathchord.yml >/dev/null

for _ in $(seq 1 120); do
	query=$(curl --fail --silent --get --data-urlencode 'query=up{job="pathchord-ingress"}' http://127.0.0.1:19090/api/v1/query)
	if printf '%s' "$query" | jq -e '.data.result[0].value[1] == "1"' >/dev/null; then
		break
	fi
	sleep 0.25
done
printf '%s' "$query" | jq -e '.data.result[0].value[1] == "1"' >/dev/null
curl --fail --silent --get --data-urlencode 'query=pathchord_observation_generation' http://127.0.0.1:19090/api/v1/query | jq -e '.data.result | length == 1' >/dev/null
curl --fail --silent --get --data-urlencode 'query=pathchord:egress_wire_utilization_ratio' http://127.0.0.1:19090/api/v1/query | jq -e '.status == "success"' >/dev/null
curl --fail --silent http://127.0.0.1:19090/api/v1/rules | jq -e '[.data.groups[].rules[] | select(.name == "PathChordMetricsMissing" or .name == "PathChordTransitNodesDown")] | length == 2' >/dev/null

for _ in $(seq 1 120); do
	probe=$(curl --fail --silent -H "Authorization: Bearer $token" http://127.0.0.1:18090/api/v1/metrics/snapshot)
	nodes=$(curl --fail --silent -H "Authorization: Bearer $token" http://127.0.0.1:18090/api/v1/nodes)
	if printf '%s' "$nodes" | jq -e '.ok == true and .result.items[0].observed.state == "up" and .result.items[0].observed.rtt_ms != null' >/dev/null 2>&1; then
		break
	fi
	sleep 0.25
done
printf '%s' "$probe" | jq -e '.ok == true and .result.generation != null' >/dev/null
printf '%s' "$nodes" | jq -e '.ok == true and .result.items[0].observed.state == "up" and .result.items[0].observed.rtt_ms != null' >/dev/null
probe_rtt_ms=$(printf '%s' "$nodes" | jq -r '.result.items[0].observed.rtt_ms')

kill "$ingress_pid"
wait "$ingress_pid" 2>/dev/null || true
ingress_pid=''
for _ in $(seq 1 120); do
	alerts=$(curl --fail --silent http://127.0.0.1:19090/api/v1/alerts)
	if printf '%s' "$alerts" | jq -e '[.data.alerts[] | select(.labels.alertname == "PathChordMetricsMissing" and .state == "firing")] | length == 1' >/dev/null 2>&1; then
		break
	fi
	sleep 0.5
done
printf '%s' "$alerts" | jq -e '[.data.alerts[] | select(.labels.alertname == "PathChordMetricsMissing" and .state == "firing")] | length == 1' >/dev/null
start_ingress
for _ in $(seq 1 120); do
	if curl --fail --silent -H "Authorization: Bearer $token" http://127.0.0.1:18090/metrics >/dev/null 2>&1; then
		break
	fi
	sleep 0.1
done
curl --fail --silent -H "Authorization: Bearer $token" http://127.0.0.1:18090/metrics >/dev/null

# A fresh Grafana database runs its schema migrations before it serves requests.
for _ in $(seq 1 120); do
	grafana_health=$(curl --fail --silent --max-time 2 http://127.0.0.1:13000/api/health 2>/dev/null || true)
	if printf '%s' "$grafana_health" | jq -e '.database == "ok"' >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
if ! printf '%s' "$grafana_health" | jq -e '.database == "ok"' >/dev/null; then
	echo 'Timed out waiting for the Grafana database to become ready' >&2
	exit 1
fi
for _ in $(seq 1 120); do
	dashboard=$(curl --fail --silent -u admin:pathchord-local http://127.0.0.1:13000/api/dashboards/uid/pathchord-overview 2>/dev/null || true)
	if printf '%s' "$dashboard" | jq -e '.dashboard.uid == "pathchord-overview" and ([.dashboard.panels[].title] | index("Transit node health") != null)' >/dev/null 2>&1; then
		break
	fi
	sleep 0.25
done
curl --fail --silent -u admin:pathchord-local http://127.0.0.1:13000/api/datasources/uid/pathchord-prometheus | jq -e '.type == "prometheus"' >/dev/null
printf '%s' "$dashboard" | jq -e '.dashboard.uid == "pathchord-overview" and ([.dashboard.panels[].title] | index("Transit node health") != null)' >/dev/null

printf '%s\n' 'PathChord monitoring Docker smoke passed'
printf '%s\n' 'Prometheus scrape: up=1'
printf '%s\n' 'Prometheus rules: loaded'
printf '%s\n' 'Grafana datasource/dashboard: provisioned'
printf '%s\n' 'Snapshot gauges: gauge types preserved; no snapshot counter type'
printf 'Unauthorized scrape rejected; local probe RTT: %s ms\n' "$probe_rtt_ms"
printf '%s\n' 'Metrics missing alert: fired after target shutdown'
