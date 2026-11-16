#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ingressd=${PATHCHORD_INGRESSD:-$root_dir/target/debug/pathchord-ingressd}
egressd=${PATHCHORD_EGRESSD:-$root_dir/target/debug/pathchord-egressd}
ctl=${PATHCHORDCTL:-$root_dir/target/debug/pathchordctl}

for binary in "$ingressd" "$egressd" "$ctl"; do
	if [ ! -x "$binary" ]; then
		echo "missing executable: $binary" >&2
		exit 1
	fi
done

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/pathchord-role-smoke.XXXXXX")
ingress_pid=''
egress_pid=''
target_pid=''
udp_target_pid=''
cleanup() {
	[ -z "$udp_target_pid" ] || kill "$udp_target_pid" 2>/dev/null || true
	[ -z "$target_pid" ] || kill "$target_pid" 2>/dev/null || true
	[ -z "$ingress_pid" ] || kill "$ingress_pid" 2>/dev/null || true
	[ -z "$egress_pid" ] || kill "$egress_pid" 2>/dev/null || true
	wait "$target_pid" 2>/dev/null || true
	wait "$ingress_pid" 2>/dev/null || true
	wait "$egress_pid" 2>/dev/null || true
	rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

umask 077
mkdir -p "$tmp_dir/ingress-data" "$tmp_dir/ingress-secrets"

egress_key_json=$($ctl keygen --output "$tmp_dir/egress.key.json")
ingress_key_json=$($ctl keygen --output "$tmp_dir/ingress.key.json")
egress_public=$(printf '%s\n' "$egress_key_json" | jq -r '.public_key')
ingress_public=$(printf '%s\n' "$ingress_key_json" | jq -r '.public_key')

sed "s/REPLACE_WITH_EGRESS_PUBLIC_KEY/$egress_public/; s/127.0.0.1:7890/127.0.0.1:27890/" \
	"$root_dir/examples/ingress-egress.yaml" > "$tmp_dir/ingress.yaml"

$egressd \
	--egress-id exit \
	--identity "$tmp_dir/egress.key.json" \
	--bind 127.0.0.1:9443 \
	--authorization-db "$tmp_dir/authorizations.db" \
	--control-socket "$tmp_dir/egress.sock" \
	>"$tmp_dir/egress.log" 2>&1 &
egress_pid=$!

for _ in $(seq 1 100); do
	[ -S "$tmp_dir/egress.sock" ] && break
	sleep 0.05
done
[ -S "$tmp_dir/egress.sock" ]

$ctl --socket "$tmp_dir/egress.sock" enroll add \
	--ingress-id entry --egress-id exit --public-key "$ingress_public" \
	--expected-generation 0 >"$tmp_dir/enroll.json"
jq -e '.ok == true' "$tmp_dir/enroll.json" >/dev/null

nc -l 18080 < "$root_dir/scripts/fixtures/http-ok-response.txt" \
	>"$tmp_dir/target.log" 2>&1 &
target_pid=$!

$ingressd \
	--socket "$tmp_dir/ingress.sock" \
	--ingress-id entry \
	--config "$tmp_dir/ingress.yaml" \
	--identity "$tmp_dir/ingress.key.json" \
	--data-dir "$tmp_dir/ingress-data" \
	--credentials-dir "$tmp_dir/ingress-secrets" \
	>"$tmp_dir/ingress.log" 2>&1 &
ingress_pid=$!

for _ in $(seq 1 100); do
	[ -S "$tmp_dir/ingress.sock" ] && break
	sleep 0.05
done
[ -S "$tmp_dir/ingress.sock" ]

$ctl --socket "$tmp_dir/ingress.sock" status >"$tmp_dir/ingress-status.json"
$ctl --socket "$tmp_dir/egress.sock" status >"$tmp_dir/egress-status.json"
for _ in $(seq 1 100); do
	$ctl --socket "$tmp_dir/ingress.sock" status >"$tmp_dir/ingress-status.json"
	$ctl --socket "$tmp_dir/egress.sock" status >"$tmp_dir/egress-status.json"
	if jq -e '.ok == true and .result.ingress.state == "running" and .result.ready_paths > 0' "$tmp_dir/ingress-status.json" >/dev/null \
		&& jq -e '.ok == true and .result.runtime.running == true and .result.runtime.active_paths > 0' "$tmp_dir/egress-status.json" >/dev/null; then
		break
	fi
	sleep 0.1
done
if ! jq -e '.ok == true and .result.ingress.state == "running" and .result.ready_paths > 0' "$tmp_dir/ingress-status.json" >/dev/null \
	|| ! jq -e '.ok == true and .result.runtime.running == true and .result.runtime.active_paths > 0' "$tmp_dir/egress-status.json" >/dev/null; then
	cat "$tmp_dir/ingress-status.json" "$tmp_dir/egress-status.json" "$tmp_dir/ingress.log" "$tmp_dir/egress.log" >&2
	exit 1
fi

body=$(curl --noproxy '' --silent --show-error --max-time 5 \
	-x http://127.0.0.1:27890 http://127.0.0.1:18080)
if [ "$body" != ok ]; then
	cat "$tmp_dir/ingress.log" "$tmp_dir/egress.log" >&2
	exit 1
fi

rustc "$root_dir/scripts/fixtures/socks5-udp-smoke.rs" -O -o "$tmp_dir/socks5-udp-smoke"
rustc "$root_dir/scripts/fixtures/udp-echo.rs" -O -o "$tmp_dir/udp-echo"
"$tmp_dir/udp-echo" >"$tmp_dir/udp-target.log" 2>&1 &
udp_target_pid=$!
if "$tmp_dir/socks5-udp-smoke" 27890 18081; then
	kill "$udp_target_pid" 2>/dev/null || true
	echo "role binary TCP smoke passed; UDP datagram was submitted through SOCKS5"
else
	kill "$udp_target_pid" 2>/dev/null || true
	echo "role binary TCP smoke passed; UDP client submission was unavailable" >&2
fi
