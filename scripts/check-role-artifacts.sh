#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
egress_tree=$(cargo tree --offline -p pathchord-egressd --edges normal)
case "$egress_tree" in
	*pathchord-ingress*|*pathchord-transit*)
		echo "Egress artifact unexpectedly depends on Ingress or Transit" >&2
		exit 1
		;;
esac

for binary in pathchord-ingressd pathchord-egressd pathchordctl; do
	path="$root_dir/target/release/$binary"
	[ -x "$path" ] || {
		echo "missing release artifact: $path" >&2
		exit 1
	}
	version=$("$path" --version)
	printf '%s\n' "$version"
done

ingress_version=$("$root_dir/target/release/pathchord-ingressd" --version | awk '{print $2}')
egress_version=$("$root_dir/target/release/pathchord-egressd" --version | awk '{print $2}')
ctl_version=$("$root_dir/target/release/pathchordctl" --version | awk '{print $2}')
[ "$ingress_version" = "$egress_version" ]
[ "$ingress_version" = "$ctl_version" ]
printf '%s\n' "role artifact dependency and version checks passed"
