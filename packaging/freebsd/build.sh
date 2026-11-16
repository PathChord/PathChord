#!/bin/sh
set -eu

output_dir=${1:-dist}
root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
version=${PATHCHORD_VERSION:-$("$root_dir/packaging/version.sh")}
ingress_binary=${PATHCHORD_INGRESS_BINARY:-$root_dir/target/release/pathchord-ingressd}
egress_binary=${PATHCHORD_EGRESS_BINARY:-$root_dir/target/release/pathchord-egressd}
ctl_binary=${PATHCHORDCTL_BINARY:-$root_dir/target/release/pathchordctl}
for binary in "$ingress_binary" "$egress_binary" "$ctl_binary"; do
  case "$binary" in
    /*) ;;
    *) binary="$root_dir/$binary" ;;
  esac
done

case "$version" in
  ''|*[!0-9A-Za-z.+_-]*)
    printf '%s\n' "invalid PathChord package version: $version" >&2
    exit 2
    ;;
esac

for binary in "$ingress_binary" "$egress_binary" "$ctl_binary"; do
  if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
    printf '%s\n' "FreeBSD package input binary was not found: $binary" >&2
    exit 1
  fi
done
if ! command -v pkg >/dev/null 2>&1; then
  printf '%s\n' 'FreeBSD pkg(8) is required to assemble a .pkg artifact.' >&2
  exit 1
fi

mkdir -p "$output_dir"
stage_dir=$(mktemp -d "${TMPDIR:-/tmp}/pathchord-pkg.XXXXXX")
cleanup() { rm -rf "$stage_dir"; }
trap cleanup EXIT INT TERM

install -d "$stage_dir/usr/local/bin" "$stage_dir/usr/local/etc/pathchord/ingress" \
  "$stage_dir/usr/local/etc/pathchord/egress" \
  "$stage_dir/usr/local/etc/rc.d" "$stage_dir/usr/local/share/man/man1" \
  "$stage_dir/usr/local/share/pathchord" \
  "$stage_dir/usr/local/share/licenses/pathchord" "$stage_dir/var/db/pathchord-ingress" \
  "$stage_dir/var/db/pathchord-egress"
install -m 0755 "$ingress_binary" "$stage_dir/usr/local/bin/pathchord-ingressd"
install -m 0755 "$egress_binary" "$stage_dir/usr/local/bin/pathchord-egressd"
install -m 0755 "$ctl_binary" "$stage_dir/usr/local/bin/pathchordctl"
install -m 0644 "$root_dir/LICENSE" "$stage_dir/usr/local/share/licenses/pathchord/LICENSE"
install -m 0644 "$root_dir/packaging/common/default-config.yaml" \
  "$stage_dir/usr/local/etc/pathchord/ingress/ingress.yaml"
install -m 0644 "$root_dir/packaging/common/pathchord.1" \
  "$stage_dir/usr/local/share/man/man1/pathchord.1"
sed 's/%%PREFIX%%/\/usr\/local/g' "$root_dir/packaging/freebsd/pkg-message" \
  > "$stage_dir/usr/local/share/pathchord/pkg-message"
cp "$root_dir/packaging/freebsd/pathchord.in" "$stage_dir/usr/local/etc/rc.d/pathchord"
cp "$root_dir/packaging/freebsd/pathchord-egress.in" "$stage_dir/usr/local/etc/rc.d/pathchord-egress"
chmod 0755 "$stage_dir/usr/local/etc/rc.d/pathchord" "$stage_dir/usr/local/etc/rc.d/pathchord-egress"

cat > "$stage_dir/+PRE-INSTALL" <<'EOF'
#!/bin/sh
if ! pw groupshow pathchord >/dev/null 2>&1; then
  pw groupadd pathchord -r
fi
if ! pw usershow pathchord >/dev/null 2>&1; then
  pw useradd pathchord -r -g pathchord -d /var/empty -s /usr/sbin/nologin
fi
EOF
chmod 0755 "$stage_dir/+PRE-INSTALL"

cat > "$stage_dir/+MANIFEST" <<EOF
name: "pathchord"
version: "$version"
origin: "net/pathchord"
comment: "Adaptive multipath proxy runtime with HTTP and SOCKS listeners"
maintainer: "PathChord contributors <pathchord@example.invalid>"
www: "https://github.com/KagurazakaNyaa/PathChord"
prefix: "/usr/local"
licenselogic: "single"
licenses: [ "GPL-3.0-only" ]
users: [ "pathchord" ]
groups: [ "pathchord" ]
desc: <<EOD
PathChord provides local HTTP forwarding, CONNECT, SOCKS4/4a/5, mixed
listeners, and authenticated Egress Paths.
EOD
EOF

pkg create -r "$stage_dir" -m "$stage_dir/+MANIFEST" -o "$output_dir"
printf '%s\n' "Created FreeBSD package in $output_dir"
