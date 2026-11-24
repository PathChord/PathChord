#!/bin/sh
set -eu
root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../common/package-role.sh
. "$root_dir/packaging/common/package-role.sh"
output_dir=${1:-"$root_dir/dist"}
version=${PATHCHORD_VERSION:-$("$root_dir/packaging/version.sh")}
case "$version" in ''|*[!0-9A-Za-z.+_-]*) exit 2 ;; esac
command -v pkg >/dev/null
mkdir -p "$output_dir"
stage=$(mktemp -d "${TMPDIR:-/tmp}/pathchord-pkg.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
install -d "$stage/usr/local/bin" "$stage/usr/local/libexec" "$stage/usr/local/etc/rc.d" \
    "$stage/usr/local/share/man/man1" "$stage/usr/local/share/licenses/$package_name" \
    "$stage/usr/local/etc/pathchord/$role" "$stage/var/db/pathchord-$role"
install -m0755 "$daemon_binary" "$stage/usr/local/bin/$package_name"
install -m0755 "$ctl_binary" "$stage/usr/local/bin/pathchordctl"
install -m0755 "$root_dir/packaging/common/setup-layout.sh" "$stage/usr/local/libexec/pathchord-setup-layout"
install -m0755 "$root_dir/packaging/freebsd/$package_name.in" "$stage/usr/local/etc/rc.d/$package_name"
install -m0644 "$root_dir/LICENSE" "$stage/usr/local/share/licenses/$package_name/LICENSE"
install -m0644 "$root_dir/packaging/common/pathchord.1" "$stage/usr/local/share/man/man1/pathchord.1"
install -d "$stage/usr/local/share/man/zh_CN/man1"
install -m0644 "$root_dir/packaging/common/pathchord.zh-CN.1" "$stage/usr/local/share/man/zh_CN/man1/pathchord.1"
if [ "$role" = ingress ]; then template=default-config.yaml; else template=default-egress-config.yaml; fi
sed -e 's@/var/lib/pathchord-@/var/db/pathchord-@g' -e 's@/run/pathchord/@/var/run/pathchord/@g' \
    "$root_dir/packaging/common/$template" > "$stage/usr/local/etc/pathchord/$role/$role.yaml.sample"
cp "$root_dir/packaging/freebsd/pkg-install" "$stage/+INSTALL"
cp "$root_dir/packaging/freebsd/pkg-deinstall" "$stage/+DEINSTALL"
cat > "$stage/+MANIFEST" <<EOF
name: "$package_name"
version: "$version"
origin: "net/$package_name"
comment: "PathChord $role runtime and local management client"
maintainer: "PathChord contributors <pathchord@invalid.example>"
www: "https://github.com/KagurazakaNyaa/PathChord"
prefix: "/usr/local"
licenselogic: "single"
licenses: [ "GPL-3.0-only" ]
annotations: { "pathchord-role": "$role", "pathchord-conflicts": "$other_package,pathchord" }
desc: "Single-role PathChord $role service and management client."
EOF
(cd "$stage" && find usr -type f -print | sed 's@^@/@') > "$stage/+PLIST"
cat >> "$stage/+PLIST" <<EOF
@dir(root,wheel,0755) /usr/local/etc/pathchord
@dir(root,pathchord,0750) /usr/local/etc/pathchord/$role
@dir(pathchord,pathchord,0700) /var/db/pathchord-$role
EOF
pkg create -r "$stage" -m "$stage" -p "$stage/+PLIST" -o "$output_dir"
