#!/bin/sh
set -eu
root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../common/package-role.sh
. "$root_dir/packaging/common/package-role.sh"
output_dir=${1:-"$root_dir/dist"}
version=${PATHCHORD_VERSION:-$("$root_dir/packaging/version.sh")}
case "$version" in ''|*[!0-9A-Za-z.+:~_-]*) exit 2 ;; esac
deb_arch=${PATHCHORD_DEB_ARCH:-}
if [ -z "$deb_arch" ]; then
    if command -v dpkg >/dev/null; then deb_arch=$(dpkg --print-architecture)
    else
        case "$(uname -m)" in x86_64) deb_arch=amd64;; aarch64) deb_arch=arm64;; *) echo 'set PATHCHORD_DEB_ARCH' >&2; exit 2;; esac
    fi
fi
command -v dpkg-deb >/dev/null
mkdir -p "$output_dir"
stage=$(mktemp -d "${TMPDIR:-/tmp}/pathchord-deb.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
install -d "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/libexec" \
    "$stage/usr/share/man/man1" "$stage/usr/share/doc/$package_name" \
    "$stage/usr/lib/systemd/system" "$stage/usr/lib/tmpfiles.d" "$stage/etc/pathchord/$role"
install -m0755 "$daemon_binary" "$stage/usr/bin/$package_name"
install -m0755 "$ctl_binary" "$stage/usr/bin/pathchordctl"
install -m0755 "$root_dir/packaging/common/setup-layout.sh" "$stage/usr/libexec/pathchord-setup-layout"
install -m0644 "$root_dir/LICENSE" "$stage/usr/share/doc/$package_name/copyright"
install -m0644 "$root_dir/packaging/common/pathchord.1" "$stage/usr/share/man/man1/pathchord.1"
gzip -n -9 "$stage/usr/share/man/man1/pathchord.1"
install -m0644 "$root_dir/packaging/debian/$package_name.service" "$stage/usr/lib/systemd/system/$package_name.service"
if [ "$role" = ingress ]; then
    dependencies="libc6, adduser, ca-certificates"
    template=default-config.yaml
    install -d "$stage/usr/share/pathchord/systemd"
    install -m0644 "$root_dir/packaging/common/ingress-transparent.conf" "$stage/usr/share/pathchord/systemd/transparent.conf"
    install -m0644 "$root_dir/packaging/common/ingress-ebpf.conf" "$stage/usr/share/pathchord/systemd/ebpf.conf"
else
    dependencies="libc6, adduser"
    template=default-egress-config.yaml
fi
install -m0644 "$root_dir/packaging/common/$template" "$stage/etc/pathchord/$role/$role.yaml"
chmod 0750 "$stage/etc/pathchord/$role"
cat > "$stage/usr/lib/tmpfiles.d/pathchord.conf" <<EOF
d /etc/pathchord/$role 0750 root pathchord - -
d /var/lib/pathchord-$role 0700 pathchord pathchord - -
d /run/pathchord 0700 pathchord pathchord - -
EOF
cat > "$stage/DEBIAN/control" <<EOF
Package: $package_name
Version: $version-1
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: PathChord contributors <pathchord@invalid.example>
Depends: $dependencies
Conflicts: $other_package, pathchord
Description: PathChord $role runtime and local management client
 Installs only the $role daemon for a single-role machine.
EOF
printf '/etc/pathchord/%s/%s.yaml\n' "$role" "$role" > "$stage/DEBIAN/conffiles"
cat > "$stage/DEBIAN/postinst" <<EOF
#!/bin/sh
set -eu
if [ "\${1:-}" = configure ]; then
    getent group pathchord >/dev/null 2>&1 || addgroup --system pathchord
    getent passwd pathchord >/dev/null 2>&1 || adduser --system --ingroup pathchord --home /nonexistent --no-create-home --shell /usr/sbin/nologin pathchord
    /usr/libexec/pathchord-setup-layout '$role'
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload
        if [ -e /run/pathchord/.restart ]; then
            rm /run/pathchord/.restart
            systemctl start '$package_name.service'
        fi
    fi
fi
EOF
cat > "$stage/DEBIAN/prerm" <<EOF
#!/bin/sh
set -eu
if [ -d /run/systemd/system ]; then
    if [ "\${1:-}" = upgrade ] && systemctl is-active --quiet '$package_name.service'; then
        touch /run/pathchord/.restart
    fi
    systemctl stop '$package_name.service'
fi
EOF
cat > "$stage/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -eu
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
EOF
chmod 0755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm" "$stage/DEBIAN/postrm"
package="$output_dir/${package_name}_${version}-1_${deb_arch}.deb"
dpkg-deb --build "$stage" "$package"
printf '%s\n' "$package"
