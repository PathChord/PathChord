#!/bin/sh
# Assemble a Debian binary package from a release or cross-compiled binary.
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output_dir=${1:-"$root_dir/dist"}
version=${PATHCHORD_VERSION:-$("$root_dir/packaging/version.sh")}
binary=${PATHCHORD_BINARY:-"$root_dir/target/release/pathchord"}
case "$binary" in
	/*) ;;
	*) binary="$root_dir/$binary" ;;
esac

case "$version" in
	''|*[!0-9A-Za-z.+:~_-]*)
		echo "invalid PathChord package version: $version" >&2
		exit 2
		;;
esac

if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
	echo "PathChord binary is missing or not executable: $binary" >&2
	exit 1
fi

if [ -n "${PATHCHORD_DEB_ARCH:-}" ]; then
	deb_arch=$PATHCHORD_DEB_ARCH
elif command -v dpkg >/dev/null 2>&1; then
	deb_arch=$(dpkg --print-architecture)
else
	case "$(uname -m)" in
		x86_64) deb_arch=amd64 ;;
		aarch64) deb_arch=arm64 ;;
		armv7*) deb_arch=armhf ;;
		i686|i386) deb_arch=i386 ;;
		*) echo "set PATHCHORD_DEB_ARCH for this host" >&2; exit 2 ;;
	esac
fi

mkdir -p "$output_dir"
stage=$(mktemp -d "${TMPDIR:-/tmp}/pathchord-deb.XXXXXX")
cleanup() { rm -rf "$stage"; }
trap cleanup EXIT HUP INT TERM

install -d "$stage/DEBIAN" \
	"$stage/usr/bin" \
	"$stage/usr/share/doc/pathchord" \
	"$stage/usr/share/man/man1" \
	"$stage/usr/lib/systemd/system" \
	"$stage/etc/pathchord" \
	"$stage/var/lib/pathchord"
install -m0755 "$binary" "$stage/usr/bin/pathchord"
install -m0644 "$root_dir/LICENSE" "$stage/usr/share/doc/pathchord/copyright"
install -m0644 "$root_dir/packaging/common/pathchord.1" \
	"$stage/usr/share/man/man1/pathchord.1"
gzip -n -9 "$stage/usr/share/man/man1/pathchord.1"
install -m0644 "$root_dir/packaging/common/default-config.yaml" \
	"$stage/etc/pathchord/ingress.yaml"
install -m0644 "$root_dir/packaging/debian/pathchord-ingress.service" \
	"$stage/usr/lib/systemd/system/pathchord-ingress.service"
install -m0644 "$root_dir/packaging/debian/pathchord-egress.service" \
	"$stage/usr/lib/systemd/system/pathchord-egress.service"

cat >"$stage/DEBIAN/control" <<EOF
Package: pathchord
Version: ${version}-1
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: PathChord contributors <pathchord@invalid.example>
Depends: libc6, adduser
Description: PathChord multipath proxy runtime
 PathChord provides local HTTP forwarding, HTTP CONNECT, SOCKS4/4a/5,
 and same-port mixed listeners with authenticated Egress paths.
EOF

cat >"$stage/DEBIAN/conffiles" <<'EOF'
/etc/pathchord/ingress.yaml
EOF

cat >"$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu

if [ "${1:-}" = configure ]; then
	if ! getent group pathchord >/dev/null 2>&1; then
		addgroup --system pathchord
	fi
	if ! getent passwd pathchord >/dev/null 2>&1; then
		adduser --system --ingroup pathchord --home /nonexistent \
			--no-create-home --shell /usr/sbin/nologin pathchord
	fi
	install -d -o pathchord -g pathchord -m 0750 /var/lib/pathchord
	install -d -o root -g pathchord -m 0750 /etc/pathchord/secrets
	install -d -o pathchord -g pathchord -m 0750 /run/pathchord
	chown root:pathchord /etc/pathchord
	chmod 0750 /etc/pathchord
	if command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload || true
	fi
fi

exit 0
EOF
chmod 0755 "$stage/DEBIAN/postinst"

cat >"$stage/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -eu

if [ "${1:-}" = remove ] && command -v deb-systemd-invoke >/dev/null 2>&1; then
	deb-systemd-invoke stop pathchord-ingress.service pathchord-egress.service || true
fi
exit 0
EOF
chmod 0755 "$stage/DEBIAN/prerm"

cat >"$stage/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -eu
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi
exit 0
EOF
chmod 0755 "$stage/DEBIAN/postrm"

(cd "$stage" && find . -type f -not -path './DEBIAN/*' -print | sort | \
	sed 's#^./##' | xargs md5sum >DEBIAN/md5sums)

package="$output_dir/pathchord_${version}-1_${deb_arch}.deb"
if ! command -v dpkg-deb >/dev/null 2>&1; then
	echo "dpkg-deb is required to build a Debian package" >&2
	exit 127
fi
dpkg-deb --build "$stage" "$package"
printf '%s\n' "$package"
