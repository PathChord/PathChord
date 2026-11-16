#!/bin/sh
# Assemble an Alpine APK from a release or cross-compiled binary.
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output_dir=${1:-"$root_dir/dist"}
version=${PATHCHORD_VERSION:-$("$root_dir/packaging/version.sh")}
ingress_binary=${PATHCHORD_INGRESS_BINARY:-"$root_dir/target/release/pathchord-ingressd"}
egress_binary=${PATHCHORD_EGRESS_BINARY:-"$root_dir/target/release/pathchord-egressd"}
ctl_binary=${PATHCHORDCTL_BINARY:-"$root_dir/target/release/pathchordctl"}
for binary in "$ingress_binary" "$egress_binary" "$ctl_binary"; do
	case "$binary" in
		/*) ;;
		*) binary="$root_dir/$binary" ;;
	esac
done

case "$version" in
	''|*[!0-9A-Za-z.+_-]*)
		echo "invalid PathChord package version: $version" >&2
		exit 2
		;;
esac
for binary in "$ingress_binary" "$egress_binary" "$ctl_binary"; do
	if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
		echo "PathChord binary is missing or not executable: $binary" >&2
		exit 1
	fi
done
if ! command -v abuild >/dev/null 2>&1; then
	echo "abuild is required to build an Alpine package" >&2
	exit 127
fi

arch=${PATHCHORD_ALPINE_ARCH:-}
if [ -z "$arch" ]; then
	case "$(uname -m)" in
		x86_64) arch=x86_64 ;;
		aarch64) arch=aarch64 ;;
		armv7*) arch=armv7 ;;
		ppc64le) arch=ppc64le ;;
		s390x) arch=s390x ;;
		riscv64) arch=riscv64 ;;
		*) echo "set PATHCHORD_ALPINE_ARCH for this host" >&2; exit 2 ;;
	esac
fi
case "$arch" in
	*[!A-Za-z0-9_]*) echo "invalid Alpine architecture: $arch" >&2; exit 2 ;;
esac

mkdir -p "$output_dir"
work=$(mktemp -d "${TMPDIR:-/tmp}/pathchord-alpine.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
cp "$ingress_binary" "$work/pathchord-ingressd"
cp "$egress_binary" "$work/pathchord-egressd"
cp "$ctl_binary" "$work/pathchordctl"
cp "$root_dir/LICENSE" "$work/LICENSE"
cp "$root_dir/packaging/common/pathchord.1" "$work/pathchord.1"
cp "$root_dir/packaging/common/default-config.yaml" "$work/default-config.yaml"
cp "$root_dir/packaging/alpine/pathchord-ingressd.initd" "$work/pathchord-ingressd.initd"
cp "$root_dir/packaging/alpine/pathchord-egressd.initd" "$work/pathchord-egressd.initd"
cp "$root_dir/packaging/alpine/pathchord.pre-install" "$work/pathchord.pre-install"

cat >"$work/APKBUILD" <<'EOF'
pkgname=pathchord
pkgver=__PATHCHORD_VERSION__
pkgrel=0
pkgdesc="Multipath proxy runtime with HTTP, SOCKS, and Egress listeners"
url="https://github.com/KagurazakaNyaa/PathChord"
arch="__PATHCHORD_ARCH__"
license="GPL-3.0-only"
depends=""
makedepends=""
pkgusers="pathchord"
pkggroups="pathchord"
install="$pkgname.pre-install"
source="pathchord-ingressd pathchord-egressd pathchordctl LICENSE pathchord.1 default-config.yaml pathchord-ingressd.initd pathchord-egressd.initd"
sha256sums="
SKIP
SKIP
SKIP
SKIP
SKIP
SKIP
"

build() {
	:
}

package() {
	install -Dm0755 "$srcdir/pathchord-ingressd" "$pkgdir/usr/bin/pathchord-ingressd"
	install -Dm0755 "$srcdir/pathchord-egressd" "$pkgdir/usr/bin/pathchord-egressd"
	install -Dm0755 "$srcdir/pathchordctl" "$pkgdir/usr/bin/pathchordctl"
	install -Dm0644 "$srcdir/LICENSE" "$pkgdir/usr/share/licenses/pathchord/LICENSE"
	install -Dm0644 "$srcdir/pathchord.1" "$pkgdir/usr/share/man/man1/pathchord.1"
	gzip -n -9 "$pkgdir/usr/share/man/man1/pathchord.1"
	install -Dm0644 "$srcdir/default-config.yaml" "$pkgdir/etc/pathchord/ingress/ingress.yaml"
	install -Dm0755 "$srcdir/pathchord-ingressd.initd" "$pkgdir/etc/init.d/pathchord-ingressd"
	install -Dm0755 "$srcdir/pathchord-egressd.initd" "$pkgdir/etc/init.d/pathchord-egressd"
}
EOF
sed -i \
	-e "s/__PATHCHORD_VERSION__/$version/g" \
	-e "s/__PATHCHORD_ARCH__/$arch/g" \
	"$work/APKBUILD"

(cd "$work" && SRCDEST="$work" abuild checksum && SRCDEST="$work" abuild -r)
package=$(find "$work" "${HOME:-/nonexistent}/packages" -type f \
	-name 'pathchord-*.apk' -print 2>/dev/null | sort | tail -n 1)
if [ -z "$package" ]; then
	echo "abuild did not produce a package" >&2
	exit 1
fi
destination="$output_dir/$(basename "$package")"
cp "$package" "$destination"
printf '%s\n' "$destination"
