#!/bin/sh
# Assemble an Arch package from a release or cross-compiled binary.
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
	''|*[!0-9A-Za-z.+_-]*)
		echo "invalid PathChord package version: $version" >&2
		exit 2
		;;
esac
if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
	echo "PathChord binary is missing or not executable: $binary" >&2
	exit 1
fi
if ! command -v makepkg >/dev/null 2>&1; then
	echo "makepkg is required to build an Arch package" >&2
	exit 127
fi

arch=${PATHCHORD_ARCH:-}
if [ -z "$arch" ]; then
	case "$(uname -m)" in
		x86_64) arch=x86_64 ;;
		aarch64) arch=aarch64 ;;
		armv7*) arch=armv7h ;;
		riscv64) arch=riscv64 ;;
		*) echo "set PATHCHORD_ARCH for this host" >&2; exit 2 ;;
	esac
fi
case "$arch" in
	*[!A-Za-z0-9_]*) echo "invalid Arch architecture: $arch" >&2; exit 2 ;;
esac

mkdir -p "$output_dir"
work=$(mktemp -d "${TMPDIR:-/tmp}/pathchord-arch.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
mkdir -p "$work/src/common"
cp "$binary" "$work/src/pathchord"
cp "$root_dir/packaging/common/pathchord.1" "$work/src/common/pathchord.1"
cp "$root_dir/packaging/common/default-config.yaml" "$work/src/common/default-config.yaml"
cp "$root_dir/LICENSE" "$work/src/common/LICENSE"
cp "$root_dir/packaging/arch/pathchord-ingress.service" "$work/src/common/pathchord-ingress.service"
cp "$root_dir/packaging/arch/pathchord-egress.service" "$work/src/common/pathchord-egress.service"
cp "$root_dir/packaging/arch/pathchord.sysusers" "$work/src/common/pathchord.sysusers"
cp "$root_dir/packaging/arch/pathchord.tmpfiles" "$work/src/common/pathchord.tmpfiles"

cat >"$work/PKGBUILD" <<'EOF'
pkgname=pathchord
pkgver=__PATHCHORD_VERSION__
pkgrel=1
pkgdesc='Multipath proxy runtime with HTTP, SOCKS, and Egress listeners'
arch=('__PATHCHORD_ARCH__')
url='https://github.com/KagurazakaNyaa/PathChord'
license=('GPL-3.0-only')
depends=('glibc')
source=()
sha256sums=()

build() {
    :
}

package() {
    install -Dm0755 "$srcdir/pathchord" "$pkgdir/usr/bin/pathchord"
    install -Dm0644 "$srcdir/common/LICENSE" "$pkgdir/usr/share/licenses/pathchord/LICENSE"
    install -Dm0644 "$srcdir/common/pathchord.1" \
        "$pkgdir/usr/share/man/man1/pathchord.1"
    install -Dm0644 "$srcdir/common/default-config.yaml" \
        "$pkgdir/etc/pathchord/ingress.yaml"
    install -Dm0644 "$srcdir/common/pathchord-ingress.service" \
        "$pkgdir/usr/lib/systemd/system/pathchord-ingress.service"
    install -Dm0644 "$srcdir/common/pathchord-egress.service" \
        "$pkgdir/usr/lib/systemd/system/pathchord-egress.service"
    install -Dm0644 "$srcdir/common/pathchord.sysusers" \
        "$pkgdir/usr/lib/sysusers.d/pathchord.conf"
    install -Dm0644 "$srcdir/common/pathchord.tmpfiles" \
        "$pkgdir/usr/lib/tmpfiles.d/pathchord.conf"
}
EOF
sed -i \
	-e "s/__PATHCHORD_VERSION__/$version/g" \
	-e "s/__PATHCHORD_ARCH__/$arch/g" \
	"$work/PKGBUILD"

(cd "$work" && makepkg --nodeps --force --noconfirm)
package=$(find "$work" -maxdepth 1 -type f \
	-name "pathchord-${version}-1-${arch}.pkg.tar.*" -print -quit)
if [ -z "$package" ]; then
	package=$(find "$work" -maxdepth 1 -type f -name 'pathchord-*.pkg.tar.*' \
		-not -name 'pathchord-debug-*' -print -quit)
fi
if [ -z "$package" ]; then
	echo "makepkg did not produce a package" >&2
	exit 1
fi
destination="$output_dir/$(basename "$package")"
cp "$package" "$destination"
printf '%s\n' "$destination"
