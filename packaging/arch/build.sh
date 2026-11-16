#!/bin/sh
# Assemble an Arch package from a release or cross-compiled binary.
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
cp "$ingress_binary" "$work/src/pathchord-ingressd"
cp "$egress_binary" "$work/src/pathchord-egressd"
cp "$ctl_binary" "$work/src/pathchordctl"
cp "$root_dir/packaging/common/pathchord.1" "$work/src/common/pathchord.1"
cp "$root_dir/packaging/common/default-config.yaml" "$work/src/common/default-config.yaml"
cp "$root_dir/LICENSE" "$work/src/common/LICENSE"
cp "$root_dir/packaging/arch/pathchord-ingressd.service" "$work/src/common/pathchord-ingressd.service"
cp "$root_dir/packaging/arch/pathchord-egressd.service" "$work/src/common/pathchord-egressd.service"
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
    install -Dm0755 "$srcdir/pathchord-ingressd" "$pkgdir/usr/bin/pathchord-ingressd"
    install -Dm0755 "$srcdir/pathchord-egressd" "$pkgdir/usr/bin/pathchord-egressd"
    install -Dm0755 "$srcdir/pathchordctl" "$pkgdir/usr/bin/pathchordctl"
    install -Dm0644 "$srcdir/common/LICENSE" "$pkgdir/usr/share/licenses/pathchord/LICENSE"
    install -Dm0644 "$srcdir/common/pathchord.1" \
        "$pkgdir/usr/share/man/man1/pathchord.1"
    install -Dm0644 "$srcdir/common/default-config.yaml" \
        "$pkgdir/etc/pathchord/ingress/ingress.yaml"
    install -Dm0644 "$srcdir/common/pathchord-ingressd.service" \
		"$pkgdir/usr/lib/systemd/system/pathchord-ingressd.service"
    install -Dm0644 "$srcdir/common/pathchord-egressd.service" \
		"$pkgdir/usr/lib/systemd/system/pathchord-egressd.service"
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
