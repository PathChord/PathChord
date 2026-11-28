#!/bin/sh
set -eu
root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../common/package-role.sh
. "$root_dir/packaging/common/package-role.sh"
output_dir=${1:-"$root_dir/dist"}
version=$("$root_dir/packaging/version.sh")
case "$version" in ''|*[!0-9A-Za-z.+_-]*) echo 'invalid alpine package version' >&2; exit 2 ;; esac
arch=${PATHCHORD_ALPINE_ARCH:-$(uname -m)}
command -v abuild >/dev/null
mkdir -p "$output_dir"
work=$(mktemp -d "${TMPDIR:-/tmp}/pathchord-alpine.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
cp "$daemon_binary" "$work/$package_name"
cp "$ctl_binary" "$work/pathchordctl"
cp "$root_dir/LICENSE" "$work/LICENSE"
cp "$root_dir/packaging/common/pathchord.1" "$work/pathchord.1"
cp "$root_dir/packaging/common/pathchord.zh-CN.1" "$work/pathchord.zh-CN.1"
cp "$root_dir/packaging/common/setup-layout.sh" "$work/setup-layout.sh"
cp "$root_dir/packaging/alpine/$package_name.initd" "$work/role.initd"
if [ "$role" = ingress ]; then template=default-config.yaml; else template=default-egress-config.yaml; fi
cp "$root_dir/packaging/common/$template" "$work/role.yaml"
for hook in pre-install pre-upgrade post-install post-upgrade pre-deinstall; do
    cp "$root_dir/packaging/alpine/pathchord.$hook" "$work/$package_name.$hook"
done
cat > "$work/APKBUILD" <<'EOF'
pkgname=__PACKAGE__
pkgver=__VERSION__
pkgrel=0
pkgdesc="PathChord __ROLE__ runtime and local management client"
url="https://github.com/KagurazakaNyaa/PathChord"
arch="__ARCH__"
license="GPL-3.0-only"
depends="__CERTIFICATES__ !__OTHER__ !pathchord"
makedepends=""
options="!check !strip"
pkgusers="pathchord"
pkggroups="pathchord"
install="$pkgname.pre-install $pkgname.pre-upgrade $pkgname.post-install $pkgname.post-upgrade $pkgname.pre-deinstall"
source="$pkgname pathchordctl LICENSE pathchord.1 pathchord.zh-CN.1 setup-layout.sh role.yaml role.initd"
sha256sums="SKIP"
package() {
    install -Dm0755 "$srcdir/$pkgname" "$pkgdir/usr/bin/$pkgname"
    install -Dm0755 "$srcdir/pathchordctl" "$pkgdir/usr/bin/pathchordctl"
    install -Dm0755 "$srcdir/setup-layout.sh" "$pkgdir/usr/libexec/pathchord-setup-layout"
    install -Dm0644 "$srcdir/LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    install -Dm0644 "$srcdir/pathchord.1" "$pkgdir/usr/share/man/man1/pathchord.1"
    install -Dm0644 "$srcdir/pathchord.zh-CN.1" "$pkgdir/usr/share/man/zh_CN/man1/pathchord.1"
    gzip -n -9 "$pkgdir/usr/share/man/man1/pathchord.1"
    gzip -n -9 "$pkgdir/usr/share/man/zh_CN/man1/pathchord.1"
    install -Dm0644 "$srcdir/role.yaml" "$pkgdir/etc/pathchord/__ROLE__/__ROLE__.yaml"
    chmod 0750 "$pkgdir/etc/pathchord/__ROLE__"
    install -Dm0755 "$srcdir/role.initd" "$pkgdir/etc/init.d/$pkgname"
}
EOF
if [ "$role" = ingress ]; then certificates=ca-certificates; else certificates=; fi
sed -i -e "s/__CERTIFICATES__/$certificates/g" -e "s/__PACKAGE__/$package_name/g" -e "s/__OTHER__/$other_package/g" \
    -e "s/__ROLE__/$role/g" -e "s/__VERSION__/$version/g" -e "s/__ARCH__/$arch/g" "$work/APKBUILD"
(cd "$work" && SRCDEST="$work" abuild checksum && SRCDEST="$work" abuild -d -r)
package=$(find "${HOME:-/nonexistent}/packages" -type f -name "$package_name-$version-r0.apk" -print -quit)
[ -n "$package" ]
cp "$package" "$output_dir/"
printf '%s\n' "$output_dir/$(basename "$package")"
