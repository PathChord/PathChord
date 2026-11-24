#!/bin/sh
set -eu
root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../common/package-role.sh
. "$root_dir/packaging/common/package-role.sh"
output_dir=${1:-"$root_dir/dist"}
version=${PATHCHORD_VERSION:-$("$root_dir/packaging/version.sh")}
case "$version" in ''|*[!0-9A-Za-z.+_-]*) exit 2 ;; esac
arch=${PATHCHORD_ARCH:-$(uname -m)}
command -v makepkg >/dev/null
mkdir -p "$output_dir"
work=$(mktemp -d "${TMPDIR:-/tmp}/pathchord-arch.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$work/src/common"
cp "$daemon_binary" "$work/src/$package_name"
cp "$ctl_binary" "$work/src/pathchordctl"
cp "$root_dir/packaging/arch/pathchord.install" "$work/pathchord.install"
cp "$root_dir/packaging/arch/pathchord.sysusers" "$work/src/common/pathchord.sysusers"
cp "$root_dir/packaging/arch/$package_name.service" "$work/src/common/role.service"
cp "$root_dir/packaging/common/"* "$work/src/common/"
cp "$root_dir/LICENSE" "$work/src/common/LICENSE"
if [ "$role" = ingress ]; then template=default-config.yaml; else template=default-egress-config.yaml; fi
cp "$work/src/common/$template" "$work/src/common/role.yaml"
cat > "$work/src/common/pathchord.tmpfiles" <<EOF
d /etc/pathchord/$role 0750 root pathchord - -
d /var/lib/pathchord-$role 0700 pathchord pathchord - -
d /run/pathchord 0700 pathchord pathchord - -
EOF
cat > "$work/PKGBUILD" <<'EOF'
pkgname=__PACKAGE__
pkgver=__VERSION__
pkgrel=1
pkgdesc='PathChord __ROLE__ runtime and local management client'
arch=('__ARCH__')
url='https://github.com/KagurazakaNyaa/PathChord'
license=('GPL-3.0-only')
depends=('glibc' __CERTIFICATES__)
conflicts=('__OTHER__' 'pathchord')
backup=('etc/pathchord/__ROLE__/__ROLE__.yaml')
install=pathchord.install
options=('!debug')
source=()
sha256sums=()
package() {
    install -Dm0644 "$srcdir/common/LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    install -Dm0755 "$srcdir/$pkgname" "$pkgdir/usr/bin/$pkgname"
    install -Dm0755 "$srcdir/pathchordctl" "$pkgdir/usr/bin/pathchordctl"
    install -Dm0755 "$srcdir/common/setup-layout.sh" "$pkgdir/usr/libexec/pathchord-setup-layout"
    install -Dm0644 "$srcdir/common/pathchord.1" "$pkgdir/usr/share/man/man1/pathchord.1"
    install -Dm0644 "$srcdir/common/pathchord.zh-CN.1" "$pkgdir/usr/share/man/zh_CN/man1/pathchord.1"
    install -Dm0644 "$srcdir/common/role.yaml" "$pkgdir/etc/pathchord/__ROLE__/__ROLE__.yaml"
    chmod 0750 "$pkgdir/etc/pathchord/__ROLE__"
    install -Dm0644 "$srcdir/common/role.service" "$pkgdir/usr/lib/systemd/system/$pkgname.service"
    install -Dm0644 "$srcdir/common/pathchord.sysusers" "$pkgdir/usr/lib/sysusers.d/pathchord.conf"
    install -Dm0644 "$srcdir/common/pathchord.tmpfiles" "$pkgdir/usr/lib/tmpfiles.d/pathchord.conf"
    if [ '__ROLE__' = ingress ]; then
        install -Dm0644 "$srcdir/common/ingress-transparent.conf" "$pkgdir/usr/share/pathchord/systemd/transparent.conf"
        install -Dm0644 "$srcdir/common/ingress-ebpf.conf" "$pkgdir/usr/share/pathchord/systemd/ebpf.conf"
    fi
}
EOF
if [ "$role" = ingress ]; then certificates="'ca-certificates'"; else certificates=; fi
sed -i -e "s/__CERTIFICATES__/$certificates/g" -e "s/__PACKAGE__/$package_name/g" -e "s/__OTHER__/$other_package/g" \
    -e "s/__ROLE__/$role/g" -e "s/__VERSION__/$version/g" -e "s/__ARCH__/$arch/g" "$work/PKGBUILD"
(cd "$work" && makepkg --nodeps --force --noconfirm)
package=$(find "$work" -maxdepth 1 -name "$package_name-$version-1-$arch.pkg.tar.*" -print -quit)
[ -n "$package" ]
cp "$package" "$output_dir/"
printf '%s\n' "$output_dir/$(basename "$package")"
