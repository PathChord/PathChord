#!/bin/sh
# Run only inside a disposable package host/container/VM.
set -eu
[ "${PATHCHORD_DISPOSABLE_PACKAGE_HOST:-}" = 1 ] || exit 2
role=${1:?role is required}
older=${2:?older role package is required}
newer=${3:?newer role package is required}
opposite=${4:?opposite role package is required}
case "$role" in ingress) other=egress;; egress) other=ingress;; *) exit 2;; esac
package="pathchord-${role}d"
other_package="pathchord-${other}d"
# shellcheck disable=SC1091
. /etc/os-release
case "$ID" in
    debian|ubuntu)
        for exclusions in /etc/dpkg/dpkg.cfg.d/*; do
            [ -f "$exclusions" ] || continue
            sed -i '\|^path-exclude.*/usr/share/man|d' "$exclusions"
        done
        install_package() { dpkg --force-confold -i "$1"; }
        remove_package() { dpkg -r "$1"; }
        inventory() { dpkg-deb --fsys-tarfile "$1" | tar -tf -; }
        ;;
    arch)
        sed -i '/^NoExtract.*usr\/share\/man/s/^/#/' /etc/pacman.conf
        install_package() { pacman -U --noconfirm "$1"; }
        remove_package() { pacman -R --noconfirm "$1"; }
        inventory() { tar -tf "$1"; }
        ;;
    alpine)
        install_package() { apk add --force-non-repository "$1"; }
        remove_package() { apk del "$1"; }
        inventory() { apk info --who-owns /dev/null >/dev/null 2>&1 || :; tar -tf "$1"; }
        ;;
    *) exit 2 ;;
esac
inventory "$older" > /tmp/pathchord-package-inventory
if grep -Eq "(^|/)(usr/bin/$other_package|etc/init.d/$other_package|usr/lib/systemd/system/$other_package.service|etc/pathchord/$other/)(/|$)" /tmp/pathchord-package-inventory; then
    echo 'role package contains opposite-role resources' >&2
    exit 1
fi
install_package "$older"
getent passwd pathchord
[ -x "/usr/bin/$package" ]
[ ! -e "/usr/bin/$other_package" ]
[ -x /usr/bin/pathchordctl ]
[ "$(stat -c '%U:%G:%a' "/var/lib/pathchord-$role")" = 'pathchord:pathchord:700' ]
[ "$(stat -c '%U:%G:%a' "/etc/pathchord/$role")" = 'root:pathchord:750' ]
[ "$(stat -c '%U:%G:%a' /run/pathchord)" = 'pathchord:pathchord:700' ]
[ -f /usr/share/man/man1/pathchord.1.gz ]
gzip -t /usr/share/man/man1/pathchord.1.gz
"/usr/bin/$package" --version
pathchordctl --version
config="/etc/pathchord/$role/$role.yaml"
printf '\n# operator-lifecycle-sentinel\n' >> "$config"
state="/var/lib/pathchord-$role"
printf 'operator-%s\n' "$role" > "$state/lifecycle-sentinel"
pathchordctl keygen --output "$state/lifecycle.key.json" >/dev/null
printf 'authorization-state-fixture\n' > "$state/lifecycle.authorizations.db"
chown pathchord:pathchord "$state"/lifecycle*
chmod 0600 "$state"/lifecycle*
sha256sum "$state"/lifecycle* > /tmp/pathchord-lifecycle.sha256
verify_state() {
    sha256sum -c /tmp/pathchord-lifecycle.sha256
    grep -q '^# operator-lifecycle-sentinel$' "$config"
    [ "$(stat -c '%U:%G:%a' "$state")" = 'pathchord:pathchord:700' ]
}
if install_package "$opposite" >/tmp/pathchord-conflict.log 2>&1; then
    echo 'opposite role installation unexpectedly succeeded' >&2
    exit 1
fi
verify_state
[ -x "/usr/bin/$package" ]
[ ! -e "/usr/bin/$other_package" ]
install_package "$newer"
verify_state
install_package "$older"
verify_state
remove_package "$package"
sha256sum -c /tmp/pathchord-lifecycle.sha256
saved=''
for candidate in "$config" "$config.pacsave" "$config.apk-save"; do
    if [ -f "$candidate" ] && grep -q '^# operator-lifecycle-sentinel$' "$candidate"; then saved=$candidate; break; fi
done
[ -n "$saved" ]
# A role replacement is explicit: remove the first package, then install the
# other. Historical private files must remain byte-for-byte intact.
install_package "$opposite"
[ -x "/usr/bin/$other_package" ]
[ ! -e "/usr/bin/$package" ]
sha256sum -c /tmp/pathchord-lifecycle.sha256
grep -q '^# operator-lifecycle-sentinel$' "$saved"
remove_package "$other_package"
printf '%s\n' "$ID/$role: payload, conflict, shared account, upgrade, rollback, uninstall and explicit replacement passed"
