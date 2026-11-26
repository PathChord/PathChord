#!/bin/sh
# Native service lifecycle acceptance inside a disposable Linux guest only.
set -eu
[ "${PATHCHORD_DISPOSABLE_PACKAGE_HOST:-}" = 1 ] || exit 2
role=${1:?role is required}
older=${2:?older role artifact is required}
newer=${3:?newer role artifact is required}
opposite=${4:?opposite role artifact is required}
case "$role" in ingress) other=egress;; egress) other=ingress;; *) exit 2;; esac
service="pathchord-${role}d"
# shellcheck disable=SC1091
. /etc/os-release
case "$ID" in
    debian|ubuntu)
        install_package() { dpkg --force-confold -i "$1"; }
        remove_package() { dpkg -r "$service"; }
        ;;
    arch)
        install_package() { pacman -U --noconfirm "$1"; }
        remove_package() { pacman -R --noconfirm "$service"; }
        ;;
    alpine)
        install_package() { apk add --force-non-repository "$1"; }
        remove_package() { apk del "$service"; }
        ;;
    *) exit 2 ;;
esac
install_package "$older"
[ ! -e "/usr/bin/pathchord-${other}d" ]
if [ "$role" = egress ]; then
    identity=/var/lib/pathchord-egress/egress.key.json
    if [ ! -e "$identity" ]; then
        pathchordctl -o json keygen --identity-file "$identity" >/dev/null
        chown pathchord:pathchord "$identity"
    fi
fi
config="/etc/pathchord/$role/$role.yaml"
printf '\n# native-service-operator-sentinel\n' >> "$config"
if [ "$ID" = alpine ]; then
    mkdir -p /run/openrc
    touch /run/openrc/softlevel
    printf 'auto lo\niface lo inet loopback\n' > /etc/network/interfaces
    rc-service networking start
    start_service() { rc-service "$service" start; }
    stop_service() { rc-service "$service" stop; }
    active_service() { rc-service "$service" status; }
    service_pid() { cat "/run/$service.pid"; }
else
    start_service() { systemctl start "$service"; }
    stop_service() { systemctl stop "$service"; }
    active_service() { systemctl is-active "$service"; }
    service_pid() { systemctl show "$service" -p MainPID --value; }
fi
endpoint="/run/pathchord/$role.sock"
expected_capabilities=0000000000000000
ready() {
    for _attempt in $(seq 1 200); do
        if [ -S "$endpoint" ] && pathchordctl --socket "$endpoint" status >/dev/null 2>&1; then break; fi
        sleep 0.05
    done
    if [ ! -S "$endpoint" ]; then
        if [ "$ID" = alpine ]; then cat "/var/lib/pathchord-$role/service.log"
        else systemctl status "$service" --no-pager; fi
        exit 1
    fi
    if [ "$role" = egress ] && [ -e /var/lib/pathchord-egress/native-enrollment.fixture ]; then
        pathchordctl -o json --socket "$endpoint" enroll get --ingress-id lifecycle-fixture > /tmp/pathchord-enrollment.json
        grep -q lifecycle-fixture /tmp/pathchord-enrollment.json
        grep -q native-upgrade /tmp/pathchord-enrollment.json
        grep -Fq -e "$(cat /var/lib/pathchord-egress/native-enrollment.fixture)" /tmp/pathchord-enrollment.json
    fi
    active_service
    su -s /bin/sh -c "pathchordctl --socket $endpoint status" pathchord
    [ "$(stat -c '%U:%G:%a' "$endpoint")" = 'pathchord:pathchord:660' ]
    pid=$(service_pid)
    [ "$(awk '/^Uid:/ {print $2}' "/proc/$pid/status")" = "$(id -u pathchord)" ]
    [ "$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")" = "$expected_capabilities" ]
    grep '^Uid:\|^Gid:\|^Groups:\|^CapEff:\|^CapBnd:' "/proc/$pid/status"
    if [ "$ID" != alpine ]; then
        [ "$(awk '/^CapBnd:/ {print $2}' "/proc/$pid/status")" = "$expected_capabilities" ]
        if [ "$expected_capabilities" = 0000000000000000 ]; then [ ! -e "/proc/$pid/root/dev/net/tun" ]; fi
        systemctl show "$service" -p User -p CapabilityBoundingSet -p PrivateDevices
    fi
}
start_service
ready
if [ "$role" = egress ]; then
    public=$(pathchordctl -o json keygen --identity-file /var/lib/pathchord-egress/native-ingress.key.json | sed -n 's/.*"public_key": "\([^" ]*\)".*/\1/p')
    pathchordctl --socket "$endpoint" enroll add --ingress-id lifecycle-fixture --egress-id egress \
        --public-key "$public" --expected-generation 0 --label sentinel=native-upgrade
    printf '%s\n' "$public" > /var/lib/pathchord-egress/native-enrollment.fixture
    chmod 0600 /var/lib/pathchord-egress/native-enrollment.fixture
    ready
fi
before=$(service_pid)
sha256sum "$config" > /tmp/pathchord-active-config.sha256
if install_package "$opposite" >/tmp/pathchord-active-conflict.log 2>&1; then
    echo 'opposite role replaced a running service unexpectedly' >&2
    exit 1
fi
[ "$(service_pid)" = "$before" ]
sha256sum -c /tmp/pathchord-active-config.sha256
ready
install_package "$newer"
ready
[ "$(service_pid)" != "$before" ]
before=$(service_pid)
install_package "$older"
ready
[ "$(service_pid)" != "$before" ]
grep -q '^# native-service-operator-sentinel$' "$config"
stop_service
[ ! -S "$endpoint" ]
if [ "$role" = ingress ]; then
    # Verify the documented opt-in privilege mechanism with the actual service
    # manager, then restore the default before the removal checks.
    if [ "$ID" = alpine ]; then
        printf 'capabilities="^cap_net_admin,^cap_net_raw"\n' > /etc/conf.d/pathchord-ingressd
    else
        mkdir -p /etc/systemd/system/pathchord-ingressd.service.d
        cp /usr/share/pathchord/systemd/transparent.conf /etc/systemd/system/pathchord-ingressd.service.d/transparent.conf
        systemctl daemon-reload
    fi
    expected_capabilities=0000000000003000
    start_service
    ready
    pid=$(service_pid)
    [ "$(awk '/^CapAmb:/ {print $2}' "/proc/$pid/status")" = "$expected_capabilities" ]
    stop_service
    if [ "$ID" = alpine ]; then rm /etc/conf.d/pathchord-ingressd
    else
        rm /etc/systemd/system/pathchord-ingressd.service.d/transparent.conf
        systemctl daemon-reload
    fi
    expected_capabilities=0000000000000000
fi
start_service
ready
if [ "$role" = egress ]; then
    # Make a stable snapshot after closing SQLite; restart once to verify that
    # package removal performs the final service stop itself.
    stop_service

    sha256sum /var/lib/pathchord-egress/egress.key.json /var/lib/pathchord-egress/authorizations.db > /tmp/pathchord-native-state.sha256
    start_service
    ready
fi
remove_package
[ ! -S "$endpoint" ]
if [ "$role" = egress ]; then sha256sum -c /tmp/pathchord-native-state.sha256; fi
printf '%s\n' "$ID/$role: native service start, owner control, capability limits, conflict, active upgrade/rollback and stop passed"
