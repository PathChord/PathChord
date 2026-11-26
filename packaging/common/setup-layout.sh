#!/bin/sh
# Called by the selected role's native package hooks as the package administrator.
set -eu
role=${1:?role is required}
case "$role" in ingress|egress) ;; *) exit 2 ;; esac
case "$(uname -s)" in
    FreeBSD) config_root=/usr/local/etc/pathchord; state_root=/var/db; runtime_root=/var/run/pathchord; root_group=wheel ;;
    *) config_root=/etc/pathchord; state_root=/var/lib; runtime_root=/run/pathchord; root_group=root ;;
esac
install -d -o root -g "$root_group" -m 0755 "$config_root"
install -d -o root -g pathchord -m 0750 "$config_root/$role"
install -d -o pathchord -g pathchord -m 0700 "$state_root/pathchord-$role"
chown -R pathchord:pathchord "$state_root/pathchord-$role"
if [ "$role" = ingress ]; then
    if [ -d "$config_root/ingress/secrets" ] && [ ! -e "$state_root/pathchord-ingress/credentials" ]; then
        mv "$config_root/ingress/secrets" "$state_root/pathchord-ingress/credentials"
    fi
    install -d -o pathchord -g pathchord -m 0700 "$state_root/pathchord-ingress/credentials"
    chown -R pathchord:pathchord "$state_root/pathchord-ingress/credentials"
fi
install -d -o pathchord -g pathchord -m 0750 "$runtime_root"
for endpoint in "$runtime_root/$role.sock" "$runtime_root/$role.sock.lock"; do
    if [ -e "$endpoint" ]; then
        chown pathchord:pathchord "$endpoint"
        chmod 0600 "$endpoint"
    fi
done
