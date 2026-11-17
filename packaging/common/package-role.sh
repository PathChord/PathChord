# shellcheck disable=SC2034
# Shared build-time role selection. Source after setting root_dir.
case "${PATHCHORD_ROLE:-}" in
    ingress) role=ingress; other_role=egress; daemon_binary=${PATHCHORD_DAEMON_BINARY:-${PATHCHORD_INGRESS_BINARY:-"$root_dir/target/release/pathchord-ingressd"}} ;;
    egress) role=egress; other_role=ingress; daemon_binary=${PATHCHORD_DAEMON_BINARY:-${PATHCHORD_EGRESS_BINARY:-"$root_dir/target/release/pathchord-egressd"}} ;;
    *) echo 'set PATHCHORD_ROLE to ingress or egress before building a role package' >&2; exit 2 ;;
esac
package_name="pathchord-${role}d"
other_package="pathchord-${other_role}d"
ctl_binary=${PATHCHORDCTL_BINARY:-"$root_dir/target/release/pathchordctl"}
absolute_binary() {
    case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s/%s\n' "$root_dir" "$1" ;; esac
}
daemon_binary=$(absolute_binary "$daemon_binary")
ctl_binary=$(absolute_binary "$ctl_binary")
for binary in "$daemon_binary" "$ctl_binary"; do
    if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
        echo "missing executable: $binary" >&2
        exit 1
    fi
done
