# FreeBSD role package

Select `PATHCHORD_ROLE=ingress` or `PATHCHORD_ROLE=egress` when building the
ports recipe. It installs only that daemon, `pathchordctl`, `pathchord(1)`, the
matching rc.d script and role configuration under
`/usr/local/etc/pathchord/<role>`. The two role packages conflict, and both
use the local non-login `pathchord` account.

For prebuilt FreeBSD artifacts, run the assembler on a native `pkg(8)` host:

```sh
PATHCHORD_ROLE=egress \
PATHCHORD_DAEMON_BINARY=/path/to/x86_64-unknown-freebsd/pathchord-egressd \
PATHCHORDCTL_BINARY=/path/to/x86_64-unknown-freebsd/pathchordctl \
PATHCHORD_VERSION=0.1.0 packaging/freebsd/build.sh dist
```

The ports recipe uses `@sample`. The prebuilt assembler also ships only a
`.sample` template and initializes the operator file only when it is absent,
without requiring a ports keyword tree. Package upgrades and
rollback retain operator edits, while uninstall preserves private files.
Changing roles requires explicit removal of the installed package before the
other is installed. Opposite-role installation must not overwrite existing
identities or authorization data.

Enable only the selected service in `/etc/rc.conf` with
`pathchord_ingressd_enable="YES"` or `pathchord_egressd_enable="YES"`.
For Egress, provision `/var/db/pathchord-egress/egress.key.json` and update its
loopback bind in `egress.yaml` before service startup. The rc.d wrappers use
`/var/run/pathchord/<role>.sock`. Private state directories use `0700`. The
runtime directory uses `0750` and the socket uses `0660`, both owned by
`pathchord:pathchord`. Add a trusted operator to the group with
`sudo pw groupmod pathchord -m USER` and start a new login session. Ingress credential JSON is stored
in `/var/db/pathchord-ingress/credentials` outside its resource tree.

The assembler and ports recipe require native FreeBSD package tools. A Linux
cross-build can supply the binaries, while package installation, rc.d behavior,
local control and signal handling are verified on FreeBSD itself.

## Upgrade and rollback

Package replacement stops the selected active service before extracting files.
FreeBSD `pkg` reaps descendant processes after package scripts finish, so recovery
runs outside those scripts. After the package operation returns, start the role
again and query its protected control endpoint:

```sh
pkg add -f pathchord-egressd-0.1.1.pkg
service pathchord-egressd onestart
pathchordctl --socket /var/run/pathchord/egress.sock status
```

For rollback, replace the package path with the prior tested artifact and repeat
the service start and status check. Use the matching Ingress service/socket for
an Ingress profile. Configuration, identity and authorization data are preserved;
this procedure includes a service interruption. Uninstall stops a running role
and retains private operator state. Explicit role replacement installs the other
profile only after removal of the current package.
