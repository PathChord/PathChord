# FreeBSD package

`Makefile` is a ports skeleton for a source build. It uses the standard Cargo
ports framework and installs `pathchord-ingressd`, `pathchord-egressd`, and
`pathchordctl`, both rc.d service definitions, `pathchordctl(1)`, and the
loopback-only default configuration at
`/usr/local/etc/pathchord/ingress/ingress.yaml`.

For release automation that already has a cross-compiled FreeBSD binary, use
the artifact assembler from a native FreeBSD host:

```sh
PATHCHORD_INGRESS_BINARY=/path/to/x86_64-unknown-freebsd/pathchord-ingressd \
PATHCHORD_EGRESS_BINARY=/path/to/x86_64-unknown-freebsd/pathchord-egressd \
PATHCHORDCTL_BINARY=/path/to/x86_64-unknown-freebsd/pathchordctl \
PATHCHORD_VERSION=0.1.0 \
  packaging/freebsd/build.sh dist
```

The assembler calls `pkg create` and therefore must run on a host with
FreeBSD `pkg(8)`. A Linux cross-build or a successful ELF link does not prove
that the package installs or that rc.d/service behavior works on FreeBSD.

Enable Ingress in `/etc/rc.conf` with `pathchord_ingressd_enable="YES"`. The Egress
service is separately controlled by `pathchord_egressd_enable` and requires an
operator-provisioned identity under `/var/db/pathchord-egress`.

The rc.d wrappers pass `/var/run/pathchord/ingress.sock` and
`/var/run/pathchord/egress.sock` explicitly because FreeBSD uses
`/var/run` for runtime sockets.
