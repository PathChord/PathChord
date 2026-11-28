# PathChord packages

Install one role per machine: `pathchord-ingressd` on an Ingress client or
`pathchord-egressd` on an Egress target host. Each package contains its daemon,
`pathchordctl`, `pathchord(1)`, its own configuration template and matching
service definition. The packages conflict with one another and with the former
combined `pathchord` package. Remove the existing package explicitly before
changing roles; private operator configuration, identities and state are retained.

Both Unix profiles use the local non-login `pathchord` account. Only the selected
role's state and credential directories are prepared. Private state directories
use `0700` and control locks use `0600`. Configuration directories are
`root:pathchord` with mode `0750`. The runtime directory uses `0750` and the
control socket uses `0660`, both owned by `pathchord:pathchord`. The
`pathchord` group grants local service administration. On Linux, add a trusted
operator with `sudo usermod -aG pathchord USER`, then start a new login session.
On FreeBSD, use `sudo pw groupmod pathchord -m USER`.

## Package layout

| Target | Recipe | Service | Configuration root | Artifact |
| --- | --- | --- | --- | --- |
| Debian | `debian/build.sh` | Selected systemd unit | `/etc/pathchord/<role>` | `.deb` |
| Alpine | `alpine/APKBUILD`, `alpine/build.sh` | Selected OpenRC script | `/etc/pathchord/<role>` | `.apk` |
| Arch Linux | `arch/PKGBUILD`, `arch/build.sh` | Selected systemd unit and sysusers/tmpfiles | `/etc/pathchord/<role>` | `.pkg.tar.*` |
| FreeBSD | `freebsd/Makefile`, `freebsd/build.sh` | Selected rc.d script | `/usr/local/etc/pathchord/<role>` | `.pkg` |
| Windows | `windows/build.ps1` | Selected WinSW-compatible service definition | `%ProgramData%\PathChord\config\<role>` | NSIS `.exe` |

The Ingress template exposes only a loopback mixed HTTP/SOCKS listener. Its
private credential directory is `/var/lib/pathchord-ingress/credentials`, or
`/var/db/pathchord-ingress/credentials` on FreeBSD, outside the resource tree.
The Egress template binds only loopback and requires an operator-provisioned
identity under `/var/lib/pathchord-egress` (`/var/db/pathchord-egress` on
FreeBSD). Set the intended network bind in the selected configuration before
serving another machine.

## Building

Select the role explicitly; omitting it fails before package assembly:

```sh
cargo build --locked --release --bin pathchord-ingressd --bin pathchordctl
make -C packaging ROLE=ingress package-deb
make -C packaging ROLE=ingress package-alpine
make -C packaging ROLE=ingress package-arch
make -C packaging ROLE=ingress package-freebsd
make -C packaging ROLE=ingress package-windows
```

Use `ROLE=egress` and build `pathchord-egressd` plus `pathchordctl` for the
other deployment. A Unix assembler may also be invoked with
`PATHCHORD_ROLE=ingress` or `PATHCHORD_ROLE=egress`. Set
`PATHCHORD_DAEMON_BINARY` and `PATHCHORDCTL_BINARY` for prebuilt target
artifacts. The native tools are `dpkg-deb`, `abuild`, `makepkg`, FreeBSD
`pkg`, and Windows PowerShell/NSIS.

### Package version

Builds from a checkout read `[workspace.package].version` in the root
`Cargo.toml`. To give a CI package a different version, set `PATHCHORD_VERSION`
in the build environment. An explicit Make `VERSION` or PowerShell `-Version`
takes precedence for that invocation. Use a version accepted by the target
package manager. After building the role binaries, these commands print the
default version and build an Arch package with a CI version.

```sh
make -C packaging version
PATHCHORD_VERSION=0.1.2.7 make -C packaging ROLE=ingress package-arch
```

The GitHub release workflow accepts the Actions variable `PATHCHORD_VERSION`.
With the variable unset, the workflow reads the checked-out source's Cargo
version. Assembling prebuilt binaries changes package metadata and
preserves the supplied binaries. When using a standalone source recipe outside
the checkout, supply the version of an existing `v<version>` source tag so the
recipe can fetch its archive.

For Alpine, build static musl binaries and use a temporary test signing key or
the release signing identity appropriate to the build. Install the public key
in the target host's `/etc/apk/keys` before signature-verified installation:

```sh
cargo build --locked --release --target x86_64-unknown-linux-musl --bin pathchord-egressd --bin pathchordctl
PATHCHORD_ROLE=egress PATHCHORD_DAEMON_BINARY=target/x86_64-unknown-linux-musl/release/pathchord-egressd PATHCHORDCTL_BINARY=target/x86_64-unknown-linux-musl/release/pathchordctl packaging/alpine/build.sh dist
```

The assembler preserves the supplied binary bytes. The source APKBUILD builds
only the selected daemon and client. The role service account remains after
uninstall so retained private files do not become owned by a reused UID.

## Service isolation and optional Ingress privileges

Systemd profiles have empty capability sets and private device namespaces by
default. Egress requires neither TUN access nor network-administration
capabilities. An OpenRC Egress runs directly as the unprivileged `pathchord`
account without a privileged namespace launcher.

To configure Linux transparent/TUN listeners, install the Ingress-only drop-in:

```sh
sudo install -d /etc/systemd/system/pathchord-ingressd.service.d
sudo install -m 0644 /usr/share/pathchord/systemd/transparent.conf /etc/systemd/system/pathchord-ingressd.service.d/transparent.conf
sudo systemctl daemon-reload
sudo systemctl restart pathchord-ingressd
```

The additional `ebpf.conf` drop-in grants `CAP_BPF` and `CAP_PERFMON` and prepares
`/sys/fs/bpf/pathchord` for the service account. Mount bpffs and install the
[eBPF prerequisites](../docs/guides/deployment.md#linux-transparent-and-tun-listeners)
first. Install this beside `transparent.conf` only for a configured eBPF listener.
Neither drop-in is included in an Egress package.

On Alpine, OpenRC with libcap support accepts
`capabilities="^cap_net_admin,^cap_net_raw"` in
`/etc/conf.d/pathchord-ingressd`; add `^cap_bpf,^cap_perfmon` for eBPF and prepare
the account-owned bpffs directory as an administrator. Validate the host's
OpenRC capability support before starting privileged listeners. Ordinary
explicit Ingress listeners require no extra capabilities.

Windows installs one selected service definition. The registration script uses
its restricted virtual service account and grants that service SID, SYSTEM and
Administrators access to the role's private paths. Named Pipe control retains
owner/administrator/SYSTEM authorization. See the
[Windows instructions](windows/README.md) for WinSW registration and selected
role removal. Native device permissions must be provisioned before Windows TUN
can run under a restricted service account.

## Native acceptance

Use disposable native package hosts for each role profile. Inspect metadata,
selected binary/client, manual, configuration, service account and filesystem
permissions, then exercise service start/control/stop and active upgrade and
rollback. Opposite-role installation must fail while the installed service and
private state remain intact. After explicit removal, install the other role
and verify that retained operator files have not been overwritten.

`scripts/test-qemu-alpine-packages.py` builds signed APKs and tests each profile
on a separate QEMU guest. `scripts/test-systemd-packages.py` boots an exported
native systemd image in isolated PID, mount and network namespaces.
`scripts/test-linux-package-lifecycle.sh` and
`scripts/test-native-role-service.sh` run only with
`PATHCHORD_DISPOSABLE_PACKAGE_HOST=1` inside those disposable hosts. These
scripts do not install packages or alter services on the development host.
