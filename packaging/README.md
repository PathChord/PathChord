# PathChord packages

The package recipes in this directory install `pathchord-ingressd`,
`pathchord-egressd`, `pathchordctl`, the shared manual page, and the
loopback-only Ingress configuration template. Linux and Alpine service
packages use `/etc/pathchord/ingress` and `/etc/pathchord/egress`, the FreeBSD
port uses matching role directories under `/usr/local/etc/pathchord`, and
packaged Windows services use `%ProgramData%\PathChord\config\ingress` and
`egress`.

The template deliberately exposes only a loopback mixed listener. Replace it,
or add validated resources beside it, before enabling a listener for another
network. Private identities, credential JSON, bearer tokens, and runtime data
must remain outside the configuration directory.

## Package layout

| Target | Recipe | Service definition | Package output |
| --- | --- | --- | --- |
| Debian | `debian/` | `pathchord-ingressd.service`, `pathchord-egressd.service` | `.deb` |
| Alpine | `alpine/APKBUILD` | OpenRC `pathchord-ingressd` and `pathchord-egressd` init scripts | `.apk` |
| Arch Linux | `arch/PKGBUILD` | `pathchord-ingressd.service`, `pathchord-egressd.service` | `.pkg.tar.*` |
| FreeBSD | `freebsd/Makefile` | `rc.d/pathchord-ingressd`, `rc.d/pathchord-egressd` | `.pkg` |
| Windows | `windows/pathchord.nsi` | WinSW-compatible `pathchord-ingressd`/`pathchord-egressd` XML and installer script | `.exe` |

All Unix recipes install `pathchord.1` for the `pathchordctl(1)` client and
install `default-config.yaml` as `ingress/ingress.yaml` in the package's configuration
directory. Package-native service files use that directory explicitly so a
service cannot accidentally consume a working-directory configuration.

## Building

Build the release binary first, then select a native package target:

```sh
cargo build --locked --release --bin pathchord-ingressd --bin pathchord-egressd --bin pathchordctl
make -C packaging package-deb
make -C packaging package-alpine
make -C packaging package-arch
make -C packaging package-freebsd
make -C packaging package-windows
```

The package scripts accept `PATHCHORD_INGRESS_BINARY`,
`PATHCHORD_EGRESS_BINARY`, and `PATHCHORDCTL_BINARY` for cross-compiled or CI
artifacts. The package version defaults to the `[workspace.package]` version in
`Cargo.toml`; set `PATHCHORD_VERSION` when producing a release from a tagged
artifact. Host tools (`dpkg-deb`, `abuild`, `makepkg`, FreeBSD `pkg`, and
NSIS) are intentionally required only by the matching target.

For Alpine x86_64 cross-builds, install the Rust musl target and use Rust's
default static PIE linker rather than overriding Cargo's target linker with
`musl-gcc`. For example, select an installed toolchain containing that target:

```sh
cargo +stable build --locked --release --bin pathchord-ingressd --bin pathchord-egressd --bin pathchordctl --target x86_64-unknown-linux-musl
PATHCHORD_INGRESS_BINARY=target/x86_64-unknown-linux-musl/release/pathchord-ingressd PATHCHORD_EGRESS_BINARY=target/x86_64-unknown-linux-musl/release/pathchord-egressd PATHCHORDCTL_BINARY=target/x86_64-unknown-linux-musl/release/pathchordctl make -C packaging package-alpine
```

Run `abuild` with a signing key in the package-building environment. The
generated APK uses that key; a target host must trust its public key before
installing it with signature verification. The package creates the
`pathchord` system user and group if absent and preserves them on removal.

The Windows service XML is compatible with WinSW. The installer also ships a
PowerShell registration script so operators can choose the WinSW binary and
service account policy available on their host; PathChord remains a normal
console process when run directly.

Package builds are artifact assembly checks until they are run on their native
package host. A successful Linux cross-build does not establish native
FreeBSD or Windows service-control behavior.
