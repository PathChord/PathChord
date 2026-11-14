# PathChord packages

The package recipes in this directory install the same `pathchord` binary,
the shared manual page, and the loopback-only configuration template. Linux
and Alpine service packages use `/etc/pathchord`, the FreeBSD port uses
`/usr/local/etc/pathchord`, and packaged Windows services use
`%ProgramData%\PathChord\config`.

The template deliberately exposes only a loopback mixed listener. Replace it,
or add validated resources beside it, before enabling a listener for another
network. Private identities, credential JSON, bearer tokens, and runtime data
must remain outside the configuration directory.

## Package layout

| Target | Recipe | Service definition | Package output |
| --- | --- | --- | --- |
| Debian | `debian/` | `pathchord-ingress.service`, `pathchord-egress.service` | `.deb` |
| Alpine | `alpine/APKBUILD` | OpenRC `pathchord` and `pathchord-egress` init scripts | `.apk` |
| Arch Linux | `arch/PKGBUILD` | `pathchord-ingress.service`, `pathchord-egress.service` | `.pkg.tar.*` |
| FreeBSD | `freebsd/Makefile` | `rc.d/pathchord`, `rc.d/pathchord-egress` | `.pkg` |
| Windows | `windows/pathchord.nsi` | WinSW-compatible service XML and installer script | `.exe` |

All Unix recipes install `pathchord.1` as `pathchord(1)` and install
`default-config.yaml` as `ingress.yaml` in the package's configuration
directory. Package-native service files use that directory explicitly so a
service cannot accidentally consume a working-directory configuration.

## Building

Build the release binary first, then select a native package target:

```sh
cargo build --locked --release -p pathchord-cli
make -C packaging package-deb
make -C packaging package-alpine
make -C packaging package-arch
make -C packaging package-freebsd
make -C packaging package-windows
```

The package scripts accept `PATHCHORD_BINARY` for a cross-compiled or CI
artifact. The package version defaults to the `[workspace.package]` version in
`Cargo.toml`; set `PATHCHORD_VERSION` when producing a release from a tagged
artifact. Host tools (`dpkg-deb`, `abuild`, `makepkg`, FreeBSD `pkg`, and
NSIS) are intentionally required only by the matching target.

The Windows service XML is compatible with WinSW. The installer also ships a
PowerShell registration script so operators can choose the WinSW binary and
service account policy available on their host; PathChord remains a normal
console process when run directly.

Package builds are artifact assembly checks until they are run on their native
package host. A successful Linux cross-build does not establish native
FreeBSD or Windows service-control behavior.
