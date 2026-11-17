# Native single-role package acceptance on 2026-11-17

This record covers the selected-role package model: one Ingress or Egress
package per machine, a local non-login `pathchord` account on Unix, and explicit
removal before replacing the installed role. It supersedes the earlier
same-machine two-account package experiments for this change's acceptance.

## Method and evidence boundaries

The fixture versions `0.1.0` and `0.1.1` contain the same tested role binary and
management client, with distinct package-manager versions. The upgrade and
rollback checks exercise package hooks, installed service recovery, permissions,
configuration preservation and retained private state. They do not establish
compatibility between different protocol releases or a historical database
schema migration. Alpine uses an ephemeral validation signing identity whose
public key is trusted only by the disposable guests; it is not a release key.

All QEMU caches, disk overlays, initramfs files and native host output now live
under `/data/pathchord-qemu`. Native Linux service acceptance uses either an
Alpine QEMU guest with its own kernel or a Debian/Arch filesystem booted with its
own systemd manager in `systemd-nspawn --boot --register=no --private-network`.
The latter shares the development host's kernel and has isolated PID, mount and
network namespaces. No package is installed on the development host, and no
host service, interface, route or packet-filter rule is modified.

## Linux role profiles

| Package host | Ingress evidence | Egress evidence | Result |
| --- | --- | --- | --- |
| Arch Linux, native `makepkg` and systemd 262 | `/data/pathchord-qemu/runs/native-packages/arch-ingress-capabilities-20261117/package-evidence.json` | `/data/pathchord-qemu/runs/native-packages/arch-egress-enrolled-20261117/package-evidence.json` | Both role profiles passed. |
| Debian 12, native `dpkg-deb` and systemd 252 | `/data/pathchord-qemu/runs/native-packages/debian-ingress-final-20261117/package-evidence.json` | `/data/pathchord-qemu/runs/native-packages/debian-egress-enrolled-r2-20261117/package-evidence.json` | Both role profiles passed after adding the Ingress CA dependency. |
| Alpine 3.24.4, Linux 6.18.63, native `abuild` and OpenRC | `/data/pathchord-qemu/runs/native-packages/alpine-final-profile-20261117/package-evidence.json` | `/data/pathchord-qemu/runs/native-packages/alpine-capabilities-20261117/package-evidence.json` | Both profiles passed on separate QEMU guests; the second run reuses the signature-verified APKs for the real authorization-state check. |

For each profile the package contains only the selected daemon, `pathchordctl`,
manual, selected configuration and matching service definition. Native package
installation rejects the other role while the installed daemon, configuration
and sentinel state remain unchanged. The account is non-login `pathchord`;
private state and runtime roots are `0700`, configuration directories are
`root:pathchord` with mode `0750`, and control sockets are `0600`.

The tests inspect the payload and run each daemon under the packaged service
manager. `pathchordctl status` succeeds as the service account. Default process
capabilities are empty; systemd also enforces an empty bounding set and private
devices. OpenRC starts Egress directly as the unprivileged account and requires
no privileged namespace launcher or network-administration capabilities. The
Ingress opt-in mechanism was also checked with the actual managers: the systemd
transparent drop-in and OpenRC IAB capability setting give the non-login process
`CAP_NET_ADMIN` and `CAP_NET_RAW` in its effective/ambient sets (`0x3000`). Removing
the opt-in restores the default empty effective set. This verifies the privilege
handoff; packet interception and TUN behavior have their own native-platform
acceptance evidence.

Lifecycle tests preserve an edited operator configuration, private identity and
authorization-state sentinel through upgrade, rollback, uninstall and explicit
role replacement. Running-service tests require a new PID after upgrade and
rollback, a working owner control endpoint and removal of the socket on stop.
The Egress extension enrolls a real Ingress public key with an administrator
sentinel label, queries that record after each restart, and verifies the actual
Egress identity and closed SQLite database remain byte-for-byte intact after
package removal.

The minimal Debian image initially failed Ingress startup with `native TLS root
store is empty`. The Ingress package now declares `ca-certificates`; Arch and
Alpine Ingress profiles declare the corresponding dependency as well. Egress
retains its smaller dependency set. This failure was a package runtime
prerequisite, and copying an unrelated host trust store was not used to pass it.

## FreeBSD profile evidence

Both FreeBSD profiles passed on FreeBSD 15.1-RELEASE with native `pkg` 2.6.2.
The cloud image's official SHA-256 checksum was verified before use. A matching
FreeBSD SDK supplied the role binaries, which were copied and stripped for the
fixture without changing the cross-build artifacts.

| Evidence | Path |
| --- | --- |
| Native build and both complete role lifecycles | `/data/pathchord-qemu/runs/native-packages/freebsd-single-role-final-20261117/package-evidence.json` |
| Final running-conflict and actual SQLite/identity preservation acceptance | `/data/pathchord-qemu/runs/native-packages/freebsd-final-acceptance-20261117/package-evidence.json` |
| Four native role package artifacts and checksums | `artifacts/` and `inventory.log` under both directories above |

For both roles, native installation, metadata, selected payload, non-login
account, configuration/runtime permissions, owner control, service stop and
external recovery after upgrade/rollback passed. Opposite-role installation
while running is rejected without changing the existing PID or private state.
The edited operator configuration and private identity/authorization sentinels
survive upgrade, rollback, uninstall and explicit replacement. The Egress case
also enrolls a real Ingress key and sentinel label, queries that authorization
after both recovered restarts, and compares the actual closed SQLite database
and Egress identity hashes after removal and role replacement. Removal of an
active package stops its matching rc.d service and removes its control socket.

The prebuilt assembler ships a `.sample` template and initializes the actual
operator file only when it does not exist; that actual file is not a payload
that `pkg add -f` can overwrite. The native fixture demonstrated that forced
local reinstallation replaced an edited `@config` file despite its registered
config metadata. The ports recipe retains `@sample`, which uses the ports
keyword framework. The prebuilt assembler needs no ports tree.
The installed package checks shared-file conflicts and runs an explicit
opposite-role guard before account or state setup. The `pkg` manifest's
`conflicts` relation cannot be used to declare a not-yet-registered opposite
package: native installation exposed a foreign-key failure with that form.

FreeBSD rc.subr applies the `${name}_user` identity before executing the daemon
wrapper; passing `daemon -u` again caused `initgroups: Operation not permitted`
and was removed. The unprivileged daemon opens its PID file after this drop. Its PID file
therefore belongs inside the account-owned `/var/run/pathchord` directory;
a top-level `/var/run` PID file failed with `Permission denied` during native
service validation. Role logs are written under the private state directory so
startup errors remain inspectable.

`pkg` reaps residual script descendants with `PROC_REAP_KILL`/`SIGKILL`, as
confirmed in upstream `libpkg/utils.c` and `libpkg/scripts.c`. Starting a service
inside `POST-INSTALL` therefore did not survive the package command. The package
stops an active matching role in `PRE-INSTALL` and reports the recovery command;
the package-host harness waits for `pkg` to return, then calls `service ...
onestart` and verifies control and state. Rollback uses the same outer recovery
step. No background process or privilege broker is used to escape the reaper.
The [FreeBSD package guide](../../../../packaging/freebsd/README.md#upgrade-and-rollback)
documents that service interruption and recovery procedure.

## Acceptance state

Debian, Alpine, Arch and FreeBSD each have native evidence for both role
profiles and their package/service lifecycle. Windows remains an explicitly
unverified target under task 1.5: static installer checks do not satisfy its
native binary, ACL, Named Pipe or service recovery acceptance. No Windows
release candidate should inherit another platform's result.

## Windows static package checks

`scripts/check-windows-role-packages.py` compiles both NSIS profiles with
warnings treated as errors and inspects their archive contents. It uses synthetic
PE inputs to test installer syntax and conditional payload selection. These
fixture installers are not release artifacts and do not establish native Windows
binary, Service Control Manager, Named Pipe, ACL or device behavior.

PowerShell 7.7.0 parses `build.ps1` and `install-service.ps1` successfully. The
selected WinSW XML uses a restricted virtual service account and resolves its
executable from the wrapper's `%BASE%`, including a custom installation path.
The installer and registration script agree on the 64-bit role registry key.
The installer rejects an opposite registered role before stopping services or
writing private files; the uninstaller preserves operator data.

Native Windows acceptance, including upgrade/rollback, actual service ACLs,
Named Pipe control and any Ingress device authorization, remains unverified.
The optional GNU cross-build was stopped to keep shared host I/O available and
is not counted as Windows-native evidence.

## Reproduction

Use `scripts/test-systemd-packages.py` with `--role`, `--older`, `--newer` and
`--opposite` to boot an exported native Debian/Arch image and run both lifecycle
and service acceptance. An Ingress host image must contain the declared CA
package. `scripts/test-qemu-alpine-packages.py --bin-dir <musl-binaries>` builds
and signs both profiles, then checks each in its own guest. Its `--artifacts`
option reuses an earlier signed APK set and public verification key.
`scripts/test-qemu-freebsd-packages.py --bin-dir <freebsd-binaries>` builds with
native `pkg` and tests rc.d behavior inside the FreeBSD QEMU guest.
