# Windows native validation on 2026-11-18

This record supersedes the acceptance results in the [first Windows
run](2026-11-17-windows-qemu-validation.md). That historical report and its
failure logs remain available. The current run uses freshly built executables
from revision `550503adbe92a1c0c73c664e9fdee77462e58a8b` plus the recorded
worktree changes. A cross-build is recorded as build provenance; all results
below were executed by the Windows guest.

## Prepared snapshot and guest

The Windows installation is Windows 11 Pro x64, Simplified Chinese, 26H2 build
`26300.9457`, running under QEMU/KVM with OVMF Secure Boot and swtpm 2.0.
Before the clean shutdown, readiness, the running SSH service, Secure Boot and
TPM readiness were verified. Hibernation was disabled. `qemu-img check` passed
after shutdown.

The reusable cold snapshot is
`/data/pathchord-qemu/windows/snapshots/windows-ready-20261118/`. It retains the
qcow2 backing chain to `/data/pathchord-qemu/windows/base4/disk.qcow2`, matching
OVMF variables, TPM state and private management credentials. Both baseline
disk files are read-only. The snapshot is a backing-chain snapshot, so its
`base4` backing disk must be retained. Credentials are kept privately until
the guest is intentionally retired; they are not part of repository evidence.

The two writable test guests are independent overlays:

- `/data/pathchord-qemu/windows/validation-20261118/platform` for runtime and
  host integration;
- `/data/pathchord-qemu/windows/validation-20261118/packages-guest` for NSIS and
  service lifecycle acceptance.

All writable VM disks, firmware, TPM state, media, credentials, logs and test
outputs are under `/data`. Management uses loopback-only SSH with restricted
QEMU user networking. Tests do not write to the prepared snapshot. To create
another disposable guest from the prepared snapshot, select a new output
directory and run from the repository root:

```sh
python3 -B scripts/qemu_windows.py \
  --root /data/pathchord-qemu/windows/snapshots/windows-ready-20261118 \
  clone --output /data/pathchord-qemu/windows/next-validation
python3 -B scripts/qemu_windows.py \
  --root /data/pathchord-qemu/windows/next-validation start
```

## Native suite and focused repeats

The latest staged directory is `C:\PathChordLab\stage-latest`. PowerShell
7.7.0 ran the suite with the following invocation:

```powershell
& C:\PathChordLab\tools\pwsh\pwsh.exe -NoProfile -File `
  C:\PathChordLab\checkout\scripts\test-windows-platforms.ps1 `
  -Phase Suite -BinDirectory C:\PathChordLab\stage-latest `
  -ArtifactManifest C:\PathChordLab\stage-latest\artifacts.json `
  -OutputDirectory C:\PathChordLab\results\suite-latest
```

The complete suite passed: **52 executable groups, 1,075 tests passed, zero
failures, 117 explicitly ignored external-peer/host child-entry fixtures, and
zero executable timeouts**. The explicit host fixtures are recorded separately;
ignored external-peer cases do not become interoperability evidence.

The suite includes HTTP/CONNECT, SOCKS4/4a/5, Mixed and SOCKS5 UDP,
authentication, source restrictions, IPv4/IPv6/domain resolution, bounded
resources, reload and shutdown. The additional native Windows IPv6 fixture
passed authenticated HTTP/SOCKS TCP and UDP, hostname resolution, 4 KiB UDP,
TCP half-close and bounded shutdown.

Focused repeats also passed: Path control ordering/deduplication, stalled
candidate timeout/failover, and directory replacement/noise were each repeated
ten times, for **30 passes and zero failures**. These repeats retain the strict
protocol assertions and do not reinterpret a Winsock reset as a valid response.

## WinINet and registry recovery

The explicit native host test
`native_windows_proxy_preserves_types_absence_and_crash_recovery` passed.
It covers WinINet apply/refresh, exact type and bytes for prior registry values,
originally absent values, and forced-process termination followed by journal
recovery in a new process. In particular, the saved `REG_EXPAND_SZ` value
remains `REG_EXPAND_SZ` after restoration.

## Ordinary-user and service control

The first SSH secondary-logon launch method returned `0xC0000142` for both
PathChord and built-in Windows programs; that historical diagnostic remains in
the earlier host logs. The final fixture uses SCM service logon under a local
Users account that is not an administrator. The native result passed all of the
following:

- CIM-reported daemon owner SID equals the owner-token probe SID;
- the owner and an administrator can query the Named Pipe;
- an unrelated ordinary user is denied;
- in-place valid configuration changes become visible;
- an invalid candidate leaves the last-good generation active; and
- atomic replacement becomes visible.

The recorded owner SID was `S-1-5-21-2917005514-3884835169-1399400339-1021`,
the unrelated-user SID was `S-1-5-21-2917005514-3884835169-1399400339-1022`,
and the owner was explicitly verified outside the local Administrators group.
The machine-readable result is
`/data/pathchord-qemu/windows/validation-20261118/platform-results/host-scm3-results.json`.

## Repairs exercised by the suite

- Rejected HTTP and SOCKS connections shut down their sending direction and
  perform a bounded read drain. This prevents Winsock from erasing the final
  protocol error response with a reset while preserving strict `400`/`431`
  and SOCKS `0x07` assertions.
- UDP target setup skips unscoped IPv6 link-local candidates and bounds each
  candidate's connect operation to one second before trying the next address.
- Recursive directory watching ignores root-level non-rename `Modify` events.
  The native notify backend maps `FILE_ACTION_MODIFIED` to `Modify(Any)`;
  resource-child events and directory create/remove/rename still trigger reload.
- Registry recovery restores journaled values, notifies WinINet, reapplies the
  exact saved registry types and bytes, and only then deletes the journal.
- Test portability uses platform paths and Named Pipe clients. Control teardown
  waits for its real acknowledgement, and synthetic timeout tests use paused
  Tokio time rather than depending on Windows timer resolution.

NSIS and service-account repairs and their separate native acceptance are
recorded under the [package change](../../2026-11-18-validate-native-packages/).

## Evidence and validation limits

Build provenance is
`/data/pathchord-qemu/windows/validation-20261118/build/validation-manifest.json`
(SHA-256 `cfa2a6fe1be236b3d6737dc19a6b4cc6b9480e55fd1ee84f3e45128389e1c903`).
It records the dirty source revision, 12 source hashes, build command/log hash,
staged artifact hashes and suite result. All 12 source hashes were independently
checked against the worktree after the run.

Runtime evidence is under
`/data/pathchord-qemu/windows/validation-20261118/platform-results/`:

- `suite-final-results.json`, `suite-final-host.json` and
  `suite-final-artifacts.json` identify the passing suite;
- `registry-results.json`, `registry-host.json` and `native-registry-proxy.log`
  identify the passing explicit registry fixture;
- `host-scm3-results.json` records the passing registry and nonadministrator
  owner/control/watcher groups. Its SHA-256 is
  `6553877786db07a77f624452cf409c74952131125697df2781394fca0b4fe75f`.
  `host-scm3.zip` contains their host logs, with SHA-256
  `7dcbd99574847a9e27612fd81d143a43a421b8107fdd62807b7b984ab6fb3801`;
- `platform-final.tar.gz` retains per-test logs and historical failed host
  attempts as well as the passing suite. Its SHA-256 is
  `1c8544bdeb131241d61374384fc65e87d0171a0687c6ccd023d47305747e2662`.

The Linux regression run passed 1,108 tests with zero failures and 118 explicit
ignores; the locked build, strict Clippy and formatting checks passed. This is
separate Linux evidence and is not used to fill Windows host checks.

After evidence collection the platform guest had no remaining fixture service,
fixture user or PathChord daemon. Secure Boot and TPM readiness still passed.
The guest shut down cleanly through ACPI and its overlay passed
`qemu-img check`. The disk chain and private management credentials remain
available for another run.

This is native execution on one Windows 11 Pro build under QEMU/KVM. It does
not establish older Windows compatibility, physical hardware, Wintun
distribution/TUN acceptance, external-peer execution, production rollout or
WAN performance. Package fixture versions use identical runtime binaries and
do not establish protocol-version or database-schema migration.
