# Windows QEMU validation on 2026-11-17

This record captures the first native Windows run for `validate-native-platforms`.
The active tasks remain open because the run exposed reproducible Windows
failures and the host phase stopped at the system-proxy registry check.

## Guest and evidence

The guest is Windows 11 Pro x64, Simplified Chinese, build `26300.9457`,
running under QEMU/KVM with OVMF Secure Boot and an emulated TPM 2.0. The guest
reported `Confirm-SecureBootUEFI = True`, `TpmPresent = True`, and
`TpmReady = True`. The native process ran as the local administrator
`PC-WIN11\pcadmin`; the guest management endpoint was loopback-only SSH through
QEMU user networking. PowerShell 7.7.0 was used for the harness.

The clean installed baseline is `/data/pathchord-qemu/windows/base2`. The
listener/control overlay is `/data/pathchord-qemu/windows/native-platform` and
the package overlay is `/data/pathchord-qemu/windows/native-packages`. The
machine-readable host metadata and test archives are retained outside the
repository under `/data/pathchord-qemu/windows/results/`:

- `platform/host-final.zip` contains the WinINet/registry host result;
- `platform/suite-final.zip` contains all per-executable suite logs and results;
- `platform/focused-*.log` contains exact reruns of the unstable or failing
  cases;
- `host.json` records the guest OS, build, Secure Boot, TPM and SSH service.

The executable suite ran 52 staged Windows test binaries: 1,064 tests passed,
7 failed, 117 were explicitly ignored because their external peers were not
available, and no executable timed out.

## Observed results

Portable listener and control coverage exercised HTTP/CONNECT, SOCKS4/4a/5,
Mixed, SOCKS5 UDP, authentication, IPv4/IPv6 and bounded shutdown paths. The
following failures remain:

- malformed HTTP and rejected Mixed SOCKS requests observed Windows
  `WSAECONNRESET` where the existing tests expected an EOF response;
- an initial reordered-session-control `PathClosed` failure, which passed on
  the focused rerun;
- an initial stalled ordinary-proxy failover timeout, which passed on the
  focused rerun;
- Egress UDP candidate fallback reproducibly returned `Elapsed(())` before
  trying the later candidate;
- directory configuration watching reproducibly published a new generation
  for an unrelated runtime event;
- the relative truststore assertion used POSIX separators in the staged binary.

The path-separator assertion is corrected in the worktree, but was not included
in the staged executable rerun. A proposed reset-test adaptation was retained
only as `/data/pathchord-qemu/windows/results/unverified-reset-test-adaptation.patch`
because it had not been validated on the updated Windows binary. These edits
do not turn the native evidence above into a passing result.

The Windows system-proxy test ran natively and found a contract violation. The
seeded `ProxyOverride` value was `REG_EXPAND_SZ` (type 2). After apply, restore,
and the WinINet settings notification, its bytes matched the saved value but
its registry type was `REG_SZ` (type 1). The host phase stopped at this failure,
so the subsequent ordinary-user Named Pipe ACL and host watcher checks were not
executed in that phase.

The likely repair boundary is the restore/notification ordering: after the
WinINet notification, the adapter must verify or reapply every journaled value
with its saved type and bytes before deleting the journal. This needs a new
Windows build and a repeat of the native host test.

The temporary host SSH keys, generated guest-account password records and
installation seed media were removed after execution. The retained disks are
execution/evidence snapshots; another managed SSH run should prepare a new
guest with `scripts/qemu_windows.py` and fresh credentials. The baseline's
automatic device encryption also means offline OS-volume extraction must not
be assumed to work. Future baseline preparation should retain private local
management credentials until the VM itself is intentionally retired.

## Limits

This is native Windows execution in QEMU/KVM for one Windows 11 Pro build. It
does not establish support for all Windows releases, physical hardware,
Wintun installation, or a production network. The failures above keep tasks
1.1, 1.2 and 1.3 unchecked.
