# FreeBSD native platform validation

The 2026-11-17 run completed **1083 passing tests, zero failures and 118
explicitly ignored external-peer tests** across 51 native FreeBSD test
executables. All executable tests ran inside an independent FreeBSD 15.1-RELEASE
amd64 QEMU/KVM guest as the non-login `pathchord` account. A separate real Egress
process verified private identity, SQLite database and control-socket ownership
and modes, native SQLite operation, graceful SIGTERM and socket removal.

The retained [JSON evidence](2026-11-17-freebsd-native-validation.json) records
the image checksum and provenance, host and SDK metadata, compiler commands,
all test executable hashes and results, role hashes, source hashes and log
hashes. The complete local run is
`/data/pathchord-qemu/runs/freebsd-final-20261117-1655`; it took 116.22 seconds
including guest startup, artifact staging, execution and the service check.
The guest has been shut down and its temporary SSH credentials removed.

## Build and execution boundaries

The compiler ran on Linux. Clang 23.1.5, LLD 23.1.5 and `llvm-ar` used a
FreeBSD 15.1 SDK exported from the same official cloud-image family, with
consistent target-specific C/C++/archiver/linker selection. A native pthread C
smoke binary executed in the guest before the Rust tests. This is cross linking
followed by actual native execution; the target build alone is not the
execution evidence.

The SDK exports `usr/include`, target `usr/lib`, `lib` and `libexec`. Guest
compiler and debug-symbol trees are excluded. Absolute SDK library symlinks are
rewritten to stay within the sysroot. The exported archive SHA-256 is
`e5b9c75447e2b1d043dfcb35feb0c8404982b049e0be37213b9be5a84693e746`.
Headers, libraries and startup objects are from one target SDK. The linker
preserves Cargo's explicit build-library paths rather than redirecting them
through a different checkout or sysroot.

All VM volumes, SDK/cache files, host cross-build temporary files and reports
use `/data/pathchord-qemu`. The cross-build root is
`/data/pathchord-qemu/freebsd-build`, with an independent `target` directory
and `TMPDIR`. Guest temporary files belong to the disposable VM's disk under
that root. Compilation uses two jobs and no debug information for this
validation profile; the guest executes one test thread per executable.

The default image mirror is the requested CERNET mirror. This run reused the
already downloaded official image after verifying its official checksum; the
JSON preserves both the requested mirror and the actual cached source.
The compressed image SHA-256 is
`e4ca4db889f8559c9b9dfcacc70405c038476f4b6d41649b152d3809a2ed9e1f`.

## Reproduce

The [runner](../../../../scripts/test-freebsd-platforms.py) owns its guest through
the [FreeBSD lab context](../../../../scripts/qemu_freebsd.py). It does not
change host accounts, routes, firewall rules or service configuration.

```sh
python3 -B scripts/test-freebsd-platforms.py \
  --output /data/pathchord-qemu/runs/freebsd-platforms-new-run \
  --jobs 2 --test-threads 1
```

The build command issued by the runner is:

```sh
cargo build --locked --workspace --all-targets \
  --target x86_64-unknown-freebsd --jobs 2 \
  --message-format=json-render-diagnostics
```

The target environment is generated under `freebsd-build/toolchain.json` and
includes `CC_x86_64_unknown_freebsd`, `CXX_x86_64_unknown_freebsd`,
`AR_x86_64_unknown_freebsd`,
`CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_LINKER`, `CARGO_TARGET_DIR` and `TMPDIR`.
Each native executable runs through `su -m pathchord`, with an explicit private
HOME/TMPDIR and `umask 077`. The final run reused the identical artifacts from
the immediately preceding incremental build; both commands are preserved in
the JSON.

For a focused native diagnostic without rebuilding:

```sh
python3 -B scripts/test-freebsd-platforms.py \
  --output /data/pathchord-qemu/runs/freebsd-focused-new-run \
  --reuse-artifacts /data/pathchord-qemu/runs/freebsd-final-20261117-1650/artifacts.json \
  --test-target pathchord_egress \
  --test-filter node::tests::incomplete_admission_releases_the_only_path_permit \
  --repetitions 5 --test-threads 1
```

## Observed coverage

| Area | Native execution evidence |
| --- | --- |
| Explicit listeners | HTTP forwarding/CONNECT, SOCKS4/4a/5, Mixed, SOCKS5 UDP, credentials, source restrictions, IPv4/IPv6, hostname preservation, cancellation, half-close and bounded shutdown |
| DNS | Native DNS runtime tests, local UDP/TCP exchange and truncation recovery, route errors, cache bounds and typed failure behavior; Egress hostname resolution also runs against the guest resolver |
| Configuration | Complete bundles, duplicate/reference validation, directory add/update/rename/remove, atomic file/root replacement, single-file in-place writes, deletion/recreation, invalid-candidate retention and in-place/atomic geodata updates |
| Management | Unix socket framing and ownership, status, local enrollment, independent role processes, Web token authorization, generation fences, subscription control and process restart |
| Native dependencies | Every role passes guest `ldd`; Noise/crypto, native sockets, bundled SQLite and libprocstat-backed metadata are exercised by the actual FreeBSD executables |
| Process metadata | The native provider queries an established local socket and may report its real current owner or unknown under permission limits; an absent socket returns unknown, and no user/group identity is fabricated |
| Private storage | Generated identities and control sockets are checked for mode 0600 and the effective service UID; the standalone Egress check also verifies an actual 0600 SQLite file owned by `pathchord` |
| Lifecycle/resources | Admission timeout/permit recovery, terminal revocation, draining and fresh Session identity, bounded task/buffer/queue behavior, real listener cancellation and graceful role-process SIGTERM with socket removal |

The final role executable SHA-256 values are:

| Artifact | SHA-256 |
| --- | --- |
| `pathchord-ingressd` | `3b7b0e5f9401bbe51d827f38fd5b2488c1b2e7bac3b58c63d9ae8f0dc3c53964` |
| `pathchord-egressd` | `9a1b7728b255aa178f1b1e99b70b903d866a1755f68349d759a7345b7698b817` |
| `pathchordctl` | `09ed50c2b46d37c4c73a5479b8bf23d0c4d156fa343d824e0088b33aa1d4a806` |

## Failures found and repaired

The first native run exposed a Linux-only positive eBPF configuration test
which expected policy conversion to succeed on every host. It now asserts
successful conversion on Linux and explicit platform rejection elsewhere.
The product's FreeBSD interception boundary is unchanged.

A shortened admission test had two platform assumptions: unread TCP data can
cause a reset rather than EOF, and its raw test sockets allowed Nagle/delayed
ACK latency to consume a 150 ms handshake deadline. Five native repetitions
initially produced three failures. The test now accepts EOF or connection reset
as terminal closure and sets TCP_NODELAY on its handshake sockets. The native
Egress suite then passes all 59 tests, including timeout permit recovery.

The single-file configuration watcher found a product issue: notify 8.2.2's
kqueue backend watches only the directory inode in non-recursive mode, so a
parent-directory watch does not observe in-place writes to an existing child.
The reloader now watches the file inode as well as the parent and re-arms that
watch after replacement. External geodata files have the same protection.
On FreeBSD, coarse parent events trigger a bounded candidate rescan. The native
regressions cover initial in-place writes, atomic replacement, subsequent
in-place writes, deletion/recreation and in-place geodata updates; invalid
candidates still retain the last good generation.

Two harness issues are recorded separately from product defects: the original
two-second SSH banner timeout occasionally prevented an executable from
starting, and an additional standalone check initially supplied port zero to
the service schema, which correctly rejects it. The runner uses a ten-second
management connection deadline and a fixed unused loopback port in its private
guest for that service check. The final complete run has no transport errors
or test failures.

## Limits

This verifies FreeBSD 15.1-RELEASE amd64 in QEMU with the recorded source and
artifact hashes. FreeBSD transparent interception and TUN remain explicitly
unsupported; platform-neutral fake-device tests do not establish native support
for those features. The 118 external-peer fixtures were deliberately ignored in
this native suite and have separate local/QEMU protocol evidence. Native
packaging, rc.d installation, upgrade/rollback and package removal are a
different validation task and are not inferred from these runtime tests.
