# Windows package lifecycle validation on 2026-11-18

This record is the completed native follow-up to the historical [first package
run](2026-11-17-windows-qemu-package-validation.md). The first report retains
the original exit-code-2 failures; this run used the repaired installer helper
and a clean writable overlay cloned from the prepared Windows snapshot.

## Host and build

The package guest is the Windows 11 Pro 26H2 build `26300.9457` x64 QEMU guest used
for the native platform validation. PowerShell 7.7.0 launched the package
harness. NSIS 3.13 and WinSW x64 were staged in the guest. The harness records
their SHA-256 values and the three role binary hashes in
`package-evidence.json`.

The reusable baseline and package overlay are:

- `/data/pathchord-qemu/windows/snapshots/windows-ready-20261118/`;
- `/data/pathchord-qemu/windows/validation-20261118/packages-guest/`.

All disks, firmware, TPM state, fixture media, credentials and output remain
under `/data`. The package guest was never used as the prepared baseline.

The final-candidate invocation uses a new output directory and the same latest
role binaries as the passing platform suite:

```powershell
$env:PATHCHORD_DISPOSABLE_WINDOWS_HOST = '1'
& C:\PathChordLab\tools\pwsh\pwsh.exe -NoProfile -File `
  C:\PathChordLab\checkout\scripts\test-windows-role-packages.ps1 `
  -BinDirectory C:\PathChordLab\stage-latest `
  -WinSW C:\PathChordLab\tools\WinSW-x64.exe `
  -MakeNSIS C:\PathChordLab\nsis\makensis.exe `
  -OutputDirectory C:\PathChordLab\results\packages-final5 `
  -InstallDirectory 'C:\PathChord Latest Candidate'
```

The complete machine-readable result is retained at
`/data/pathchord-qemu/windows/validation-20261118/package-results/final5/package-evidence.json`
with SHA-256
`b6632306b95ab4586ebdcdc82388e894123598909b0b5aee70f8b7ec9e33f345`.
The guest log archive is
`/data/pathchord-qemu/windows/validation-20261118/package-results/final5/evidence.zip`
with SHA-256
`bc0bd71500b026ed90cb1045632040a9bc71cbe50f2b49e8529e44a8eca94f81`.
The result JSON has `passed: true`; its archive contains 38 files including
build logs, service/control responses, owner probes, conflict responses,
upgrade/rollback records and package hashes. The separate
`final5/installer-inputs.json` records all 12 inputs and four installer hashes;
its SHA-256 is
`911579f6d544c0a862ad77199664bc1a90c242b0701bd0a57f1a3fcdf9da3069`.

All three role hashes match the latest native platform suite build, and all
nine packaging/document input hashes match the current worktree. The earlier
passing `final4` fixture remains historical evidence; it used an older staged
runtime build, so the final candidate was rebuilt and fully exercised again.
All four final installers were downloaded to `final5/installers/` and their
SHA-256 values were verified against the native input manifest.

## Native NSIS and service acceptance

The harness built both roles at versions 0.1.0 and 0.1.1 from the staged native
role binaries. The selected payload for each role contains its daemon,
`pathchordctl`, `pathchord(1)`, the role service definition and default
configuration. The opposite daemon and opposite service definition are absent.
The fixture install path included spaces:
`C:\PathChord Latest Candidate`.

For each role, the native run passed:

- installation, payload and registry/service agreement;
- virtual service-account assignment and private config/data/credentials/logs
  ACLs;
- owner and administrator Named Pipe status access;
- rejection of an unrelated ordinary user;
- rejection of installing the opposite role while preserving the running PID
  and sentinel state;
- upgrade from 0.1.0 to 0.1.1 with service recovery and operator-state hashes
  unchanged;
- rollback to 0.1.0 with the same preservation checks;
- silent uninstall with the service, process, role registration and installed
  payload removed while private operator state remained; and
- explicit replacement with the opposite role while retaining the Egress
  identity/authorization hashes where applicable.

The run completed with exit code 0 in 588.0 seconds and recorded 15 passing
events: one dual-role NSIS build event, seven Ingress events and seven Egress
events. The Egress run created a real enrollment record and retained its
`egress.key.json` and `authorizations.db` hashes across upgrade, rollback,
uninstall and explicit replacement.

After the run no fixture service, daemon, ordinary-user probe account, owner
probe scheduled task or role registration remained. Secure Boot and TPM
readiness still passed. The package guest was shut down cleanly and its overlay
passed `qemu-img check`; private management credentials, firmware and TPM state
were retained for reuse.

## Repairs validated

The installer invokes the 64-bit Windows PowerShell executable from NSIS and
the helper normalizes `PSModulePath` before loading Windows PowerShell Desktop
modules. This fixes the PowerShell 7 inherited-environment failure that caused
the earlier exit code 2. The empty active-service list is handled without
passing an empty name to SCM. Virtual service SIDs are assigned through SCM
after WinSW registers the wrapper; the service XML does not request a virtual
account before that SID exists. The Win32 service account change omits an empty
`StartPassword`, which Windows rejects for virtual accounts.

## Evidence limits

This is native package and service evidence for one Windows 26H2 build under
QEMU/KVM. It does not prove physical-hardware behavior, older Windows support,
Wintun/TUN distribution, or a production upgrade. Package fixture versions
0.1.0 and 0.1.1 intentionally use the same tested runtime binaries, so the run
does not establish a protocol-version or database-schema migration.
