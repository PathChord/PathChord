# Windows QEMU package validation on 2026-11-17

The Windows package run used the same Windows 11 Pro x64 QEMU guest baseline as
the platform run and kept all disks and output under `/data/pathchord-qemu`.
PowerShell 7.7.0, portable NSIS 3.13 and WinSW 3.0.0-alpha.11 were staged with
recorded SHA-256 values. The four role/version installers were built inside
Windows from the tested role binaries:

- Ingress 0.1.0 and 0.1.1;
- Egress 0.1.0 and 0.1.1.

The native NSIS build phase passed and produced matching role binaries for both
fixture versions. The package evidence is retained under
`/data/pathchord-qemu/windows/results/packages-attempt2/` and
`packages-attempt3/`, with installer build logs and the machine-readable
`package-evidence.json`.

The first actual Ingress installer invocation returned exit code 2 before it
registered the role, created a service, or wrote the role registry value. The
same result reproduced with the existing installer and with both spaced and
unspaced custom install paths. Initial harness attempts left only the
pre-install `ProgramData\PathChord\installer\active.json` marker. A later manual
raw-argument invocation wrote the daemon, management client, service files and
default configuration, but still returned 2 before role registration. Direct
`install-service.ps1 -Action Stop -Role ingress` and `-Action Prepare` succeeded
outside NSIS, so the exact NSIS-to-PowerShell failure boundary remains unresolved.

Because installation did not complete, SCM service lifecycle,
Named Pipe control, ACLs, opposite-role rejection, upgrade, rollback,
uninstall, and explicit role replacement were not accepted as native evidence.
Task 1.5 remains unchecked. The existing static NSIS checks still do not replace
this native result.
