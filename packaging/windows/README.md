# Windows role package

Build the selected profile from a Windows PowerShell prompt with Rust and NSIS:

```powershell
pwsh -File packaging\windows\build.ps1 -Role ingress
pwsh -File packaging\windows\build.ps1 -Role egress
```

Each installer contains only the selected daemon, `pathchordctl`, the manual,
matching service XML and role configuration. `-SkipBuild -DaemonBinary <path>
-CtlBinary <path>` uses matching prebuilt Windows executables. The installer
name includes the selected role and Cargo workspace version.

The installer rejects a conflicting installed role before stopping services,
writing files or changing ACLs. To change roles, uninstall the current profile
and run the other installer. `%ProgramData%\PathChord` operator configuration,
identity, credential and authorization state is preserved on removal.

WinSW is an explicit dependency and is not redistributed. Obtain and audit an
approved WinSW binary, copy it to `%ProgramFiles%\PathChord\winsw.exe`, then
register the selected role from an elevated PowerShell prompt:

```powershell
Set-Location "$env:ProgramFiles\PathChord\services"
.\install-service.ps1 -Action Install
```

The registration script reads the selected `role.txt`, registers only that
service, and applies ACLs for its restricted virtual account, SYSTEM and
Administrators. The service account can read its configuration and modify its
own data, credentials and logs. Ordinary users cannot access private state.

Before starting Egress, provision
`%ProgramData%\PathChord\data\egress\egress.key.json` and configure its
loopback default for the intended interface. Start the selected service with
`Start-Service PathChordEgressd` or `Start-Service PathChordIngressd`.
Upgrades stop the selected active service before replacing binaries and restore
it after ACL preparation; the existing configuration and identities are retained.
The uninstaller stops and unregisters only the selected WinSW wrapper.

Each role executable owns shutdown through its console/control signals. WinSW
supplies the Service Control Manager bridge and restart policy. Windows TUN
requires native device authorization for the selected Ingress service account;
explicit HTTP/SOCKS listeners require no administrator service account.
