# Windows package

`pathchord.nsi` creates a per-machine NSIS installer. The installer places the
binary under `Program Files\PathChord`, installs the loopback default resource
at `%ProgramData%\PathChord\config\ingress.yaml`, and includes the service
definitions and the `pathchord(1)` manual.

Build from a Windows PowerShell prompt with Rust, NSIS, and the selected Rust
target installed:

```powershell
pwsh -File packaging\windows\build.ps1
```

Use `-SkipBuild` when a matching `target\x86_64-pc-windows-msvc\release\pathchord.exe`
already exists. `build.ps1` reads the workspace version from `Cargo.toml` and
passes it to NSIS; the generated installer name contains that version.

The package includes WinSW-compatible `pathchord-ingress.xml` and
`pathchord-egress.xml` definitions. WinSW is not redistributed by PathChord.
Download and audit the WinSW release approved by the operator, copy its
executable to the installation directory as `winsw.exe`, then run an elevated:

```powershell
Set-Location "$env:ProgramFiles\PathChord\services"
.\install-service.ps1 -Action Install
```

The script copies WinSW to the two service wrapper names and registers both
services. The Egress definition is a template: provision an Egress identity
at `%ProgramData%\PathChord\credentials\egress.key.json` and replace the
example bind/identity values before starting it. To remove the wrappers, run
the same script with `-Action Uninstall` before uninstalling the package.

The PathChord executable currently owns shutdown through its console/control
signals; WinSW supplies the Windows Service Control Manager bridge and restart
policy. The XML files are therefore the service contract shipped by this
package, while the wrapper remains an explicit, auditable dependency.
