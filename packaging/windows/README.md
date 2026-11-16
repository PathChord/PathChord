# Windows package

`pathchord.nsi` creates a per-machine NSIS installer. The installer places the
three binaries under `Program Files\PathChord`, installs the loopback default
resource at `%ProgramData%\PathChord\config\ingress\ingress.yaml`, and
includes the service definitions and the `pathchordctl(1)` manual.

Build from a Windows PowerShell prompt with Rust, NSIS, and the selected Rust
target installed:

```powershell
pwsh -File packaging\windows\build.ps1
```

Use `-SkipBuild` when matching `pathchord-ingressd.exe`, `pathchord-egressd.exe`,
and `pathchordctl.exe` files already exist. `build.ps1` reads the workspace
version from `Cargo.toml` and passes it to NSIS; the generated installer name
contains that version.

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
at `%ProgramData%\PathChord\data\egress\egress.key.json` and replace the
example bind/identity values before starting it. To remove the wrappers, run
the same script with `-Action Uninstall` before uninstalling the package.

Each role executable owns shutdown through its console/control signals; WinSW
supplies the Windows Service Control Manager bridge and restart policy. The XML
files are the service contract shipped by this package, while the wrapper
remains an explicit, auditable dependency.
