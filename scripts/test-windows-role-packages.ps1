<#
Run only inside a disposable Windows package host. The caller stages the real
Windows role binaries, this checkout and the explicitly selected WinSW/NSIS
tools. All retained evidence is written beneath OutputDirectory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BinDirectory,
    [Parameter(Mandatory = $true)] [string] $WinSW,
    [Parameter(Mandatory = $true)] [string] $MakeNSIS,
    [Parameter(Mandatory = $true)] [string] $OutputDirectory,
    [string] $ReuseInstallersDirectory = '',
    [ValidateSet('ingress', 'egress', 'both')] [string] $Role = 'both',
    [string] $InstallDirectory = 'C:\PathChord Native Fixture'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:PATHCHORD_DISPOSABLE_WINDOWS_HOST -ne '1') {
    throw 'Set PATHCHORD_DISPOSABLE_WINDOWS_HOST=1 only inside a disposable Windows guest.'
}
if (-not [Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem) {
    throw 'The native role-package matrix requires a 64-bit Windows process.'
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run the package-host matrix from an elevated administrator process.'
}
$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$BinDirectory = [IO.Path]::GetFullPath($BinDirectory)
$InstallDirectory = [IO.Path]::GetFullPath($InstallDirectory)
$PrivateRoot = Join-Path $env:ProgramData 'PathChord'
if (Test-Path 'HKLM:\Software\PathChord') { throw 'A PathChord package is already registered; use a clean guest overlay.' }
foreach ($id in @('PathChordIngressd', 'PathChordEgressd')) {
    if (Get-Service -Name $id -ErrorAction SilentlyContinue) { throw "Service $id already exists; use a clean guest overlay." }
}
if (Test-Path -LiteralPath $InstallDirectory) { throw 'The fixture install directory already exists.' }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$Installers = Join-Path $OutputDirectory 'installers'
New-Item -ItemType Directory -Force -Path $Installers | Out-Null
$Events = [Collections.Generic.List[object]]::new()
$RunId = [Guid]::NewGuid().ToString('N')
$Manifest = [ordered]@{
    schema_version = 1
    windows = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
        Select-Object ProductName, DisplayVersion, CurrentBuild, UBR, EditionID
    powershell = $PSVersionTable.PSVersion.ToString()
    management_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    started_at = [DateTime]::UtcNow.ToString('o')
    tools = @()
    artifacts = @()
    results = $Events
    passed = $false
}
foreach ($path in @($WinSW, $MakeNSIS)) {
    $Manifest.tools += [ordered]@{path = $path; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash}
}
foreach ($name in @('pathchord-ingressd.exe', 'pathchord-egressd.exe', 'pathchordctl.exe')) {
    $path = Join-Path $BinDirectory $name
    $Manifest.artifacts += [ordered]@{name = $name; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash}
}

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}
function Save-Event([string] $Name, $Details) {
    $Events.Add([ordered]@{name = $Name; passed = $true; at = [DateTime]::UtcNow.ToString('o'); details = $Details})
    Write-Host "$Name`: passed"
}
function Installer-Inputs {
    $inputs = [ordered]@{}
    foreach ($name in @('pathchord-ingressd.exe', 'pathchord-egressd.exe', 'pathchordctl.exe')) {
        $inputs["bin/$name"] = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $BinDirectory $name)).Hash
    }
    foreach ($name in @('LICENSE', 'packaging/common/default-config.yaml', 'packaging/common/pathchord.1',
        'packaging/windows/version.ps1', 'packaging/windows/build.ps1', 'packaging/windows/pathchord.nsi', 'packaging/windows/install-service.ps1',
        'packaging/windows/egress.yaml', 'packaging/windows/pathchord-ingressd.xml', 'packaging/windows/pathchord-egressd.xml')) {
        $inputs[$name] = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $RepoRoot $name)).Hash
    }
    return $inputs
}
function Invoke-Native([string] $Executable, [string[]] $Arguments, [string] $Label, [int] $TimeoutSeconds = 90, [switch] $AllowFailure) {
    # ProcessStartInfo preserves native exit codes even for GUI NSIS executables.
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    Assert-True ($process.Start()) "Could not start $Label."
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $process.Kill($true)
        throw "$Label exceeded its $TimeoutSeconds second deadline."
    }
    $text = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $OutputDirectory "$Label.log"), $text)
    $code = $process.ExitCode
    $process.Dispose()
    if (-not $AllowFailure -and $code -ne 0) { throw "$Label exited $code`: $text" }
    return [pscustomobject]@{ExitCode = $code; Text = $text}
}
function Invoke-Installer([string] $Path, [string] $Label, [switch] $AllowFailure) {
    # NSIS consumes everything after /D= as the directory, including spaces.
    # A single raw Arguments string avoids adding quotes around that switch.
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Path
    $start.UseShellExecute = $false
    $start.Arguments = "/S /D=$InstallDirectory"
    $process = [Diagnostics.Process]::Start($start)
    if (-not $process.WaitForExit(180000)) {
        $process.Kill($true)
        throw "$Label exceeded its 180 second deadline."
    }
    $code = $process.ExitCode
    $process.Dispose()
    [ordered]@{installer = $Path; arguments = $start.Arguments; exit_code = $code} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory "$Label.json") -Encoding utf8
    if (-not $AllowFailure -and $code -ne 0) { throw "$Label exited $code." }
    return $code
}
function Invoke-Control([string] $CurrentRole, [string[]] $Arguments, [string] $Label) {
    $ctl = Join-Path $InstallDirectory 'pathchordctl.exe'
    $result = Invoke-Native $ctl (@('-o', 'json', '--socket', "\\.\pipe\pathchord-$CurrentRole") + $Arguments) $Label
    return $result.Text | ConvertFrom-Json
}
function Invoke-ServiceOwnerProbe([int] $ProcessId, [string] $Pipe, [string] $Label) {
    # Service-token DACLs need not grant TOKEN_DUPLICATE to Administrators.
    # Run only this test probe as SYSTEM, then impersonate the real daemon token.
    $script = Join-Path $OutputDirectory "$Label-owner-probe.ps1"
    $result = Join-Path $OutputDirectory "$Label-owner-probe.json"
    $errorFile = Join-Path $OutputDirectory "$Label-owner-probe-error.log"
    $source = Join-Path $PSScriptRoot 'windows-token-probe.cs'
    $quote = { param($Text) "'" + $Text.Replace("'", "''") + "'" }
    @"
`$ErrorActionPreference = 'Stop'
try {
    Add-Type -Path $(& $quote $source)
    [PathChordPackageTokenProbe]::EnableDebugPrivilege()
    [PathChordPackageTokenProbe]::Owner($ProcessId, $(& $quote $Pipe)) |
        ConvertTo-Json | Set-Content -LiteralPath $(& $quote $result) -Encoding utf8
} catch { `$_ | Out-String | Set-Content -LiteralPath $(& $quote $errorFile); exit 1 }
"@ | Set-Content -LiteralPath $script -Encoding utf8
    $taskName = 'PathChordPackageOwner-' + [Guid]::NewGuid().ToString('N')
    try {
        $action = New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'pwsh.exe') -Argument "-NoLogo -NoProfile -File `"$script`""
        Register-ScheduledTask -TaskName $taskName -Action $action -User SYSTEM -RunLevel Highest -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath $result) -and -not (Test-Path -LiteralPath $errorFile)) {
            Start-Sleep -Milliseconds 100
        }
        if (Test-Path -LiteralPath $errorFile) { throw (Get-Content -LiteralPath $errorFile -Raw) }
        Assert-True (Test-Path -LiteralPath $result) 'Service-owner token probe did not complete.'
        return Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
    } finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}
function Get-RoleProcess([string] $CurrentRole) {
    $name = "pathchord-${CurrentRole}d.exe"
    $found = @(Get-CimInstance Win32_Process -Filter "Name='$name'" |
        Where-Object ExecutablePath -eq (Join-Path $InstallDirectory $name))
    Assert-True ($found.Count -eq 1) "Expected one packaged $name process, found $($found.Count)."
    return $found[0]
}
function Wait-Control([string] $CurrentRole, [string] $Label) {
    $deadline = [DateTime]::UtcNow.AddSeconds(40)
    do {
        try { return Invoke-Control $CurrentRole @('status') $Label }
        catch { $lastError = $_; Start-Sleep -Milliseconds 150 }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "The $CurrentRole service did not become ready: $lastError"
}
function Assert-PrivateAcl([string] $CurrentRole, [string] $ServiceSid) {
    $records = @()
    foreach ($family in @('config', 'data', 'credentials', 'logs')) {
        $path = Join-Path $PrivateRoot "$family\$CurrentRole"
        $acl = Get-Acl -LiteralPath $path
        Assert-True $acl.AreAccessRulesProtected "Inherited ACL remains enabled on $path."
        $allowed = @('S-1-5-18', 'S-1-5-32-544', $ServiceSid)
        $grants = @()
        foreach ($rule in $acl.Access) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            Assert-True ($sid -in $allowed) "Unexpected ACL principal $sid on $path."
            Assert-True ($rule.AccessControlType -eq 'Allow') "Unexpected deny ACL on $path."
            if ($sid -eq $ServiceSid) {
                $expected = if ($family -eq 'config') { [Security.AccessControl.FileSystemRights]::ReadAndExecute } else { [Security.AccessControl.FileSystemRights]::Modify }
                Assert-True (($rule.FileSystemRights -band $expected) -eq $expected) "Service lacks $expected on $path."
                if ($family -eq 'config') {
                    Assert-True (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -eq 0) "Service can write its configuration."
                }
            }
            $grants += [ordered]@{sid = $sid; rights = $rule.FileSystemRights.ToString()}
        }
        Assert-True ($grants.sid -contains $ServiceSid) "Service SID is missing from $path."
        $records += [ordered]@{family = $family; sddl = $acl.Sddl; grants = $grants}
    }
    return $records
}
function Read-State([string] $CurrentRole) {
    $state = [ordered]@{}
    foreach ($relative in @("config\$CurrentRole\$CurrentRole.yaml", "data\$CurrentRole\lifecycle.identity", "data\$CurrentRole\lifecycle.authorizations", "credentials\$CurrentRole\lifecycle.credential")) {
        $state[$relative] = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PrivateRoot $relative)).Hash
    }
    return $state
}
function Assert-State($Expected, [string] $CurrentRole) {
    $actual = Read-State $CurrentRole
    foreach ($key in $Expected.Keys) { Assert-True ($Expected[$key] -eq $actual[$key]) "Private operator state changed at $key." }
}
function Remove-Role([string] $CurrentRole) {
    $uninstaller = Join-Path $InstallDirectory 'uninstall.exe'
    $start = [Diagnostics.ProcessStartInfo]::new($uninstaller, "/S _?=$InstallDirectory")
    $start.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($start)
    if (-not $process.WaitForExit(90000)) { $process.Kill($true); throw 'Uninstall deadline exceeded.' }
    Assert-True ($process.ExitCode -eq 0) 'The native uninstaller failed.'
    $process.Dispose()
    Assert-True (-not (Test-Path 'HKLM:\Software\PathChord')) 'Role registry survived uninstall.'
    Assert-True (-not (Get-Service -Name "PathChord$($CurrentRole.Substring(0,1).ToUpper())$($CurrentRole.Substring(1))d" -ErrorAction SilentlyContinue)) 'Service survived uninstall.'
    Assert-True (-not (Get-CimInstance Win32_Process -Filter "Name='pathchord-${CurrentRole}d.exe'")) 'Daemon survived uninstall.'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $InstallDirectory "pathchord-${CurrentRole}d.exe"))) 'Daemon binary survived uninstall.'
    # Our explicitly supplied WinSW is not an installer payload.
    $suppliedWinSW = Join-Path $InstallDirectory 'winsw.exe'
    if (Test-Path -LiteralPath $suppliedWinSW) { Remove-Item -LiteralPath $suppliedWinSW }
    if (Test-Path -LiteralPath $uninstaller) { Remove-Item -LiteralPath $uninstaller }
    if (Test-Path -LiteralPath $InstallDirectory) {
        Assert-True (@(Get-ChildItem -LiteralPath $InstallDirectory -Force).Count -eq 0) 'Unexpected files remained in fixture installation.'
        Remove-Item -LiteralPath $InstallDirectory
    }
}

# Query the control pipe while impersonating the actual daemon token. This
# checks owner access without granting another account the service's identity.
if (-not ('PathChordPackageTokenProbe' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'windows-token-probe.cs') }
[PathChordPackageTokenProbe]::EnableDebugPrivilege()
$DeniedUser = 'pcpkg' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$DeniedPassword = 'Pc9!' + [Guid]::NewGuid().ToString('N')
$DeniedAccount = $null
try {
    $DeniedAccount = New-LocalUser -Name $DeniedUser -Password (ConvertTo-SecureString $DeniedPassword -AsPlainText -Force) -AccountNeverExpires -PasswordNeverExpires
    Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $DeniedAccount
    $inputs = Installer-Inputs
    if ($ReuseInstallersDirectory) {
        $previous = Get-Content -LiteralPath (Join-Path $ReuseInstallersDirectory 'installer-inputs.json') -Raw | ConvertFrom-Json -AsHashtable
        Assert-True ($previous.native_windows_build -eq $true) 'The reused fixtures have no native Windows build record.'
        Assert-True ($previous.inputs.Count -eq $inputs.Count) 'Reused installer input set changed.'
        foreach ($name in $inputs.Keys) {
            Assert-True ($previous.inputs[$name] -eq $inputs[$name]) "Reused installer input changed: $name"
        }
        foreach ($currentRole in @('ingress', 'egress')) {
            foreach ($version in @('0.1.0', '0.1.1')) {
                $name = "pathchord-${currentRole}d-$version-windows-x86_64-setup.exe"
                $source = Join-Path $ReuseInstallersDirectory $name
                $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash
                Assert-True ($previous.installers[$name] -eq $hash) "Reused installer hash changed: $name"
                Copy-Item -LiteralPath $source -Destination (Join-Path $Installers $name)
            }
        }
        Save-Event 'native-nsis-build-reused' @{source = $ReuseInstallersDirectory; inputs_verified = $true; identical_binaries = $true}
    } else {
        foreach ($currentRole in @('ingress', 'egress')) {
            foreach ($version in @('0.1.0', '0.1.1')) {
                $build = Join-Path $RepoRoot 'packaging\windows\build.ps1'
                $arguments = @('-NoLogo', '-NoProfile', '-File', $build, '-Role', $currentRole, '-Version', $version, '-SkipBuild', '-MakeNSIS', $MakeNSIS,
                    '-DaemonBinary', (Join-Path $BinDirectory "pathchord-${currentRole}d.exe"), '-CtlBinary', (Join-Path $BinDirectory 'pathchordctl.exe'), '-OutputDirectory', $Installers)
                Invoke-Native (Join-Path $PSHOME 'pwsh.exe') $arguments "build-$currentRole-$version" -TimeoutSeconds 600 | Out-Null
            }
        }
        Save-Event 'native-nsis-build' @{profiles = @('ingress', 'egress'); versions = @('0.1.0', '0.1.1'); identical_binaries = $true}
    }
    $installerHashes = [ordered]@{}
    foreach ($file in Get-ChildItem -LiteralPath $Installers -Filter '*setup.exe') {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash
        $Manifest.artifacts += [ordered]@{name = $file.Name; sha256 = $hash}
        $installerHashes[$file.Name] = $hash
    }
    [ordered]@{native_windows_build = $true; inputs = $inputs; installers = $installerHashes} |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $Installers 'installer-inputs.json') -Encoding utf8
    $roles = if ($Role -eq 'both') { @('ingress', 'egress') } else { @($Role) }
    foreach ($currentRole in $roles) {
        if ((Split-Path -Leaf $WinSW) -ne 'WinSW-x64.exe') { throw 'This fixture requires the pinned WinSW3 binary named WinSW-x64.exe.' }
        $otherRole = if ($currentRole -eq 'ingress') { 'egress' } else { 'ingress' }
        $serviceId = if ($currentRole -eq 'ingress') { 'PathChordIngressd' } else { 'PathChordEgressd' }
        $daemonName = "pathchord-${currentRole}d.exe"
        $older = Join-Path $Installers "pathchord-${currentRole}d-0.1.0-windows-x86_64-setup.exe"
        $newer = Join-Path $Installers "pathchord-${currentRole}d-0.1.1-windows-x86_64-setup.exe"
        $opposite = Join-Path $Installers "pathchord-${otherRole}d-0.1.0-windows-x86_64-setup.exe"
        Invoke-Installer $older "$currentRole-install" | Out-Null
        $payload = @(Get-ChildItem -LiteralPath $InstallDirectory -Recurse -File | ForEach-Object {$_.FullName.Substring($InstallDirectory.Length + 1)})
        foreach ($relative in @($daemonName, 'pathchordctl.exe', 'pathchord.1', 'LICENSE', "services\pathchord-${currentRole}d.xml", 'services\install-service.ps1', 'services\role.txt', 'uninstall.exe')) {
            Assert-True ($payload -contains $relative) "Missing installed payload $relative."
        }
        Assert-True (-not ($payload -contains "pathchord-${otherRole}d.exe")) 'Opposite daemon was installed.'
        Assert-True (-not ($payload -contains "services\pathchord-${otherRole}d.xml")) 'Opposite service definition was installed.'
        Assert-True (((Get-Content -LiteralPath (Join-Path $InstallDirectory 'services\role.txt') -Raw).Trim()) -eq $currentRole) 'Installed role marker is incorrect.'
        $registration = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\pathchord-${currentRole}d"
        Assert-True ($registration.InstallLocation -eq $InstallDirectory) 'Installer ignored the custom directory.'
        $configPath = Join-Path $PrivateRoot "config\$currentRole\$currentRole.yaml"
        $template = Get-Content -LiteralPath $configPath -Raw
        Assert-True ($template.Contains('127.0.0.1:')) 'Default configuration is not loopback-only.'
        [xml]$serviceXml = Get-Content -LiteralPath (Join-Path $InstallDirectory "services\pathchord-${currentRole}d.xml") -Raw
        Assert-True ($serviceXml.service.executable -eq "%BASE%\$daemonName") 'Service executable does not resolve from the wrapper directory.'
        Assert-True ($serviceXml.service.arguments.Contains("%ProgramData%\PathChord\config\$currentRole")) 'Installer and service disagree on the configuration directory.'
        Save-Event "$currentRole-payload" @{files = $payload; install_location = $registration.InstallLocation; version = $registration.DisplayVersion}

        Add-Content -LiteralPath $configPath -Value "`r`n# operator-lifecycle-sentinel"
        $statePath = Join-Path $PrivateRoot "data\$currentRole"
        $credentialPath = Join-Path $PrivateRoot "credentials\$currentRole"
        $ctl = Join-Path $InstallDirectory 'pathchordctl.exe'
        if (-not (Test-Path -LiteralPath (Join-Path $statePath 'lifecycle.identity'))) {
            Invoke-Native $ctl @('-o', 'json', 'keygen', '--identity-file', (Join-Path $statePath 'lifecycle.identity')) "$currentRole-keygen-sentinel" | Out-Null
        }
        [IO.File]::WriteAllText((Join-Path $statePath 'lifecycle.authorizations'), ('authorization-state-fixture-' + $RunId))
        [IO.File]::WriteAllText((Join-Path $credentialPath 'lifecycle.credential'), ('private-credential-fixture-' + $RunId))
        if ($currentRole -eq 'egress' -and -not (Test-Path -LiteralPath (Join-Path $statePath 'egress.key.json'))) {
            Invoke-Native $ctl @('-o', 'json', 'keygen', '--identity-file', (Join-Path $statePath 'egress.key.json')) 'egress-keygen' | Out-Null
        }
        $expectedState = Read-State $currentRole
        $register = Join-Path $InstallDirectory 'services\install-service.ps1'
        Copy-Item -LiteralPath $WinSW -Destination (Join-Path $InstallDirectory 'winsw.exe')
        Invoke-Native (Join-Path $PSHOME 'pwsh.exe') @('-NoProfile', '-File', $register, '-Action', 'Install') "$currentRole-register-service" | Out-Null
        $service = Get-CimInstance Win32_Service -Filter "Name='$serviceId'"
        Assert-True ($service.StartName -eq "NT SERVICE\$serviceId") 'Service account is not the selected virtual service account.'
        $serviceSid = [Security.Principal.NTAccount]::new('NT SERVICE', $serviceId).Translate([Security.Principal.SecurityIdentifier]).Value
        $acls = Assert-PrivateAcl $currentRole $serviceSid
        Start-Service -Name $serviceId
        Wait-Control $currentRole "$currentRole-start-status" | Out-Null
        $daemon = Get-RoleProcess $currentRole
        $owner = Invoke-CimMethod -InputObject $daemon -MethodName GetOwnerSid
        Assert-True ($owner.ReturnValue -eq 0 -and $owner.Sid -eq $serviceSid) 'The real daemon does not run under its virtual service SID.'
        $ownerProbe = Invoke-ServiceOwnerProbe ([int]$daemon.ProcessId) "pathchord-$currentRole" $currentRole
        Assert-True ($ownerProbe.Sid -eq $serviceSid) 'Control probe did not use the service token.'
        $ownerResponse = $ownerProbe.Response | ConvertFrom-Json
        Assert-True $ownerResponse.ok 'Service-owner control request was rejected.'
        $denied = [PathChordPackageTokenProbe]::OrdinaryUser($DeniedUser, $DeniedPassword, "pathchord-$currentRole")
        Assert-True $denied.AccessDenied 'The ordinary user was not denied by the private Named Pipe ACL.'
        Save-Event "$currentRole-account-acl-control" @{service_sid = $serviceSid; actual_owner_sid = $owner.Sid; acl = $acls; owner_control = $true; admin_control = $true; ordinary_user_denied = $true; ordinary_user_sid = $denied.Sid}
        if ($currentRole -eq 'egress') {
            $keyResult = Invoke-Native $ctl @('-o', 'json', 'keygen', '--identity-file', (Join-Path $statePath 'native-ingress.key.json')) 'egress-enrollment-keygen'
            $public = ($keyResult.Text | ConvertFrom-Json).public_key
            Invoke-Control 'egress' @('enroll', 'add', '--ingress-id', 'lifecycle-fixture', '--egress-id', 'egress', '--public-key', $public, '--expected-generation', '0', '--label', 'sentinel=native-upgrade') 'egress-enroll' | Out-Null
            $identityHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $statePath 'egress.key.json')).Hash
        }
        $beforeConflict = (Get-RoleProcess $currentRole).ProcessId
        $conflictResult = Invoke-Installer $opposite "$currentRole-opposite-conflict" -AllowFailure
        Assert-True ($conflictResult -ne 0) 'Opposite-role installer returned success.'
        Assert-True ((Get-RoleProcess $currentRole).ProcessId -eq $beforeConflict) 'Opposite-role rejection changed the running daemon PID.'
        Assert-State $expectedState $currentRole
        Assert-True ((Get-ItemProperty 'HKLM:\Software\PathChord').Role -eq $currentRole) 'Opposite-role rejection changed the role registry.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $InstallDirectory "pathchord-${otherRole}d.exe"))) 'Opposite-role rejection wrote the other daemon.'
        Wait-Control $currentRole "$currentRole-conflict-status" | Out-Null
        Save-Event "$currentRole-opposite-rejection" @{exit_code = $conflictResult; unchanged_pid = $beforeConflict; state_hashes = $expectedState}
        foreach ($operation in @(@{name = 'upgrade'; artifact = $newer; version = '0.1.1'}, @{name = 'rollback'; artifact = $older; version = '0.1.0'})) {
            $before = (Get-RoleProcess $currentRole).ProcessId
            Invoke-Installer $operation.artifact "$currentRole-$($operation.name)" | Out-Null
            Wait-Control $currentRole "$currentRole-$($operation.name)-status" | Out-Null
            $after = (Get-RoleProcess $currentRole).ProcessId
            Assert-True ($before -ne $after) "$($operation.name) did not restart the running daemon."
            Assert-State $expectedState $currentRole
            Assert-PrivateAcl $currentRole $serviceSid | Out-Null
            Assert-True ((Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\pathchord-${currentRole}d").DisplayVersion -eq $operation.version) 'Package version metadata did not change.'
            if ($currentRole -eq 'egress') {
                $enrollment = Invoke-Control 'egress' @('enroll', 'get', '--ingress-id', 'lifecycle-fixture') "egress-$($operation.name)-enrollment"
                Assert-True (($enrollment | ConvertTo-Json -Depth 12).Contains('native-upgrade')) 'Real authorization record was lost.'
                Assert-True ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $statePath 'egress.key.json')).Hash -eq $identityHash) 'Actual Egress identity changed.'
            }
            Save-Event "$currentRole-$($operation.name)" @{old_pid = $before; new_pid = $after; version = $operation.version; state_preserved = $true}
        }
        Stop-Service -Name $serviceId
        (Get-Service -Name $serviceId).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(40))
        Assert-True (-not (Get-CimInstance Win32_Process -Filter "Name='$daemonName'")) 'Daemon remained after SCM stop.'
        $closedState = [ordered]@{}
        if ($currentRole -eq 'egress') {
            foreach ($file in @('egress.key.json', 'authorizations.db')) { $closedState[$file] = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $statePath $file)).Hash }
        }
        Start-Service -Name $serviceId
        Wait-Control $currentRole "$currentRole-before-uninstall-status" | Out-Null
        Remove-Role $currentRole
        Assert-State $expectedState $currentRole
        foreach ($file in $closedState.Keys) { Assert-True ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $statePath $file)).Hash -eq $closedState[$file]) "Closed Egress file $file changed during uninstall." }
        Save-Event "$currentRole-uninstall" @{operator_state_preserved = $true; actual_egress_hashes = $closedState; service_removed = $true; process_removed = $true}
        Invoke-Installer $opposite "$currentRole-replace-role" | Out-Null
        Assert-True ((Get-ItemProperty 'HKLM:\Software\PathChord').Role -eq $otherRole) 'Explicit role replacement did not install the other role.'
        Assert-True (Test-Path -LiteralPath (Join-Path $InstallDirectory "pathchord-${otherRole}d.exe")) 'Replacement daemon missing.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $InstallDirectory $daemonName))) 'Prior daemon survived replacement.'
        Assert-State $expectedState $currentRole
        foreach ($file in $closedState.Keys) { Assert-True ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $statePath $file)).Hash -eq $closedState[$file]) "Closed Egress file $file changed during explicit replacement." }
        Remove-Role $otherRole
        Save-Event "$currentRole-explicit-replacement" @{new_role = $otherRole; old_operator_state_preserved = $true; actual_egress_hashes = $closedState}
    }
    $Manifest.passed = $true
} catch {
    $Manifest.error = $_.ToString()
    $Manifest.error_stack = $_.ScriptStackTrace
    foreach ($currentRole in @('ingress', 'egress')) {
        $source = Join-Path $PrivateRoot "logs\$currentRole"
        if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination (Join-Path $OutputDirectory "failure-logs-$currentRole") -Recurse -Force }
    }
    throw
} finally {
    if ($null -ne $DeniedAccount) { Remove-LocalUser -SID $DeniedAccount.SID -ErrorAction SilentlyContinue }
    $DeniedPassword = $null
    $Manifest.finished_at = [DateTime]::UtcNow.ToString('o')
    $Manifest | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'package-evidence.json') -Encoding utf8
}
