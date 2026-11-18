[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BinDirectory,
    [Parameter(Mandatory = $true)] [string] $ArtifactManifest,
    [Parameter(Mandatory = $true)] [string] $OutputDirectory,
    [ValidateSet('All', 'Suite', 'Host')] [string] $Phase = 'All',
    [int] $TestThreads = 1,
    [int] $ExecutableTimeoutSeconds = 300
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'Run only inside a disposable native Windows guest.' }
$BinDirectory = (Resolve-Path -LiteralPath $BinDirectory).Path
$ArtifactManifest = (Resolve-Path -LiteralPath $ArtifactManifest).Path
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$env:TEMP = Join-Path $OutputDirectory 'tmp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Path $env:TEMP -Force | Out-Null
$env:PATHCHORD_TEST_WINDOWS_ROOT = $OutputDirectory
Remove-Item Env:PATHCHORD_CONFIG -ErrorAction SilentlyContinue
Remove-Item Env:PATHCHORD_CONFIG_DIR -ErrorAction SilentlyContinue
$records = [System.Collections.Generic.List[object]]::new()
$artifacts = @(Get-Content -LiteralPath $ArtifactManifest -Raw | ConvertFrom-Json)

function Save-Json([object] $Value, [string] $Path) {
    ConvertTo-Json -InputObject $Value -Depth 30 | Set-Content -LiteralPath $Path -Encoding utf8
}
function Assert-Condition([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}
function Invoke-Native([string] $Executable, [string[]] $Arguments, [string] $Label, [int] $Timeout = 30) {
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.CreateNoWindow = $true
    $info.WorkingDirectory = $OutputDirectory
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    $started = [DateTime]::UtcNow
    if (-not $process.Start()) { throw "Could not start $Label." }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($Timeout * 1000)
    if ($timedOut) { $process.Kill($true); $process.WaitForExit() }
    $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
    $output | Set-Content -LiteralPath (Join-Path $OutputDirectory "$Label.log") -Encoding utf8
    $result = [ordered]@{
        label = $Label; executable = $Executable; arguments = $Arguments
        exit_code = $process.ExitCode; timed_out = $timedOut
        elapsed_seconds = ([DateTime]::UtcNow - $started).TotalSeconds
        output = $output
    }
    $process.Dispose()
    return [pscustomobject] $result
}
function Invoke-Control([string] $Pipe) {
    $value = Invoke-Native (Join-Path $BinDirectory 'pathchordctl.exe') @('--socket', $Pipe, 'status') 'control-status'
    if ($value.exit_code -ne 0) { throw "Local control failed: $($value.output)" }
    $response = $value.output | ConvertFrom-Json
    Assert-Condition $response.ok 'Local control did not return success.'
    return $response
}
function Wait-Until([scriptblock] $Predicate, [string] $Description, [int] $Timeout = 30) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Timeout)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (& $Predicate) { return }
        Start-Sleep -Milliseconds 200
    }
    throw "Timed out waiting for $Description."
}

try {
    Save-Json ([ordered]@{
        os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
        powershell = $PSVersionTable.PSVersion.ToString()
        account = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        account_sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        bin_directory = $BinDirectory; artifact_manifest = $ArtifactManifest
        utc = [DateTime]::UtcNow.ToString('o')
    }) (Join-Path $OutputDirectory 'host.json')
    foreach ($artifact in $artifacts) {
        $binary = Join-Path $BinDirectory ([IO.Path]::GetFileName($artifact.path))
        $hash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-Condition ($hash -eq $artifact.sha256) "Artifact hash mismatch: $binary"
    }
    if ($Phase -in @('All', 'Suite')) {
        foreach ($artifact in @($artifacts | Where-Object { $_.test })) {
            $binary = Join-Path $BinDirectory ([IO.Path]::GetFileName($artifact.path))
            $label = [IO.Path]::GetFileNameWithoutExtension($binary)
            $run = Invoke-Native $binary @("--test-threads=$TestThreads") $label $ExecutableTimeoutSeconds
            $match = [regex]::Matches($run.output, 'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored')
            $entry = [ordered]@{
                name = $artifact.name; executable = [IO.Path]::GetFileName($binary)
                sha256 = $artifact.sha256; exit_code = $run.exit_code
                timed_out = $run.timed_out; elapsed_seconds = $run.elapsed_seconds
                verdict = 'missing_summary'; passed = 0; failed = 0; ignored = 0
            }
            if ($match.Count -gt 0) {
                $summary = $match[$match.Count - 1]
                $entry.verdict = $summary.Groups[1].Value
                $entry.passed = [int] $summary.Groups[2].Value
                $entry.failed = [int] $summary.Groups[3].Value
                $entry.ignored = [int] $summary.Groups[4].Value
            }
            $records.Add([pscustomobject] $entry)
            Save-Json $records (Join-Path $OutputDirectory 'results.json')
            Write-Output (ConvertTo-Json -InputObject $entry -Compress)
        }
    }
    if ($Phase -in @('All', 'Host')) {
        $native = @($artifacts | Where-Object { $_.test -and $_.name -eq 'windows_platform' })
        Assert-Condition ($native.Count -eq 1) 'Missing Windows native registry acceptance executable.'
        $nativeBinary = Join-Path $BinDirectory ([IO.Path]::GetFileName($native[0].path))
        $run = Invoke-Native $nativeBinary @('--ignored', '--exact', 'native_windows_proxy_preserves_types_absence_and_crash_recovery', '--nocapture') 'native-registry-proxy' 120
        Assert-Condition ($run.exit_code -eq 0 -and $run.output -match '1 passed; 0 failed') 'Native registry proxy/recovery acceptance failed.'
        $records.Add([pscustomobject]@{ name = 'native_registry_proxy'; verdict = 'ok'; passed = 1; failed = 0; ignored = 0; exit_code = 0; elapsed_seconds = $run.elapsed_seconds })

        $probeSource = Join-Path $PSScriptRoot 'windows-token-probe.cs'
        if (-not ('PathChordPackageTokenProbe' -as [type])) {
            Add-Type -Path $probeSource
        }
        [PathChordPackageTokenProbe]::EnableDebugPrivilege()
        $suffix = [Guid]::NewGuid().ToString('N').Substring(0, 7)
        $ownerName = "pcowner$suffix"
        $deniedName = "pcdeny$suffix"
        $ownerPassword = 'Pc!' + [Guid]::NewGuid().ToString('N') + '9a'
        $deniedPassword = 'Pc!' + [Guid]::NewGuid().ToString('N') + '9a'
        $ownerSecure = ConvertTo-SecureString $ownerPassword -AsPlainText -Force
        $deniedSecure = ConvertTo-SecureString $deniedPassword -AsPlainText -Force
        $owner = $null
        $daemon = $null
        $ownerService = $null
        $ownerWrapper = $null
        $ownerXml = $null
        try {
            $owner = New-LocalUser -Name $ownerName -Password $ownerSecure -AccountNeverExpires -PasswordNeverExpires -Description 'Disposable PathChord native listener owner'
            Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $owner
            New-LocalUser -Name $deniedName -Password $deniedSecure -AccountNeverExpires -PasswordNeverExpires -Description 'Disposable PathChord denied control identity' | Out-Null
            $identityRoot = Join-Path $OutputDirectory 'ordinary-user'
            New-Item -ItemType Directory -Path $identityRoot -Force | Out-Null
            & icacls.exe $identityRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$($owner.SID.Value):(OI)(CI)F" | Out-Null
            Assert-Condition ($LASTEXITCODE -eq 0) 'Could not isolate ordinary-user state.'
            $dataRoot = Join-Path $identityRoot 'data'
            $credentialRoot = Join-Path $identityRoot 'credentials'
            New-Item -ItemType Directory -Path $dataRoot, $credentialRoot -Force | Out-Null
            $portProbe = [System.Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
            $portProbe.Start(); $port = $portProbe.LocalEndpoint.Port; $portProbe.Stop()
            $configPath = Join-Path $identityRoot 'ingress.yaml'
            $config = @"
apiVersion: pathchord.io/v1
kind: Listener
metadata: {name: native-http}
spec: {type: http, bind: '127.0.0.1:$port'}
---
apiVersion: pathchord.io/v1
kind: DNSPolicy
metadata: {name: default}
spec: {defaultRoute: local, local: {servers: ['127.0.0.1:53']}}
---
apiVersion: pathchord.io/v1
kind: FallbackPolicy
metadata: {name: default}
spec: {action: direct}
"@
            [IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))
            $pipe = "\\.\pipe\pathchord-owner-$suffix"
            # The role binary consumes a validated directory bundle. Keep the
            # authored ingress.yaml inside that directory so this host check
            # exercises the same source precedence and watcher path as a
            # packaged Windows service.
            $arguments = @('--socket', $pipe, '--config-dir', $identityRoot, '--data-dir', $dataRoot, '--credentials-dir', $credentialRoot)
            # Secondary logon from the SSH service inherits a noninteractive
            # desktop which prevents even cmd.exe/whoami.exe initialization on
            # this Windows host. SCM supplies a proper service logon context
            # while retaining this ordinary Users account's exact user SID.
            $winSW = Join-Path (Split-Path -Parent $BinDirectory) 'tools\WinSW-x64.exe'
            Assert-Condition (Test-Path -LiteralPath $winSW) 'The ordinary-user fixture requires the pinned WinSW tool.'
            $ownerService = "PathChordOwner$suffix"
            $ownerWrapper = Join-Path $identityRoot 'ordinary-owner-service.exe'
            $ownerXml = Join-Path $identityRoot 'ordinary-owner-service.xml'
            Copy-Item -LiteralPath $winSW -Destination $ownerWrapper
            $serviceArguments = ($arguments | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' }) -join ' '
            $escapedArguments = [Security.SecurityElement]::Escape($serviceArguments)
            $escapedExecutable = [Security.SecurityElement]::Escape((Join-Path $BinDirectory 'pathchord-ingressd.exe'))
            $escapedRoot = [Security.SecurityElement]::Escape($identityRoot)
            $escapedAccount = [Security.SecurityElement]::Escape("$env:COMPUTERNAME\$ownerName")
            $escapedPassword = [Security.SecurityElement]::Escape($ownerPassword)
            [IO.File]::WriteAllText($ownerXml, @"
<service>
  <id>$ownerService</id><name>$ownerService</name><startmode>Manual</startmode>
  <serviceaccount><username>$escapedAccount</username><password>$escapedPassword</password><allowservicelogon>true</allowservicelogon></serviceaccount>
  <executable>$escapedExecutable</executable><arguments>$escapedArguments</arguments>
  <workingdirectory>$escapedRoot</workingdirectory><logpath>$escapedRoot</logpath>
  <log mode="roll"/><stoptimeout>10 sec</stoptimeout>
</service>
"@, [Text.UTF8Encoding]::new($false))
            $register = Invoke-Native $ownerWrapper @('install') 'ordinary-user-service-install' 60
            Assert-Condition ($register.exit_code -eq 0) 'Ordinary-user service fixture registration failed.'
            # WinSW reopens its own SCM service while starting. The ordinary
            # account can control this disposable fixture, not the SCM or any
            # other service, and receives no administrator membership.
            $serviceAcl = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;$($owner.SID.Value))"
            & sc.exe sdset $ownerService $serviceAcl | Out-Null
            Assert-Condition ($LASTEXITCODE -eq 0) 'Could not grant the ordinary fixture owner access to its SCM object.'
            Start-Service -Name $ownerService
            Wait-Until { try { $null = Invoke-Control $pipe; return $true } catch { return $false } } 'ordinary-user Ingress Named Pipe' 60
            $admin = Invoke-Control $pipe
            $nativeProcess = @(Get-CimInstance Win32_Process -Filter "Name='pathchord-ingressd.exe'" | Where-Object { $_.CommandLine -like "*$pipe*" })
            Assert-Condition ($nativeProcess.Count -eq 1) 'Expected one ordinary-user fixture daemon.'
            $actualOwner = Invoke-CimMethod -InputObject $nativeProcess[0] -MethodName GetOwnerSid
            Assert-Condition ($actualOwner.ReturnValue -eq 0 -and $actualOwner.Sid -eq $owner.SID.Value) 'SCM daemon does not run under the ordinary owner account.'
            $daemon = Get-Process -Id $nativeProcess[0].ProcessId
            $ownerResult = [PathChordPackageTokenProbe]::AuthorizedUser($ownerName, $ownerPassword, $pipe.Substring(9))
            Assert-Condition ($ownerResult.Sid -eq $owner.SID.Value) 'Owner token does not match ordinary daemon account.'
            Assert-Condition (-not $ownerResult.AccessDenied -and ($ownerResult.Response | ConvertFrom-Json).ok) 'Pipe owner could not query its daemon.'
            $administrators = @(Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')) | ForEach-Object { $_.SID.Value })
            Assert-Condition ($owner.SID.Value -notin $administrators) 'Ordinary fixture owner is an administrator.'
            $deniedResult = [PathChordPackageTokenProbe]::OrdinaryUser($deniedName, $deniedPassword, $pipe.Substring(9))
            Assert-Condition $deniedResult.AccessDenied 'Unrelated ordinary user accessed protected Named Pipe.'
            $initialGeneration = $admin.result.configuration_reload.active_generation
            $rejectConfig = $config.Replace('action: direct', 'action: reject')
            [IO.File]::WriteAllText($configPath, $rejectConfig, [Text.UTF8Encoding]::new($false))
            Wait-Until { $value = Invoke-Control $pipe; return $value.result.configuration_reload.active_generation -gt $initialGeneration } 'in-place Windows configuration reload'
            $afterReload = Invoke-Control $pipe
            $activeGeneration = $afterReload.result.configuration_reload.active_generation
            [IO.File]::WriteAllText($configPath, "invalid: [", [Text.UTF8Encoding]::new($false))
            Wait-Until { $value = Invoke-Control $pipe; return $value.result.configuration_reload.state -eq 'rejected' } 'invalid configuration diagnostic'
            $invalid = Invoke-Control $pipe
            Assert-Condition ($invalid.result.configuration_reload.active_generation -eq $activeGeneration) 'Invalid reload changed the last-good generation.'
            $replacement = "$configPath.new"
            [IO.File]::WriteAllText($replacement, $config, [Text.UTF8Encoding]::new($false))
            $replacementBackup = "$configPath.backup"
            [IO.File]::Replace($replacement, $configPath, $replacementBackup, $true)
            Remove-Item -LiteralPath $replacementBackup -Force
            Wait-Until { $value = Invoke-Control $pipe; return $value.result.configuration_reload.active_generation -gt $activeGeneration } 'atomic Windows configuration replacement'
            $records.Add([pscustomobject]@{
                name = 'ordinary_user_control_and_watcher'; verdict = 'ok'; passed = 1; failed = 0; ignored = 0; exit_code = 0
                daemon_owner_sid = $actualOwner.Sid; owner_probe_sid = $ownerResult.Sid; unauthorized_sid = $deniedResult.Sid
                launch_context = 'SCM service logon for a nonadministrator local Users account'; owner_is_administrator = $false
                administrator_control = $true; owner_control = $true; unauthorized_access_denied = $true
                in_place_reload = $true; invalid_candidate_retained = $true; atomic_replacement_reload = $true
            })
        } finally {
            if ($ownerService) {
                Stop-Service -Name $ownerService -Force -ErrorAction SilentlyContinue
                if ($ownerWrapper -and (Test-Path -LiteralPath $ownerWrapper)) {
                    $null = & $ownerWrapper uninstall
                }
            }
            if ($ownerXml) { Remove-Item -LiteralPath $ownerXml -Force -ErrorAction SilentlyContinue }
            if ($ownerWrapper) { Remove-Item -LiteralPath $ownerWrapper -Force -ErrorAction SilentlyContinue }
            if ($daemon) { $daemon.Refresh(); if (-not $daemon.HasExited) { Stop-Process -Id $daemon.Id -Force }; $daemon.Dispose() }
            foreach ($name in @($ownerName, $deniedName)) { Remove-LocalUser -Name $name -ErrorAction SilentlyContinue }
        }
    }
    Save-Json $records (Join-Path $OutputDirectory 'results.json')
    $bad = @($records | Where-Object { $_.verdict -ne 'ok' -or $_.exit_code -ne 0 -or $_.failed -ne 0 })
    Assert-Condition ($bad.Count -eq 0) "$($bad.Count) native Windows result groups failed; inspect results.json and per-executable logs."
    Write-Output 'Windows native platform acceptance passed.'
} catch {
    Save-Json $records (Join-Path $OutputDirectory 'results.json')
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $OutputDirectory 'failure.log') -Encoding utf8
    throw
}
