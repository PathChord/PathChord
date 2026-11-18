[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall', 'Prepare', 'Stop')]
    [string] $Action = 'Install',
    [string] $WinSW = '',
    [ValidateSet('ingress', 'egress')]
    [string] $Role = ''
)

# NSIS can inherit PSModulePath from PowerShell 7. Windows PowerShell 5 must
# load its Desktop modules rather than Core modules with the same names.
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $env:PSModulePath = @(
        ([IO.Path]::Combine([Environment]::GetFolderPath('MyDocuments'), 'WindowsPowerShell\Modules')),
        ([IO.Path]::Combine($env:ProgramFiles, 'WindowsPowerShell\Modules')),
        ([IO.Path]::Combine($PSHOME, 'Modules'))
    ) -join [IO.Path]::PathSeparator
}
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$privateRoot = Join-Path $env:ProgramData 'PathChord'

function Set-RoleDirectoryAcl([string] $Path, [System.Security.Principal.SecurityIdentifier] $ServiceSid, [bool] $Writable) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $administrators = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    # Replace inherited and obsolete explicit grants, including the former shared account.
    $items = @((Get-Item -LiteralPath $Path)) + @(Get-ChildItem -LiteralPath $Path -Force -Recurse)
    foreach ($item in $items) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Private role root contains a reparse point: $($item.FullName)"
        }
        $acl = Get-Acl -LiteralPath $item.FullName
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($rule) }
        $acl.SetOwner($administrators)
        $inheritance = if ($item.PSIsContainer) {
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        } else { [System.Security.AccessControl.InheritanceFlags]::None }
        foreach ($principal in @($administrators, $system)) {
            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
                $principal, 'FullControl', $inheritance, 'None', 'Allow'))
        }
        $rights = if ($Writable) { 'Modify' } else { 'ReadAndExecute' }
        if ($null -ne $ServiceSid) {
            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
                $ServiceSid, $rights, $inheritance, 'None', 'Allow'))
        }
        Set-Acl -LiteralPath $item.FullName -AclObject $acl
    }
}

if ([string]::IsNullOrWhiteSpace($Role)) {
    $roleFile = Join-Path $PSScriptRoot 'role.txt'
    if (-not (Test-Path -LiteralPath $roleFile)) { throw 'Select the installed role explicitly.' }
    $Role = (Get-Content -LiteralPath $roleFile -Raw).Trim()
}
if ($Role -notin @('ingress', 'egress')) { throw 'Invalid installed role.' }
$registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
$registration = $registry.OpenSubKey('Software\PathChord')
$registeredRole = if ($registration) { $registration.GetValue('Role') } else { $null }
if ($registration) { $registration.Dispose() }
$registry.Dispose()
if ($registeredRole -and $registeredRole -ne $Role) { throw 'Uninstall the other PathChord role before changing roles.' }
$id = if ($Role -eq 'ingress') { 'PathChordIngressd' } else { 'PathChordEgressd' }
$services = @(@{Name = "pathchord-${Role}d"; Id = $id; Role = $Role})
$installerState = Join-Path $privateRoot 'installer'
trap {
    # A silent NSIS install has no interactive console. Preserve the helper's
    # exact failure without requiring the operator to reproduce it manually.
    $failure = $_ | Out-String
    try {
        Set-RoleDirectoryAcl $installerState $null $false
        $failure | Set-Content -LiteralPath (Join-Path $installerState "$Role-$Action-error.log")
    } catch { }
    Write-Error -Message $failure -ErrorAction Continue
    exit 1
}
if ($Action -eq 'Stop') {
    Set-RoleDirectoryAcl $installerState $null $false
    $active = @()
    foreach ($service in $services) {
        $installed = Get-Service -Name $service.Id -ErrorAction SilentlyContinue
        if ($installed -and $installed.Status -ne 'Stopped') {
            $active += $service.Id
            Stop-Service -Name $service.Id -ErrorAction Stop
            (Get-Service -Name $service.Id).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
    }
    ConvertTo-Json -InputObject $active | Set-Content -LiteralPath (Join-Path $installerState 'active.json')
    exit 0
}
if ($Action -eq 'Prepare') {
    foreach ($service in $services) {
        $installed = Get-CimInstance Win32_Service -Filter "Name='$($service.Id)'"
        $serviceSid = $null
        if ($installed) {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot "$($service.Name).xml") -Destination (Join-Path $root "$($service.Name)-service.xml") -Force
            $changed = Invoke-CimMethod -InputObject $installed -MethodName Change -Arguments @{
                StartName = "NT SERVICE\$($service.Id)"
            }
            if ($changed.ReturnValue -ne 0) { throw "Could not isolate $($service.Id)." }
            & sc.exe sidtype $service.Id unrestricted | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not enable service SID." }
            $serviceSid = [System.Security.Principal.NTAccount]::new('NT SERVICE', $service.Id).Translate(
                [System.Security.Principal.SecurityIdentifier])
        }
        Set-RoleDirectoryAcl (Join-Path $privateRoot "config\$($service.Role)") $serviceSid $false
        foreach ($family in @('data', 'credentials', 'logs')) {
            Set-RoleDirectoryAcl (Join-Path $privateRoot "$family\$($service.Role)") $serviceSid $true
        }
    }
    $activeFile = Join-Path $installerState 'active.json'
    if (Test-Path -LiteralPath $activeFile) {
        # Windows PowerShell deserializes JSON [] as one empty pipeline value
        # when wrapped in @(...). Filter it before passing names to SCM.
        $activeText = (Get-Content -LiteralPath $activeFile -Raw).Trim()
        $activeIds = @()
        if ($activeText -and $activeText -ne '[]') {
            $activeValue = $activeText | ConvertFrom-Json
            $activeIds = @($activeValue | ForEach-Object { [string]$_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
        foreach ($id in $activeIds) {
            Start-Service -Name $id -ErrorAction Stop
        }
        Remove-Item -LiteralPath $activeFile -Force
    }
    exit 0
}

if ($Action -eq 'Install') {
    if ([string]::IsNullOrWhiteSpace($WinSW)) { $WinSW = Join-Path $root 'winsw.exe' }
    if (-not (Test-Path -LiteralPath $WinSW -PathType Leaf)) {
        throw "WinSW was not found at '$WinSW'. Supply an audited WinSW executable with -WinSW."
    }
}
foreach ($service in $services) {
    $name = $service.Name
    $wrapper = Join-Path $root "$name-service.exe"
    $wrapperConfig = Join-Path $root "$name-service.xml"
    if ($Action -eq 'Install') {
        # Stop an existing instance before replacing its account or inherited ACLs.
        $existing = Get-Service -Name $service.Id -ErrorAction SilentlyContinue
        if ($existing) {
            Stop-Service -Name $service.Id -ErrorAction Stop
            & $wrapper uninstall
            if ($LASTEXITCODE -ne 0) { throw "WinSW could not unregister $name." }
        }
        Copy-Item -LiteralPath $WinSW -Destination $wrapper -Force
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot "$name.xml") -Destination $wrapperConfig -Force
        & $wrapper install
        if ($LASTEXITCODE -ne 0) { throw "WinSW failed to install $name (exit code $LASTEXITCODE)." }
        # Register the wrapper under LocalSystem first. The virtual service
        # account SID is created by SCM only after CreateService succeeds, so
        # WinSW cannot safely grant logon rights to NT SERVICE\<id> during its
        # own install step. Assign the virtual account through SCM afterwards.
        $installed = Get-CimInstance Win32_Service -Filter "Name='$($service.Id)'"
        if (-not $installed) { throw "SCM did not create $name." }
        $changed = Invoke-CimMethod -InputObject $installed -MethodName Change -Arguments @{
            StartName = "NT SERVICE\$($service.Id)"
        }
        if ($changed.ReturnValue -ne 0) { throw "Could not assign the virtual service account to $name (return $($changed.ReturnValue))." }
        & sc.exe sidtype $service.Id unrestricted | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not enable the service SID for $name." }
        $serviceSid = [System.Security.Principal.NTAccount]::new('NT SERVICE', $service.Id).Translate(
            [System.Security.Principal.SecurityIdentifier])
        Set-RoleDirectoryAcl (Join-Path $privateRoot "config\$($service.Role)") $serviceSid $false
        foreach ($family in @('data', 'credentials', 'logs')) {
            Set-RoleDirectoryAcl (Join-Path $privateRoot "$family\$($service.Role)") $serviceSid $true
        }
        # Virtual accounts have ordinary filesystem rights; neither role runs as LocalSystem.
        $installed = Get-CimInstance Win32_Service -Filter "Name='$($service.Id)'"
        if ($installed.StartName -ne "NT SERVICE\$($service.Id)") {
            throw "Unexpected service account for ${name}: $($installed.StartName)"
        }
    } elseif (Test-Path -LiteralPath $wrapper) {
        & $wrapper stop
        & $wrapper uninstall
        if ($LASTEXITCODE -ne 0) { throw "WinSW failed to uninstall $name (exit code $LASTEXITCODE)." }
        Remove-Item -LiteralPath $wrapper -Force
        Remove-Item -LiteralPath $wrapperConfig -Force -ErrorAction SilentlyContinue
    }
}
