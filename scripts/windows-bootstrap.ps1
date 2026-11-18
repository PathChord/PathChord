$ErrorActionPreference = 'Stop'
$lab = 'C:\PathChordLab'
New-Item -ItemType Directory -Force -Path $lab | Out-Null
Start-Transcript -Path "$lab\bootstrap.log" -Append
try {
    $seed = (Get-CimInstance Win32_LogicalDisk | Where-Object VolumeName -eq 'PCSEED').DeviceID
    if (-not $seed) { throw 'The isolated lab seed volume was not found.' }
    $sshRoot = "$env:ProgramFiles\OpenSSH"
    if (-not (Test-Path -LiteralPath "$sshRoot\sshd.exe")) {
        Expand-Archive -LiteralPath "$seed\OpenSSH-Win64.zip" -DestinationPath $env:ProgramFiles -Force
        Move-Item -LiteralPath "$env:ProgramFiles\OpenSSH-Win64" -Destination $sshRoot -Force
    }
    if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$sshRoot\install-sshd.ps1"
        if ($LASTEXITCODE -ne 0) { throw 'OpenSSH service installation failed.' }
    }
    New-Item -ItemType Directory -Force -Path "$env:ProgramData\ssh" | Out-Null
    Copy-Item -LiteralPath "$seed\authorized_keys" -Destination "$env:ProgramData\ssh\administrators_authorized_keys" -Force
    & icacls.exe "$env:ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the lab SSH key file.' }
    @'
Port 22
PubkeyAuthentication yes
PasswordAuthentication no
AllowUsers pcadmin
Subsystem sftp sftp-server.exe
Match User pcadmin
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
'@ | Set-Content -LiteralPath "$env:ProgramData\ssh\sshd_config" -Encoding ascii
    New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null
    New-NetFirewallRule -Name PathChordLabSSH -DisplayName PathChordLabSSH -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any | Out-Null
    Set-Service sshd -StartupType Automatic
    Start-Service sshd
    # The guest is an offline test baseline; keep the installed build fixed.
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Set-Service wuauserv -StartupType Disabled
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -Value 1
    & powercfg.exe /change standby-timeout-ac 0
    & powercfg.exe /change monitor-timeout-ac 0
    & powercfg.exe /hibernate off
    if ($LASTEXITCODE -ne 0) { throw 'Could not disable hibernation for the test baseline.' }
    # A reusable baseline must shut down fully and remain accessible offline.
    $bitlockerKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker'
    if (-not (Test-Path -LiteralPath $bitlockerKey)) {
        New-Item -Path $bitlockerKey -Force | Out-Null
    }
    New-ItemProperty -Path $bitlockerKey -Name PreventDeviceEncryption -Value 1 -PropertyType DWord -Force | Out-Null
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Remove-ItemProperty -Path $winlogon -Name DefaultPassword -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $winlogon -Name AutoAdminLogon -Value '0'
    # Setup caches answer files containing the temporary local account password.
    Get-ChildItem 'C:\Windows\Panther' -Filter '*unattend*.xml' -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    @{
        ready = $true
        os = (Get-CimInstance Win32_OperatingSystem).Caption
        build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        architecture = $env:PROCESSOR_ARCHITECTURE
        identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        ssh = (Get-Service sshd).Status.ToString()
    } | ConvertTo-Json | Set-Content -LiteralPath "$lab\ready.json" -Encoding UTF8
} catch {
    $_ | Out-String | Set-Content -LiteralPath "$lab\bootstrap-error.txt"
    throw
} finally {
    Stop-Transcript
}
