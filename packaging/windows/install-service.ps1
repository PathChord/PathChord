[CmdletBinding()]
param(
    [ValidateSet('Install', 'Uninstall')]
    [string] $Action = 'Install',
    [string] $WinSW = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($WinSW)) {
    $WinSW = Join-Path $root 'winsw.exe'
}
if (-not (Test-Path -LiteralPath $WinSW -PathType Leaf)) {
    throw "WinSW executable was not found at '$WinSW'. Download and audit WinSW, then pass -WinSW or copy it to the PathChord installation directory."
}

$services = @('pathchord-ingressd', 'pathchord-egressd')
foreach ($name in $services) {
    $wrapper = Join-Path $root "$name-service.exe"
    $config = Join-Path $PSScriptRoot "$name.xml"
    if ($Action -eq 'Install') {
        Copy-Item -LiteralPath $WinSW -Destination $wrapper -Force
        Copy-Item -LiteralPath $config -Destination (Join-Path $root "$name-service.xml") -Force
        & $wrapper install
        if ($LASTEXITCODE -ne 0) { throw "WinSW failed to install $name (exit code $LASTEXITCODE)." }
    } else {
        if (Test-Path -LiteralPath $wrapper) {
            & $wrapper stop
            & $wrapper uninstall
            if ($LASTEXITCODE -ne 0) { throw "WinSW failed to uninstall $name (exit code $LASTEXITCODE)." }
            Remove-Item -LiteralPath $wrapper -Force
            Remove-Item -LiteralPath (Join-Path $root "$name-service.xml") -Force -ErrorAction SilentlyContinue
        }
    }
}
