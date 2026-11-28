[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('ingress', 'egress')]
    [string] $Role,
    [string] $Target = 'x86_64-pc-windows-msvc',
    [string] $Cargo = 'cargo',
    [string] $MakeNSIS = 'makensis',
    [string] $Version = $env:PATHCHORD_VERSION,
    [string] $DaemonBinary = '',
    [string] $CtlBinary = '',
    [string] $OutputDirectory = '',
    [switch] $SkipBuild
)
$ErrorActionPreference = 'Stop'
$Role = $Role.ToLowerInvariant()
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$name = "pathchord-${Role}d"
$Version = & (Join-Path $PSScriptRoot 'version.ps1') -Version $Version
if (-not $SkipBuild -and [string]::IsNullOrWhiteSpace($DaemonBinary)) {
    & $Cargo build --manifest-path (Join-Path $repoRoot 'Cargo.toml') --locked --release --bin $name --bin pathchordctl --target $Target
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }
}
if ([string]::IsNullOrWhiteSpace($DaemonBinary)) { $DaemonBinary = "target\$Target\release\$name.exe" }
if ([string]::IsNullOrWhiteSpace($CtlBinary)) { $CtlBinary = "target\$Target\release\pathchordctl.exe" }
foreach ($variable in @('DaemonBinary', 'CtlBinary')) {
    $path = (Get-Variable -Name $variable).Value
    if (-not [IO.Path]::IsPathRooted($path)) { $path = Join-Path $repoRoot $path }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing binary: $path" }
    Set-Variable -Name $variable -Value $path
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $repoRoot 'dist' }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$outputFile = Join-Path $OutputDirectory "$name-$Version-windows-x86_64-setup.exe"
$prefix = if ([Environment]::OSVersion.Platform -eq 'Win32NT') { '/D' } else { '-D' }
& $MakeNSIS "${prefix}APP_ROLE=$Role" "${prefix}APP_VERSION=$Version" `
    "${prefix}DAEMON_BINARY_PATH=$DaemonBinary" "${prefix}CTL_BINARY_PATH=$CtlBinary" `
    "${prefix}OUTPUT_PATH=$outputFile" (Join-Path $PSScriptRoot 'pathchord.nsi')
if ($LASTEXITCODE -ne 0) { throw 'makensis failed.' }
