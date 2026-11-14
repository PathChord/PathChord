[CmdletBinding()]
param(
    [string] $Target = 'x86_64-pc-windows-msvc',
    [string] $Cargo = 'cargo',
    [string] $MakeNSIS = 'makensis',
    [string] $Version = '',
    [string] $Binary = '',
    [string] $OutputDirectory = '',
    [switch] $SkipBuild
)

$ErrorActionPreference = 'Stop'
$packagingRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $packagingRoot
$cargoManifest = Join-Path $repoRoot 'Cargo.toml'
$manifestText = Get-Content -LiteralPath $cargoManifest -Raw
$version = $Version
if ([string]::IsNullOrWhiteSpace($version)) {
    $versionMatch = [regex]::Match($manifestText, '(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"')
    if (-not $versionMatch.Success) {
        throw "Could not read the workspace version from $cargoManifest."
    }
    $version = $versionMatch.Groups[1].Value
}

if ([string]::IsNullOrWhiteSpace($Binary)) {
    $Binary = Join-Path $repoRoot "target\$Target\release\pathchord.exe"
} elseif (-not [IO.Path]::IsPathRooted($Binary)) {
    $Binary = Join-Path $repoRoot $Binary
}
if (-not $SkipBuild -and [string]::IsNullOrWhiteSpace($PSBoundParameters['Binary'])) {
    & $Cargo build --locked --release -p pathchord-cli --target $Target
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit code $LASTEXITCODE)." }
}

$binary = $Binary
if (-not (Test-Path -LiteralPath $binary -PathType Leaf) -and
    (Test-Path -LiteralPath "$binary.exe" -PathType Leaf)) {
    $binary = "$binary.exe"
}
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "Expected Windows binary was not found at $binary."
}

$outputPath = $OutputDirectory
if ([string]::IsNullOrWhiteSpace($outputPath)) {
    $outputPath = (Get-Location).Path
}
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
$outputFile = Join-Path $outputPath "PathChord-$version-windows-x86_64-setup.exe"
$makensisArgs = @(
    "/DAPP_VERSION=$version",
    "/DBINARY_PATH=$binary",
    "/DOUTPUT_PATH=$outputFile",
    (Join-Path $PSScriptRoot 'pathchord.nsi')
)
& $MakeNSIS @makensisArgs
if ($LASTEXITCODE -ne 0) { throw "makensis failed (exit code $LASTEXITCODE)." }
