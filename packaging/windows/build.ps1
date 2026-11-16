[CmdletBinding()]
param(
    [string] $Target = 'x86_64-pc-windows-msvc',
    [string] $Cargo = 'cargo',
    [string] $MakeNSIS = 'makensis',
    [string] $Version = '',
    [string] $IngressBinary = '',
    [string] $EgressBinary = '',
    [string] $CtlBinary = '',
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

if ([string]::IsNullOrWhiteSpace($IngressBinary)) {
    $IngressBinary = Join-Path $repoRoot "target\$Target\release\pathchord-ingressd.exe"
} elseif (-not [IO.Path]::IsPathRooted($IngressBinary)) {
    $IngressBinary = Join-Path $repoRoot $IngressBinary
}
if ([string]::IsNullOrWhiteSpace($EgressBinary)) {
    $EgressBinary = Join-Path $repoRoot "target\$Target\release\pathchord-egressd.exe"
} elseif (-not [IO.Path]::IsPathRooted($EgressBinary)) {
    $EgressBinary = Join-Path $repoRoot $EgressBinary
}
if ([string]::IsNullOrWhiteSpace($CtlBinary)) {
    $CtlBinary = Join-Path $repoRoot "target\$Target\release\pathchordctl.exe"
} elseif (-not [IO.Path]::IsPathRooted($CtlBinary)) {
    $CtlBinary = Join-Path $repoRoot $CtlBinary
}
if (-not $SkipBuild -and [string]::IsNullOrWhiteSpace($PSBoundParameters['IngressBinary'])) {
    & $Cargo build --locked --release --bin pathchord-ingressd --bin pathchord-egressd --bin pathchordctl --target $Target
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit code $LASTEXITCODE)." }
}

$binaries = @{
    Ingress = $IngressBinary
    Egress = $EgressBinary
    Ctl = $CtlBinary
}
foreach ($entry in $binaries.GetEnumerator()) {
    if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf) -and
        (Test-Path -LiteralPath "$($entry.Value).exe" -PathType Leaf)) {
        $binaries[$entry.Key] = "$($entry.Value).exe"
    }
    if (-not (Test-Path -LiteralPath $binaries[$entry.Key] -PathType Leaf)) {
        throw "Expected Windows $($entry.Key) binary was not found at $($binaries[$entry.Key])."
    }
}

$outputPath = $OutputDirectory
if ([string]::IsNullOrWhiteSpace($outputPath)) {
    $outputPath = (Get-Location).Path
}
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
$outputFile = Join-Path $outputPath "PathChord-$version-windows-x86_64-setup.exe"
$makensisArgs = @(
    "/DAPP_VERSION=$version",
    "/DINGRESS_BINARY_PATH=$($binaries['Ingress'])",
    "/DEGRESS_BINARY_PATH=$($binaries['Egress'])",
    "/DCTL_BINARY_PATH=$($binaries['Ctl'])",
    "/DOUTPUT_PATH=$outputFile",
    (Join-Path $PSScriptRoot 'pathchord.nsi')
)
& $MakeNSIS @makensisArgs
if ($LASTEXITCODE -ne 0) { throw "makensis failed (exit code $LASTEXITCODE)." }
