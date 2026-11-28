param([string] $Version = $env:PATHCHORD_VERSION)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($Version)) {
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $inWorkspace = $false
    foreach ($line in Get-Content -LiteralPath (Join-Path $root 'Cargo.toml')) {
        if ($line -match '^\s*\[') {
            $inWorkspace = $line -match '^\s*\[workspace\.package\]\s*(?:#.*)?$'
        } elseif ($inWorkspace -and $line -match '^\s*version\s*=\s*(["''])([^"'']+)\1\s*(?:#.*)?$') {
            $Version = $Matches[2]
            break
        }
    }
}
if ($Version -cnotmatch '\A[0-9][0-9A-Za-z.+_-]*\z') {
    throw 'Invalid or missing package version; check PATHCHORD_VERSION or [workspace.package].version.'
}
$Version
