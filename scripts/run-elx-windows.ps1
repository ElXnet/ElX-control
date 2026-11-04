#requires -Version 5.1
<#
.SYNOPSIS
  Prepare and run the ElX-ui / ElXray / ElX-control local test workspace.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\run-elx-windows.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\run-elx-windows.ps1 -Workspace D:\ElX-test
#>
[CmdletBinding()]
param(
    [string]$Workspace = (Join-Path $env:USERPROFILE 'ElX-test')
)
$ErrorActionPreference = 'Stop'
$branches = [ordered]@{
    'ElX-ui'      = 'elx-control-journal'
    'ElXray'      = 'restrict-runtime-unlimited'
    'ElX-control' = 'feat/multinode-policy'
}
function Invoke-Git {
    param([string[]]$Arguments)
    & git @Arguments
    if ($LASTEXITCODE -ne 0) { throw "git $($Arguments -join ' ') failed ($LASTEXITCODE)" }
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'Install Git for Windows before running this script.' }
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { throw 'WSL is required; run wsl --install from an elevated terminal.' }
New-Item -ItemType Directory -Force -Path $Workspace | Out-Null
foreach ($name in $branches.Keys) {
    $branch = $branches[$name]
    $dir = Join-Path $Workspace $name
    if (-not (Test-Path (Join-Path $dir '.git'))) {
        if (Test-Path $dir) { throw "$dir already exists but is not a Git repository" }
        Invoke-Git -Arguments @('clone', '--branch', $branch, '--single-branch', "https://github.com/ElXnet/$name.git", $dir)
    } else {
        $dirty = & git -C $dir status --porcelain
        if ($LASTEXITCODE -ne 0 -or $dirty) { throw "$dir has local changes; commit or stash them first" }
        Invoke-Git -Arguments @('-C', $dir, 'fetch', 'origin', $branch)
        $current = (& git -C $dir branch --show-current).Trim()
        if ($current -ne $branch) { throw "$dir is on branch '$current', expected '$branch'. Switch branches manually." }
        Invoke-Git -Arguments @('-C', $dir, 'pull', '--ff-only', 'origin', $branch)
    }
}
$control = Join-Path $Workspace 'ElX-control'
$linuxControl = (& wsl.exe wslpath -a -u $control).Trim()
if ($LASTEXITCODE -ne 0 -or -not $linuxControl.StartsWith('/')) {
    throw 'Could not translate Windows workspace path to WSL. Check your WSL installation.'
}
if ($linuxControl.Contains("'")) { throw 'Workspace path cannot contain an apostrophe.' }
$linuxCommand = "set -euo pipefail; cd '$linuxControl'; command -v go; command -v python3; command -v openssl; command -v gcc; command -v docker; docker info >/dev/null; bash scripts/elx-test-local.sh"
Write-Host "Running standalone ElX Control tests via WSL in: $linuxControl" -ForegroundColor Cyan
& wsl.exe -- bash -lc $linuxCommand
if ($LASTEXITCODE -ne 0) { throw "ElX tests failed (exit code $LASTEXITCODE); inspect the WSL output above." }
Write-Host 'PASS: ElX Windows/WSL suite' -ForegroundColor Green
