#requires -Version 5.1
<#
.SYNOPSIS
  Prepare and run the ElX-ui / ElXray / ElX-control local test workspace.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\run-elx-windows.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\run-elx-windows.ps1 -Workspace D:\ElX-test -Distro Ubuntu
#>
[CmdletBinding()]
param(
    [string]$Workspace = (Join-Path $env:USERPROFILE 'ElX-test'),
    [string]$Distro = ''
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
# Docker Desktop can become the default WSL distribution; it has no bash or build tools.
# Select a regular Linux distribution, or pass -Distro explicitly.
if (-not $Distro) {
    $available = @(& wsl.exe --list --quiet | ForEach-Object {
        ($_ -replace [char]0, '').Trim()
    } | Where-Object { $_ -and $_ -notmatch '^docker-desktop' })
    if ($LASTEXITCODE -ne 0 -or $available.Count -eq 0) {
        throw 'No regular WSL Linux distribution found. Install Ubuntu (wsl --install -d Ubuntu) or pass -Distro.'
    }
    $preferred = @($available | Where-Object { $_ -match '^Ubuntu' })
    if ($preferred.Count -gt 0) { $Distro = $preferred[0] } else { $Distro = $available[0] }
}
Write-Host "Using WSL distribution: $Distro" -ForegroundColor Cyan
$control = Join-Path $Workspace 'ElX-control'
# --exec passes Windows backslashes through to wslpath without shell interpretation.
$pathOutput = & wsl.exe --distribution $Distro --exec wslpath -a -u $control
if ($LASTEXITCODE -ne 0 -or -not $pathOutput) {
    throw "Could not translate Windows path '$control' in WSL distribution '$Distro'."
}
$linuxControl = ([string]($pathOutput | Select-Object -Last 1)).Trim()
if (-not $linuxControl.StartsWith('/')) { throw "Unexpected translated path: '$linuxControl'" }
if ($linuxControl.Contains("'")) { throw 'Workspace path cannot contain an apostrophe.' }
# Pass the Linux script as an argv path instead of a shell -c string.
# This avoids Windows PowerShell quote mangling with embedded Bash commands.
Write-Host "Running standalone ElX Control tests via WSL in: $linuxControl" -ForegroundColor Cyan
& wsl.exe --distribution $Distro --exec bash "$linuxControl/scripts/elx-test-local.sh"
if ($LASTEXITCODE -ne 0) { throw "ElX tests failed (exit code $LASTEXITCODE); inspect the WSL output above." }
Write-Host 'PASS: ElX Windows/WSL suite' -ForegroundColor Green
