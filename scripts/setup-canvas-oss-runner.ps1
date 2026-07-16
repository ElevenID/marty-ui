[CmdletBinding()]
param(
    [string]$WslDistribution = "Ubuntu-24.04",
    [string]$RunnerDirectory = "~/actions-runner-canvas-oss",
    [switch]$InstallUbuntuIfMissing,
    [string]$RunnerArchiveUrl,
    [string]$RunnerArchiveSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($WslDistribution -notmatch '^[A-Za-z0-9_.-]+$') {
    throw "WSL distribution name contains unsupported characters"
}
if ($RunnerDirectory -notmatch '^~?/[A-Za-z0-9_./-]+$') {
    throw "RunnerDirectory must be a simple path inside WSL"
}
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "WSL is unavailable. Enable WSL2 before provisioning the dedicated runner."
}

function Get-WslText([string[]]$Arguments) {
    $text = (& wsl.exe @Arguments 2>&1 | Out-String) -replace "`0", ""
    return $text.Trim()
}

function Convert-ToWslPath([string]$WindowsPath) {
    if ($WindowsPath -notmatch '^([A-Za-z]):\\(.*)$') {
        throw "Runner repository path must be on a Windows drive"
    }
    $drive = $Matches[1].ToLowerInvariant()
    $relative = $Matches[2].Replace('\', '/')
    return "/mnt/$drive/$relative"
}

function Invoke-WslBash([string]$Command, [switch]$Root) {
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Command))
    $arguments = @("-d", $WslDistribution)
    if ($Root) { $arguments += @("--user", "root") }
    # A fixed ASCII decoder command prevents PowerShell/wsl.exe from
    # reinterpreting Bash quoting or injecting CRLF into shell variables.
    $arguments += @("--", "bash", "-lc", "echo $encodedCommand | base64 --decode | bash")
    & wsl.exe @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "WSL setup command failed with exit code $LASTEXITCODE"
    }
}

$installed = @(
    (Get-WslText @("--list", "--quiet")) -split "`r?`n" |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
)
if ($installed -notcontains $WslDistribution) {
    if (-not $InstallUbuntuIfMissing) {
        $inventory = if ($installed.Count -gt 0) { $installed -join ", " } else { "none" }
        throw "$WslDistribution is not installed (installed: $inventory). No Canvas OSS runner exists. Rerun with -InstallUbuntuIfMissing to request the distro install."
    }
    Write-Host "Requesting dedicated $WslDistribution installation..."
    & wsl.exe --install --distribution $WslDistribution --no-launch --version 2
    if ($LASTEXITCODE -ne 0) {
        throw "WSL distribution installation failed or requires a Windows restart"
    }
    throw "$WslDistribution was requested without launching it. Restart Windows if requested, launch the distro once to create a non-root user, enable its Docker Desktop integration, then rerun this script."
}

$verboseInventory = Get-WslText @("--list", "--verbose")
$escapedDistribution = [regex]::Escape($WslDistribution)
if ($verboseInventory -notmatch "(?m)^\s*\*?\s*$escapedDistribution\s+\S+\s+2\s*$") {
    & wsl.exe --terminate $WslDistribution | Out-Null
    & wsl.exe --set-version $WslDistribution 2 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set $WslDistribution to WSL2" }
}
$uid = Get-WslText @("-d", $WslDistribution, "--", "id", "-u")
if ($uid -eq "0") {
    throw "$WslDistribution has no non-root default user. Launch it interactively once and create the runner user before continuing."
}
$wslHome = Get-WslText @("-d", $WslDistribution, "--", "printenv", "HOME")
$wslRunnerDirectory = if ($RunnerDirectory.StartsWith("~/")) {
    "$wslHome/$($RunnerDirectory.Substring(2))"
} else {
    $RunnerDirectory
}

Write-Host "Installing dedicated runner prerequisites in $WslDistribution..."
Invoke-WslBash "export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y ca-certificates curl git gh jq nodejs npm python3" -Root

& wsl.exe -d $WslDistribution -- bash -lc "test -x '$wslRunnerDirectory/config.sh' && test -x '$wslRunnerDirectory/run.sh'"
if ($LASTEXITCODE -ne 0) {
    if ($RunnerArchiveUrl -notmatch '^https://github\.com/actions/runner/releases/download/v[0-9.]+/actions-runner-linux-x64-[0-9.]+\.tar\.gz$') {
        throw "Runner binary is absent. Supply the current official Linux x64 -RunnerArchiveUrl from GitHub's New self-hosted runner page."
    }
    if ($RunnerArchiveSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw "Runner binary is absent. Supply GitHub's 64-character -RunnerArchiveSha256 checksum."
    }
    $checksum = $RunnerArchiveSha256.ToLowerInvariant()
    $runnerInstallScript = @'
set -euo pipefail
archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 '__RUNNER_URL__' --output "$archive"
echo '__RUNNER_SHA__  '"$archive" | sha256sum --check --status
mkdir -p '__RUNNER_DIRECTORY__'
tar -xzf "$archive" -C '__RUNNER_DIRECTORY__'
'@
    $runnerInstallScript = $runnerInstallScript.Replace("__RUNNER_URL__", $RunnerArchiveUrl)
    $runnerInstallScript = $runnerInstallScript.Replace("__RUNNER_SHA__", $checksum)
    $runnerInstallScript = $runnerInstallScript.Replace("__RUNNER_DIRECTORY__", $wslRunnerDirectory)
    Invoke-WslBash $runnerInstallScript
    Invoke-WslBash "'$wslRunnerDirectory/bin/installdependencies.sh'" -Root
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$wslRepoRoot = Convert-ToWslPath $repoRoot
Invoke-WslBash "python3 '$wslRepoRoot/scripts/check_canvas_oss_runner.py' --host-setup --output /tmp/canvas-oss-runner-host-preflight.json && rm -f /tmp/canvas-oss-runner-host-preflight.json"

Write-Host "Runner binary and host prerequisites are ready. No GitHub runner was registered."
Write-Host "Run register-canvas-oss-runner.ps1; it will require a fresh short-lived GitHub registration token and verify server-side labels before accepting one job."
