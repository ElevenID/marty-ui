[CmdletBinding()]
param(
    [string]$Repository = "ElevenID/marty-ui",
    [string]$WslDistribution = "Ubuntu-24.04",
    [string]$RunnerDirectory = "~/actions-runner-canvas-oss"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    throw "Repository must use owner/name syntax"
}
if ($WslDistribution -notmatch '^[A-Za-z0-9_.-]+$') {
    throw "WSL distribution name contains unsupported characters"
}
if ($RunnerDirectory -notmatch '^~?/[A-Za-z0-9_./-]+$') {
    throw "RunnerDirectory must be a simple path inside the dedicated WSL distribution"
}
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "WSL is not installed. The Canvas OSS runner is not provisioned."
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "Windows GitHub CLI is required and must have repository runner-administration permission."
}
& gh auth status | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Windows GitHub CLI is not authenticated."
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

function Invoke-WslBash([string]$Command) {
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Command))
    # A fixed ASCII decoder command prevents PowerShell/wsl.exe from
    # reinterpreting Bash quoting or injecting CRLF into shell variables.
    & wsl.exe -d $WslDistribution -- bash -lc "echo $encodedCommand | base64 --decode | bash"
    if ($LASTEXITCODE -ne 0) {
        throw "WSL command failed with exit code $LASTEXITCODE"
    }
}

$installedDistributions = @(
    (Get-WslText @("--list", "--quiet")) -split "`r?`n" |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
)
if ($installedDistributions -notcontains $WslDistribution) {
    $inventory = if ($installedDistributions.Count -gt 0) { $installedDistributions -join ", " } else { "none" }
    throw "Dedicated $WslDistribution runner distro is absent (installed: $inventory). The host currently has no Canvas OSS runner; run setup-canvas-oss-runner.ps1 first."
}
$verboseInventory = Get-WslText @("--list", "--verbose")
$escapedDistribution = [regex]::Escape($WslDistribution)
if ($verboseInventory -notmatch "(?m)^\s*\*?\s*$escapedDistribution\s+\S+\s+2\s*$") {
    throw "$WslDistribution exists but is not WSL2. Refusing runner registration."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$wslRepoRoot = Convert-ToWslPath $repoRoot
if (-not $wslRepoRoot.StartsWith("/")) {
    throw "Could not resolve the repository path inside $WslDistribution"
}
$wslHome = Get-WslText @("-d", $WslDistribution, "--", "printenv", "HOME")
$wslRunnerDirectory = if ($RunnerDirectory.StartsWith("~/")) {
    "$wslHome/$($RunnerDirectory.Substring(2))"
} else {
    $RunnerDirectory
}

# This verifies Ubuntu 24.04, gh/jq/node/python3/docker, the Docker Desktop
# socket, disk/memory capacity, marty-infra-network, and the existing tunnel before
# any short-lived GitHub registration is created.
Invoke-WslBash "test -x '$wslRunnerDirectory/config.sh' && test -x '$wslRunnerDirectory/run.sh'"
Invoke-WslBash "python3 '$wslRepoRoot/scripts/check_canvas_oss_runner.py' --host-setup --output /tmp/canvas-oss-runner-host-preflight.json && rm -f /tmp/canvas-oss-runner-host-preflight.json"

$repoUrl = "https://github.com/$Repository"
$runnerName = "canvas-oss-wsl2-$($env:COMPUTERNAME)-$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))"

# Ephemeral runners normally remove their local registration after one job. If
# a reboot left a local registration behind, use GitHub's short-lived removal
# token. Any mismatch fails closed and requires operator cleanup.
& wsl.exe -d $WslDistribution -- bash -lc "test -f '$wslRunnerDirectory/.runner'"
if ($LASTEXITCODE -eq 0) {
    $removeToken = (& gh api --method POST "repos/$Repository/actions/runners/remove-token" --jq .token).Trim()
    if (-not $removeToken) { throw "Could not obtain short-lived runner removal token" }
    Invoke-WslBash "cd '$wslRunnerDirectory' && ./config.sh remove --token '$removeToken'"
    $removeToken = $null
}

$registrationToken = (& gh api --method POST "repos/$Repository/actions/runners/registration-token" --jq .token).Trim()
if (-not $registrationToken) { throw "Could not obtain short-lived runner registration token" }

Write-Host "Registering one-job Canvas OSS runner: $runnerName"
Invoke-WslBash "cd '$wslRunnerDirectory' && ./config.sh --url '$repoUrl' --token '$registrationToken' --name '$runnerName' --labels 'canvas-oss-wsl2' --unattended --ephemeral"
$registrationToken = $null

# Confirm the server-side registration contains every routing label before the
# runner accepts a job. The Windows gh identity, not the workflow token, owns
# this repository-administration check.
$expectedLabels = @("self-hosted", "linux", "x64", "canvas-oss-wsl2")
$registered = $null
foreach ($attempt in 1..10) {
    $response = & gh api "repos/$Repository/actions/runners?per_page=100" | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw "Could not verify ephemeral runner registration" }
    $registered = @($response.runners | Where-Object { $_.name -eq $runnerName }) | Select-Object -First 1
    if ($null -ne $registered) { break }
    Start-Sleep -Seconds 2
}
if ($null -eq $registered) {
    throw "Ephemeral runner registration did not appear in GitHub; refusing to start it"
}
$actualLabels = @($registered.labels | ForEach-Object { ([string]$_.name).ToLowerInvariant() })
$missingLabels = @($expectedLabels | Where-Object { $_ -notin $actualLabels })
if ($missingLabels.Count -gt 0) {
    throw "Ephemeral runner is missing required labels: $($missingLabels -join ', ')"
}

# Foreground execution is intentional. A Windows Scheduled Task launched at
# 01:50 Denver remains alive until the admitted 02:07 job finishes. The marker
# is inherited by the runner process and is rechecked inside the workflow.
Invoke-WslBash "export CANVAS_OSS_RUNNER_LABELS_VERIFIED='$runnerName'; cd '$wslRunnerDirectory' && exec ./run.sh"
