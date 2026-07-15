[CmdletBinding()]
param(
    [ValidateSet("Deploy", "Rollback")]
    [string]$Mode = "Deploy",
    [string]$Container = "marty-ui-prod"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$manifestPath = [string]$env:ELEVENID_DEMO_MANIFEST
$videoId = [string]$env:ELEVENID_DEMO_VIDEO_ID
if ([string]::IsNullOrWhiteSpace($manifestPath) -or [string]::IsNullOrWhiteSpace($videoId)) {
    throw "ELEVENID_DEMO_MANIFEST and ELEVENID_DEMO_VIDEO_ID are required"
}
$manifestPath = (Resolve-Path $manifestPath).Path
$manifestName = Split-Path $manifestPath -Leaf
$indexPath = Join-Path (Split-Path $manifestPath -Parent) "index.json"
$backupRoot = Join-Path $repoRoot "tests\artifacts\demo-publication-backups\$videoId"
$containerRoot = "/usr/share/nginx/html/demos/manifests"

if ($Mode -eq "Rollback") {
    if (-not (Test-Path (Join-Path $backupRoot $manifestName))) {
        throw "No demo-content backup exists for $videoId"
    }
    docker cp (Join-Path $backupRoot $manifestName) "${Container}:${containerRoot}/${manifestName}"
    if ($LASTEXITCODE -ne 0) { throw "Failed to restore the demo manifest" }
    docker cp (Join-Path $backupRoot "index.json") "${Container}:${containerRoot}/index.json"
    if ($LASTEXITCODE -ne 0) { throw "Failed to restore the demo index" }
    exit 0
}

New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
if (-not (Test-Path (Join-Path $backupRoot $manifestName))) {
    docker cp "${Container}:${containerRoot}/${manifestName}" (Join-Path $backupRoot $manifestName)
    if ($LASTEXITCODE -ne 0) { throw "Failed to back up the deployed demo manifest" }
    docker cp "${Container}:${containerRoot}/index.json" (Join-Path $backupRoot "index.json")
    if ($LASTEXITCODE -ne 0) { throw "Failed to back up the deployed demo index" }
}

docker cp $manifestPath "${Container}:${containerRoot}/${manifestName}"
if ($LASTEXITCODE -ne 0) { throw "Failed to deploy the demo manifest" }
docker cp $indexPath "${Container}:${containerRoot}/index.json"
if ($LASTEXITCODE -ne 0) { throw "Failed to deploy the demo index" }

$deployed = docker exec $Container cat "${containerRoot}/${manifestName}" | ConvertFrom-Json
$scenario = $deployed.scenarios | Where-Object { $_.youtube_id -eq $videoId }
if ($null -eq $scenario -or $scenario.state -ne "PUBLIC") {
    throw "The deployed manifest does not expose public video $videoId"
}
