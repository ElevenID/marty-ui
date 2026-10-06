[CmdletBinding()]
param(
    [ValidateSet("Deploy", "Rollback")]
    [string]$Mode = "Deploy",
    [string]$Container = "marty-ui-prod",
    [string]$BackupRoot
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
$backupRoot = if ([string]::IsNullOrWhiteSpace($BackupRoot)) {
    Join-Path $repoRoot "tests\artifacts\demo-publication-backups\$videoId"
} else {
    $allowed = [IO.Path]::GetFullPath((Join-Path $repoRoot 'tests\artifacts'))
    $candidate = [IO.Path]::GetFullPath($BackupRoot)
    if (-not $candidate.StartsWith(
        ($allowed.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar),
        [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Scoped demo backup must stay under tests/artifacts'
    }
    $candidate
}
$strictBackup = -not [string]::IsNullOrWhiteSpace($BackupRoot)
$manifestBackup = Join-Path $backupRoot $manifestName
$indexBackup = Join-Path $backupRoot 'index.json'
$targetFile = Join-Path $backupRoot 'target.json'
$containerRoot = "/usr/share/nginx/html/demos/manifests"

function Assert-ScopedBackup {
    if (-not (Test-Path -LiteralPath $manifestBackup -PathType Leaf) -or
        -not (Test-Path -LiteralPath $indexBackup -PathType Leaf) -or
        -not (Test-Path -LiteralPath $targetFile -PathType Leaf)) {
        throw 'Scoped demo backup is incomplete'
    }
    $target = Get-Content -LiteralPath $targetFile -Raw | ConvertFrom-Json
    if ($target.schema -cne 'marty.demo-publication-backup/v1' -or
        $target.container_id -cne $Container -or
        $target.video_id -cne $videoId -or
        $target.manifest_name -cne $manifestName) {
        throw 'Scoped demo backup belongs to another target'
    }
}

if ($Mode -eq "Rollback") {
    if ($strictBackup) { Assert-ScopedBackup }
    elseif (-not (Test-Path -LiteralPath $manifestBackup -PathType Leaf) -or
            -not (Test-Path -LiteralPath $indexBackup -PathType Leaf)) {
        throw "No demo-content backup exists for $videoId"
    }
    docker cp $manifestBackup "${Container}:${containerRoot}/${manifestName}"
    if ($LASTEXITCODE -ne 0) { throw "Failed to restore the demo manifest" }
    docker cp $indexBackup "${Container}:${containerRoot}/index.json"
    if ($LASTEXITCODE -ne 0) { throw "Failed to restore the demo index" }
    exit 0
}

New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
if ($strictBackup -and ((Test-Path -LiteralPath $manifestBackup) -or
                        (Test-Path -LiteralPath $indexBackup) -or
                        (Test-Path -LiteralPath $targetFile))) {
    Assert-ScopedBackup
}
elseif (-not (Test-Path -LiteralPath $manifestBackup -PathType Leaf)) {
    try {
        docker cp "${Container}:${containerRoot}/${manifestName}" $manifestBackup
        if ($LASTEXITCODE -ne 0) { throw "Failed to back up the deployed demo manifest" }
        docker cp "${Container}:${containerRoot}/index.json" $indexBackup
        if ($LASTEXITCODE -ne 0) { throw "Failed to back up the deployed demo index" }
        if ($strictBackup) {
            [ordered]@{
                schema = 'marty.demo-publication-backup/v1'
                container_id = $Container
                video_id = $videoId
                manifest_name = $manifestName
            } | ConvertTo-Json -Compress | Set-Content -LiteralPath $targetFile -Encoding utf8
        }
    }
    catch {
        if ($strictBackup) {
            Remove-Item -LiteralPath $manifestBackup, $indexBackup, $targetFile `
                -ErrorAction SilentlyContinue
        }
        throw
    }
}
elseif (-not (Test-Path -LiteralPath $indexBackup -PathType Leaf)) {
    throw 'Demo backup is missing the index file'
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
