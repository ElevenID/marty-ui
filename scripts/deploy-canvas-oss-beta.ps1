[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDir,

    [Parameter(Mandatory = $true)]
    [string]$AuditPath,

    [switch]$AllowOutsideMaintenanceWindow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-DenverNow {
    $zone = $null
    foreach ($zoneId in @("America/Denver", "Mountain Standard Time")) {
        try {
            $zone = [TimeZoneInfo]::FindSystemTimeZoneById($zoneId)
            break
        }
        catch {
            continue
        }
    }
    if ($null -eq $zone) {
        throw "Could not resolve the America/Denver maintenance-window timezone"
    }
    return [TimeZoneInfo]::ConvertTime([DateTimeOffset]::UtcNow, $zone)
}

function Get-SelfhostProductionInvariant {
    $ids = @(& docker ps -a --filter "label=com.docker.compose.project=marty-selfhost-prod" --format '{{.ID}}')
    if ($LASTEXITCODE -ne 0) {
        throw "Could not enumerate marty-selfhost-prod containers"
    }
    if ($ids.Count -eq 0) {
        return @()
    }
    $json = & docker inspect @ids
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect marty-selfhost-prod containers"
    }
    $containers = ConvertFrom-Json -InputObject ($json -join "`n")
    $records = foreach ($container in $containers) {
        [ordered]@{
            container = $container.Name.TrimStart("/")
            container_id = $container.Id
            image_id = $container.Image
            started_at = $container.State.StartedAt
            running = [bool]$container.State.Running
        }
    }
    return @($records | Sort-Object container)
}

function Get-InvariantDigest([object[]]$Records) {
    $payload = ConvertTo-Json -InputObject @($Records) -Depth 4 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") })
    }
    finally {
        $sha.Dispose()
    }
}

function Compare-SelfhostProductionInvariant([object[]]$Before, [object[]]$After) {
    $beforeByName = @{}
    $afterByName = @{}
    foreach ($record in $Before) { $beforeByName[$record.container] = $record }
    foreach ($record in $After) { $afterByName[$record.container] = $record }
    $names = @($beforeByName.Keys + $afterByName.Keys | Sort-Object -Unique)
    $changes = @()
    foreach ($name in $names) {
        if (-not $beforeByName.ContainsKey($name)) {
            $changes += [ordered]@{ container = $name; fields = @("added") }
            continue
        }
        if (-not $afterByName.ContainsKey($name)) {
            $changes += [ordered]@{ container = $name; fields = @("removed") }
            continue
        }
        $changedFields = @()
        foreach ($field in @("container_id", "image_id", "started_at", "running")) {
            if ($beforeByName[$name].$field -cne $afterByName[$name].$field) {
                $changedFields += $field
            }
        }
        if ($changedFields.Count -gt 0) {
            $changes += [ordered]@{ container = $name; fields = $changedFields }
        }
    }
    return @($changes)
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$allowedRoot = (Resolve-Path (Join-Path $repoRoot "tests\artifacts")).Path
$resolvedArtifacts = (Resolve-Path $ArtifactDir).Path
$artifactPrefix = $allowedRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $resolvedArtifacts.StartsWith($artifactPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Beta deploy ArtifactDir must stay under marty-ui/tests/artifacts"
}
if ($resolvedArtifacts -match "selfhost|production") {
    throw "Beta deploy evidence path cannot target self-host production"
}
if (-not (Test-Path -LiteralPath (Join-Path $resolvedArtifacts "source-manifest.json") -PathType Leaf)) {
    throw "Beta deploy artifact is missing source-manifest.json"
}

$resolvedAudit = [IO.Path]::GetFullPath($AuditPath)
$resolvedArtifactPrefix = $resolvedArtifacts.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $resolvedAudit.StartsWith($resolvedArtifactPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Beta deploy AuditPath must stay under ArtifactDir"
}
$auditParent = Split-Path -Parent $resolvedAudit
New-Item -ItemType Directory -Force -Path $auditParent | Out-Null

$denverNow = Get-DenverNow
if (($denverNow.Hour -lt 2 -or $denverNow.Hour -ge 6) -and -not $AllowOutsideMaintenanceWindow) {
    throw "Beta deploy is allowed only from 02:00 through 05:59 America/Denver; current local time is $($denverNow.ToString('yyyy-MM-dd HH:mm:ss zzz'))"
}

$startedAt = (Get-Date).ToUniversalTime().ToString("o")
$selfhostBefore = @(Get-SelfhostProductionInvariant)
$selfhostBeforeDigest = Get-InvariantDigest $selfhostBefore
$selfhostAfter = @()
$selfhostAfterDigest = $null
$selfhostChanges = @()
$selfhostInvariantStatus = "error"
$deploymentError = $null
$invariantError = $null
$exitCode = 1
$outcome = "failed"
try {
    & (Join-Path $PSScriptRoot "deploy-local-beta-release.ps1") `
        -ArtifactDir $resolvedArtifacts `
        -BetaOrigin "https://beta.elevenidllc.com" `
        -EnablePortableCanvas `
        -CanvasOrigin "https://canvas-test.elevenidllc.com" `
        -PilotOrganizationId "00000000-0000-0000-0000-000000000001"
    $exitCode = 0
    $outcome = "passed"
}
catch {
    $deploymentError = $_
}
finally {
    try {
        $selfhostAfter = @(Get-SelfhostProductionInvariant)
        $selfhostAfterDigest = Get-InvariantDigest $selfhostAfter
        $selfhostChanges = @(Compare-SelfhostProductionInvariant $selfhostBefore $selfhostAfter)
        if ($selfhostChanges.Count -gt 0) {
            $selfhostInvariantStatus = "changed"
            $invariantError = "marty-selfhost-prod container invariants changed during beta deployment"
            $exitCode = 1
            $outcome = "failed"
        }
        else {
            $selfhostInvariantStatus = "passed"
        }
    }
    catch {
        $selfhostInvariantStatus = "error"
        $invariantError = "Could not verify marty-selfhost-prod invariants after beta deployment"
        $exitCode = 1
        $outcome = "failed"
    }

    $source = Get-Content -LiteralPath (Join-Path $resolvedArtifacts "source-manifest.json") -Raw | ConvertFrom-Json
    $deploymentPath = Join-Path $resolvedArtifacts "local-deployment-manifest.json"
    $deploymentSha256 = $null
    if (Test-Path -LiteralPath $deploymentPath -PathType Leaf) {
        $deploymentSha256 = (Get-FileHash -LiteralPath $deploymentPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    [ordered]@{
        schema_version = 1
        operation = "deploy_beta_release_and_run_migrations"
        explicitly_requested = $true
        destructive_state_reset = $false
        beta_origin = "https://beta.elevenidllc.com"
        source_id = $source.marty_ui_sha
        release_version = $source.release_version
        maintenance_window = "02:00-06:00 America/Denver"
        maintenance_window_override = [bool]$AllowOutsideMaintenanceWindow
        denver_started_at = $denverNow.ToString("o")
        started_at = $startedAt
        finished_at = (Get-Date).ToUniversalTime().ToString("o")
        status = $outcome
        exit_code = $exitCode
        deployment_manifest_sha256 = $deploymentSha256
        selfhost_production_touched = if ($selfhostInvariantStatus -eq "passed") { $false } else { $null }
        selfhost_production_invariant = [ordered]@{
            status = $selfhostInvariantStatus
            before_count = $selfhostBefore.Count
            after_count = $selfhostAfter.Count
            before_sha256 = $selfhostBeforeDigest
            after_sha256 = $selfhostAfterDigest
            changes = $selfhostChanges
        }
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resolvedAudit -Encoding utf8
}

if ($null -ne $invariantError) {
    throw $invariantError
}
if ($null -ne $deploymentError) {
    throw $deploymentError
}
