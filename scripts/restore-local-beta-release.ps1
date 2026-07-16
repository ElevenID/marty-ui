<#
.SYNOPSIS
Restores only the disposable local beta stack from a quiesced release backup.

.DESCRIPTION
This is a supervised recovery command for a failed beta migration. It refuses
non-beta artifacts and non-Compose-owned target containers. It restores the
Marty and Keycloak databases, applicant JSON store, Redis snapshot, and the
pre-deploy application/UI images. OpenBao remains running because the beta dev
server holds its transit keys in process memory; the Canvas bootstrap is
additive and does not rotate or delete existing keys.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ArtifactDir,
    [Parameter(Mandatory = $true)][switch]$ConfirmBetaRestore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Checked([string]$FilePath, [string[]]$Arguments) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$FilePath failed with exit code $LASTEXITCODE" }
}

function Wait-ForContainerHealth([string[]]$Containers, [int]$TimeoutSeconds = 420) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $pending = @()
        foreach ($container in $Containers) {
            $state = docker inspect $container --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>$null
            if ($LASTEXITCODE -ne 0 -or $state -notin @("healthy", "running")) { $pending += $container }
        }
        if ($pending.Count -eq 0) { return }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "Restored beta containers did not become healthy: $($pending -join ', ')"
}

function Assert-ContainerOwnership([string]$Container, [string]$ExpectedProject) {
    $existingContainers = @(& docker ps -a --format '{{.Names}}')
    if ($LASTEXITCODE -ne 0) { throw "Could not enumerate Docker containers" }
    if ($Container -notin $existingContainers) { return $false }
    $json = & docker inspect $Container
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect beta container: $Container" }
    $inspect = (ConvertFrom-Json -InputObject ($json -join "`n"))[0]
    $project = $inspect.Config.Labels.'com.docker.compose.project'
    if ($project -ne $ExpectedProject) {
        throw "Refusing beta restore: $Container belongs to Compose project $project, not $ExpectedProject"
    }
    return $true
}

if (-not $ConfirmBetaRestore) { throw "-ConfirmBetaRestore is required" }
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = (Resolve-Path (Join-Path $repoRoot "tests\artifacts")).Path
$resolvedArtifacts = (Resolve-Path $ArtifactDir).Path
$artifactPrefix = $artifactRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $resolvedArtifacts.StartsWith($artifactPrefix, [StringComparison]::OrdinalIgnoreCase) -or $resolvedArtifacts -match "selfhost|production") {
    throw "Restore ArtifactDir must be a beta artifact under marty-ui/tests/artifacts"
}

$backupDir = Join-Path $resolvedArtifacts "backup"
$backupManifestPath = Join-Path $resolvedArtifacts "backup-manifest.json"
$preDeployPath = Join-Path $resolvedArtifacts "pre-deploy-containers.json"
foreach ($required in @($backupManifestPath, $preDeployPath, (Join-Path $resolvedArtifacts "source-manifest.json"))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing beta recovery input: $required" }
}
$backupManifest = Get-Content -LiteralPath $backupManifestPath -Raw | ConvertFrom-Json
if ($backupManifest.schema_version -ne 1 -or $backupManifest.phase -ne "maintenance_quiesced" -or $backupManifest.application_writers_stopped -ne $true) {
    throw "Backup is not a quiesced beta maintenance snapshot"
}
$requiredFiles = @("applicant_store.json", "openbao-data.tar.gz", "postgres-globals.sql", "postgres-keycloak.dump", "postgres-marty.dump", "redis-dump.rdb")
foreach ($record in @($backupManifest.files)) {
    if ($record.name -notin $requiredFiles) { throw "Unexpected file in beta backup manifest" }
    $path = Join-Path $backupDir $record.name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing beta backup file: $($record.name)" }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $record.sha256) { throw "Beta backup checksum mismatch: $($record.name)" }
}
foreach ($name in $requiredFiles) {
    if ($name -notin @($backupManifest.files.name)) { throw "Beta backup manifest is incomplete: $name" }
}

$applicationMap = [ordered]@{
    "marty-auth" = "auth"; "marty-organization" = "organization"; "marty-credential-template" = "credential-template"
    "marty-trust-profile" = "trust-profile"; "marty-applicant" = "applicant"; "marty-notification" = "notification"
    "marty-compliance-profile" = "compliance-profile"; "marty-presentation-policy" = "presentation-policy"
    "marty-deployment-profile" = "deployment-profile"; "marty-flow" = "flow"; "marty-verification" = "verification"
    "marty-revocation-profile" = "revocation-profile"; "marty-device-registration" = "device-registration"
    "marty-event-stream" = "event-stream"; "marty-issuance" = "issuance"
    "marty-canvas-sync-worker" = "canvas-sync-worker"; "marty-gateway" = "gateway"
}
$preDeployDocument = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $preDeployPath -Raw)
$preDeploy = @()
foreach ($record in $preDeployDocument) {
    $preDeploy += $record
}
$targetNames = @($applicationMap.Keys) + @("marty-keycloak", "marty-ui-prod")
foreach ($name in $targetNames) {
    $project = if ($name -eq "marty-ui-prod") { "marty-ui-prod" } else { "marty-ui" }
    if (Assert-ContainerOwnership $name $project) { docker stop $name 2>$null | Out-Null }
}
foreach ($infra in @("marty-postgres", "marty-redis", "marty-openbao")) {
    if (-not (Assert-ContainerOwnership $infra "marty-ui")) { throw "Required beta infrastructure is absent: $infra" }
}

Invoke-Checked docker @("cp", (Join-Path $backupDir "postgres-marty.dump"), "marty-postgres:/tmp/beta-restore-marty.dump")
Invoke-Checked docker @("cp", (Join-Path $backupDir "postgres-keycloak.dump"), "marty-postgres:/tmp/beta-restore-keycloak.dump")
foreach ($database in @("marty", "keycloak")) {
    Invoke-Checked docker @("exec", "marty-postgres", "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$database' AND pid <> pg_backend_pid();")
    Invoke-Checked docker @("exec", "marty-postgres", "dropdb", "-U", "postgres", "--if-exists", $database)
    Invoke-Checked docker @("exec", "marty-postgres", "createdb", "-U", "postgres", "-O", $database, $database)
    Invoke-Checked docker @("exec", "marty-postgres", "pg_restore", "-U", "postgres", "-d", $database, "--no-owner", "--role=$database", "/tmp/beta-restore-$database.dump")
}
Invoke-Checked docker @("cp", (Join-Path $backupDir "applicant_store.json"), "marty-applicant:/app/data/applicant_store.json")

$redisVolume = (docker volume inspect marty-ui_redis_data | ConvertFrom-Json)[0]
if ($LASTEXITCODE -ne 0 -or $redisVolume.Labels.'com.docker.compose.project' -ne "marty-ui") {
    throw "Refusing to restore a Redis volume not owned by the marty-ui Compose project"
}
Invoke-Checked docker @("stop", "marty-redis")
Invoke-Checked docker @("run", "--rm", "--mount", "type=volume,src=marty-ui_redis_data,dst=/data", "--mount", "type=bind,src=$backupDir,dst=/backup,readonly", "postgres:15-alpine", "sh", "-lc", "rm -rf /data/appendonlydir && rm -f /data/dump.rdb && cp /backup/redis-dump.rdb /data/dump.rdb")
Invoke-Checked docker @("start", "marty-redis")
Wait-ForContainerHealth @("marty-redis")

$gatewayRecord = @($preDeploy | Where-Object { $_.container -eq "marty-gateway" })[0]
foreach ($name in @("MARTY_RELEASE_VERSION", "MARTY_UI_SHA", "ELEVENID_STACK_VERSION", "ELEVENID_IMAGE_DIGESTS_JSON")) {
    $property = $gatewayRecord.runtime_marker_environment.PSObject.Properties[$name]
    if ($null -ne $property -and $null -ne $property.Value) {
        Set-Item -Path "Env:$name" -Value ([string]$property.Value)
    }
}
$restoreComposePath = Join-Path $resolvedArtifacts "restore-images.yml"
$restoreYaml = @("services:")
$restoreServices = @()
foreach ($record in $preDeploy) {
    if ($record.running -and $applicationMap.Contains($record.container)) {
        if ($record.image_id -notmatch '^sha256:[0-9a-f]{64}$') { throw "Invalid pre-deploy image ID for $($record.container)" }
        $service = $applicationMap[$record.container]
        $restoreServices += $service
        $restoreYaml += "  ${service}:"
        $restoreYaml += "    image: $($record.image_id)"
    }
}
$restoreYaml -join "`n" | Set-Content -LiteralPath $restoreComposePath -Encoding utf8
$composeArgs = @("compose", "--project-name", "marty-ui")
foreach ($file in @("docker-compose.base.yml", "docker-compose.profile.dev.yml", "docker-compose.profile.tunnel.yml", "docker-compose.profile.waltid.yml", "docker-compose.profile.canvas-real.yml", "docker-compose.profile.canvas-sandbox.yml")) {
    $composeArgs += @("-f", (Join-Path $repoRoot $file))
}
$composeArgs += @("-f", $restoreComposePath)

Invoke-Checked docker @("start", "marty-keycloak")
Wait-ForContainerHealth @("marty-keycloak")
if ($restoreServices.Count -gt 0) {
    Invoke-Checked docker ($composeArgs + @("up", "--detach", "--no-build", "--no-deps", "--force-recreate") + $restoreServices)
    Wait-ForContainerHealth @($applicationMap.Keys | Where-Object { $applicationMap[$_] -in $restoreServices })
}
if ("marty-canvas-sync-worker" -notin @($preDeploy.container)) {
    $workerExists = @(& docker ps -a --filter "name=^/marty-canvas-sync-worker$" --format '{{.Names}}')
    if ($LASTEXITCODE -ne 0) { throw "Could not query the beta Canvas worker" }
    if ($workerExists -contains "marty-canvas-sync-worker") {
        Invoke-Checked docker @("rm", "--force", "marty-canvas-sync-worker")
    }
}
$uiRecord = @($preDeploy | Where-Object { $_.container -eq "marty-ui-prod" -and $_.running })
if ($uiRecord.Count -gt 0) {
    $env:MARTY_UI_RELEASE_IMAGE = $uiRecord[0].image_id
    Invoke-Checked docker @("compose", "-f", (Join-Path $repoRoot "docker-compose.ui-release.yml"), "up", "--detach", "--no-build", "--force-recreate", "ui-prod")
    Wait-ForContainerHealth @("marty-ui-prod")
}

[ordered]@{
    schema_version = 1
    operation = "restore_quiesced_local_beta_release"
    beta_only = $true
    artifact_dir = $resolvedArtifacts
    restored_at = (Get-Date).ToUniversalTime().ToString("o")
    openbao_process_preserved = $true
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $resolvedArtifacts "beta-restore-audit.json") -Encoding utf8
Write-Host "Supervised local beta restore complete. OpenBao remained running and marty-selfhost-prod was not addressed."
