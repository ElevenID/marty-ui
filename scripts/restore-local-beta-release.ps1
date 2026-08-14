<#
.SYNOPSIS
Restores a quiesced elevenid-beta release snapshot after a failed migration.

.DESCRIPTION
This command is intentionally limited to the elevenid-beta Compose project.
It resolves containers by Compose service labels and never addresses self-host
production or demo-release-candidate resources.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ArtifactDir,
    [string]$TunnelEnvFile = (Join-Path (Split-Path -Parent $PSScriptRoot) ".env.tunnel.beta.local"),
    [string]$GeneratedEnvFile = (Join-Path (Split-Path -Parent $PSScriptRoot) ".env.beta.generated.local"),
    [Parameter(Mandatory = $true)][switch]$ConfirmBetaRestore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (-not $ConfirmBetaRestore) { throw "-ConfirmBetaRestore is required" }

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = (Resolve-Path (Join-Path $repoRoot "tests\artifacts")).Path
$resolvedArtifacts = (Resolve-Path $ArtifactDir).Path
$allowedPrefix = $artifactRoot.TrimEnd('\') + '\'
if (-not $resolvedArtifacts.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase) -or $resolvedArtifacts -match "selfhost|production|demo-release-candidate") {
    throw "Restore ArtifactDir must be a local beta artifact under tests/artifacts"
}

$project = "elevenid-beta"
$uiProject = "elevenid-beta-ui"
$env:MARTY_NETWORK_NAME = "elevenid-beta-network"
$composeFiles = @(
    "docker-compose.base.yml", "docker-compose.beta.yml", "docker-compose.profile.dev.yml",
    "docker-compose.profile.tunnel.yml", "deploy-config/compose/tunnel-beta/revocation-profile-rust.yml",
    "docker-compose.profile.waltid.yml",
    "docker-compose.profile.canvas-real.yml", "docker-compose.profile.canvas-sandbox.yml"
) | ForEach-Object { Join-Path $repoRoot $_ }
$uiCompose = Join-Path $repoRoot "docker-compose.ui-release.yml"
$envFiles = @(
    $TunnelEnvFile,
    $GeneratedEnvFile
)
foreach ($envFile in $envFiles) {
    if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) { throw "Required beta environment file is missing: $envFile" }
}
$stackLock = Get-Content -LiteralPath (Join-Path $repoRoot "release\stack-lock.json") -Raw | ConvertFrom-Json
function Get-StackArtifact([string]$Name, [string]$Type) {
    $component = @($stackLock.components | Where-Object name -eq $Name)
    if ($component.Count -ne 1) { throw "Stack lock must contain exactly one $Name component" }
    $artifact = @($component[0].artifacts | Where-Object type -eq $Type)
    if ($artifact.Count -ne 1 -or $artifact[0].digest -notmatch '^sha256:[0-9a-f]{64}$' -or -not $artifact[0].uri) {
        throw "Stack lock artifact is incomplete: $Name/$Type"
    }
    return $artifact[0]
}
$martyCommon = Get-StackArtifact "marty-common" "python"
$martyRs = Get-StackArtifact "marty-core-python" "python"
$martyVerification = Get-StackArtifact "marty-verification-python" "python"
$martyIso18013 = Get-StackArtifact "marty-iso18013-python" "python"
$martyIssuance = Get-StackArtifact "marty-credentials-issuance" "oci"
$env:MARTY_COMMON_URI = $martyCommon.uri
$env:MARTY_COMMON_DIGEST = $martyCommon.digest
$env:MARTY_RS_URI = $martyRs.uri
$env:MARTY_RS_DIGEST = $martyRs.digest
$env:MARTY_VERIFICATION_URI = $martyVerification.uri
$env:MARTY_VERIFICATION_DIGEST = $martyVerification.digest
$env:MARTY_ISO18013_URI = $martyIso18013.uri
$env:MARTY_ISO18013_DIGEST = $martyIso18013.digest
$env:MARTY_ISSUANCE_IMAGE = "$($martyIssuance.uri)@$($martyIssuance.digest)"
$docsIds = @(& docker ps -a --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=docs" --format '{{.ID}}')
if ($LASTEXITCODE -ne 0 -or $docsIds.Count -ne 1) { throw "Expected one existing beta docs container" }
$env:MARTY_DOCS_IMAGE = & docker inspect $docsIds[0] --format '{{.Config.Image}}'
if ($LASTEXITCODE -ne 0 -or $env:MARTY_DOCS_IMAGE -notmatch '^sha256:[0-9a-f]{64}$') {
    throw "Existing beta docs image is not immutable"
}

function Invoke-Checked([string]$FilePath, [string[]]$Arguments) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$FilePath failed with exit code $LASTEXITCODE" }
}

function Get-ComposeArgs([string[]]$Tail) {
    $args = @("compose", "--project-name", $project)
    foreach ($envFile in $envFiles) { $args += @("--env-file", $envFile) }
    foreach ($file in $composeFiles) { $args += @("-f", $file) }
    return $args + $Tail
}

function Find-ServiceContainer([string]$Service) {
    $arguments = Get-ComposeArgs @("ps", "--all", "--quiet", $Service)
    $id = & docker @arguments
    if ($LASTEXITCODE -ne 0) { throw "Could not resolve beta service $Service" }
    $ids = @($id | Where-Object { $_ })
    if ($ids.Count -gt 1) { throw "Expected at most one beta container for $Service" }
    if ($ids.Count -eq 0) { return $null }
    $inspect = & docker inspect $ids[0] | ConvertFrom-Json
    if ($inspect[0].Config.Labels.'com.docker.compose.project' -ne $project) {
        throw "Refusing container outside $project"
    }
    return [string]$ids[0]
}

function Get-ServiceContainer([string]$Service) {
    $container = Find-ServiceContainer $Service
    if (-not $container) { throw "Expected one beta container for $Service" }
    return $container
}

function Wait-ForServiceHealth([string[]]$Services, [int]$TimeoutSeconds = 420) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $pending = @()
        foreach ($service in $Services) {
            $container = Find-ServiceContainer $service
            if (-not $container) { $pending += "$service=missing"; continue }
            $state = & docker inspect $container --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>$null
            if ($LASTEXITCODE -ne 0 -or $state -notin @("healthy", "running")) {
                $pending += "$service=$state"
            }
        }
        if ($pending.Count -eq 0) { return }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "Restored beta services did not become healthy: $($pending -join ', ')"
}

$backupDir = Join-Path $resolvedArtifacts "backup"
$backupManifestPath = Join-Path $resolvedArtifacts "backup-manifest.json"
$preDeployPath = Join-Path $resolvedArtifacts "pre-deploy-containers.json"
foreach ($required in @($backupManifestPath, $preDeployPath, (Join-Path $resolvedArtifacts "source-manifest.json"))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing beta recovery input: $required" }
}
$manifest = Get-Content -LiteralPath $backupManifestPath -Raw | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.phase -ne "maintenance_quiesced" -or $manifest.application_writers_stopped -ne $true) {
    throw "Backup is not a quiesced beta maintenance snapshot"
}
$requiredFiles = @("applicant_store.json", "openbao-data.tar.gz", "postgres-globals.sql", "postgres-keycloak.dump", "postgres-marty.dump", "redis-dump.rdb")
foreach ($name in $requiredFiles) {
    $record = @($manifest.files | Where-Object name -eq $name)
    $path = Join-Path $backupDir $name
    if ($record.Count -ne 1 -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Incomplete beta backup: $name" }
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $record[0].sha256) { throw "Beta backup checksum mismatch: $name" }
}

$preDeployDocument = Get-Content -LiteralPath $preDeployPath -Raw | ConvertFrom-Json
$preDeploy = @($preDeployDocument | ForEach-Object { $_ })
$applicationServices = @(
    "auth", "organization", "credential-template", "trust-profile", "applicant", "notification",
    "compliance-profile", "presentation-policy", "deployment-profile", "flow", "verification",
    "revocation-profile", "device-registration", "event-stream", "issuance", "canvas-sync-worker", "gateway"
)
Invoke-Checked docker (Get-ComposeArgs (@("stop") + $applicationServices + @("keycloak")))

$postgres = Get-ServiceContainer "postgres"
Invoke-Checked docker @("cp", (Join-Path $backupDir "postgres-marty.dump"), "${postgres}:/tmp/beta-restore-marty.dump")
Invoke-Checked docker @("cp", (Join-Path $backupDir "postgres-keycloak.dump"), "${postgres}:/tmp/beta-restore-keycloak.dump")
foreach ($database in @("marty", "keycloak")) {
    Invoke-Checked docker @("exec", $postgres, "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$database' AND pid <> pg_backend_pid();")
    Invoke-Checked docker @("exec", $postgres, "dropdb", "-U", "postgres", "--if-exists", $database)
    Invoke-Checked docker @("exec", $postgres, "createdb", "-U", "postgres", "-O", $database, $database)
    Invoke-Checked docker @("exec", $postgres, "pg_restore", "-U", "postgres", "-d", $database, "--no-owner", "--role=$database", "/tmp/beta-restore-$database.dump")
}

$redisVolumeName = "elevenid-beta_redis_data"
$redisVolumeRaw = & docker volume inspect $redisVolumeName
if ($LASTEXITCODE -ne 0) { throw "Required beta Redis volume is absent" }
$redisVolume = ($redisVolumeRaw -join "`n") | ConvertFrom-Json
if ($redisVolume[0].Labels.'com.docker.compose.project' -ne $project) { throw "Refusing non-beta Redis volume" }
Invoke-Checked docker (Get-ComposeArgs @("stop", "redis"))
Invoke-Checked docker @("run", "--rm", "--mount", "type=volume,src=$redisVolumeName,dst=/data", "--mount", "type=bind,src=$backupDir,dst=/backup,readonly", "postgres:15-alpine", "sh", "-lc", "rm -rf /data/appendonlydir && rm -f /data/dump.rdb && cp /backup/redis-dump.rdb /data/dump.rdb")
Invoke-Checked docker (Get-ComposeArgs @("start", "redis"))
Wait-ForServiceHealth @("redis")

$gatewayRecord = @($preDeploy | Where-Object { $_.service -eq "gateway" } | Select-Object -First 1)
if ($gatewayRecord.Count -eq 1) {
    foreach ($name in @("MARTY_RELEASE_VERSION", "MARTY_UI_SHA", "ELEVENID_STACK_VERSION", "ELEVENID_IMAGE_DIGESTS_JSON")) {
        $property = $gatewayRecord[0].runtime_marker_environment.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value) {
            Set-Item -Path "Env:$name" -Value ([string]$property.Value)
        }
    }
}
$restoreImages = Join-Path $resolvedArtifacts "restore-images.yml"
$yaml = @("services:")
$restoreServices = @()
foreach ($record in $preDeploy) {
    if ($record.running -and $record.service -in $applicationServices) {
        if ($record.image_id -notmatch '^sha256:[0-9a-f]{64}$') { throw "Invalid image ID for $($record.service)" }
        $restoreServices += [string]$record.service
        $yaml += "  $($record.service):"
        $yaml += "    image: $($record.image_id)"
    }
}
$yaml -join "`n" | Set-Content -LiteralPath $restoreImages -Encoding utf8
$composeFiles += $restoreImages
Invoke-Checked docker (Get-ComposeArgs (@("up", "--detach", "--no-build", "--no-deps", "--force-recreate") + @("keycloak") + $restoreServices))
Wait-ForServiceHealth (@("keycloak") + $restoreServices)

if ("canvas-sync-worker" -notin @($preDeploy.service)) {
    $worker = Find-ServiceContainer "canvas-sync-worker"
    if ($worker) { Invoke-Checked docker @("rm", "--force", $worker) }
}

$applicant = Get-ServiceContainer "applicant"
Invoke-Checked docker @("cp", (Join-Path $backupDir "applicant_store.json"), "${applicant}:/app/data/applicant_store.json")

$uiRecord = @($preDeploy | Where-Object { $_.service -eq "ui-prod" -and $_.running } | Select-Object -First 1)
if ($uiRecord.Count -eq 1) {
    if ($uiRecord[0].image_id -notmatch '^sha256:[0-9a-f]{64}$') { throw "Invalid beta UI image ID" }
    $env:MARTY_UI_RELEASE_IMAGE = $uiRecord[0].image_id
    Invoke-Checked docker @("compose", "--project-name", $uiProject, "--env-file", $envFiles[0], "--env-file", $envFiles[1], "-f", $uiCompose, "up", "--detach", "--no-build", "--force-recreate", "--wait", "ui-prod")
}

[ordered]@{
    schema_version = 2
    operation = "restore_quiesced_local_beta_release"
    compose_project = $project
    ui_compose_project = $uiProject
    beta_only = $true
    restored_at = (Get-Date).ToUniversalTime().ToString("o")
    openbao_process_preserved = $true
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $resolvedArtifacts "beta-restore-audit.json") -Encoding utf8
Write-Host "Supervised elevenid-beta restore complete; self-host production was not addressed."
