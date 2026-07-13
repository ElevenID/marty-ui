[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDir,

    [string]$BetaOrigin = "https://beta.elevenidllc.com",

    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$script:WorkspaceRoot = (Resolve-Path (Join-Path $script:RepoRoot "..")).Path
$script:ArtifactRoot = (Resolve-Path (Join-Path $script:RepoRoot "tests\artifacts")).Path
$script:ArtifactDir = (Resolve-Path $ArtifactDir).Path
$script:ComposeFiles = @(
    "docker-compose.base.yml",
    "docker-compose.profile.dev.yml",
    "docker-compose.profile.tunnel.yml",
    "docker-compose.profile.waltid.yml",
    "docker-compose.profile.canvas-real.yml",
    "docker-compose.profile.canvas-sandbox.yml"
)
$script:ApplicationServices = @(
    "auth",
    "organization",
    "credential-template",
    "trust-profile",
    "applicant",
    "notification",
    "compliance-profile",
    "presentation-policy",
    "deployment-profile",
    "flow",
    "verification",
    "revocation-profile",
    "device-registration",
    "event-stream",
    "billing",
    "issuance",
    "gateway"
)
$script:ApplicationContainers = @(
    "marty-auth",
    "marty-organization",
    "marty-credential-template",
    "marty-trust-profile",
    "marty-applicant",
    "marty-notification",
    "marty-compliance-profile",
    "marty-presentation-policy",
    "marty-deployment-profile",
    "marty-flow",
    "marty-verification",
    "marty-revocation-profile",
    "marty-device-registration",
    "marty-event-stream",
    "marty-billing",
    "marty-issuance",
    "marty-gateway"
)

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

function Invoke-Compose {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $composeArgs = @("compose")
    foreach ($file in $script:ComposeFiles) {
        $composeArgs += @("-f", $file)
    }
    $composeArgs += $Arguments
    Invoke-Checked -FilePath docker -Arguments $composeArgs
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Wait-ForContainerHealth {
    param([string[]]$Containers, [int]$TimeoutSeconds = 420)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $pending = @()
        foreach ($container in $Containers) {
            $state = docker inspect $container --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>$null
            if ($LASTEXITCODE -ne 0 -or $state -notin @("healthy", "running")) {
                $pending += "$container=$state"
            }
        }
        if ($pending.Count -eq 0) {
            return
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "Containers did not become healthy: $($pending -join ', ')"
}

function Get-ContainerRecords([string[]]$Containers) {
    $records = @()
    foreach ($container in $Containers) {
        $json = docker inspect $container 2>$null
        if ($LASTEXITCODE -ne 0) {
            continue
        }
        $inspect = ($json | ConvertFrom-Json)[0]
        $health = $null
        if ($inspect.State.PSObject.Properties.Name -contains "Health") {
            $health = $inspect.State.Health.Status
        }
        $records += [ordered]@{
            container = $container
            configured_image = $inspect.Config.Image
            image_id = $inspect.Image
            status = $inspect.State.Status
            health = $health
        }
    }
    return $records
}

if (-not $script:ArtifactDir.StartsWith($script:ArtifactRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must stay under $script:ArtifactRoot"
}
if ($BetaOrigin -notmatch '^https://[^/]+$') {
    throw "BetaOrigin must be an absolute HTTPS origin without a path"
}

$sourceManifestPath = Join-Path $script:ArtifactDir "source-manifest.json"
if (-not (Test-Path -LiteralPath $sourceManifestPath -PathType Leaf)) {
    throw "Missing source manifest: $sourceManifestPath"
}
$sourceManifest = Get-Content -LiteralPath $sourceManifestPath -Raw | ConvertFrom-Json
if ($sourceManifest.schema_version -ne 1 -or $sourceManifest.mip_version -ne "0.3.1") {
    throw "Source manifest is not a supported MIP 0.3.1 local release"
}
if ($sourceManifest.source_kind -ne "local-worktree-snapshot" -or $sourceManifest.promotion_eligible -ne $false) {
    throw "Local source manifest must be a non-promotable worktree snapshot"
}

$releaseVersion = [string]$sourceManifest.release_version
$sourceId = [string]$sourceManifest.marty_ui_sha
if ($sourceId -notmatch '^[0-9a-f]{40}$') {
    throw "Local source ID must be 40 lowercase hexadecimal characters"
}

$backupDir = Join-Path $script:ArtifactDir "backup"
$logsDir = Join-Path $script:ArtifactDir "logs"

Write-Step "Local beta release plan"
Write-Host "Release: $releaseVersion"
Write-Host "Source ID: $sourceId"
Write-Host "Origin: $BetaOrigin"
Write-Host "Artifact directory: $script:ArtifactDir"
Write-Host "Promotion eligible: false"

if ($PlanOnly) {
    [ordered]@{
        release_version = $releaseVersion
        marty_ui_sha = $sourceId
        beta_origin = $BetaOrigin
        application_services = $script:ApplicationServices
        steps = @(
            "backup",
            "build migration image",
            "isolated beta-copy rehearsal",
            "build application and UI images",
            "maintenance stop",
            "live migration",
            "atomic application/UI recreation",
            "local and tunneled marker verification"
        )
    } | ConvertTo-Json -Depth 5
    exit 0
}

New-Item -ItemType Directory -Path $backupDir, $logsDir -Force | Out-Null
$releaseComposeFile = Join-Path $script:ArtifactDir "local-release-images.yml"
$releaseCompose = @("services:")
foreach ($service in $script:ApplicationServices) {
    $releaseCompose += "  ${service}:"
    $releaseCompose += "    image: elevenid-local/${service}:${releaseVersion}"
}
$releaseCompose -join "`n" | Set-Content -LiteralPath $releaseComposeFile -Encoding utf8
$script:ComposeFiles += $releaseComposeFile

Write-Step "Verify immutable source snapshot and worktree"
Invoke-Checked -FilePath python -Arguments @(
    (Join-Path $script:RepoRoot "scripts\create_local_release_manifest.py"),
    "--workspace", $script:WorkspaceRoot,
    "--verify-manifest", $sourceManifestPath
)

Write-Step "Preflight running beta topology"
Invoke-Checked -FilePath docker -Arguments @("info", "--format", "{{.ServerVersion}}")
foreach ($container in @("marty-postgres", "marty-redis", "marty-openbao", "marty-applicant", "marty-gateway", "marty-ui-prod")) {
    Invoke-Checked -FilePath docker -Arguments @("inspect", $container, "--format", "{{.State.Status}}")
}

$preDeployContainers = Get-ContainerRecords ($script:ApplicationContainers + @("marty-ui-prod"))
$preDeployContainers | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $script:ArtifactDir "pre-deploy-containers.json") -Encoding utf8

Write-Step "Backup PostgreSQL, applicant store, Redis, and OpenBao"
$safeRelease = $releaseVersion -replace '[^a-zA-Z0-9_.-]', '_'
Invoke-Checked -FilePath docker -Arguments @("exec", "marty-postgres", "sh", "-lc", "pg_dump -U postgres -Fc -d marty -f /tmp/$safeRelease-marty.dump && pg_dump -U postgres -Fc -d keycloak -f /tmp/$safeRelease-keycloak.dump && pg_dumpall -U postgres --globals-only -f /tmp/$safeRelease-globals.sql")
Invoke-Checked -FilePath docker -Arguments @("cp", "marty-postgres:/tmp/$safeRelease-marty.dump", (Join-Path $backupDir "postgres-marty.dump"))
Invoke-Checked -FilePath docker -Arguments @("cp", "marty-postgres:/tmp/$safeRelease-keycloak.dump", (Join-Path $backupDir "postgres-keycloak.dump"))
Invoke-Checked -FilePath docker -Arguments @("cp", "marty-postgres:/tmp/$safeRelease-globals.sql", (Join-Path $backupDir "postgres-globals.sql"))
Invoke-Checked -FilePath docker -Arguments @("cp", "marty-applicant:/app/data/applicant_store.json", (Join-Path $backupDir "applicant_store.json"))
Invoke-Checked -FilePath docker -Arguments @("exec", "marty-redis", "redis-cli", "SAVE")
Invoke-Checked -FilePath docker -Arguments @("cp", "marty-redis:/data/dump.rdb", (Join-Path $backupDir "redis-dump.rdb"))
Invoke-Checked -FilePath docker -Arguments @("run", "--rm", "--mount", "type=volume,src=marty-ui_openbao_data,dst=/source,readonly", "--mount", "type=bind,src=$backupDir,dst=/backup", "postgres:15-alpine", "sh", "-lc", "cd /source && tar -czf /backup/openbao-data.tar.gz .")

$backupRecords = Get-ChildItem -LiteralPath $backupDir -File | ForEach-Object {
    [ordered]@{ name = $_.Name; size = $_.Length; sha256 = Get-FileSha256 $_.FullName }
}
$backupRecords | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $script:ArtifactDir "backup-manifest.json") -Encoding utf8

Write-Step "Build immutable migration image"
$migrationImage = "elevenid-local/db-migrate:$releaseVersion"
Invoke-Checked -FilePath docker -Arguments @("build", "--file", (Join-Path $script:RepoRoot "services\Dockerfile.migrations"), "--tag", $migrationImage, "--label", "org.opencontainers.image.version=$releaseVersion", "--label", "org.opencontainers.image.revision=$sourceId", $script:WorkspaceRoot)

Write-Step "Rehearse one-way migration on isolated beta copy"
$copySuffix = $sourceId.Substring(0, 12)
$copyContainer = "marty-beta-copy-$copySuffix"
$copyPassword = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
try {
    $existing = docker ps -a --filter "name=^/$copyContainer$" --format '{{.Names}}'
    if ($existing) {
        Invoke-Checked -FilePath docker -Arguments @("rm", "--force", $copyContainer)
    }
    Invoke-Checked -FilePath docker -Arguments @("run", "--detach", "--name", $copyContainer, "--network", "marty-infra-network", "--env", "POSTGRES_PASSWORD=$copyPassword", "postgres:15-alpine")
    $ready = $false
    foreach ($attempt in 1..60) {
        docker exec $copyContainer pg_isready -U postgres | Out-Null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) { throw "Rehearsal PostgreSQL did not become ready" }
    Invoke-Checked -FilePath docker -Arguments @("exec", $copyContainer, "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", "CREATE ROLE marty LOGIN PASSWORD '$copyPassword';")
    Invoke-Checked -FilePath docker -Arguments @("exec", $copyContainer, "createdb", "-U", "postgres", "-O", "marty", "marty")
    Invoke-Checked -FilePath docker -Arguments @("cp", (Join-Path $backupDir "postgres-marty.dump"), "${copyContainer}:/tmp/marty.dump")
    Invoke-Checked -FilePath docker -Arguments @("exec", $copyContainer, "pg_restore", "-U", "postgres", "-d", "marty", "--no-owner", "--role=marty", "/tmp/marty.dump")
    $copyUrl = "postgresql://marty:$copyPassword@${copyContainer}:5432/marty"
    & docker run --rm --network marty-infra-network --env "DATABASE_URL=$copyUrl" --env "PUBLIC_API_URL=$BetaOrigin" --env "MARTY_MIGRATION_PROFILE=beta" --env "MARTY_KMS_BOOTSTRAP_ENABLED=false" $migrationImage python /app/run_all_migrations.py 2>&1 | Tee-Object -FilePath (Join-Path $logsDir "migration-rehearsal.log")
    if ($LASTEXITCODE -ne 0) { throw "Migration rehearsal failed" }
    & docker run --rm --network marty-infra-network --env "DATABASE_URL=$copyUrl" --env "PUBLIC_API_URL=$BetaOrigin" --env "MARTY_MIGRATION_PROFILE=beta" --env "MARTY_KMS_BOOTSTRAP_ENABLED=false" $migrationImage python /app/run_all_migrations.py --verify-only 2>&1 | Tee-Object -FilePath (Join-Path $logsDir "migration-rehearsal-verify.log")
    if ($LASTEXITCODE -ne 0) { throw "Migration rehearsal verification failed" }
}
finally {
    $candidate = docker ps -a --filter "name=^/$copyContainer$" --format '{{.Names}}'
    if ($candidate -eq $copyContainer -and $copyContainer.StartsWith("marty-beta-copy-")) {
        docker rm --force $copyContainer | Out-Null
    }
}

Write-Step "Build marker-bearing application images"
$env:MARTY_RELEASE_VERSION = $releaseVersion
$env:MARTY_UI_SHA = $sourceId
Invoke-Compose -Arguments (@("build", "--build-arg", "MARTY_RELEASE_VERSION=$releaseVersion", "--build-arg", "MARTY_UI_SHA=$sourceId") + $script:ApplicationServices)

Write-Step "Build marker-bearing public UI image"
$uiImage = "elevenid-local/ui:$releaseVersion"
Invoke-Checked -FilePath docker -Arguments @("buildx", "build", "--load", "--file", (Join-Path $script:RepoRoot "docker\ui.Dockerfile"), "--build-context", "marty-cli=$(Join-Path $script:WorkspaceRoot 'marty-cli')", "--build-context", "marty-blog=$(Join-Path $script:WorkspaceRoot 'marty-blog')", "--build-context", "marty-subscriptions=$(Join-Path $script:WorkspaceRoot 'marty-subscriptions')", "--build-arg", "UI_VARIANT=public", "--build-arg", "NGINX_CONFIG=nginx.spa.conf", "--build-arg", "MARTY_RELEASE_VERSION=$releaseVersion", "--build-arg", "MARTY_UI_SHA=$sourceId", "--tag", $uiImage, $script:RepoRoot)

Write-Step "Enter maintenance window and apply live migration"
Invoke-Checked -FilePath docker -Arguments (@("stop") + $script:ApplicationContainers + @("marty-ui-prod"))
try {
    $env:MARTY_MIGRATION_PROFILE = "beta"
    $env:PUBLIC_API_URL = $BetaOrigin
    & docker run --rm --network marty-infra-network --env "DATABASE_URL=postgresql://marty:marty_dev_password@postgres:5432/marty" --env "PUBLIC_API_URL=$BetaOrigin" --env "MARTY_MIGRATION_PROFILE=beta" --env "MARTY_KMS_BOOTSTRAP_ENABLED=false" $migrationImage python /app/run_all_migrations.py 2>&1 | Tee-Object -FilePath (Join-Path $logsDir "migration-live.log")
    if ($LASTEXITCODE -ne 0) { throw "Live migration failed" }

    Write-Step "Recreate application containers from coordinated images"
    Invoke-Compose -Arguments (@("up", "--detach", "--no-build", "--no-deps", "--force-recreate") + $script:ApplicationServices)
    Wait-ForContainerHealth $script:ApplicationContainers

    Write-Step "Recreate public UI from immutable image"
    $env:MARTY_UI_RELEASE_IMAGE = $uiImage
    Invoke-Checked -FilePath docker -Arguments @("compose", "-f", "docker-compose.ui-release.yml", "up", "--detach", "--no-build", "--force-recreate", "ui-prod")
    Wait-ForContainerHealth @("marty-ui-prod")
}
catch {
    Write-Warning "Deployment failed after maintenance began. Backups and pre-deploy image IDs are preserved in $script:ArtifactDir."
    throw
}

Write-Step "Verify local and tunneled runtime markers"
$servicesMarker = Invoke-RestMethod -Uri "http://127.0.0.1:8000/.well-known/marty-release" -TimeoutSec 30
$uiMarker = Invoke-RestMethod -Uri "http://127.0.0.1:3002/marty-ui-release.json" -TimeoutSec 30
$betaServicesMarker = Invoke-RestMethod -Uri "$BetaOrigin/.well-known/marty-release" -Headers @{ "Cache-Control" = "no-cache" } -TimeoutSec 30
$betaUiMarker = Invoke-RestMethod -Uri "$BetaOrigin/marty-ui-release.json" -Headers @{ "Cache-Control" = "no-cache" } -TimeoutSec 30
foreach ($marker in @($servicesMarker, $uiMarker, $betaServicesMarker, $betaUiMarker)) {
    if ($marker.release_version -ne $releaseVersion -or $marker.marty_ui_sha -ne $sourceId) {
        throw "Runtime marker does not match local release provenance"
    }
}

$postDeployContainers = Get-ContainerRecords ($script:ApplicationContainers + @("marty-ui-prod"))
$deploymentManifest = [ordered]@{
    schema_version = 1
    release_version = $releaseVersion
    mip_version = "0.3.1"
    source_kind = "local-worktree-snapshot"
    marty_ui_sha = $sourceId
    beta_origin = $BetaOrigin
    promotion_eligible = $false
    release_ready = $false
    backup_manifest = "backup-manifest.json"
    source_manifest = "source-manifest.json"
    services_marker = $servicesMarker
    ui_marker = $uiMarker
    images = $postDeployContainers
    deployed_at = (Get-Date).ToUniversalTime().ToString("o")
}
$deploymentManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $script:ArtifactDir "local-deployment-manifest.json") -Encoding utf8

Write-Step "Local beta deployment complete"
Write-Host "Release: $releaseVersion"
Write-Host "Source ID: $sourceId"
Write-Host "Evidence: $script:ArtifactDir"
