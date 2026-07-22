[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDir,

    [string]$BetaOrigin = "https://beta.elevenidllc.com",

    [switch]$EnablePortableCanvas,

    [string]$CanvasOrigin = "https://canvas-test.elevenidllc.com",

    [string]$PilotOrganizationId = "00000000-0000-0000-0000-000000000001",

    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (Get-Variable PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    # Docker and Alembic emit normal progress logs on stderr. Native failures
    # remain fail-closed through the explicit $LASTEXITCODE checks below.
    $PSNativeCommandUseErrorActionPreference = $false
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$script:WorkspaceRoot = (Resolve-Path (Join-Path $script:RepoRoot "..")).Path
$script:ArtifactRoot = (Resolve-Path (Join-Path $script:RepoRoot "tests\artifacts")).Path
$script:ArtifactDir = (Resolve-Path $ArtifactDir).Path
$script:ComposeFiles = @(
    (Join-Path $script:RepoRoot "docker-compose.base.yml"),
    (Join-Path $script:RepoRoot "docker-compose.profile.dev.yml"),
    (Join-Path $script:RepoRoot "docker-compose.profile.tunnel.yml"),
    (Join-Path $script:RepoRoot "docker-compose.profile.waltid.yml"),
    (Join-Path $script:RepoRoot "docker-compose.profile.canvas-real.yml"),
    (Join-Path $script:RepoRoot "docker-compose.profile.canvas-sandbox.yml")
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
    "issuance",
    "canvas-sync-worker",
    "gateway"
)
$script:ApplicationBuildServices = @(
    $script:ApplicationServices | Where-Object { $_ -ne "canvas-sync-worker" }
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
    "marty-issuance",
    "marty-canvas-sync-worker",
    "marty-gateway"
)
$script:InfrastructureWriterContainers = @("marty-keycloak")

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

function Invoke-DockerLogged {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Native stderr carries Docker/Alembic progress, so determine failure
        # from the process exit code while preserving the combined audit log.
        $ErrorActionPreference = "Continue"
        & docker @Arguments 2>&1 | Tee-Object -FilePath $LogPath
        $nativeExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($nativeExitCode -ne 0) {
        throw "$FailureMessage (exit code $nativeExitCode)"
    }
}

function Invoke-Compose {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $composeArgs = @("compose", "--project-name", "marty-ui")
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
    $existingContainers = @(& docker ps -a --format '{{.Names}}')
    if ($LASTEXITCODE -ne 0) {
        throw "Could not enumerate Docker containers"
    }
    foreach ($container in $Containers) {
        if ($container -notin $existingContainers) {
            continue
        }
        $json = & docker inspect $container
        if ($LASTEXITCODE -ne 0) {
            throw "Could not inspect Docker container: $container"
        }
        $inspect = (ConvertFrom-Json -InputObject ($json -join "`n"))[0]
        $health = $null
        if ($inspect.State.PSObject.Properties.Name -contains "Health") {
            $health = $inspect.State.Health.Status
        }
        $markerEnvironment = [ordered]@{}
        foreach ($entry in @($inspect.Config.Env)) {
            $parts = $entry -split "=", 2
            if ($parts[0] -in @("MARTY_RELEASE_VERSION", "MARTY_UI_SHA", "ELEVENID_STACK_VERSION", "ELEVENID_IMAGE_DIGESTS_JSON")) {
                $markerEnvironment[$parts[0]] = if ($parts.Count -gt 1) { $parts[1] } else { "" }
            }
        }
        $records += [ordered]@{
            container = $container
            configured_image = $inspect.Config.Image
            image_id = $inspect.Image
            status = $inspect.State.Status
            running = [bool]$inspect.State.Running
            started_at = $inspect.State.StartedAt
            health = $health
            compose_project = $inspect.Config.Labels.'com.docker.compose.project'
            compose_service = $inspect.Config.Labels.'com.docker.compose.service'
            runtime_marker_environment = $markerEnvironment
        }
    }
    return $records
}

function New-BetaStateBackup {
    param(
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$SafeRelease,
        [Parameter(Mandatory = $true)][string]$Phase,
        [Parameter(Mandatory = $true)][bool]$WritersStopped
    )

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Invoke-Checked -FilePath docker -Arguments @("exec", "marty-postgres", "sh", "-lc", "pg_dump -U postgres -Fc -d marty -f /tmp/$SafeRelease-marty.dump && pg_dump -U postgres -Fc -d keycloak -f /tmp/$SafeRelease-keycloak.dump && pg_dumpall -U postgres --globals-only -f /tmp/$SafeRelease-globals.sql")
    Invoke-Checked -FilePath docker -Arguments @("cp", "marty-postgres:/tmp/$SafeRelease-marty.dump", (Join-Path $Destination "postgres-marty.dump"))
    Invoke-Checked -FilePath docker -Arguments @("cp", "marty-postgres:/tmp/$SafeRelease-keycloak.dump", (Join-Path $Destination "postgres-keycloak.dump"))
    Invoke-Checked -FilePath docker -Arguments @("cp", "marty-postgres:/tmp/$SafeRelease-globals.sql", (Join-Path $Destination "postgres-globals.sql"))
    Invoke-Checked -FilePath docker -Arguments @("cp", "marty-applicant:/app/data/applicant_store.json", (Join-Path $Destination "applicant_store.json"))
    Invoke-Checked -FilePath docker -Arguments @("exec", "marty-redis", "redis-cli", "SAVE")
    Invoke-Checked -FilePath docker -Arguments @("cp", "marty-redis:/data/dump.rdb", (Join-Path $Destination "redis-dump.rdb"))
    Invoke-Checked -FilePath docker -Arguments @("run", "--rm", "--mount", "type=volume,src=marty-ui_openbao_data,dst=/source,readonly", "--mount", "type=bind,src=$Destination,dst=/backup", "postgres:15-alpine", "sh", "-lc", "cd /source && tar -czf /backup/openbao-data.tar.gz .")

    $files = @(Get-ChildItem -LiteralPath $Destination -File | Sort-Object Name | ForEach-Object {
        [ordered]@{ name = $_.Name; size = $_.Length; sha256 = Get-FileSha256 $_.FullName }
    })
    [ordered]@{
        schema_version = 1
        phase = $Phase
        application_writers_stopped = $WritersStopped
        created_at = (Get-Date).ToUniversalTime().ToString("o")
        files = $files
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ManifestPath -Encoding utf8
}

function Start-ContainersBestEffort([string[]]$Containers) {
    foreach ($container in $Containers) {
        try {
            docker start $container 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Could not restart beta container $container during automatic pre-migration recovery."
            }
        }
        catch {
            Write-Warning "Could not restart beta container $container during automatic pre-migration recovery."
        }
    }
}

$artifactPrefix = $script:ArtifactRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $script:ArtifactDir.StartsWith($artifactPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "ArtifactDir must stay under $script:ArtifactRoot"
}
if ($BetaOrigin -notmatch '^https://[^/]+$') {
    throw "BetaOrigin must be an absolute HTTPS origin without a path"
}
if ($EnablePortableCanvas -and $CanvasOrigin -notmatch '^https://[^/]+$') {
    throw "CanvasOrigin must be an absolute HTTPS origin without a path"
}
if ($EnablePortableCanvas -and $PilotOrganizationId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    throw "PilotOrganizationId must be a UUID"
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
$preflightBackupDir = Join-Path $script:ArtifactDir "preflight-backup"
$logsDir = Join-Path $script:ArtifactDir "logs"

Write-Step "Local beta release plan"
Write-Host "Release: $releaseVersion"
Write-Host "Source ID: $sourceId"
Write-Host "Origin: $BetaOrigin"
Write-Host "Artifact directory: $script:ArtifactDir"
Write-Host "Promotion eligible: false"
Write-Host "Portable Canvas enabled: $([bool]$EnablePortableCanvas)"

if ($PlanOnly) {
    [ordered]@{
        release_version = $releaseVersion
        marty_ui_sha = $sourceId
        beta_origin = $BetaOrigin
        portable_canvas_enabled = [bool]$EnablePortableCanvas
        canvas_origin = if ($EnablePortableCanvas) { $CanvasOrigin } else { $null }
        pilot_organization_id = if ($EnablePortableCanvas) { $PilotOrganizationId } else { $null }
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

New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
$releaseComposeFile = Join-Path $script:ArtifactDir "local-release-images.yml"
$releaseCompose = @("services:")
foreach ($service in $script:ApplicationServices) {
    $imageService = if ($service -eq "canvas-sync-worker") { "issuance" } else { $service }
    $releaseCompose += "  ${service}:"
    $releaseCompose += "    image: elevenid-local/${imageService}:${releaseVersion}"
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
foreach ($container in @("marty-postgres", "marty-redis", "marty-openbao", "marty-keycloak", "marty-applicant", "marty-gateway", "marty-ui-prod")) {
    Invoke-Checked -FilePath docker -Arguments @("inspect", $container, "--format", "{{.State.Status}}")
}

$preDeployContainers = Get-ContainerRecords ($script:ApplicationContainers + $script:InfrastructureWriterContainers + @("marty-ui-prod"))
$preDeployContainers | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $script:ArtifactDir "pre-deploy-containers.json") -Encoding utf8

Write-Step "Capture preflight backup for isolated migration rehearsal"
$safeRelease = $releaseVersion -replace '[^a-zA-Z0-9_.-]', '_'
New-BetaStateBackup `
    -Destination $preflightBackupDir `
    -ManifestPath (Join-Path $script:ArtifactDir "preflight-backup-manifest.json") `
    -SafeRelease $safeRelease `
    -Phase "preflight_rehearsal" `
    -WritersStopped $false

Write-Step "Build immutable migration image"
$migrationImage = "elevenid-local/db-migrate:$releaseVersion"
Invoke-Checked -FilePath docker -Arguments @("build", "--file", (Join-Path $script:RepoRoot "services\Dockerfile.migrations"), "--tag", $migrationImage, "--label", "org.opencontainers.image.version=$releaseVersion", "--label", "org.opencontainers.image.revision=$sourceId", $script:WorkspaceRoot)

Write-Step "Rehearse one-way migration on isolated beta copy"
$copySuffix = $sourceId.Substring(0, 12)
$copyContainer = "marty-beta-copy-$copySuffix"
$copyRedisContainer = "marty-beta-copy-redis-$copySuffix"
$copyOpenBaoContainer = "marty-beta-copy-openbao-$copySuffix"
$copyPassword = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
$copyBaoToken = -join ((1..40) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
$rehearsalContainers = @($copyContainer)
if ($EnablePortableCanvas) {
    $rehearsalContainers += @($copyRedisContainer, $copyOpenBaoContainer)
}
try {
    foreach ($candidate in $rehearsalContainers) {
        $existing = docker ps -a --filter "name=^/$candidate$" --format '{{.Names}}'
        if ($existing -and $candidate.StartsWith("marty-beta-copy-")) {
            Invoke-Checked -FilePath docker -Arguments @("rm", "--force", $candidate)
        }
    }
    Invoke-Checked -FilePath docker -Arguments @("run", "--detach", "--name", $copyContainer, "--network", "marty-infra-network", "--env", "POSTGRES_PASSWORD=$copyPassword", "postgres:15-alpine")
    if ($EnablePortableCanvas) {
        Invoke-Checked -FilePath docker -Arguments @("run", "--detach", "--name", $copyRedisContainer, "--network", "marty-infra-network", "redis:7-alpine")
        Invoke-Checked -FilePath docker -Arguments @("run", "--detach", "--name", $copyOpenBaoContainer, "--network", "marty-infra-network", "--env", "BAO_DEV_ROOT_TOKEN_ID=$copyBaoToken", "--env", "BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200", "quay.io/openbao/openbao:2", "server", "-dev")
    }
    $ready = $false
    foreach ($attempt in 1..60) {
        docker exec $copyContainer pg_isready -U postgres | Out-Null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) { throw "Rehearsal PostgreSQL did not become ready" }
    if ($EnablePortableCanvas) {
        $redisReady = $false
        $openBaoReady = $false
        foreach ($attempt in 1..60) {
            docker exec $copyRedisContainer redis-cli ping 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { $redisReady = $true }
            docker exec $copyOpenBaoContainer bao status -address=http://127.0.0.1:8200 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { $openBaoReady = $true }
            if ($redisReady -and $openBaoReady) { break }
            Start-Sleep -Seconds 2
        }
        if (-not $redisReady) { throw "Rehearsal Redis did not become ready" }
        if (-not $openBaoReady) { throw "Rehearsal OpenBao did not become ready" }
    }
    Invoke-Checked -FilePath docker -Arguments @("exec", $copyContainer, "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", "CREATE ROLE marty LOGIN PASSWORD '$copyPassword';")
    Invoke-Checked -FilePath docker -Arguments @("exec", $copyContainer, "createdb", "-U", "postgres", "-O", "marty", "marty")
    Invoke-Checked -FilePath docker -Arguments @("cp", (Join-Path $preflightBackupDir "postgres-marty.dump"), "${copyContainer}:/tmp/marty.dump")
    Invoke-Checked -FilePath docker -Arguments @("exec", $copyContainer, "pg_restore", "-U", "postgres", "-d", "marty", "--no-owner", "--role=marty", "/tmp/marty.dump")
    $copyUrl = "postgresql://marty:$copyPassword@${copyContainer}:5432/marty"
    $rehearsalKmsEnabled = if ($EnablePortableCanvas) { "true" } else { "false" }
    $rehearsalArguments = @(
        "run", "--rm", "--network", "marty-infra-network",
        "--env", "DATABASE_URL=$copyUrl",
        "--env", "PUBLIC_API_URL=$BetaOrigin",
        "--env", "MARTY_MIGRATION_PROFILE=beta",
        "--env", "MARTY_KMS_BOOTSTRAP_ENABLED=$rehearsalKmsEnabled"
    )
    if ($EnablePortableCanvas) {
        $rehearsalArguments += @(
            "--env", "REDIS_URL=redis://${copyRedisContainer}:6379",
            "--env", "BAO_ADDR=http://${copyOpenBaoContainer}:8200",
            "--env", "BAO_TOKEN=$copyBaoToken",
            "--env", "MARTY_ORG_ID=$PilotOrganizationId"
        )
    }
    $rehearsalArguments += @($migrationImage, "python", "/app/run_all_migrations.py")
    Invoke-DockerLogged -Arguments $rehearsalArguments -LogPath (Join-Path $logsDir "migration-rehearsal.log") -FailureMessage "Migration rehearsal failed"
    $verifyArguments = @("run", "--rm", "--network", "marty-infra-network", "--env", "DATABASE_URL=$copyUrl", "--env", "PUBLIC_API_URL=$BetaOrigin", "--env", "MARTY_MIGRATION_PROFILE=beta", "--env", "MARTY_KMS_BOOTSTRAP_ENABLED=false", $migrationImage, "python", "/app/run_all_migrations.py", "--verify-only")
    Invoke-DockerLogged -Arguments $verifyArguments -LogPath (Join-Path $logsDir "migration-rehearsal-verify.log") -FailureMessage "Migration rehearsal verification failed"
}
finally {
    foreach ($expectedContainer in $rehearsalContainers) {
        $candidate = docker ps -a --filter "name=^/$expectedContainer$" --format '{{.Names}}'
        if ($candidate -eq $expectedContainer -and $expectedContainer.StartsWith("marty-beta-copy-")) {
            docker rm --force $expectedContainer | Out-Null
        }
    }
}

Write-Step "Build marker-bearing application images"
$env:MARTY_RELEASE_VERSION = $releaseVersion
$env:MARTY_UI_SHA = $sourceId
Invoke-Compose -Arguments (@("build", "--build-arg", "MARTY_RELEASE_VERSION=$releaseVersion", "--build-arg", "MARTY_UI_SHA=$sourceId") + $script:ApplicationBuildServices)

Write-Step "Build marker-bearing public UI image"
$uiImage = "elevenid-local/ui:$releaseVersion"
Invoke-Checked -FilePath docker -Arguments @("buildx", "build", "--load", "--file", (Join-Path $script:RepoRoot "docker\ui.Dockerfile"), "--build-context", "marty-cli=$(Join-Path $script:WorkspaceRoot 'marty-cli')", "--build-context", "marty-blog=$(Join-Path $script:WorkspaceRoot 'marty-blog')", "--build-arg", "UI_VARIANT=public", "--build-arg", "NGINX_CONFIG=nginx.spa.conf", "--build-arg", "MARTY_RELEASE_VERSION=$releaseVersion", "--build-arg", "MARTY_UI_SHA=$sourceId", "--tag", $uiImage, $script:RepoRoot)

# Builds consume coordinated live worktrees. Revalidate every snapshotted input
# after the final build and before stopping beta writers, so a concurrent edit
# cannot be deployed under the source identity captured at the start of the run.
Write-Step "Reverify coordinated source after image builds"
Invoke-Checked -FilePath python -Arguments @(
    (Join-Path $script:RepoRoot "scripts\create_local_release_manifest.py"),
    "--workspace", $script:WorkspaceRoot,
    "--verify-manifest", $sourceManifestPath
)

Write-Step "Bind runtime evidence marker to the completed image set"
$stackVersion = (Get-Content -LiteralPath (Join-Path $script:RepoRoot "VERSION") -Raw).Trim()
if ($stackVersion -notmatch '^\d{4}\.\d{2}\.\d+$') {
    throw "VERSION must contain an ElevenID LLC platform YYYY.MM.PATCH identifier"
}
$runtimeImageDigests = [ordered]@{}
foreach ($service in $script:ApplicationServices) {
    $imageService = if ($service -eq "canvas-sync-worker") { "issuance" } else { $service }
    $imageRef = "elevenid-local/${imageService}:${releaseVersion}"
    $imageId = docker image inspect $imageRef --format '{{.Id}}'
    if ($LASTEXITCODE -ne 0 -or $imageId -notmatch '^sha256:[0-9a-f]{64}$') {
        throw "Could not resolve immutable image ID for $imageRef"
    }
    $runtimeImageDigests[$service] = $imageId
}
$uiImageId = docker image inspect $uiImage --format '{{.Id}}'
if ($LASTEXITCODE -ne 0 -or $uiImageId -notmatch '^sha256:[0-9a-f]{64}$') {
    throw "Could not resolve immutable image ID for $uiImage"
}
$runtimeImageDigests["ui-prod"] = $uiImageId
$env:ELEVENID_STACK_VERSION = $stackVersion
$env:ELEVENID_IMAGE_DIGESTS_JSON = $runtimeImageDigests | ConvertTo-Json -Compress

Write-Step "Enter maintenance window and apply live migration"
$canvasLtiJwksPath = Join-Path $script:ArtifactDir "canvas-lti-public-jwks.json"
$canvasLtiActiveKidPath = Join-Path $script:ArtifactDir "canvas-lti-active-kid.txt"
$canvasLtiActiveKid = $null
$canvasLtiJwksSha256 = $null
$maintenanceCandidates = $script:ApplicationContainers + $script:InfrastructureWriterContainers + @("marty-ui-prod")
$maintenanceContainers = @($preDeployContainers | Where-Object { $_.running -and $_.container -in $maintenanceCandidates } | ForEach-Object { $_.container })
if ($maintenanceContainers.Count -gt 0) {
    Invoke-Checked -FilePath docker -Arguments (@("stop") + $maintenanceContainers)
}
$liveMutationStarted = $false
try {
    foreach ($container in $maintenanceContainers) {
        $running = docker inspect $container --format '{{.State.Running}}' 2>$null
        if ($LASTEXITCODE -ne 0 -or $running -ne "false") {
            throw "Beta writer did not stop cleanly: $container"
        }
    }

    Write-Step "Capture quiesced maintenance snapshot"
    New-BetaStateBackup `
        -Destination $backupDir `
        -ManifestPath (Join-Path $script:ArtifactDir "backup-manifest.json") `
        -SafeRelease $safeRelease `
        -Phase "maintenance_quiesced" `
        -WritersStopped $true
    $restoreScript = Join-Path $script:RepoRoot "scripts\restore-local-beta-release.ps1"
    "& `"$restoreScript`" -ArtifactDir `"$script:ArtifactDir`" -ConfirmBetaRestore" | Set-Content -LiteralPath (Join-Path $script:ArtifactDir "supervised-recovery.txt") -Encoding utf8

    $env:MARTY_MIGRATION_PROFILE = "beta"
    $env:PUBLIC_API_URL = $BetaOrigin
    $previousBaoToken = $env:BAO_TOKEN
    try {
        if ($EnablePortableCanvas) {
            $env:BAO_TOKEN = if ($env:BAO_DEV_ROOT_TOKEN) { $env:BAO_DEV_ROOT_TOKEN } else { "dev-only-token" }
        }
        $kmsBootstrapEnabled = if ($EnablePortableCanvas) { "true" } else { "false" }
        $migrationArguments = @(
            "run", "--rm", "--network", "marty-infra-network",
            "--env", "DATABASE_URL=postgresql://marty:marty_dev_password@postgres:5432/marty",
            "--env", "PUBLIC_API_URL=$BetaOrigin",
            "--env", "MARTY_MIGRATION_PROFILE=beta",
            "--env", "MARTY_KMS_BOOTSTRAP_ENABLED=$kmsBootstrapEnabled"
        )
        if ($EnablePortableCanvas) {
            $migrationArguments += @(
                "--env", "REDIS_URL=redis://redis:6379",
                "--env", "BAO_ADDR=http://openbao:8200",
                "--env", "BAO_TOKEN",
                "--env", "MARTY_ORG_ID=$PilotOrganizationId"
            )
        }
        $migrationArguments += @($migrationImage, "python", "/app/run_all_migrations.py")
        $liveMutationStarted = $true
        Invoke-DockerLogged -Arguments $migrationArguments -LogPath (Join-Path $logsDir "migration-live.log") -FailureMessage "Live migration failed"
    }
    finally {
        if ($null -eq $previousBaoToken) {
            Remove-Item Env:\BAO_TOKEN -ErrorAction SilentlyContinue
        }
        else {
            $env:BAO_TOKEN = $previousBaoToken
        }
    }

    if ($EnablePortableCanvas) {
        Write-Step "Publish the dedicated OpenBao LTI tool public key"
        $canvasLtiIssuerDid = "did:web:$(([uri]$BetaOrigin).Host):orgs:marty"
        $canvasLtiVerificationMethodId = "$canvasLtiIssuerDid#lti-tool-marty-rs256"
        $openBaoResponsePath = [IO.Path]::GetTempFileName()
        try {
            $openBaoResponse = & docker exec marty-openbao sh -lc 'BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$BAO_DEV_ROOT_TOKEN_ID" bao read -format=json transit/keys/lti-tool-marty-rs256' 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $openBaoResponse) {
                throw "Could not read the dedicated Canvas LTI public key from OpenBao"
            }
            $openBaoResponse -join "`n" | Set-Content -LiteralPath $openBaoResponsePath -Encoding utf8
            Invoke-Checked -FilePath python -Arguments @(
                (Join-Path $script:RepoRoot "scripts\export_canvas_lti_public_jwks.py"),
                "--input", $openBaoResponsePath,
                "--output", $canvasLtiJwksPath,
                "--active-kid-output", $canvasLtiActiveKidPath,
                "--key-name", "lti-tool-marty-rs256",
                "--verification-method-id", $canvasLtiVerificationMethodId
            )
        }
        finally {
            Remove-Item -LiteralPath $openBaoResponsePath -Force -ErrorAction SilentlyContinue
        }

        $canvasLtiActiveKid = (Get-Content -LiteralPath $canvasLtiActiveKidPath -Raw).Trim()
        $canvasLtiPublicJwks = (Get-Content -LiteralPath $canvasLtiJwksPath -Raw).Trim()
        if ($canvasLtiActiveKid -ne $canvasLtiVerificationMethodId) {
            throw "Exported Canvas LTI active kid is invalid"
        }
        $canvasLtiDocument = $canvasLtiPublicJwks | ConvertFrom-Json
        if (-not $canvasLtiDocument.keys -or $canvasLtiActiveKid -notin @($canvasLtiDocument.keys.kid)) {
            throw "Exported Canvas LTI JWKS does not contain its active kid"
        }
        $canvasLtiJwksSha256 = Get-FileSha256 $canvasLtiJwksPath

        $env:CANVAS_LTI_EXPERIENCE_BASE_URL = $BetaOrigin
        $env:CANVAS_OAUTH_COMPLETION_REDIRECT_URL = "$BetaOrigin/console/org/deploy/canvas"
        $env:CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID = $PilotOrganizationId
        $env:CANVAS_LTI_TOOL_ISSUER_PROFILE_ID = "ip-marty-canvas-lti-tool"
        $env:CANVAS_LTI_TOOL_ISSUER_DID = $canvasLtiIssuerDid
        $env:CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS = "ip-marty-vc-jwt-issuer,ip-marty-mdoc-dsc,ip-marty-vdsnc-issuer"
        $env:CANVAS_LTI_TOOL_ACTIVE_KID = $canvasLtiActiveKid
        $env:CANVAS_LTI_TOOL_PUBLIC_JWKS = $canvasLtiPublicJwks
        $env:CANVAS_PORTABLE_INTEGRATION_ENABLED = "true"
        $env:CANVAS_PILOT_ORGANIZATION_IDS = $PilotOrganizationId
        $env:CANVAS_LEGACY_EVENT_INGEST_ENABLED = "false"
        $env:CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST = $CanvasOrigin
        $env:CANVAS_ALLOW_PRIVATE_BASE_URLS = "false"
        $env:CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS = "false"
    }

    if ("marty-keycloak" -in $maintenanceContainers) {
        Invoke-Checked -FilePath docker -Arguments @("start", "marty-keycloak")
        Wait-ForContainerHealth @("marty-keycloak")
    }

    Write-Step "Recreate application containers from coordinated images"
    Invoke-Compose -Arguments (@("up", "--detach", "--no-build", "--no-deps", "--force-recreate") + $script:ApplicationServices)
    Wait-ForContainerHealth $script:ApplicationContainers

    Write-Step "Recreate public UI from immutable image"
    $env:MARTY_UI_RELEASE_IMAGE = $uiImage
    Invoke-Checked -FilePath docker -Arguments @("compose", "-f", (Join-Path $script:RepoRoot "docker-compose.ui-release.yml"), "up", "--detach", "--no-build", "--force-recreate", "ui-prod")
    Wait-ForContainerHealth @("marty-ui-prod")
}
catch {
    if (-not $liveMutationStarted) {
        Start-ContainersBestEffort $maintenanceContainers
        Write-Warning "Deployment failed before live mutation. Previously running beta containers were restarted."
    }
    else {
        Write-Warning "Deployment failed after live mutation began. Run the supervised beta-only command in $script:ArtifactDir\supervised-recovery.txt before resuming service."
    }
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
foreach ($marker in @($servicesMarker, $betaServicesMarker)) {
    if ($marker.stack_version -ne $stackVersion -or $marker.mip_version -ne "0.3.1" -or $marker.deployment_release_marker -ne $releaseVersion) {
        throw "Services runtime marker does not match Stack and MIP provenance"
    }
    foreach ($entry in $runtimeImageDigests.GetEnumerator()) {
        if ($marker.image_digests.($entry.Key) -ne $entry.Value) {
            throw "Services runtime marker image mismatch for $($entry.Key)"
        }
    }
}

$postDeployContainers = Get-ContainerRecords ($script:ApplicationContainers + @("marty-ui-prod"))
$deploymentManifest = [ordered]@{
    schema_version = 1
    release_version = $releaseVersion
    stack_version = $stackVersion
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
    canvas_portable_configuration = [ordered]@{
        enabled = [bool]$EnablePortableCanvas
        canvas_origin = if ($EnablePortableCanvas) { $CanvasOrigin } else { $null }
        pilot_organization_id = if ($EnablePortableCanvas) { $PilotOrganizationId } else { $null }
        lti_issuer_profile_id = if ($EnablePortableCanvas) { "ip-marty-canvas-lti-tool" } else { $null }
        lti_issuer_did = if ($EnablePortableCanvas) { $canvasLtiIssuerDid } else { $null }
        lti_active_kid = $canvasLtiActiveKid
        public_jwks_sha256 = $canvasLtiJwksSha256
        legacy_event_ingest_enabled = $false
    }
    deployed_at = (Get-Date).ToUniversalTime().ToString("o")
}
$deploymentManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $script:ArtifactDir "local-deployment-manifest.json") -Encoding utf8

Write-Step "Local beta deployment complete"
Write-Host "Release: $releaseVersion"
Write-Host "Source ID: $sourceId"
Write-Host "Evidence: $script:ArtifactDir"
