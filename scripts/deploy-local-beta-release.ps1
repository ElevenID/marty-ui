[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDir,

    [string]$BetaOrigin = "https://beta.elevenidllc.com",

    [switch]$EnablePortableCanvas,

    [string]$CanvasOrigin = "https://canvas-test.elevenidllc.com",

    [string]$PilotOrganizationId = "00000000-0000-0000-0000-000000000001",

    [string]$TunnelEnvFile,

    [string]$GeneratedEnvFile,

    [switch]$OfficialStackRelease,

    [string]$RecorderRevision,

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
if ([string]::IsNullOrWhiteSpace($TunnelEnvFile)) {
    $TunnelEnvFile = Join-Path $script:RepoRoot ".env.tunnel.beta.local"
}
if ([string]::IsNullOrWhiteSpace($GeneratedEnvFile)) {
    $GeneratedEnvFile = Join-Path $script:RepoRoot ".env.beta.generated.local"
}
$script:BetaProject = "elevenid-beta"
$script:BetaUiProject = "elevenid-beta-ui"
$script:BetaNetwork = "elevenid-beta-network"
$script:VolumeHelperImage = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
$env:MARTY_NETWORK_NAME = $script:BetaNetwork
$script:EnvFiles = @($TunnelEnvFile, $GeneratedEnvFile)
foreach ($envFile in $script:EnvFiles) {
    if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) { throw "Required beta environment file is missing: $envFile" }
}
$script:ComposeFiles = @(
    (Join-Path $script:RepoRoot "docker-compose.base.yml"),
    (Join-Path $script:RepoRoot "docker-compose.beta.yml"),
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
    "signing-keys",
    "flow",
    "verification",
    "revocation-profile",
    "device-registration",
    "event-stream",
    "issuance",
    "issuance-native",
    "canvas-sync-worker",
    "gateway"
)
$script:ApplicationBuildServices = @(
    $script:ApplicationServices | Where-Object { $_ -notin @("issuance", "canvas-sync-worker") }
)
$script:InfrastructureWriterServices = @("keycloak")

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
    $composeArgs = @("compose", "--project-name", $script:BetaProject)
    foreach ($envFile in $script:EnvFiles) { $composeArgs += @("--env-file", $envFile) }
    foreach ($file in $script:ComposeFiles) {
        $composeArgs += @("-f", $file)
    }
    $composeArgs += $Arguments
    Invoke-Checked -FilePath docker -Arguments $composeArgs
}

function Invoke-VerificationMigration {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^(sha256:[0-9a-f]{64}|[^@\s]+@sha256:[0-9a-f]{64})$')]
        [string]$Image,
        [Parameter(Mandatory = $true)][string]$DatabaseUrl,
        [Parameter(Mandatory = $true)][string]$LogPath
    )
    # The released Rust binary owns schema validation, locking and migration;
    # do not duplicate its SQL or rely on dependencies during --no-deps cutover.
    $previousDatabaseUrl = [Environment]::GetEnvironmentVariable("DATABASE_URL", "Process")
    try {
        $env:DATABASE_URL = $DatabaseUrl
        Invoke-DockerLogged -Arguments @(
            "run", "--rm", "--network", $script:BetaNetwork,
            "--entrypoint", "/usr/local/bin/marty-verification-service",
            "--env", "DATABASE_URL", $Image, "migrate"
        ) -LogPath $LogPath -FailureMessage "Native verification migration failed"
    }
    finally {
        if ($null -eq $previousDatabaseUrl) {
            Remove-Item Env:\DATABASE_URL -ErrorAction SilentlyContinue
        }
        else {
            [Environment]::SetEnvironmentVariable("DATABASE_URL", $previousDatabaseUrl, "Process")
        }
    }
}

function Invoke-ComposeLogged {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )
    $composeArgs = @("compose", "--project-name", $script:BetaProject)
    foreach ($envFile in $script:EnvFiles) { $composeArgs += @("--env-file", $envFile) }
    foreach ($file in $script:ComposeFiles) {
        $composeArgs += @("-f", $file)
    }
    $composeArgs += $Arguments
    Invoke-DockerLogged -Arguments $composeArgs -LogPath $LogPath -FailureMessage $FailureMessage
}

function Get-DotEnvValue([string]$Path, [string]$Name) {
    $line = Get-Content -LiteralPath $Path | Where-Object { $_ -match "^$([regex]::Escape($Name))=" } | Select-Object -Last 1
    if (-not $line) { throw "Required beta setting is absent: $Name" }
    $value = ($line -split "=", 2)[1]
    if ([string]::IsNullOrWhiteSpace($value)) { throw "Required beta setting is empty: $Name" }
    return $value
}

function Get-ComposeContainerId {
    param(
        [Parameter(Mandatory = $true)][string]$Service,
        [switch]$Ui
    )
    if ($Ui) {
        $id = & docker ps -a --filter "label=com.docker.compose.project=$script:BetaUiProject" --filter "label=com.docker.compose.service=$Service" --format '{{.ID}}'
    }
    else {
        $args = @("compose", "--project-name", $script:BetaProject)
        foreach ($envFile in $script:EnvFiles) { $args += @("--env-file", $envFile) }
        foreach ($file in $script:ComposeFiles) { $args += @("-f", $file) }
        $args += @("ps", "--all", "--quiet", $Service)
        $id = & docker @args
    }
    if ($LASTEXITCODE -ne 0) { throw "Could not resolve Compose service: $Service" }
    $ids = @($id | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($ids.Count -gt 1) { throw "Compose service resolved to multiple containers: $Service" }
    if ($ids.Count -eq 1) { return [string]$ids[0] }
    return $null
}

function Assert-BetaVolume([string]$Name) {
    $raw = & docker volume inspect $Name
    if ($LASTEXITCODE -ne 0) { throw "Required beta volume is absent: $Name" }
    $volume = ($raw -join "`n") | ConvertFrom-Json
    if ($volume.Count -ne 1 -or $volume[0].Labels.'com.docker.compose.project' -ne $script:BetaProject) {
        throw "Refusing volume outside $($script:BetaProject): $Name"
    }
    return $Name
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-Utf8Text([string]$Path, [string]$Content) {
    $utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8WithoutBom)
}

function Get-OfficialReleasePlan {
    $manifestPath = Join-Path $script:ArtifactDir "stack-manifest.json"
    $checksumsPath = Join-Path $script:ArtifactDir "SHA256SUMS"
    foreach ($required in @($manifestPath, $checksumsPath)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Official stack release input is missing: $required"
        }
    }
    $output = & python `
        (Join-Path $script:RepoRoot "scripts\prepare_official_beta_release.py") `
        --manifest $manifestPath `
        --checksums $checksumsPath `
        --recorder-revision $RecorderRevision `
        --expected-ui-revision (git -C $script:RepoRoot rev-parse HEAD) 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Official stack release validation failed: $($output -join ' ')"
    }
    try {
        return (($output -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw "Official stack release validator returned invalid JSON"
    }
}

function Assert-OfficialReleaseSource([object]$Plan, [switch]$VerifyAttestation) {
    $head = & git -C $script:RepoRoot rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $head -ne $Plan.marty_ui_sha) {
        throw "Official beta deployment must execute from the released Marty UI commit"
    }
    $status = & git -C $script:RepoRoot status --porcelain=v1 --untracked-files=normal
    if ($LASTEXITCODE -ne 0 -or @($status).Count -ne 0) {
        throw "Official beta deployment requires a clean released Marty UI worktree"
    }
    $tag = "v$($Plan.release_version)"
    $tagType = & git -C $script:RepoRoot cat-file -t "refs/tags/$tag" 2>$null
    $tagCommit = & git -C $script:RepoRoot rev-parse "refs/tags/$tag^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0 -or $tagType -ne "tag" -or $tagCommit -ne $Plan.marty_ui_sha) {
        throw "Official beta deployment requires the exact local annotated release tag"
    }
    $remoteTag = @(& git ls-remote https://github.com/ElevenID/marty-ui.git "refs/tags/$tag" "refs/tags/$tag^{}")
    if ($LASTEXITCODE -ne 0 -or $remoteTag.Count -ne 2) {
        throw "Official beta deployment requires the published annotated release tag"
    }
    $remoteTagRecords = @{}
    foreach ($record in $remoteTag) {
        $parts = $record -split "\s+", 2
        if ($parts.Count -ne 2) { throw "Published release tag response is invalid" }
        $remoteTagRecords[$parts[1]] = $parts[0]
    }
    if ($remoteTagRecords["refs/tags/$tag"] -ne (& git -C $script:RepoRoot rev-parse "refs/tags/$tag") -or
        $remoteTagRecords["refs/tags/$tag^{}"] -ne $Plan.marty_ui_sha) {
        throw "Local and published release tags do not identify the same official source"
    }
    $remoteRecorder = @(& git ls-remote https://github.com/ElevenID/marty-demo-recorder.git refs/heads/main)
    if ($LASTEXITCODE -ne 0 -or $remoteRecorder.Count -ne 1 -or ($remoteRecorder[0] -split "\s+", 2)[0] -ne $RecorderRevision) {
        throw "Recorder revision must match protected marty-demo-recorder main"
    }
    if ($VerifyAttestation) {
        Invoke-Checked -FilePath gh -Arguments @(
            "attestation", "verify", (Join-Path $script:ArtifactDir "stack-manifest.json"),
            "--repo", "ElevenID/marty-ui"
        )
    }
}

function Assert-OfficialImageLabels(
    [string]$Reference,
    [string]$Role,
    [string]$ExpectedVersion,
    [string]$ExpectedRevision
) {
    $version = & docker image inspect $Reference --format '{{index .Config.Labels "org.opencontainers.image.version"}}'
    if ($LASTEXITCODE -ne 0 -or $version -ne $ExpectedVersion) {
        throw "Official $Role image version label does not match the stack release"
    }
    $revision = & docker image inspect $Reference --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
    if ($LASTEXITCODE -ne 0 -or $revision -ne $ExpectedRevision) {
        throw "Official $Role image revision label does not match the stack release"
    }
}

function Initialize-DurableRuntimeConfig([string]$SourceRevision) {
    $commonGitDirOutput = & git -C $script:RepoRoot rev-parse --path-format=absolute --git-common-dir
    if ($LASTEXITCODE -ne 0) {
        throw "Could not resolve the primary marty-ui checkout for durable beta runtime configuration"
    }
    $commonGitDir = [IO.Path]::GetFullPath([string]($commonGitDirOutput | Select-Object -Last 1))
    $primaryCheckoutRoot = Split-Path -Parent $commonGitDir
    $durableArtifactRoot = Join-Path $primaryCheckoutRoot "tests\artifacts\runtime-config"
    New-Item -ItemType Directory -Path $durableArtifactRoot -Force | Out-Null
    $durableArtifactRoot = (Resolve-Path -LiteralPath $durableArtifactRoot).Path

    $runtimeConfigRoot = Join-Path $durableArtifactRoot $SourceRevision
    $stagingRoot = Join-Path $durableArtifactRoot ("{0}.staging.{1}" -f $SourceRevision, [Guid]::NewGuid().ToString("N"))
    $allowedPrefix = $durableArtifactRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    foreach ($candidate in @($runtimeConfigRoot, $stagingRoot)) {
        $absoluteCandidate = [IO.Path]::GetFullPath($candidate)
        if (-not $absoluteCandidate.StartsWith($allowedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Durable runtime configuration must stay under $durableArtifactRoot"
        }
    }

    $runtimeSources = @(
        "docker/init-databases.sh",
        "config/keycloak",
        "scripts/setup-keycloak.sh",
        "docker/openbao-init.sh",
        "config/envoy/envoy.yaml",
        "config/envoy/proto_descriptor.pb",
        "docker/canvas-localhost-bridge/server.py",
        "config/canvas/production-local.rb",
        "config/canvas/dynamic_settings.local.yml",
        "config/canvas/session_store.local.yml",
        "docker/waltid/wallet-api/config",
        "docker/waltid/nginx.conf",
        "nginx-tunnel.conf.template",
        "scripts/nginx-entrypoint.sh"
    )

    New-Item -ItemType Directory -Path $stagingRoot | Out-Null
    try {
        foreach ($relativePath in $runtimeSources) {
            $sourcePath = Join-Path $script:RepoRoot $relativePath
            if (-not (Test-Path -LiteralPath $sourcePath)) {
                throw "Required beta runtime configuration is missing: $relativePath"
            }
            $destinationPath = Join-Path $stagingRoot $relativePath
            New-Item -ItemType Directory -Path (Split-Path -Parent $destinationPath) -Force | Out-Null
            Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Recurse -Force
        }

        $stagingPrefix = $stagingRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        $runtimeFiles = @(Get-ChildItem -LiteralPath $stagingRoot -File -Recurse | Sort-Object FullName | ForEach-Object {
            [ordered]@{
                path = $_.FullName.Substring($stagingPrefix.Length).Replace("\", "/")
                size = $_.Length
                sha256 = Get-FileSha256 $_.FullName
            }
        })
        $runtimeConfigManifest = [ordered]@{
            schema_version = 1
            marty_ui_revision = $SourceRevision
            files = $runtimeFiles
        }
        $stagedManifestPath = Join-Path $stagingRoot "runtime-config-manifest.json"
        Write-Utf8Text -Path $stagedManifestPath -Content (($runtimeConfigManifest | ConvertTo-Json -Depth 5) + "`n")

        if (Test-Path -LiteralPath $runtimeConfigRoot -PathType Container) {
            $existingManifestPath = Join-Path $runtimeConfigRoot "runtime-config-manifest.json"
            if (-not (Test-Path -LiteralPath $existingManifestPath -PathType Leaf) -or
                (Get-FileSha256 $existingManifestPath) -ne (Get-FileSha256 $stagedManifestPath)) {
                throw "Durable runtime configuration conflicts with content-addressed revision $SourceRevision"
            }
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force
        }
        else {
            Move-Item -LiteralPath $stagingRoot -Destination $runtimeConfigRoot
        }
    }
    catch {
        if (Test-Path -LiteralPath $stagingRoot) {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force
        }
        throw
    }

    $script:RuntimeConfigRoot = (Resolve-Path -LiteralPath $runtimeConfigRoot).Path
    $script:RuntimeConfigManifestPath = Join-Path $script:RuntimeConfigRoot "runtime-config-manifest.json"
    $env:MARTY_RUNTIME_CONFIG_ROOT = $script:RuntimeConfigRoot
}

function Wait-ForServiceHealth {
    param([string[]]$Services, [int]$TimeoutSeconds = 420, [switch]$Ui)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $pending = @()
        foreach ($service in $Services) {
            $container = Get-ComposeContainerId -Service $service -Ui:$Ui
            if (-not $container) { $pending += "$service=missing"; continue }
            $state = docker inspect $container --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>$null
            if ($LASTEXITCODE -ne 0 -or $state -notin @("healthy", "running")) {
                $pending += "$service=$state"
            }
        }
        if ($pending.Count -eq 0) {
            return
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "Services did not become healthy: $($pending -join ', ')"
}

function Get-ServiceRecords([string[]]$Services, [switch]$IncludeUi) {
    $records = @()
    $targets = @($Services | ForEach-Object { [ordered]@{ service = $_; ui = $false } })
    if ($IncludeUi) { $targets += [ordered]@{ service = "ui-prod"; ui = $true } }
    foreach ($target in $targets) {
        $container = Get-ComposeContainerId -Service $target.service -Ui:$target.ui
        if (-not $container) { continue }
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
        $rollbackEnvironment = [ordered]@{}
        foreach ($entry in @($inspect.Config.Env)) {
            $parts = $entry -split "=", 2
            if ($parts[0] -in @("MARTY_RELEASE_VERSION", "MARTY_UI_SHA", "ELEVENID_STACK_VERSION", "ELEVENID_COMPONENT_REVISIONS_JSON", "ELEVENID_IMAGE_DIGESTS_JSON")) {
                $markerEnvironment[$parts[0]] = if ($parts.Count -gt 1) { $parts[1] } else { "" }
            }
            if ($parts.Count -gt 1 -and $parts[0] -in @("GRPC_INSECURE_ALLOWED", "ALLOW_PLAINTEXT_GRPC")) {
                $rollbackEnvironment[$parts[0]] = $parts[1]
            }
            if ($parts.Count -gt 1 -and $parts[0] -eq "DATABASE_URL" -and $parts[1] -match '^([a-zA-Z][a-zA-Z0-9+.-]*)://') {
                $rollbackEnvironment["DATABASE_DRIVER"] = $Matches[1]
            }
        }
        $records += [ordered]@{
            container_id = $container
            container = $inspect.Name.TrimStart('/')
            service = $target.service
            configured_image = $inspect.Config.Image
            image_id = $inspect.Image
            status = $inspect.State.Status
            running = [bool]$inspect.State.Running
            started_at = $inspect.State.StartedAt
            health = $health
            compose_project = $inspect.Config.Labels.'com.docker.compose.project'
            compose_service = $inspect.Config.Labels.'com.docker.compose.service'
            runtime_marker_environment = $markerEnvironment
            rollback_environment = $rollbackEnvironment
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
        [Parameter(Mandatory = $true)][bool]$WritersStopped,
        [Parameter(Mandatory = $true)][string]$RedisPassword
    )

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $postgres = Get-ComposeContainerId -Service "postgres"
    $applicant = Get-ComposeContainerId -Service "applicant"
    $redis = Get-ComposeContainerId -Service "redis"
    foreach ($required in @($postgres, $applicant, $redis)) { if (-not $required) { throw "Beta backup requires the running state services" } }
    $applicantVolume = Assert-BetaVolume "elevenid-beta_applicant_data"
    $openBaoVolume = Assert-BetaVolume "elevenid-beta_openbao_data"
    Invoke-Checked -FilePath docker -Arguments @("exec", $postgres, "sh", "-lc", "pg_dump -U postgres -Fc -d marty -f /tmp/$SafeRelease-marty.dump && pg_dump -U postgres -Fc -d keycloak -f /tmp/$SafeRelease-keycloak.dump && pg_dumpall -U postgres --globals-only -f /tmp/$SafeRelease-globals.sql")
    Invoke-Checked -FilePath docker -Arguments @("cp", "${postgres}:/tmp/$SafeRelease-marty.dump", (Join-Path $Destination "postgres-marty.dump"))
    Invoke-Checked -FilePath docker -Arguments @("cp", "${postgres}:/tmp/$SafeRelease-keycloak.dump", (Join-Path $Destination "postgres-keycloak.dump"))
    Invoke-Checked -FilePath docker -Arguments @("cp", "${postgres}:/tmp/$SafeRelease-globals.sql", (Join-Path $Destination "postgres-globals.sql"))
    Invoke-Checked -FilePath docker -Arguments @("run", "--rm", "--mount", "type=volume,src=$applicantVolume,dst=/source,readonly", "--mount", "type=bind,src=$Destination,dst=/backup", $script:VolumeHelperImage, "sh", "-lc", "test -s /source/applicant_store.json && cp /source/applicant_store.json /backup/applicant_store.json")
    $redisSave = & docker exec --env "REDISCLI_AUTH=$RedisPassword" $redis redis-cli SAVE
    $redisSaveLine = [string]($redisSave | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0 -or $redisSaveLine.Trim() -ne "OK") {
        throw "Authenticated beta Redis snapshot failed"
    }
    Invoke-Checked -FilePath docker -Arguments @("cp", "${redis}:/data/dump.rdb", (Join-Path $Destination "redis-dump.rdb"))
    Invoke-Checked -FilePath docker -Arguments @("run", "--rm", "--mount", "type=volume,src=$openBaoVolume,dst=/source,readonly", "--mount", "type=bind,src=$Destination,dst=/backup", $script:VolumeHelperImage, "sh", "-lc", "cd /source && tar -czf /backup/openbao-data.tar.gz .")

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
if ($OfficialStackRelease) {
    if ($RecorderRevision -notmatch '^[0-9a-f]{40}$') {
        throw "OfficialStackRelease requires RecorderRevision as a full lowercase commit SHA"
    }
    $officialPlan = Get-OfficialReleasePlan
    $sourceManifest = $officialPlan.source_manifest
}
else {
    if (-not [string]::IsNullOrWhiteSpace($RecorderRevision)) {
        throw "RecorderRevision is only valid with OfficialStackRelease"
    }
    if (-not (Test-Path -LiteralPath $sourceManifestPath -PathType Leaf)) {
        throw "Missing source manifest: $sourceManifestPath"
    }
    $sourceManifest = Get-Content -LiteralPath $sourceManifestPath -Raw | ConvertFrom-Json
    if ($sourceManifest.schema_version -ne 1 -or $sourceManifest.mip_version -ne "0.5.0") {
        throw "Source manifest is not a supported MIP 0.5.0 local release"
    }
    if ($sourceManifest.source_kind -ne "local-worktree-snapshot" -or $sourceManifest.promotion_eligible -ne $false) {
        throw "Local source manifest must be a non-promotable worktree snapshot"
    }
}
$martyDbPassword = Get-DotEnvValue -Path $GeneratedEnvFile -Name "MARTY_DB_PASSWORD"
$redisPassword = Get-DotEnvValue -Path $GeneratedEnvFile -Name "REDIS_PASSWORD"
$encodedRedisPassword = [Uri]::EscapeDataString($redisPassword)
$baoDevRootToken = Get-DotEnvValue -Path $GeneratedEnvFile -Name "BAO_DEV_ROOT_TOKEN"
$grpcServiceToken = Get-DotEnvValue -Path $GeneratedEnvFile -Name "GRPC_SERVICE_TOKEN"
if ($grpcServiceToken.Length -lt 32 -or $grpcServiceToken -match '^(?i:change[-_]?me|changeme|replace[-_]?me)') {
    throw "GRPC_SERVICE_TOKEN must be a non-placeholder value of at least 32 characters"
}
$requiredFlowSecrets = @(
    "FLOW_WEBHOOK_SECRET",
    "FLOW_APPLICATION_EVENT_HMAC_KEY",
    "ISSUANCE_API_KEY",
    "SIGNING_KEYS_INTERNAL_API_KEY"
)
foreach ($name in $requiredFlowSecrets) {
    $secret = Get-DotEnvValue -Path $GeneratedEnvFile -Name $name
    if ($secret.Length -lt 32 -or $secret -match '^(?i:change[-_]?me|changeme|replace[-_]?me)') {
        throw "$name must be a non-placeholder value of at least 32 characters"
    }
}
$workloadIdentityPathNames = @(
    "MARTY_WORKLOAD_IDENTITY_CA_CERT_FILE",
    "PP_WORKLOAD_SERVER_CERT_FILE",
    "PP_WORKLOAD_SERVER_KEY_FILE",
    "FLOW_WORKLOAD_CLIENT_CERT_FILE",
    "FLOW_WORKLOAD_CLIENT_KEY_FILE",
    "FLOW_WORKLOAD_SERVER_CERT_FILE",
    "FLOW_WORKLOAD_SERVER_KEY_FILE",
    "AUTH_WORKLOAD_CLIENT_CERT_FILE",
    "AUTH_WORKLOAD_CLIENT_KEY_FILE",
    "APPLICANT_WORKLOAD_CLIENT_CERT_FILE",
    "APPLICANT_WORKLOAD_CLIENT_KEY_FILE",
    "VERIFICATION_WORKLOAD_CLIENT_CERT_FILE",
    "VERIFICATION_WORKLOAD_CLIENT_KEY_FILE",
    "DEPLOYMENT_PROFILE_WORKLOAD_CLIENT_CERT_FILE",
    "DEPLOYMENT_PROFILE_WORKLOAD_CLIENT_KEY_FILE",
    "COMPLIANCE_PROFILE_WORKLOAD_CLIENT_CERT_FILE",
    "COMPLIANCE_PROFILE_WORKLOAD_CLIENT_KEY_FILE"
)
$workloadIdentityPaths = @{}
foreach ($name in $workloadIdentityPathNames) {
    $path = Get-DotEnvValue -Path $GeneratedEnvFile -Name $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "$name does not identify a readable workload identity file"
    }
    $workloadIdentityPaths[$name] = (Resolve-Path -LiteralPath $path).Path
}
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw "OpenSSL is required to validate beta workload identity certificates"
}
$workloadCa = $workloadIdentityPaths["MARTY_WORKLOAD_IDENTITY_CA_CERT_FILE"]
$workloadLeafNames = @(
    "PP_WORKLOAD_SERVER_CERT_FILE",
    "FLOW_WORKLOAD_CLIENT_CERT_FILE",
    "FLOW_WORKLOAD_SERVER_CERT_FILE",
    "AUTH_WORKLOAD_CLIENT_CERT_FILE",
    "APPLICANT_WORKLOAD_CLIENT_CERT_FILE",
    "VERIFICATION_WORKLOAD_CLIENT_CERT_FILE",
    "DEPLOYMENT_PROFILE_WORKLOAD_CLIENT_CERT_FILE",
    "COMPLIANCE_PROFILE_WORKLOAD_CLIENT_CERT_FILE"
)
foreach ($name in $workloadLeafNames) {
    $certificate = $workloadIdentityPaths[$name]
    Invoke-Checked -FilePath openssl -Arguments @("x509", "-checkend", "3600", "-noout", "-in", $certificate)
    Invoke-Checked -FilePath openssl -Arguments @("verify", "-CAfile", $workloadCa, $certificate)
}
$repositoryNames = @($sourceManifest.repositories.PSObject.Properties.Name | Sort-Object)
$componentEntries = @($sourceManifest.component_revisions)
$componentNames = @($componentEntries | ForEach-Object { [string]$_.component } | Sort-Object)
if ($repositoryNames.Count -eq 0 -or ($repositoryNames -join "`n") -ne ($componentNames -join "`n")) {
    throw "Source manifest component revisions must cover the exact coordinated repository set"
}
$componentRevisions = [ordered]@{}
foreach ($entry in $componentEntries) {
    $component = [string]$entry.component
    $revision = [string]$entry.revision
    if ($componentRevisions.Contains($component) -or $revision -notmatch '^[0-9a-f]{40}$') {
        throw "Source manifest contains an invalid or duplicate component revision: $component"
    }
    $componentRevisions[$component] = $revision
}

$releaseVersion = [string]$sourceManifest.release_version
$sourceId = [string]$sourceManifest.marty_ui_sha
if ($sourceId -notmatch '^[0-9a-f]{40}$') {
    throw "Source ID must be 40 lowercase hexadecimal characters"
}

$stackLockPath = if ($OfficialStackRelease) {
    Join-Path $script:ArtifactDir "stack-manifest.json"
}
else {
    Join-Path $script:RepoRoot "release\stack-lock.json"
}
$stackLock = Get-Content -LiteralPath $stackLockPath -Raw | ConvertFrom-Json
function Get-StackArtifact([string]$Name, [string]$Type, [string]$SourceRepository) {
    $component = @($stackLock.components | Where-Object name -eq $Name)
    if ($component.Count -ne 1) { throw "Stack lock must contain exactly one $Name component" }
    if ([string]$component[0].commit -notmatch '^[0-9a-f]{40}$') {
        throw "Stack lock component commit is invalid: $Name"
    }
    if (-not [string]::IsNullOrWhiteSpace($SourceRepository)) {
        if (-not $componentRevisions.Contains($SourceRepository)) {
            throw "Source manifest does not contain the stack component repository: $SourceRepository"
        }
        if ([string]$component[0].commit -ne [string]$componentRevisions[$SourceRepository]) {
            throw "Stack lock $Name commit must match source manifest repository $SourceRepository"
        }
    }
    $artifact = @($component[0].artifacts | Where-Object type -eq $Type)
    if ($artifact.Count -ne 1 -or $artifact[0].digest -notmatch '^sha256:[0-9a-f]{64}$' -or -not $artifact[0].uri) {
        throw "Stack lock artifact is incomplete: $Name/$Type"
    }
    return [pscustomobject]@{
        Version = [string]$component[0].version
        Commit = [string]$component[0].commit
        Uri = [string]$artifact[0].uri
        Digest = [string]$artifact[0].digest
    }
}
$martyCommon = Get-StackArtifact "marty-common" "python"
$martyRs = Get-StackArtifact "marty-core-python" "python" "marty-core"
$martyVerification = Get-StackArtifact "marty-verification-python" "python" "marty-core"
$martyIso18013 = Get-StackArtifact "marty-iso18013-python" "python" "marty-core"
$martyApiCore = Get-StackArtifact "marty-api-core" "npm" "marty-cli"
$martyBlog = Get-StackArtifact "marty-blog" "npm" "marty-blog"
$martyIssuance = Get-StackArtifact "marty-credentials-issuance" "oci" "marty-credentials"

$backupDir = Join-Path $script:ArtifactDir "backup"
$preflightBackupDir = Join-Path $script:ArtifactDir "preflight-backup"
$logsDir = Join-Path $script:ArtifactDir "logs"
$sourceKind = [string]$sourceManifest.source_kind
$promotionEligible = [bool]$sourceManifest.promotion_eligible
$releaseInput = if ($OfficialStackRelease) { "official attested stack release" } else { "local coordinated worktree snapshot" }
$plannedImageStep = if ($OfficialStackRelease) { "pull and verify digest-only official images" } else { "build migration, application, and UI images" }

Write-Step "Beta release plan"
Write-Host "Release: $releaseVersion"
Write-Host "Source ID: $sourceId"
Write-Host "Source kind: $sourceKind"
Write-Host "Release input: $releaseInput"
Write-Host "Origin: $BetaOrigin"
Write-Host "Artifact directory: $script:ArtifactDir"
Write-Host "Promotion eligible: $promotionEligible"
Write-Host "Portable Canvas enabled: $([bool]$EnablePortableCanvas)"
Write-Host "Compose project: $script:BetaProject"
Write-Host "UI Compose project: $script:BetaUiProject"
Write-Host "Network: $script:BetaNetwork"

if ($PlanOnly) {
    [ordered]@{
        release_version = $releaseVersion
        marty_ui_sha = $sourceId
        source_kind = $sourceKind
        release_input = $releaseInput
        promotion_eligible = $promotionEligible
        beta_origin = $BetaOrigin
        portable_canvas_enabled = [bool]$EnablePortableCanvas
        canvas_origin = if ($EnablePortableCanvas) { $CanvasOrigin } else { $null }
        pilot_organization_id = if ($EnablePortableCanvas) { $PilotOrganizationId } else { $null }
        compose_project = $script:BetaProject
        ui_compose_project = $script:BetaUiProject
        network = $script:BetaNetwork
        application_services = $script:ApplicationServices
        steps = @(
            "backup",
            $plannedImageStep,
            "isolated beta-copy rehearsal",
            "maintenance stop",
            "live migration",
            "atomic application/UI recreation",
            "local and tunneled marker verification"
        )
    } | ConvertTo-Json -Depth 5
    exit 0
}

New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
if ($OfficialStackRelease) {
    Write-Utf8Text -Path $sourceManifestPath -Content (($sourceManifest | ConvertTo-Json -Depth 8) + "`n")
}
$releaseComposeFile = Join-Path $script:ArtifactDir "local-release-images.yml"
$releaseCompose = @("services:")
foreach ($service in $script:ApplicationServices) {
    $releaseCompose += "  ${service}:"
    if ($service -in @("issuance", "canvas-sync-worker")) {
        $releaseCompose += '    image: ${MARTY_ISSUANCE_IMAGE}'
    }
    elseif ($OfficialStackRelease) {
        $releaseCompose += '    image: ${MARTY_SERVICES_IMAGE}'
        $runtimeServiceName = $service -replace '-', '_'
        $releaseCompose += "    environment:"
        $releaseCompose += "      SERVICE_NAME: $runtimeServiceName"
    }
    else {
        $releaseCompose += "    image: elevenid-local/${service}:${releaseVersion}"
    }
}
$releaseCompose -join "`n" | Set-Content -LiteralPath $releaseComposeFile -Encoding utf8
$script:ComposeFiles += $releaseComposeFile

if ($OfficialStackRelease) {
    Write-Step "Verify official release source, protected recorder, and artifact attestation"
    Assert-OfficialReleaseSource -Plan $officialPlan -VerifyAttestation
}
else {
    Write-Step "Verify immutable source snapshot and worktree"
    Invoke-Checked -FilePath python -Arguments @(
        (Join-Path $script:RepoRoot "scripts\create_local_release_manifest.py"),
        "--workspace", $script:WorkspaceRoot,
        "--verify-manifest", $sourceManifestPath
    )
}

Write-Step "Stage durable source-pinned beta runtime configuration"
Initialize-DurableRuntimeConfig -SourceRevision $sourceId
Write-Host "Runtime configuration: $script:RuntimeConfigRoot"

Write-Step "Preflight running beta topology"
Invoke-Checked -FilePath docker -Arguments @("info", "--format", "{{.ServerVersion}}")
$env:MARTY_COMMON_URI = $martyCommon.Uri
$env:MARTY_COMMON_DIGEST = $martyCommon.Digest
$env:MARTY_RS_URI = $martyRs.Uri
$env:MARTY_RS_DIGEST = $martyRs.Digest
$env:MARTY_VERIFICATION_URI = $martyVerification.Uri
$env:MARTY_VERIFICATION_DIGEST = $martyVerification.Digest
$env:MARTY_ISO18013_URI = $martyIso18013.Uri
$env:MARTY_ISO18013_DIGEST = $martyIso18013.Digest
$env:MARTY_ISSUANCE_IMAGE = "$($martyIssuance.Uri)@$($martyIssuance.Digest)"
if ($OfficialStackRelease) {
    $env:MARTY_SERVICES_IMAGE = [string]$officialPlan.images.services.reference
    $migrationImage = [string]$officialPlan.images.migrations.reference
    $uiImage = [string]$officialPlan.images.ui.reference
    foreach ($image in @($env:MARTY_SERVICES_IMAGE, $migrationImage, $uiImage, $env:MARTY_ISSUANCE_IMAGE)) {
        Invoke-Checked -FilePath docker -Arguments @("pull", $image)
    }
    Assert-OfficialImageLabels -Reference $env:MARTY_SERVICES_IMAGE -Role "services" -ExpectedVersion $releaseVersion -ExpectedRevision $sourceId
    Assert-OfficialImageLabels -Reference $migrationImage -Role "migrations" -ExpectedVersion $releaseVersion -ExpectedRevision $sourceId
    Assert-OfficialImageLabels -Reference $uiImage -Role "UI" -ExpectedVersion $releaseVersion -ExpectedRevision $sourceId
    Assert-OfficialImageLabels -Reference $env:MARTY_ISSUANCE_IMAGE -Role "issuance" -ExpectedVersion "v$($martyIssuance.Version)" -ExpectedRevision $martyIssuance.Commit
}
else {
    Invoke-Checked -FilePath docker -Arguments @("pull", $env:MARTY_ISSUANCE_IMAGE)
}
$docsIds = @(& docker ps -a --filter "label=com.docker.compose.project=$script:BetaProject" --filter "label=com.docker.compose.service=docs" --format '{{.ID}}')
if ($LASTEXITCODE -ne 0 -or $docsIds.Count -ne 1) { throw "Expected one existing beta docs container" }
$env:MARTY_DOCS_IMAGE = & docker inspect $docsIds[0] --format '{{.Config.Image}}'
if ($LASTEXITCODE -ne 0 -or $env:MARTY_DOCS_IMAGE -notmatch '^sha256:[0-9a-f]{64}$') {
    throw "Existing beta docs image is not immutable"
}
foreach ($service in @("postgres", "redis", "openbao", "keycloak", "applicant", "gateway")) {
    $container = Get-ComposeContainerId -Service $service
    if (-not $container) { throw "Required beta service is absent: $service" }
    Invoke-Checked -FilePath docker -Arguments @("inspect", $container, "--format", "{{.State.Status}}")
}
$uiContainer = Get-ComposeContainerId -Service "ui-prod" -Ui
if (-not $uiContainer) { throw "Required beta UI service is absent" }
Invoke-Checked -FilePath docker -Arguments @("inspect", $uiContainer, "--format", "{{.State.Status}}")

$preDeployContainers = Get-ServiceRecords ($script:ApplicationServices + $script:InfrastructureWriterServices) -IncludeUi
$preDeployContainers | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $script:ArtifactDir "pre-deploy-containers.json") -Encoding utf8

Write-Step "Capture preflight backup for isolated migration rehearsal"
$safeRelease = $releaseVersion -replace '[^a-zA-Z0-9_.-]', '_'
New-BetaStateBackup `
    -Destination $preflightBackupDir `
    -ManifestPath (Join-Path $script:ArtifactDir "preflight-backup-manifest.json") `
    -SafeRelease $safeRelease `
    -Phase "preflight_rehearsal" `
    -WritersStopped $false `
    -RedisPassword $redisPassword

if (-not $OfficialStackRelease) {
    Write-Step "Build immutable migration image"
    $migrationImage = "elevenid-local/db-migrate:$releaseVersion"
    Invoke-Checked -FilePath docker -Arguments @(
        "build", "--file", (Join-Path $script:RepoRoot "services\Dockerfile.migrations"),
        "--build-arg", "MARTY_RELEASE_VERSION=$releaseVersion", "--build-arg", "MARTY_UI_SHA=$sourceId",
        "--build-arg", "MARTY_COMMON_VERSION=$($martyCommon.Version)", "--build-arg", "MARTY_COMMON_URI=$($martyCommon.Uri)",
        "--build-arg", "MARTY_COMMON_DIGEST=$($martyCommon.Digest)",
        "--build-arg", "MARTY_RS_VERSION=$($martyRs.Version)", "--build-arg", "MARTY_RS_URI=$($martyRs.Uri)",
        "--build-arg", "MARTY_RS_DIGEST=$($martyRs.Digest)",
        "--build-arg", "MARTY_VERIFICATION_VERSION=$($martyVerification.Version)", "--build-arg", "MARTY_VERIFICATION_URI=$($martyVerification.Uri)",
        "--build-arg", "MARTY_VERIFICATION_DIGEST=$($martyVerification.Digest)",
        "--build-arg", "MARTY_ISO18013_VERSION=$($martyIso18013.Version)", "--build-arg", "MARTY_ISO18013_URI=$($martyIso18013.Uri)",
        "--build-arg", "MARTY_ISO18013_DIGEST=$($martyIso18013.Digest)",
        "--tag", $migrationImage, "--label", "org.opencontainers.image.version=$releaseVersion",
        "--label", "org.opencontainers.image.revision=$sourceId", $script:RepoRoot
    )
}

$env:MARTY_RELEASE_VERSION = $releaseVersion
$env:MARTY_UI_SHA = $sourceId
if (-not $OfficialStackRelease) {
    Write-Step "Build marker-bearing application images"
    $applicationBuildArguments = @(
        "build", "--build-arg", "MARTY_RELEASE_VERSION=$releaseVersion", "--build-arg", "MARTY_UI_SHA=$sourceId"
    )
    # Build serially before rehearsal so the actual local verifier runtime,
    # not a separately built migration artifact, owns the rehearsal schema.
    foreach ($service in $script:ApplicationBuildServices) {
        Write-Host "Building release image: $service"
        Invoke-Compose -Arguments ($applicationBuildArguments + @($service))
    }
}

if ($OfficialStackRelease) {
    $verificationMigrationImage = $env:MARTY_SERVICES_IMAGE
}
else {
    $verificationMigrationImage = & docker image inspect "elevenid-local/verification:$releaseVersion" --format '{{.Id}}'
    if ($LASTEXITCODE -ne 0 -or $verificationMigrationImage -notmatch '^sha256:[0-9a-f]{64}$') {
        throw "Could not pin the local verification runtime image before rehearsal"
    }
    # Keep the exact rehearsed local image even if another process retags it.
    $verificationImageOverride = Join-Path $script:ArtifactDir "verification-runtime-image.yml"
    Write-Utf8Text -Path $verificationImageOverride -Content "services:`n  verification:`n    image: $verificationMigrationImage`n"
    $script:ComposeFiles += $verificationImageOverride
}

Write-Step "Rehearse one-way migration on isolated beta copy"
$copySuffix = $sourceId.Substring(0, 12)
$copyContainer = "elevenid-beta-copy-$copySuffix"
$copyRedisContainer = "elevenid-beta-copy-redis-$copySuffix"
$copyOpenBaoContainer = "elevenid-beta-copy-openbao-$copySuffix"
$copyPassword = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
$copyRedisPassword = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
$encodedCopyRedisPassword = [Uri]::EscapeDataString($copyRedisPassword)
$copyBaoToken = -join ((1..40) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
$rehearsalContainers = @($copyContainer, $copyOpenBaoContainer, $copyRedisContainer)
try {
    foreach ($candidate in $rehearsalContainers) {
        $existing = docker ps -a --filter "name=^/$candidate$" --format '{{.Names}}'
        if ($existing -and $candidate.StartsWith("elevenid-beta-copy-")) {
            Invoke-Checked -FilePath docker -Arguments @("rm", "--force", $candidate)
        }
    }
    Invoke-Checked -FilePath docker -Arguments @("run", "--detach", "--name", $copyContainer, "--network", $script:BetaNetwork, "--env", "POSTGRES_PASSWORD=$copyPassword", "postgres:15-alpine")
    Invoke-Checked -FilePath docker -Arguments @("run", "--detach", "--name", $copyOpenBaoContainer, "--network", $script:BetaNetwork, "--env", "BAO_DEV_ROOT_TOKEN_ID=$copyBaoToken", "--env", "BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200", "quay.io/openbao/openbao:2", "server", "-dev")
    Invoke-Checked -FilePath docker -Arguments @(
        "run", "--detach", "--name", $copyRedisContainer, "--network", $script:BetaNetwork,
        "redis:7-alpine", "redis-server", "--requirepass", $copyRedisPassword
    )
    $ready = $false
    foreach ($attempt in 1..60) {
        docker exec $copyContainer pg_isready -U postgres | Out-Null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) { throw "Rehearsal PostgreSQL did not become ready" }
    $redisReady = $false
    $openBaoReady = $false
    foreach ($attempt in 1..60) {
        $redisPing = docker exec $copyRedisContainer redis-cli --no-auth-warning -a $copyRedisPassword ping 2>$null
        if ($LASTEXITCODE -eq 0 -and $redisPing -eq "PONG") { $redisReady = $true }
        docker exec $copyOpenBaoContainer bao status -address=http://127.0.0.1:8200 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $openBaoReady = $true }
        if ($redisReady -and $openBaoReady) { break }
        Start-Sleep -Seconds 2
    }
    if (-not $redisReady) { throw "Rehearsal Redis did not become ready" }
    if (-not $openBaoReady) { throw "Rehearsal OpenBao did not become ready" }
    Invoke-Checked -FilePath docker -Arguments @("exec", $copyContainer, "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", "CREATE ROLE marty LOGIN PASSWORD '$copyPassword';")
    Invoke-Checked -FilePath docker -Arguments @("exec", $copyContainer, "createdb", "-U", "postgres", "-O", "marty", "marty")
    Invoke-Checked -FilePath docker -Arguments @("cp", (Join-Path $preflightBackupDir "postgres-marty.dump"), "${copyContainer}:/tmp/marty.dump")
    Invoke-Checked -FilePath docker -Arguments @("exec", $copyContainer, "pg_restore", "-U", "postgres", "-d", "marty", "--no-owner", "--role=marty", "/tmp/marty.dump")
    $copyUrl = "postgresql://marty:$copyPassword@${copyContainer}:5432/marty"
    $rehearsalArguments = @(
        "run", "--rm", "--network", $script:BetaNetwork,
        "--env", "DATABASE_URL=$copyUrl",
        "--env", "PUBLIC_API_URL=$BetaOrigin",
        "--env", "MARTY_MIGRATION_PROFILE=beta",
        "--env", "MARTY_KMS_BOOTSTRAP_ENABLED=true",
        "--env", "BAO_ADDR=http://${copyOpenBaoContainer}:8200",
        "--env", "BAO_TOKEN=$copyBaoToken",
        "--env", "REDIS_URL=redis://:${encodedCopyRedisPassword}@${copyRedisContainer}:6379",
        "--env", "MARTY_ORG_ID=$PilotOrganizationId"
    )
    $rehearsalArguments += @($migrationImage, "python", "/app/services/run_all_migrations.py")
    Invoke-DockerLogged -Arguments $rehearsalArguments -LogPath (Join-Path $logsDir "migration-rehearsal.log") -FailureMessage "Migration rehearsal failed"
    $verifyArguments = @("run", "--rm", "--network", $script:BetaNetwork, "--env", "DATABASE_URL=$copyUrl", "--env", "PUBLIC_API_URL=$BetaOrigin", "--env", "MARTY_MIGRATION_PROFILE=beta", "--env", "MARTY_KMS_BOOTSTRAP_ENABLED=false", $migrationImage, "python", "/app/services/run_all_migrations.py", "--verify-only")
    Invoke-DockerLogged -Arguments $verifyArguments -LogPath (Join-Path $logsDir "migration-rehearsal-verify.log") -FailureMessage "Migration rehearsal verification failed"
    $copyIssuanceUrl = "postgresql+asyncpg://marty:$copyPassword@${copyContainer}:5432/marty"
    Invoke-ComposeLogged `
        -Arguments @("run", "--rm", "--no-deps", "--env", "DATABASE_URL=$copyIssuanceUrl", "issuance-migrations") `
        -LogPath (Join-Path $logsDir "issuance-migration-rehearsal.log") `
        -FailureMessage "Issuance migration rehearsal failed"
    Invoke-ComposeLogged `
        -Arguments @("run", "--rm", "--no-deps", "--env", "DATABASE_URL=$copyIssuanceUrl", "issuance-migrations", "python", "manage_migrations.py", "current") `
        -LogPath (Join-Path $logsDir "issuance-migration-rehearsal-verify.log") `
        -FailureMessage "Issuance migration rehearsal verification failed"
    foreach ($verificationPass in 1..2) {
        Invoke-VerificationMigration -Image $verificationMigrationImage -DatabaseUrl $copyUrl `
            -LogPath (Join-Path $logsDir "verification-migration-rehearsal-$verificationPass.log")
    }
}
finally {
    foreach ($expectedContainer in $rehearsalContainers) {
        $candidate = docker ps -a --filter "name=^/$expectedContainer$" --format '{{.Names}}'
        if ($candidate -eq $expectedContainer -and $expectedContainer.StartsWith("elevenid-beta-copy-")) {
            docker rm --force $expectedContainer | Out-Null
        }
    }
}

if (-not $OfficialStackRelease) {
    Write-Step "Build marker-bearing public UI image"
    $uiImage = "elevenid-local/ui:$releaseVersion"
    Invoke-Checked -FilePath docker -Arguments @(
        "buildx", "build", "--load", "--file", (Join-Path $script:RepoRoot "docker\ui.Dockerfile"),
        "--build-arg", "UI_VARIANT=public", "--build-arg", "NGINX_CONFIG=nginx.spa.conf",
        "--build-arg", "MARTY_RELEASE_VERSION=$releaseVersion", "--build-arg", "MARTY_UI_SHA=$sourceId",
        "--build-arg", "MARTY_API_CORE_VERSION=$($martyApiCore.Version)", "--build-arg", "MARTY_API_CORE_URI=$($martyApiCore.Uri)",
        "--build-arg", "MARTY_API_CORE_DIGEST=$($martyApiCore.Digest)", "--build-arg", "MARTY_BLOG_VERSION=$($martyBlog.Version)",
        "--build-arg", "MARTY_BLOG_URI=$($martyBlog.Uri)", "--build-arg", "MARTY_BLOG_DIGEST=$($martyBlog.Digest)",
        "--tag", $uiImage, $script:RepoRoot
    )
}

Write-Step "Verify public UI image homepage content"
$uiRootHtml = @(docker run --rm --entrypoint cat $uiImage /usr/share/nginx/html/index.html)
if ($LASTEXITCODE -ne 0) {
    throw "Could not read the public UI homepage from $uiImage"
}
$uiRootText = $uiRootHtml -join "`n"
if ($uiRootText -notmatch "ElevenID" -or $uiRootText -match "Welcome to nginx") {
    throw "Public UI image homepage failed the ElevenID content contract"
}

# Revalidate the selected release input before stopping beta writers, so a
# concurrent change cannot be deployed under the source identity captured at
# the start of the run.
if ($OfficialStackRelease) {
    Write-Step "Reverify official source and release inputs before maintenance"
    $revalidatedPlan = Get-OfficialReleasePlan
    if (($revalidatedPlan | ConvertTo-Json -Depth 10 -Compress) -ne ($officialPlan | ConvertTo-Json -Depth 10 -Compress)) {
        throw "Official release inputs changed during deployment preparation"
    }
    Assert-OfficialReleaseSource -Plan $officialPlan
}
else {
    Write-Step "Reverify coordinated source after image builds"
    Invoke-Checked -FilePath python -Arguments @(
        (Join-Path $script:RepoRoot "scripts\create_local_release_manifest.py"),
        "--workspace", $script:WorkspaceRoot,
        "--verify-manifest", $sourceManifestPath
    )
}

Write-Step "Bind runtime evidence marker to the completed image set"
$stackVersion = (Get-Content -LiteralPath (Join-Path $script:RepoRoot "VERSION") -Raw).Trim()
if ($stackVersion -notmatch '^\d{4}\.\d{2}\.\d+$') {
    throw "VERSION must contain an ElevenID LLC platform YYYY.MM.PATCH identifier"
}
$runtimeImageDigests = [ordered]@{}
foreach ($service in $script:ApplicationServices) {
    if ($OfficialStackRelease) {
        $runtimeImageDigests[$service] = if ($service -in @("issuance", "canvas-sync-worker")) {
            [string]$officialPlan.images.issuance.digest
        }
        else {
            [string]$officialPlan.images.services.digest
        }
    }
    else {
        $imageRef = if ($service -in @("issuance", "canvas-sync-worker")) {
            $env:MARTY_ISSUANCE_IMAGE
        }
        else {
            "elevenid-local/${service}:${releaseVersion}"
        }
        $imageId = docker image inspect $imageRef --format '{{.Id}}'
        if ($LASTEXITCODE -ne 0 -or $imageId -notmatch '^sha256:[0-9a-f]{64}$') {
            throw "Could not resolve immutable image ID for $imageRef"
        }
        $runtimeImageDigests[$service] = $imageId
    }
}
if ($OfficialStackRelease) {
    $runtimeImageDigests["ui-prod"] = [string]$officialPlan.images.ui.digest
}
else {
    $uiImageId = docker image inspect $uiImage --format '{{.Id}}'
    if ($LASTEXITCODE -ne 0 -or $uiImageId -notmatch '^sha256:[0-9a-f]{64}$') {
        throw "Could not resolve immutable image ID for $uiImage"
    }
    $runtimeImageDigests["ui-prod"] = $uiImageId
}
$env:ELEVENID_STACK_VERSION = $stackVersion
$env:ELEVENID_COMPONENT_REVISIONS_JSON = $componentRevisions | ConvertTo-Json -Compress
$env:ELEVENID_IMAGE_DIGESTS_JSON = $runtimeImageDigests | ConvertTo-Json -Compress
$imageDigestsPath = Join-Path $script:ArtifactDir "image-digests.json"
Write-Utf8Text -Path $imageDigestsPath -Content ($env:ELEVENID_IMAGE_DIGESTS_JSON + "`n")

Write-Step "Enter maintenance window and apply live migration"
$canvasLtiIssuerDid = $null
$maintenanceServices = $script:ApplicationServices + $script:InfrastructureWriterServices + @("ui-prod")
$maintenanceContainers = @($preDeployContainers | Where-Object { $_.running -and $_.service -in $maintenanceServices } | ForEach-Object { $_.container_id })
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
        -WritersStopped $true `
        -RedisPassword $redisPassword
    $restoreScript = Join-Path $script:RepoRoot "scripts\restore-local-beta-release.ps1"
    "& `"$restoreScript`" -ArtifactDir `"$script:ArtifactDir`" -TunnelEnvFile `"$TunnelEnvFile`" -GeneratedEnvFile `"$GeneratedEnvFile`" -ConfirmBetaRestore" | Set-Content -LiteralPath (Join-Path $script:ArtifactDir "supervised-recovery.txt") -Encoding utf8

    Write-Step "Reconcile beta OpenBao state from release configuration"
    Invoke-ComposeLogged `
        -Arguments @("run", "--rm", "--no-deps", "openbao-init") `
        -LogPath (Join-Path $logsDir "openbao-init-live.log") `
        -FailureMessage "Beta OpenBao reconciliation failed"

    $env:MARTY_MIGRATION_PROFILE = "beta"
    $env:PUBLIC_API_URL = $BetaOrigin
    $previousBaoToken = $env:BAO_TOKEN
    try {
        $env:BAO_TOKEN = $baoDevRootToken
        $migrationArguments = @(
            "run", "--rm", "--network", $script:BetaNetwork,
            "--env", "DATABASE_URL=postgresql://marty:${martyDbPassword}@postgres:5432/marty",
            "--env", "PUBLIC_API_URL=$BetaOrigin",
            "--env", "MARTY_MIGRATION_PROFILE=beta",
            "--env", "MARTY_KMS_BOOTSTRAP_ENABLED=true",
            "--env", "BAO_ADDR=http://openbao:8200",
            "--env", "BAO_TOKEN",
            "--env", "REDIS_URL=redis://:${encodedRedisPassword}@redis:6379",
            "--env", "MARTY_ORG_ID=$PilotOrganizationId"
        )
        $migrationArguments += @($migrationImage, "python", "/app/services/run_all_migrations.py")
        $liveMutationStarted = $true
        Invoke-DockerLogged -Arguments $migrationArguments -LogPath (Join-Path $logsDir "migration-live.log") -FailureMessage "Live migration failed"
        $liveIssuanceUrl = "postgresql+asyncpg://marty:${martyDbPassword}@postgres:5432/marty"
        Invoke-ComposeLogged `
            -Arguments @("run", "--rm", "--no-deps", "--env", "DATABASE_URL=$liveIssuanceUrl", "issuance-migrations") `
            -LogPath (Join-Path $logsDir "issuance-migration-live.log") `
            -FailureMessage "Live issuance migration failed"
        Invoke-ComposeLogged `
            -Arguments @("run", "--rm", "--no-deps", "--env", "DATABASE_URL=$liveIssuanceUrl", "issuance-migrations", "python", "manage_migrations.py", "current") `
            -LogPath (Join-Path $logsDir "issuance-migration-live-verify.log") `
            -FailureMessage "Live issuance migration verification failed"
        Invoke-VerificationMigration -Image $verificationMigrationImage `
            -DatabaseUrl "postgresql://marty:${martyDbPassword}@postgres:5432/marty" `
            -LogPath (Join-Path $logsDir "verification-migration-live.log")
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
        Write-Step "Bind Canvas LTI signing to the seeded issuer DID"
        $betaHost = ([Uri]$BetaOrigin).DnsSafeHost
        $canvasLtiIssuerDid = "did:web:${betaHost}:orgs:marty"
        $env:CANVAS_LTI_EXPERIENCE_BASE_URL = $BetaOrigin
        $env:CANVAS_OAUTH_COMPLETION_REDIRECT_URL = "$BetaOrigin/console/org/deploy/canvas"
        $env:CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID = $PilotOrganizationId
        $env:CANVAS_LTI_TOOL_ISSUER_DID = $canvasLtiIssuerDid
        $env:CANVAS_PORTABLE_INTEGRATION_ENABLED = "true"
        $env:CANVAS_PILOT_ORGANIZATION_IDS = $PilotOrganizationId
        $env:CANVAS_LEGACY_EVENT_INGEST_ENABLED = "false"
        $env:CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST = $CanvasOrigin
        $env:CANVAS_ALLOW_PRIVATE_BASE_URLS = "false"
        $env:CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS = "false"
    }

    Write-Step "Recreate infrastructure writers from release configuration"
    Invoke-Compose -Arguments (@("up", "--detach", "--no-build", "--no-deps", "--force-recreate") + $script:InfrastructureWriterServices)
    Wait-ForServiceHealth $script:InfrastructureWriterServices

    Write-Step "Recreate application containers from coordinated images"
    Invoke-Compose -Arguments (@("up", "--detach", "--no-build", "--no-deps", "--force-recreate") + $script:ApplicationServices)
    Wait-ForServiceHealth $script:ApplicationServices

    Write-Step "Recreate public UI from immutable image"
    $env:MARTY_UI_RELEASE_IMAGE = $uiImage
    $uiComposeArguments = @("compose", "--project-name", $script:BetaUiProject)
    foreach ($envFile in $script:EnvFiles) { $uiComposeArguments += @("--env-file", $envFile) }
    $uiComposeArguments += @("-f", (Join-Path $script:RepoRoot "docker-compose.ui-release.yml"), "up", "--detach", "--no-build", "--force-recreate", "ui-prod")
    Invoke-Checked -FilePath docker -Arguments $uiComposeArguments
    Wait-ForServiceHealth @("ui-prod") -Ui
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
$nativeIssuanceContainer = Get-ComposeContainerId -Service "issuance-native"
if (-not $nativeIssuanceContainer) { throw "Native issuance beta container is absent" }
$nativeIssuanceVersionRaw = & docker exec $nativeIssuanceContainer curl --fail --silent --show-error http://127.0.0.1:8005/version
if ($LASTEXITCODE -ne 0) { throw "Native issuance version probe failed" }
$nativeIssuanceMarker = $nativeIssuanceVersionRaw | ConvertFrom-Json
if ($nativeIssuanceMarker.service -ne "issuance-service" -or $nativeIssuanceMarker.version -ne $releaseVersion -or $nativeIssuanceMarker.build_revision -ne $sourceId) {
    throw "Native issuance runtime marker does not match local release provenance"
}
$localIssuerMetadata = Invoke-RestMethod -Uri "http://127.0.0.1:8000/.well-known/openid-credential-issuer" -TimeoutSec 30
$betaIssuerMetadata = Invoke-RestMethod -Uri "$BetaOrigin/.well-known/openid-credential-issuer" -Headers @{ "Cache-Control" = "no-cache" } -TimeoutSec 30
foreach ($metadata in @($localIssuerMetadata, $betaIssuerMetadata)) {
    if (-not $metadata.credential_issuer -or -not $metadata.credential_endpoint -or -not $metadata.nonce_endpoint) {
        throw "Native issuance discovery probe returned incomplete metadata"
    }
}
$localNonce = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/v1/issuance/nonce" -ContentType "application/json" -Body "{}" -TimeoutSec 30
$betaNonce = Invoke-RestMethod -Method Post -Uri "$BetaOrigin/v1/issuance/nonce" -Headers @{ "Cache-Control" = "no-cache" } -ContentType "application/json" -Body "{}" -TimeoutSec 30
foreach ($nonce in @($localNonce, $betaNonce)) {
    if ($nonce.c_nonce -notmatch '^[A-Za-z0-9_-]{43}$') {
        throw "Native issuance nonce probe violated the frozen response contract"
    }
}
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
    if ($marker.stack_version -ne $stackVersion -or $marker.mip_version -ne "0.5.0" -or $marker.deployment_release_marker -ne $releaseVersion) {
        throw "Services runtime marker does not match Stack and MIP provenance"
    }
    $observedComponentNames = @($marker.component_revisions.PSObject.Properties.Name | Sort-Object)
    if (($observedComponentNames -join "`n") -ne ($componentNames -join "`n")) {
        throw "Services runtime marker component revision set does not match the source manifest"
    }
    foreach ($entry in $componentRevisions.GetEnumerator()) {
        if ($marker.component_revisions.($entry.Key) -ne $entry.Value) {
            throw "Services runtime marker component revision mismatch for $($entry.Key)"
        }
    }
    foreach ($entry in $runtimeImageDigests.GetEnumerator()) {
        if ($marker.image_digests.($entry.Key) -ne $entry.Value) {
            throw "Services runtime marker image mismatch for $($entry.Key)"
        }
    }
}

Write-Step "Create exact deployed demo binding for qualification"
$deployedDemoManifestPath = Join-Path $script:ArtifactDir "deployed-demo-manifest.json"
Invoke-Checked -FilePath python -Arguments @(
    (Join-Path $script:RepoRoot "scripts\bind_deployed_demo_manifest.py"),
    "--template", (Join-Path $script:RepoRoot "ui\public\demos\manifests\${stackVersion}.json"),
    "--source-manifest", $sourceManifestPath,
    "--image-digests-file", $imageDigestsPath,
    "--output", $deployedDemoManifestPath
)

$postDeployContainers = Get-ServiceRecords $script:ApplicationServices -IncludeUi
$deploymentManifest = [ordered]@{
    schema_version = 1
    release_version = $releaseVersion
    stack_version = $stackVersion
    mip_version = "0.5.0"
    source_kind = $sourceKind
    marty_ui_sha = $sourceId
    beta_origin = $BetaOrigin
    compose_project = $script:BetaProject
    ui_compose_project = $script:BetaUiProject
    network = $script:BetaNetwork
    promotion_eligible = $promotionEligible
    release_ready = $false
    backup_manifest = "backup-manifest.json"
    source_manifest = "source-manifest.json"
    official_stack_manifest = if ($OfficialStackRelease) { "stack-manifest.json" } else { $null }
    official_stack_manifest_sha256 = if ($OfficialStackRelease) { [string]$officialPlan.stack_manifest_sha256 } else { $null }
    runtime_config_root = $script:RuntimeConfigRoot
    runtime_config_manifest_sha256 = Get-FileSha256 $script:RuntimeConfigManifestPath
    verification_migration_image = $verificationMigrationImage
    component_revisions = $componentRevisions
    deployed_demo_manifest = "deployed-demo-manifest.json"
    deployed_demo_manifest_sha256 = Get-FileSha256 $deployedDemoManifestPath
    services_marker = $servicesMarker
    issuance_native_marker = $nativeIssuanceMarker
    ui_marker = $uiMarker
    images = $postDeployContainers
    canvas_portable_configuration = [ordered]@{
        enabled = [bool]$EnablePortableCanvas
        canvas_origin = if ($EnablePortableCanvas) { $CanvasOrigin } else { $null }
        pilot_organization_id = if ($EnablePortableCanvas) { $PilotOrganizationId } else { $null }
        lti_issuer_did = $canvasLtiIssuerDid
        signing_resolution = if ($EnablePortableCanvas) { "organization-scoped-issuer-did" } else { $null }
        legacy_event_ingest_enabled = $false
    }
    deployed_at = (Get-Date).ToUniversalTime().ToString("o")
}
$deploymentManifestJson = $deploymentManifest | ConvertTo-Json -Depth 8
Write-Utf8Text `
    -Path (Join-Path $script:ArtifactDir "local-deployment-manifest.json") `
    -Content ($deploymentManifestJson + "`n")

Write-Step "Beta deployment complete"
Write-Host "Release: $releaseVersion"
Write-Host "Source ID: $sourceId"
Write-Host "Evidence: $script:ArtifactDir"
