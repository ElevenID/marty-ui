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
    [string]$TunnelEnvFile,
    [string]$GeneratedEnvFile,
    [Parameter(Mandatory = $true)][switch]$ConfirmBetaRestore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (-not $ConfirmBetaRestore) { throw "-ConfirmBetaRestore is required" }

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
. (Join-Path $PSScriptRoot "beta-worker-launch-contract.ps1")
if ([string]::IsNullOrWhiteSpace($TunnelEnvFile)) {
    $TunnelEnvFile = Join-Path $repoRoot ".env.tunnel.beta.local"
}
if ([string]::IsNullOrWhiteSpace($GeneratedEnvFile)) {
    $GeneratedEnvFile = Join-Path $repoRoot ".env.beta.generated.local"
}
$artifactRoot = (Resolve-Path (Join-Path $repoRoot "tests\artifacts")).Path
$resolvedArtifacts = (Resolve-Path $ArtifactDir).Path
$allowedPrefix = $artifactRoot.TrimEnd('\') + '\'
if (-not $resolvedArtifacts.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase) -or $resolvedArtifacts -match "selfhost|production|demo-release-candidate") {
    throw "Restore ArtifactDir must be a local beta artifact under tests/artifacts"
}

$project = "elevenid-beta"
$uiProject = "elevenid-beta-ui"
$volumeHelperImage = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
$env:MARTY_NETWORK_NAME = "elevenid-beta-network"
$composeFiles = @(
    "docker-compose.base.yml", "docker-compose.beta.yml", "docker-compose.profile.dev.yml",
    "docker-compose.profile.tunnel.yml",
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

function Assert-BetaVolume([string]$Name) {
    $raw = & docker volume inspect $Name
    if ($LASTEXITCODE -ne 0) { throw "Required beta volume is absent: $Name" }
    $volume = ($raw -join "`n") | ConvertFrom-Json
    if ($volume.Count -ne 1 -or $volume[0].Labels.'com.docker.compose.project' -ne $project) {
        throw "Refusing volume outside ${project}: $Name"
    }
    return $Name
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
    "revocation-profile", "device-registration", "event-stream", "signing-keys", "issuance",
    "issuance-native", "canvas-sync-worker", "gateway"
)
$priorBureau = @($preDeploy | Where-Object { $_.service -eq "passport-beta-bureau" })
$priorSigner = @($preDeploy | Where-Object { $_.service -eq "passport-callback-signer" })
if ($priorBureau.Count -gt 1) { throw "Ambiguous beta passport bureau recovery records" }
if ($priorSigner.Count -gt 1 -or $priorSigner.Count -ne $priorBureau.Count) {
    throw "Beta passport callback recovery records must contain both bureau and signer"
}

function Assert-RestoredPassportCallbackNetwork {
    $name = "elevenid-beta-passport-callback-signing"
    $ids = @()
    $openbao = $null
    foreach ($service in @("openbao", "passport-beta-bureau", "passport-callback-signer")) {
        $container = Find-ServiceContainer $service
        if (-not $container) { throw "Missing restored passport callback service: $service" }
        $id = & docker inspect $container --format '{{.Id}}'
        if ($LASTEXITCODE -ne 0 -or $id -notmatch '^[0-9a-f]{64}$') {
            throw "Invalid restored passport callback service identity"
        }
        $running = & docker inspect $container --format '{{.State.Running}}'
        if ($LASTEXITCODE -ne 0 -or $running -ne "true") {
            throw "Restored passport callback service is not running: $service"
        }
        $ids += [string]$id
        if ($service -eq "openbao") { $openbao = [string]$id }
    }
    $raw = & docker network inspect $name
    if ($LASTEXITCODE -ne 0) { throw "Restored passport callback network is missing" }
    $network = @(($raw -join "`n") | ConvertFrom-Json)
    if ($network.Count -ne 1 -or $network[0].Internal -ne $true) {
        throw "Restored passport callback network is not isolated"
    }
    $members = @($network[0].Containers.PSObject.Properties.Name)
    if (@($members | Where-Object { $_ -notin $ids }).Count -ne 0) {
        throw "Unexpected container joined the restored passport callback network"
    }
    if ($openbao -notin $members) {
        Invoke-Checked docker @("network", "connect", "--alias", "openbao", $name, $openbao)
    }
    $raw = & docker network inspect $name
    if ($LASTEXITCODE -ne 0) { throw "Restored passport callback network is missing" }
    $network = @(($raw -join "`n") | ConvertFrom-Json)
    $members = @($network[0].Containers.PSObject.Properties.Name)
    if ($network.Count -ne 1 -or $network[0].Internal -ne $true -or
        $members.Count -ne 3 -or @($members | Where-Object { $_ -notin $ids }).Count -ne 0) {
        throw "Restored passport callback network membership is invalid"
    }
    $openbaoNetworksRaw = & docker inspect $openbao --format '{{json .NetworkSettings.Networks}}'
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect restored OpenBao callback network aliases" }
    $openbaoNetworks = ($openbaoNetworksRaw -join "`n") | ConvertFrom-Json
    $openbaoEndpoint = $openbaoNetworks.PSObject.Properties[$name]
    if (-not $openbaoEndpoint -or "openbao" -notin @($openbaoEndpoint.Value.Aliases)) {
        throw "Restored OpenBao lacks its isolated callback network alias"
    }
}

function Restore-PriorPassportCallbackNetwork {
    if ($priorBureau.Count -ne 0 -or $null -eq $callbackNetworkBefore) { return }
    $name = "elevenid-beta-passport-callback-signing"
    $networkNames = @(& docker network ls --format '{{.Name}}')
    if ($LASTEXITCODE -ne 0) { throw "Could not inventory restored beta callback networks" }
    $matches = @($networkNames | Where-Object { $_ -ceq $name })
    if ($matches.Count -gt 1) { throw "Ambiguous restored beta callback network" }
    if ($matches.Count -eq 0) {
        if ($callbackNetworkBefore.exists) { throw "Preexisting beta callback network was lost" }
        return
    }
    $raw = & docker network inspect $name
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect restored beta callback network" }
    $network = @(($raw -join "`n") | ConvertFrom-Json)
    if ($network.Count -ne 1 -or $network[0].Internal -ne $true -or
        $network[0].Id -notmatch '^[0-9a-f]{64}$' -or
        $network[0].Labels.'com.docker.compose.project' -ne $project) {
        throw "Restored beta callback network is not owned and isolated"
    }
    if ($callbackNetworkBefore.exists -and $network[0].Id -cne $callbackNetworkBefore.id) {
        throw "Preexisting beta callback network identity changed"
    }
    $openbaoContainer = Find-ServiceContainer "openbao"
    if (-not $openbaoContainer) { throw "OpenBao is missing during beta callback network restore" }
    $openbaoId = & docker inspect $openbaoContainer --format '{{.Id}}'
    if ($LASTEXITCODE -ne 0 -or $openbaoId -notmatch '^[0-9a-f]{64}$') {
        throw "Could not identify OpenBao during beta callback network restore"
    }
    $priorMembers = @($callbackNetworkBefore.members)
    $members = @($network[0].Containers.PSObject.Properties.Name)
    $allowedMembers = if ($callbackNetworkBefore.exists) { @($priorMembers + $openbaoId) } else { @($openbaoId) }
    if (@($members | Where-Object { $_ -notin $allowedMembers }).Count -ne 0) {
        throw "Unexpected member blocks beta callback network rollback cleanup"
    }
    if ($openbaoId -in $members -and $openbaoId -notin $priorMembers) {
        Invoke-Checked docker @("network", "disconnect", $name, $openbaoId)
    }
    $raw = & docker network inspect $name
    if ($LASTEXITCODE -ne 0) { throw "Could not recheck restored beta callback network" }
    $network = @(($raw -join "`n") | ConvertFrom-Json)
    $members = @($network[0].Containers.PSObject.Properties.Name)
    if ($network.Count -ne 1 -or
        $members.Count -ne $priorMembers.Count -or
        @($members | Where-Object { $_ -notin $priorMembers }).Count -ne 0) {
        throw "Beta callback network does not match its predeploy membership"
    }
    if (-not $callbackNetworkBefore.exists) {
        Invoke-Checked docker @("network", "rm", [string]$network[0].Id)
    }
}
if ($priorBureau.Count -eq 1) {
    if ($priorBureau[0].image_id -notmatch '^sha256:[0-9a-f]{64}$' -or
        $priorBureau[0].compose_project -ne $project -or
        $priorBureau[0].compose_service -ne "passport-beta-bureau") {
        throw "Invalid beta passport bureau recovery record"
    }
    if ($priorSigner[0].image_id -notmatch '^sha256:[0-9a-f]{64}$' -or
        $priorSigner[0].image_id -ne $priorBureau[0].image_id -or
        $priorSigner[0].compose_project -ne $project -or
        $priorSigner[0].compose_service -ne "passport-callback-signer") {
        throw "Invalid beta passport callback signer recovery record"
    }
    $env:MARTY_SERVICES_IMAGE = [string]$priorBureau[0].image_id
    $composeFiles += Join-Path $repoRoot "docker-compose.profile.passport-native-beta.yml"
    $applicationServices += "passport-callback-signer"
    $applicationServices += "passport-beta-bureau"
}
$currentBureauIds = @(& docker ps -a --filter "label=com.docker.compose.project=$project" `
    --filter "label=com.docker.compose.service=passport-beta-bureau" --format '{{.ID}}')
if ($LASTEXITCODE -ne 0 -or $currentBureauIds.Count -gt 1) {
    throw "Could not uniquely resolve current beta passport bureau"
}
$currentBureau = if ($currentBureauIds.Count -eq 1) { [string]$currentBureauIds[0] } else { $null }
$currentSignerIds = @(& docker ps -a --filter "label=com.docker.compose.project=$project" `
    --filter "label=com.docker.compose.service=passport-callback-signer" --format '{{.ID}}')
if ($LASTEXITCODE -ne 0 -or $currentSignerIds.Count -gt 1) {
    throw "Could not uniquely resolve current beta passport callback signer"
}
$currentSigner = if ($currentSignerIds.Count -eq 1) { [string]$currentSignerIds[0] } else { $null }
$callbackNetworkBeforePath = Join-Path $resolvedArtifacts "passport-callback-network-before.json"
$callbackNetworkBefore = $null
if (Test-Path -LiteralPath $callbackNetworkBeforePath -PathType Leaf) {
    $callbackNetworkBefore = Get-Content -LiteralPath $callbackNetworkBeforePath -Raw | ConvertFrom-Json
    if ($callbackNetworkBefore.schema_version -ne 1 -or
        $callbackNetworkBefore.exists -isnot [bool] -or
        ($callbackNetworkBefore.exists -and $callbackNetworkBefore.id -notmatch '^[0-9a-f]{64}$') -or
        (-not $callbackNetworkBefore.exists -and $null -ne $callbackNetworkBefore.id)) {
        throw "Invalid predeploy beta callback network record"
    }
}
elseif ($priorBureau.Count -gt 0 -or $currentBureau -or $currentSigner) {
    throw "Missing predeploy beta callback network record for passport recovery"
}
if ($null -ne $callbackNetworkBefore) {
    $name = "elevenid-beta-passport-callback-signing"
    $networkNames = @(& docker network ls --format '{{.Name}}')
    if ($LASTEXITCODE -ne 0) { throw "Could not inventory beta callback network before restore" }
    $matches = @($networkNames | Where-Object { $_ -ceq $name })
    if ($matches.Count -gt 1 -or ($matches.Count -eq 0 -and $callbackNetworkBefore.exists)) {
        throw "Predeploy beta callback network identity is unavailable"
    }
    if ($matches.Count -eq 1) {
        $raw = & docker network inspect $name
        if ($LASTEXITCODE -ne 0) { throw "Could not inspect beta callback network before restore" }
        $network = @(($raw -join "`n") | ConvertFrom-Json)
        if ($network.Count -ne 1 -or $network[0].Internal -ne $true -or
            $network[0].Id -notmatch '^[0-9a-f]{64}$' -or
            $network[0].Labels.'com.docker.compose.project' -ne $project -or
            ($callbackNetworkBefore.exists -and $network[0].Id -cne $callbackNetworkBefore.id)) {
            throw "Beta callback network identity or isolation changed before restore"
        }
        $allowedIds = @()
        foreach ($container in @((Find-ServiceContainer "openbao"), $currentBureau, $currentSigner)) {
            if ($container) {
                $id = & docker inspect $container --format '{{.Id}}'
                if ($LASTEXITCODE -ne 0 -or $id -notmatch '^[0-9a-f]{64}$') {
                    throw "Could not identify beta callback container before restore"
                }
                $allowedIds += [string]$id
            }
        }
        $members = @($network[0].Containers.PSObject.Properties.Name)
        if (@($members | Where-Object { $_ -notin $allowedIds }).Count -ne 0) {
            throw "Unexpected member blocks beta callback network restore"
        }
    }
}
$gatewayRecord = @($preDeploy | Where-Object { $_.service -eq "gateway" } | Select-Object -First 1)
if ($gatewayRecord.Count -eq 1) {
    foreach ($name in @("MARTY_RELEASE_VERSION", "MARTY_UI_SHA", "ELEVENID_STACK_VERSION", "ELEVENID_COMPONENT_REVISIONS_JSON", "ELEVENID_IMAGE_DIGESTS_JSON")) {
        $property = $gatewayRecord[0].runtime_marker_environment.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value) {
            Set-Item -Path "Env:$name" -Value ([string]$property.Value)
        }
    }
}
$restoreImages = Join-Path $resolvedArtifacts "restore-images.yml"
$yaml = @("services:")
$restoreServices = @()
# Complete rollback launch/image/environment validation is read-only and precedes
# the first stop/database/volume mutation. Never print resolved Compose secrets.
$workerRecords = @($preDeploy | Where-Object { $_.service -eq "canvas-sync-worker" -and $_.running })
if ($workerRecords.Count -gt 1) { throw "Ambiguous beta worker recovery records" }
$workerLaunch = $null
if ($workerRecords.Count -eq 1) {
    $workerRecord = $workerRecords[0]
    if ($workerRecord.image_id -notmatch '^sha256:[0-9a-f]{64}$') { throw "Invalid worker rollback image ID" }
    $rawImage = & docker image inspect $workerRecord.image_id
    if ($LASTEXITCODE -ne 0) { throw "Worker rollback image must be available for preflight inspection before stopping beta" }
    $image = @((($rawImage -join "`n") | ConvertFrom-Json))
    if ($image.Count -ne 1 -or $image[0].Id -cne $workerRecord.image_id) { throw "Worker rollback image identity mismatch" }
    $currentWorker = $null
    if ($null -eq $workerRecord.PSObject.Properties['rollback_launch']) {
        $configArguments = Get-ComposeArgs @('config', '--format', 'json')
        $rawConfiguration = & docker @configArguments
        if ($LASTEXITCODE -ne 0) { throw "Legacy worker rollback requires a readable matching Compose configuration before stopping beta" }
        $configuration = ($rawConfiguration -join "`n") | ConvertFrom-Json
        $currentWorker = (Get-BetaWorkerField $configuration.services 'canvas-sync-worker').Value
    }
    $workerLaunch = Resolve-BetaWorkerRollbackLaunch -Record $workerRecord -CurrentWorker $currentWorker -ImageConfig $image[0].Config
}
foreach ($record in $preDeploy) {
    if ($record.running -and $record.service -in $applicationServices) {
        if ($record.image_id -notmatch '^sha256:[0-9a-f]{64}$') { throw "Invalid image ID for $($record.service)" }
        $restoreServices += [string]$record.service
        $yaml += "  $($record.service):"
        $yaml += "    image: $($record.image_id)"
        $hasWorkerLaunch = $record.service -eq 'canvas-sync-worker'
        if ($hasWorkerLaunch) { $yaml += @(ConvertTo-BetaWorkerRollbackLines -Launch $workerLaunch) }
        $compatibility = $record.PSObject.Properties["rollback_environment"]
        if ($null -ne $compatibility -and $null -ne $compatibility.Value) {
            $environment = @($compatibility.Value.PSObject.Properties)
            if ($environment.Count -gt 0 -and -not $hasWorkerLaunch) {
                $yaml += "    environment:"
            }
            foreach ($property in $environment) {
                if ($property.Name -eq "DATABASE_DRIVER") {
                    $driver = [string]$property.Value
                    if ($driver -notin @("postgresql", "postgresql+asyncpg")) {
                        throw "Unsupported rollback database driver for $($record.service)"
                    }
                    $yaml += '      DATABASE_URL: ' + $driver + '://marty:${MARTY_DB_PASSWORD:-marty_dev_password}@postgres:5432/marty'
                    continue
                }
                if ($property.Name -notin @("GRPC_INSECURE_ALLOWED", "ALLOW_PLAINTEXT_GRPC") -or [string]$property.Value -notin @("true", "false")) {
                    throw "Unsupported rollback environment for $($record.service)"
                }
                $yaml += "      $($property.Name): `"$($property.Value)`""
            }
        }
    }
}
$uiRecord = @($preDeploy | Where-Object { $_.service -eq "ui-prod" -and $_.running } | Select-Object -First 1)
if ($uiRecord.Count -eq 1 -and $uiRecord[0].image_id -notmatch '^sha256:[0-9a-f]{64}$') { throw "Invalid beta UI image ID" }
# Resolve every existing data target before stopping services or restoring any
# earlier store. A missing/mislabeled later volume must fail without partial restore.
$postgres = Get-ServiceContainer "postgres"
$redisVolumeName = Assert-BetaVolume "elevenid-beta_redis_data"
$applicantVolumeName = Assert-BetaVolume "elevenid-beta_applicant_data"
$yaml -join "`n" | Set-Content -LiteralPath $restoreImages -Encoding utf8
$composeFiles += $restoreImages
Invoke-Checked docker (Get-ComposeArgs (@("stop") + $applicationServices + @("keycloak")))
if ($priorBureau.Count -eq 0 -and $currentBureau) {
    Invoke-Checked docker @("stop", $currentBureau)
}
if ($priorSigner.Count -eq 0 -and $currentSigner) {
    Invoke-Checked docker @("stop", $currentSigner)
}

Invoke-Checked docker @("cp", (Join-Path $backupDir "postgres-marty.dump"), "${postgres}:/tmp/beta-restore-marty.dump")
Invoke-Checked docker @("cp", (Join-Path $backupDir "postgres-keycloak.dump"), "${postgres}:/tmp/beta-restore-keycloak.dump")
foreach ($database in @("marty", "keycloak")) {
    Invoke-Checked docker @("exec", $postgres, "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$database' AND pid <> pg_backend_pid();")
    Invoke-Checked docker @("exec", $postgres, "dropdb", "-U", "postgres", "--if-exists", $database)
    Invoke-Checked docker @("exec", $postgres, "createdb", "-U", "postgres", "-O", $database, $database)
    Invoke-Checked docker @("exec", $postgres, "pg_restore", "-U", "postgres", "-d", $database, "--no-owner", "--role=$database", "/tmp/beta-restore-$database.dump")
}

Invoke-Checked docker (Get-ComposeArgs @("stop", "redis"))
Invoke-Checked docker @("run", "--rm", "--mount", "type=volume,src=$redisVolumeName,dst=/data", "--mount", "type=bind,src=$backupDir,dst=/backup,readonly", $volumeHelperImage, "sh", "-lc", "rm -rf /data/appendonlydir && rm -f /data/dump.rdb && cp /backup/redis-dump.rdb /data/dump.rdb")
Invoke-Checked docker (Get-ComposeArgs @("start", "redis"))
Wait-ForServiceHealth @("redis")
Invoke-Checked docker @("run", "--rm", "--mount", "type=volume,src=$applicantVolumeName,dst=/data", "--mount", "type=bind,src=$backupDir,dst=/backup,readonly", $volumeHelperImage, "sh", "-lc", "test -s /backup/applicant_store.json && cp /backup/applicant_store.json /data/applicant_store.json.tmp && mv /data/applicant_store.json.tmp /data/applicant_store.json")
$callbackRestore = @($restoreServices | Where-Object { $_ -in @("passport-callback-signer", "passport-beta-bureau") })
if ($priorBureau.Count -eq 1 -and $callbackRestore.Count -ne 2) {
    throw "Both passport callback services must be running in the restored beta snapshot"
}
if ($callbackRestore.Count -eq 2) {
    Invoke-Checked docker (Get-ComposeArgs (@("up", "--detach", "--no-build", "--no-deps", "--force-recreate") + $callbackRestore))
    Wait-ForServiceHealth $callbackRestore
    Assert-RestoredPassportCallbackNetwork
}
$otherRestore = @($restoreServices | Where-Object { $_ -notin $callbackRestore })
Invoke-Checked docker (Get-ComposeArgs (@("up", "--detach", "--no-build", "--no-deps", "--force-recreate") + @("keycloak") + $otherRestore))
Wait-ForServiceHealth (@("keycloak") + $restoreServices)
if ($callbackRestore.Count -eq 2) { Assert-RestoredPassportCallbackNetwork }

if ("canvas-sync-worker" -notin @($preDeploy.service)) {
    $worker = Find-ServiceContainer "canvas-sync-worker"
    if ($worker) { Invoke-Checked docker @("rm", "--force", $worker) }
}
if ("issuance-native" -notin @($preDeploy.service)) {
    $nativeIssuance = Find-ServiceContainer "issuance-native"
    if ($nativeIssuance) { Invoke-Checked docker @("rm", "--force", $nativeIssuance) }
}
if ($priorBureau.Count -eq 0 -and $currentBureau) {
    Invoke-Checked docker @("rm", $currentBureau)
}
if ($priorSigner.Count -eq 0 -and $currentSigner) {
    Invoke-Checked docker @("rm", $currentSigner)
}
Restore-PriorPassportCallbackNetwork

if ($uiRecord.Count -eq 1) {
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
