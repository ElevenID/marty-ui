param(
    [Parameter(Mandatory = $true)][string]$StackManifest,
    [Parameter(Mandatory = $true)][string]$FenceReceipt,
    [Parameter(Mandatory = $true)][string]$MaintenanceReceipt,
    [Parameter(Mandatory = $true)][string]$NativeReceipt,
    [Parameter(Mandatory = $true)][string]$ApplicationFile,
    [Parameter(Mandatory = $true)][string]$IssuerChainFile,
    [Parameter(Mandatory = $true)][string]$IssuerCeremonyFile,
    [Parameter(Mandatory = $true)][string]$CscaSessionFile,
    [Parameter(Mandatory = $true)][string]$DscSessionFile,
    [Parameter(Mandatory = $true)][string]$FlowFile,
    [Parameter(Mandatory = $true)][string]$SessionFile,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

# One beta-only forward cutover. On failure the mutation marker stays pending;
# no old application container or Python migration is started for recovery.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Protected aggregate deployment requires the Windows beta host'
}
$repo = Split-Path -Parent $PSScriptRoot
$root = [IO.Path]::GetFullPath($repo).TrimEnd([IO.Path]::DirectorySeparatorChar)
if (-not [IO.Path]::IsPathRooted($OutputPath)) {
    throw 'Aggregate beta receipt path must be absolute'
}
$output = [IO.Path]::GetFullPath($OutputPath)
if ($output.StartsWith($root + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Aggregate beta receipt must be outside protected source'
}
$planPath = $output + '.plan.json'
$productionPostflightPath = $output + '.production-postflight.json'
$productionRecoveryPath = $output + '.production-recovery-' + [Guid]::NewGuid().ToString('N') + '.json'
$fenceRecheckPath = $output + '.pretransition-fence.json'
$credentialsPretransitionPath = $output + '.credentials-pretransition.json'
$ceremonyIntentPath = $output + '.issuer-ceremony-intent.json'
$ceremonyPath = $output + '.issuer-ceremony.json'
$kmsPretransitionPath = $output + '.kms-pretransition.json'
$transitionPath = $output + '.transition.json'
$writePath = $output + '.rust-write.json'
$writeIntentPath = $output + '.rust-write-intent.json'
$flowWritePath = $output + '.rust-flow.json'
$flowWriteIntentPath = $output + '.rust-flow-intent.json'
$referenceIntentPath = $output + '.reference-intents'
$continuityPath = $output + '.credentials-continuity.json'
$issuanceMigrationPath = $output + '.issuance-migration.json'
$issuanceDependencyPath = $output + '.issuance-dependency.json'
$applicationPath = [IO.Path]::GetFullPath($ApplicationFile)
if (-not [IO.Path]::IsPathRooted($ApplicationFile)) {
    throw 'Private Rust passport application path must be absolute'
}
if ($applicationPath.StartsWith($root + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Private Rust passport application file must be outside protected source'
}
$issuerChainPath = [IO.Path]::GetFullPath($IssuerChainFile)
if (-not [IO.Path]::IsPathRooted($IssuerChainFile) -or
    -not (Test-Path -LiteralPath $issuerChainPath -PathType Leaf) -or
    $issuerChainPath.StartsWith($root + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Selected beta issuer chain must be an absolute file outside protected source'
}
$issuerCeremonyPath = [IO.Path]::GetFullPath($IssuerCeremonyFile)
$cscaSessionPath = [IO.Path]::GetFullPath($CscaSessionFile)
$dscSessionPath = [IO.Path]::GetFullPath($DscSessionFile)
if (-not [IO.Path]::IsPathRooted($IssuerCeremonyFile) -or
    -not [IO.Path]::IsPathRooted($CscaSessionFile) -or
    -not [IO.Path]::IsPathRooted($DscSessionFile)) {
    throw 'Governed beta issuer ceremony inputs must be absolute files'
}
foreach ($privatePath in @($issuerCeremonyPath, $cscaSessionPath, $dscSessionPath)) {
    if (-not (Test-Path -LiteralPath $privatePath -PathType Leaf) -or
        $privatePath.StartsWith($root + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Governed beta issuer ceremony input must be outside protected source'
    }
}
if ($cscaSessionPath -ceq $dscSessionPath) {
    throw 'CSCA and DSC ceremonies require distinct operator sessions'
}
$flowPath = [IO.Path]::GetFullPath($FlowFile)
$sessionPath = [IO.Path]::GetFullPath($SessionFile)
if (-not [IO.Path]::IsPathRooted($FlowFile) -or
    -not [IO.Path]::IsPathRooted($SessionFile)) {
    throw 'Private Rust Flow inputs must be absolute files'
}
foreach ($privatePath in @($flowPath, $sessionPath)) {
    if ($privatePath.StartsWith($root + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Private Rust Flow input must be an absolute file outside protected source'
    }
}
if (-not (Test-Path -LiteralPath $sessionPath -PathType Leaf)) {
    throw 'Private Rust Flow session is unavailable'
}
$intentPath = [IO.Path]::GetFullPath($MaintenanceReceipt) + '.intent.json'
$reservedPaths = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase)
foreach ($path in @(
    $output, $planPath, $productionPostflightPath, $productionRecoveryPath,
    $fenceRecheckPath, $credentialsPretransitionPath, $ceremonyIntentPath,
    $ceremonyPath, $kmsPretransitionPath, $transitionPath, $writePath,
    $writeIntentPath, $flowWritePath, $flowWriteIntentPath, $referenceIntentPath,
    $continuityPath, $issuanceMigrationPath, $issuanceDependencyPath,
    ($output + '.fence-receipt.json'),
    ($output + '.maintenance-receipt.json'), ($output + '.maintenance-intent.json'),
    ($output + '.native-receipt.json'), $intentPath,
    ([IO.Path]::GetFullPath($StackManifest)),
    ([IO.Path]::GetFullPath($FenceReceipt)),
    ([IO.Path]::GetFullPath($MaintenanceReceipt)),
    ([IO.Path]::GetFullPath($NativeReceipt)), $issuerChainPath,
    $issuerCeremonyPath, $cscaSessionPath, $dscSessionPath, $sessionPath,
    $applicationPath, $flowPath
)) {
    if (-not $reservedPaths.Add($path)) {
        throw "Aggregate beta input/output paths must be distinct: $path"
    }
}
. (Join-Path $PSScriptRoot 'beta-deployment-lock.ps1')
. (Join-Path $PSScriptRoot 'beta-passport-fence-legacy-boundary.ps1')

function Invoke-Plan {
    param([string[]]$Arguments)
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $rows = @(& python @Arguments 2>$null)
        if ($LASTEXITCODE -ne 0 -or $rows.Count -ne 1) {
            throw 'Protected aggregate beta plan check failed'
        }
        return ($rows[0] | ConvertFrom-Json -ErrorAction Stop)
    }
    finally { $ErrorActionPreference = $previous }
}

function Assert-ProductionContinuity {
    param([switch]$MaintenanceOnly)
    $arguments = @((Join-Path $PSScriptRoot 'verify_passport_beta_aggregate_runtime.py'))
    if ($MaintenanceOnly) {
        $arguments += @('--stack-manifest', $StackManifest,
            '--maintenance-intent', $intentPath,
            '--maintenance-receipt', $MaintenanceReceipt,
            '--fence-receipt', $FenceReceipt,
            '--native-receipt', $NativeReceipt,
            '--production-maintenance-only')
    }
    else {
        $arguments += @('--plan', $planPath, '--maintenance-intent', $intentPath,
            '--production-attachments-sha256',
            [string]$script:plan.production_attachments_sha256,
            '--production-only')
    }
    $proof = Invoke-Plan -Arguments $arguments
    if ($proof.schema -cne 'marty.passport-beta-production-continuity/v1' -or
        $proof.verified -ne $true -or
        $proof.public_route.origin -cne 'https://elevenidllc.com/' -or
        $proof.public_route.status -ne 200) {
        throw 'Production continuity or public route is unavailable'
    }
    if (-not $MaintenanceOnly -and
        ($proof.source_commit -cne [string]$script:plan.source_commit -or
         $proof.production_snapshot_sha256 -cne
            [string]$script:plan.production_snapshot_sha256 -or
         $proof.production_attachments_sha256 -cne
            [string]$script:plan.production_attachments_sha256)) {
        throw 'Production continuity differs from signed aggregate plan'
    }
    return $proof
}

function Invoke-ProductionRecovery {
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $rows = @(& python (Join-Path $PSScriptRoot 'recover_passport_beta_production.py') `
            --restore --baseline $productionRecoveryPath `
            --expected-sha256 $script:productionRecoveryDigest 2>$null)
        if ($rows.Count -ne 1) {
            throw 'Production recovery did not return one receipt'
        }
        $receipt = $rows[0] | ConvertFrom-Json -ErrorAction Stop
        if ($receipt.schema -cne 'marty.passport-beta-production-recovery/v1' -or
            $receipt.verified -isnot [bool] -or
            $receipt.continuity_breached -isnot [bool]) {
            throw 'Production recovery receipt is invalid'
        }
        return $receipt
    }
    finally { $ErrorActionPreference = $previous }
}

function Write-ProductionPostflight {
    $postflight = [ordered]@{
        schema = 'marty.passport-beta-production-postflight/v1'
        deployment_failed = $true
        verified = $false
        production_running = $false
        recovery_attempted = $script:productionRecoveryReady
        checked_at_utc = [DateTime]::UtcNow.ToString('o')
    }
    $postflightFailure = $null
    $recovery = $null
    if ($script:productionRecoveryReady) {
        try {
            $recovery = Invoke-ProductionRecovery
            $postflight.recovery = $recovery
            $postflight.production_running = ($recovery.verified -eq $true)
            if ($recovery.verified -ne $true) {
                $postflightFailure = 'Production recovery did not verify health and public route'
            }
        }
        catch { $postflightFailure = 'Production recovery result is unavailable' }
    }
    try {
        $proof = Assert-ProductionContinuity -MaintenanceOnly
        $postflight.verified = ($null -eq $postflightFailure -and
            ($null -eq $recovery -or $recovery.continuity_breached -ne $true))
        $postflight.production_running = $true
        $postflight.proof = $proof
    }
    catch { if ($null -eq $postflightFailure) { $postflightFailure = $_.Exception.Message } }
    try {
        Replace-DurableJson -Path $productionPostflightPath `
            -Json ($postflight | ConvertTo-Json -Depth 10 -Compress)
    }
    catch { if ($null -eq $postflightFailure) { $postflightFailure = 'Production postflight receipt write failed' } }
    if ($null -ne $postflightFailure) {
        Write-Warning "Production postflight failed: $postflightFailure"
    }
}

function Write-DurableJson {
    param([string]$Path, [string]$Json)
    $temporary = $Path + '.stage-' + [Guid]::NewGuid().ToString('N')
    try {
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($Json + "`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        [IO.File]::Move($temporary, $Path)
    }
    finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Assert-DockerIdentity {
    param($Intent)
    $context = @(& docker context show 2>$null)
    $daemon = @(& docker info --format '{{.ID}}' 2>$null)
    if ($context.Count -ne 1 -or $daemon.Count -ne 1 -or
        $context[0] -cne [string]$Intent.docker.context -or
        $daemon[0] -cne [string]$Intent.docker.daemon_id) {
        throw 'Aggregate beta Docker context changed'
    }
}

function Assert-Render {
    $check = Invoke-Plan -Arguments ($script:plannerArgs + @(
        '--verify-render-plan', $planPath))
    if ($check.schema -cne 'marty.passport-beta-aggregate-render-check/v1' -or
        $check.verified -ne $true -or
        $check.source_commit -cne $script:plan.source_commit -or
        $check.beta_render_sha256 -cne $script:plan.beta_render_sha256 -or
        $check.ui_render_sha256 -cne $script:plan.ui_render_sha256) {
        throw 'Aggregate beta Compose render changed before startup'
    }
    Assert-DockerIdentity -Intent $script:intent
}

function Assert-PreservedIngressOrigin {
    foreach ($service in @('keycloak', 'nginx-proxy')) {
        $id = [string]$script:plan.old_container_ids_by_service.$service
        if ($id -notmatch '^[0-9a-f]{64}$') {
            throw "Old beta ingress identity is invalid: $service"
        }
        $raw = @(& docker inspect $id --format '{{json .Config.Env}}' 2>$null)
        if ($LASTEXITCODE -ne 0 -or $raw.Count -ne 1) {
            throw "Old beta ingress environment is unavailable: $service"
        }
        $entries = ConvertFrom-Json -InputObject $raw[0] -ErrorAction Stop
        $values = @{}
        foreach ($entry in $entries) {
            if ($entry -notmatch '^([^=]+)=(.*)$' -or $values.ContainsKey($Matches[1])) {
                throw "Old beta ingress environment is ambiguous: $service"
            }
            $values[$Matches[1]] = $Matches[2]
        }
        if ($service -ceq 'keycloak') {
            if ($values['KC_HOSTNAME'] -cne 'https://beta.elevenidllc.com' -or
                $values['UI_BASE_URL'] -cne 'https://beta.elevenidllc.com' -or
                $values['PUBLIC_DOMAIN'] -cne 'beta.elevenidllc.com') {
                throw 'Old beta Keycloak points outside the beta origin'
            }
        }
        elseif ($values['PUBLIC_DOMAIN'] -cne 'beta.elevenidllc.com' -or
                $values['GATEWAY_UPSTREAM'] -cne 'gateway:8000') {
            throw 'Old beta Nginx points outside the beta gateway'
        }
    }
}

function Assert-OpenBaoToken {
    $check = Invoke-Plan -Arguments ($script:plannerArgs + @(
        '--verify-openbao-token', $planPath))
    if ($check.schema -cne 'marty.passport-beta-openbao-token-check/v1' -or
        $check.verified -ne $true -or
        $check.source_commit -cne $script:plan.source_commit) {
        throw 'New callback signer token differs from preserved beta OpenBao'
    }
}

function Invoke-SignedIssuanceMigration {
    Assert-Render
    $arguments = @('compose', '--project-name', 'elevenid-beta')
    foreach ($file in @('.env.tunnel.beta.local', '.env.beta.generated.local')) {
        $arguments += @('--env-file', (Join-Path $root $file))
    }
    foreach ($file in @(
        'docker-compose.base.yml', 'docker-compose.beta.yml',
        'docker-compose.profile.dev.yml', 'docker-compose.profile.tunnel.yml',
        'docker-compose.profile.waltid.yml',
        'docker-compose.profile.canvas-real.yml',
        'docker-compose.profile.canvas-sandbox.yml',
        'docker-compose.profile.passport-native-beta.yml',
        'docker-compose.profile.passport-premigrated-beta.yml')) {
        $arguments += @('-f', (Join-Path $root $file))
    }
    $arguments += @('-f', '-', 'run', '--rm', '--no-deps', '--no-build',
        'issuance-migrations')
    $script:plan.image_override | & docker @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Signed Rust issuance schema verification failed' }
    $expected = @(
        'issuance_service_baseline_v1',
        '0000_merge_issuance_heads_bridge',
        '0001_oid4vci_public_protocol', '0002_physical_document_jobs',
        '0003_passport_bureau_provider_binding', '0004_passport_submission_intent',
        '0005_passport_submission_provenance', '0006_passport_beta_batch_identity',
        '0007_passport_beta_batch_provenance', '0008_passport_beta_batch_wire_evidence'
    ) | Sort-Object
    $actual = @(Invoke-BetaPsql -Sql `
        'SELECT version FROM issuance_service.rust_schema_migrations ORDER BY version;')
    if (($actual -join ',') -cne ($expected -join ',')) {
        throw 'Rust issuance migration ledger differs from the signed migration set'
    }
    $receipt = [ordered]@{
        schema = 'marty.passport-beta-issuance-migration/v1'
        source_commit = $script:plan.source_commit
        services_image = $script:plan.services_image
        postgres_container_id = $script:plan.postgres_container_id
        versions = $actual
    }
    if (Test-Path -LiteralPath $issuanceMigrationPath) {
        $prior = Get-Content -LiteralPath $issuanceMigrationPath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
        if (@($prior.PSObject.Properties.Name).Count -ne $receipt.Count -or
            @($prior.PSObject.Properties.Name | Where-Object { $_ -notin $receipt.Keys }).Count -ne 0 -or
            $prior.schema -cne $receipt.schema -or
            $prior.source_commit -cne $receipt.source_commit -or
            $prior.services_image -cne $receipt.services_image -or
            $prior.postgres_container_id -cne $receipt.postgres_container_id -or
            (@($prior.versions) -join ',') -cne ($actual -join ',')) {
            throw 'Prior Rust issuance migration receipt differs on resume'
        }
    }
    else {
        Write-DurableJson -Path $issuanceMigrationPath `
            -Json ($receipt | ConvertTo-Json -Depth 5 -Compress)
    }
}

function Invoke-Compose {
    param([string[]]$Services, [switch]$Ui)
    Assert-Render
    if ($Ui -and $script:readyUi) { return }
    if (-not $Ui) {
        $Services = @($Services | Where-Object { $_ -notin $script:readyServices })
        if ($Services.Count -eq 0) { return }
    }
    $arguments = @('compose', '--project-name', 'elevenid-beta')
    if ($Ui) { $arguments = @('compose', '--project-name', 'elevenid-beta-ui') }
    foreach ($file in @('.env.tunnel.beta.local', '.env.beta.generated.local')) {
        $arguments += @('--env-file', (Join-Path $root $file))
    }
    if ($Ui) {
        $arguments += @('-f', (Join-Path $root 'docker-compose.ui-release.yml'),
            'up', '--detach', '--no-build', '--no-deps', '--force-recreate', 'ui-prod')
        & docker @arguments | Out-Null
    }
    else {
        foreach ($file in @(
            'docker-compose.base.yml', 'docker-compose.beta.yml',
            'docker-compose.profile.dev.yml', 'docker-compose.profile.tunnel.yml',
            'docker-compose.profile.waltid.yml',
            'docker-compose.profile.canvas-real.yml',
            'docker-compose.profile.canvas-sandbox.yml',
            'docker-compose.profile.passport-native-beta.yml',
            'docker-compose.profile.passport-premigrated-beta.yml')) {
            $arguments += @('-f', (Join-Path $root $file))
        }
        $arguments += @('-f', '-', 'up', '--detach', '--no-build', '--no-deps',
            '--force-recreate') + $Services
        $script:plan.image_override | & docker @arguments | Out-Null
    }
    if ($LASTEXITCODE -ne 0) { throw 'Signed aggregate beta Compose startup failed' }
}

function Wait-BetaHealthy {
    param([string[]]$Services, [switch]$Ui)
    $project = if ($Ui) { 'elevenid-beta-ui' } else { 'elevenid-beta' }
    $deadline = [DateTime]::UtcNow.AddMinutes(5)
    do {
        $pending = @()
        foreach ($service in $Services) {
            $ids = @(& docker ps --all --filter "label=com.docker.compose.project=$project" `
                --filter "label=com.docker.compose.service=$service" --format '{{.ID}}' 2>$null)
            if ($LASTEXITCODE -ne 0 -or $ids.Count -ne 1) {
                $pending += $service
                continue
            }
            $state = @(& docker inspect --format `
                '{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' `
                $ids[0] 2>$null)
            if ($LASTEXITCODE -ne 0 -or $state.Count -ne 1 -or
                $state[0] -notin @('true|healthy', 'true|none')) {
                $pending += $service
            }
        }
        if ($pending.Count -eq 0) { return }
        Start-Sleep -Seconds 3
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Aggregate beta service health did not converge'
}

function Invoke-BetaPsql {
    param([string]$Sql)
    $container = [string]$script:plan.postgres_container_id
    if ($container -notmatch '^[0-9a-f]{64}$') {
        throw 'Aggregate beta PostgreSQL identity is invalid'
    }
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $rows = @($Sql | & docker exec -i $container psql -X -U postgres -d marty `
            -qAt -v ON_ERROR_STOP=1 -f - 2>$null)
        if ($LASTEXITCODE -ne 0) { throw 'Aggregate beta database gate failed' }
        return $rows
    }
    finally { $ErrorActionPreference = $previous }
}

function Replace-DurableJson {
    param([string]$Path, [string]$Json)
    $temporary = $Path + '.stage-' + [Guid]::NewGuid().ToString('N')
    try {
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($Json + "`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        if ([IO.File]::Exists($Path)) {
            [IO.File]::Replace($temporary, $Path, $null)
        }
        else { [IO.File]::Move($temporary, $Path) }
    }
    finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Assert-FenceRecheckReceipt {
    $check = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_fence_direct_writes.py'),
        '--postgres-container', [string]$script:plan.postgres_container_id,
        '--docker-context', [string]$script:intent.docker.context,
        '--daemon-id', [string]$script:intent.docker.daemon_id,
        '--system-identifier', [string]$script:plan.postgres_system_identifier,
        '--database-oid', [string]$script:plan.database_oid,
        '--fence-epoch', [string]$script:plan.fence_epoch,
        '--verify-receipt', $fenceRecheckPath)
    if ($check.schema -cne 'marty.passport-beta-fence-direct-probe-check/v1' -or
        $check.verified -ne $true -or
        $check.postgres_container_id -cne $script:plan.postgres_container_id -or
        [string]$check.fence_epoch -cne [string]$script:plan.fence_epoch -or
        $check.receipt_file_sha256 -cne
            (Get-FileHash -LiteralPath $fenceRecheckPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'Pretransition valid write rejection receipt verification failed'
    }
    return $check
}

function Assert-ForwardGeneration {
    param([switch]$RequireIngressClosed)
    $check = Invoke-Plan -Arguments ($script:plannerArgs + @(
        '--verify-resume-plan', $planPath))
    if ($check.schema -cne 'marty.passport-beta-aggregate-resume-check/v1' -or
        $check.verified -ne $true -or $check.app_login_enabled -ne $true -or
        $check.source_commit -cne $script:plan.source_commit) {
        throw 'Stopped Python writer or signed beta generation changed'
    }
    $oldWriter = [string]$script:plan.legacy_writer_container_id
    if ($oldWriter -notmatch '^[0-9a-f]{64}$') {
        throw 'Old passport writer identity is invalid'
    }
    $oldState = @(& docker inspect --format '{{.State.Running}}' $oldWriter 2>$null)
    if ($LASTEXITCODE -eq 0 -and
        ($oldState.Count -ne 1 -or $oldState[0] -cne 'false')) {
        throw 'Old Python passport writer restarted'
    }
    if ($RequireIngressClosed) {
        foreach ($name in @($script:plan.recreate_ingress_last) +
                 @($script:plan.restart_ingress_last)) {
            $active = @(& docker ps --filter 'label=com.docker.compose.project=elevenid-beta' `
                --filter "label=com.docker.compose.service=$name" --format '{{.ID}}' 2>$null)
            if ($LASTEXITCODE -ne 0 -or $active.Count -ne 0) {
                throw "Passport ingress opened before Rust write proof: $name"
            }
        }
    }
    return $check
}

function Invoke-RustOwnerTransition {
    $container = [string]$script:plan.postgres_container_id
    $phase = @(Invoke-BetaPsql -Sql `
        "SELECT phase FROM passport_cutover.state WHERE singleton=true;")
    if ($phase.Count -ne 1 -or $phase[0] -notin @('fully_fenced', 'rust_owner')) {
        throw 'Aggregate beta passport owner phase is invalid'
    }
    if ($phase[0] -ceq 'fully_fenced') {
        if ((Test-Path -LiteralPath $transitionPath) -or
            (Test-Path -LiteralPath $writePath)) {
            throw 'Rust owner receipt exists before database transition'
        }
        Assert-ForwardGeneration -RequireIngressClosed | Out-Null
        Assert-Render
        $sqlFiles = [ordered]@{
            'passport-beta-rust-owner-transition.sql' = 'transition_sql_sha256'
            'passport-beta-fence-verify.sql' = 'fence_verify_sql_sha256'
            'passport-beta-fence-drain.sql' = 'drain_sql_sha256'
            'passport-beta-rust-owner-verify.sql' = 'rust_owner_verify_sql_sha256'
        }
        $stage = '/tmp/marty-passport-rust-owner-' + [Guid]::NewGuid().ToString('N')
        & docker exec -u postgres $container mkdir -m 700 -- $stage | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Rust owner SQL stage could not be created' }
        try {
            foreach ($name in $sqlFiles.Keys) {
                $field = $sqlFiles[$name]
                $expected = [string]$script:plan.PSObject.Properties[$field].Value
                $path = Join-Path $root "scripts/sql/$name"
                if ($expected -notmatch '^[0-9a-f]{64}$' -or
                    (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() `
                        -cne $expected) {
                    throw "Protected Rust owner SQL changed: $name"
                }
                & docker cp $path "${container}:$stage/$name" | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "Rust owner SQL stage failed: $name" }
                $hash = @(& docker exec -u postgres $container sha256sum -- `
                    "$stage/$name" 2>$null)
                if ($LASTEXITCODE -ne 0 -or $hash.Count -ne 1 -or
                    $hash[0] -notmatch '^([0-9a-f]{64})  ' -or
                    $Matches[1] -cne $expected) {
                    throw "Staged Rust owner SQL changed: $name"
                }
            }
            Assert-Render
            $fenceRecheck = Invoke-Plan -Arguments @(
                (Join-Path $PSScriptRoot 'probe_passport_beta_fence_direct_writes.py'),
                '--postgres-container', $container,
                '--docker-context', [string]$script:intent.docker.context,
                '--daemon-id', [string]$script:intent.docker.daemon_id,
                '--system-identifier', [string]$script:plan.postgres_system_identifier,
                '--database-oid', [string]$script:plan.database_oid,
                '--fence-epoch', [string]$script:plan.fence_epoch)
            if ($fenceRecheck.schema -cne 'marty.passport-beta-fence-direct-probe/v1' -or
                $fenceRecheck.postgres_container_id -cne $container -or
                [string]$fenceRecheck.fence_epoch -cne [string]$script:plan.fence_epoch -or
                @($fenceRecheck.rejections.PSObject.Properties).Count -ne 3 -or
                [string]$fenceRecheck.receipt_sha256 -cnotmatch '^[0-9a-f]{64}$') {
                throw 'Valid beta passport job and Flow writes were not rejected before transition'
            }
            Replace-DurableJson -Path $fenceRecheckPath `
                -Json ($fenceRecheck | ConvertTo-Json -Depth 20 -Compress)
            Assert-FenceRecheckReceipt | Out-Null
            Assert-ForwardGeneration -RequireIngressClosed | Out-Null
            $previous = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $rows = @(& docker exec $container psql -X -U postgres -d marty `
                    -qAt -v ON_ERROR_STOP=1 `
                    -c "SET marty.passport_beta_verified_project = 'elevenid-beta'" `
                    -c "SET marty.passport_beta_expected_system_identifier = '$($script:plan.postgres_system_identifier)'" `
                    -c "SET marty.passport_beta_expected_database_oid = '$($script:plan.database_oid)'" `
                    -c "SET marty.passport_beta_expected_fence_epoch = '$($script:plan.fence_epoch)'" `
                    -c "SET marty.passport_beta_expected_source_commit = '$($script:plan.source_commit)'" `
                    -c "SET marty.passport_beta_expected_native_migration_sha256 = '$($script:plan.migration_set_sha256)'" `
                    -f "$stage/passport-beta-rust-owner-transition.sql" 2>$null)
                if ($LASTEXITCODE -ne 0 -or $rows.Count -lt 2) {
                    throw 'Atomic Rust owner SQL failed'
                }
            }
            finally { $ErrorActionPreference = $previous }
            $committed = $rows[-1] | ConvertFrom-Json -ErrorAction Stop
            if ($committed.schema -cne 'marty.passport-beta-rust-owner-transition/v1' -or
                $committed.phase -cne 'rust_owner' -or
                [string]$committed.fence_epoch -cne [string]$script:plan.fence_epoch) {
                throw 'Atomic Rust owner SQL returned a different transition'
            }
        }
        finally {
            foreach ($name in $sqlFiles.Keys) {
                & docker exec -u postgres $container rm -f -- "$stage/$name" 2>$null |
                    Out-Null
            }
            & docker exec -u postgres $container rmdir -- $stage 2>$null | Out-Null
        }
    }
    if (-not (Test-Path -LiteralPath $fenceRecheckPath)) {
        throw 'Pretransition valid write rejection receipt is missing'
    }
    Assert-FenceRecheckReceipt | Out-Null
    $proof = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'verify_passport_beta_rust_owner.py'),
        '--plan', $planPath)
    if ($proof.schema -cne 'marty.passport-beta-rust-owner-proof/v1' -or
        $proof.verified -ne $true -or
        $proof.source_commit -cne $script:plan.source_commit -or
        $proof.postgres_container_id -cne $container -or
        [string]$proof.fence_epoch -cne [string]$script:plan.fence_epoch) {
        throw 'Committed Rust owner differs from signed aggregate plan'
    }
    if (Test-Path -LiteralPath $transitionPath) {
        $recorded = Get-Content -LiteralPath $transitionPath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
        if (($recorded | ConvertTo-Json -Depth 20 -Compress) -cne
            ($proof | ConvertTo-Json -Depth 20 -Compress)) {
            throw 'Durable Rust owner receipt differs from database proof'
        }
    }
    else {
        Write-DurableJson -Path $transitionPath `
            -Json ($proof | ConvertTo-Json -Depth 20 -Compress)
    }
    return $proof
}

function Assert-PreservedOpenBao {
    $id = [string]$script:plan.old_container_ids_by_service.openbao
    $expected = @($script:intent.beta_generation | Where-Object { $_.service -ceq 'openbao' })
    $preserved = @($script:plan.preserved_infrastructure)
    if ($id -notmatch '^[0-9a-f]{64}$' -or
        $preserved.Count -ne 1 -or $preserved[0] -cne 'openbao' -or
        $expected.Count -ne 1 -or $expected[0].container_id -cne $id) {
        throw 'Aggregate beta preserved OpenBao plan is invalid'
    }
    $raw = @(& docker inspect $id 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'Preserved beta OpenBao is unavailable' }
    $items = @((($raw -join "`n") | ConvertFrom-Json -ErrorAction Stop))
    if ($items.Count -ne 1 -or $items[0].Id -cne $id -or
        $items[0].State.Running -ne $true -or
        $items[0].State.Status -cne 'running' -or
        $items[0].State.StartedAt -cne [string]$expected[0].started_at -or
        $items[0].Image -cne [string]$expected[0].image_id -or
        $items[0].Config.Labels.'com.docker.compose.project' -cne 'elevenid-beta' -or
        $items[0].Config.Labels.'com.docker.compose.service' -cne 'openbao') {
        throw 'Preserved beta OpenBao changed or stopped'
    }
    $probe = @'
            set -eu
            export VAULT_ADDR=http://127.0.0.1:8200
            export VAULT_TOKEN="$BAO_DEV_ROOT_TOKEN_ID"
            test -n "$VAULT_TOKEN"
            test "$(bao read -field=type transit/keys/passport-artifact-marty-aes256)" = aes256-gcm96
            test "$(bao read -field=exportable transit/keys/passport-artifact-marty-aes256)" = false
            test "$(bao read -field=type transit/keys/passport-bureau-callback-marty-hmac)" = hmac
            test "$(bao read -field=exportable transit/keys/passport-bureau-callback-marty-hmac)" = false
            test "$(bao read -field=type transit/keys/cred-dsc-marty-primary)" = ecdsa-p256
'@
    $payload = [Text.UTF8Encoding]::new($false).GetBytes(
        $probe.Replace("`r`n", "`n") + "`n")
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'docker.exe'
    $start.Arguments = "exec -i $id sh -s"
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'Preserved OpenBao probe did not start' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.BaseStream.Write($payload, 0, $payload.Length)
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            throw 'Preserved OpenBao probe timed out'
        }
        $null = $stdout.Result
        $null = $stderr.Result
        if ($process.ExitCode -ne 0) {
            throw 'Preserved beta OpenBao passport key capability is unavailable'
        }
    }
    finally { $process.Dispose() }
}

function Connect-PreservedOpenBao {
    $network = 'elevenid-beta-passport-callback-signing'
    $id = [string]$script:plan.old_container_ids_by_service.openbao
    $raw = @(& docker network inspect $network 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'Aggregate callback network is unavailable' }
    $items = @((($raw -join "`n") | ConvertFrom-Json -ErrorAction Stop))
    if ($items.Count -ne 1 -or $items[0].Name -cne $network -or
        $items[0].Internal -ne $true -or
        $items[0].Labels.'com.docker.compose.project' -cne 'elevenid-beta' -or
        $items[0].Labels.'com.docker.compose.network' -cne 'passport-callback-signing') {
        throw 'Aggregate callback network differs from protected beta Compose'
    }
    $members = @($items[0].Containers.PSObject.Properties.Name)
    $signer = @(& docker ps --all --filter 'label=com.docker.compose.project=elevenid-beta' `
        --filter 'label=com.docker.compose.service=passport-callback-signer' `
        --format '{{.ID}}' 2>$null)
    if ($LASTEXITCODE -ne 0 -or $signer.Count -ne 1) {
        throw 'Aggregate callback signer identity is ambiguous'
    }
    $signerId = @(& docker inspect --format '{{.Id}}' $signer[0] 2>$null)
    if ($LASTEXITCODE -ne 0 -or $signerId.Count -ne 1 -or
        $signerId[0] -notmatch '^[0-9a-f]{64}$') {
        throw 'Aggregate callback signer identity is invalid'
    }
    $allowed = @($id, $signerId[0])
    $bureau = @(& docker ps --all --filter 'label=com.docker.compose.project=elevenid-beta' `
        --filter 'label=com.docker.compose.service=passport-beta-bureau' `
        --format '{{.ID}}' 2>$null)
    if ($LASTEXITCODE -ne 0 -or $bureau.Count -gt 1) {
        throw 'Aggregate beta bureau identity is ambiguous'
    }
    if ($bureau.Count -eq 1) {
        $bureauId = @(& docker inspect --format '{{.Id}}' $bureau[0] 2>$null)
        if ($LASTEXITCODE -ne 0 -or $bureauId.Count -ne 1 -or
            $bureauId[0] -notmatch '^[0-9a-f]{64}$') {
            throw 'Aggregate beta bureau identity is invalid'
        }
        $allowed += $bureauId[0]
    }
    if (@($members | Where-Object { $_ -notin $allowed }).Count -ne 0 -or
        $signerId[0] -notin $members) {
        throw 'Aggregate callback network has unexpected members'
    }
    if ($id -notin $members) {
        & docker network connect --alias openbao $network $id | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Preserved OpenBao network attachment failed' }
    }
    Assert-PreservedOpenBao
}

function Start-OldBetaContainer {
    param([string]$Service)
    Assert-Render
    $id = [string]$script:plan.old_container_ids_by_service.$Service
    if ($id -notmatch '^[0-9a-f]{64}$') {
        throw 'Old beta infrastructure identity is invalid'
    }
    $state = @(& docker inspect --format '{{.Id}}|{{.State.Running}}|{{.State.Status}}' `
        $id 2>$null)
    if ($LASTEXITCODE -ne 0 -or $state.Count -ne 1 -or
        $state[0] -notmatch '^([0-9a-f]{64})\|(true|false)\|(running|exited)$' -or
        $Matches[1] -cne $id) {
        throw 'Old beta infrastructure state is invalid'
    }
    if ($Matches[2] -ceq 'false') {
        & docker start $id | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Old beta infrastructure failed to start' }
    }
}

$script:plan = $null
$script:productionRecoveryReady = $false
$script:productionRecoveryDigest = $null
$lock = Enter-BetaDeploymentLock -AllowPending
try {
    if (-not (Test-Path -LiteralPath (Get-BetaPassportFenceMarkerPath)) -or
        -not (Test-Path -LiteralPath (Get-BetaMutationMarkerPath)) -or
        -not (Test-Path -LiteralPath $MaintenanceReceipt) -or
        -not (Test-Path -LiteralPath $NativeReceipt) -or
        -not (Test-Path -LiteralPath $intentPath) -or
        (Test-Path -LiteralPath $output)) {
        throw 'Aggregate beta marker or receipt state is invalid'
    }
    $script:intent = Get-Content -LiteralPath $intentPath -Raw -Encoding UTF8 |
        ConvertFrom-Json -ErrorAction Stop
    $script:plannerArgs = @(
        (Join-Path $PSScriptRoot 'prepare_passport_beta_aggregate_compose.py'),
        '--stack-manifest', $StackManifest, '--fence-receipt', $FenceReceipt,
        '--maintenance-receipt', $MaintenanceReceipt, '--native-receipt', $NativeReceipt)
    $script:readyServices = @()
    $script:readyUi = $false
    $resuming = Test-Path -LiteralPath $planPath
    if ($resuming) {
        $script:plan = Get-Content -LiteralPath $planPath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
    }
    else {
        $script:plan = Invoke-Plan -Arguments $script:plannerArgs
        if ($script:plan.schema -cne 'marty.passport-beta-aggregate-compose-plan/v1' -or
            $script:plan.source_commit -notmatch '^[0-9a-f]{40}$') {
            throw 'Signed aggregate beta Compose plan is invalid'
        }
        Write-DurableJson -Path $planPath `
            -Json ($script:plan | ConvertTo-Json -Depth 30 -Compress)
    }
    if ([string]$script:plan.postgres_container_id -cne
        [string]$script:intent.postgres_container_id) {
        throw 'Aggregate beta database identity differs from maintenance intent'
    }
    $referenceOutputPreflight = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_reference_provision.py'),
        '--preflight-outputs', '--plan', $planPath,
        '--issuer-chain-file', $issuerChainPath,
        '--intent-dir', $referenceIntentPath,
        '--application-file', $applicationPath, '--flow-file', $flowPath)
    if ($referenceOutputPreflight.schema -cne
        'marty.passport-beta-reference-output-preflight/v1' -or
        $referenceOutputPreflight.verified -ne $true) {
        throw 'Beta passport reference outputs failed preflight'
    }
    $loginBefore = @(Invoke-BetaPsql -Sql `
        "SELECT rolcanlogin FROM pg_roles WHERE rolname='marty';")
    if ($loginBefore.Count -ne 1 -or $loginBefore[0] -notin @('t', 'f')) {
        throw 'Aggregate beta app role is unavailable'
    }
    if ($loginBefore[0] -ceq 't') {
        if (-not $resuming) {
            throw 'Aggregate beta app login opened without a durable deployment plan'
        }
        $exact = Invoke-Plan -Arguments ($script:plannerArgs + @(
            '--verify-resume-plan', $planPath))
        if ($exact.schema -cne 'marty.passport-beta-aggregate-resume-check/v1' -or
            $exact.verified -ne $true -or
            $exact.app_login_enabled -ne $true) {
            throw 'Aggregate beta forward resume differs from signed plan'
        }
        $script:readyServices = @($exact.ready_services)
        $script:readyUi = ($exact.ready_ui -eq $true)
    }
    else {
        $exact = Invoke-Plan -Arguments ($script:plannerArgs + @('--verify-plan', $planPath))
        if ($exact.schema -cne 'marty.passport-beta-aggregate-plan-check/v1' -or
            $exact.verified -ne $true) {
            throw 'Aggregate beta plan changed before database handoff'
        }
    }
    if ([string]$script:plan.production_attachments_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Maintenance-bound production network baseline is invalid'
    }
    if ([string]$script:plan.beta_origin -cne 'https://beta.elevenidllc.com') {
        throw 'Aggregate deployment plan has the wrong public beta origin'
    }
    $null = Assert-ProductionContinuity
    $recoveryBaseline = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'recover_passport_beta_production.py'),
        '--capture', '--output', $productionRecoveryPath)
    if ($recoveryBaseline.schema -cne 'marty.passport-beta-production-recovery-capture/v1' -or
        [string]$recoveryBaseline.baseline_sha256 -notmatch '^[0-9a-f]{64}$' -or
        $recoveryBaseline.snapshot_sha256 -cne [string]$script:plan.production_snapshot_sha256 -or
        $recoveryBaseline.attachments_sha256 -cne [string]$script:plan.production_attachments_sha256 -or
        $recoveryBaseline.docker.context -cne [string]$script:intent.docker.context -or
        $recoveryBaseline.docker.daemon_id -cne [string]$script:intent.docker.daemon_id) {
        throw 'Production recovery baseline differs from protected maintenance plan'
    }
    $script:productionRecoveryDigest = [string]$recoveryBaseline.baseline_sha256
    $script:productionRecoveryReady = $true
    $null = Assert-ProductionContinuity
    $env:MARTY_SERVICES_IMAGE = [string]$script:plan.services_image
    $env:MARTY_UI_RELEASE_IMAGE = [string]$script:plan.ui_image
    $expectedBuildVars = @(
        'MARTY_COMMON_URI', 'MARTY_COMMON_DIGEST',
        'MARTY_RS_URI', 'MARTY_RS_DIGEST',
        'MARTY_VERIFICATION_URI', 'MARTY_VERIFICATION_DIGEST',
        'MARTY_ISO18013_URI', 'MARTY_ISO18013_DIGEST')
    $actualBuildVars = @($script:plan.build_only_artifacts.PSObject.Properties.Name)
    if ($actualBuildVars.Count -ne $expectedBuildVars.Count -or
        @($actualBuildVars | Where-Object { $_ -notin $expectedBuildVars }).Count -ne 0) {
        throw 'Signed beta build-only artifact bindings are invalid'
    }
    foreach ($name in $expectedBuildVars) {
        [Environment]::SetEnvironmentVariable(
            $name, [string]$script:plan.build_only_artifacts.$name, 'Process')
    }
    if ([string]$script:plan.docs_image -notmatch '^sha256:[0-9a-f]{64}$') {
        throw 'Preserved beta docs image is not immutable'
    }
    $env:MARTY_DOCS_IMAGE = [string]$script:plan.docs_image
    $env:MARTY_NETWORK_NAME = 'elevenid-beta-network'
    Assert-Render
    Assert-PreservedIngressOrigin
    Assert-PreservedOpenBao
    Assert-OpenBaoToken
    foreach ($image in @($script:plan.services_image, $script:plan.ui_image)) {
        & docker pull $image | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Signed aggregate beta image pull failed' }
    }
    Assert-Render
    $enablePath = Join-Path $root 'scripts/sql/passport-beta-db-enable-app-login.sql'
    $actualSql = (Get-FileHash -LiteralPath $enablePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSql -cne [string]$script:plan.enable_login_sql_sha256) {
        throw 'Protected aggregate beta app-login SQL changed'
    }
    $session = "SET marty.passport_beta_verified_project = 'elevenid-beta';`n" +
        "SET marty.passport_beta_expected_system_identifier = '$($script:plan.postgres_system_identifier)';`n" +
        "SET marty.passport_beta_expected_database_oid = '$($script:plan.database_oid)';`n" +
        "SET marty.passport_beta_expected_fence_epoch = '$($script:plan.fence_epoch)';`n" +
        "SET marty.passport_beta_expected_source_commit = '$($script:plan.source_commit)';`n" +
        "SET marty.passport_beta_expected_native_migration_sha256 = '$($script:plan.migration_set_sha256)';`n"
    $sql = [Text.UTF8Encoding]::new($false, $true).GetString(
        [IO.File]::ReadAllBytes($enablePath))
    if ($loginBefore[0] -ceq 'f') {
        Invoke-BetaPsql -Sql ($session + $sql) | Out-Null
    }
    $login = @(Invoke-BetaPsql -Sql "SELECT rolcanlogin FROM pg_roles WHERE rolname='marty';")
    if ($login.Count -ne 1 -or $login[0] -cne 't') {
        throw 'Aggregate beta app login did not open after native gates'
    }
    Invoke-SignedIssuanceMigration
    $old = $script:plan.old_container_ids_by_service
    $infra = @($script:plan.restart_infrastructure |
        Sort-Object { [Array]::IndexOf(@('redis','keycloak'), [string]$_) })
    foreach ($name in $infra) {
        Start-OldBetaContainer -Service $name
    }
    Wait-BetaHealthy -Services $infra
    Invoke-Compose -Services @('passport-callback-signer')
    Connect-PreservedOpenBao
    Wait-BetaHealthy -Services @('passport-callback-signer')
    Invoke-Compose -Services @('passport-beta-bureau')
    Wait-BetaHealthy -Services @('passport-beta-bureau')
    $applications = @($script:plan.recreate_applications | Where-Object {
        $_ -notin @('passport-callback-signer', 'passport-beta-bureau') })
    Invoke-Compose -Services $applications
    Wait-BetaHealthy -Services $applications
    $resumingAfterContinuity = Test-Path -LiteralPath $continuityPath
    Assert-ForwardGeneration -RequireIngressClosed:(-not $resumingAfterContinuity) |
        Out-Null
    $references = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_reference_provision.py'),
        '--phase', 'references', '--plan', $planPath,
        '--issuer-chain-file', $issuerChainPath,
        '--session-file', $sessionPath, '--dsc-session-file', $dscSessionPath,
        '--intent-dir', $referenceIntentPath,
        '--application-file', $applicationPath)
    if ($references.schema -cne 'marty.passport-beta-reference-provision/v1' -or
        $references.phase -cne 'references' -or
        $references.verified -ne $true -or
        $references.source_commit -cne $script:plan.source_commit -or
        [string]$references.gateway_container_id -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$references.application_file_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Pilot beta passport references were not provisioned by staged Gateway'
    }
    $applicationProof = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_rust_owner_write.py'),
        '--plan', $planPath, '--application-file', $applicationPath,
        '--validate-only')
    if ($applicationProof.schema -cne 'marty.passport-beta-rust-owner-input/v1' -or
        $applicationProof.source_commit -cne $script:plan.source_commit -or
        [string]$applicationProof.application_file_sha256 -cne
            [string]$references.application_file_sha256) {
        throw 'Private Rust passport probe input differs from staged references'
    }
    $phaseBeforeTransition = @(Invoke-BetaPsql -Sql `
        "SELECT phase FROM passport_cutover.state WHERE singleton=true;")
    if ($phaseBeforeTransition.Count -ne 1 -or
        $phaseBeforeTransition[0] -notin @('fully_fenced', 'rust_owner')) {
        throw 'Passport ownership phase changed before private beta validation'
    }
    if ($phaseBeforeTransition[0] -ceq 'fully_fenced') {
        $pretransition = Invoke-Plan -Arguments @(
            (Join-Path $PSScriptRoot 'probe_passport_beta_credentials_continuity.py'),
            '--plan', $planPath, '--pretransition')
        if ($pretransition.schema -cne 'marty.passport-beta-credentials-pretransition/v1' -or
            $pretransition.verified -ne $true -or
            $pretransition.source_commit -cne $script:plan.source_commit -or
            $pretransition.postgres_container_id -cne $script:plan.postgres_container_id -or
            [string]$pretransition.fence_epoch -cne [string]$script:plan.fence_epoch -or
            $pretransition.issuance_image -cne $script:plan.services_image -or
            $pretransition.rust_passport_capabilities_verified -ne $true -or
            $pretransition.unrelated_issuance_nonce_write_verified -ne $true -or
            [string]$pretransition.receipt_sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Signed Rust issuance lacks pretransition passport proof'
        }
        Replace-DurableJson -Path $credentialsPretransitionPath `
            -Json ($pretransition | ConvertTo-Json -Depth 20 -Compress)
    }
    if (-not (Test-Path -LiteralPath $credentialsPretransitionPath)) {
        throw 'Replacement Credentials pretransition receipt is missing'
    }
    $pretransitionCheck = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_credentials_continuity.py'),
        '--plan', $planPath,
        '--verify-pretransition-receipt', $credentialsPretransitionPath)
    if ($pretransitionCheck.schema -cne
            'marty.passport-beta-credentials-pretransition-check/v1' -or
        $pretransitionCheck.verified -ne $true -or
        $pretransitionCheck.source_commit -cne $script:plan.source_commit -or
        $pretransitionCheck.postgres_container_id -cne
            $script:plan.postgres_container_id -or
        [string]$pretransitionCheck.fence_epoch -cne [string]$script:plan.fence_epoch -or
        $pretransitionCheck.issuance_image -cne $script:plan.services_image -or
        [string]$pretransitionCheck.receipt_file_sha256 -cne
            (Get-FileHash -LiteralPath $credentialsPretransitionPath `
                -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'Replacement Credentials pretransition receipt changed'
    }
    $ceremonyProof = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_aggregate_ceremony.py'),
        '--plan', $planPath, '--application-file', $applicationPath,
        '--issuer-chain-file', $issuerChainPath,
        '--ceremony-file', $issuerCeremonyPath,
        '--csca-session-file', $cscaSessionPath,
        '--dsc-session-file', $dscSessionPath,
        '--intent', $ceremonyIntentPath)
    $ceremonyHash = (Get-FileHash -LiteralPath $issuerCeremonyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ceremonyProof.schema -cne 'marty.passport-beta-aggregate-ceremony/v1' -or
        $ceremonyProof.verified -ne $true -or
        $ceremonyProof.source_commit -cne $script:plan.source_commit -or
        $ceremonyProof.application_file_sha256 -cne [string]$applicationProof.application_file_sha256 -or
        $ceremonyProof.issuer_chain_file_sha256 -cne
            (Get-FileHash -LiteralPath $issuerChainPath -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $ceremonyProof.ceremony_file_sha256 -cne $ceremonyHash -or
        $ceremonyProof.intent_file_sha256 -cne
            (Get-FileHash -LiteralPath $ceremonyIntentPath -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $ceremonyProof.gateway_container_id -cnotmatch '^[0-9a-f]{64}$' -or
        $ceremonyProof.gateway_request_traces_verified -ne $true -or
        $ceremonyProof.profile_creation_verified -ne $true -or
        $ceremonyProof.certificate_chain_verified -ne $true) {
        throw 'Governed beta issuer ceremony did not complete through signed Gateway'
    }
    $ceremonyJson = $ceremonyProof | ConvertTo-Json -Depth 20 -Compress
    if (Test-Path -LiteralPath $ceremonyPath) {
        $recordedCeremony = Get-Content -LiteralPath $ceremonyPath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
        if (($recordedCeremony | ConvertTo-Json -Depth 20 -Compress) -cne $ceremonyJson) {
            throw 'Durable beta issuer ceremony differs from current signed Gateway'
        }
    }
    else {
        Write-DurableJson -Path $ceremonyPath -Json $ceremonyJson
    }
    $kmsProof = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_aggregate_kms.py'),
        '--plan', $planPath, '--application-file', $applicationPath,
        '--issuer-chain-file', $issuerChainPath)
    $issuerChainHash = (Get-FileHash -LiteralPath $issuerChainPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($kmsProof.schema -cne 'marty.passport-beta-aggregate-kms-pretransition/v1' -or
        $kmsProof.verified -ne $true -or
        $kmsProof.source_commit -cne $script:plan.source_commit -or
        $kmsProof.application_file_sha256 -cne [string]$applicationProof.application_file_sha256 -or
        [string]$kmsProof.issuer_chain_file_sha256 -cne $issuerChainHash -or
        [string]$kmsProof.signing_keys_container_id -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$kmsProof.openbao_container_id -cne
            [string]$script:plan.old_container_ids_by_service.openbao -or
        $kmsProof.managed_kms_custody_verified -ne $true -or
        $kmsProof.chain_verified -ne $true -or
        $kmsProof.csca_certificate_sha256 -cne $ceremonyProof.csca_certificate_sha256 -or
        $kmsProof.dsc_certificate_sha256 -cne $ceremonyProof.dsc_certificate_sha256 -or
        $kmsProof.private_key_exported -ne $false) {
        throw 'Selected beta issuer chain lacks current managed KMS proof'
    }
    $kmsJson = $kmsProof | ConvertTo-Json -Depth 20 -Compress
    if (Test-Path -LiteralPath $kmsPretransitionPath) {
        $recordedKms = Get-Content -LiteralPath $kmsPretransitionPath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
        if (($recordedKms | ConvertTo-Json -Depth 20 -Compress) -cne $kmsJson) {
            throw 'Durable beta issuer KMS proof differs from current live chain'
        }
    }
    else {
        Write-DurableJson -Path $kmsPretransitionPath -Json $kmsJson
    }
    $dependencyOutput = & docker exec $pretransitionCheck.issuance_container_id `
        /usr/local/bin/marty-issuance-service probe-dependencies
    if ($LASTEXITCODE -ne 0) {
        throw 'Signed Rust issuance dependency probe failed before owner transition'
    }
    $dependency = $dependencyOutput | ConvertFrom-Json -ErrorAction Stop
    if ($dependency.schema -cne 'marty.issuance-dependency-probe/v1' -or
        $dependency.verified -ne $true) {
        throw 'Signed Rust issuance dependency probe did not verify before owner transition'
    }
    $dependencyReceipt = [ordered]@{
        schema = 'marty.passport-beta-issuance-dependency/v1'
        source_commit = $script:plan.source_commit
        services_image = $script:plan.services_image
        issuance_container_id = $pretransitionCheck.issuance_container_id
        postgres_container_id = $script:plan.postgres_container_id
        verified = $true
    }
    $dependencyJson = $dependencyReceipt | ConvertTo-Json -Depth 5 -Compress
    if (Test-Path -LiteralPath $issuanceDependencyPath) {
        $priorDependency = Get-Content -LiteralPath $issuanceDependencyPath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
        if (($priorDependency | ConvertTo-Json -Depth 5 -Compress) -cne $dependencyJson) {
            throw 'Prior Rust issuance dependency receipt differs on resume'
        }
    }
    else {
        Write-DurableJson -Path $issuanceDependencyPath -Json $dependencyJson
    }
    $owner = Invoke-RustOwnerTransition
    $firstWriteAttempt = -not (Test-Path -LiteralPath $writeIntentPath)
    if ($firstWriteAttempt) {
        $writeIntent = [ordered]@{
            schema = 'marty.passport-beta-rust-owner-write-intent/v1'
            source_commit = $script:plan.source_commit
            transition_txid = [string]$owner.transition_txid
            application_file_sha256 = [string]$applicationProof.application_file_sha256
            flow_execution_id = 'rust-owner-' + [Guid]::NewGuid().ToString('N')
        }
        Write-DurableJson -Path $writeIntentPath `
            -Json ($writeIntent | ConvertTo-Json -Depth 10 -Compress)
    }
    else {
        $writeIntent = Get-Content -LiteralPath $writeIntentPath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
    }
    if ($writeIntent.schema -cne 'marty.passport-beta-rust-owner-write-intent/v1' -or
        $writeIntent.source_commit -cne $script:plan.source_commit -or
        [string]$writeIntent.transition_txid -cne [string]$owner.transition_txid -or
        [string]$writeIntent.application_file_sha256 -cne
            [string]$applicationProof.application_file_sha256 -or
        [string]$writeIntent.flow_execution_id -cnotmatch '^rust-owner-[0-9a-f]{32}$') {
        throw 'Private Rust passport write intent differs from committed owner or input'
    }
    $writeArguments = @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_rust_owner_write.py'),
        '--plan', $planPath, '--application-file', $applicationPath,
        '--intent', $writeIntentPath, '--receipt', $writePath)
    $write = Invoke-Plan -Arguments $writeArguments
    if ($write.schema -cne 'marty.passport-beta-rust-owner-write/v1' -or
        $write.source_commit -cne $script:plan.source_commit -or
        [string]$write.transition_txid -cne [string]$owner.transition_txid -or
        [string]$write.application_file_sha256 -cne
            [string]$applicationProof.application_file_sha256 -or
        $write.database_row_verified -ne $true) {
        throw 'Private Rust passport write proof is invalid'
    }
    if (Test-Path -LiteralPath $writePath) {
        $recordedWrite = Get-Content -LiteralPath $writePath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
        if (($recordedWrite | ConvertTo-Json -Depth 20 -Compress) -cne
            ($write | ConvertTo-Json -Depth 20 -Compress)) {
            throw 'Durable private Rust write receipt differs from live proof'
        }
    }
    else {
        Write-DurableJson -Path $writePath `
            -Json ($write | ConvertTo-Json -Depth 20 -Compress)
    }
    Assert-ForwardGeneration -RequireIngressClosed:(-not $resumingAfterContinuity) |
        Out-Null
    $flowProvision = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_reference_provision.py'),
        '--phase', 'flow', '--plan', $planPath,
        '--issuer-chain-file', $issuerChainPath,
        '--session-file', $sessionPath, '--intent-dir', $referenceIntentPath,
        '--application-file', $applicationPath, '--flow-file', $flowPath)
    if ($flowProvision.schema -cne 'marty.passport-beta-reference-provision/v1' -or
        $flowProvision.phase -cne 'flow' -or
        $flowProvision.verified -ne $true -or
        $flowProvision.source_commit -cne $script:plan.source_commit -or
        [string]$flowProvision.gateway_container_id -cne
            [string]$references.gateway_container_id -or
        [string]$flowProvision.application_file_sha256 -cne
            [string]$applicationProof.application_file_sha256 -or
        [string]$flowProvision.flow_file_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Pilot beta physical Flow was not provisioned by staged Gateway'
    }
    $flowReferences = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_rust_owner_flow.py'),
        '--plan', $planPath, '--flow-file', $flowPath,
        '--application-file', $applicationPath,
        '--session-file', $sessionPath, '--validate-only')
    if ($flowReferences.schema -cne 'marty.passport-beta-rust-owner-flow-references/v1' -or
        $flowReferences.verified -ne $true -or
        $flowReferences.source_commit -cne $script:plan.source_commit -or
        [string]$flowReferences.application_file_sha256 -cne
            [string]$applicationProof.application_file_sha256 -or
        [string]$flowReferences.flow_file_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$flowReferences.gateway_container_id -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$flowReferences.flow_container_id -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Live private Flow references differ from beta application input'
    }
    $firstFlowAttempt = -not (Test-Path -LiteralPath $flowWriteIntentPath)
    if ($firstFlowAttempt) {
        $flowWriteIntent = [ordered]@{
            schema = 'marty.passport-beta-rust-owner-flow-intent/v1'
            source_commit = $script:plan.source_commit
            transition_txid = [string]$owner.transition_txid
            flow_file_sha256 = [string]$flowReferences.flow_file_sha256
            application_file_sha256 = [string]$applicationProof.application_file_sha256
            external_reference = 'rust-owner-flow-' + [Guid]::NewGuid().ToString('N')
        }
        Write-DurableJson -Path $flowWriteIntentPath `
            -Json ($flowWriteIntent | ConvertTo-Json -Depth 10 -Compress)
    }
    else {
        $flowWriteIntent = Get-Content -LiteralPath $flowWriteIntentPath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
    }
    if ($flowWriteIntent.schema -cne 'marty.passport-beta-rust-owner-flow-intent/v1' -or
        $flowWriteIntent.source_commit -cne $script:plan.source_commit -or
        [string]$flowWriteIntent.transition_txid -cne [string]$owner.transition_txid -or
        [string]$flowWriteIntent.flow_file_sha256 -cne
            [string]$flowReferences.flow_file_sha256 -or
        [string]$flowWriteIntent.application_file_sha256 -cne
            [string]$applicationProof.application_file_sha256 -or
        [string]$flowWriteIntent.external_reference -cnotmatch
            '^rust-owner-flow-[0-9a-f]{32}$') {
        throw 'Private Rust Flow intent differs from committed owner or input'
    }
    $flowWrite = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_rust_owner_flow.py'),
        '--plan', $planPath, '--flow-file', $flowPath,
        '--application-file', $applicationPath,
        '--session-file', $sessionPath,
        '--intent', $flowWriteIntentPath, '--receipt', $flowWritePath)
    if ($flowWrite.schema -cne 'marty.passport-beta-rust-owner-flow/v1' -or
        $flowWrite.source_commit -cne $script:plan.source_commit -or
        [string]$flowWrite.transition_txid -cne [string]$owner.transition_txid -or
        [string]$flowWrite.flow_file_sha256 -cne
            [string]$flowReferences.flow_file_sha256 -or
        [string]$flowWrite.application_file_sha256 -cne
            [string]$applicationProof.application_file_sha256 -or
        $flowWrite.flow_and_job_rows_verified -ne $true -or
        [string]$flowWrite.gateway_write_route_request_id -cnotmatch
            '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
        $flowWrite.gateway_container_id -cne $flowReferences.gateway_container_id -or
        $flowWrite.flow_container_id -cne $flowReferences.flow_container_id) {
        throw 'Private Rust physical Flow write proof is invalid'
    }
    if (Test-Path -LiteralPath $flowWritePath) {
        $recordedFlow = Get-Content -LiteralPath $flowWritePath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
        if (($recordedFlow | ConvertTo-Json -Depth 20 -Compress) -cne
            ($flowWrite | ConvertTo-Json -Depth 20 -Compress)) {
            throw 'Durable private Rust Flow receipt differs from live proof'
        }
    }
    else {
        Write-DurableJson -Path $flowWritePath `
            -Json ($flowWrite | ConvertTo-Json -Depth 20 -Compress)
    }
    if ($resumingAfterContinuity) {
        $continuity = Get-Content -LiteralPath $continuityPath -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
    }
    else {
        Assert-ForwardGeneration -RequireIngressClosed | Out-Null
        $continuity = Invoke-Plan -Arguments @(
            (Join-Path $PSScriptRoot 'probe_passport_beta_credentials_continuity.py'),
            '--plan', $planPath)
    }
    if ($continuity.schema -cne 'marty.passport-beta-credentials-continuity/v1' -or
        $continuity.verified -ne $true -or
        $continuity.source_commit -cne $script:plan.source_commit -or
        [string]$continuity.transition_txid -cne [string]$owner.transition_txid -or
        [string]$continuity.issuance_container_id -cnotmatch '^[0-9a-f]{64}$' -or
        $continuity.issuance_container_id -cne
            $pretransitionCheck.issuance_container_id -or
        $continuity.issuance_image -cne $script:plan.services_image -or
        $continuity.rust_passport_capabilities_verified -ne $true -or
        $continuity.unrelated_issuance_nonce_write_verified -ne $true -or
        [string]$continuity.nonce_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Rust passport or unrelated issuance continuity proof is invalid'
    }
    if (-not $resumingAfterContinuity) {
        Write-DurableJson -Path $continuityPath `
            -Json ($continuity | ConvertTo-Json -Depth 20 -Compress)
    }
    else {
        $continuityResume = Invoke-Plan -Arguments @(
            (Join-Path $PSScriptRoot 'probe_passport_beta_credentials_continuity.py'),
            '--plan', $planPath, '--verify-resume', $continuityPath)
        if ($continuityResume.schema -cne
                'marty.passport-beta-credentials-continuity-resume/v1' -or
            $continuityResume.verified -ne $true -or
            $continuityResume.source_commit -cne $script:plan.source_commit -or
            [string]$continuityResume.transition_txid -cne
                [string]$owner.transition_txid -or
            $continuityResume.issuance_container_id -cne
                $continuity.issuance_container_id -or
            $continuityResume.issuance_image -cne $script:plan.services_image -or
            $continuityResume.rust_passport_capabilities_verified -ne $true -or
            $continuityResume.unrelated_issuance_nonce_write_verified -ne $true -or
            [string]$continuityResume.prior_receipt_sha256 -cne
                (Get-FileHash -LiteralPath $continuityPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
            throw 'Credentials continuity changed during forward resume'
        }
    }
    Assert-ForwardGeneration -RequireIngressClosed:(-not $resumingAfterContinuity) |
        Out-Null
    Invoke-Compose -Services @($script:plan.recreate_ingress_last)
    Wait-BetaHealthy -Services @($script:plan.recreate_ingress_last)
    foreach ($name in @($script:plan.restart_ingress_last)) {
        Start-OldBetaContainer -Service $name
    }
    Wait-BetaHealthy -Services @($script:plan.restart_ingress_last)
    Invoke-Compose -Ui
    Wait-BetaHealthy -Services @('ui-prod') -Ui
    $runtime = Invoke-Plan -Arguments @(
        (Join-Path $PSScriptRoot 'verify_passport_beta_aggregate_runtime.py'),
        '--plan', $planPath, '--maintenance-intent', $intentPath,
        '--production-attachments-sha256',
        [string]$script:plan.production_attachments_sha256)
    if ($null -eq $runtime.beta_runtime -or
        $null -eq $runtime.beta_runtime.PSObject.Properties['issuance-native']) {
        throw 'Aggregate beta runtime has no signed native issuance process'
    }
    if ($runtime.schema -cne 'marty.passport-beta-aggregate-runtime/v1' -or
        $runtime.verified -ne $true -or
        $runtime.source_commit -cne $script:plan.source_commit -or
        [string]$runtime.rust_owner.transition_txid -cne
            [string]$owner.transition_txid -or
        [string]$runtime.beta_runtime.PSObject.Properties['issuance-native'].Value.container_id `
            -cne [string]$write.issuance_container_id -or
        @($runtime.beta_runtime.PSObject.Properties).Count -ne @($runtime.beta_services).Count -or
        $null -eq $runtime.ui_runtime) {
        throw 'Aggregate beta runtime did not match signed Rust plan'
    }
    # Preserve the exact protected lineage beside the final receipt. The
    # acceptance runner rechecks these bytes and the live native SQL marker.
    [IO.File]::Copy([IO.Path]::GetFullPath($FenceReceipt),
        $output + '.fence-receipt.json', $true)
    [IO.File]::Copy([IO.Path]::GetFullPath($MaintenanceReceipt),
        $output + '.maintenance-receipt.json', $true)
    [IO.File]::Copy($intentPath, $output + '.maintenance-intent.json', $true)
    [IO.File]::Copy([IO.Path]::GetFullPath($NativeReceipt),
        $output + '.native-receipt.json', $true)
    $receipt = [ordered]@{
        schema = 'marty.passport-beta-aggregate-deployment/v1'
        beta_origin = $script:plan.beta_origin
        source_commit = $script:plan.source_commit
        plan_sha256 = (Get-FileHash -LiteralPath $planPath -Algorithm SHA256).Hash.ToLowerInvariant()
        native_receipt_sha256 = $script:plan.native_receipt_sha256
        issuance_migration_receipt_sha256 = (Get-FileHash `
            -LiteralPath $issuanceMigrationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        transition_receipt_sha256 = (Get-FileHash -LiteralPath $transitionPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        rust_owner = $runtime.rust_owner
        private_rust_write_receipt_sha256 = (Get-FileHash -LiteralPath $writePath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        private_rust_write = $write
        private_rust_flow_receipt_sha256 = (Get-FileHash -LiteralPath $flowWritePath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        private_rust_flow = $flowWrite
        credentials_continuity_receipt_sha256 = (Get-FileHash -LiteralPath $continuityPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        credentials_continuity = $continuity
        issuance_dependency_receipt_sha256 = (Get-FileHash -LiteralPath $issuanceDependencyPath -Algorithm SHA256).Hash.ToLowerInvariant()
        credentials_pretransition_receipt_sha256 = (Get-FileHash `
            -LiteralPath $credentialsPretransitionPath -Algorithm SHA256).Hash.ToLowerInvariant()
        credentials_pretransition = $pretransitionCheck
        issuer_ceremony_receipt_sha256 = (Get-FileHash -LiteralPath $ceremonyPath -Algorithm SHA256).Hash.ToLowerInvariant()
        issuer_ceremony = $ceremonyProof
        kms_pretransition_receipt_sha256 = (Get-FileHash -LiteralPath $kmsPretransitionPath -Algorithm SHA256).Hash.ToLowerInvariant()
        kms_pretransition = $kmsProof
        pretransition_fence_receipt_sha256 = (Get-FileHash `
            -LiteralPath $fenceRecheckPath -Algorithm SHA256).Hash.ToLowerInvariant()
        cutover_snapshot_file_sha256 = $script:plan.cutover_snapshot_file_sha256
        cutover_snapshot_sha256 = $script:plan.cutover_snapshot_sha256
        cutover_report_file_sha256 = $script:plan.cutover_report_file_sha256
        cutover_report_run_id = $script:plan.cutover_report_run_id
        legacy_writer_container_id = $script:plan.legacy_writer_container_id
        legacy_writer_image_digest = $script:plan.legacy_writer_image_digest
        legacy_writer_started_at = $script:plan.legacy_writer_started_at
        legacy_writer_generation = $script:plan.legacy_writer_generation
        production_snapshot_sha256 = $runtime.production_snapshot_sha256
        production_public_route = $runtime.production_public_route
        beta_services = $runtime.beta_services
        beta_runtime = $runtime.beta_runtime
        ui_container_id = $runtime.ui_container_id
        ui_runtime = $runtime.ui_runtime
        acceptance_pending = $true
    }
    Write-DurableJson -Path $output `
        -Json ($receipt | ConvertTo-Json -Depth 20 -Compress)
    Write-Output $output
}
catch {
    $deploymentFailure = $_
    Write-ProductionPostflight
    throw $deploymentFailure
}
finally { Exit-BetaDeploymentLock -Lock $lock }
