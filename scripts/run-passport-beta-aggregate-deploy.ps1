param(
    [Parameter(Mandatory = $true)][string]$StackManifest,
    [Parameter(Mandatory = $true)][string]$FenceReceipt,
    [Parameter(Mandatory = $true)][string]$MaintenanceReceipt,
    [Parameter(Mandatory = $true)][string]$NativeReceipt,
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
$intentPath = [IO.Path]::GetFullPath($MaintenanceReceipt) + '.intent.json'
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
    $env:MARTY_SERVICES_IMAGE = [string]$script:plan.services_image
    $env:MARTY_ISSUANCE_IMAGE = [string]$script:plan.issuance_image
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
    foreach ($image in @($script:plan.services_image, $script:plan.issuance_image,
            $script:plan.ui_image)) {
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
    if ($runtime.schema -cne 'marty.passport-beta-aggregate-runtime/v1' -or
        $runtime.verified -ne $true -or
        $runtime.source_commit -cne $script:plan.source_commit -or
        $null -eq $runtime.beta_runtime -or
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
        production_snapshot_sha256 = $runtime.production_snapshot_sha256
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
finally { Exit-BetaDeploymentLock -Lock $lock }
