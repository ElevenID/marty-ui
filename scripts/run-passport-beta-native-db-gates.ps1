param(
    [Parameter(Mandatory = $true)][string]$StackManifest,
    [Parameter(Mandatory = $true)][string]$FenceReceipt,
    [Parameter(Mandatory = $true)][string]$MaintenanceReceipt,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

# Runs after the protected maintenance-start operator. It does not start any
# service or clear the pending beta mutation marker; the aggregate deploy owns
# Rust validate-mode startup and acceptance.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Protected beta native database gate requires the Windows beta host'
}
$repo = Split-Path -Parent $PSScriptRoot
$repoAbsolute = [IO.Path]::GetFullPath($repo).TrimEnd([IO.Path]::DirectorySeparatorChar)
if (-not [IO.Path]::IsPathRooted($OutputPath)) {
    throw 'Beta native database receipt path must be absolute'
}
$outputAbsolute = [IO.Path]::GetFullPath($OutputPath)
if ($outputAbsolute.StartsWith(
        $repoAbsolute + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Beta native database receipt must be outside protected source'
}
$sqlStage = $outputAbsolute + '.native.sql'
$intent = [IO.Path]::GetFullPath($MaintenanceReceipt) + '.intent.json'
. (Join-Path $PSScriptRoot 'beta-deployment-lock.ps1')
. (Join-Path $PSScriptRoot 'beta-passport-fence-legacy-boundary.ps1')

function Invoke-PlanPython {
    param([string[]]$Arguments)
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $rows = @(& python @Arguments 2>$null)
        if ($LASTEXITCODE -ne 0 -or $rows.Count -ne 1) {
            throw 'Protected beta native database plan check failed'
        }
        return ($rows[0] | ConvertFrom-Json -ErrorAction Stop)
    }
    finally { $ErrorActionPreference = $previous }
}

function Invoke-BetaPsql {
    param([string]$Container, [string]$Sql)
    if ($Container -notmatch '^[0-9a-f]{64}$') {
        throw 'Beta PostgreSQL container identity is invalid'
    }
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $rows = @($Sql | & docker exec -i $Container psql -X -U postgres `
            -d marty -qAt -v ON_ERROR_STOP=1 -f - 2>$null)
        if ($LASTEXITCODE -ne 0) { throw 'Protected beta database SQL failed' }
        return $rows
    }
    finally { $ErrorActionPreference = $previous }
}

function Get-BytesSha256 {
    param([byte[]]$Bytes)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $digest = $hasher.ComputeHash($Bytes) }
    finally { $hasher.Dispose() }
    return ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
}

function Read-ExactSql {
    param([string]$Relative, [string]$ExpectedSha256)
    if ($ExpectedSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Protected beta SQL digest is invalid'
    }
    $bytes = [IO.File]::ReadAllBytes((Join-Path $repo $Relative))
    if ((Get-BytesSha256 -Bytes $bytes) -cne $ExpectedSha256) {
        throw "Protected beta SQL changed: $Relative"
    }
    $sql = [Text.UTF8Encoding]::new($false, $true).GetString($bytes).Replace("`r`n", "`n")
    if ($sql.Contains("`r")) { throw "Protected beta SQL line endings changed: $Relative" }
    return $sql
}

function Invoke-ExactNativeSql {
    param([string]$Container, [byte[]]$Payload)
    if ($Container -notmatch '^[0-9a-f]{64}$' -or $Payload.Length -eq 0) {
        throw 'Exact native SQL target or payload is invalid'
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'docker.exe'
    $start.Arguments = "exec -i $Container psql -X -U postgres -d marty -qAt -v ON_ERROR_STOP=1 -f -"
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'Could not start exact native SQL executor' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.BaseStream.Write($Payload, 0, $Payload.Length)
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(600000)) {
            $process.Kill()
            throw 'Exact native SQL executor timed out'
        }
        $null = $stdout.Result
        $null = $stderr.Result
        if ($process.ExitCode -ne 0) { throw 'Exact native Rust SQL failed' }
    }
    finally { $process.Dispose() }
}

function Assert-StoppedGeneration {
    param([string[]]$BaseArguments, [string]$Intent)
    $state = Invoke-PlanPython -Arguments ($BaseArguments + @(
        '--verify-plan', $Intent, '--require-stopped'))
    if ($state.schema -cne 'marty.passport-beta-db-maintenance-state/v1' -or
        $state.verified -ne $true) {
        throw 'Beta service generation or production changed during native gates'
    }
    return $state
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

$lock = Enter-BetaDeploymentLock -AllowPending
try {
    if (-not (Test-Path -LiteralPath (Get-BetaPassportFenceMarkerPath)) -or
        -not (Test-Path -LiteralPath (Get-BetaMutationMarkerPath)) -or
        -not (Test-Path -LiteralPath $MaintenanceReceipt) -or
        -not (Test-Path -LiteralPath $intent) -or
        (Test-Path -LiteralPath $outputAbsolute)) {
        throw 'Protected beta native gate marker or receipt state is invalid'
    }
    $maintenance = Get-Content -LiteralPath $MaintenanceReceipt -Raw -Encoding UTF8 |
        ConvertFrom-Json -ErrorAction Stop
    $maintenancePlan = Get-Content -LiteralPath $intent -Raw -Encoding UTF8 |
        ConvertFrom-Json -ErrorAction Stop
    $maintenanceBase = @(
        (Join-Path $PSScriptRoot 'prepare_passport_beta_db_maintenance.py'),
        '--stack-manifest', $StackManifest, '--fence-receipt', $FenceReceipt,
        '--cutover-snapshot', [string]$maintenancePlan.cutover_snapshot_path,
        '--cutover-report', [string]$maintenancePlan.cutover_report_path)
    $state = Assert-StoppedGeneration -BaseArguments $maintenanceBase -Intent $intent
    $intentSha = (Get-FileHash -LiteralPath $intent -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($maintenance.schema -cne 'marty.passport-beta-db-maintenance-start/v1' -or
        $maintenance.intent_sha256 -cne $intentSha -or
        $maintenance.source_commit -cne $maintenancePlan.source_commit -or
        $maintenance.postgres_container_id -cne $maintenancePlan.postgres_container_id -or
        [string]$maintenance.fence_epoch -cne [string]$maintenancePlan.fence_epoch -or
        $maintenance.production_snapshot_sha256 -cne $state.production_snapshot_sha256 -or
        (@($maintenance.stopped_container_ids) -join ',') -cne
            (@($maintenancePlan.stop_container_ids) -join ',')) {
        throw 'Protected beta maintenance receipt differs from stopped generation'
    }
    $nativeBase = @(
        (Join-Path $PSScriptRoot 'prepare_passport_beta_native_migrations.py'),
        '--stack-manifest', $StackManifest, '--fence-receipt', $FenceReceipt)
    $native = Invoke-PlanPython -Arguments ($nativeBase + @('--output-sql', $sqlStage))
    $container = [string]$native.postgres_container_id
    $systemId = [string]$native.postgres_system_identifier
    $databaseOid = [string]$native.database_oid
    $epoch = [string]$native.fence_epoch
    $head = [string]$native.source_commit
    $digest = [string]$native.migration_set_sha256
    if ($native.schema -cne 'marty.passport-beta-native-migration-plan/v1' -or
        $container -cne [string]$maintenancePlan.postgres_container_id -or
        $systemId -cne [string]$maintenancePlan.postgres_system_identifier -or
        $databaseOid -cne [string]$maintenancePlan.database_oid -or
        $epoch -cne [string]$maintenancePlan.fence_epoch -or
        $head -cne [string]$maintenancePlan.source_commit -or
        $head -notmatch '^[0-9a-f]{40}$' -or
        $digest -notmatch '^[0-9a-f]{64}$') {
        throw 'Signed native SQL differs from stopped beta target'
    }
    $payload = [IO.File]::ReadAllBytes($sqlStage)
    if ((Get-BytesSha256 -Bytes $payload) -cne [string]$native.sql_sha256) {
        throw 'Staged native SQL differs from signed plan'
    }
    $verify = Read-ExactSql 'scripts/sql/passport-beta-fence-verify.sql' `
        ([string]$maintenancePlan.verify_sql_sha256)
    $finalize = Read-ExactSql 'scripts/sql/passport-beta-batch-acl-finalize.sql' `
        ([string]$native.batch_acl_sql_sha256)
    $session = "SET marty.passport_beta_verified_project = 'elevenid-beta';`n" +
        "SET marty.passport_beta_expected_system_identifier = '$systemId';`n" +
        "SET marty.passport_beta_expected_database_oid = '$databaseOid';`n" +
        "SET marty.passport_beta_expected_fence_epoch = '$epoch';`n" +
        "SET marty.passport_beta_expected_source_commit = '$head';`n" +
        "SET marty.passport_beta_expected_native_migration_sha256 = '$digest';`n"
    $before = @(Invoke-BetaPsql -Container $container -Sql ($session + $verify))
    if ($before.Count -ne 1) { throw 'Fenced beta verifier failed before native SQL' }
    $receiptExists = @(Invoke-BetaPsql -Container $container -Sql (
        $session + "SELECT to_regclass('passport_cutover.native_migration_receipt') IS NOT NULL;"))
    if ($receiptExists.Count -ne 1 -or $receiptExists[0] -notin @('t', 'f')) {
        throw 'Native migration receipt state is ambiguous'
    }
    $login = @(Invoke-BetaPsql -Container $container -Sql (
        $session + "SELECT rolcanlogin FROM pg_roles WHERE rolname='marty';"))
    if ($login.Count -ne 1 -or $login[0] -notin @('t', 'f')) {
        throw 'Beta application login role state is ambiguous'
    }
    if ($login[0] -ne 'f') {
        throw 'Beta application login opened before the aggregate Rust deployment'
    }
    if ($receiptExists[0] -eq 'f') {
        $null = Assert-StoppedGeneration -BaseArguments $maintenanceBase -Intent $intent
        Invoke-ExactNativeSql -Container $container -Payload $payload
    }
    $marker = @(Invoke-BetaPsql -Container $container -Sql (
        $session + 'SELECT fence_epoch::text || ''|'' || source_commit || ''|'' || ' +
        'migration_set_sha256 FROM passport_cutover.native_migration_receipt WHERE singleton;'))
    if ($marker.Count -ne 1 -or
        $marker[0] -cne "$epoch|$head|$digest") {
        throw 'Committed native migrations differ from signed source'
    }
    $null = Assert-StoppedGeneration -BaseArguments $maintenanceBase -Intent $intent
    Invoke-BetaPsql -Container $container -Sql ($session + $finalize) | Out-Null
    $null = Assert-StoppedGeneration -BaseArguments $maintenanceBase -Intent $intent
    $stillClosed = @(Invoke-BetaPsql -Container $container -Sql (
        $session + "SELECT rolcanlogin FROM pg_roles WHERE rolname='marty';"))
    if ($stillClosed.Count -ne 1 -or $stillClosed[0] -ne 'f') {
        throw 'Beta application login changed during native database gates'
    }
    $after = @(Invoke-BetaPsql -Container $container -Sql ($session + $verify))
    if ($after.Count -ne 1 -or $after[0] -cne $before[0]) {
        throw 'Beta passport fence changed during native database gates'
    }
    $finalState = Assert-StoppedGeneration -BaseArguments $maintenanceBase -Intent $intent
    $receipt = [ordered]@{
        schema = 'marty.passport-beta-native-db-gates/v1'
        source_commit = $head
        postgres_container_id = $container
        postgres_system_identifier = $systemId
        database_oid = $databaseOid
        fence_epoch = $epoch
        migration_image = $native.migration_image
        migration_set_sha256 = $digest
        native_sql_sha256 = $native.sql_sha256
        production_snapshot_sha256 = $finalState.production_snapshot_sha256
        maintenance_receipt_sha256 = (Get-FileHash -LiteralPath $MaintenanceReceipt `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        stopped_container_ids = $maintenancePlan.stop_container_ids
        app_login_enabled = $false
    }
    Write-DurableJson -Path $outputAbsolute `
        -Json ($receipt | ConvertTo-Json -Depth 20 -Compress)
    Write-Output $outputAbsolute
}
finally { Exit-BetaDeploymentLock -Lock $lock }
