param(
    [Parameter(Mandatory = $true)][string]$StackManifest,
    [Parameter(Mandatory = $true)][string]$FenceReceipt,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [switch]$ResumePending
)

# Beta-only: leave the mutation marker in place until the aggregate release
# operator has completed native migrations, deployment, and acceptance.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Protected beta maintenance requires the Windows beta deployment host'
}
$repo = Split-Path -Parent $PSScriptRoot
$repoAbsolute = [IO.Path]::GetFullPath($repo).TrimEnd([IO.Path]::DirectorySeparatorChar)
if (-not [IO.Path]::IsPathRooted($OutputPath)) {
    throw 'Beta maintenance receipt path must be absolute'
}
$outputAbsolute = [IO.Path]::GetFullPath($OutputPath)
if ($outputAbsolute.StartsWith(
        $repoAbsolute + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Beta maintenance receipt must be outside protected source'
}
$intentAbsolute = $outputAbsolute + '.intent.json'
. (Join-Path $PSScriptRoot 'beta-deployment-lock.ps1')
. (Join-Path $PSScriptRoot 'beta-passport-fence-legacy-boundary.ps1')

function Invoke-MaintenancePython {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& python @Arguments 2>$null)
        if ($LASTEXITCODE -ne 0 -or $output.Count -ne 1) {
            throw 'Protected beta maintenance plan check failed'
        }
        return ($output[0] | ConvertFrom-Json -ErrorAction Stop)
    }
    finally { $ErrorActionPreference = $previous }
}

function Invoke-MaintenancePsql {
    param([string]$Container, [string]$Sql)
    if ($Container -notmatch '^[0-9a-f]{64}$') {
        throw 'Protected beta PostgreSQL container identity is invalid'
    }
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @($Sql | & docker exec -i $Container psql -X -U postgres `
            -d marty -qAt -v ON_ERROR_STOP=1 -f - 2>$null)
        if ($LASTEXITCODE -ne 0) { throw 'Protected beta maintenance SQL failed' }
        return $output
    }
    finally { $ErrorActionPreference = $previous }
}

function Read-ExactSql {
    param([string]$Relative, [string]$ExpectedSha256)
    if ($ExpectedSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Protected beta SQL digest is invalid'
    }
    $path = Join-Path $repo $Relative
    $bytes = [IO.File]::ReadAllBytes($path)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $digest = $hasher.ComputeHash($bytes) }
    finally { $hasher.Dispose() }
    $actual = ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    if ($actual -cne $ExpectedSha256) { throw "Protected beta SQL changed: $Relative" }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $sql = $utf8.GetString($bytes).Replace("`r`n", "`n")
    if ($sql.Contains("`r")) { throw "Protected beta SQL line endings changed: $Relative" }
    return $sql
}

function Write-DurableJson {
    param([string]$Path, [string]$Json)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Json + "`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

function Assert-DockerIdentity {
    param($Plan)
    $context = @(& docker context show 2>$null)
    $daemon = @(& docker info --format '{{.ID}}' 2>$null)
    if ($context.Count -ne 1 -or $daemon.Count -ne 1 -or
        $context[0] -cne [string]$Plan.docker.context -or
        $daemon[0] -cne [string]$Plan.docker.daemon_id) {
        throw 'Docker context changed during beta maintenance'
    }
}

$lock = Enter-BetaDeploymentLock -AllowPending:$ResumePending
try {
    if (-not (Test-Path -LiteralPath (Get-BetaPassportFenceMarkerPath)) -or
        (Test-Path -LiteralPath $outputAbsolute)) {
        throw 'Fenced beta maintenance marker or output state is invalid'
    }
    $planner = Join-Path $PSScriptRoot 'prepare_passport_beta_db_maintenance.py'
    $baseArgs = @($planner, '--stack-manifest', $StackManifest,
        '--fence-receipt', $FenceReceipt)
    if ($ResumePending) {
        if (-not (Test-Path -LiteralPath $intentAbsolute)) {
            throw 'Beta maintenance has no durable pending intent to resume'
        }
        $plan = Get-Content -LiteralPath $intentAbsolute -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
    }
    else {
        if (Test-Path -LiteralPath $intentAbsolute) {
            throw 'A prior beta maintenance intent requires supervised review'
        }
        $plan = Invoke-MaintenancePython -Arguments $baseArgs
        if ($plan.schema -cne 'marty.passport-beta-db-maintenance-plan/v1') {
            throw 'Protected beta maintenance plan is invalid'
        }
    }
    if ($ResumePending) {
        $state = Invoke-MaintenancePython -Arguments ($baseArgs + @(
            '--verify-plan', $intentAbsolute))
        if ($state.schema -cne
                'marty.passport-beta-db-maintenance-state/v1' -or
                $state.verified -ne $true) {
            throw 'Pending beta maintenance intent differs from live target'
        }
        if (-not (Test-Path -LiteralPath (Get-BetaMutationMarkerPath))) {
            if (@($state.stopped_container_ids).Count -ne 0) {
                throw 'Beta services stopped without a durable mutation marker'
            }
            Start-BetaMutation
        }
    }
    $container = [string]$plan.postgres_container_id
    $systemId = [string]$plan.postgres_system_identifier
    $databaseOid = [string]$plan.database_oid
    $epoch = [string]$plan.fence_epoch
    if ($container -notmatch '^[0-9a-f]{64}$' -or
        $systemId -notmatch '^[0-9]+$' -or
        $databaseOid -notmatch '^[0-9]+$' -or $epoch -notmatch '^[0-9]+$') {
        throw 'Protected beta maintenance target fields are invalid'
    }
    Assert-DockerIdentity -Plan $plan
    $session = "SET marty.passport_beta_verified_project = 'elevenid-beta';`n" +
        "SET marty.passport_beta_expected_system_identifier = '$systemId';`n" +
        "SET marty.passport_beta_expected_database_oid = '$databaseOid';`n" +
        "SET marty.passport_beta_expected_fence_epoch = '$epoch';`n"
    $verify = Read-ExactSql 'scripts/sql/passport-beta-fence-verify.sql' `
        ([string]$plan.verify_sql_sha256)
    $start = Read-ExactSql 'scripts/sql/passport-beta-db-maintenance-start.sql' `
        ([string]$plan.start_sql_sha256)
    $fenceRows = @(Invoke-MaintenancePsql -Container $container -Sql ($session + $verify))
    if ($fenceRows.Count -ne 1) { throw 'Fenced beta verifier returned ambiguous evidence' }
    $fence = $fenceRows[0] | ConvertFrom-Json -ErrorAction Stop
    if ($fence.schema -cne 'marty.passport-beta-fence-verification/v1' -or
        $fence.phase -cne 'fully_fenced' -or [string]$fence.epoch -cne $epoch) {
        throw 'Protected beta fence changed before maintenance'
    }
    if (-not $ResumePending) {
        Write-DurableJson -Path $intentAbsolute `
            -Json ($plan | ConvertTo-Json -Depth 20 -Compress)
        Start-BetaMutation
    }
    $state = Invoke-MaintenancePython -Arguments ($baseArgs + @(
        '--verify-plan', $intentAbsolute))
    if ($state.verified -ne $true) { throw 'Beta maintenance intent changed' }
    $ingress = @('cloudflared', 'nginx-proxy', 'envoy', 'gateway', 'waltid-nginx')
    $ordered = @($plan.beta_generation | Where-Object { $_.service -in $ingress } |
        Sort-Object { [Array]::IndexOf($ingress, [string]$_.service) }) +
        @($plan.beta_generation | Where-Object {
            $_.service -ne 'postgres' -and $_.service -notin $ingress
        })
    foreach ($service in $ordered) {
        $id = [string]$service.container_id
        if ($id -notmatch '^[0-9a-f]{64}$') {
            throw 'Beta maintenance stop target is invalid'
        }
        Assert-DockerIdentity -Plan $plan
        $current = @(& docker inspect --format '{{.State.Running}}' $id 2>$null)
        if ($LASTEXITCODE -ne 0 -or $current.Count -ne 1 -or
            $current[0] -notin @('true', 'false')) {
            throw 'Beta maintenance container state is unavailable'
        }
        if ($current[0] -eq 'true') {
            & docker stop --time 60 $id | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Beta service did not stop cleanly' }
        }
    }
    $stopped = Invoke-MaintenancePython -Arguments ($baseArgs + @(
        '--verify-plan', $intentAbsolute, '--require-stopped'))
    if ($stopped.verified -ne $true -or
        @($stopped.stopped_container_ids).Count -ne
            @($plan.stop_container_ids).Count) {
        throw 'Beta application generation is not fully stopped'
    }
    Assert-DockerIdentity -Plan $plan
    Invoke-MaintenancePsql -Container $container -Sql ($session + $start) | Out-Null
    $fenceRows = @(Invoke-MaintenancePsql -Container $container -Sql ($session + $verify))
    if ($fenceRows.Count -ne 1) { throw 'Beta fence verification disappeared' }
    $fenceAfter = $fenceRows[0] | ConvertFrom-Json -ErrorAction Stop
    if ($fenceAfter.schema -cne $fence.schema -or
        $fenceAfter.phase -cne $fence.phase -or
        [string]$fenceAfter.epoch -cne $epoch) {
        throw 'Beta fence changed during database maintenance'
    }
    $final = Invoke-MaintenancePython -Arguments ($baseArgs + @(
        '--verify-plan', $intentAbsolute, '--require-stopped'))
    if ($final.verified -ne $true) { throw 'Beta or production changed during maintenance' }
    $receipt = [ordered]@{
        schema = 'marty.passport-beta-db-maintenance-start/v1'
        source_commit = $plan.source_commit
        postgres_container_id = $container
        postgres_system_identifier = $systemId
        database_oid = $databaseOid
        fence_epoch = $epoch
        stopped_container_ids = $plan.stop_container_ids
        production_snapshot_sha256 = $final.production_snapshot_sha256
        intent_sha256 = (Get-FileHash -LiteralPath $intentAbsolute -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Write-DurableJson -Path $outputAbsolute `
        -Json ($receipt | ConvertTo-Json -Depth 20 -Compress)
    Write-Output $outputAbsolute
}
finally { Exit-BetaDeploymentLock -Lock $lock }
