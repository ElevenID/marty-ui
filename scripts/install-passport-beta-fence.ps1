param(
    [Parameter(Mandatory = $true)][string]$StackManifest,
    [Parameter(Mandatory = $true)][string]$BetaBaselineManifest,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

# Run only from the clean protected main release after target approval lands.
# This is a separate fence installation, before the later aggregate deployment.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Protected beta fence installation requires the Windows beta deployment host lock and markers'
}
$repo = Split-Path -Parent $PSScriptRoot
$repoAbsolute = [IO.Path]::GetFullPath($repo).TrimEnd([IO.Path]::DirectorySeparatorChar)
if (-not [IO.Path]::IsPathRooted($OutputPath)) {
    throw 'Beta fence receipt path must be absolute'
}
# The WSL protected receipt collector can map only local DOS drive paths.
# Reject UNC, device, and extended-length paths before any fence mutation.
if ($OutputPath -cnotmatch '^[A-Za-z]:\\[^\\/:*?"<>|\r\n]+(?:\\[^\\/:*?"<>|\r\n]+)*$') {
    throw 'Beta fence receipt path must be a local Windows drive file'
}
$outputAbsolute = [IO.Path]::GetFullPath($OutputPath)
if ($outputAbsolute -cnotmatch '^[A-Za-z]:\\[^\\/:*?"<>|\r\n]+(?:\\[^\\/:*?"<>|\r\n]+)*$') {
    throw 'Canonical beta fence receipt path is not a local Windows drive file'
}
if ($outputAbsolute.StartsWith(
        $repoAbsolute + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Beta fence receipt must be outside protected source'
}
. (Join-Path $PSScriptRoot 'beta-deployment-lock.ps1')
. (Join-Path $PSScriptRoot 'beta-passport-fence-legacy-boundary.ps1')

function Invoke-FencePython {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& python @Arguments 2>$null)
        if ($LASTEXITCODE -ne 0 -or $output.Count -ne 1) {
            throw 'Protected beta fence Python check failed'
        }
        return ($output[0] | ConvertFrom-Json -ErrorAction Stop)
    }
    finally { $ErrorActionPreference = $previousErrorAction }
}

function Invoke-FencePsql {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$Sql
    )
    if ($Container -notmatch '^[0-9a-f]{64}$') {
        throw 'Protected beta PostgreSQL container identity is invalid'
    }
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @($Sql | & docker exec -i $Container psql -X -U postgres `
            -d marty -qAt -v ON_ERROR_STOP=1 -f - 2>$null)
        if ($LASTEXITCODE -ne 0) { throw 'Protected beta fence SQL failed' }
        return $output
    }
    finally { $ErrorActionPreference = $previousErrorAction }
}

function Assert-SourceSqlHash {
    param([string]$Relative, [string]$Expected)
    $path = Join-Path $repo $Relative
    $bytes = [IO.File]::ReadAllBytes($path)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $digest = $hasher.ComputeHash($bytes) }
    finally { $hasher.Dispose() }
    $actual = ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    if ($actual -cne $Expected) {
        throw "Protected beta fence SQL changed: $Relative"
    }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $sql = $utf8.GetString($bytes).Replace("`r`n", "`n")
    if ($sql.Contains("`r")) {
        throw "Protected beta fence SQL has unsupported line endings: $Relative"
    }
    # PostgreSQL stores function bodies verbatim. Stable LF endings are part
    # of the reviewed verifier's pg_get_functiondef hashes.
    return $sql
}

$lock = Enter-BetaDeploymentLock
try {
    $approval = Join-Path $repo 'deploy-config/passport-beta-fence-approved-target.json'
    $plan = Invoke-FencePython -Arguments @(
        (Join-Path $PSScriptRoot 'check_passport_beta_fence_authority.py'),
        '--approved-target', $approval,
        '--stack-manifest', $StackManifest,
        '--beta-baseline-manifest', $BetaBaselineManifest
    )
    if ($plan.schema -cne 'marty.passport-beta-fence-authority-plan/v1' -or
        $plan.verified -ne $true -or
        (Test-Path -LiteralPath (Get-BetaPassportFenceMarkerPath)) -or
        (Test-Path -LiteralPath $outputAbsolute)) {
        throw 'Protected beta fence intent, authority, or output state is invalid'
    }
    $container = [string]$plan.postgres_container_id
    $systemId = [string]$plan.postgres_system_identifier
    $databaseOid = [string]$plan.database_oid
    if ($container -notmatch '^[0-9a-f]{64}$' -or
        $systemId -notmatch '^[0-9]+$' -or $databaseOid -notmatch '^[0-9]+$') {
        throw 'Protected beta fence target is invalid'
    }
    $install = Assert-SourceSqlHash 'scripts/sql/passport-beta-fence-install.sql' `
        ([string]$plan.install_sql_sha256)
    $drain = Assert-SourceSqlHash 'scripts/sql/passport-beta-fence-drain.sql' `
        ([string]$plan.drain_sql_sha256)
    $verify = Assert-SourceSqlHash 'scripts/sql/passport-beta-fence-verify.sql' `
        ([string]$plan.verify_sql_sha256)
    $include = '\ir passport-beta-fence-drain.sql'
    if ($install.IndexOf($include, [StringComparison]::Ordinal) -lt 0 -or
        $install.IndexOf($include, $install.IndexOf($include) + 1,
            [StringComparison]::Ordinal) -ge 0) {
        throw 'Protected beta fence drain include is ambiguous'
    }
    $install = $install.Replace($include, $drain)
    $session = "SET marty.passport_beta_verified_project = 'elevenid-beta';`n" +
        "SET marty.passport_beta_expected_system_identifier = '$systemId';`n" +
        "SET marty.passport_beta_expected_database_oid = '$databaseOid';`n"

    $before = Invoke-FencePython -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_fence_target.py'))
    if ($before.schema -cne 'marty.passport-beta-fence-target/v1' -or
        $before.observation_sha256 -cne $plan.target_observation_sha256 -or
        $before.beta.postgres_system_identifier -cne $systemId -or
        $before.beta.database_oid -cne $databaseOid -or
        $before.beta.services.postgres.container_id -cne $container -or
        $before.docker.context -cne $plan.docker.context -or
        $before.docker.daemon_id -cne $plan.docker.daemon_id -or
        $before.production.sha256 -cne $plan.production_snapshot_sha256 -or
        $before.production_attachments_sha256 -cne $plan.production_attachments_sha256 -or
        ($before.beta.services | ConvertTo-Json -Depth 20 -Compress) -cne
            ($plan.beta_services | ConvertTo-Json -Depth 20 -Compress) -or
        ($before.beta.database_route | ConvertTo-Json -Depth 20 -Compress) -cne
            ($plan.database_route | ConvertTo-Json -Depth 20 -Compress)) {
        throw 'Approved beta service generation or database route changed before fence'
    }

    # The persistent fence marker precedes any database mutation. A failure
    # leaves both markers for supervised inspection and blocks legacy deploy.
    Start-BetaMutation
    $markerPath = Get-BetaPassportFenceMarkerPath
    $stream = [IO.File]::Open($markerPath, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(
            "passport fence intent $([DateTime]::UtcNow.ToString('o'))`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }

    Invoke-FencePsql -Container $container -Sql ($session + $install) | Out-Null
    $verified = @(Invoke-FencePsql -Container $container -Sql ($session + $verify))
    if ($verified.Count -ne 1) { throw 'Beta fence verifier returned ambiguous evidence' }
    $fence = $verified[0] | ConvertFrom-Json -ErrorAction Stop
    if ($fence.schema -cne 'marty.passport-beta-fence-verification/v1' -or
        $fence.phase -cne 'fully_fenced' -or $fence.epoch -le 0) {
        throw 'Beta fence verifier did not confirm the full fence'
    }
    $direct = Invoke-FencePython -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_fence_direct_writes.py'),
        '--postgres-container', $container,
        '--docker-context', ([string]$plan.docker.context),
        '--daemon-id', ([string]$plan.docker.daemon_id),
        '--system-identifier', $systemId,
        '--database-oid', $databaseOid,
        '--fence-epoch', ([string]$fence.epoch)
    )
    $after = Invoke-FencePython -Arguments @(
        (Join-Path $PSScriptRoot 'probe_passport_beta_fence_target.py'),
        '--fenced'
    )
    if ($after.schema -cne 'marty.passport-beta-fence-postinstall-target/v1' -or
        $after.beta.postgres_system_identifier -cne $systemId -or
        $after.beta.database_oid -cne $databaseOid -or
        $after.beta.services.postgres.container_id -cne $container -or
        $after.docker.context -cne $plan.docker.context -or
        $after.docker.daemon_id -cne $plan.docker.daemon_id -or
        $after.production.sha256 -cne $plan.production_snapshot_sha256 -or
        $after.production_attachments_sha256 -cne $plan.production_attachments_sha256 -or
        $direct.fence_epoch -ne $fence.epoch -or
        $direct.postgres_container_id -cne $container) {
        throw 'Beta fence target or production changed during installation'
    }
    if (($after.beta.services | ConvertTo-Json -Depth 20 -Compress) -cne
            ($plan.beta_services | ConvertTo-Json -Depth 20 -Compress) -or
        ($after.beta.database_route | ConvertTo-Json -Depth 20 -Compress) -cne
            ($plan.database_route | ConvertTo-Json -Depth 20 -Compress) -or
        ($after.beta.postgres_runtime | ConvertTo-Json -Depth 20 -Compress) -cne
            ($plan.postgres_runtime | ConvertTo-Json -Depth 20 -Compress)) {
        throw 'Approved beta service generation or database route changed'
    }
    $verifiedFinal = @(Invoke-FencePsql -Container $container -Sql ($session + $verify))
    if ($verifiedFinal.Count -ne 1 -or $verifiedFinal[0] -cne $verified[0]) {
        throw 'Beta fence verification changed after direct write probes'
    }
    $receipt = [ordered]@{
        schema = 'marty.passport-beta-fence-installation/v1'
        source_commit = $plan.source.source_commit
        credentials_deletion_head = $plan.credentials_deletion_head
        approved_target_observation_sha256 = $plan.target_observation_sha256
        beta_services = $plan.beta_services
        verify_sql_sha256 = $plan.verify_sql_sha256
        postgres_system_identifier = $systemId
        database_oid = $databaseOid
        postgres_container_id = $container
        fence = $fence
        direct_database_probe = $direct
        post_install_observation_sha256 = $after.observation_sha256
        production_snapshot_sha256 = $after.production.sha256
        production_attachments_sha256 = $after.production_attachments_sha256
    }
    $json = $receipt | ConvertTo-Json -Depth 20 -Compress
    $outputStream = [IO.File]::Open($outputAbsolute, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($json + "`n")
        $outputStream.Write($bytes, 0, $bytes.Length)
        $outputStream.Flush($true)
    }
    finally { $outputStream.Dispose() }
    # A completed host marker binds later snapshots to these exact receipt
    # bytes. An interrupted write leaves the original intent marker and fails
    # closed. This mutable host record is continuity evidence; the later
    # protected producer must attest installer provenance before acceptance.
    $receiptHasher = [Security.Cryptography.SHA256]::Create()
    try {
        $receiptHash = $receiptHasher.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes($json + "`n"))
    }
    finally { $receiptHasher.Dispose() }
    $markerRecord = [ordered]@{
        schema = 'marty.passport-beta-fence-host-record/v1'
        receipt_path = $outputAbsolute
        receipt_file_sha256 = ([BitConverter]::ToString($receiptHash)).Replace('-', '').ToLowerInvariant()
        source_commit = $plan.source.source_commit
        approved_target_observation_sha256 = $plan.target_observation_sha256
    } | ConvertTo-Json -Compress
    $markerStream = [IO.File]::Open($markerPath, [IO.FileMode]::Truncate,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $markerBytes = [Text.Encoding]::UTF8.GetBytes($markerRecord + "`n")
        $markerStream.Write($markerBytes, 0, $markerBytes.Length)
        $markerStream.Flush($true)
    }
    finally { $markerStream.Dispose() }
    Complete-BetaMutation
    Write-Output $outputAbsolute
}
finally { Exit-BetaDeploymentLock -Lock $lock }
