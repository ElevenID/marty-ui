[CmdletBinding()]
param([string]$PostgresContainer, [string]$OutputPath, [switch]$Apply)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'beta-passport-fence-legacy-boundary.ps1')
. (Join-Path $PSScriptRoot 'beta-deployment-lock.ps1')

function Get-BetaResetFenceCandidate {
    param([string]$Container, [string]$MarkerPath)
    if ($Container -cnotmatch '^[0-9a-f]{64}$') { throw 'Use the full beta PostgreSQL container ID' }
    $raw = & docker inspect $Container
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect beta PostgreSQL' }
    $observed = @($raw | ConvertFrom-Json)[0]
    if ($observed.Id -cne $Container -or -not $observed.State.Running -or
        $observed.Config.Labels.'com.docker.compose.project' -cne 'elevenid-beta' -or
        $observed.Config.Labels.'com.docker.compose.service' -cne 'postgres') {
        throw 'Target is not the running elevenid-beta PostgreSQL container'
    }
    $sql = "SELECT json_build_object('database_oid',(SELECT oid FROM pg_database WHERE datname=current_database()),'system_identifier',(SELECT system_identifier::text FROM pg_control_system()),'passport_cutover_schema_count',(SELECT count(*) FROM pg_namespace WHERE nspname='passport_cutover'));"
    $raw = & docker exec $Container psql -U postgres -d marty -At -v ON_ERROR_STOP=1 -c $sql
    if ($LASTEXITCODE -ne 0) { throw 'Cannot establish current beta database identity' }
    $database = $raw | ConvertFrom-Json
    if ($database.system_identifier -cnotmatch '^[0-9]+$' -or
        [string]$database.database_oid -cnotmatch '^[0-9]+$' -or
        $database.passport_cutover_schema_count -ne 0) {
        throw 'Current database is fenced or its identity is ambiguous'
    }
    foreach ($path in @($MarkerPath)) {
        $item = Get-Item -LiteralPath $path
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Fence marker must be a regular file'
        }
    }
    $markerHash = (Get-FileHash -LiteralPath $MarkerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $marker = Get-Content -LiteralPath $MarkerPath -Raw | ConvertFrom-Json
    if ($marker.schema -cne 'marty.passport-beta-fence-host-record/v1' -or
        $marker.receipt_file_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Incomplete or unrecognized fence intent cannot be reconciled'
    }
    $receiptItem = Get-Item -LiteralPath $marker.receipt_path
    if ($receiptItem.PSIsContainer -or ($receiptItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Fence receipt must be a regular file'
    }
    $receiptHash = (Get-FileHash -LiteralPath $marker.receipt_path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($receiptHash -cne $marker.receipt_file_sha256) { throw 'Fence receipt hash mismatch' }
    $receipt = Get-Content -LiteralPath $marker.receipt_path -Raw | ConvertFrom-Json
    if ($receipt.schema -cne 'marty.passport-beta-fence-installation/v1' -or
        $receipt.postgres_container_id -cnotmatch '^[0-9a-f]{64}$' -or
        $receipt.postgres_system_identifier -cnotmatch '^[0-9]+$' -or
        $receipt.postgres_container_id -ceq $Container -or
        $receipt.postgres_system_identifier -ceq $database.system_identifier) {
        throw 'Fence receipt is not bound to a different, replaced PostgreSQL cluster'
    }
    return [ordered]@{
        schema = 'marty.beta-reset-fence-reconciliation/v1'
        state = 'VERIFIED_STALE_AFTER_RESET'
        marker_path = $MarkerPath
        marker_sha256 = $markerHash
        original_receipt_path = $marker.receipt_path
        original_receipt_sha256 = $receiptHash
        old_postgres_container_id = $receipt.postgres_container_id
        old_postgres_system_identifier = $receipt.postgres_system_identifier
        current_postgres_container_id = $Container
        current_postgres_system_identifier = $database.system_identifier
        current_database_oid = [string]$database.database_oid
        current_passport_cutover_schema_count = 0
        database_changed = $false
    }
}

function Invoke-BetaResetFenceReconciliation {
    param([string]$Container, [string]$MarkerPath, [string]$Output, [switch]$Archive)
    $lock = Enter-BetaDeploymentLock
    try {
        $candidate = Get-BetaResetFenceCandidate -Container $Container -MarkerPath $MarkerPath
        if (-not $Archive) { return $candidate }
        if (-not $Output -or (Test-Path -LiteralPath $Output)) { throw 'Use a new reconciliation receipt path' }
        $archivePath = [IO.Path]::GetFullPath($MarkerPath + '.reset-' + [guid]::NewGuid().ToString('N') + '.archived')
        $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($MarkerPath))
        if ([IO.Path]::GetDirectoryName($archivePath) -cne $parent -or (Test-Path -LiteralPath $archivePath)) {
            throw 'Archive must be a new file beside the original marker'
        }
        $candidate.archive_path = $archivePath
        $candidate.state = 'ARCHIVE_INTENT'
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        $intentBytes = $utf8.GetBytes(($candidate | ConvertTo-Json -Depth 5) + "`n")
        $stream = [IO.File]::Open($Output, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($intentBytes, 0, $intentBytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
        # Revalidate both the database and original bytes immediately before the move.
        $fresh = Get-BetaResetFenceCandidate -Container $Container -MarkerPath $MarkerPath
        foreach ($key in @('marker_sha256', 'original_receipt_sha256', 'current_postgres_system_identifier', 'current_database_oid')) {
            if ($fresh[$key] -cne $candidate[$key]) { throw 'Reset evidence changed during reconciliation' }
        }
        Move-Item -LiteralPath $MarkerPath -Destination $archivePath -ErrorAction Stop
        if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $candidate.marker_sha256) {
            throw 'Archived marker bytes changed; inspect the retained reconciliation intent'
        }
        $candidate.state = 'ARCHIVED_STALE_AFTER_RESET'
        [IO.File]::WriteAllText($Output, (($candidate | ConvertTo-Json -Depth 5) + "`n"), $utf8)
        return $candidate
    }
    finally { Exit-BetaDeploymentLock -Lock $lock }
}

if ($MyInvocation.InvocationName -ne '.') {
    if (-not $PostgresContainer -or ($Apply -and -not $OutputPath)) {
        throw 'PostgresContainer is required; Apply also requires a new OutputPath'
    }
    Invoke-BetaResetFenceReconciliation -Container $PostgresContainer `
        -MarkerPath (Get-BetaPassportFenceMarkerPath) -Output $OutputPath -Archive:$Apply |
        ConvertTo-Json -Depth 5
}
