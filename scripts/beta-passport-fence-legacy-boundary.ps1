# Pre-fence deploy and restore flatten the passport guard owner's DDL boundary.
function Get-BetaPassportFenceMarkerPath {
    $root = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        [Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)
    } else {
        '/var/tmp'
    }
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw 'A host-wide beta passport fence marker location is unavailable'
    }
    return (Join-Path $root 'ElevenID-Marty-elevenid-beta-passport-fence.pending')
}

function Assert-LegacyBetaDatabaseUnfenced {
    param([Parameter(Mandatory = $true)][string]$PostgresContainer)
    if ($PostgresContainer -notmatch '^[0-9a-f]{12,64}$') {
        throw 'Beta PostgreSQL container identity is invalid'
    }
    if (Test-Path -LiteralPath (Get-BetaPassportFenceMarkerPath)) {
        throw 'Legacy beta deploy or restore cannot run after passport fence intent'
    }
    $result = @(& docker exec $PostgresContainer psql -U postgres -d marty -At `
        -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_namespace WHERE nspname='passport_cutover'" 2>$null)
    if ($LASTEXITCODE -ne 0 -or $result.Count -ne 1 -or $result[0] -notin @('0', '1')) {
        throw 'Could not establish unfenced beta database state'
    }
    if ($result[0] -ne '0') {
        throw 'Legacy beta deploy or restore cannot preserve the passport fence'
    }
}
