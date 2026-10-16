# Operational clean-database replacement for the non-public beta Keycloak.
# The caller owns the beta deployment lock, stopped writers, and release image
# qualification. No function here migrates or copies local KeyProvider rows.

function Assert-BetaKeycloakBackup {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $resolved = (Resolve-Path -LiteralPath $ManifestPath -ErrorAction Stop).Path
    $manifest = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or
        $manifest.phase -ne 'maintenance_quiesced' -or
        $manifest.application_writers_stopped -ne $true) {
        throw 'Keycloak clean replacement requires a quiesced beta backup'
    }
    $root = Split-Path -Parent $resolved
    $backup = Join-Path $root 'backup'
    foreach ($name in @('postgres-marty.dump', 'postgres-keycloak.dump',
            'postgres-globals.sql', 'openbao-data.tar.gz', 'redis-dump.rdb',
            'applicant_store.json')) {
        $record = @($manifest.files | Where-Object { $_.name -ceq $name })
        $path = Join-Path $backup $name
        if ($record.Count -ne 1 -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Keycloak clean replacement backup is incomplete: $name"
        }
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($record[0].sha256 -cne $actual) {
            throw "Keycloak clean replacement backup checksum failed: $name"
        }
    }
}

function Assert-BetaKeycloakPostgres {
    param([Parameter(Mandatory = $true)][string]$Container)

    $raw = & docker inspect $Container
    if ($LASTEXITCODE -ne 0) { throw 'Beta PostgreSQL container is unavailable' }
    $records = @(($raw -join "`n") | ConvertFrom-Json)
    if ($records.Count -ne 1 -or
        $records[0].Config.Labels.'com.docker.compose.project' -cne 'elevenid-beta' -or
        $records[0].Config.Labels.'com.docker.compose.service' -cne 'postgres' -or
        $records[0].State.Running -ne $true) {
        throw 'Refusing Keycloak database replacement outside running beta PostgreSQL'
    }
}

function Invoke-BetaKeycloakAdminSql {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$Sql
    )
    $result = @(& docker exec $Container psql -U postgres -d postgres -v ON_ERROR_STOP=1 -At -c $Sql)
    if ($LASTEXITCODE -ne 0) { throw 'Beta Keycloak PostgreSQL operation failed' }
    return $result
}

function Assert-BetaKeycloakDatabaseNames {
    param(
        [Parameter(Mandatory = $true)][string]$RetainedName,
        [Parameter(Mandatory = $true)][string]$FailedName
    )
    if ($RetainedName -cnotmatch '^keycloak_before_kms_[0-9a-f]{12}$' -or
        $FailedName -cnotmatch '^keycloak_failed_kms_[0-9a-f]{12}$' -or
        $RetainedName.Substring(20) -cne $FailedName.Substring(20)) {
        throw 'Keycloak clean replacement database names are invalid'
    }
}

function Assert-BetaKeycloakDatabasesQuiesced {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$RetainedName,
        [Parameter(Mandatory = $true)][string]$FailedName
    )
    $sql = "SELECT count(*) FROM pg_stat_activity WHERE datname IN ('keycloak', '$RetainedName', '$FailedName') AND pid <> pg_backend_pid()"
    $connections = @(Invoke-BetaKeycloakAdminSql -Container $Container -Sql $sql)
    if ($connections.Count -ne 1 -or $connections[0] -cne '0') {
        throw 'Keycloak database connections remain during clean replacement'
    }
}

function Invoke-BetaKeycloakCleanSwap {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$RetainedName,
        [Parameter(Mandatory = $true)][string]$FailedName
    )
    Assert-BetaKeycloakBackup -ManifestPath $ManifestPath
    Assert-BetaKeycloakPostgres -Container $Container
    Assert-BetaKeycloakDatabaseNames -RetainedName $RetainedName -FailedName $FailedName
    Assert-BetaKeycloakDatabasesQuiesced -Container $Container -RetainedName $RetainedName -FailedName $FailedName
    $sql = "SELECT datname FROM pg_database WHERE datname IN ('keycloak', '$RetainedName', '$FailedName') ORDER BY datname"
    $names = @(Invoke-BetaKeycloakAdminSql -Container $Container -Sql $sql)
    if (($names -join ',') -cne 'keycloak') {
        throw 'Keycloak clean replacement requires one original database and unused cutover names'
    }
    Invoke-BetaKeycloakAdminSql -Container $Container -Sql "ALTER DATABASE keycloak RENAME TO $RetainedName" | Out-Null
    try {
        & docker exec $Container createdb -U postgres -O keycloak keycloak
        if ($LASTEXITCODE -ne 0) { throw 'Fresh Keycloak database creation failed' }
    }
    catch {
        Invoke-BetaKeycloakAdminSql -Container $Container -Sql "ALTER DATABASE $RetainedName RENAME TO keycloak" | Out-Null
        throw
    }
}

function Restore-BetaKeycloakCleanSwap {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$RetainedName,
        [Parameter(Mandatory = $true)][string]$FailedName
    )
    Assert-BetaKeycloakPostgres -Container $Container
    Assert-BetaKeycloakDatabaseNames -RetainedName $RetainedName -FailedName $FailedName
    Assert-BetaKeycloakDatabasesQuiesced -Container $Container -RetainedName $RetainedName -FailedName $FailedName
    $sql = "SELECT datname FROM pg_database WHERE datname IN ('keycloak', '$RetainedName', '$FailedName') ORDER BY datname"
    $names = @(Invoke-BetaKeycloakAdminSql -Container $Container -Sql $sql)
    if (($names -join ',') -cne "keycloak,$RetainedName") {
        throw 'Keycloak clean rollback requires the fresh and retained databases only'
    }
    Invoke-BetaKeycloakAdminSql -Container $Container -Sql "ALTER DATABASE keycloak RENAME TO $FailedName" | Out-Null
    try {
        Invoke-BetaKeycloakAdminSql -Container $Container -Sql "ALTER DATABASE $RetainedName RENAME TO keycloak" | Out-Null
    }
    catch {
        Invoke-BetaKeycloakAdminSql -Container $Container -Sql "ALTER DATABASE $FailedName RENAME TO keycloak" | Out-Null
        throw
    }
}
