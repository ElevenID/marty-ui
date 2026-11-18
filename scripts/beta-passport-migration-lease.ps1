# Only a future source-bound beta release operator may call these functions.
# The operator must hold the host-wide beta lock, keep writers stopped, and
# run the exact signed migration image before ending the lease.
function Invoke-BetaPassportLeaseSql {
    param(
        [Parameter(Mandatory = $true)][string]$PostgresContainer,
        [Parameter(Mandatory = $true)][string]$Sql
    )
    if ($PostgresContainer -notmatch '^[0-9a-f]{64}$') {
        throw 'Beta migration PostgreSQL container identity is invalid'
    }
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @($Sql | & docker exec -i $PostgresContainer psql -X -U postgres `
            -d marty -qAt -v ON_ERROR_STOP=1 2>$null)
        if ($LASTEXITCODE -ne 0) {
            throw 'Beta migration role transaction failed'
        }
        return $output
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
    }
}

function Assert-BetaPassportLeaseMarkers {
    if (-not (Test-Path -LiteralPath (Get-BetaMutationMarkerPath)) -or
        -not (Test-Path -LiteralPath (Get-BetaPassportFenceMarkerPath))) {
        throw 'Beta migration requires the locked mutation and durable passport fence markers'
    }
}

function Start-BetaPassportMigrationLease {
    param(
        [Parameter(Mandatory = $true)][string]$PostgresContainer,
        [Parameter(Mandatory = $true)][string]$SystemIdentifier,
        [Parameter(Mandatory = $true)][string]$DatabaseOid,
        [Parameter(Mandatory = $true)][string]$TemporaryPassword
    )
    Assert-BetaPassportLeaseMarkers
    if ($SystemIdentifier -notmatch '^[0-9]+$' -or $DatabaseOid -notmatch '^[0-9]+$' -or
        $TemporaryPassword -notmatch '^[0-9a-f]{64}$') {
        throw 'Beta migration lease inputs are invalid'
    }
    $expires = [DateTime]::UtcNow.AddMinutes(30).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $sql = @'
BEGIN;
DO $preflight$
BEGIN
    IF current_database() <> 'marty'
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
        OR '__SYSTEM_ID__' IS DISTINCT FROM
            (SELECT system_identifier::text FROM pg_control_system())
        OR '__DATABASE_OID__' IS DISTINCT FROM
            (SELECT oid::text FROM pg_database WHERE datname=current_database())
        OR (SELECT count(*) FROM passport_cutover.state
            WHERE singleton=true AND phase='fully_fenced' AND epoch>0) <> 1
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='marty_beta_migrator'
            AND NOT rolcanlogin AND NOT rolinherit AND NOT rolsuper
            AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolbypassrls)
        OR EXISTS (SELECT 1 FROM pg_auth_members WHERE
            roleid='marty_beta_migrator'::regrole OR member='marty_beta_migrator'::regrole)
        OR EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename='marty'
            AND pid<>pg_backend_pid()) THEN
        RAISE EXCEPTION 'beta passport migration lease preflight failed';
    END IF;
END
$preflight$;
-- Guarded schema/table DDL stays unavailable to this network login.
GRANT marty TO marty_beta_migrator;
ALTER ROLE marty_beta_migrator LOGIN INHERIT
    PASSWORD '__PASSWORD__' VALID UNTIL '__EXPIRES__';
COMMIT;
'@
    $sql = $sql.Replace('__SYSTEM_ID__', $SystemIdentifier).
        Replace('__DATABASE_OID__', $DatabaseOid).
        Replace('__PASSWORD__', $TemporaryPassword).
        Replace('__EXPIRES__', $expires)
    Invoke-BetaPassportLeaseSql -PostgresContainer $PostgresContainer -Sql $sql | Out-Null
}

function Stop-BetaPassportMigrationLease {
    param(
        [Parameter(Mandatory = $true)][string]$PostgresContainer,
        [Parameter(Mandatory = $true)][string]$SystemIdentifier,
        [Parameter(Mandatory = $true)][string]$DatabaseOid
    )
    Assert-BetaPassportLeaseMarkers
    if ($SystemIdentifier -notmatch '^[0-9]+$' -or $DatabaseOid -notmatch '^[0-9]+$') {
        throw 'Beta migration lease target is invalid'
    }
    $sql = @'
BEGIN;
DO $target$
BEGIN
    IF current_database() <> 'marty'
        OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
        OR '__SYSTEM_ID__' IS DISTINCT FROM
            (SELECT system_identifier::text FROM pg_control_system())
        OR '__DATABASE_OID__' IS DISTINCT FROM
            (SELECT oid::text FROM pg_database WHERE datname=current_database()) THEN
        RAISE EXCEPTION 'beta passport migration lease target changed';
    END IF;
END
$target$;
ALTER ROLE marty_beta_migrator NOLOGIN NOINHERIT PASSWORD NULL VALID UNTIL 'infinity';
REVOKE marty FROM marty_beta_migrator;
COMMIT;
-- Authentication and inherited guarded DDL are now disabled even if cleanup fails.
SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity
    WHERE usename='marty_beta_migrator' AND pid<>pg_backend_pid();
BEGIN;
DO $closed$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_auth_members WHERE
        roleid='marty_beta_migrator'::regrole OR member='marty_beta_migrator'::regrole)
        OR EXISTS (SELECT 1 FROM pg_stat_activity
            WHERE usename='marty_beta_migrator' AND pid<>pg_backend_pid())
        OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname='marty_beta_migrator'
            AND (rolcanlogin OR rolinherit OR rolsuper OR rolcreaterole
                 OR rolcreatedb OR rolbypassrls)) THEN
        RAISE EXCEPTION 'beta passport migration lease remains active';
    END IF;
END
$closed$;
COMMIT;
'@
    $sql = $sql.Replace('__SYSTEM_ID__', $SystemIdentifier).
        Replace('__DATABASE_OID__', $DatabaseOid)
    Invoke-BetaPassportLeaseSql -PostgresContainer $PostgresContainer -Sql $sql | Out-Null
}
