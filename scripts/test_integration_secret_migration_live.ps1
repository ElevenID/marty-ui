# Opt-in live contract. Build these two development binaries first:
# cargo build -p marty-signing-keys --bin marty-signing-keys
# cargo build -p marty-issuance-service --features integration-secret-migration --bin marty-integration-secret-migrate
# Uses only disposable Docker containers and synthetic fixture material.
$ErrorActionPreference = 'Stop'
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 10)
$pgName = "kmsmig-pg-$suffix"
$baoName = "kmsmig-bao-$suffix"
$redisName = "kmsmig-redis-$suffix"
$created = @()
$service = $null
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $workspaceRoot 'rust\target' }
$binRoot = Join-Path $targetRoot 'debug'
try {
    $pgId = docker run --rm -d --name $pgName -e POSTGRES_USER=kmstest -e POSTGRES_PASSWORD=kmstest -e POSTGRES_DB=kmstest -p 127.0.0.1::5432 postgres:16
    if ($LASTEXITCODE -ne 0) { throw 'disposable PostgreSQL startup failed' }
    $created += $pgName
    $baoId = docker run --rm -d --name $baoName -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 -p 127.0.0.1::8200 quay.io/openbao/openbao:2 server -dev -dev-root-token-id=kmstest-token
    if ($LASTEXITCODE -ne 0) { throw 'disposable OpenBao startup failed' }
    $created += $baoName
    $redisId = docker run --rm -d --name $redisName -p 127.0.0.1::6379 redis:7-alpine
    if ($LASTEXITCODE -ne 0) { throw 'disposable Redis startup failed' }
    $created += $redisName
    $pgPort = [int]((docker port $pgName 5432/tcp) -split ':')[-1]
    $baoPort = [int]((docker port $baoName 8200/tcp) -split ':')[-1]
    $redisPort = [int]((docker port $redisName 6379/tcp) -split ':')[-1]
    $baoUrl = "http://127.0.0.1:$baoPort"
    for ($i = 0; $i -lt 60; $i++) {
        docker exec $pgName pg_isready -U kmstest -d kmstest *> $null
        $pgReady = $LASTEXITCODE -eq 0
        try { $baoReady = (Invoke-WebRequest "$baoUrl/v1/sys/health" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 } catch { $baoReady = $false }
        if ($pgReady -and $baoReady) { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not ($pgReady -and $baoReady)) { throw 'disposable services did not become healthy' }
    $headers = @{ 'X-Vault-Token' = 'kmstest-token' }
    Invoke-RestMethod -Uri "$baoUrl/v1/sys/mounts/transit" -Method Post -Headers $headers -ContentType 'application/json' -Body '{"type":"transit"}' | Out-Null
    Invoke-RestMethod -Uri "$baoUrl/v1/transit/keys/integration-secret-envelope-marty-aes256" -Method Post -Headers $headers -ContentType 'application/json' -Body '{"type":"aes256-gcm96","exportable":false}' | Out-Null
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $servicePort = $listener.LocalEndpoint.Port
    $listener.Stop()
    $env:SIGNING_KEYS_SERVICE_PORT = [string]$servicePort
    $env:SIGNING_KEYS_INTERNAL_API_KEY = 'kmstest-internal-key'
    $env:SIGNING_KEYS_REDIS_URL = "redis://127.0.0.1:$redisPort/2"
    $env:BAO_ADDR = $baoUrl
    $env:BAO_TOKEN = 'kmstest-token'
    $service = Start-Process -FilePath "$binRoot\marty-signing-keys.exe" -PassThru -WindowStyle Hidden -RedirectStandardOutput "$binRoot\migration-signing-$suffix-out.log" -RedirectStandardError "$binRoot\migration-signing-$suffix-err.log"
    for ($i = 0; $i -lt 60; $i++) {
        if ($service.HasExited) { throw 'signing-keys service exited during startup' }
        try {
            $client = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $servicePort)
            $client.Dispose()
            break
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if ($i -ge 60) { throw 'signing-keys service did not listen' }
    $env:DATABASE_URL = "postgresql://kmstest:kmstest@127.0.0.1:$pgPort/kmstest"
    $env:SIGNING_KEYS_INTERNAL_URL = "http://127.0.0.1:$servicePort/internal"
    $env:INTEGRATION_SECRET_MASTER_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
    $legacy = 'AAECAwQFBgcICQoLJGO4baSW72joIuXuxcQODO+j4mW1no3FYXSCh604xhydFOI='
    $schema = "CREATE SCHEMA issuance_service; CREATE TABLE issuance_service.organization_integration_secrets (id text PRIMARY KEY, organization_id text NOT NULL, provider text NOT NULL, purpose text NOT NULL, encrypted_secret_value text NOT NULL);"
    docker exec $pgName psql -U kmstest -d kmstest -v ON_ERROR_STOP=1 -c $schema | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'fixture schema creation failed' }
    Remove-Item Env:INTEGRATION_SECRET_MASTER_KEY
    & "$binRoot\marty-integration-secret-migrate.exe" audit
    if ($LASTEXITCODE -ne 0) { throw 'empty-table remote provider proof failed' }
    $env:SIGNING_KEYS_INTERNAL_API_KEY = 'wrong-key'
    $ErrorActionPreference = 'Continue'
    & "$binRoot\marty-integration-secret-migrate.exe" audit 2>$null
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -eq 0) { throw 'empty-table audit accepted unavailable KMS authentication' }
    $env:SIGNING_KEYS_INTERNAL_API_KEY = 'kmstest-internal-key'
    $env:INTEGRATION_SECRET_MASTER_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
    docker exec $pgName psql -U kmstest -d kmstest -v ON_ERROR_STOP=1 -c "INSERT INTO issuance_service.organization_integration_secrets VALUES ('secret-1','org-1','canvas','oauth_client_secret','$legacy')" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'fixture insert failed' }
    docker exec $pgName pg_dump -U kmstest -d kmstest --format=custom --file=/tmp/integration-secret-precutover.dump
    if ($LASTEXITCODE -ne 0) { throw 'pre-cutover database snapshot failed' }
    $ErrorActionPreference = 'Continue'
    & "$binRoot\marty-integration-secret-migrate.exe" audit 2>$null
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -eq 0) { throw 'pre-migration audit unexpectedly accepted legacy ciphertext' }
    & "$binRoot\marty-integration-secret-migrate.exe" migrate
    if ($LASTEXITCODE -ne 0) { throw 'migration failed' }
    & "$binRoot\marty-integration-secret-migrate.exe" migrate
    if ($LASTEXITCODE -ne 0) { throw 'idempotent migration rerun failed' }
    Remove-Item Env:INTEGRATION_SECRET_MASTER_KEY
    & "$binRoot\marty-integration-secret-migrate.exe" audit
    if ($LASTEXITCODE -ne 0) { throw 'remote-only audit failed' }
    $stored = docker exec $pgName psql -U kmstest -d kmstest -tAc 'SELECT encrypted_secret_value FROM issuance_service.organization_integration_secrets'
    if ($LASTEXITCODE -ne 0 -or $stored -notmatch 'marty.integration-secret-envelope/v1' -or $stored -match 'canvas-secret-value') { throw 'database envelope check failed' }
    Invoke-RestMethod -Uri "$baoUrl/v1/transit/keys/integration-secret-envelope-marty-aes256/rotate" -Method Post -Headers $headers -ContentType 'application/json' -Body '{}' | Out-Null
    & "$binRoot\marty-integration-secret-migrate.exe" audit
    if ($LASTEXITCODE -ne 0) { throw 'audit after rotation failed' }
    docker exec $pgName psql -U kmstest -d kmstest -v ON_ERROR_STOP=1 -c "UPDATE issuance_service.organization_integration_secrets SET purpose='wrong-purpose' WHERE id='secret-1'" | Out-Null
    $ErrorActionPreference = 'Continue'
    & "$binRoot\marty-integration-secret-migrate.exe" audit 2>$null
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -eq 0) { throw 'binding mismatch was accepted' }
    docker exec $pgName createdb -U kmstest kmstest_recovery
    if ($LASTEXITCODE -ne 0) { throw 'recovery database creation failed' }
    docker exec $pgName pg_restore -U kmstest -d kmstest_recovery --exit-on-error /tmp/integration-secret-precutover.dump
    if ($LASTEXITCODE -ne 0) { throw 'pre-cutover database snapshot restore failed' }
    $recovered = docker exec $pgName psql -U kmstest -d kmstest_recovery -tAc 'SELECT encrypted_secret_value FROM issuance_service.organization_integration_secrets'
    if ($LASTEXITCODE -ne 0 -or $recovered.Trim() -ne $legacy) { throw 'restored legacy envelope differs from pre-cutover snapshot' }
    $env:DATABASE_URL = "postgresql://kmstest:kmstest@127.0.0.1:$pgPort/kmstest_recovery"
    $env:INTEGRATION_SECRET_MASTER_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
    & "$binRoot\marty-integration-secret-migrate.exe" migrate
    if ($LASTEXITCODE -ne 0) { throw 'restored snapshot migration failed' }
    Remove-Item Env:INTEGRATION_SECRET_MASTER_KEY
    & "$binRoot\marty-integration-secret-migrate.exe" audit
    if ($LASTEXITCODE -ne 0) { throw 'restored snapshot remote-only audit failed' }
    Write-Output "PASS disposable PostgreSQL/OpenBao/signing-keys migration, remote-only audit, rotation, binding rejection, database snapshot restore and re-migration"
} finally {
    if ($null -ne $service -and -not $service.HasExited) { Stop-Process -Id $service.Id -Force -ErrorAction SilentlyContinue }
    foreach ($name in $created) {
        if (docker ps --format '{{.Names}}' | Where-Object { $_ -eq $name }) {
            docker stop $name | Out-Null
        }
    }
}
