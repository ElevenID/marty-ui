# Set BETA_FENCE_DISPOSABLE_DOCKER=1 to exercise the exact operator function
# against an isolated PostgreSQL container. No beta or production container is
# selected by this test.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:BETA_FENCE_DISPOSABLE_DOCKER -cne '1') {
    throw 'Disposable Docker test requires BETA_FENCE_DISPOSABLE_DOCKER=1'
}
$operator = Join-Path (Split-Path -Parent $PSScriptRoot) `
    'scripts/run-passport-beta-native-db-gates.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $operator, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Native database operator has a parse error' }
$functions = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Invoke-ExactNativeSql'
}, $true))
if ($functions.Count -ne 1) { throw 'Exact native SQL stream function is absent' }
. ([scriptblock]::Create($functions[0].Extent.Text))

$name = 'marty-native-sql-stream-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$image = 'postgres:15-alpine@sha256:fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c'
$container = $null
try {
    $container = @(& docker run --rm -d --name $name --network none `
        -e POSTGRES_PASSWORD=disposable-only $image)
    if ($LASTEXITCODE -ne 0 -or $container.Count -ne 1 -or
        $container[0] -notmatch '^[0-9a-f]{64}$') {
        throw 'Disposable PostgreSQL did not start'
    }
    $id = [string]$container[0]
    $ready = $false
    $ErrorActionPreference = 'Continue'
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $probe = @(& docker exec $id psql -U postgres -d postgres -At `
            -c 'SELECT 1' 2>$null)
        if ($LASTEXITCODE -eq 0 -and $probe.Count -eq 1 -and $probe[0] -eq '1') {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    $ErrorActionPreference = 'Stop'
    if (-not $ready) { throw 'Disposable PostgreSQL was not ready' }
    $created = $false
    $ErrorActionPreference = 'Continue'
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        & docker exec $id createdb -U postgres marty 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $created = $true; break }
        Start-Sleep -Milliseconds 250
    }
    $ErrorActionPreference = 'Stop'
    if (-not $created) { throw 'Disposable marty database was not created' }
    $unicode = [string][char]0x00e9
    $sql = "SET client_encoding='UTF8';`n" +
        "CREATE TABLE native_byte_probe (value text NOT NULL);`n" +
        "INSERT INTO native_byte_probe VALUES ('$unicode');`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($sql)
    Invoke-ExactNativeSql -Container $id -Payload $bytes
    $hex = @(& docker exec $id psql -U postgres -d marty -At `
        -c "SELECT encode(convert_to(value, 'UTF8'), 'hex') FROM native_byte_probe")
    if ($LASTEXITCODE -ne 0 -or $hex.Count -ne 1 -or $hex[0] -cne 'c3a9') {
        throw 'Exact native SQL stream changed UTF-8 bytes'
    }
    Write-Output 'disposable exact-byte native SQL stream passed'
}
finally {
    if ($null -ne $container -and $container.Count -eq 1 -and
        $container[0] -match '^[0-9a-f]{64}$') {
        & docker stop ([string]$container[0]) 2>$null | Out-Null
    }
}
