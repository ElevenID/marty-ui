# Opt-in recovery contract for the self-host OpenBao file-storage configuration.
# Uses synthetic data and disposable Docker containers/volumes only. The copy is
# taken while OpenBao is stopped; no Transit key backup or plaintext export.
$ErrorActionPreference = 'Stop'
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 10)
$sourceName = "kmsrecovery-source-$suffix"
$restoredName = "kmsrecovery-restored-$suffix"
$sourceVolume = "kmsrecovery-source-data-$suffix"
$restoredVolume = "kmsrecovery-restored-data-$suffix"
$containers = @()
$volumes = @()
$config = (Resolve-Path (Join-Path $PSScriptRoot '..\docker\openbao-selfhost.hcl')).Path

function Wait-InitializedApi([string]$BaseUrl) {
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            return Invoke-RestMethod -Uri "$BaseUrl/v1/sys/init" -TimeoutSec 2
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    throw 'disposable OpenBao initialization API did not become ready'
}

function Start-FileOpenBao([string]$Name, [string]$Volume) {
    docker run --rm -d --name $Name -p 127.0.0.1::8200 `
        --mount "type=volume,src=$Volume,dst=/bao/data" `
        --mount "type=bind,src=$config,dst=/bao/config/openbao.hcl,readonly" `
        quay.io/openbao/openbao:2 server '-config=/bao/config/openbao.hcl' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'disposable OpenBao startup failed' }
    $port = [int]((docker port $Name 8200/tcp) -split ':')[-1]
    return "http://127.0.0.1:$port"
}

try {
    docker volume create $sourceVolume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'source volume creation failed' }
    $volumes += $sourceVolume
    docker volume create $restoredVolume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'recovery volume creation failed' }
    $volumes += $restoredVolume
    foreach ($volume in $volumes) {
        docker run --rm --entrypoint sh `
            --mount "type=volume,src=$volume,dst=/bao/data" `
            quay.io/openbao/openbao:2 -c 'chown 100:1000 /bao/data' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'disposable OpenBao storage ownership setup failed' }
    }

    $sourceUrl = Start-FileOpenBao $sourceName $sourceVolume
    $containers += $sourceName
    if ((Wait-InitializedApi $sourceUrl).initialized) { throw 'new source volume was already initialized' }
    $initialized = Invoke-RestMethod -Uri "$sourceUrl/v1/sys/init" -Method Post `
        -ContentType 'application/json' -Body '{"secret_shares":1,"secret_threshold":1}'
    $unsealKey = [string]$initialized.keys_base64[0]
    $rootToken = [string]$initialized.root_token
    if (-not $unsealKey -or -not $rootToken) { throw 'source initialization omitted recovery material' }
    $unsealBody = @{ key = $unsealKey } | ConvertTo-Json -Compress
    $unsealed = Invoke-RestMethod -Uri "$sourceUrl/v1/sys/unseal" -Method Post `
        -ContentType 'application/json' -Body $unsealBody
    if ($unsealed.sealed) { throw 'source OpenBao remained sealed' }
    $headers = @{ 'X-Vault-Token' = $rootToken }
    Invoke-RestMethod -Uri "$sourceUrl/v1/sys/mounts/transit" -Method Post `
        -Headers $headers -ContentType 'application/json' -Body '{"type":"transit"}' | Out-Null
    $keyName = 'integration-secret-envelope-marty-aes256'
    Invoke-RestMethod -Uri "$sourceUrl/v1/transit/keys/$keyName" -Method Post `
        -Headers $headers -ContentType 'application/json' `
        -Body '{"type":"aes256-gcm96","exportable":false,"allow_plaintext_backup":false}' | Out-Null
    $plaintext = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('synthetic-recovery-proof'))
    $encrypted = Invoke-RestMethod -Uri "$sourceUrl/v1/transit/encrypt/$keyName" -Method Post `
        -Headers $headers -ContentType 'application/json' -Body (@{ plaintext = $plaintext } | ConvertTo-Json -Compress)
    $ciphertext = [string]$encrypted.data.ciphertext
    if (-not $ciphertext.StartsWith('vault:v1:')) { throw 'source encryption did not produce a Transit envelope' }

    docker stop $sourceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'source OpenBao did not stop before snapshot' }
    $containers = @($containers | Where-Object { $_ -ne $sourceName })
    docker run --rm --entrypoint sh `
        --mount "type=volume,src=$sourceVolume,dst=/source,readonly" `
        --mount "type=volume,src=$restoredVolume,dst=/restored" `
        postgres:16 -c 'cp -a /source/. /restored/' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'cold OpenBao storage snapshot copy failed' }

    $restoredUrl = Start-FileOpenBao $restoredName $restoredVolume
    $containers += $restoredName
    if (-not (Wait-InitializedApi $restoredUrl).initialized) { throw 'restored storage was not initialized' }
    $restoredUnseal = Invoke-RestMethod -Uri "$restoredUrl/v1/sys/unseal" -Method Post `
        -ContentType 'application/json' -Body $unsealBody
    if ($restoredUnseal.sealed) { throw 'restored OpenBao remained sealed' }
    $decrypted = Invoke-RestMethod -Uri "$restoredUrl/v1/transit/decrypt/$keyName" -Method Post `
        -Headers $headers -ContentType 'application/json' `
        -Body (@{ ciphertext = $ciphertext } | ConvertTo-Json -Compress)
    if ([string]$decrypted.data.plaintext -cne $plaintext) {
        throw 'restored OpenBao could not decrypt the pre-snapshot envelope'
    }
    Write-Output 'PASS disposable OpenBao file-storage cold snapshot, unseal and pre-snapshot decrypt'
} finally {
    foreach ($name in $containers) {
        if (docker ps --format '{{.Names}}' | Where-Object { $_ -eq $name }) {
            docker stop $name | Out-Null
        }
    }
    foreach ($volume in $volumes) {
        docker volume rm $volume | Out-Null
    }
}
