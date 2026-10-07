# Opt-in cold recovery contract for the self-host OpenBao Raft configuration.
# Uses synthetic data and disposable Docker containers/volumes only. The copy is
# taken while OpenBao is stopped; no Transit key backup or plaintext export.
$ErrorActionPreference = 'Stop'
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 10)
$sourceName = "kmsrecovery-source-$suffix"
$restoredName = "kmsrecovery-restored-$suffix"
$snapshotName = "kmsrecovery-snapshot-$suffix"
$sourceVolume = "kmsrecovery-source-data-$suffix"
$restoredVolume = "kmsrecovery-restored-data-$suffix"
$snapshotVolume = "kmsrecovery-snapshot-data-$suffix"
$containers = @()
$volumes = @()
$config = (Resolve-Path (Join-Path $PSScriptRoot '..\docker\openbao-selfhost.hcl')).Path
$image = if ($env:MARTY_OPENBAO_PROBE_IMAGE) { $env:MARTY_OPENBAO_PROBE_IMAGE } else { 'marty-openbao-ha-probe:local' }
$python = if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) { 'python' } else { 'python3' }
$hostTemp = Join-Path ([System.IO.Path]::GetTempPath()) "kms-raft-export-$suffix"

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

function Wait-RaftLeader([string]$BaseUrl, [hashtable]$Headers) {
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            $leader = Invoke-RestMethod -Uri "$BaseUrl/v1/sys/leader" -Headers $Headers -TimeoutSec 2
            if ($leader.is_self) { return }
        } catch {
            # Raft may still be electing its leader after unseal.
        }
        Start-Sleep -Milliseconds 500
    }
    throw 'disposable OpenBao did not become the Raft leader'
}

function Start-RaftOpenBao([string]$Name, [string]$Volume) {
    docker run --rm -d --name $Name --label marty.disposable=kms-raft-recovery-probe -p 127.0.0.1::8200 `
        --mount "type=volume,src=$Volume,dst=/bao/data" `
        --mount "type=bind,src=$config,dst=/bao/config/openbao.hcl,readonly" `
        $image server '-config=/bao/config/openbao.hcl' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'disposable OpenBao startup failed' }
    $port = [int]((docker port $Name 8200/tcp) -split ':')[-1]
    return "http://127.0.0.1:$port"
}

try {
    docker volume create --label marty.disposable=kms-raft-recovery-probe $sourceVolume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'source volume creation failed' }
    $volumes += $sourceVolume
    docker volume create --label marty.disposable=kms-raft-recovery-probe $restoredVolume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'recovery volume creation failed' }
    $volumes += $restoredVolume
    docker volume create --label marty.disposable=kms-raft-recovery-probe $snapshotVolume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'snapshot recovery volume creation failed' }
    $volumes += $snapshotVolume
    foreach ($volume in $volumes) {
        docker run --rm --entrypoint sh `
            --mount "type=volume,src=$volume,dst=/bao/data" `
            $image -c 'chown 100:1000 /bao/data' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'disposable OpenBao storage ownership setup failed' }
    }

    $containers += $sourceName
    $sourceUrl = Start-RaftOpenBao $sourceName $sourceVolume
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
    Wait-RaftLeader $sourceUrl $headers
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

    $pluginSha = [string]((docker exec $sourceName sha256sum /plugins/openbao-didcomm-authcrypt) -split '\s+')[0]
    if ($LASTEXITCODE -ne 0 -or $pluginSha.Length -ne 64) { throw 'candidate plugin binary is unavailable' }
    $pluginBody = @{ command = 'openbao-didcomm-authcrypt'; sha256 = $pluginSha } | ConvertTo-Json -Compress
    Invoke-RestMethod -Uri "$sourceUrl/v1/sys/plugins/catalog/secret/openbao-didcomm-authcrypt" -Method Put `
        -Headers $headers -ContentType 'application/json' -Body $pluginBody | Out-Null
    Invoke-RestMethod -Uri "$sourceUrl/v1/sys/mounts/didcomm" -Method Post `
        -Headers $headers -ContentType 'application/json' -Body '{"type":"openbao-didcomm-authcrypt"}' | Out-Null
    $senderBody = '{"sender_did":"did:example:recovery","sender_key_id":"did:example:recovery#agreement-1"}'
    $sender = Invoke-RestMethod -Uri "$sourceUrl/v1/didcomm/keys/tenant_a/sender" -Method Post `
        -Headers $headers -ContentType 'application/json' -Body $senderBody
    $haip = Invoke-RestMethod -Uri "$sourceUrl/v1/didcomm/haip/keys/tenant_a/flow_a" -Method Post `
        -Headers $headers -ContentType 'application/json' -Body '{}'
    $senderVersion = [string]$sender.data.version
    $haipVersion = [string]$haip.data.version
    if (-not $senderVersion -or -not $haipVersion) { throw 'source plugin omitted key versions' }

    $hostState = Join-Path $hostTemp 'state'
    $hostExports = Join-Path $hostTemp 'exports'
    New-Item -ItemType Directory -Path $hostState, $hostExports -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $hostState 'selfhost-init.json'), ($initialized | ConvertTo-Json -Depth 12))
    [System.IO.File]::WriteAllText((Join-Path $hostState 'root.token'), $rootToken)
    [System.IO.File]::WriteAllText((Join-Path $hostState 'unseal.key'), $unsealKey)
    & $python (Join-Path $PSScriptRoot 'export-selfhost-openbao.py') `
        --state-dir $hostState --export-dir $hostExports --config-file $config --bao-url $sourceUrl | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'live Raft snapshot exporter failed' }
    $archives = @(Get-ChildItem -LiteralPath $hostExports -Filter '*.zip')
    if ($archives.Count -ne 1) { throw 'live Raft snapshot exporter did not create one archive' }
    $extracted = Join-Path $hostTemp 'extracted'
    Expand-Archive -LiteralPath $archives[0].FullName -DestinationPath $extracted
    $manifest = Get-Content -LiteralPath (Join-Path $extracted 'manifest.json') -Raw | ConvertFrom-Json
    $snapshotFile = Join-Path $extracted 'raft.snap'
    $snapshotHash = (Get-FileHash -LiteralPath $snapshotFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($manifest.format -cne 'marty-openbao-raft-snapshot-v1' -or
        $manifest.snapshot_sha256 -cne $snapshotHash) {
        throw 'live Raft snapshot archive failed its manifest check'
    }

    docker stop $sourceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'source OpenBao did not stop before snapshot' }
    $containers = @($containers | Where-Object { $_ -ne $sourceName })
    docker run --rm --entrypoint sh `
        --mount "type=volume,src=$sourceVolume,dst=/source,readonly" `
        --mount "type=volume,src=$restoredVolume,dst=/restored" `
        $image -c 'cp -a /source/. /restored/' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'cold OpenBao storage snapshot copy failed' }

    $containers += $restoredName
    $restoredUrl = Start-RaftOpenBao $restoredName $restoredVolume
    if (-not (Wait-InitializedApi $restoredUrl).initialized) { throw 'restored storage was not initialized' }
    $restoredUnseal = Invoke-RestMethod -Uri "$restoredUrl/v1/sys/unseal" -Method Post `
        -ContentType 'application/json' -Body $unsealBody
    if ($restoredUnseal.sealed) { throw 'restored OpenBao remained sealed' }
    Wait-RaftLeader $restoredUrl $headers
    $decrypted = Invoke-RestMethod -Uri "$restoredUrl/v1/transit/decrypt/$keyName" -Method Post `
        -Headers $headers -ContentType 'application/json' `
        -Body (@{ ciphertext = $ciphertext } | ConvertTo-Json -Compress)
    if ([string]$decrypted.data.plaintext -cne $plaintext) {
        throw 'restored OpenBao could not decrypt the pre-snapshot envelope'
    }
    $restoredSender = Invoke-RestMethod -Uri "$restoredUrl/v1/didcomm/keys/tenant_a/sender/versions/$senderVersion" -Headers $headers
    $restoredHaip = Invoke-RestMethod -Uri "$restoredUrl/v1/didcomm/haip/keys/tenant_a/flow_a/versions/$haipVersion" -Headers $headers
    if ([string]$restoredSender.data.version -cne $senderVersion -or
        [string]$restoredHaip.data.version -cne $haipVersion) {
        throw 'restored OpenBao lost pre-snapshot plugin key versions'
    }

    $containers += $snapshotName
    $snapshotUrl = Start-RaftOpenBao $snapshotName $snapshotVolume
    if ((Wait-InitializedApi $snapshotUrl).initialized) { throw 'snapshot recovery volume was already initialized' }
    $snapshotInit = Invoke-RestMethod -Uri "$snapshotUrl/v1/sys/init" -Method Post `
        -ContentType 'application/json' -Body '{"secret_shares":1,"secret_threshold":1}'
    $snapshotUnsealBody = @{ key = [string]$snapshotInit.keys_base64[0] } | ConvertTo-Json -Compress
    $snapshotUnsealed = Invoke-RestMethod -Uri "$snapshotUrl/v1/sys/unseal" -Method Post `
        -ContentType 'application/json' -Body $snapshotUnsealBody
    if ($snapshotUnsealed.sealed) { throw 'snapshot recovery node remained sealed' }
    $snapshotHeaders = @{ 'X-Vault-Token' = [string]$snapshotInit.root_token }
    Wait-RaftLeader $snapshotUrl $snapshotHeaders
    Invoke-RestMethod -Uri "$snapshotUrl/v1/sys/storage/raft/snapshot-force" -Method Post `
        -Headers $snapshotHeaders -ContentType 'application/octet-stream' -InFile $snapshotFile | Out-Null
    docker stop $snapshotName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'snapshot recovery node did not stop' }
    $snapshotUrl = Start-RaftOpenBao $snapshotName $snapshotVolume
    $snapshotUnsealed = Invoke-RestMethod -Uri "$snapshotUrl/v1/sys/unseal" -Method Post `
        -ContentType 'application/json' -Body $unsealBody
    if ($snapshotUnsealed.sealed) { throw 'snapshot recovery did not accept original unseal key' }
    Wait-RaftLeader $snapshotUrl $headers
    $snapshotDecrypted = Invoke-RestMethod -Uri "$snapshotUrl/v1/transit/decrypt/$keyName" -Method Post `
        -Headers $headers -ContentType 'application/json' `
        -Body (@{ ciphertext = $ciphertext } | ConvertTo-Json -Compress)
    if ([string]$snapshotDecrypted.data.plaintext -cne $plaintext) {
        throw 'snapshot restore could not decrypt pre-snapshot Transit ciphertext'
    }
    $snapshotSender = Invoke-RestMethod -Uri "$snapshotUrl/v1/didcomm/keys/tenant_a/sender/versions/$senderVersion" -Headers $headers
    $snapshotHaip = Invoke-RestMethod -Uri "$snapshotUrl/v1/didcomm/haip/keys/tenant_a/flow_a/versions/$haipVersion" -Headers $headers
    if ([string]$snapshotSender.data.version -cne $senderVersion -or
        [string]$snapshotHaip.data.version -cne $haipVersion) {
        throw 'snapshot restore lost pre-snapshot plugin key versions'
    }
    Write-Output 'PASS disposable OpenBao live Raft export, cold restore and fresh-cluster snapshot restore'
} finally {
    foreach ($name in $containers) {
        docker rm -f $name 2>$null | Out-Null
    }
    foreach ($volume in $volumes) {
        docker volume rm $volume | Out-Null
    }
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $resolvedTemp = [System.IO.Path]::GetFullPath($hostTemp)
    if ($resolvedTemp.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
        [System.IO.Path]::GetFileName($resolvedTemp).StartsWith('kms-raft-export-', [System.StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
