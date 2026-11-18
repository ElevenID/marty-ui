param(
    [Parameter(Mandatory = $true)][string]$StackManifest,
    [Parameter(Mandatory = $true)][string]$BetaBaselineManifest,
    [Parameter(Mandatory = $true)][string]$PriorStackManifest,
    [Parameter(Mandatory = $true)][string]$PreinstallTargetFile,
    [Parameter(Mandatory = $true)][string]$PriorReceipt,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

# The SQL fence is already installed. Reissue only its source-bound host
# receipt after the next signed release proves the identical fence SQL.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Protected fence receipt rebind requires the Windows beta host'
}
$repo = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')
if ($OutputPath -cnotmatch '^[A-Za-z]:\\[^\\/:*?"<>|\r\n]+(?:\\[^\\/:*?"<>|\r\n]+)*$') {
    throw 'Rebound fence receipt must use an absolute local Windows drive path'
}
$output = [IO.Path]::GetFullPath($OutputPath)
if ($output.StartsWith($repo + '\', [StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $output)) {
    throw 'Rebound fence receipt path is inside source or already exists'
}
$prior = [IO.Path]::GetFullPath($PriorReceipt)
if ($prior -ceq $output -or -not (Test-Path -LiteralPath $prior -PathType Leaf)) {
    throw 'Prior completed fence receipt is unavailable'
}
. (Join-Path $PSScriptRoot 'beta-deployment-lock.ps1')
. (Join-Path $PSScriptRoot 'beta-passport-fence-legacy-boundary.ps1')
. (Join-Path $PSScriptRoot 'beta-passport-fence-rebind-record.ps1')

function Get-BytesSha256([byte[]]$Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
}

$lock = Enter-BetaDeploymentLock
try {
    $markerPath = Get-BetaPassportFenceMarkerPath
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw 'Completed beta fence host record is missing'
    }
    $oldMarkerBytes = [IO.File]::ReadAllBytes($markerPath)
    $oldMarker = [Text.Encoding]::UTF8.GetString($oldMarkerBytes) | ConvertFrom-Json
    $oldReceiptBytes = [IO.File]::ReadAllBytes($prior)
    $oldHash = Get-BytesSha256 $oldReceiptBytes
    $oldReceipt = [Text.Encoding]::UTF8.GetString($oldReceiptBytes) | ConvertFrom-Json
    if ($oldMarker.schema -cne 'marty.passport-beta-fence-host-record/v1' -or
        $oldMarker.receipt_path -cne $prior -or
        $oldMarker.receipt_file_sha256 -cne $oldHash -or
        $oldMarker.source_commit -cne $oldReceipt.source_commit -or
        $oldMarker.approved_target_observation_sha256 -cne
            $oldReceipt.approved_target_observation_sha256) {
        throw 'Completed beta fence host record differs from the prior receipt'
    }
    $args = @(
        (Join-Path $PSScriptRoot 'check_passport_beta_fence_rebind_authority.py'),
        '--stack-manifest', $StackManifest,
        '--beta-baseline-manifest', $BetaBaselineManifest,
        '--prior-stack-manifest', $PriorStackManifest,
        '--preinstall-target', $PreinstallTargetFile,
        '--prior-receipt', $prior
    )
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& python @args 2>$null)
        if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 1) {
            throw 'Signed fence source rebind authority failed'
        }
        $plan = $lines[0] | ConvertFrom-Json -ErrorAction Stop
    }
    finally { $ErrorActionPreference = $previousErrorAction }
    if ($plan.schema -cne 'marty.passport-beta-fence-rebind-plan/v1' -or
        $plan.verified -ne $true -or
        $plan.prior_receipt_file_sha256 -cne $oldHash -or
        $plan.prior_source_commit -cne $oldReceipt.source_commit -or
        $plan.receipt.source_commit -cne $plan.source_commit -or
        $plan.receipt.rebind.prior_receipt_file_sha256 -cne $oldHash -or
        (Get-BytesSha256 ([IO.File]::ReadAllBytes($prior))) -cne $oldHash -or
        (Get-BytesSha256 ([IO.File]::ReadAllBytes($markerPath))) -cne
            (Get-BytesSha256 $oldMarkerBytes)) {
        throw 'Completed beta fence receipt or host record changed during rebind'
    }
    $receiptJson = ($plan.receipt | ConvertTo-Json -Depth 40 -Compress) + "`n"
    $receiptBytes = [Text.UTF8Encoding]::new($false).GetBytes($receiptJson)
    $receiptHash = Get-BytesSha256 $receiptBytes
    $marker = [ordered]@{
        schema = 'marty.passport-beta-fence-host-record/v1'
        receipt_path = $output
        receipt_file_sha256 = $receiptHash
        source_commit = $plan.source_commit
        approved_target_observation_sha256 =
            $plan.receipt.approved_target_observation_sha256
    }
    $markerBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($marker | ConvertTo-Json -Compress) + "`n")
    Write-BetaFenceReboundRecord -Output $output -ReceiptBytes $receiptBytes `
        -MarkerPath $markerPath -MarkerBytes $markerBytes `
        -OldMarkerBytes $oldMarkerBytes
    Write-Output ([ordered]@{
        schema = 'marty.passport-beta-fence-source-rebind-result/v1'
        source_commit = $plan.source_commit
        receipt_path = $output
        receipt_file_sha256 = $receiptHash
        prior_receipt_file_sha256 = $oldHash
    } | ConvertTo-Json -Compress)
}
finally { Exit-BetaDeploymentLock -Lock $lock }
