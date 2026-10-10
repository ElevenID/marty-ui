function Write-BetaFenceReboundRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Output,
        [Parameter(Mandatory = $true)][byte[]]$ReceiptBytes,
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][byte[]]$MarkerBytes,
        [Parameter(Mandatory = $true)][byte[]]$OldMarkerBytes
    )
    $temporary = $MarkerPath + '.rebind-v11241.tmp'
    $backup = $MarkerPath + '.before-rebind-v11241'
    if ((Test-Path -LiteralPath $Output) -or
        (Test-Path -LiteralPath $temporary) -or
        (Test-Path -LiteralPath $backup)) {
        throw 'Fence rebind output, backup, or temporary path already exists'
    }
    $stream = [IO.File]::Open($Output, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($ReceiptBytes, 0, $ReceiptBytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    if ((Get-BytesSha256 ([IO.File]::ReadAllBytes($Output))) -cne
            (Get-BytesSha256 $ReceiptBytes)) {
        throw 'Rebound fence receipt did not persist intact'
    }
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($MarkerBytes, 0, $MarkerBytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    [IO.File]::Replace($temporary, $MarkerPath, $backup, $true)
    if ((Get-BytesSha256 ([IO.File]::ReadAllBytes($MarkerPath))) -cne
            (Get-BytesSha256 $MarkerBytes) -or
        (Get-BytesSha256 ([IO.File]::ReadAllBytes($backup))) -cne
            (Get-BytesSha256 $OldMarkerBytes)) {
        throw 'Fence host record atomic replacement requires inspection'
    }
}
