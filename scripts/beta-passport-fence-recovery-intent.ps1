# Read-only checks shared by recovery preflight and final receipt completion.
function Assert-BetaPassportFenceRecoveryIntent {
    param(
        [Parameter(Mandatory = $true)][string]$FenceMarkerPath,
        [Parameter(Mandatory = $true)][string]$MutationMarkerPath
    )
    if (-not (Test-Path -LiteralPath $FenceMarkerPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $MutationMarkerPath -PathType Leaf)) {
        throw 'Interrupted fence intent markers are unavailable or changed'
    }
    $intent = [IO.File]::ReadAllText($FenceMarkerPath)
    if ($intent -cnotmatch
        '^passport fence intent ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z)\r?\n$') {
        throw 'Interrupted fence intent markers are unavailable or changed'
    }
    return [DateTimeOffset]::Parse($Matches[1])
}

function Assert-BetaPassportFenceRecoveryTiming {
    param(
        [Parameter(Mandatory = $true)][DateTimeOffset]$IntentAt,
        [Parameter(Mandatory = $true)][DateTimeOffset]$InstalledAt
    )
    # The Windows host and Docker VM clocks can differ by subsecond amounts.
    $lag = $InstalledAt - $IntentAt
    if ($lag.TotalSeconds -lt -5 -or $lag.TotalMinutes -gt 10) {
        throw 'Interrupted fence intent is not contemporaneous with installation'
    }
}
