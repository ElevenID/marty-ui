function Assert-CompleteRunnerInventory {
    param($Response)
    $runners = @($Response.runners | Where-Object { $null -ne $_ })
    if ($Response.total_count -ne $runners.Count) {
        throw "Repository runner inventory is incomplete"
    }
    return $runners
}

function Assert-ExistingRunnerRouting {
    param([object[]]$Runners, [string]$PurposeLabel)
    foreach ($existing in $Runners) {
        $labels = @($existing.labels | ForEach-Object { ([string]$_.name).ToLowerInvariant() })
        if ("canvas-oss-wsl2" -in $labels -and "passport-beta-wsl2" -in $labels) {
            throw "Existing runner $($existing.name) advertises both protected purposes"
        }
        if ($PurposeLabel -in $labels) {
            throw "Existing runner $($existing.name) already advertises $PurposeLabel"
        }
    }
}

function Assert-NewRunnerRouting {
    param($Registered, [string]$PurposeLabel)
    $expectedLabels = @("self-hosted", "linux", "x64", $PurposeLabel)
    $actualLabels = @($Registered.labels | ForEach-Object { ([string]$_.name).ToLowerInvariant() })
    $missingLabels = @($expectedLabels | Where-Object { $_ -notin $actualLabels })
    if ($missingLabels.Count -gt 0) {
        throw "Ephemeral runner is missing required labels: $($missingLabels -join ', ')"
    }
    $unexpectedLabels = @($actualLabels | Where-Object { $_ -notin $expectedLabels })
    if ($unexpectedLabels.Count -gt 0) {
        throw "Ephemeral runner has unexpected routing labels: $($unexpectedLabels -join ', ')"
    }
}
