# Pure, worker-only rollback data contract. No Docker, filesystem, or environment writes.
# Never accept arbitrary shell text or copy the container's secret-bearing environment.
function Get-BetaWorkerField {
    param($Object, [string]$Name)
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ($key -ceq $Name) { return [pscustomobject]@{ Present = $true; Value = $Object[$key] } }
        }
        return [pscustomobject]@{ Present = $false; Value = $null }
    }
    if ($null -eq $Object) { return [pscustomobject]@{ Present = $false; Value = $null } }
    foreach ($property in $Object.PSObject.Properties) {
        if ($property.Name -ceq $Name) { return [pscustomobject]@{ Present = $true; Value = $property.Value } }
    }
    return [pscustomobject]@{ Present = $false; Value = $null }
}

function Test-BetaWorkerVector {
    param($Value, [string[]]$Expected)
    if ($null -eq $Value -or $Value -isnot [array] -or $Value.Count -ne $Expected.Count) { return $false }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ($Value[$index] -isnot [string] -or $Value[$index] -cne $Expected[$index]) { return $false }
    }
    return $true
}

function Get-BetaWorkerSelectionContracts {
    [pscustomobject]@{
        Name = 'SERVICE_NAME'; PresentField = 'service_name_present'; ValueField = 'service_name'
        Allowed = @('', 'issuance', 'issuance-native', 'issuance_native', 'canvas-sync-worker', 'canvas_sync_worker')
    }
    [pscustomobject]@{
        Name = 'CANVAS_SYNC_PROCESSOR'; PresentField = 'canvas_sync_processor_present'; ValueField = 'canvas_sync_processor'
        Allowed = @('', 'issuance.infrastructure.api.canvas_routes:process_authoritative_canvas_sync_target')
    }
}

function Get-BetaWorkerSelector {
    param($Environment, [ValidateSet('SERVICE_NAME', 'CANVAS_SYNC_PROCESSOR')][string]$Name = 'SERVICE_NAME')
    $present = $false
    $value = $null
    if ($null -ne $Environment -and $Environment -isnot [array]) { throw "Invalid worker image environment shape; use a reviewed recovery manifest." }
    foreach ($entry in $Environment) {
        if ($entry -isnot [string]) { throw "Invalid worker image environment entry; use a reviewed recovery manifest." }
        if ($entry -ceq $Name -or $entry.StartsWith($Name + '=', [StringComparison]::Ordinal)) {
            if ($present -or $entry -ceq $Name) { throw "Ambiguous worker selector; use a reviewed recovery manifest." }
            $present = $true
            $value = $entry.Substring($Name.Length + 1)
        }
    }
    return [pscustomobject]@{ Present = $present; Value = $value }
}

function Assert-BetaWorkerRollbackLaunch {
    param($Launch)
    $selections = @(Get-BetaWorkerSelectionContracts)
    $names = @('schema_version', 'entrypoint', 'command') + @($selections | ForEach-Object { $_.PresentField; $_.ValueField })
    if ($null -eq $Launch -or ($Launch -isnot [System.Collections.IDictionary] -and $Launch -isnot [pscustomobject])) {
        throw "Invalid worker rollback launch object; use a reviewed recovery manifest."
    }
    $actualNames = if ($Launch -is [System.Collections.IDictionary]) { @($Launch.Keys) } else { @($Launch.PSObject.Properties.Name) }
    if ($actualNames.Count -ne $names.Count -or @($actualNames | Where-Object { $_ -cnotin $names }).Count -ne 0) {
        throw "Invalid worker rollback launch fields; use a reviewed recovery manifest."
    }
    $version = (Get-BetaWorkerField $Launch 'schema_version').Value
    if (($version -isnot [int] -and $version -isnot [long]) -or $version -ne 1) { throw "Unsupported worker rollback launch version; use a reviewed recovery manifest." }
    $entrypoint = (Get-BetaWorkerField $Launch 'entrypoint').Value
    $command = (Get-BetaWorkerField $Launch 'command').Value
    foreach ($name in @('entrypoint', 'command')) {
        $vector = (Get-BetaWorkerField $Launch $name).Value
        if ($null -ne $vector) {
            if ($vector -isnot [array] -or @($vector | Where-Object { $_ -isnot [string] }).Count -ne 0) {
                throw "Invalid worker rollback argument vector; use a reviewed recovery manifest."
            }
        }
    }
    foreach ($selection in $selections) {
        $present = (Get-BetaWorkerField $Launch $selection.PresentField).Value
        $selector = (Get-BetaWorkerField $Launch $selection.ValueField).Value
        if ($present -isnot [bool] -or (-not $present -and $null -ne $selector) -or
            ($present -and ($selector -isnot [string] -or $selector -cnotin $selection.Allowed))) {
            throw "Unsupported worker rollback selector; use a reviewed recovery manifest."
        }
    }
    $entrypointEmpty = $null -eq $entrypoint -or $entrypoint.Count -eq 0
    $commandEmpty = $null -eq $command -or $command.Count -eq 0
    $direct = $null
    if ($entrypointEmpty) { $direct = $command }
    elseif ($commandEmpty) { $direct = $entrypoint }
    $knownDirect = (Test-BetaWorkerVector $direct @('python', '-m', 'issuance.canvas_worker')) -or
        (Test-BetaWorkerVector $direct @('python3', '-m', 'issuance.canvas_worker')) -or
        (Test-BetaWorkerVector $direct @('/usr/local/bin/marty-canvas-sync-worker'))
    $dispatcher = (Test-BetaWorkerVector $direct @('/app/services/entrypoint.sh')) -and
        $Launch.service_name_present -and $Launch.service_name -cin @('canvas-sync-worker', 'canvas_sync_worker')
    # This is the exact tracked selfhost loader form, not a shell command parser.
    $loader = (Test-BetaWorkerVector $entrypoint @('/bin/sh', '-c')) -and
        (Test-BetaWorkerVector $command @(". /app/load-secrets-env.sh`nexec python -m issuance.canvas_worker`n"))
    if (-not ($knownDirect -or $dispatcher -or $loader)) {
        throw "Unsupported worker rollback launch; recover with matching reviewed source or a complete supported launch manifest before stopping beta."
    }
}

function New-BetaWorkerRollbackLaunch {
    param($ContainerConfig)
    foreach ($name in @('Entrypoint', 'Cmd', 'Env')) {
        if (-not (Get-BetaWorkerField $ContainerConfig $name).Present) { throw "Incomplete worker container configuration; use a reviewed recovery manifest." }
    }
    $launch = [ordered]@{
        schema_version = 1
        entrypoint = (Get-BetaWorkerField $ContainerConfig 'Entrypoint').Value
        command = (Get-BetaWorkerField $ContainerConfig 'Cmd').Value
    }
    foreach ($selection in @(Get-BetaWorkerSelectionContracts)) {
        $selector = Get-BetaWorkerSelector -Environment (Get-BetaWorkerField $ContainerConfig 'Env').Value -Name $selection.Name
        $launch[$selection.PresentField] = $selector.Present
        $launch[$selection.ValueField] = $selector.Value
    }
    Assert-BetaWorkerRollbackLaunch $launch
    return [pscustomobject]$launch
}

function Resolve-BetaWorkerRollbackLaunch {
    param($Record, $CurrentWorker, $ImageConfig)
    if (-not (Get-BetaWorkerField $ImageConfig 'Env').Present -or -not (Get-BetaWorkerField $ImageConfig 'Entrypoint').Present) {
        throw "Worker rollback requires inspected immutable image configuration before stopping beta."
    }
    $imageEnvironment = (Get-BetaWorkerField $ImageConfig 'Env').Value
    $captured = Get-BetaWorkerField $Record 'rollback_launch'
    if ($captured.Present) {
        Assert-BetaWorkerRollbackLaunch $captured.Value
        foreach ($selection in @(Get-BetaWorkerSelectionContracts)) {
            $imageSelector = Get-BetaWorkerSelector -Environment $imageEnvironment -Name $selection.Name
            if (-not (Get-BetaWorkerField $captured.Value $selection.PresentField).Value -and $imageSelector.Present) {
                throw "Absent worker selector conflicts with immutable image defaults; use matching reviewed recovery source before stopping beta."
            }
        }
        return $captured.Value
    }
    # Old manifests contain no launch provenance. Only a demonstrably compatible
    # legacy Python composition may use this fallback; never infer a Rust launch.
    $command = (Get-BetaWorkerField $CurrentWorker 'command').Value
    $entrypoint = (Get-BetaWorkerField $CurrentWorker 'entrypoint').Value
    $imageEntrypoint = (Get-BetaWorkerField $ImageConfig 'Entrypoint').Value
    $imageCommand = (Get-BetaWorkerField $ImageConfig 'Cmd').Value
    # The shared Rust image also has a null entrypoint. Require the inspected
    # legacy image's known Python default, not just Python-shaped current source.
    $legacyImage = (Test-BetaWorkerVector $imageCommand @('python', '-m', 'uvicorn', 'main:app', '--host', '0.0.0.0', '--port', '8005')) -or
        (Test-BetaWorkerVector $imageCommand @('python3', '-m', 'uvicorn', 'main:app', '--host', '0.0.0.0', '--port', '8005')) -or
        (Test-BetaWorkerVector $imageCommand @('python', '-m', 'issuance.canvas_worker')) -or
        (Test-BetaWorkerVector $imageCommand @('python3', '-m', 'issuance.canvas_worker'))
    if (-not ((Test-BetaWorkerVector $command @('python', '-m', 'issuance.canvas_worker')) -or
            (Test-BetaWorkerVector $command @('python3', '-m', 'issuance.canvas_worker'))) -or
        -not $legacyImage -or
        ($null -ne $entrypoint -and -not (Test-BetaWorkerVector $entrypoint @())) -or
        ($null -ne $imageEntrypoint -and -not (Test-BetaWorkerVector $imageEntrypoint @()))) {
        throw "Legacy worker rollback lacks launch provenance; use matching reviewed legacy Python source or a complete launch manifest before stopping beta."
    }
    $environment = (Get-BetaWorkerField $CurrentWorker 'environment').Value
    if ($null -ne $environment -and $environment -isnot [System.Collections.IDictionary] -and $environment -isnot [pscustomobject]) {
        throw "Legacy worker environment must be a resolved mapping before stopping beta."
    }
    $effectiveEnvironment = @()
    foreach ($selection in @(Get-BetaWorkerSelectionContracts)) {
        $currentSelector = Get-BetaWorkerField $environment $selection.Name
        $imageSelector = Get-BetaWorkerSelector -Environment $imageEnvironment -Name $selection.Name
        if ($currentSelector.Present) {
            if ($currentSelector.Value -isnot [string]) { throw "Legacy worker selector may not use ambient resolution; use reviewed recovery source." }
            $effectiveEnvironment += $selection.Name + '=' + $currentSelector.Value
        }
        elseif ($imageSelector.Present) { $effectiveEnvironment += $selection.Name + '=' + $imageSelector.Value }
    }
    $launch = New-BetaWorkerRollbackLaunch ([pscustomobject]@{ Entrypoint = $imageEntrypoint; Cmd = $command; Env = $effectiveEnvironment })
    # New captures preserve intentional empty/absent processor selection. An old
    # record cannot distinguish that state from a partially migrated source, so
    # require the validated nonempty built-in without silently supplying it.
    if (-not $launch.canvas_sync_processor_present -or [string]::IsNullOrEmpty($launch.canvas_sync_processor)) {
        throw "Legacy worker rollback cannot establish its processor selection; use matching reviewed legacy source or an explicit complete launch manifest before stopping beta."
    }
    return $launch
}

function ConvertTo-BetaWorkerRollbackLines {
    param($Launch)
    Assert-BetaWorkerRollbackLaunch $Launch
    # Compose null inherits defaults; explicit [] reproduces an effectively empty
    # Docker vector even if the current composition/image has different defaults.
    foreach ($name in @('entrypoint', 'command')) {
        $vector = (Get-BetaWorkerField $Launch $name).Value
        $serialized = if ($null -eq $vector) { '[]' } else { ConvertTo-Json -InputObject $vector -Compress }
        "    ${name}: $serialized"
    }
    '    environment:'
    foreach ($selection in @(Get-BetaWorkerSelectionContracts)) {
        if ((Get-BetaWorkerField $Launch $selection.PresentField).Value) {
            '      ' + $selection.Name + ': ' + (ConvertTo-Json -InputObject (Get-BetaWorkerField $Launch $selection.ValueField).Value -Compress)
        }
        else {
            # A bare YAML null would resolve from the invoking host or .env instead.
            '      ' + $selection.Name + ': !reset null'
        }
    }
}
