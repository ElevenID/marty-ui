[CmdletBinding()]
param(
    [string]$TaskName = 'Marty-Recovery-At-Boot',
    [string]$RecoveryConfigurationFile,
    [string]$ManagedPython,
    [switch]$RenewCredentials,
    [string]$LogicalTlsProject,
    [int]$RenewalIntervalMinutes = 0,
    [int]$FirstRenewalDelaySeconds = 0,
    [int]$RenewalWindowMinutes = 0,
    [switch]$CheckOnly,
    [int]$TimeoutSeconds = 3600,
    [int]$PreflightTimeoutSeconds = 300,
    [string]$StatusFile
)
$ErrorActionPreference = 'Stop'

if ($ManagedPython) {
    # Managed tasks belong to the interactive Docker Desktop operator. Verify
    # the complete saved invocation before starting exactly this separate task.
    if ($TaskName -eq 'Marty-Recovery-At-Boot' -or $TaskName -notmatch '\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\z' -or
        $TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 3600 -or
        $PreflightTimeoutSeconds -lt 1 -or $PreflightTimeoutSeconds -gt 600) {
        throw 'Use a separate managed task name and a bounded observation timeout.'
    }
    foreach ($file in @($RecoveryConfigurationFile, $ManagedPython)) {
        if (-not [IO.Path]::IsPathRooted($file) -or $file.Contains('"') -or
            -not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw 'Managed verification requires existing absolute configuration and interpreter paths.'
        }
    }
    if ($RenewCredentials) {
        if ($LogicalTlsProject -cnotmatch '\Amarty-(selfhost|production)-[a-z0-9][a-z0-9-]{0,59}\z' -or
            $RenewalIntervalMinutes -lt 15 -or $RenewalIntervalMinutes -gt 240 -or
            ($FirstRenewalDelaySeconds -ne 0 -and ($FirstRenewalDelaySeconds -lt 15 -or
                $FirstRenewalDelaySeconds -gt 60*$RenewalIntervalMinutes)) -or
            $RenewalWindowMinutes -lt 0 -or $RenewalWindowMinutes -gt 1440 -or
            ($RenewalWindowMinutes -gt 0 -and 60*$RenewalWindowMinutes -le $(if ($FirstRenewalDelaySeconds) {$FirstRenewalDelaySeconds} else {60*$RenewalIntervalMinutes}))) {
            throw 'Use the exact enrolled namespace and installed renewal interval.'
        }
    } elseif ($LogicalTlsProject -or $PSBoundParameters.ContainsKey('RenewalIntervalMinutes') -or
        $PSBoundParameters.ContainsKey('FirstRenewalDelaySeconds') -or $PSBoundParameters.ContainsKey('RenewalWindowMinutes')) {
        throw 'Renewal settings require RenewCredentials.'
    }
    if ($StatusFile -and (-not [IO.Path]::IsPathRooted($StatusFile) -or
        -not (Test-Path -LiteralPath (Split-Path -Parent $StatusFile) -PathType Container) -or
        (Test-Path -LiteralPath $StatusFile))) {
        throw 'Use a new absolute status file in an existing directory.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $userIds = @($identity.Name, $identity.User.Value)
    $recoveryScript = Join-Path $PSScriptRoot 'recover-marty-after-reboot.ps1'
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $powerShellPath = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
    $expectedArguments = "-NoProfile -NonInteractive -WindowStyle Hidden -File `"$recoveryScript`" -RecoveryConfigurationFile `"$RecoveryConfigurationFile`" -ManagedPython `"$ManagedPython`" -WaitForEngine"
    if ($RenewCredentials) { $expectedArguments += " -RenewCredentials -LogicalTlsProject `"$LogicalTlsProject`"" }

    function Assert-ManagedTask($Task) {
        $expectedTriggers = if ($RenewCredentials) { 2 } else { 1 }
        if ($Task.TaskName -cne $TaskName -or $Task.TaskPath -ne '\' -or
            $Task.Principal.UserId -notin $userIds -or
            [string]$Task.Principal.LogonType -ne 'Interactive' -or
            [string]$Task.Principal.RunLevel -ne 'Limited' -or
            @($Task.Actions).Count -ne 1 -or @($Task.Triggers).Count -ne $expectedTriggers) {
            throw 'The task does not belong to the expected managed interactive operator.'
        }
        $logons = @($Task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' })
        if ($logons.Count -ne 1) { throw 'Expected exactly one operator logon trigger.' }
        $action = @($Task.Actions)[0];$trigger = $logons[0]
        if ($action.Execute -ine $powerShellPath -or $action.Arguments -cne $expectedArguments -or
            $action.WorkingDirectory -ine $repoRoot -or
            $trigger.CimClass.CimClassName -ne 'MSFT_TaskLogonTrigger' -or
            $trigger.UserId -notin $userIds -or $trigger.Delay -ne 'PT2M' -or -not $trigger.Enabled -or
            -not $Task.Settings.Enabled -or -not $Task.Settings.StartWhenAvailable -or
            [string]$Task.Settings.MultipleInstances -ne 'IgnoreNew') {
            throw 'The managed task action, trigger or execution settings differ from the expected invocation.'
        }
        if ($RenewCredentials) {
            $timers = @($Task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskTimeTrigger' })
            if ($timers.Count -ne 1) { throw 'Expected exactly one independent renewal time trigger.' }
            $timer = $timers[0]
            if ($trigger.Repetition.Interval -or $trigger.Repetition.Duration -or
                -not $timer.Enabled -or [string]$timer.RandomDelay -notin @('', 'PT0S') -or
                $timer.Repetition.Interval -ne ('PT'+$RenewalIntervalMinutes+'M') -or
                $timer.Repetition.Duration -or $timer.Repetition.StopAtDurationEnd -or
                $Task.Settings.ExecutionTimeLimit -ne 'PT1H' -or $Task.Settings.RestartCount -ne 0) {
                throw 'The renewal repetition or no-replay settings differ from the expected definition.'
            }
            $registration = [DateTimeOffset]::MinValue;$boundary = [DateTimeOffset]::MinValue
            $utcPattern = '\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|\+00:00)\z'
            if ([string]$Task.Date -cnotmatch $utcPattern -or [string]$timer.StartBoundary -cnotmatch $utcPattern -or
                -not [DateTimeOffset]::TryParse([string]$Task.Date, [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::None, [ref]$registration) -or
                -not [DateTimeOffset]::TryParse([string]$timer.StartBoundary, [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::None, [ref]$boundary)) {
                throw 'Renewal registration and first-run boundaries must be explicit UTC timestamps.'
            }
            $firstDelay = if ($FirstRenewalDelaySeconds) { $FirstRenewalDelaySeconds } else { 60*$RenewalIntervalMinutes }
            if (($boundary-$registration).TotalSeconds -ne $firstDelay -or $registration -gt [DateTimeOffset]::UtcNow.AddSeconds(60)) {
                throw 'The first renewal boundary differs from the expected delay or registration clock.'
            }
            foreach ($renewalTrigger in @($trigger, $timer)) {
                if ($RenewalWindowMinutes) {
                    $end = [DateTimeOffset]::MinValue
                    if ([string]$renewalTrigger.EndBoundary -cnotmatch $utcPattern -or
                        -not [DateTimeOffset]::TryParse([string]$renewalTrigger.EndBoundary, [Globalization.CultureInfo]::InvariantCulture,
                            [Globalization.DateTimeStyles]::None, [ref]$end) -or
                        $end -ne $registration.AddMinutes($RenewalWindowMinutes)) {
                        throw 'Both renewal triggers must expire at the exact qualified UTC boundary.'
                    }
                } elseif ($renewalTrigger.EndBoundary) {
                    throw 'An indefinite renewal task must not contain a trigger expiry.'
                }
            }
        } elseif ($trigger.Repetition.Interval -or $Task.Settings.ExecutionTimeLimit -ne 'PT20M' -or
            $Task.Settings.RestartCount -ne 3 -or $Task.Settings.RestartInterval -ne 'PT2M') {
            throw 'The retained-ID recovery task settings differ from the expected definition.'
        }
    }
    $tasks = @(Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop)
    if ($tasks.Count -ne 1) { throw 'Expected exactly one root-folder managed task.' }
    $task = $tasks[0];Assert-ManagedTask $task
    if ([string]$task.State -ne 'Ready') { throw 'The managed task is not idle and ready; no task was started.' }
    $arguments = @('-NoProfile', '-NonInteractive', '-File', $recoveryScript,
        '-RecoveryConfigurationFile', $RecoveryConfigurationFile, '-ManagedPython', $ManagedPython, '-CheckOnly')
    if ($RenewCredentials) { $arguments += @('-RenewCredentials', '-LogicalTlsProject', $LogicalTlsProject) }
    # Reuse the existing kill-on-close Win32 job, bounded pipe drains and owned
    # process cleanup. Never leave an unobserved preflight descendant running.
    $ownedPreflight = 'import sys;sys.path.insert(0,sys.argv[1]);from selfhost_windows_renewal import run_owned_mutation;r=run_owned_mutation(sys.argv[3:],timeout=int(sys.argv[2]));sys.exit(r.returncode)'
    & $ManagedPython '-c' $ownedPreflight $PSScriptRoot ([string]$PreflightTimeoutSeconds) $powerShellPath @arguments *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Read-only runtime preflight failed; no task was started.' }
    $result = [ordered]@{ verified_at = (Get-Date).ToUniversalTime().ToString('o'); task_name = $TaskName
        definition_verified = $true; configuration_verified = $true; task_start_requested = $false
        fresh_task_completion_observed = $false; requested_run_attribution_verified = $false
        operator_logon_qualified = $false; periodic_trigger_qualified = $false
        host_reboot_qualified = $false; production_admission = $false }
    if (-not $CheckOnly) {
        $before = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
        $task = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
        Assert-ManagedTask $task
        if ([string]$task.State -ne 'Ready') { throw 'The task became active; no task was started.' }
        # This is an acceptance budget, measured monotonically. Local task API
        # calls can return late; no late observation is accepted as success.
        $timer = [Diagnostics.Stopwatch]::StartNew()
        Start-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
        $result.task_start_requested = $true
        do {
            Start-Sleep -Milliseconds 250
            $task = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
            $info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
            Assert-ManagedTask $task
            if ($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                throw 'Task observation budget expired; preserve its records and do not replay or stop it.'
            }
            if ($info.LastRunTime -gt $before.LastRunTime -and [string]$task.State -ne 'Running') { break }
        } while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
        if ($info.LastRunTime -le $before.LastRunTime -or [string]$task.State -ne 'Ready') {
            throw 'Task completion is unproven; preserve its records and do not replay or stop it.'
        }
        if ($info.LastTaskResult -ne 0) { throw 'The managed task failed; preserve its recovery records.' }
        if ($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw 'Late task completion cannot qualify.' }
        # IgnoreNew may race another trigger: a fresh successful execution is
        # proven, but it cannot be attributed uniquely to this start request.
        $result.fresh_task_completion_observed = $true
        $result.last_run_time = $info.LastRunTime.ToUniversalTime().ToString('o')
        $result.last_task_result = $info.LastTaskResult
    }
    $body = $result | ConvertTo-Json
    if ($StatusFile) {
        # Never overwrite an earlier qualification or unrelated local file.
        $stream = [IO.File]::Open($StatusFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($body + [Environment]::NewLine)
            $stream.Write($bytes, 0, $bytes.Length);$stream.Flush($true)
        } finally { $stream.Dispose() }
    }
    Write-Output $body
    return
}
if ($PSBoundParameters.Count) {
    throw 'Custom verification settings require explicit managed mode; legacy verification retains its historical invocation.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This verifier must run elevated.'
}

$taskName = 'Marty-Recovery-At-Boot'
$task = Get-ScheduledTask -TaskName $taskName
Start-ScheduledTask -TaskName $taskName

$deadline = (Get-Date).AddMinutes(5)
do {
    Start-Sleep -Seconds 2
    $task = Get-ScheduledTask -TaskName $taskName
} while ($task.State -eq 'Running' -and (Get-Date) -lt $deadline)

$taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
$dockerService = Get-Service -Name 'com.docker.service'
$status = [ordered]@{
    verified_at = (Get-Date).ToString('o')
    docker_service_status = $dockerService.Status.ToString()
    docker_service_start_type = $dockerService.StartType.ToString()
    task_name = $task.TaskName
    task_state = $task.State.ToString()
    task_principal = $task.Principal.UserId
    task_run_level = $task.Principal.RunLevel.ToString()
    trigger_type = $task.Triggers[0].CimClass.CimClassName
    trigger_delay = $task.Triggers[0].Delay
    last_run_time = $taskInfo.LastRunTime.ToString('o')
    last_task_result = $taskInfo.LastTaskResult
}

$statusRoot = Join-Path $env:ProgramData 'Marty'
New-Item -ItemType Directory -Force -Path $statusRoot | Out-Null
$status | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $statusRoot 'boot-recovery-status.json') -Encoding UTF8
if ($taskInfo.LastTaskResult -ne 0) {
    throw "Boot recovery test failed with task result $($taskInfo.LastTaskResult)."
}
