[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RecoveryConfigurationFile,
    [string]$ManagedPython,
    [switch]$RenewCredentials,
    [string]$LogicalTlsProject,
    [int]$RenewalIntervalMinutes = 0,
    [int]$FirstRenewalDelaySeconds = 0,
    [string]$TaskName = 'Marty-Recovery-At-Boot'
)
$ErrorActionPreference = 'Stop'
if ($RenewCredentials) {
    if (-not $ManagedPython -or $LogicalTlsProject -cnotmatch '\Amarty-(selfhost|production)-[a-z0-9][a-z0-9-]{0,59}\z' -or
        $RenewalIntervalMinutes -lt 15 -or $RenewalIntervalMinutes -gt 240 -or
        ($FirstRenewalDelaySeconds -ne 0 -and ($FirstRenewalDelaySeconds -lt 15 -or
            $FirstRenewalDelaySeconds -gt 60*$RenewalIntervalMinutes))) {
        throw 'Renewal requires managed settings, enrolled logical TLS namespace and an explicitly qualified interval (15-240 minutes).'
    }
} elseif ($LogicalTlsProject -or $PSBoundParameters.ContainsKey('RenewalIntervalMinutes') -or
    $PSBoundParameters.ContainsKey('FirstRenewalDelaySeconds')) {
    throw 'Renewal options require explicit RenewCredentials mode.'
}

function New-ManagedRecoveryTaskDefinition($Scheduler, [string]$UserId,
    [string]$PowerShellPath, [string]$Arguments, [string]$WorkingDirectory,
    [int]$RenewalIntervalMinutes = 0, [int]$FirstRenewalDelaySeconds = 0) {
    if ($RenewalIntervalMinutes -ne 0 -and ($RenewalIntervalMinutes -lt 15 -or $RenewalIntervalMinutes -gt 240)) {
        throw 'Renewal interval must be explicitly qualified between 15 and 240 minutes.'
    }
    if ($FirstRenewalDelaySeconds -ne 0 -and ($RenewalIntervalMinutes -eq 0 -or
        $FirstRenewalDelaySeconds -lt 15 -or $FirstRenewalDelaySeconds -gt 60*$RenewalIntervalMinutes)) {
        throw 'First renewal delay must be 15 seconds through the qualified interval, or zero for its default.'
    }
    $definition = $Scheduler.NewTask(0)
    $definition.RegistrationInfo.Description = 'Recover the retained Marty candidate after operator logon and Docker Desktop startup.'
    $definition.Principal.UserId = $UserId
    $definition.Principal.LogonType = 3 # TASK_LOGON_INTERACTIVE_TOKEN
    $definition.Principal.RunLevel = 0 # TASK_RUNLEVEL_LUA
    $trigger = $definition.Triggers.Create(9) # TASK_TRIGGER_LOGON
    $trigger.UserId = $UserId
    $trigger.Delay = 'PT2M'
    if ($RenewalIntervalMinutes) {
        # A logon trigger alone cannot start recurrence for a user who is
        # already signed in when this definition is registered. Keep logon
        # renewal request once, and give recurrence its own UTC time trigger.
        $nowUtc = [DateTimeOffset]::UtcNow
        $registeredUtc = $nowUtc.AddTicks(-($nowUtc.Ticks % [TimeSpan]::TicksPerSecond))
        $format = "yyyy-MM-dd'T'HH:mm:sszzz"
        $definition.RegistrationInfo.Date = $registeredUtc.ToString($format, [Globalization.CultureInfo]::InvariantCulture)
        $firstDelay = if ($FirstRenewalDelaySeconds) { $FirstRenewalDelaySeconds } else { 60*$RenewalIntervalMinutes }
        $timer = $definition.Triggers.Create(1) # TASK_TRIGGER_TIME
        $timer.Enabled = $true
        $timer.StartBoundary = $registeredUtc.AddSeconds($firstDelay).ToString($format, [Globalization.CultureInfo]::InvariantCulture)
        $timer.Repetition.Interval = 'PT' + $RenewalIntervalMinutes + 'M'
        $timer.Repetition.StopAtDurationEnd = $false
        # No Duration: repeat indefinitely while this interactive user is available.
        $definition.RegistrationInfo.Description = 'Renew the retained online Marty candidate using its guarded native owner.'
    }
    $action = $definition.Actions.Create(0) # TASK_ACTION_EXEC
    $action.Path = $PowerShellPath
    $action.Arguments = $Arguments
    $action.WorkingDirectory = $WorkingDirectory
    $definition.Settings.StartWhenAvailable = $true
    $definition.Settings.ExecutionTimeLimit = 'PT20M'
    $definition.Settings.RestartCount = 3
    $definition.Settings.RestartInterval = 'PT2M'
    if ($RenewalIntervalMinutes) {
        $definition.Settings.ExecutionTimeLimit = 'PT1H'
        $definition.Settings.RestartCount = 0 # never immediately replay a failed renewal
    }
    $definition.Settings.MultipleInstances = 2 # TASK_INSTANCES_IGNORE_NEW
    $definition.Settings.Enabled = $true
    return $definition
}

if ($TaskName -notmatch '\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\z') {
    throw 'Use a simple root-folder scheduled task name.'
}
if ($ManagedPython) {
    if (-not $PSBoundParameters.ContainsKey('TaskName') -or $TaskName -eq 'Marty-Recovery-At-Boot') {
        throw 'Managed recovery requires a separate explicit task name; preserve the existing deployment task.'
    }
    if (-not [IO.Path]::IsPathRooted($ManagedPython) -or
        -not (Test-Path -LiteralPath $ManagedPython -PathType Leaf) -or $ManagedPython.Contains('"')) {
        throw 'Managed recovery requires an existing absolute trusted interpreter path.'
    }
    # Enumerate successfully before registering. Never replace an existing task,
    # including one owned by another operator or stored in a different folder.
    if (@(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -eq $TaskName }).Count) {
        throw 'The managed recovery task name already exists; inspect its ownership before any replacement.'
    }
}
elseif ($TaskName -ne 'Marty-Recovery-At-Boot') {
    throw 'Custom task names require managed recovery; legacy recovery retains its historical task only.'
}

# Docker Desktop belongs to the signed-in user's session and Docker context.
# A SYSTEM boot task cannot assume that user's daemon, registry or proof tools.
if (-not [IO.Path]::IsPathRooted($RecoveryConfigurationFile) -or
    -not (Test-Path -LiteralPath $RecoveryConfigurationFile -PathType Leaf) -or
    $RecoveryConfigurationFile.Contains('"')) {
    throw 'An existing absolute nonsecret recovery configuration path is required.'
}
$recoveryScript = Join-Path $PSScriptRoot 'recover-marty-after-reboot.ps1'
$repoRoot = Split-Path -Parent $PSScriptRoot
$powerShellPath = 'PowerShell.exe'
if ($ManagedPython) {
    $powerShellPath = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
    if (-not (Test-Path -LiteralPath $powerShellPath -PathType Leaf)) {
        throw 'The Windows system PowerShell executable is unavailable.'
    }
}
# Validate the exact saved invocation before replacing any task. Run in a child
# process because the recovery wrapper deliberately exits with its result.
$preflightArguments = @('-NoProfile', '-NonInteractive', '-File', $recoveryScript,
                         '-RecoveryConfigurationFile', $RecoveryConfigurationFile, '-CheckOnly')
if ($ManagedPython) { $preflightArguments += @('-ManagedPython', $ManagedPython) }
if ($RenewCredentials) { $preflightArguments += @('-RenewCredentials', '-LogicalTlsProject', $LogicalTlsProject) }
& $powerShellPath @preflightArguments *> $null
if ($LASTEXITCODE -ne 0) { throw 'Recovery preflight failed; the scheduled task was not changed.' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$actionArguments = "-NoProfile -NonInteractive -File `"$recoveryScript`" -RecoveryConfigurationFile `"$RecoveryConfigurationFile`""
if ($ManagedPython) { $actionArguments += " -ManagedPython `"$ManagedPython`" -WaitForEngine" }
if ($RenewCredentials) { $actionArguments += " -RenewCredentials -LogicalTlsProject `"$LogicalTlsProject`"" }
if ($ManagedPython) {
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $folder = $scheduler.GetFolder('\')
    $definition = New-ManagedRecoveryTaskDefinition $scheduler $identity.Name $powerShellPath $actionArguments $repoRoot $RenewalIntervalMinutes $FirstRenewalDelaySeconds
    # TASK_CREATE=2 is atomic create-only, never TASK_UPDATE or CREATE_OR_UPDATE.
    # A collision after the inventory/preflight therefore refuses at registration.
    $folder.RegisterTaskDefinition($TaskName, $definition, 2, $identity.Name, $null, 3) | Out-Null
    if ($RenewCredentials) {
        Write-Host 'Separate online renewal task created; expiry recovery and full-host boot are not qualified.'
    } else { Write-Host 'Managed recovery task created for this operator at logon; full-host boot recovery is not qualified.' }
    return
}
$taskAction = New-ScheduledTaskAction `
    -Execute 'PowerShell.exe' `
    -Argument $actionArguments `
    -WorkingDirectory $repoRoot
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$taskTrigger.Delay = 'PT2M'
$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId $identity.Name -LogonType Interactive -RunLevel Limited
$taskSettings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 20) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 2) `
    -MultipleInstances IgnoreNew

$registration = @{
    TaskName = $TaskName; Action = $taskAction; Trigger = $taskTrigger
    Principal = $taskPrincipal; Settings = $taskSettings
    Description = 'Recover the retained Marty deployment after operator logon and Docker Desktop startup.'
}
$registration.Force = $true
Register-ScheduledTask @registration | Out-Null
Write-Host 'Recovery task retained for this operator at logon; full-host boot recovery is not qualified.'
