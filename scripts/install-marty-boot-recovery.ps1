$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This installer must run from an elevated Administrator PowerShell session.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$recoveryScript = Join-Path $PSScriptRoot 'recover-marty-after-reboot.ps1'
if (-not (Test-Path -LiteralPath $recoveryScript)) {
    throw "Recovery script not found: $recoveryScript"
}

Set-Service -Name 'com.docker.service' -StartupType Automatic
Start-Service -Name 'com.docker.service' -ErrorAction SilentlyContinue

$taskAction = New-ScheduledTaskAction `
    -Execute 'PowerShell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$recoveryScript`"" `
    -WorkingDirectory $repoRoot
$taskTrigger = New-ScheduledTaskTrigger -AtStartup
$taskTrigger.Delay = 'PT2M'
$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId 'SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel Highest
$taskSettings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 20) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 2) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName 'Marty-Recovery-At-Boot' `
    -Action $taskAction `
    -Trigger $taskTrigger `
    -Principal $taskPrincipal `
    -Settings $taskSettings `
    -Description 'Recover Marty production and beta Docker Compose stacks after Windows boot.' `
    -Force | Out-Null

$service = Get-Service -Name 'com.docker.service'
$task = Get-ScheduledTask -TaskName 'Marty-Recovery-At-Boot'
Write-Host "Docker service: status=$($service.Status) startup=$($service.StartType)"
Write-Host "Recovery task: state=$($task.State) trigger=AtStartup delay=PT2M principal=SYSTEM"
