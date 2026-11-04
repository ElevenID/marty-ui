[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RecoveryConfigurationFile
)
$ErrorActionPreference = 'Stop'

# Docker Desktop belongs to the signed-in user's session and Docker context.
# A SYSTEM boot task cannot assume that user's daemon, registry or proof tools.
if (-not [IO.Path]::IsPathRooted($RecoveryConfigurationFile) -or
    -not (Test-Path -LiteralPath $RecoveryConfigurationFile -PathType Leaf) -or
    $RecoveryConfigurationFile.Contains('"')) {
    throw 'An existing absolute nonsecret recovery configuration path is required.'
}
$recoveryScript = Join-Path $PSScriptRoot 'recover-marty-after-reboot.ps1'
$repoRoot = Split-Path -Parent $PSScriptRoot
# Validate the exact saved invocation before replacing any task. Run in a child
# process because the recovery wrapper deliberately exits with its result.
& PowerShell.exe -NoProfile -NonInteractive -File $recoveryScript `
    -RecoveryConfigurationFile $RecoveryConfigurationFile -CheckOnly *> $null
if ($LASTEXITCODE -ne 0) { throw 'Recovery preflight failed; the scheduled task was not changed.' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$taskAction = New-ScheduledTaskAction `
    -Execute 'PowerShell.exe' `
    -Argument "-NoProfile -NonInteractive -File `"$recoveryScript`" -RecoveryConfigurationFile `"$RecoveryConfigurationFile`"" `
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

Register-ScheduledTask `
    -TaskName 'Marty-Recovery-At-Boot' `
    -Action $taskAction `
    -Trigger $taskTrigger `
    -Principal $taskPrincipal `
    -Settings $taskSettings `
    -Description 'Recover the retained Marty Compose deployment after operator logon and Docker Desktop startup.' `
    -Force | Out-Null
Write-Host 'Recovery task retained for this operator at logon; full-host boot recovery is not qualified.'
