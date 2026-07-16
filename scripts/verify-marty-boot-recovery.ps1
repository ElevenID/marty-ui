$ErrorActionPreference = 'Stop'

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
