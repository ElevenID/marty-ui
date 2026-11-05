"""Actual PowerShell verifier with task API recorders; no real task is accessed."""
import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_windows_compose_recovery as legacy

pytestmark = pytest.mark.skipif(os.name != 'nt' or not legacy.POWERSHELL, reason='Windows verifier recorder')


def invoke(tmp_path, case):
    scripts = tmp_path/'scripts';scripts.mkdir()
    verifier = scripts/'verify-marty-boot-recovery.ps1'
    shutil.copyfile(legacy.ROOT/'scripts/verify-marty-boot-recovery.ps1', verifier)
    config = tmp_path/"operator's configuration.json";config.write_text('{}')
    python = tmp_path/"operator's interpreter.exe";python.touch()
    child = tmp_path/'preflight.json';started = tmp_path/'started.json'
    (scripts/'recover-marty-after-reboot.ps1').write_text(
        'param([string]$RecoveryConfigurationFile,[string]$ManagedPython,[switch]$CheckOnly,'
        '[switch]$RenewCredentials,[string]$LogicalTlsProject)\n'
        '@{check=[bool]$CheckOnly;configuration=$RecoveryConfigurationFile;python=$ManagedPython;'
        'renew=[bool]$RenewCredentials;logical=$LogicalTlsProject} | ConvertTo-Json | Set-Content '+legacy.quote(child)+
        '\nexit '+('1' if case == 'preflight-failure' else '0')+'\n')
    code = r'''
$ErrorActionPreference='Stop'
$global:started=$false
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$shell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
$recovery=Join-Path SCRIPTS 'recover-marty-after-reboot.ps1'
$expected='-NoProfile -NonInteractive -File "'+$recovery+'" -RecoveryConfigurationFile "'+CONFIG+'" -ManagedPython "'+PYTHON+'" -WaitForEngine'
if ('CASE' -like 'renew*') { $expected+=' -RenewCredentials -LogicalTlsProject "marty-selfhost-synthetic"' }
$global:task=[pscustomobject]@{
 TaskName='Marty-Candidate-Qualification';TaskPath='\';State='Ready'
 Principal=[pscustomobject]@{UserId=$user;LogonType='Interactive';RunLevel='Limited'}
 Actions=@([pscustomobject]@{Execute=$shell;Arguments=$expected;WorkingDirectory=ROOT})
 Triggers=@([pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='MSFT_TaskLogonTrigger'};
 UserId=$user;Delay='PT2M';Enabled=$true;Repetition=[pscustomobject]@{Interval='';Duration='';StopAtDurationEnd=$false}})
 Settings=[pscustomobject]@{Enabled=$true;StartWhenAvailable=$true;MultipleInstances='IgnoreNew';
 ExecutionTimeLimit='PT20M';RestartCount=3;RestartInterval='PT2M'} }
if ('CASE' -like 'renew*') {
 $global:task.Triggers[0].Repetition.Interval='PT240M'
 $global:task.Settings.ExecutionTimeLimit='PT1H';$global:task.Settings.RestartCount=0
}
switch ('CASE') {
 'wrong-user' {$global:task.Principal.UserId='SYSTEM'}
 'highest' {$global:task.Principal.RunLevel='Highest'}
 'wrong-logon' {$global:task.Principal.LogonType='ServiceAccount'}
 'wrong-folder' {$global:task.TaskPath='\OtherOwner\'}
 'wrong-action' {$global:task.Actions[0].Arguments+=' -CheckOnly'}
 'wrong-launcher' {$global:task.Actions[0].Execute='other.exe'}
 'wrong-cwd' {$global:task.Actions[0].WorkingDirectory='C:\other'}
 'extra-action' {$global:task.Actions+= $global:task.Actions[0]}
 'extra-trigger' {$global:task.Triggers+= $global:task.Triggers[0]}
 'wrong-trigger-user' {$global:task.Triggers[0].UserId='SYSTEM'}
 'wrong-trigger-type' {$global:task.Triggers[0].CimClass.CimClassName='MSFT_TaskBootTrigger'}
 'busy' {$global:task.State='Running'}
 'disabled' {$global:task.Settings.Enabled=$false}
 'parallel' {$global:task.Settings.MultipleInstances='Parallel'}
 'renew-retries' {$global:task.Settings.RestartCount=3}
 'renew-duration' {$global:task.Triggers[0].Repetition.Duration='PT1H'}
 'renew-interval' {$global:task.Triggers[0].Repetition.Interval='PT15M'}
}
function Get-ScheduledTask {
 param($TaskName,$TaskPath)
 if ($TaskName -ne 'Marty-Candidate-Qualification' -or $TaskPath -ne '\') {throw 'Foreign task access forbidden'}
 if ('CASE' -eq 'inventory-failure') {throw 'Synthetic inventory failure'}
 if ('CASE' -eq 'missing') {return}
 if ($global:started -and 'CASE' -eq 'never-finished') {$global:task.State='Running'}
 return $global:task
}
function Get-ScheduledTaskInfo {
 param($TaskName,$TaskPath)
 if ($TaskName -ne 'Marty-Candidate-Qualification' -or $TaskPath -ne '\') {throw 'Foreign task info forbidden'}
 $time=[datetime]'2020-01-01T00:00:00Z'
 if ($global:started -and 'CASE' -ne 'never-ran') {$time=$time.AddDays(1)}
 return [pscustomobject]@{LastRunTime=$time;LastTaskResult=$(if ('CASE' -eq 'failed-task') {1} else {0})}
}
function Start-ScheduledTask {
 param($TaskName,$TaskPath)
 if ($TaskName -ne 'Marty-Candidate-Qualification' -or $TaskPath -ne '\') {throw 'Foreign task start forbidden'}
 if ($global:started) {throw 'Replay forbidden'}
 $global:started=$true
 @{name=$TaskName;path=$TaskPath} | ConvertTo-Json | Set-Content STARTED
}
function Stop-ScheduledTask {throw 'Stop forbidden'}
function Unregister-ScheduledTask {throw 'Delete forbidden'}
function Set-ScheduledTask {throw 'Update forbidden'}
& VERIFIER -TaskName 'Marty-Candidate-Qualification' -RecoveryConfigurationFile CONFIG -ManagedPython PYTHON -TimeoutSeconds 1 OPTIONS
'''
    options = '-CheckOnly' if case in {'check', 'renew-check'} else ''
    if case.startswith('renew'):
        options += " -RenewCredentials -LogicalTlsProject 'marty-selfhost-synthetic' -RenewalIntervalMinutes 240"
    for key, value in {'CASE': case, 'SCRIPTS': legacy.quote(scripts), 'ROOT': legacy.quote(tmp_path),
                       'CONFIG': legacy.quote(config), 'PYTHON': legacy.quote(python),
                       'STARTED': legacy.quote(started), 'VERIFIER': legacy.quote(verifier),
                       'OPTIONS': options}.items():code = code.replace(key, value)
    result = subprocess.run([legacy.POWERSHELL, '-NoProfile', '-NonInteractive', '-EncodedCommand',
        base64.b64encode(code.encode('utf-16le')).decode()], capture_output=True, text=True, timeout=15)
    return result, child, started


@pytest.mark.parametrize('case', ['check', 'renew-check', 'run', 'renew-run'])
def test_exact_managed_task_check_or_one_bounded_run(tmp_path, case):
    result, child, started = invoke(tmp_path, case)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    preflight = json.loads(child.read_text(encoding='utf-8-sig'))
    assert preflight['check'] is True
    assert preflight['renew'] == case.startswith('renew')
    run = case.endswith('run')
    assert started.exists() == run
    assert report['definition_verified'] and report['configuration_verified']
    assert report['task_started'] == report['task_completed'] == run
    assert not report['operator_logon_qualified'] and not report['periodic_trigger_qualified']
    assert not report['host_reboot_qualified'] and not report['production_admission']


@pytest.mark.parametrize('case', ['wrong-user', 'highest', 'wrong-logon', 'wrong-folder',
    'wrong-action', 'wrong-launcher', 'wrong-cwd', 'extra-action', 'extra-trigger',
    'wrong-trigger-user', 'wrong-trigger-type', 'busy', 'disabled', 'parallel',
    'renew-retries', 'renew-duration', 'renew-interval', 'inventory-failure', 'missing', 'preflight-failure'])
def test_unqualified_task_never_starts(tmp_path, case):
    result, _child, started = invoke(tmp_path, case)
    assert result.returncode != 0 and not started.exists()


@pytest.mark.parametrize('case', ['never-ran', 'never-finished', 'failed-task'])
def test_unknown_or_failed_task_outcome_never_reports_success_or_replays(tmp_path, case):
    result, child, started = invoke(tmp_path, case)
    assert result.returncode != 0 and child.exists() and started.exists()
    assert '"task_completed":  true' not in result.stdout
