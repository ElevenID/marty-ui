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
    python = Path(sys.executable)
    child = tmp_path/'preflight.json';started = tmp_path/'started.json'
    (scripts/'recover-marty-after-reboot.ps1').write_text(
        'param([string]$RecoveryConfigurationFile,[string]$ManagedPython,[switch]$CheckOnly,'
        '[switch]$RenewCredentials,[string]$LogicalTlsProject)\n'
        '@{check=[bool]$CheckOnly;configuration=$RecoveryConfigurationFile;python=$ManagedPython;'
        'renew=[bool]$RenewCredentials;logical=$LogicalTlsProject} | ConvertTo-Json | Set-Content '+legacy.quote(child)+
        ('\nStart-Sleep -Seconds 4\n' if case == 'preflight-timeout' else '')+
        '\nexit '+('1' if case == 'preflight-failure' else '0')+'\n')
    # Record the owned transport boundary; its actual Win32 job/descendant
    # semantics have separate tests. The child here is only our harmless stub.
    (scripts/'selfhost_windows_renewal.py').write_text(
        'import subprocess,json\nfrom pathlib import Path\n'
        'def run_owned_mutation(args,timeout):\n'
        ' Path('+repr(str(tmp_path/'owned.json'))+').write_text(json.dumps({"args":args,"timeout":timeout}))\n'
        ' return subprocess.run(args,timeout=timeout,capture_output=True)\n')
    code = r'''
$ErrorActionPreference='Stop'
$global:started=$false
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$shell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
$recovery=Join-Path SCRIPTS 'recover-marty-after-reboot.ps1'
$expected='-NoProfile -NonInteractive -WindowStyle Hidden -File "'+$recovery+'" -RecoveryConfigurationFile "'+CONFIG+'" -ManagedPython "'+PYTHON+'" -WaitForEngine'
if ('CASE' -like 'renew*') { $expected+=' -RenewCredentials -LogicalTlsProject "marty-selfhost-synthetic"' }
$global:task=[pscustomobject]@{
 TaskName='Marty-Candidate-Qualification';TaskPath='\';State='Ready';Date=''
 Principal=[pscustomobject]@{UserId=$user;LogonType='Interactive';RunLevel='Limited'}
 Actions=@([pscustomobject]@{Execute=$shell;Arguments=$expected;WorkingDirectory=ROOT})
 Triggers=@([pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='MSFT_TaskLogonTrigger'};
 UserId=$user;Delay='PT2M';Enabled=$true;Repetition=[pscustomobject]@{Interval='';Duration='';StopAtDurationEnd=$false}})
 Settings=[pscustomobject]@{Enabled=$true;StartWhenAvailable=$true;MultipleInstances='IgnoreNew';
 ExecutionTimeLimit='PT20M';RestartCount=3;RestartInterval='PT2M'} }
if ('CASE' -like 'renew*') {
 $registered=[DateTimeOffset]::UtcNow
 $registered=$registered.AddTicks(-($registered.Ticks % [TimeSpan]::TicksPerSecond))
 $delay=if ('CASE' -eq 'renew-first-check') {15} else {14400}
 $global:task.Date=$registered.ToString("yyyy-MM-dd'T'HH:mm:sszzz")
 $global:task.Triggers+=@([pscustomobject]@{
  CimClass=[pscustomobject]@{CimClassName='MSFT_TaskTimeTrigger'};Enabled=$true;EndBoundary='';RandomDelay=''
  StartBoundary=$registered.AddSeconds($delay).ToString("yyyy-MM-dd'T'HH:mm:sszzz")
  Repetition=[pscustomobject]@{Interval='PT240M';Duration='';StopAtDurationEnd=$false} })
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
 'renew-duration' {$global:task.Triggers[1].Repetition.Duration='PT1H'}
 'renew-interval' {$global:task.Triggers[1].Repetition.Interval='PT15M'}
 'renew-logon-repetition' {$global:task.Triggers[0].Repetition.Interval='PT240M'}
 'renew-legacy-logon-only' {$global:task.Triggers=@($global:task.Triggers[0]);$global:task.Triggers[0].Repetition.Interval='PT240M'}
 'renew-local-boundary' {$global:task.Triggers[1].StartBoundary='2026-11-05T10:00:00'}
 'renew-wrong-delay' {$global:task.Triggers[1].StartBoundary=$registered.AddSeconds(14401).ToString("yyyy-MM-dd'T'HH:mm:sszzz")}
 'renew-missing-date' {$global:task.Date=''}
 'renew-timer-disabled' {$global:task.Triggers[1].Enabled=$false}
 'renew-timer-end' {$global:task.Triggers[1].EndBoundary='2027-01-01T00:00:00+00:00'}
 'renew-timer-random' {$global:task.Triggers[1].RandomDelay='PT1H'}
 'renew-duplicate-logon' {$global:task.Triggers[1]=$global:task.Triggers[0]}
 'renew-reordered-check' {$global:task.Triggers=@($global:task.Triggers[1],$global:task.Triggers[0])}
 'renew-utc-z-check' {$global:task.Date=$global:task.Date.Replace('+00:00','Z');$global:task.Triggers[1].StartBoundary=$global:task.Triggers[1].StartBoundary.Replace('+00:00','Z')}
 'renew-future-registration' {$global:task.Date=$registered.AddDays(1).ToString("yyyy-MM-dd'T'HH:mm:sszzz");$global:task.Triggers[1].StartBoundary=$registered.AddDays(1).AddSeconds(14400).ToString("yyyy-MM-dd'T'HH:mm:sszzz")}
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
 if ($global:started -and 'CASE' -eq 'late-success') {Start-Sleep -Milliseconds 1200}
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
& VERIFIER -TaskName 'Marty-Candidate-Qualification' -RecoveryConfigurationFile CONFIG -ManagedPython PYTHON -TimeoutSeconds 1 -PreflightTimeoutSeconds PREFLIGHT OPTIONS
'''
    options = '-CheckOnly' if case.endswith('check') else ''
    if case.startswith('renew'):
        options += " -RenewCredentials -LogicalTlsProject 'marty-selfhost-synthetic' -RenewalIntervalMinutes 240"
        if case=='renew-first-check':options+=' -FirstRenewalDelaySeconds 15'
        elif case=='renew-invalid-first-delay':options+=' -FirstRenewalDelaySeconds 14'
        elif case=='renew-wrong-delay-config':options+=' -FirstRenewalDelaySeconds 120'
    for key, value in {'CASE': case, 'SCRIPTS': legacy.quote(scripts), 'ROOT': legacy.quote(tmp_path),
                       'CONFIG': legacy.quote(config), 'PYTHON': legacy.quote(python),
                       'STARTED': legacy.quote(started), 'VERIFIER': legacy.quote(verifier),
                       'PREFLIGHT': '1' if case == 'preflight-timeout' else '3',
                       'OPTIONS': options}.items():code = code.replace(key, value)
    result = subprocess.run([legacy.POWERSHELL, '-NoProfile', '-NonInteractive', '-EncodedCommand',
        base64.b64encode(code.encode('utf-16le')).decode()], capture_output=True, text=True, timeout=15)
    return result, child, started


@pytest.mark.parametrize('case', ['check', 'renew-check', 'run', 'renew-run',
                                'renew-first-check','renew-reordered-check','renew-utc-z-check'])
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
    assert report['task_start_requested'] == report['fresh_task_completion_observed'] == run
    assert not report['requested_run_attribution_verified']
    owned = json.loads((tmp_path/'owned.json').read_text())
    assert owned['timeout'] == 3 and '-CheckOnly' in owned['args']
    assert not report['operator_logon_qualified'] and not report['periodic_trigger_qualified']
    assert not report['host_reboot_qualified'] and not report['production_admission']


@pytest.mark.parametrize('case', ['wrong-user', 'highest', 'wrong-logon', 'wrong-folder',
    'wrong-action', 'wrong-launcher', 'wrong-cwd', 'extra-action', 'extra-trigger',
    'wrong-trigger-user', 'wrong-trigger-type', 'busy', 'disabled', 'parallel',
    'renew-retries', 'renew-duration', 'renew-interval', 'inventory-failure', 'missing', 'preflight-failure',
    'preflight-timeout','renew-logon-repetition','renew-legacy-logon-only','renew-local-boundary',
    'renew-wrong-delay','renew-missing-date','renew-timer-disabled','renew-timer-end',
    'renew-timer-random','renew-duplicate-logon','renew-future-registration',
    'renew-invalid-first-delay','renew-wrong-delay-config'])
def test_unqualified_task_never_starts(tmp_path, case):
    result, _child, started = invoke(tmp_path, case)
    assert result.returncode != 0 and not started.exists()


@pytest.mark.parametrize('case', ['never-ran', 'never-finished', 'failed-task', 'late-success'])
def test_unknown_or_failed_task_outcome_never_reports_success_or_replays(tmp_path, case):
    result, child, started = invoke(tmp_path, case)
    assert result.returncode != 0 and child.exists() and started.exists()
    assert '"fresh_task_completion_observed":  true' not in result.stdout
