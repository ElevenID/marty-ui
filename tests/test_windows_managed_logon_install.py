"""Actual PowerShell installer with child/task API recorders, no real task."""
import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_windows_compose_recovery as legacy

pytestmark=pytest.mark.skipif(os.name!='nt' or not legacy.POWERSHELL,reason='Windows task API recorder')


def invoke(tmp_path,case):
    installer=tmp_path/'install.ps1'
    shutil.copyfile(legacy.ROOT/'scripts/install-marty-boot-recovery.ps1',installer)
    config=tmp_path/"operator's managed configuration.json";config.write_text('{}')
    python=tmp_path/"operator's python.exe";python.touch()
    child=tmp_path/'child.json';record=tmp_path/'task.json'
    (tmp_path/'recover-marty-after-reboot.ps1').write_text(
        'param([string]$RecoveryConfigurationFile,[string]$ManagedPython,[switch]$CheckOnly,[switch]$RenewCredentials,[string]$LogicalTlsProject)\n'
        '@{configuration=$RecoveryConfigurationFile; python=$ManagedPython; check=[bool]$CheckOnly; renew=[bool]$RenewCredentials; logical=$LogicalTlsProject} '
        '| ConvertTo-Json | Set-Content '+legacy.quote(child)+
        '\nexit '+('1' if case=='preflight-failure' else '0')+'\n')
    code=r'''
$ErrorActionPreference='Stop'
$global:record=@{trigger_types=@()}
function Get-ScheduledTask {
 if ('CASE' -eq 'inventory-failure') { throw 'synthetic inventory failure' }
 if ('CASE' -eq 'existing-task') { return [pscustomobject]@{TaskName='Marty-Candidate-Recovery';TaskPath='\OtherOwner\'} }
}
function Register-ScheduledTask { throw 'Native task cmdlet forbidden in managed recorder' }
$global:trigger=[pscustomobject]@{UserId='';Delay='';Repetition=[pscustomobject]@{Interval='';StopAtDurationEnd=$true}}
$global:timer=[pscustomobject]@{Enabled=$false;StartBoundary='';Repetition=[pscustomobject]@{Interval='';StopAtDurationEnd=$true}}
$global:action=[pscustomobject]@{Path='';Arguments='';WorkingDirectory=''}
$global:definition=[pscustomobject]@{
 RegistrationInfo=[pscustomobject]@{Description='';Date=''}
 Principal=[pscustomobject]@{UserId='';LogonType=0;RunLevel=0}
 Settings=[pscustomobject]@{StartWhenAvailable=$false;ExecutionTimeLimit='';RestartCount=0;RestartInterval='';MultipleInstances=0;Enabled=$false}
 Triggers=[pscustomobject]@{};Actions=[pscustomobject]@{} }
$global:definition.Triggers | Add-Member ScriptMethod Create { param($kind)
 $global:record.trigger_types+=@($kind)
 if ($kind -eq 9) {return $global:trigger}
 if ($kind -eq 1) {return $global:timer}
 throw 'Unexpected trigger kind' }
$global:definition.Actions | Add-Member ScriptMethod Create { param($kind)
 $global:record.action_type=$kind;return $global:action }
$global:folder=[pscustomobject]@{}
$global:folder | Add-Member ScriptMethod RegisterTaskDefinition {
 param($name,$definition,$flags,$userId,$password,$logonType)
 if ($flags -ne 2) { throw 'Atomic create-only flag required' }
 $global:record.name=$name;$global:record.flags=$flags
 $global:record.principal=@($definition.Principal.UserId,$definition.Principal.LogonType,$definition.Principal.RunLevel)
 $global:record.registration_logon=$logonType;$global:record.no_password=($null -eq $password)
 $global:record.action=$global:action.Arguments;$global:record.launcher=$global:action.Path
 $global:record.delay=$global:trigger.Delay;$global:record.settings=$definition.Settings
 $global:record.repetition=$global:trigger.Repetition
 $global:record.timer=$global:timer;$global:record.registered=$definition.RegistrationInfo.Date
 if ('CASE' -eq 'late-collision') {
  $global:record | ConvertTo-Json | Set-Content COLLISION
  throw 'Synthetic registration-time collision; existing task preserved'
 }
 $global:record | ConvertTo-Json | Set-Content RECORD
 return @{} }
$global:scheduler=[pscustomobject]@{}
$global:scheduler | Add-Member ScriptMethod Connect { }
$global:scheduler | Add-Member ScriptMethod GetFolder { param($path)
 if ($path -ne '\') { throw 'Root folder required' };return $global:folder }
$global:scheduler | Add-Member ScriptMethod NewTask { param($flags)
 if ($flags -ne 0) { throw 'NewTask flags must be zero' };return $global:definition }
# Block every real COM activation, including unexpected additional calls.
function New-Object { param($ComObject)
 if ($ComObject -ne 'Schedule.Service') { throw 'Unexpected COM request' }
 return $global:scheduler }
& INSTALLER -RecoveryConfigurationFile CONFIG -ManagedPython PYTHON TASK
'''
    task="-TaskName 'Marty-Candidate-Recovery'"
    if case=='missing-name':task=''
    elif case=='historical-name':task="-TaskName 'Marty-Recovery-At-Boot'"
    elif case=='unsafe-name':task="-TaskName '../other'"
    elif case=='legacy-custom':
        task="-TaskName 'OtherOwnerTask'"
        code=code.replace(' -ManagedPython PYTHON','')
    if case=='missing-python':python.unlink()
    if case.startswith('renew'):
        task+=" -RenewCredentials -LogicalTlsProject 'marty-selfhost-synthetic' -RenewalIntervalMinutes 240"
        if case=='renew-bad-interval':task=task.replace('240','0')
        elif case=='renew-bad-project':task=task.replace('marty-selfhost-synthetic','PRIVATE_SENTINEL')
        elif case=='renew-no-python':code=code.replace(' -ManagedPython PYTHON','')
        elif case=='renew-short-first-delay':task+=' -FirstRenewalDelaySeconds 14'
        elif case=='renew-long-first-delay':task+=' -FirstRenewalDelaySeconds 14401'
        elif case=='renew-first':task+=' -FirstRenewalDelaySeconds 15'
    if case=='recovery-first-delay':task+=' -FirstRenewalDelaySeconds 15'
    for key,value in {'CASE':case,'COLLISION':legacy.quote(tmp_path/'collision.json'),
        'RECORD':legacy.quote(record),'INSTALLER':legacy.quote(installer),
        'CONFIG':legacy.quote(config),'PYTHON':legacy.quote(python),'TASK':task}.items():
        code=code.replace(key,value)
    result=subprocess.run([legacy.POWERSHELL,'-NoProfile','-NonInteractive','-EncodedCommand',
        base64.b64encode(code.encode('utf-16le')).decode()],capture_output=True,text=True,timeout=30)
    return result,config,python,child,record


def test_managed_install_retains_explicit_interpreter_and_separate_logon_task(tmp_path):
    result,config,python,child,record=invoke(tmp_path,'success')
    assert result.returncode==0,result.stderr
    assert json.loads(child.read_text(encoding='utf-8-sig'))=={
        'configuration':str(config),'python':str(python),'check':True,'renew':False,'logical':''}
    task=json.loads(record.read_text(encoding='utf-8-sig'))
    assert task['name']=='Marty-Candidate-Recovery' and task['flags']==2
    assert task['trigger_types']==[9] and task['action_type']==0
    assert task['principal'][1:]==[3,0] and task['registration_logon']==3 and task['no_password']
    assert Path(task['launcher']).is_absolute() and task['launcher'].lower().endswith('powershell.exe')
    assert task['delay']=='PT2M' and task['settings']['ExecutionTimeLimit']=='PT20M'
    assert task['settings']['MultipleInstances']==2
    assert '-ManagedPython "'+str(python)+'"' in task['action']
    assert '-RecoveryConfigurationFile "'+str(config)+'"' in task['action']
    assert '-WaitForEngine' in task['action'] and '-CheckOnly' not in task['action']
    assert '-WindowStyle Hidden -File ' in task['action']


@pytest.mark.parametrize('case',['renew','renew-first'])
def test_renewal_install_is_separate_create_only_and_preflight_never_mints(tmp_path,case):
    from datetime import datetime, timedelta
    result,config,python,child,record=invoke(tmp_path,case)
    assert result.returncode==0,result.stderr
    checked=json.loads(child.read_text(encoding='utf-8-sig'))
    assert checked['check'] and checked['renew'] and checked['logical']=='marty-selfhost-synthetic'
    task=json.loads(record.read_text(encoding='utf-8-sig'))
    assert task['flags']==2 and task['name']=='Marty-Candidate-Recovery'
    assert task['trigger_types']==[9,1] and task['repetition']['Interval']==''
    assert task['timer']['Repetition']=={'Interval':'PT240M','StopAtDurationEnd':False}
    registered=datetime.fromisoformat(task['registered']);first=datetime.fromisoformat(task['timer']['StartBoundary'])
    assert registered.utcoffset()==first.utcoffset()==timedelta(0)
    assert (first-registered).total_seconds()==(15 if case=='renew-first' else 14400)
    assert task['settings']['RestartCount']==0 and task['settings']['ExecutionTimeLimit']=='PT1H'
    assert '-RenewCredentials -LogicalTlsProject "marty-selfhost-synthetic"' in task['action']
    assert '-CheckOnly' not in task['action']


@pytest.mark.parametrize('case',['missing-name','historical-name','unsafe-name','missing-python',
                               'existing-task','inventory-failure','preflight-failure','late-collision','legacy-custom',
                               'renew-bad-interval','renew-bad-project','renew-no-python',
                               'renew-short-first-delay','renew-long-first-delay','recovery-first-delay'])
def test_managed_install_never_registers_on_bad_identity_inventory_or_preflight(tmp_path,case):
    result,_config,_python,child,record=invoke(tmp_path,case)
    assert result.returncode!=0 and not record.exists()
    assert child.exists()==(case in ['preflight-failure','late-collision'])
    if case=='late-collision':
        attempt=json.loads((tmp_path/'collision.json').read_text(encoding='utf-8-sig'))
        assert attempt['flags']==2
