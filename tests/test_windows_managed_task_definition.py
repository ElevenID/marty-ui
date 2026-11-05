"""Qualify native COM serialization of an unregistered task definition only."""
import base64
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_windows_compose_recovery as legacy

pytestmark=pytest.mark.skipif(os.name!='nt' or not legacy.POWERSHELL,reason='Unregistered Windows COM definition')


@pytest.mark.parametrize('interval,delay,window',[(0,0,0),(240,0,0),(240,15,0),(15,120,25)])
def test_native_task_definition_xml_without_registering_or_starting_any_task(interval,delay,window):
    source=legacy.quote(legacy.ROOT/'scripts/install-marty-boot-recovery.ps1')
    code=r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(SOURCE,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Source parse failure' }
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'New-ManagedRecoveryTaskDefinition'},$false)
if (-not $function) { throw 'Missing definition factory' }
# Extract only the reviewed pure definition factory; never invoke installer body.
. ([scriptblock]::Create($function.Extent.Text))
function Register-ScheduledTask { throw 'Registration forbidden' }
$service=New-Object -ComObject 'Schedule.Service'
$service.Connect()
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$shell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
$definition=New-ManagedRecoveryTaskDefinition $service $user $shell '-NoProfile -NonInteractive -File C:/synthetic/recovery.ps1' 'C:/synthetic' INTERVAL DELAY WINDOW
if (INTERVAL -gt 0 -and $definition.Settings.RestartCount -ne 0) { throw 'Renewal retries must be disabled' }
# No GetFolder, RegisterTaskDefinition, RegisterTask, Run or DeleteTask call.
$definition.XmlText
'''.replace('SOURCE',source).replace('INTERVAL',str(interval)).replace('DELAY',str(delay)).replace('WINDOW',str(window))
    result=subprocess.run([legacy.POWERSHELL,'-NoProfile','-NonInteractive','-EncodedCommand',
        base64.b64encode(code.encode('utf-16le')).decode()],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    root=ET.fromstring(result.stdout)
    ns={'t':'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    def text(xpath):return root.find(xpath,ns).text
    assert text('t:Principals/t:Principal/t:LogonType')=='InteractiveToken'
    assert text('t:Principals/t:Principal/t:RunLevel')=='LeastPrivilege'
    assert text('t:Triggers/t:LogonTrigger/t:Delay')=='PT2M'
    assert text('t:Settings/t:ExecutionTimeLimit')==('PT1H' if interval else 'PT20M')
    assert text('t:Settings/t:MultipleInstancesPolicy')=='IgnoreNew'
    if interval:
        assert root.find('t:Triggers/t:LogonTrigger/t:Repetition',ns) is None
        assert text('t:Triggers/t:TimeTrigger/t:Repetition/t:Interval')==f'PT{interval}M'
        assert root.find('t:Triggers/t:TimeTrigger/t:Repetition/t:Duration',ns) is None
        assert text('t:Triggers/t:TimeTrigger/t:Repetition/t:StopAtDurationEnd')=='false'
        registered=datetime.fromisoformat(text('t:RegistrationInfo/t:Date'))
        first=datetime.fromisoformat(text('t:Triggers/t:TimeTrigger/t:StartBoundary'))
        assert registered.utcoffset()==first.utcoffset()==timedelta(0)
        assert (first-registered).total_seconds()==(delay or 60*interval)
        for kind in ('LogonTrigger','TimeTrigger'):
            end=root.find(f't:Triggers/t:{kind}/t:EndBoundary',ns)
            if window:
                assert datetime.fromisoformat(end.text)==registered+timedelta(minutes=window)
            else:
                assert end is None
        count=root.find('t:Settings/t:RestartOnFailure/t:Count',ns)
        assert count is None or count.text=='0' # COM omits the zero default
    else:
        assert text('t:Settings/t:RestartOnFailure/t:Count')=='3'
        assert root.find('t:Triggers/t:TimeTrigger',ns) is None
    assert Path(text('t:Actions/t:Exec/t:Command')).is_absolute()
