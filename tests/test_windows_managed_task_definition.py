"""Qualify native COM serialization of an unregistered task definition only."""
import base64
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_windows_compose_recovery as legacy

pytestmark=pytest.mark.skipif(os.name!='nt' or not legacy.POWERSHELL,reason='Unregistered Windows COM definition')


def test_native_task_definition_xml_without_registering_or_starting_any_task():
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
$definition=New-ManagedRecoveryTaskDefinition $service $user $shell '-NoProfile -NonInteractive -File C:/synthetic/recovery.ps1' 'C:/synthetic'
# No GetFolder, RegisterTaskDefinition, RegisterTask, Run or DeleteTask call.
$definition.XmlText
'''.replace('SOURCE',source)
    result=subprocess.run([legacy.POWERSHELL,'-NoProfile','-NonInteractive','-EncodedCommand',
        base64.b64encode(code.encode('utf-16le')).decode()],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    root=ET.fromstring(result.stdout)
    ns={'t':'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    def text(xpath):return root.find(xpath,ns).text
    assert text('t:Principals/t:Principal/t:LogonType')=='InteractiveToken'
    assert text('t:Principals/t:Principal/t:RunLevel')=='LeastPrivilege'
    assert text('t:Triggers/t:LogonTrigger/t:Delay')=='PT2M'
    assert text('t:Settings/t:ExecutionTimeLimit')=='PT20M'
    assert text('t:Settings/t:MultipleInstancesPolicy')=='IgnoreNew'
    assert text('t:Settings/t:RestartOnFailure/t:Count')=='3'
    assert Path(text('t:Actions/t:Exec/t:Command')).is_absolute()
