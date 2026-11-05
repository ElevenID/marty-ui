"""Use the scheduler's XML validation-only API, without registering any task."""
import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_windows_compose_recovery as legacy

pytestmark = pytest.mark.skipif(os.name != 'nt' or not legacy.POWERSHELL,
                                reason='Windows Task Scheduler XML validator')


@pytest.mark.parametrize('bad_retry', [False, True])
def test_scheduler_validates_renewal_xml_without_registering(bad_retry):
    code = r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(SOURCE,[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw 'Source parse failure'}
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'New-ManagedRecoveryTaskDefinition'},$false)
if (-not $function) {throw 'Missing definition factory'}
. ([scriptblock]::Create($function.Extent.Text))
$scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect()
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$shell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
$definition=New-ManagedRecoveryTaskDefinition $scheduler $user $shell '-NoProfile -NonInteractive -File C:/synthetic/recovery.ps1' 'C:/synthetic' 15 120 25
if (BAD) {$definition.Settings.RestartInterval='PT2M';$definition.Settings.RestartCount=0}
$accepted=$false
try {
 # TASK_VALIDATE_ONLY=1 checks XML syntax and NEVER registers a task.
 # Never combine this flag with CREATE/UPDATE, and never invoke Run/DeleteTask.
 $scheduler.GetFolder('\').RegisterTaskDefinition('Marty-XML-Validation-Only', $definition, 1, $user, $null, 3) | Out-Null
 $accepted=$true
} catch {
 if (-not BAD -or $_.Exception.Message -notmatch 'Count') {throw}
}
if ($accepted -eq BAD) {throw 'Unexpected scheduler XML validation result'}
exit 0
'''.replace('SOURCE', legacy.quote(legacy.ROOT/'scripts/install-marty-boot-recovery.ps1'))
    code = code.replace('BAD', '$true' if bad_retry else '$false')
    result = subprocess.run([legacy.POWERSHELL, '-NoProfile', '-NonInteractive', '-EncodedCommand',
                             base64.b64encode(code.encode('utf-16le')).decode()],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
