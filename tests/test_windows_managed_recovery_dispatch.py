"""Execute the existing PowerShell wrapper with a harmless interpreter recorder."""
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_windows_compose_recovery as legacy

pytestmark=pytest.mark.skipif(os.name!='nt' or not legacy.POWERSHELL,reason='Windows PowerShell recorder')


@pytest.fixture(scope='session',autouse=True)
def recorder(tmp_path_factory):
    legacy.native_docker_recorder.__wrapped__(tmp_path_factory)


def invoke(tmp_path,*,check=False,wait=False,renew=False,bad=None):
    selection=tmp_path/'private selector.json';selection.touch()
    config=tmp_path/'retained managed.json'
    value={'schema':'marty.windows-managed-recovery/v1','selection_file':str(selection)}
    if bad=='extra-python':value['python']='untrusted.exe'
    elif bad=='relative':value['selection_file']='relative.json'
    elif bad=='missing-selection':selection.unlink()
    elif bad=='legacy':value={'schema':'marty.windows-recovery/v1','parameters':{}}
    config.write_text(json.dumps(value))
    log=tmp_path/'commands.jsonl'
    script='& '+legacy.quote(legacy.ROOT/'scripts/recover-marty-after-reboot.ps1')
    if bad!='no-config':script+=' -RecoveryConfigurationFile '+legacy.quote(config)
    if bad!='no-python':script+=' -ManagedPython '+legacy.quote(legacy.NATIVE_DOCKER)
    if check:script+=' -CheckOnly'
    if wait:script+=' -WaitForEngine'
    if renew:script+=" -RenewCredentials -LogicalTlsProject 'marty-selfhost-synthetic'"
    env={**os.environ,'MARTY_TEST_DOCKER_LOG':str(log)}
    p=subprocess.run([legacy.POWERSHELL,'-NoProfile','-NonInteractive','-EncodedCommand',
        base64.b64encode(script.encode('utf-16le')).decode()],capture_output=True,text=True,env=env,timeout=30)
    calls=[json.loads(x) for x in log.read_text(encoding='utf-8-sig').splitlines()] if log.exists() else []
    return p,calls,config


@pytest.mark.parametrize('check',[False,True])
@pytest.mark.parametrize('wait',[False,True])
def test_managed_dispatch_reaches_only_retained_owner(tmp_path,check,wait):
    p,calls,config=invoke(tmp_path,check=check,wait=wait)
    assert p.returncode==0,p.stderr
    expected=[str(legacy.ROOT/'scripts/selfhost_windows_recovery.py'),'--configuration',str(config)]
    if check:expected+=['--check-only']
    if wait:expected+=['--wait-for-engine']
    assert calls==[expected]


@pytest.mark.parametrize('bad',['extra-python','relative','missing-selection','legacy','no-config','no-python'])
def test_managed_dispatch_refuses_bad_or_mixed_configuration_before_execution(tmp_path,bad):
    p,calls,_=invoke(tmp_path,bad=bad)
    assert p.returncode!=0 and not calls


@pytest.mark.parametrize('check',[False,True])
def test_renewal_flags_reach_only_existing_managed_owner(tmp_path,check):
    p,calls,config=invoke(tmp_path,check=check,wait=True,renew=True)
    assert p.returncode==0,p.stderr
    expected=[str(legacy.ROOT/'scripts/selfhost_windows_recovery.py'),'--configuration',str(config)]
    if check:expected+=['--check-only']
    expected+=['--wait-for-engine','--renew-once','--logical-project','marty-selfhost-synthetic']
    assert calls==[expected]
