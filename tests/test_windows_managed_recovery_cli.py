"""Strict private managed configuration and qualified-owner CLI routing."""
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import selfhost_windows_recovery as recovery
from test_selfhost_windows_inputs import private_fixture

pytestmark=pytest.mark.skipif(os.name!='nt',reason='Actual private NTFS configuration fixture')


@contextmanager
def configured(monkeypatch):
    with private_fixture() as (root,_):
        selector=root/'selector.json';selector.write_text('PUBLIC_SELECTOR')
        config=root/'managed.json'
        value={'schema':'marty.windows-managed-recovery/v1','selection_file':str(selector)}
        config.write_text(json.dumps(value))
        generation=root/'generation';generation.mkdir()
        calls=[]
        def check():
            calls.append('check');return {'configuration_verified':True,'native_admission':False,'runtime_readiness':False}
        def recover(output,**kw):
            assert kw=={'fresh_authority':True}
            assert output.parent==root and output.name.startswith('windows-recovery-')
            calls.append('recover')
            result={'result':'recovered-existing','services':8,'candidate_only':True,'automatic_lifecycle':False}
            (output/'result.json').write_text(json.dumps(result))
            return result
        @contextmanager
        def lease(path):
            assert path==selector
            yield SimpleNamespace(project='marty-production-synthetic',secrets_dir=generation,
                                  docker_host='SYNTHETIC_PIPE',engine_id='SYNTHETIC_ENGINE',
                                  check_configuration=check,recover_existing=recover)
        monkeypatch.setattr(recovery.selection,'selected_inputs',lease)
        yield root,config,value,calls


@pytest.mark.parametrize('check',[False,True])
def test_cli_explicit_wait_precedes_all_engine_dependent_callbacks(monkeypatch,capsys,check):
    with configured(monkeypatch) as (_root,config,_value,calls):
        def wait(host,engine):
            assert (host,engine)==('SYNTHETIC_PIPE','SYNTHETIC_ENGINE')
            calls.append('wait')
        monkeypatch.setattr(recovery,'wait_for_engine',wait)
        assert recovery.main(['--configuration',str(config),'--wait-for-engine',
                              *(['--check-only'] if check else [])])==0
        assert calls==['wait','check' if check else 'recover']
        assert json.loads(capsys.readouterr().out)


@pytest.mark.parametrize('check',[False,True])
def test_cli_uses_existing_owner_and_check_does_not_create_attempt(monkeypatch,capsys,check):
    with configured(monkeypatch) as (root,config,_value,calls):
        assert recovery.main(['--configuration',str(config),*(['--check-only'] if check else [])])==0
        output=json.loads(capsys.readouterr().out)
        assert calls==(['check'] if check else ['recover'])
        attempts=list(root.glob('windows-recovery-*'))
        assert len(attempts)==(0 if check else 1)
        if check:assert output['native_admission'] is False and output['runtime_readiness'] is False
        else:assert output['result']=='recovered-existing' and output['candidate_only'] is True


@pytest.mark.parametrize('bad',['duplicate','program','relative','legacy','missing','nonfinite'])
def test_cli_refuses_invalid_manifest_without_echoing_content(monkeypatch,capsys,bad):
    with configured(monkeypatch) as (_root,config,value,calls):
        if bad=='duplicate':config.write_text('{"schema":"PRIVATE_SENTINEL","schema":"marty.windows-managed-recovery/v1","selection_file":"ignored"}')
        elif bad=='nonfinite':config.write_text('{"schema":NaN,"selection_file":"PRIVATE_SENTINEL"}')
        else:
            if bad=='program':value['python']='PRIVATE_SENTINEL'
            elif bad=='relative':value['selection_file']='PRIVATE_SENTINEL'
            elif bad=='legacy':value['schema']='marty.windows-recovery/v1'
            else:del value['selection_file']
            config.write_text(json.dumps(value))
        assert recovery.main(['--configuration',str(config)])==1
        captured=capsys.readouterr()
        assert not captured.out and 'PRIVATE_SENTINEL' not in captured.err and not calls


def test_cli_withholds_exception_details_and_does_not_report_success(monkeypatch,capsys):
    with configured(monkeypatch) as (_root,config,_value,calls):
        @contextmanager
        def fail(_path):
            raise ValueError('PRIVATE_SENTINEL')
            yield
        monkeypatch.setattr(recovery.selection,'selected_inputs',fail)
        assert recovery.main(['--configuration',str(config)])==1
        captured=capsys.readouterr()
        assert not captured.out and 'PRIVATE_SENTINEL' not in captured.err and not calls


@pytest.mark.parametrize('wait',[False,True])
@pytest.mark.parametrize('check',[False,True])
def test_renewal_dispatch_releases_wait_lease_and_check_never_mints(monkeypatch,capsys,wait,check):
    with configured(monkeypatch) as (_root,config,value,calls):
        original=recovery.selection.selected_inputs;active=[]
        @contextmanager
        def lease(path):
            with original(path) as selected:
                active.append(True)
                try:yield selected
                finally:active.pop()
        def renew(path,logical):
            assert not active and str(path)==value['selection_file'] and logical=='marty-selfhost-synthetic'
            calls.append('renew');return {'result':'renewed-and-selected','sequence':2}
        monkeypatch.setattr(recovery.selection,'selected_inputs',lease)
        monkeypatch.setattr(recovery.selection,'renew_once',renew)
        monkeypatch.setattr(recovery,'wait_for_engine',lambda *_a:calls.append('wait'))
        args=['--configuration',str(config),'--renew-once','--logical-project','marty-selfhost-synthetic']
        if wait:args+=['--wait-for-engine']
        if check:args+=['--check-only']
        assert recovery.main(args)==0
        assert calls==(['wait'] if wait else [])+(['check'] if check else ['renew'])
        result=json.loads(capsys.readouterr().out)
        if check:assert result['renewal_requested'] is True and result['renewal_executed'] is False
        else:assert result['result']=='renewed-and-selected'


@pytest.mark.parametrize('extra',[
    ['--renew-once'],['--logical-project','marty-selfhost-synthetic'],
    ['--renew-once','--logical-project','PRIVATE_SENTINEL'],
    ['--renew-once','--logical-project','marty-selfhost-bad\n']])
def test_invalid_renewal_mode_refuses_before_private_inputs(monkeypatch,capsys,extra):
    def forbidden(*_a,**_kw):pytest.fail('Private configuration read before mode validation')
    monkeypatch.setattr(recovery.renewal,'hold_private_input',forbidden)
    assert recovery.main(['--configuration','PRIVATE_SENTINEL',*extra])==1
    out=capsys.readouterr();assert not out.out and 'PRIVATE_SENTINEL' not in out.err


@pytest.mark.parametrize('phase',['inspect','stage','publish','activate','select','finalize'])
def test_expired_current_dispatch_never_calls_ordinary_recovery(monkeypatch,capsys,phase):
    import selfhost_windows_staging_recovery as staging
    import selfhost_windows_recovery_activation as activation
    import selfhost_windows_recovery_finish as finish
    with configured(monkeypatch) as (root,config,value,calls):
        owners={'inspect':(staging,'inspect_failed_current'),'stage':(staging,'stage_recovery_generation'),
            'publish':(staging,'publish_recovery_candidate'),'activate':(activation,'activate_recovery_candidate'),
            'select':(finish,'finish'),'finalize':(finish,'finalize')}
        seen=[]
        def invoke(*args,**kwargs):
            assert str(args[0])==value['selection_file']
            seen.append((args,kwargs));return {'phase':phase,'credential_admission':False}
        module,name=owners[phase];monkeypatch.setattr(module,name,invoke)
        args=['--configuration',str(config),'--expired-current',phase]
        if phase!='inspect':args+=['--attempt-directory',str(root/'attempt')]
        if phase=='stage':args+=['--logical-project','marty-selfhost-synthetic']
        if phase in ('select','finalize'):args+=['--source-journal',str(root/'source')]
        assert recovery.main(args)==0
        assert len(seen)==1 and not calls
        assert json.loads(capsys.readouterr().out)['phase']==phase


@pytest.mark.parametrize('extra',[['--check-only'],['--wait-for-engine'],['--renew-once'],
    ['--logical-project','PRIVATE_SENTINEL'],['--attempt-directory','PRIVATE_SENTINEL'],
    ['--source-journal','PRIVATE_SENTINEL'],['--operator-successor-file','PRIVATE_SENTINEL']])
def test_expired_inspection_refuses_mixed_or_mutation_arguments(monkeypatch,capsys,extra):
    with configured(monkeypatch) as (_root,config,_value,calls):
        assert recovery.main(['--configuration',str(config),'--expired-current','inspect',*extra])==1
        output=capsys.readouterr()
        assert not output.out and 'PRIVATE_SENTINEL' not in output.err and not calls
