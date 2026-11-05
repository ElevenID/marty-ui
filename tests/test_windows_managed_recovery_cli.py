"""Strict private managed configuration and qualified-owner CLI routing."""
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import selfhost_windows_recovery as recovery
from test_selfhost_windows_inputs import private_fixture


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
