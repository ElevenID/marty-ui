"""The managed entrypoint cannot fall back to POSIX input or Docker handling."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import selfhost_windows_recovery as recovery


@pytest.mark.skipif(os.name=='nt',reason='Actual non-Windows CLI refusal')
def test_nonwindows_cli_refuses_before_private_input_or_engine_access(monkeypatch,capsys):
    calls=[]
    def forbidden(*args,**kwargs):
        calls.append(True)
        raise AssertionError('Private input or engine access must not occur')
    monkeypatch.setattr(recovery.renewal,'hold_private_input',forbidden)
    monkeypatch.setattr(recovery,'wait_for_engine',forbidden)
    assert recovery.main(['--configuration','PRIVATE_SENTINEL.json','--wait-for-engine'])==1
    captured=capsys.readouterr()
    assert not calls and not captured.out and 'PRIVATE_SENTINEL' not in captured.err


@pytest.mark.parametrize('args',[
    ['--configuration','PRIVATE_SENTINEL','--unknown-private-flag'],
    ['--configuration','PRIVATE_SENTINEL','--logical-project'],
    ['--PRIVATE_SENTINEL'],[]])
def test_parser_refusal_never_echoes_arbitrary_arguments(monkeypatch,capsys,args):
    def forbidden(*_a,**_kw):pytest.fail('Private input read after malformed CLI')
    monkeypatch.setattr(recovery.renewal,'hold_private_input',forbidden)
    assert recovery.main(args)==1
    out=capsys.readouterr();assert not out.out and 'PRIVATE_SENTINEL' not in out.err


def test_help_is_intentional_and_does_not_read_private_inputs(monkeypatch,capsys):
    def forbidden(*_a,**_kw):pytest.fail('Private input read for help')
    monkeypatch.setattr(recovery.renewal,'hold_private_input',forbidden)
    assert recovery.main(['--help'])==0
    out=capsys.readouterr();assert '--renew-once' in out.out and not out.err
