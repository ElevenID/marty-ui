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
