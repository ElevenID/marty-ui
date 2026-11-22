"""Synthetic process-owner setup cannot survive failures or manufacture success."""
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/ci'))
import run_windows_source_tests as launcher


class Token:
    def __init__(self, *, original=b'GROUP', failure=None):
        self.original = original
        self.user = b'USER'
        self.current = original
        self.failure = failure
        self.events = []

    def owner(self):
        self.events.append('query')
        return self.current

    def use_user(self):
        self.events.append('set-user')
        if self.failure != 'setup-query':
            self.current = self.user
        if self.failure == 'setup':
            raise RuntimeError('synthetic setter failed after changing owner')

    def restore_original(self):
        self.events.append('restore')
        if self.failure != 'restore-query':
            self.current = self.original
        if self.failure == 'restore':
            raise RuntimeError('synthetic restoration failure')

    def close(self):
        self.events.append('close')
        if self.failure == 'close':
            raise RuntimeError('synthetic close failure')


@pytest.mark.parametrize('original', [b'GROUP', b'USER'])
def test_scoped_owner_restores_exact_original_after_success(original):
    token = Token(original=original)
    with launcher.synthetic_current_user_owner(lambda: token):
        assert token.current == token.user
    assert token.current == original
    assert token.events == ['set-user', 'query', 'restore', 'query', 'close']


@pytest.mark.parametrize('failure', ['setup', 'setup-query', 'body', 'restore', 'restore-query', 'close'])
def test_owner_failures_close_and_cannot_complete_successfully(failure):
    token = Token(failure=failure)
    completed = []
    with pytest.raises(RuntimeError):
        with launcher.synthetic_current_user_owner(lambda: token):
            if failure == 'body':
                raise RuntimeError('synthetic test interruption')
        completed.append(True)
    assert not completed and token.events[-1] == 'close'
    assert 'restore' in token.events
    if failure != 'restore-query':
        assert token.current == token.original


@pytest.mark.parametrize('failure', [None, 'restore', 'close'])
def test_launcher_runs_fixed_suite_and_returns_only_after_restoration(monkeypatch, tmp_path, capsys, failure):
    token = Token(failure=failure)
    events = []

    def inspect():
        events.append(('inspect', token.current))
        return {'probes': [{'passed': token.current == token.user}]}

    def creation():
        assert token.current == token.user
        events.append('parent-and-isolated-child')

    def pytest_main(arguments):
        assert token.current == token.user
        assert arguments == ['-q', 'tests/test_windows_source_install_ntfs.py',
                             '--junitxml=' + str(tmp_path / 'native.xml')]
        events.append('pytest')
        return 0

    monkeypatch.setattr(launcher, 'inspect_environment', inspect)
    monkeypatch.setattr(launcher, 'prove_parent_and_isolated_child_creation', creation)
    monkeypatch.setattr(pytest, 'main', pytest_main)
    if failure:
        with pytest.raises(RuntimeError):
            launcher.execute_suite(tmp_path / 'native.xml', token_factory=lambda: token)
        assert 'restored exactly' not in capsys.readouterr().out
    else:
        assert launcher.execute_suite(tmp_path / 'native.xml', token_factory=lambda: token) == 0
        assert 'restored exactly' in capsys.readouterr().out
    assert token.current == token.original and token.events[-1] == 'close'
    assert events == [('inspect', token.original), ('inspect', token.user),
                      'parent-and-isolated-child', 'pytest']


@pytest.mark.parametrize('failure', [RuntimeError('synthetic child owner mismatch'),
                                   subprocess.TimeoutExpired('synthetic isolated child', 15)])
def test_failed_native_creation_never_invokes_pytest_and_restores_owner(monkeypatch, tmp_path, failure):
    token = Token()
    monkeypatch.setattr(launcher, 'inspect_environment', lambda: {'probes': [{'passed': True}]})
    def refuse():
        raise failure
    monkeypatch.setattr(launcher, 'prove_parent_and_isolated_child_creation', refuse)
    monkeypatch.setattr(pytest, 'main', lambda *_args: pytest.fail('Unproved native creation reached pytest'))
    with pytest.raises(type(failure)):
        launcher.execute_suite(tmp_path / 'native.xml', token_factory=lambda: token)
    assert token.current == token.original and token.events[-1] == 'close'
