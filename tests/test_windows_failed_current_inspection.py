"""Real NTFS failed-current evidence; Docker and native authority are substituted."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_selfhost_windows_staging import staged_candidate
import selfhost_windows_selection as selection
from selfhost_windows_staging_recovery import inspect_failed_current


@contextmanager
def failed_current(monkeypatch):
    with staged_candidate(monkeypatch) as case:
        _, path, _, output, events = case
        original = selection._prove
        def refuse(*args, **kwargs):
            raise ValueError('PUBLIC_CURRENT_LIFETIME_REFUSAL')
        monkeypatch.setattr(selection, '_prove', refuse)
        with pytest.raises(ValueError):
            with selection.selected_inputs(path) as lease:
                lease.stage_renewal(output, 'marty-selfhost-synthetic')
        monkeypatch.setattr(selection, '_prove', original)
        assert events == ['authority']
        yield case


def test_inspection_keeps_guard_and_all_attempt_bytes(monkeypatch):
    with failed_current(monkeypatch) as (_, path, cfg, output, events):
        before = {p.relative_to(output): p.read_bytes() for p in output.rglob('*') if p.is_file()}
        result = inspect_failed_current(path)
        assert result['sequence'] == 1
        assert result['guard_retained'] and not result['credential_admission']
        assert before == {p.relative_to(output): p.read_bytes() for p in output.rglob('*') if p.is_file()}
        assert events == ['authority']
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):
                pytest.fail('Inspection admitted retry')


@pytest.mark.parametrize('fault', ['candidate', 'activation', 'env', 'stage', 'phase', 'extra'])
def test_inspection_refuses_changed_attempt(monkeypatch, fault):
    with failed_current(monkeypatch) as (root, path, cfg, output, events):
        stage = selection.decode((output/'intent.json').read_bytes())
        next_config = selection.decode(Path(stage['config_path']).read_bytes())
        if fault == 'candidate':
            (Path(next_config['renewed_secrets'])/'unexpected').write_bytes(b'PUBLIC')
        elif fault == 'activation':
            Path(next_config['intent']).write_bytes(b'PUBLIC_STARTED')
        elif fault == 'env':
            with (output/'renewed.env').open('ab') as stream:
                stream.write(b'UNREVIEWED_SETTING=true\n')
        elif fault == 'stage':
            stage['selected_sha256'] = '0'*64
            changed = selection.packed(stage)
            (output/'intent.json').write_bytes(changed)
            selection.renewal.renewal_staging_guard(cfg).write_bytes(changed)
        elif fault == 'phase':
            (output/'prepare.started.json').write_bytes(b'{}')
        else:
            (output/'unexpected').write_bytes(b'PUBLIC')
        with pytest.raises((ValueError, KeyError)):
            inspect_failed_current(path)
        assert events == ['authority']
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        assert not (output/'publication.json').exists()


@pytest.mark.parametrize('target', ['attempt', 'activation', 'candidate'])
def test_late_directory_proof_failure_prevents_result(monkeypatch, target):
    with failed_current(monkeypatch) as (_, path, cfg, output, events):
        stage = selection.decode((output/'intent.json').read_bytes())
        next_config = selection.decode(Path(stage['config_path']).read_bytes())
        selected = {'attempt': output, 'activation': output/'activation',
                    'candidate': Path(next_config['renewed_secrets'])}[target]
        original = selection._held_private_input
        active = []
        checked = []
        original_inspect = selection._inspect
        def observe(*args, **kwargs):
            observed = dict(original_inspect(*args, **kwargs))
            check = observed['context'].check
            def verify(**options):
                checked.append(bool(active))
                return check(**options)
            observed['context'] = SimpleNamespace(check=verify)
            return observed
        @contextmanager
        def held(asset, **kwargs):
            with original(asset, **kwargs) as value:
                if Path(asset) == selected and kwargs.get('directory'):
                    active.append(True)
                    try:
                        yield value
                    finally:
                        active.pop()
                        raise ValueError('PUBLIC_LATE_DIRECTORY_PROOF_FAILURE')
                else:
                    yield value
        monkeypatch.setattr(selection, '_held_private_input', held)
        monkeypatch.setattr(selection, '_inspect', observe)
        with pytest.raises(ValueError):
            inspect_failed_current(path)
        assert checked == [True]
        assert not active and events == ['authority']
        assert selection.renewal.renewal_staging_guard(cfg).exists()
