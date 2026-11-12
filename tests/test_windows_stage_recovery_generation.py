"""Recovery staging owns new private NTFS outputs and retains both guards."""
from pathlib import Path
import sys
from contextlib import contextmanager
from copy import deepcopy
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_windows_failed_current_inspection import failed_current
import selfhost_windows_renewal_native as native
import selfhost_windows_selection as selection
from selfhost_windows_staging_recovery import stage_recovery_generation, inspect_failed_current


@pytest.mark.parametrize('fault', [None, 'producer', 'candidate'])
@pytest.mark.parametrize('successor', [False, True])
def test_guarded_recovery_staging_never_activates_or_admits_retry(monkeypatch, fault, successor):
    with failed_current(monkeypatch) as (root, path, cfg, failed, events):
        output = root/('windows-renewal-'+'e'*32)
        output.mkdir()
        original = {p.relative_to(failed):p.read_bytes() for p in failed.rglob('*') if p.is_file()}
        def capability(*args):
            assert not selection.renewal.recovery_guard(cfg).exists()
        monkeypatch.setattr(native, 'require_recovery_capability', capability)
        import selfhost_windows_recovery_operator as operators
        @contextmanager
        def admitted(old, assets, expected, **kwargs):
            saved=deepcopy(old)
            new=deepcopy(old)
            new.update(binary='PUBLIC_SUCCESSOR',binary_sha256='b'*64,source_sha='b'*40,release_tag='v1.2.4')
            yield new, {'schema':'PUBLIC_SYNTHETIC_ADMISSION'}
            assert old==saved
        monkeypatch.setattr(operators, 'admitted_operator', admitted)
        def produce(config, current, logical, cycle, image, checkpoint):
            assert selection.renewal.recovery_guard(cfg).exists()
            assert selection.renewal.renewal_staging_guard(cfg).exists()
            events.append('recovery-producer')
            if successor:
                assert config['native']['binary']=='PUBLIC_SUCCESSOR'
                assert config['native']['source_sha']=='b'*40
            assert config['native']['renewed']=='/control/windows-renewal-'+cycle+'/generation'
            assert config['native']['token_file']=='/control/recovery-session-'+cycle+'/token'
            checkpoint('prepare', 'started', {})
            if fault == 'producer':raise RuntimeError('SYNTHETIC_PRODUCER_FAILURE')
            return {name: (b'' if value == b'' else b'PUBLIC_RECOVERED_'+name.encode()) for name,value in current.items()}
        def prove(*args):
            events.append('recovery-candidate')
            if fault == 'candidate':raise ValueError('SYNTHETIC_CANDIDATE_FAILURE')
        monkeypatch.setattr(native, 'produce_recovery_generation', produce)
        monkeypatch.setattr(native, 'preflight_recovery', prove)
        def stage():
            return stage_recovery_generation(path, output, 'marty-selfhost-synthetic',
                operator_successor={'assets':'PUBLIC_ASSETS','expected':{},'gh':'PUBLIC_GH','cosign':'PUBLIC_COSIGN'} if successor else None)
        if fault:
            with pytest.raises((ValueError, RuntimeError)):
                stage()
        else:
            result = stage()
            assert result['guards_retained'] and not result['credential_admission']
            assert result['result'] == 'provisional-candidate'
        assert original == {p.relative_to(failed):p.read_bytes() for p in failed.rglob('*') if p.is_file()}
        assert selection.renewal.recovery_guard(cfg).exists()
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        assert not (output/'result.json').exists()
        with pytest.raises(ValueError):inspect_failed_current(path)
        assert not any('activate' in str(event) for event in events)


def test_unsupported_operator_refuses_before_new_guard_or_authority(monkeypatch):
    with failed_current(monkeypatch) as (root, path, cfg, _, events):
        output=root/('windows-renewal-'+'f'*32)
        output.mkdir()
        def refuse(*args):raise ValueError('SYNTHETIC_UNSUPPORTED_OPERATOR')
        monkeypatch.setattr(native, 'require_recovery_capability', refuse)
        with pytest.raises(ValueError):
            stage_recovery_generation(path, output, 'marty-selfhost-synthetic')
        assert not list(output.iterdir())
        assert not selection.renewal.recovery_guard(cfg).exists()
        assert events == ['authority']  # Original failed attempt only.
