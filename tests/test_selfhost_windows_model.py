"""Narrow model changes and actual private NTFS append-only repair decisions.

Docker and native custody are substituted; these tests never contact a runtime.
"""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import selfhost_windows_model as repair
import selfhost_windows_selection as selection
import selfhost_windows_renewal as renewal
import selfhost_windows_renewal_native as native
from test_selfhost_windows_selection import fixture


def models():
    before = {'services': {'applicant': {'environment': {}, 'secrets': []},
                           'gateway': {'image': 'PUBLIC_SYNTHETIC'}},
              'secrets': {'issuance_api_key': {'file': '${SELFHOST_SECRET_DIR}/issuance_api_key'}}}
    after = deepcopy(before)
    after['services']['applicant']['environment']['ISSUANCE_API_KEY_FILE'] = '/run/secrets/issuance_api_key'
    after['services']['applicant']['secrets'].append(
        {'source': 'issuance_api_key', 'target': '/run/secrets/issuance_api_key'})
    return before, after


def test_exact_existing_file_binding_is_the_only_accepted_model_change():
    before, after = models()
    repair.check_repair(before, after)
    assert before['services']['applicant']['environment'] == {}


@pytest.mark.parametrize('bad', ['image', 'port', 'storage', 'inline', 'target', 'missing-mount',
                               'extra-mount', 'privileged', 'other-role', 'already-bound'])
def test_model_repair_refuses_other_changes(bad):
    before, after = models(); app = after['services']['applicant']
    if bad == 'image':app['image'] = 'PUBLIC_OTHER'
    elif bad == 'port':app['ports'] = ['8000:8000']
    elif bad == 'storage':after['secrets']['issuance_api_key']['file'] = '/other/key'
    elif bad == 'inline':app['environment']['ISSUANCE_API_KEY'] = 'PUBLIC_SYNTHETIC'
    elif bad == 'target':app['secrets'][0]['target'] = '/wrong'
    elif bad == 'missing-mount':app['secrets'] = []
    elif bad == 'extra-mount':app['secrets'].append({'source': 'other', 'target': '/other'})
    elif bad == 'privileged':app['privileged'] = True
    elif bad == 'other-role':after['services']['gateway']['image'] = 'PUBLIC_OTHER'
    else:before = deepcopy(after)
    with pytest.raises(ValueError):repair.check_repair(before, after)


@contextmanager
def runtime(monkeypatch, *, failure=None):
    with fixture(monkeypatch) as (root, phase, _tx, _outcome, path, cfg):
        # Prepare synthetic Applicant before adopting, never rewrite a selected model.
        old_path = Path(cfg['compose_file']); before = selection.decode(old_path.read_bytes())
        before['secrets']['issuance_api_key'] = {'file': '${SELFHOST_SECRET_DIR}/issuance_api_key'}
        for prefix in ('current', 'renewed'):
            (Path(cfg[prefix+'_secrets'])/'issuance_api_key').write_bytes(
                ('PUBLIC_SYNTHETIC_'+prefix).encode())
        before['services']['applicant'] = {'image': 'example.invalid/synthetic@sha256:'+'1'*64,
                                           'environment': {}, 'secrets': []}
        old_path.write_bytes(selection.packed(before))
        cfg['compose_sha256'] = selection.digest(old_path.read_bytes())
        path.write_bytes(selection.packed(cfg))
        selection.adopt(path)
        after = deepcopy(before)
        after['services']['applicant']['environment']['ISSUANCE_API_KEY_FILE'] = '/run/secrets/issuance_api_key'
        after['services']['applicant']['secrets'].append(
            {'source': 'issuance_api_key', 'target': '/run/secrets/issuance_api_key'})
        new_path = root/'repaired.compose.json';new_path.write_bytes(selection.packed(after))
        services = {'applicant', 'gateway'}
        owned = [{'Id': 'a'*64, 'Name': 'applicant'}, {'Id': 'b'*64, 'Name': 'gateway'}]
        calls = [];proofs = []
        class Docker:
            prefix = ['PUBLIC_DOCKER']
            def compose(self, project, env, model):return [*self.prefix, str(model)]
            def json(self, args):return after
            def hashes(self, command):
                return {'applicant': 'new' if command[-1] == str(new_path) else 'old', 'gateway': 'same'}
            def containers(self):return owned
        docker = Docker()
        def inspect(config, *_a, **_kw):
            return {'docker': docker, 'model': before, 'services': services, 'baseline': owned,
                    'owned': owned, 'command': docker.compose(cfg['project'], None, old_path)}
        def prove(config, *_a, **_kw):
            proofs.append(config['compose_file'])
            return phase['data']
        def recreate(_docker, command, changing, roles, model, log, progress):
            assert changing == {'applicant'} and roles == services
            selected = command[-1];calls.append(selected)
            progress('started', 0, ['applicant'])
            renewal.write_empty_private_file(log, 'PUBLIC_SYNTHETIC')
            if selected == str(new_path) and failure == 'uncertain':
                raise renewal.UncertainComposeMutation('PUBLIC_SYNTHETIC_UNCERTAIN')
            if selected == str(new_path) and failure == 'known':raise RuntimeError('PUBLIC_SYNTHETIC_KNOWN')
            progress('completed', 0, ['applicant'])
        monkeypatch.setattr(selection, '_inspect', inspect)
        monkeypatch.setattr(selection, '_prove', prove)
        monkeypatch.setattr(renewal, 'owned_roles', lambda *_: {'applicant'})
        monkeypatch.setattr(renewal, 'observations', lambda *_: {'PUBLIC_UNCHANGED': True})
        monkeypatch.setattr(renewal, '_service', lambda item: item['Name'])
        monkeypatch.setattr(renewal, 'recreate', recreate)
        monkeypatch.setattr(native, 'reauthenticate', lambda _n, _p, _d, session: session+'/token')
        yield root, path, cfg, old_path, new_path, calls, proofs


def test_repair_selects_new_model_without_rewriting_generation_or_owner(monkeypatch):
    with runtime(monkeypatch) as (_root, path, cfg, old, new, calls, proofs):
        journal = selection.directory(cfg)
        original = {p.name: p.read_bytes() for p in journal.iterdir()}
        result = repair.repair_once(path, new)
        assert result['result'] == 'model-repaired' and calls == [str(new)]
        assert proofs == [str(old), str(new)]
        assert all((journal/name).read_bytes() == body for name, body in original.items())
        assert not renewal.model_repair_guard(cfg).exists()
        with selection.selected_inputs(path) as lease:
            assert lease.sequence == 1 and lease.compose_file == new
        assert len(list(journal.iterdir())) == len(original)+2


def test_known_failure_rolls_back_only_applicant_and_preserves_decision(monkeypatch):
    with runtime(monkeypatch, failure='known') as (_r, path, cfg, old, new, calls, _proofs):
        with pytest.raises(RuntimeError, match='rolled back'):repair.repair_once(path, new)
        assert calls == [str(new), str(old)]
        assert not renewal.model_repair_guard(cfg).exists()
        with selection.selected_inputs(path) as lease:assert lease.compose_file == old


def test_uncertain_mutation_never_rolls_back_or_admits_another_operation(monkeypatch):
    with runtime(monkeypatch, failure='uncertain') as (_r, path, cfg, _old, new, calls, _p):
        with pytest.raises(renewal.UncertainComposeMutation):repair.repair_once(path, new)
        assert calls == [str(new)] and renewal.model_repair_guard(cfg).exists()
        assert not (selection.directory(cfg)/'000001.model-selection.json').exists()
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):pytest.fail('Interrupted repair admitted')


def test_mutation_cannot_be_reused_within_or_after_lease(monkeypatch):
    with runtime(monkeypatch) as (root, path, _cfg, _old, new, _c, _p):
        with selection.selected_inputs(path) as lease:
            output = root/('windows-model-'+'1'*32);output.mkdir()
            lease.repair_model(new, output)
            with pytest.raises(ValueError):lease.check_current()
            with pytest.raises(ValueError):lease.stage_renewal(root, 'PUBLIC_SYNTHETIC')
            with pytest.raises(ValueError):lease.repair_model(new, output)
        with pytest.raises(ValueError):lease.repair_model(new, output)


def test_original_records_remain_held_after_publication_lock_exit(monkeypatch):
    with runtime(monkeypatch) as (_root, path, cfg, _old, new, _c, _p):
        original_session = selection._session
        protected = []
        @contextmanager
        def session(*args, **kwargs):
            with original_session(*args, **kwargs) as value:yield value
            if kwargs.get('_pending_model_sha256'):
                for name in ('owner.json', '000001.selection.json', '000001.model-intent.json'):
                    with pytest.raises(OSError):
                        (selection.directory(cfg)/name).write_bytes(b'PUBLIC_TAMPER')
                    protected.append(name)
                with pytest.raises(OSError):renewal.model_repair_guard(cfg).write_bytes(b'PUBLIC_TAMPER')
        monkeypatch.setattr(selection, '_session', session)
        assert repair.repair_once(path, new)['result'] == 'model-repaired'
        assert len(protected) == 3


@pytest.mark.parametrize('late', ['lock', 'receipt', 'directory'])
def test_every_late_publication_exit_failure_retains_guard(monkeypatch, late):
    import selfhost_windows_inputs as inputs
    with runtime(monkeypatch) as (_root, path, cfg, _old, new, _c, _p):
        original_session = selection._session
        state = {'lock_exited': False, 'injected': False}
        @contextmanager
        def session(*args, **kwargs):
            with original_session(*args, **kwargs) as value:yield value
            if kwargs.get('_pending_model_sha256'):
                state['lock_exited'] = True
                if late == 'lock':
                    state['injected'] = True
                    raise RuntimeError('PUBLIC_LATE_LOCK')
        monkeypatch.setattr(selection, '_session', session)
        if late == 'receipt':
            original_hold = renewal.hold_private_input
            @contextmanager
            def hold(file, *args, **kwargs):
                with original_hold(file, *args, **kwargs) as value:yield value
                if state['lock_exited'] and Path(file).name == 'intent.json' and not state['injected']:
                    state['injected'] = True
                    raise RuntimeError('PUBLIC_LATE_RECEIPT')
            monkeypatch.setattr(renewal, 'hold_private_input', hold)
        if late == 'directory':
            original_directory = inputs._held_private_input
            @contextmanager
            def directory(file, *args, **kwargs):
                with original_directory(file, *args, **kwargs) as value:yield value
                if state['lock_exited'] and kwargs.get('directory') and Path(file).name.startswith('windows-model-'):
                    state['injected'] = True
                    raise RuntimeError('PUBLIC_LATE_DIRECTORY')
            monkeypatch.setattr(inputs, '_held_private_input', directory)
        with pytest.raises(RuntimeError, match='PUBLIC_LATE_'):repair.repair_once(path, new)
        assert state['injected'] and renewal.model_repair_guard(cfg).exists()
        assert (selection.directory(cfg)/'000001.model-selection.json').exists()
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):pytest.fail('Provisional decision admitted')
