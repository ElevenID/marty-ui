"""Actual NTFS journal integrity and interrupted-selection controls.

Runtime custody is substituted in journal tests; the native proof has its own
transport and snapshot controls. No Docker or application data is used here.
"""
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import selfhost_windows_selection as selection
from test_selfhost_windows_inputs import private_fixture
from test_selfhost_windows_renewal import PROJECT, model


@contextmanager
def fixture(monkeypatch, *, initial_current=False):
    if os.name != 'nt':pytest.skip('Actual private NTFS selection journal')
    with private_fixture() as (root, _):
        model_file = root/'compose.json'
        first = root/'generation0';first.mkdir()
        m = model(first);names = sorted(m['secrets'])
        model_file.write_text(json.dumps(m), encoding='utf-8')
        phase = {'active': None, 'data': 'd'*64, 'both': False}
        configs = []
        def generation(number):
            p = root/('generation'+str(number));p.mkdir(exist_ok=True)
            for name in names:
                generation_number = 0 if initial_current and number == 1 else number
                value = b'' if name == 'smtp_password' else ('PUBLIC_SYNTHETIC_'+str(generation_number)+'_'+name).encode()
                (p/name).write_bytes(value)
            env = root/('generation'+str(number)+'.env')
            env.write_text('SELFHOST_SECRET_DIR='+str(p)+'\nFIXED_SETTING=synthetic\n', encoding='utf-8')
            return p, env
        def transaction(number):
            prior = 0 if initial_current and number == 2 else number-1
            old, oldenv = generation(prior) if number == 1 else (root/('generation'+str(prior)), root/('generation'+str(prior)+'.env'))
            new, newenv = generation(number)
            outputs = root/('tx'+str(number));outputs.mkdir()
            cfg = {'schema': selection.renewal.SCHEMA, 'candidate_only': True, 'project': PROJECT,
                   'docker_host': 'npipe:////./pipe/dockerDesktopLinuxEngine', 'engine_id': 'PUBLIC_SYNTHETIC_ENGINE',
                   'compose_file': str(model_file), 'compose_sha256': selection.digest(model_file.read_bytes()),
                   'current_env': str(oldenv), 'renewed_env': str(newenv),
                   'current_secrets': str(old), 'renewed_secrets': str(new),
                   'native': {'binary': 'PUBLIC_BINARY', 'binary_sha256': '1'*64, 'source_sha': '1'*40,
                    'release_tag': 'v1.2.3', 'helper_image': 'python@sha256:'+'2'*64,
                    'control_volume': PROJECT+'-renewal-control', 'network': PROJECT+'_default',
                    'bao_addr': 'https://openbao:8200', 'ca_file': 'PUBLIC_CA', 'minimum_ttl': 3600,
                    'current': '/control/generation'+str(prior), 'renewed': '/control/generation'+str(number),
                    'token_file': '/control/session/token'}}
            if initial_current:cfg['initial_current'] = True
            for key in ['intent', 'result', 'new_log', 'rollback_log']:
                p = outputs/key;p.write_bytes(b'');cfg[key] = str(p)
            cfg['step_receipts'] = [{}]
            for key in ['new_started', 'new_completed', 'rollback_started', 'rollback_completed']:
                p = outputs/key;p.write_bytes(b'');cfg['step_receipts'][0][key] = str(p)
            path = outputs/'config.json';path.write_text(json.dumps(cfg), encoding='utf-8')
            configs.append((path, cfg));return path, cfg
        def outcome(cfg, result):
            Path(cfg['result']).write_text(json.dumps({'schema': selection.renewal.SCHEMA,
                'project': PROJECT, 'candidate_only': True, 'production_admission': False,
                'automatic_lifecycle': False, 'result': result}), encoding='utf-8')
        def prove(cfg, choice, _values, _stack, *, expected_data=None, authority_file=None):
            prefix = 'renewed' if choice == 'new' else 'current'
            selection.require(phase['both'] or Path(cfg[prefix+'_secrets']) == phase['active'])
            if expected_data is not None:selection.require(expected_data == phase['data'])
            return phase['data']
        monkeypatch.setattr(selection, '_prove', prove)
        (root/f'.{PROJECT}.renewal.lock').write_bytes(b'')
        path, cfg = transaction(1)
        phase['active'] = Path(cfg['current_secrets'] if initial_current else cfg['renewed_secrets'])
        if not initial_current:
            outcome(cfg, 'activated')
            Path(cfg['intent']).write_bytes(b'PUBLIC_SYNTHETIC_ORIGINAL_INTENT')
        yield root, phase, transaction, outcome, path, cfg


def test_initial_current_adoption_uses_real_current_proof_without_transition(monkeypatch):
    with fixture(monkeypatch, initial_current=True) as (_root, _phase, _tx, _outcome, path, cfg):
        with pytest.raises(ValueError):selection.adopt(path)
        record = selection.adopt_current(path)
        assert record['choice'] == 'old' and record['decision'] == 'adopted-current'
        assert record['result_sha256'] == selection.digest(b'')
        assert record['transition_intent_sha256'] == selection.digest(b'')
        assert selection.status(path)['state'] == 'selected'
        with selection.selected_inputs(path) as lease:
            assert lease.secrets_dir == Path(cfg['current_secrets'])
            assert lease.check_current() == 'd'*64
        with pytest.raises(ValueError):selection.adopt_current(path)


def test_initial_current_pending_intent_completes_only_after_reproof(monkeypatch):
    with fixture(monkeypatch, initial_current=True) as (root, _phase, _tx, _outcome, path, cfg):
        original = selection._append
        def interrupt(directory, raw, name, value, stack):
            if name == '000001.selection.json':raise RuntimeError('synthetic interrupted write')
            return original(directory, raw, name, value, stack)
        monkeypatch.setattr(selection, '_append', interrupt)
        with pytest.raises(RuntimeError):selection.adopt_current(path)
        monkeypatch.setattr(selection, '_append', original)
        assert selection.status(path)['state'] == 'pending-reconciliation'
        record = selection.complete(path)
        assert record['decision'] == 'adopted-current' and record['choice'] == 'old'
        assert sorted(p.name for p in selection.directory(cfg).iterdir()) == [
            '000001.intent.json','000001.selection.json','owner.json']


def test_initial_current_can_select_first_real_replacement(monkeypatch):
    with fixture(monkeypatch, initial_current=True) as (_root, phase, tx, outcome, path, _cfg):
        selection.adopt_current(path)
        next_path, next_cfg = tx(2)
        assert selection.prepare(next_path) == 2
        phase['active'] = Path(next_cfg['renewed_secrets'])
        outcome(next_cfg, 'activated')
        record = selection.complete(next_path)
        assert record['decision'] == 'activated' and record['choice'] == 'new'
        assert selection.status(path)['state'] == 'selected'
        with selection.selected_inputs(next_path) as lease:
            assert lease.secrets_dir == Path(next_cfg['renewed_secrets'])


def test_adopt_and_status_select_the_verified_new_inputs_with_empty_optionals(monkeypatch):
    with fixture(monkeypatch) as (root, _phase, _tx, _outcome, path, cfg):
        record = selection.adopt(path)
        assert record['choice'] == 'new' and record['decision'] == 'adopted'
        status = selection.status(path)
        assert status['state'] == 'selected' and status['selected']['secrets_dir'] == cfg['renewed_secrets']
        assert sorted(p.name for p in selection.directory(cfg).iterdir()) == ['000001.intent.json', '000001.selection.json', 'owner.json']
        with pytest.raises(ValueError):selection.adopt(path)


@pytest.mark.parametrize('outcome_name', ['activated', 'rolled_back'])
def test_registered_activation_commit_or_rollback_advances_chain_without_replay(monkeypatch, outcome_name):
    with fixture(monkeypatch) as (_root, phase, tx, outcome, path, cfg):
        selection.adopt(path);next_path, next_cfg = tx(2)
        assert selection.prepare(next_path) == 2
        assert selection.status(path) == {'state': 'pending-reconciliation', 'sequence': 2}
        with pytest.raises(ValueError):selection.prepare(next_path)
        phase['active'] = Path(next_cfg['renewed_secrets' if outcome_name == 'activated' else 'current_secrets'])
        outcome(next_cfg, outcome_name)
        record = selection.complete(next_path)
        assert record['decision'] == outcome_name and record['choice'] == ('new' if outcome_name == 'activated' else 'old')
        assert selection.status(path)['sequence'] == 2
        with pytest.raises(ValueError):selection.complete(next_path)


def terminal_receipts(cfg, phase):
    intent = {k: cfg[k] for k in ['current_env', 'renewed_env', 'current_secrets', 'renewed_secrets', 'compose_sha256', 'project', 'step_receipts']}
    intent.update(schema=selection.renewal.SCHEMA, layers=[['gateway']], changing=['gateway'])
    Path(cfg['intent']).write_text(json.dumps(intent))
    for event in ['started', 'completed']:
        Path(cfg['step_receipts'][0][phase+'_'+event]).write_text(json.dumps({'roles': ['gateway'], 'event': event, 'time': 1.0}))


@pytest.mark.parametrize('active', ['old', 'new', 'neither', 'incomplete'])
def test_interrupted_result_reconciliation_proves_one_current_generation_and_never_mutates(monkeypatch, active):
    with fixture(monkeypatch) as (_root, phase, tx, _outcome, path, _cfg):
        selection.adopt(path);next_path, cfg = tx(2);selection.prepare(next_path)
        phase['active'] = Path(cfg[('current' if active == 'old' else 'renewed')+'_secrets']) if active in {'old', 'new'} else None
        if active in {'new', 'neither', 'incomplete'}:terminal_receipts(cfg, 'new')
        if active == 'incomplete':Path(cfg['step_receipts'][0]['new_completed']).write_bytes(b'')
        with pytest.raises(ValueError):selection.complete(next_path)
        if active in {'old', 'new'}:
            record = selection.complete(next_path, reconcile=True)
            assert record['decision'] == 'reconciled-'+active and record['result_sha256'] is None
            assert Path(cfg['result']).read_bytes() == b''
        else:
            with pytest.raises(ValueError):selection.complete(next_path, reconcile=True)
            assert selection.status(path)['state'] == 'pending-reconciliation'


def test_unfinished_rollback_cannot_select_healthy_new_generation(monkeypatch):
    with fixture(monkeypatch) as (_root, phase, tx, _outcome, path, _cfg):
        selection.adopt(path);next_path, cfg = tx(2);selection.prepare(next_path)
        terminal_receipts(cfg, 'new')
        Path(cfg['step_receipts'][0]['rollback_started']).write_text(json.dumps({'roles': ['gateway'], 'event': 'started', 'time': 2.0}))
        phase['active'] = Path(cfg['renewed_secrets'])
        with pytest.raises(ValueError):selection.complete(next_path, reconcile=True)
        assert selection.status(path)['state'] == 'pending-reconciliation'


def test_complete_rollback_receipts_allow_current_old_selection_without_result_rewrite(monkeypatch):
    with fixture(monkeypatch) as (_root, _phase, tx, _outcome, path, _cfg):
        selection.adopt(path);next_path, cfg = tx(2);selection.prepare(next_path)
        terminal_receipts(cfg, 'new');terminal_receipts(cfg, 'rollback')
        assert selection.complete(next_path, reconcile=True)['decision'] == 'reconciled-old'
        assert Path(cfg['result']).read_bytes() == b''


@pytest.mark.parametrize('bad', ['model', 'current-bytes', 'old-env', 'data', 'engine'])
def test_drift_refuses_before_new_intent(monkeypatch, bad):
    with fixture(monkeypatch) as (_root, phase, tx, _outcome, path, initial):
        selection.adopt(path);next_path, cfg = tx(2)
        if bad == 'model':Path(cfg['compose_file']).write_bytes(b'{}')
        elif bad == 'current-bytes':next(Path(cfg['current_secrets']).iterdir()).write_bytes(b'PUBLIC_TAMPER')
        elif bad == 'old-env':Path(cfg['current_env']).write_text('SELFHOST_SECRET_DIR='+cfg['current_secrets']+'\nOTHER=changed\n')
        elif bad == 'data':phase['data'] = 'e'*64
        else:
            cfg['engine_id'] = 'OTHER_ENGINE';next_path.write_text(json.dumps(cfg))
        with pytest.raises(ValueError):selection.prepare(next_path)
        assert not (selection.directory(initial)/'000002.intent.json').exists()


@pytest.mark.parametrize('bad', ['empty', 'partial', 'chain', 'unknown'])
def test_malformed_or_extra_journal_entries_never_fall_back_to_old_selection(monkeypatch, bad):
    with fixture(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        selection.adopt(path);root = selection.directory(cfg)
        if bad in {'empty', 'partial'}:(root/'000002.intent.json').write_bytes(b'' if bad == 'empty' else b'{')
        elif bad == 'unknown':(root/'unknown.json').write_bytes(b'{}')
        else:
            p = root/'000001.selection.json';record = json.loads(p.read_bytes());record['parent'] = '0'*64;p.write_bytes(selection.packed(record))
        with pytest.raises(ValueError):selection.status(path)


def test_activation_admission_pins_registered_inputs_and_holds_records(monkeypatch):
    with fixture(monkeypatch) as (_root, _phase, tx, _outcome, path, cfg):
        selection.adopt(path);next_path, pending = tx(2);selection.prepare(next_path)
        roots = [Path(pending[k]) for k in ['current_secrets', 'renewed_secrets']]
        maps = [{p.name: p.read_bytes() for p in root.iterdir()} for root in roots]
        envs = [Path(pending[k]).read_bytes() for k in ['current_env', 'renewed_env']]
        with selection.activation_admission(pending, *maps, *envs):
            with pytest.raises(OSError):(selection.directory(cfg)/'000002.intent.json').write_bytes(b'CONCURRENT_TAMPER')
        maps[1][next(iter(maps[1]))] = b'PUBLIC_TAMPER'
        with pytest.raises(ValueError):
            with selection.activation_admission(pending, *maps, *envs):pytest.fail('Altered inputs admitted')


def test_existing_selection_blocks_unregistered_activation(monkeypatch):
    with fixture(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        selection.adopt(path)
        with pytest.raises(ValueError):
            with selection.activation_admission(cfg, {}, {}, b'', b''):pytest.fail('Unregistered activation admitted')


def test_selected_input_lease_holds_inputs_without_exposing_secret_bytes(monkeypatch):
    with fixture(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        selection.adopt(path)
        with selection.selected_inputs(path) as current:
            assert current.env_file == Path(cfg['renewed_env']) and current.sequence == 1
            sample = next(p.read_text() for p in Path(cfg['renewed_secrets']).iterdir() if p.name != 'smtp_password')
            assert sample not in repr(current)
            assert current.check_current() == 'd'*64
            for target in [path, Path(cfg['renewed_env']), next(Path(cfg['renewed_secrets']).iterdir())]:
                with pytest.raises(OSError):target.write_bytes(b'PUBLIC_TAMPER')
            with pytest.raises(ValueError):
                with selection.selected_inputs(path):pytest.fail('Concurrent lease acquired')
        with pytest.raises(ValueError):current.check_current()


def test_pending_transaction_cannot_yield_recovery_inputs(monkeypatch):
    with fixture(monkeypatch) as (_root, _phase, tx, _outcome, path, _cfg):
        selection.adopt(path);next_path, _ = tx(2);selection.prepare(next_path)
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):pytest.fail('Stale inputs returned during pending transaction')


def test_changed_original_intent_refuses_recovery_lease(monkeypatch):
    with fixture(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        selection.adopt(path);Path(cfg['intent']).write_bytes(b'PUBLIC_CHANGED_INTENT')
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):pytest.fail('Changed original transaction admitted')


@pytest.mark.parametrize('stop_after', ['owner.json', '000001.intent.json'])
def test_interrupted_initial_adoption_resumes_only_after_fresh_proof(monkeypatch, stop_after):
    with fixture(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        actual = selection._append
        def interrupted(root, raw, name, value, stack):
            actual(root, raw, name, value, stack)
            if name == stop_after:raise RuntimeError('PUBLIC_SYNTHETIC_INTERRUPTION')
        monkeypatch.setattr(selection, '_append', interrupted)
        with pytest.raises(RuntimeError):selection.adopt(path)
        monkeypatch.setattr(selection, '_append', actual)
        record = selection.adopt(path) if stop_after == 'owner.json' else selection.complete(path)
        assert record['decision'] == 'adopted' and selection.status(path)['state'] == 'selected'


def test_completed_pending_intent_after_writer_refusal_cannot_be_prepared_again(monkeypatch):
    with fixture(monkeypatch) as (_root, _phase, tx, _outcome, path, _cfg):
        selection.adopt(path);next_path, _ = tx(2);actual = selection.renewal.write_empty_private_file
        def refused(target, value):
            actual(target, value)
            if target.name == '000002.intent.json':raise ValueError('PUBLIC_SYNTHETIC_POSTWRITE_REFUSAL')
        monkeypatch.setattr(selection.renewal, 'write_empty_private_file', refused)
        with pytest.raises(ValueError):selection.prepare(next_path)
        monkeypatch.setattr(selection.renewal, 'write_empty_private_file', actual)
        assert selection.status(path)['state'] == 'pending-reconciliation'
        with pytest.raises(ValueError):selection.prepare(next_path)
        assert selection.complete(next_path, reconcile=True)['decision'] == 'reconciled-old'


def test_session_rechecks_membership_even_when_caller_raises(monkeypatch):
    with fixture(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        selection.adopt(path)
        with pytest.raises(ValueError):
            with selection._session(path):
                (selection.directory(cfg)/'PUBLIC_UNEXPECTED').write_bytes(b'PUBLIC_EVIDENCE')
                raise RuntimeError('PUBLIC_SYNTHETIC_CALLER_FAILURE')
        assert (selection.directory(cfg)/'PUBLIC_UNEXPECTED').read_bytes() == b'PUBLIC_EVIDENCE'


@pytest.mark.parametrize('marker', ['new_started', 'rollback_completed', 'new_log', 'rollback_log'])
def test_empty_activation_intent_with_command_evidence_never_selects_old(monkeypatch, marker):
    with fixture(monkeypatch) as (_root, _phase, tx, _outcome, path, _cfg):
        selection.adopt(path);next_path, cfg = tx(2);selection.prepare(next_path)
        target = cfg[marker] if marker in {'new_log', 'rollback_log'} else cfg['step_receipts'][0][marker]
        Path(target).write_bytes(b'PUBLIC_INCONSISTENT_COMMAND_EVIDENCE')
        with pytest.raises(ValueError):selection.complete(next_path, reconcile=True)
        assert selection.status(path)['state'] == 'pending-reconciliation'


@pytest.mark.parametrize('raw', [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'{"x":1e999}'])
def test_strict_decoder_refuses_duplicate_or_nonfinite_values(raw):
    with pytest.raises(ValueError):selection.decode(raw)


def test_repeated_proof_callbacks_close_transient_holds_before_return(monkeypatch):
    with fixture(monkeypatch) as (_root, _phase, _tx, _outcome, path, _cfg):
        selection.adopt(path);events = []
        @contextmanager
        def transient():
            events.append('open')
            try:yield
            finally:events.append('close')
        def prove(_cfg, _choice, _values, proof_stack, **_kwargs):
            proof_stack.enter_context(transient());return 'd'*64
        monkeypatch.setattr(selection, '_prove', prove)
        with selection.selected_inputs(path) as current:
            for _ in range(3):
                assert current.check_current() == 'd'*64
                assert events[-2:] == ['open', 'close']
        assert events == ['open', 'close']*3


def test_adopted_decision_is_invalid_after_initial_sequence(monkeypatch):
    with fixture(monkeypatch) as (_root, phase, tx, outcome, path, cfg):
        selection.adopt(path);next_path, pending = tx(2);selection.prepare(next_path)
        phase['active'] = Path(pending['renewed_secrets']);outcome(pending, 'activated')
        selection.complete(next_path)
        target = selection.directory(cfg)/'000002.selection.json'
        record = json.loads(target.read_bytes());record['decision'] = 'adopted';target.write_bytes(selection.packed(record))
        with pytest.raises(ValueError):selection.status(path)
