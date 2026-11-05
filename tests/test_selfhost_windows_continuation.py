"""Real private NTFS continuation controls, with no Docker/native mutation."""
from contextlib import contextmanager
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import selfhost_windows_continuation as continuation
import selfhost_windows_selection as selection
import selfhost_windows_renewal as renewal
from test_selfhost_windows_selection import fixture


@contextmanager
def candidate(monkeypatch):
    with fixture(monkeypatch) as data:
        root, _phase, _tx, _outcome, path, _cfg = data
        selection.adopt(path)
        class Docker:
            def containers(self):return []
        def inspect(_cfg, _choice, _values, _stack, *, expected_data, require_ready):
            assert expected_data == 'd'*64 and require_ready is False
            return {'docker': Docker(), 'baseline': []}
        monkeypatch.setattr(selection, '_inspect', inspect)
        def forbidden(*_a, **_kw):raise AssertionError('Continuation must not invoke any child mutation')
        monkeypatch.setattr(renewal, 'run_owned_mutation', forbidden)
        yield data


def advance(monkeypatch, path):
    with selection.selected_inputs(path) as lease:
        prior = lease.journal_path
        result = lease.continue_journal()
        with pytest.raises(ValueError):lease.check_current()
        with pytest.raises(ValueError):lease.continue_journal()
    return prior, Path(result['journal']), result


def test_continuation_retains_original_records_and_selected_input_identity(monkeypatch):
    with candidate(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        original = {p.name: p.read_bytes() for p in selection.directory(cfg).iterdir()}
        with selection.selected_inputs(path) as lease:
            identity = (lease.env_file, lease.secrets_dir, lease.selected_sha256, lease.generation_sequence)
        old, new, result = advance(monkeypatch, path)
        assert result['result'] == 'journal-continued' and result['generation_sequence'] == 1
        assert not result['native_admission'] and not result['automatic_lifecycle']
        assert all((old/name).read_bytes() == value for name, value in original.items())
        assert {p.name for p in new.iterdir()} == {'owner.json', 'checkpoint.json', '000001.intent.json', '000001.selection.json'}
        assert not renewal.continuation_guard(cfg).exists()
        with selection.selected_inputs(path) as lease:
            assert lease.journal_path == new and lease.sequence == 1
            assert (lease.env_file, lease.secrets_dir, lease.selected_sha256, lease.generation_sequence) == identity
            lease.check_current()


def test_activation_after_continuation_uses_active_segment_and_keeps_global_sequence(monkeypatch):
    with candidate(monkeypatch) as (_root, phase, tx, outcome, path, cfg):
        old, new, _result = advance(monkeypatch, path)
        next_path, next_cfg = tx(2)
        assert selection.prepare(next_path) == 2
        assert not (old/'000002.intent.json').exists() and (new/'000002.intent.json').exists()
        old_dir, new_dir = [Path(next_cfg[k]) for k in ('current_secrets', 'renewed_secrets')]
        with selection.activation_admission(next_cfg,
            {p.name:p.read_bytes() for p in old_dir.iterdir()}, {p.name:p.read_bytes() for p in new_dir.iterdir()},
            Path(next_cfg['current_env']).read_bytes(), Path(next_cfg['renewed_env']).read_bytes()):pass
        phase['active'] = new_dir;outcome(next_cfg, 'activated');selection.complete(next_path)
        _previous, newest, result = advance(monkeypatch, path)
        assert result['generation_sequence'] == 2
        with selection.selected_inputs(path) as lease:
            assert lease.journal_path == newest and lease.sequence == 1 and lease.generation_sequence == 2
            assert lease.secrets_dir == new_dir
        assert selection.status(path)['generation_sequence'] == 2


@pytest.mark.parametrize('decision', ['rolled_back', 'reconciled-old'])
def test_old_selection_can_continue_without_fabricating_new_activation(monkeypatch, decision):
    with candidate(monkeypatch) as (_root, phase, tx, outcome, path, _cfg):
        next_path, cfg = tx(2);selection.prepare(next_path)
        phase['active'] = Path(cfg['current_secrets'])
        if decision == 'rolled_back':outcome(cfg, 'rolled_back')
        selection.complete(next_path, reconcile=decision == 'reconciled-old')
        _old, _new, result = advance(monkeypatch, path)
        with selection.selected_inputs(path) as lease:
            assert lease.secrets_dir == phase['active'] and lease.generation_sequence == 2
            lease.check_current()
        assert result['previous_sequence'] == 2


@pytest.mark.parametrize('bad', ['old-record', 'old-extra', 'missing-target', 'target-record',
                               'target-owner', 'checkpoint', 'link', 'decision'])
def test_any_retained_history_or_link_corruption_never_falls_back(monkeypatch, bad):
    with candidate(monkeypatch) as (_root, _phase, _tx, _outcome, path, _cfg):
        old, new, _result = advance(monkeypatch, path)
        target = {'old-record':old/'000001.selection.json', 'old-extra':old/'unknown.json',
                  'target-record':new/'000001.selection.json', 'target-owner':new/'owner.json',
                  'checkpoint':new/'checkpoint.json', 'link':old/continuation.INTENT,
                  'decision':old/continuation.DECISION}.get(bad)
        if bad == 'missing-target':(new/'000001.selection.json').unlink()
        else:target.write_bytes(b'PUBLIC_SYNTHETIC_CORRUPTION')
        with pytest.raises((ValueError, OSError)):
            with selection.selected_inputs(path):pytest.fail('Corrupt continuation admitted')


def test_caller_failure_retains_guard_and_can_be_reconciled_without_replay(monkeypatch):
    with candidate(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        with pytest.raises(RuntimeError):
            with selection.selected_inputs(path) as lease:
                lease.continue_journal()
                raise RuntimeError('PUBLIC_SYNTHETIC_CALLER_FAILURE')
        assert renewal.continuation_guard(cfg).exists()
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):pytest.fail('Pending continuation admitted')
        result = continuation.reconcile(path)
        assert result['result'] == 'journal-continued' and not renewal.continuation_guard(cfg).exists()
        with selection.selected_inputs(path) as lease:assert lease.sequence == 1


def test_late_publication_failure_retains_guard_and_can_reconcile_existing_decision(monkeypatch):
    with candidate(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        original = selection._session
        @contextmanager
        def session(*args, **kwargs):
            with original(*args, **kwargs) as value:yield value
            if kwargs.get('_pending_continuation_sha256'):raise RuntimeError('PUBLIC_LATE_EXIT')
        monkeypatch.setattr(selection, '_session', session)
        with pytest.raises(RuntimeError):advance(monkeypatch, path)
        assert renewal.continuation_guard(cfg).exists()
        assert (selection.directory(cfg)/continuation.DECISION).exists()
        monkeypatch.setattr(selection, '_session', original)
        continuation.reconcile(path)
        assert not renewal.continuation_guard(cfg).exists()


def test_predecessor_and_guard_remain_held_after_publication_lock_exit(monkeypatch):
    with candidate(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        original = selection._session;blocked = []
        @contextmanager
        def session(*args, **kwargs):
            with original(*args, **kwargs) as value:yield value
            if kwargs.get('_pending_continuation_sha256'):
                for file in (selection.directory(cfg)/'owner.json', renewal.continuation_guard(cfg)):
                    with pytest.raises(OSError):file.write_bytes(b'PUBLIC_TAMPER')
                    blocked.append(file)
        monkeypatch.setattr(selection, '_session', session)
        advance(monkeypatch, path)
        assert len(blocked) == 2


def test_deep_ancestor_remains_held_across_later_publication(monkeypatch):
    with candidate(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        ancestor, _new, _result = advance(monkeypatch, path)
        original = selection._session;blocked=[]
        @contextmanager
        def session(*args, **kwargs):
            with original(*args, **kwargs) as value:yield value
            if kwargs.get('_pending_continuation_sha256'):
                with pytest.raises(OSError):(ancestor/'owner.json').write_bytes(b'PUBLIC_TAMPER')
                blocked.append(True)
        monkeypatch.setattr(selection, '_session', session)
        advance(monkeypatch, path)
        assert blocked == [True] and not renewal.continuation_guard(cfg).exists()


def test_new_child_in_sealed_ancestor_refuses_ordinary_lease_exit(monkeypatch):
    with candidate(monkeypatch) as (_root, _phase, _tx, _outcome, path, _cfg):
        ancestor, _new, _result=advance(monkeypatch,path)
        with pytest.raises((ValueError,OSError)):
            with selection.selected_inputs(path):
                (ancestor/'unknown.json').write_bytes(b'PUBLIC_PRESERVED_UNKNOWN')
        assert (ancestor/'unknown.json').read_bytes()==b'PUBLIC_PRESERVED_UNKNOWN'


@pytest.mark.parametrize('repair_first', [False, True])
def test_model_repair_and_continuation_compose_in_both_orders(monkeypatch, repair_first):
    from test_selfhost_windows_model import runtime
    import selfhost_windows_model as model
    with runtime(monkeypatch) as (_root, path, _cfg, _old_model, new_model, _calls, _proofs):
        if repair_first:model.repair_once(path, new_model)
        advance(monkeypatch, path)
        if not repair_first:model.repair_once(path, new_model)
        advance(monkeypatch, path)
        with selection.selected_inputs(path) as lease:
            assert lease.compose_file == new_model and lease.generation_sequence == 1


def test_crash_between_journal_intent_and_guard_has_explicit_metadata_reconciliation(monkeypatch):
    with candidate(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        original=selection._new_private
        def fail(file,body):
            if file==renewal.continuation_guard(cfg):raise RuntimeError('PUBLIC_GUARD_CREATION_FAILURE')
            return original(file,body)
        monkeypatch.setattr(selection,'_new_private',fail)
        with pytest.raises(RuntimeError):advance(monkeypatch,path)
        assert not renewal.continuation_guard(cfg).exists()
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):pytest.fail('Dangling intent admitted')
        monkeypatch.setattr(selection,'_new_private',original)
        assert continuation.reconcile(path)['result']=='journal-continued'


@pytest.mark.parametrize('partial',['missing-target','empty-file','corrupt-file','unknown-file'])
def test_reconciliation_only_completes_derived_missing_or_empty_seed_files(monkeypatch,partial):
    with candidate(monkeypatch) as (_root, _phase, _tx, _outcome, path, cfg):
        if partial=='missing-target':
            original=Path.mkdir
            def fail(file,*args,**kwargs):
                if '.generation-epoch-' in file.name:raise RuntimeError('PUBLIC_TARGET_CREATION_FAILURE')
                return original(file,*args,**kwargs)
            monkeypatch.setattr(Path,'mkdir',fail)
            with pytest.raises(RuntimeError):advance(monkeypatch,path)
            monkeypatch.setattr(Path,'mkdir',original)
        else:
            with pytest.raises(RuntimeError):
                with selection.selected_inputs(path) as lease:
                    result=lease.continue_journal()
                    raise RuntimeError('PUBLIC_SYNTHETIC_CALLER_FAILURE')
            target=Path(result['journal'])
            if partial=='unknown-file':(target/'unknown').write_bytes(b'PUBLIC_UNKNOWN')
            else:(target/'owner.json').write_bytes(b'' if partial=='empty-file' else b'PUBLIC_CORRUPTION')
        if partial in {'corrupt-file','unknown-file'}:
            with pytest.raises(ValueError):continuation.reconcile(path)
            assert renewal.continuation_guard(cfg).exists()
        else:
            continuation.reconcile(path)
            assert not renewal.continuation_guard(cfg).exists()


@pytest.mark.parametrize('terminal',[False,True])
@pytest.mark.parametrize('tamper',['content','child'])
def test_recovery_publication_retains_full_history_through_lock_exit(monkeypatch,terminal,tamper):
    from test_selfhost_windows_recovery import candidate as runtime
    with runtime(monkeypatch,warm=True) as (_root,path,cfg,output,_events,_items,_observed,_tx):
        ancestor,_new,_result=advance(monkeypatch,path)
        if terminal:
            with pytest.raises(RuntimeError):
                with selection.selected_inputs(path) as lease:
                    lease.recover_existing(output)
                    raise RuntimeError('PUBLIC_CALLER_FAILURE')
        original=renewal.hold_private_input;injected=[]
        @contextmanager
        def hold(file,*args,**kwargs):
            with original(file,*args,**kwargs) as value:yield value
            decision=output/('reconciliation.json' if terminal else 'result.json')
            if kwargs.get('exclusive') and decision.exists() and decision.stat().st_size and not injected:
                injected.append(True)
                if tamper=='content':
                    with pytest.raises(OSError):(ancestor/'owner.json').write_bytes(b'PUBLIC_TAMPER')
                else:(ancestor/'unknown.json').write_bytes(b'PUBLIC_PRESERVED_UNKNOWN')
        monkeypatch.setattr(renewal,'hold_private_input',hold)
        def operation():
            if terminal:return selection.reconcile_existing(path)
            with selection.selected_inputs(path) as lease:return lease.recover_existing(output)
        if tamper=='child':
            with pytest.raises((ValueError,OSError)):operation()
            assert renewal.recovery_guard(cfg).exists()
            assert (ancestor/'unknown.json').exists()
        else:
            operation()
            assert not renewal.recovery_guard(cfg).exists()
        assert injected==[True]
