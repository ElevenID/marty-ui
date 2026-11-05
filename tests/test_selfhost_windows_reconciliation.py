"""Terminal-only reconciliation, using real NTFS and substituted runtime proofs."""
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import selfhost_windows_recovery as recovery
import selfhost_windows_selection as selection
from test_selfhost_windows_recovery import candidate


@contextmanager
def terminal(monkeypatch, *, empty=True, fresh_authority=False):
    with candidate(monkeypatch) as (root,path,cfg,output,events,items,observed,tx):
        with selection.selected_inputs(path) as lease:lease.recover_existing(output,fresh_authority=fresh_authority)
        if empty:(output/'result.json').write_bytes(b'')
        original = (output/'result.json').read_bytes()
        guard = selection.renewal.recovery_guard(cfg)
        guard.write_bytes((output/'intent.json').read_bytes())
        yield root,path,cfg,output,events,items,observed,guard,original


def test_terminal_uses_recorded_fresh_session_without_logging_in_again(monkeypatch):
    import selfhost_windows_renewal_native as native
    sessions=[]
    def refresh(_cfg,_project,_prefix,session):
        sessions.append(session+'/token');return sessions[-1]
    monkeypatch.setattr(native,'reauthenticate',refresh)
    with terminal(monkeypatch,fresh_authority=True) as (_root,path,_cfg,output,events,_items,_obs,guard,original):
        assert len(sessions)==1
        actual=selection._native_current
        def check(*args,**kwargs):
            assert args[-1]==sessions[0]
            return actual(*args,**kwargs)
        monkeypatch.setattr(selection,'_native_current',check)
        before=list(events)
        decision=selection.reconcile_existing(path)
        assert decision['workload_commands_issued'] is False
        assert events==before and len(sessions)==1 and not guard.exists()
        assert (output/'result.json').read_bytes()==original


@pytest.mark.parametrize('empty',[False,True])
def test_terminal_reconciliation_preserves_original_result_and_issues_no_commands(monkeypatch,empty):
    with terminal(monkeypatch,empty=empty) as (_root,path,_cfg,output,events,_items,_obs,guard,original):
        before = list(events)
        decision = selection.reconcile_existing(path)
        assert decision['result']=='reconciled-terminal-existing' and decision['workload_commands_issued'] is False
        assert events==before and not guard.exists()
        assert (output/'result.json').read_bytes()==original
        assert selection.decode((output/'reconciliation.json').read_bytes())==decision
        with selection.selected_inputs(path) as lease:assert lease.check_current()=='d'*64


@pytest.mark.parametrize('bad',['empty-start','empty-completion','mismatched-completion','foreign-id',
                              'bad-original-result','extra-file','changed-selection','unknown-schema'])
def test_unfinished_or_changed_attempt_never_clears_guard(monkeypatch,bad):
    with terminal(monkeypatch) as (_root,path,_cfg,output,events,items,_obs,guard,_original):
        if bad=='empty-start':(output/'000.started.json').write_bytes(b'')
        elif bad=='empty-completion':(output/'000.completed.json').write_bytes(b'')
        elif bad=='mismatched-completion':(output/'000.completed.json').write_bytes(b'{}')
        elif bad=='foreign-id':items[0]['Id']='f'*64
        elif bad=='bad-original-result':(output/'result.json').write_bytes(b'{}')
        elif bad=='extra-file':(output/'unknown').write_bytes(b'PUBLIC_UNKNOWN')
        else:
            intent=selection.decode(guard.read_bytes())
            if bad=='changed-selection':intent['selected']['env_sha256']='0'*64
            else:intent['schema']='unknown'
            raw=selection.packed(intent);guard.write_bytes(raw);(output/'intent.json').write_bytes(raw)
        before=list(events)
        with pytest.raises((ValueError,OSError)):selection.reconcile_existing(path)
        assert guard.exists() and events==before


def test_failed_current_native_proof_cannot_reconcile_healthy_looking_snapshot(monkeypatch):
    with terminal(monkeypatch) as (_root,path,_cfg,output,events,_items,_obs,guard,original):
        def refuse(*_a,**_kw):raise ValueError('PUBLIC_CURRENT_PROOF_REFUSAL')
        monkeypatch.setattr(selection,'_prove',refuse)
        before=list(events)
        with pytest.raises(ValueError):selection.reconcile_existing(path)
        assert guard.exists() and events==before and (output/'result.json').read_bytes()==original


def test_readonly_reconciliation_context_cannot_start_workloads(monkeypatch):
    with terminal(monkeypatch) as (_root,path,_cfg,output,events,_items,_obs,guard,_original):
        before=list(events)
        with selection._selected_inputs(path,terminal_guard_sha256=selection.digest(guard.read_bytes())) as lease:
            with pytest.raises(ValueError):lease.recover_existing(output)
        assert guard.exists() and events==before


def test_publication_lock_exit_failure_can_resume_without_rewriting_original_result(monkeypatch):
    with terminal(monkeypatch) as (root,path,cfg,output,events,_items,_obs,guard,original):
        actual=selection.renewal.hold_private_input
        @contextmanager
        def held(p,*a,**kw):
            with actual(p,*a,**kw) as value:yield value
            receipt=output/'reconciliation.json'
            if Path(p)==root/f'.{cfg["project"]}.renewal.lock' and receipt.exists() and receipt.read_bytes():
                raise ValueError('PUBLIC_FINAL_LOCK_FAILURE')
        monkeypatch.setattr(selection.renewal,'hold_private_input',held)
        before=list(events)
        with pytest.raises(ValueError):selection.reconcile_existing(path)
        assert guard.exists() and (output/'result.json').read_bytes()==original
        saved=(output/'reconciliation.json').read_bytes()
        monkeypatch.setattr(selection.renewal,'hold_private_input',actual)
        decision=selection.reconcile_existing(path)
        assert not guard.exists() and events==before
        assert (output/'reconciliation.json').read_bytes()==saved==selection.packed(decision)


def test_receipt_change_between_lease_and_publication_keeps_guard(monkeypatch):
    with terminal(monkeypatch) as (_root,path,_cfg,output,_events,_items,_obs,guard,_original):
        actual=recovery.verify_terminal
        def verify(*a,**kw):
            pending=actual(*a,**kw)
            (output/'result.json').write_bytes(b'PUBLIC_CHANGED')
            return pending
        monkeypatch.setattr(recovery,'verify_terminal',verify)
        with pytest.raises(ValueError):selection.reconcile_existing(path)
        assert guard.exists()


@pytest.mark.parametrize('boundary',['receipt-exit','publication-lock-exit'])
def test_late_extra_entry_cannot_survive_guard_clear(monkeypatch,boundary):
    with terminal(monkeypatch) as (root,path,cfg,output,_events,_items,_obs,guard,original):
        actual=selection.renewal.hold_private_input;reads={'receipt':0}
        @contextmanager
        def held(p,*a,**kw):
            if Path(p)==output/'000.completed.json':reads['receipt']+=1
            with actual(p,*a,**kw) as value:yield value
            receipt=output/'reconciliation.json'
            if (boundary=='receipt-exit' and Path(p)==output/'000.completed.json' and reads['receipt']==2
                or boundary=='publication-lock-exit' and Path(p)==root/f'.{cfg["project"]}.renewal.lock'
                   and receipt.exists() and receipt.read_bytes()):
                (output/'late-extra').write_bytes(b'PUBLIC_EXTRA')
        monkeypatch.setattr(selection.renewal,'hold_private_input',held)
        with pytest.raises(ValueError):selection.reconcile_existing(path)
        assert guard.exists() and (output/'result.json').read_bytes()==original


def test_saved_decision_is_locked_through_other_receipt_exit_checks(monkeypatch):
    with terminal(monkeypatch) as (_root,path,_cfg,output,_events,_items,_obs,guard,_original):
        decision=selection.reconcile_existing(path)
        guard.write_bytes((output/'intent.json').read_bytes())
        actual=selection.renewal.hold_private_input;reads={'receipt':0,'denied':False}
        @contextmanager
        def held(p,*a,**kw):
            if Path(p)==output/'000.completed.json':reads['receipt']+=1
            with actual(p,*a,**kw) as value:yield value
            if Path(p)==output/'000.completed.json' and reads['receipt']==2:
                with pytest.raises(OSError):(output/'reconciliation.json').write_bytes(b'PUBLIC_TAMPER')
                reads['denied']=True
        monkeypatch.setattr(selection.renewal,'hold_private_input',held)
        assert selection.reconcile_existing(path)==decision
        assert reads['denied'] and not guard.exists()


def test_original_result_stays_locked_across_publication_lock_exit(monkeypatch):
    with terminal(monkeypatch) as (root,path,cfg,output,_events,_items,_obs,guard,original):
        actual=selection.renewal.hold_private_input;denied=[]
        @contextmanager
        def held(p,*a,**kw):
            with actual(p,*a,**kw) as value:yield value
            receipt=output/'reconciliation.json'
            if Path(p)==root/f'.{cfg["project"]}.renewal.lock' and receipt.exists() and receipt.read_bytes():
                with pytest.raises(OSError):(output/'result.json').write_bytes(b'PUBLIC_LATE_RESULT')
                denied.append(True)
        monkeypatch.setattr(selection.renewal,'hold_private_input',held)
        selection.reconcile_existing(path)
        assert denied and not guard.exists() and (output/'result.json').read_bytes()==original
