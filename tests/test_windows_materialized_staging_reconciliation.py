"""Reconcile materialized bytes with real private NTFS and mocked native APIs."""
from contextlib import contextmanager
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_selfhost_windows_staging import staged_candidate
import selfhost_windows_selection as selection
import selfhost_windows_renewal_native as native


@contextmanager
def materialized(monkeypatch, *, initial_current=False):
    with staged_candidate(monkeypatch, initial_current=initial_current) as case:
        _root,path,cfg,output,events=case
        def refuse(*_args):raise ValueError('PUBLIC_ADMISSION_REFUSAL')
        monkeypatch.setattr(native,'preflight',refuse)
        with pytest.raises(ValueError):
            with selection.selected_inputs(path) as lease:
                lease.stage_renewal(output,'marty-selfhost-synthetic')
        assert (output/'materialize.started.json').read_bytes()
        assert not (output/'materialize.completed.json').read_bytes()
        monkeypatch.setattr(native,'preflight',lambda *_a:None)
        yield case


def test_reconcile_materialized_never_replays_producer_or_clears_guard(monkeypatch):
    with materialized(monkeypatch) as (_root,path,cfg,output,events):
        before={p.name:p.read_bytes() for p in output.iterdir() if p.is_file()}
        counts={n:events.count(n) for n in ('authority','produce')}
        result=selection.reconcile_materialized(path)
        assert {n:events.count(n) for n in counts}==counts
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        assert selection.status(path)['state']=='pending-staging'
        assert selection.decode((output/'result.json').read_bytes())==result
        for name,raw in before.items():
            if name not in ('materialize.completed.json','result.json','publication.pending.json'):
                assert (output/name).read_bytes()==raw
        assert selection.prepare(Path(result['next_config']),staging_sha256=result['guard_sha256'])==2


def test_initial_current_materialized_first_replacement_reconciles_without_replay(monkeypatch):
    with materialized(monkeypatch, initial_current=True) as (_root,path,cfg,output,events):
        before = events.count('produce')
        result = selection.reconcile_materialized(path)
        assert events.count('produce') == before
        assert result['changed_files'] > 0
        assert selection.prepare(Path(result['next_config']),
                                 staging_sha256=result['guard_sha256']) == 2
        assert selection.status(path)['state'] == 'pending-reconciliation'


@pytest.mark.parametrize('fault',['authority','prepare','tls','keycloak','export','missing-boundary'])
def test_incomplete_producer_refuses_without_replay_or_publication(monkeypatch,fault):
    with staged_candidate(monkeypatch,fault=fault) as (_root,path,cfg,output,events):
        with pytest.raises((ValueError,selection.renewal.UncertainComposeMutation)):
            with selection.selected_inputs(path) as lease:lease.stage_renewal(output,'marty-selfhost-synthetic')
        before=list(events)
        with pytest.raises((ValueError,FileNotFoundError,KeyError)):
            selection.reconcile_materialized(path)
        assert events==before
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        assert not (output/'result.json').read_bytes()
        assert not (output/'publication.json').exists()


@pytest.mark.parametrize('fault',['native','current','phase','result','marker','root-extra','activation-extra','activation-started'])
def test_reconciliation_refuses_changed_or_unadmitted_state(monkeypatch,fault):
    with materialized(monkeypatch) as (_root,path,cfg,output,events):
        def refuse(*_a,**_kw):raise ValueError('PUBLIC_REFUSAL')
        if fault=='native':monkeypatch.setattr(native,'preflight',refuse)
        elif fault=='current':monkeypatch.setattr(selection,'_native_current',refuse)
        elif fault=='phase':(output/'export.completed.json').write_bytes(b'{}')
        elif fault=='result':(output/'result.json').write_bytes(b'{}')
        elif fault=='marker':(output/'publication.pending.json').write_bytes(b'{}')
        elif fault=='root-extra':(output/'unknown.json').write_bytes(b'{}')
        elif fault=='activation-extra':(output/'activation/unknown').write_bytes(b'{}')
        else:(output/'activation/intent').write_bytes(b'{}')
        counts={n:events.count(n) for n in ('authority','produce')}
        with pytest.raises((ValueError,KeyError)):selection.reconcile_materialized(path)
        assert {n:events.count(n) for n in counts}==counts
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        assert not (output/'publication.json').exists()


def test_published_reconciliation_is_immutable_and_does_not_activate(monkeypatch):
    with materialized(monkeypatch) as (_root,path,cfg,output,_events):
        first=selection.reconcile_materialized(path)
        before={p:p.read_bytes() for p in output.rglob('*') if p.is_file()}
        assert selection.reconcile_materialized(path)==first
        assert {p:p.read_bytes() for p in before}==before
        assert selection.renewal.renewal_staging_guard(cfg).exists()


@pytest.mark.parametrize('boundary',['result','pending','rename'])
def test_interrupted_metadata_publication_resumes_without_rewriting(monkeypatch,boundary):
    with materialized(monkeypatch) as (_root,path,cfg,output,events):
        original=selection.renewal.write_empty_private_file
        rename=Path.rename
        def write(target,value):
            original(target,value)
            if Path(target)==output/('result.json' if boundary=='result' else 'publication.pending.json'):
                if boundary!='rename':raise ValueError('PUBLIC_POSTWRITE_FAILURE')
        def move(source,target):
            if source==output/'publication.pending.json':raise OSError('PUBLIC_RENAME_FAILURE')
            return rename(source,target)
        monkeypatch.setattr(selection.renewal,'write_empty_private_file',write)
        if boundary=='rename':monkeypatch.setattr(Path,'rename',move)
        with pytest.raises((ValueError,OSError)):selection.reconcile_materialized(path)
        saved=(output/'result.json').read_bytes()
        assert saved and not (output/'publication.json').exists()
        before={n:events.count(n) for n in ('authority','produce')}
        monkeypatch.setattr(selection.renewal,'write_empty_private_file',original)
        monkeypatch.setattr(Path,'rename',rename)
        result=selection.reconcile_materialized(path)
        assert (output/'result.json').read_bytes()==saved==selection.packed(result)
        assert {n:events.count(n) for n in before}==before
        assert selection.renewal.renewal_staging_guard(cfg).exists()


@pytest.mark.parametrize('boundary',['phase','generation','late-root-member','late-activation-member'])
def test_all_held_exits_and_memberships_precede_publication(monkeypatch,boundary):
    with materialized(monkeypatch) as (_root,path,cfg,output,_events):
        original=selection.renewal.hold_private_input
        generation=selection.renewal.hold_private_generation
        @contextmanager
        def hold(target,**kwargs):
            with original(target,**kwargs) as value:yield value
            if Path(target)==output/'tls.completed.json':
                if boundary=='phase':raise ValueError('PUBLIC_LATE_PHASE_EXIT')
                if boundary=='late-root-member':(output/'late-unknown').write_bytes(b'PUBLIC')
                if boundary=='late-activation-member':(output/'activation/late-unknown').write_bytes(b'PUBLIC')
        @contextmanager
        def hold_generation(target,names):
            with generation(target,names) as values:yield values
            if boundary=='generation' and Path(target).name=='candidate-secrets-renewal-'+'a'*32:
                raise ValueError('PUBLIC_LATE_GENERATION_EXIT')
        monkeypatch.setattr(selection.renewal,'hold_private_input',hold)
        monkeypatch.setattr(selection.renewal,'hold_private_generation',hold_generation)
        with pytest.raises(ValueError):selection.reconcile_materialized(path)
        assert not (output/'result.json').read_bytes()
        assert not (output/'publication.json').exists()
        assert selection.renewal.renewal_staging_guard(cfg).exists()


@pytest.mark.parametrize('kind',['id','name','label'])
def test_any_remaining_cycle_helper_blocks_reconciliation(monkeypatch,kind):
    with materialized(monkeypatch) as (_root,path,cfg,output,_events):
        observed=selection._inspect(cfg,None,{},None)
        docker=observed['docker'];containers=docker.containers
        helper={'Id':'f'*64,'Name':'/unrelated','Config':{'Labels':{}}}
        if kind=='id':helper['Id']='b'*64
        elif kind=='name':helper['Name']='/'+cfg['project']+'-renew-prepare-'+'a'*32
        else:helper['Config']['Labels']['marty.windows.renewal']='a'*32
        monkeypatch.setattr(docker,'containers',lambda:[*containers(),helper])
        with pytest.raises(ValueError):selection.reconcile_materialized(path)
        assert not (output/'result.json').read_bytes()
        assert selection.renewal.renewal_staging_guard(cfg).exists()
