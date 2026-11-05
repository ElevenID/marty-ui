"""Real private NTFS staging guard and registered handoff; native/Docker mocked."""
import sys
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import selfhost_windows_renewal_native as native
import selfhost_windows_selection as selection
from test_selfhost_windows_recovery import candidate


@contextmanager
def staged_candidate(monkeypatch,*,fault=None):
    with candidate(monkeypatch,warm=True) as (root,path,cfg,_out,events,_items,_observed,_tx):
        output=root/('windows-renewal-'+'a'*32);output.mkdir()
        def reauthenticate(_cfg,_project,_prefix,session):
            events.append('authority')
            if fault=='authority':raise ValueError('PUBLIC_SCOPED_AUTHORITY_REFUSAL')
            return session+'/token'
        def produce(config,current,_logical,cycle,_image,checkpoint):
            events.append('produce')
            assert len(cycle)==32
            for phase in ('prepare','tls','keycloak','export'):
                checkpoint(phase,'started',{})
                if fault==phase:raise selection.renewal.UncertainComposeMutation('PUBLIC_UNCERTAIN_PRODUCER')
                if phase in {'prepare','tls','keycloak'}:
                    metadata={'id':{'prepare':'b','tls':'c','keycloak':'d'}[phase]*64,
                        'name':cfg['project']+'-renew-'+phase+'-'+cycle,
                        'image':_image if phase=='tls' else config['native']['helper_image']}
                    if phase=='tls':checkpoint(phase,'created',metadata)
                    checkpoint(phase,'helper',metadata)
                if fault!='missing-boundary':checkpoint(phase,'completed',{})
            return {name:(b'' if not value else b'PUBLIC_RENEWED_'+cycle.encode()+name.encode()) for name,value in current.items()}
        monkeypatch.setattr(native,'reauthenticate',reauthenticate)
        monkeypatch.setattr(native,'produce_generation',produce)
        monkeypatch.setattr(native,'preflight',lambda *_a:None)
        monkeypatch.setattr(selection.renewal,'native_preflight',lambda *_a:None)
        yield root,path,cfg,output,events


def test_stage_result_waits_for_exit_and_guard_transfers_to_pending_selection(monkeypatch):
    with staged_candidate(monkeypatch) as (_root,path,cfg,output,events):
        with selection.selected_inputs(path) as lease:
            result=lease.stage_renewal(output,'marty-selfhost-synthetic')
            assert (output/'result.json').read_bytes()==b''
            assert selection.renewal.renewal_staging_guard(cfg).exists()
            with pytest.raises(ValueError):lease.stage_renewal(output,'marty-selfhost-synthetic')
        assert selection.decode((output/'result.json').read_bytes())==result
        assert events==['authority','produce']
        assert selection.status(path)['state']=='pending-staging'
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):pytest.fail('Staging guard ignored')
        next_path=Path(result['next_config'])
        with pytest.raises(ValueError):selection.prepare(next_path)
        assert selection.prepare(next_path,staging_sha256=result['guard_sha256'])==2
        assert not selection.renewal.renewal_staging_guard(cfg).exists()
        assert selection.status(path)['state']=='pending-reconciliation'
        assert (output/'intent.json').exists() and (output/'result.json').exists()


def test_exhausted_journal_refuses_before_guard_or_credential_production(monkeypatch):
    with staged_candidate(monkeypatch) as (_root,_path,cfg,output,events):
        with ExitStack() as stack,pytest.raises(ValueError):
            selection._stage(cfg,'new',{}, {'sequence':selection.MAX_SELECTIONS},
                output,'marty-selfhost-synthetic',stack)
        assert not events and not list(output.iterdir())
        assert not selection.renewal.renewal_staging_guard(cfg).exists()


def test_refused_continuation_allocates_no_renewal_attempt_or_credentials(monkeypatch):
    with staged_candidate(monkeypatch) as (root,path,cfg,_output,events):
        original=selection.selected_inputs
        def refuse():
            events.append('continuation-refused')
            raise ValueError('PUBLIC_CONTINUATION_REFUSAL')
        @contextmanager
        def full(path):
            with original(path) as lease:yield replace(lease,sequence=selection.MAX_SELECTIONS,continue_journal=refuse)
        monkeypatch.setattr(selection,'selected_inputs',full)
        before=set(root.iterdir())
        with pytest.raises(ValueError):selection.renew_once(path,'marty-selfhost-synthetic')
        assert set(root.iterdir())==before and events==['continuation-refused']
        assert not selection.renewal.renewal_staging_guard(cfg).exists()


@pytest.mark.parametrize('fault',['authority','prepare','tls','keycloak','export','missing-boundary'])
def test_incomplete_producer_retains_guard_and_never_registers_activation(monkeypatch,fault):
    with staged_candidate(monkeypatch,fault=fault) as (_root,path,cfg,output,_events):
        with pytest.raises((ValueError,selection.renewal.UncertainComposeMutation)):
            with selection.selected_inputs(path) as lease:lease.stage_renewal(output,'marty-selfhost-synthetic')
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        assert (output/'result.json').read_bytes()==b''
        assert not (selection.directory(cfg)/'000002.intent.json').exists()
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):pytest.fail('Unknown producer replay admitted')


def test_caller_failure_after_staging_does_not_publish_or_clear_guard(monkeypatch):
    with staged_candidate(monkeypatch) as (_root,path,cfg,output,_events):
        with pytest.raises(RuntimeError):
            with selection.selected_inputs(path) as lease:
                lease.stage_renewal(output,'marty-selfhost-synthetic')
                raise RuntimeError('PUBLIC_CALLER_FAILURE')
        assert (output/'result.json').read_bytes()==b''
        assert selection.renewal.renewal_staging_guard(cfg).exists()


@pytest.mark.parametrize('boundary',['generation','lock','config','phase','guard','result','publication','writer'])
def test_late_publication_failure_is_never_admissible(monkeypatch,boundary):
    with staged_candidate(monkeypatch) as (_root,path,cfg,output,_events):
        original_input=selection.renewal.hold_private_input
        original_generation=selection.renewal.hold_private_generation
        original_write=selection.renewal.write_empty_private_file
        def matches(p):
            p=Path(p)
            return {'lock':p.name.endswith('.renewal.lock'),
                'config':p==output/'activation/config.private.json',
                'phase':p==output/'tls.completed.json',
                'guard':p==selection.renewal.renewal_staging_guard(cfg),
                'result':p==output/'result.json',
                'publication':p==output/'publication.pending.json'}.get(boundary,False)
        @contextmanager
        def held_input(p,**kw):
            with original_input(p,**kw) as raw:yield raw
            if matches(p):raise ValueError('PUBLIC_LATE_INPUT_EXIT')
        @contextmanager
        def held_generation(*a,**kw):
            with original_generation(*a,**kw) as values:yield values
            raise ValueError('PUBLIC_LATE_GENERATION_EXIT')
        def write(p,value):
            original_write(p,value)
            if Path(p)==output/'publication.pending.json':raise ValueError('PUBLIC_LATE_WRITER_EXIT')
        with pytest.raises(ValueError):
            with selection.selected_inputs(path) as lease:
                result=lease.stage_renewal(output,'marty-selfhost-synthetic')
                if boundary=='generation':monkeypatch.setattr(selection.renewal,'hold_private_generation',held_generation)
                elif boundary=='writer':monkeypatch.setattr(selection.renewal,'write_empty_private_file',write)
                else:monkeypatch.setattr(selection.renewal,'hold_private_input',held_input)
        monkeypatch.setattr(selection.renewal,'hold_private_input',original_input)
        monkeypatch.setattr(selection.renewal,'hold_private_generation',original_generation)
        monkeypatch.setattr(selection.renewal,'write_empty_private_file',original_write)
        assert not (output/'publication.json').exists()
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        with pytest.raises((ValueError,OSError)):
            selection.prepare(Path(result['next_config']),staging_sha256=result['guard_sha256'])
        assert not (selection.directory(cfg)/'000002.intent.json').exists()


@pytest.mark.parametrize('entry', ['file', 'directory'])
def test_product_marker_before_publication_preserves_staging_guard_and_empty_result(monkeypatch, entry):
    with staged_candidate(monkeypatch) as (_root, path, cfg, output, _events):
        journal = selection.directory(cfg)
        before = {item.name: item.read_bytes() for item in journal.iterdir()}
        product_guard = selection.renewal.product_transition_guard(cfg)
        with pytest.raises(ValueError):
            with selection.selected_inputs(path) as lease:
                lease.stage_renewal(output, 'marty-selfhost-synthetic')
                staging_guard = selection.renewal.renewal_staging_guard(cfg).read_bytes()
                if entry == 'file':product_guard.write_bytes(b'PUBLIC_PENDING_PRODUCT')
                else:product_guard.mkdir()
        assert (output/'result.json').read_bytes() == b''
        assert not (output/'publication.json').exists()
        assert selection.renewal.renewal_staging_guard(cfg).read_bytes() == staging_guard
        assert product_guard.exists()
        assert before == {item.name: item.read_bytes() for item in journal.iterdir()}


def test_finalizer_accepts_a_held_model_larger_than_64k(monkeypatch):
    with staged_candidate(monkeypatch) as (_root,path,cfg,output,_events):
        finish=selection._finish_stage
        monkeypatch.setattr(selection,'_finish_stage',lambda *_a:None)
        with selection.selected_inputs(path) as lease:result=lease.stage_renewal(output,'marty-selfhost-synthetic')
        model=Path(cfg['compose_file']);raw=model.read_bytes()+b' '*150000
        model.write_bytes(raw)
        adjusted=dict(cfg,compose_sha256=selection.digest(raw))
        finish(adjusted,{'stage':selection.decode((output/'intent.json').read_bytes()),'result':result})
        assert (output/'publication.json').exists()


@pytest.mark.parametrize('bad',['id','name','image','extra','tls-created','duplicate-id','phase-metadata'])
def test_helper_admission_checks_contract_even_with_matching_receipt_hashes(monkeypatch,bad):
    with staged_candidate(monkeypatch) as (_root,path,cfg,output,_events):
        with selection.selected_inputs(path) as lease:result=lease.stage_renewal(output,'marty-selfhost-synthetic')
        name='tls.created.json' if bad=='tls-created' else 'prepare.helper.json'
        if bad=='phase-metadata':name='tls.completed.json'
        receipt=selection.decode((output/name).read_bytes())
        if bad=='id':receipt['metadata']['id']='INVALID'
        elif bad=='name':receipt['metadata']['name']='foreign-helper'
        elif bad=='image':receipt['metadata']['image']='foreign@sha256:'+'f'*64
        elif bad=='extra':receipt['metadata']['extra']='PUBLIC'
        elif bad=='tls-created':receipt['metadata']['id']='e'*64
        elif bad=='duplicate-id':receipt['metadata']['id']='d'*64
        else:receipt['metadata']={'unexpected':True}
        raw=selection.packed(receipt);(output/name).write_bytes(raw)
        result['phase_sha256'][name]=selection.digest(raw)
        (output/'result.json').write_bytes(selection.packed(result))
        (output/'publication.json').write_bytes(selection.packed({'schema':selection.STAGE_SCHEMA,
            'result_sha256':selection.digest(selection.packed(result))}))
        with pytest.raises(ValueError):
            selection.prepare(Path(result['next_config']),staging_sha256=result['guard_sha256'])
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        assert not (selection.directory(cfg)/'000002.intent.json').exists()


@pytest.mark.parametrize('bad',['result','phase','config','generation','env','sha'])
def test_staged_handoff_refuses_changed_or_unknown_material(monkeypatch,bad):
    with staged_candidate(monkeypatch) as (_root,path,cfg,output,_events):
        with selection.selected_inputs(path) as lease:result=lease.stage_renewal(output,'marty-selfhost-synthetic')
        next_path=Path(result['next_config']);next_cfg=selection.decode(next_path.read_bytes())
        sha=result['guard_sha256']
        if bad=='result':(output/'result.json').write_bytes(b'{}')
        elif bad=='phase':(output/'tls.completed.json').write_bytes(b'')
        elif bad=='config':next_path.write_bytes(b'{}')
        elif bad=='generation':next(Path(next_cfg['renewed_secrets']).iterdir()).write_bytes(b'PUBLIC_CHANGED')
        elif bad=='env':(output/'renewed.env').write_bytes(b'PUBLIC_CHANGED')
        else:sha='0'*64
        with pytest.raises((ValueError,KeyError)):
            selection.prepare(next_path,staging_sha256=sha)
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        assert not (selection.directory(cfg)/'000002.intent.json').exists()


def test_failed_handoff_after_registration_still_blocks_every_new_attempt(monkeypatch):
    with staged_candidate(monkeypatch) as (_root,path,cfg,output,_events):
        with selection.selected_inputs(path) as lease:result=lease.stage_renewal(output,'marty-selfhost-synthetic')
        def refuse(*_a):raise ValueError('PUBLIC_HANDOFF_EXIT_FAILURE')
        monkeypatch.setattr(selection,'_handoff_staged',refuse)
        with pytest.raises(ValueError):selection.prepare(Path(result['next_config']),staging_sha256=result['guard_sha256'])
        assert (selection.directory(cfg)/'000002.intent.json').exists()
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):pytest.fail('Pending transfer admitted a new producer')


@pytest.mark.parametrize('outcome',['activated','rolled_back','uncertain'])
def test_one_call_cycle_uses_registered_activation_and_never_replays_unknown_work(monkeypatch,outcome):
    with staged_candidate(monkeypatch) as (_root,path,cfg,_output,events):
        if outcome=='activated':monkeypatch.setattr(selection,'_prove',lambda *_a,**_kw:'d'*64)
        def activate(next_cfg):
            assert not selection.renewal.renewal_staging_guard(cfg).exists()
            assert selection.status(path)['state']=='pending-reconciliation'
            events.append('activate')
            if outcome=='uncertain':raise selection.renewal.UncertainComposeMutation('PUBLIC_UNKNOWN_ACTIVATION')
            result={'schema':selection.renewal.SCHEMA,'project':cfg['project'],'candidate_only':True,
                'production_admission':False,'automatic_lifecycle':False,'result':outcome}
            selection.renewal.write_empty_private_file(Path(next_cfg['result']),selection.packed(result).decode())
            if outcome=='rolled_back':raise RuntimeError('PUBLIC_KNOWN_ROLLBACK')
            return result
        monkeypatch.setattr(selection.renewal,'activate',activate)
        if outcome=='activated':
            result=selection.renew_once(path,'marty-selfhost-synthetic')
            assert result['result']=='renewed-and-selected' and result['sequence']==2
            assert selection.status(path)['decision']=='activated'
        else:
            with pytest.raises((RuntimeError,selection.renewal.UncertainComposeMutation)):
                selection.renew_once(path,'marty-selfhost-synthetic')
            state=selection.status(path)
            assert state['state']==('pending-reconciliation' if outcome=='uncertain' else 'selected')
            if outcome=='rolled_back':assert state['decision']=='rolled_back'
            else:
                before=list(events)
                with pytest.raises(ValueError):selection.renew_once(path,'marty-selfhost-synthetic')
                assert events==before
        assert events.count('activate')==1


def test_full_segment_continues_before_next_credential_mint(monkeypatch):
    with staged_candidate(monkeypatch) as (_root,path,cfg,_output,events):
        monkeypatch.setattr(selection,'MAX_SELECTIONS',2)
        monkeypatch.setattr(selection,'_prove',lambda *_a,**_kw:'d'*64)
        def activate(next_cfg):
            events.append('activate')
            result={'schema':selection.renewal.SCHEMA,'project':cfg['project'],'candidate_only':True,
                'production_admission':False,'automatic_lifecycle':False,'result':'activated'}
            selection.renewal.write_empty_private_file(Path(next_cfg['result']),selection.packed(result).decode())
            return result
        monkeypatch.setattr(selection.renewal,'activate',activate)
        assert selection.renew_once(path,'marty-selfhost-synthetic')['sequence']==2
        first=selection.status(path)
        result=selection.renew_once(path,'marty-selfhost-synthetic')
        second=selection.status(path)
        assert result['sequence']==2 and result['generation_sequence']==3 and second['generation_sequence']==3
        assert second['selected']!=first['selected']
        assert events.count('authority')==2 and events.count('produce')==2 and events.count('activate')==2
        assert not selection.renewal.continuation_guard(cfg).exists()


@pytest.mark.parametrize('guard_name',['model_repair_guard','continuation_guard'])
def test_staged_admission_refuses_foreign_operation_guard_before_native_or_append(monkeypatch,guard_name):
    with staged_candidate(monkeypatch) as (_root,path,cfg,output,events):
        with selection.selected_inputs(path) as lease:
            result=lease.stage_renewal(output,'marty-selfhost-synthetic')
        guard=getattr(selection.renewal,guard_name)(cfg)
        guard.write_bytes(b'PUBLIC_OTHER_OPERATION_PENDING')
        before=list(events)
        def forbidden(*_a,**_kw):raise AssertionError('Foreign guard must refuse before native call')
        monkeypatch.setattr(selection.renewal,'native_preflight',forbidden)
        with pytest.raises(ValueError):
            selection.prepare(Path(result['next_config']),staging_sha256=result['guard_sha256'])
        assert events==before and not (selection.directory(cfg)/'000002.intent.json').exists()
        assert guard.exists() and selection.renewal.renewal_staging_guard(cfg).exists()
