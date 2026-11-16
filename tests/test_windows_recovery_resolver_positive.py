"""Actual NTFS predecessor/evidence/successor replay; runtime proof substituted."""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_selfhost_windows_selection import fixture
from test_selfhost_windows_renewal import states
import selfhost_windows_selection as selection
import selfhost_windows_recovery_journal as recovery
import selfhost_windows_renewal_native as native
from selfhost_windows_staging_recovery import RECOVERY_PHASES, RECOVERY_RECEIPTS, failed_current_receipts


@pytest.mark.parametrize('operator_successor',[False,True])
@pytest.mark.parametrize('failed_fault',[None,'selected','config'])
@pytest.mark.parametrize('commit_owner',['replay','finish','resume','proof-failure','guard-failure',
                                      'namespace-race','pending-race','empty-pending'])
def test_full_held_seed_resolves_from_original_anchor_to_ordinary_current(monkeypatch,operator_successor,failed_fault,commit_owner):
    if failed_fault and commit_owner!='replay':pytest.skip('Replay integrity covered independently')
    with fixture(monkeypatch) as (root,phase,tx,outcome,path,cfg):
        model=selection.decode(Path(cfg['compose_file']).read_bytes())
        roles={row['Service'] for row in states(model)}
        data={role:{'image':'PUBLIC_IMAGE','mounts':[]} for role in roles}
        phase['data']=selection.digest(selection.packed(data))
        selection.adopt(path)
        journal=selection.directory(cfg)
        raw={p.name:p.read_bytes() for p in journal.iterdir()}
        expected=selection.binding(cfg)
        _,records=selection._parse(raw,expected);record=records[1]
        attempt=root/('windows-renewal-'+'e'*32);attempt.mkdir()
        layers=selection.renewal.dependency_layers(model,roles,selection.renewal.owned_roles(model,roles))
        staged=selection._stage_configuration(cfg,'new',record,attempt,layers)
        admission=None
        if operator_successor:
            binary=root/'operator'/'marty-deploy-linux-amd64';binary.parent.mkdir();binary.write_bytes(b'PUBLIC_NEW_OPERATOR')
            staged['native'].update(binary=str(binary),binary_sha256=selection.digest(binary.read_bytes()),
                                    source_sha='b'*40,release_tag='v1.2.4')
            admission={'schema':'marty.windows-recovery-operator-admission/v1','source_sha':'b'*40,
                'release_tag':'v1.2.4','run_id':42,'run_attempt':1,'binary_sha256':staged['native']['binary_sha256'],
                'historical_operator_sha256':cfg['native']['binary_sha256'],'verifier_sha256':{'gh':'c'*64,'cosign':'d'*64}}
        candidate=Path(staged['renewed_secrets']);candidate.mkdir()
        for item in Path(staged['current_secrets']).iterdir():
            value=item.read_bytes()
            (candidate/item.name).write_bytes(b'' if not value else b'PUBLIC_RECOVERED_'+item.name.encode())
        lines=Path(staged['current_env']).read_bytes().splitlines(keepends=True)
        lines=[b'SELFHOST_SECRET_DIR='+candidate.as_posix().encode()+b'\n' if line.startswith(b'SELFHOST_SECRET_DIR=') else line for line in lines]
        Path(staged['renewed_env']).write_bytes(b''.join(lines))
        (attempt/'config.private.json').write_bytes(selection.packed(staged))
        failed=root/('windows-renewal-'+'a'*32);failed.mkdir()
        failed_config=selection._stage_configuration(cfg,'new',record,failed,layers)
        (failed/'activation').mkdir()
        failed_paths=[Path(failed_config[name]) for name in ('intent','result','new_log','rollback_log')]
        failed_paths += [Path(file) for step in failed_config['step_receipts'] for file in step.values()]
        for file in failed_paths:file.write_bytes(b'')
        Path(failed_config['renewed_secrets']).mkdir()
        failed_env=[b'SELFHOST_SECRET_DIR='+Path(failed_config['renewed_secrets']).as_posix().encode()+b'\n'
            if line.startswith(b'SELFHOST_SECRET_DIR=') else line
            for line in Path(failed_config['current_env']).read_bytes().splitlines(keepends=True)]
        (failed/'renewed.env').write_bytes(b''.join(failed_env))
        if failed_fault=='config':failed_config['native']['control_volume']='PUBLIC_CHANGED_CONTROL'
        failed_config_raw=selection.packed(failed_config)
        (failed/'activation/config.private.json').write_bytes(failed_config_raw)
        failed_intent={'schema':selection.STAGE_SCHEMA,'project':cfg['project'],'engine_id':cfg['engine_id'],
            'sequence':2,'selected_sha256':selection.digest(selection.packed(record['selected'])),
            'data_sha256':record['data_sha256'],'root':str(failed),
            'config_path':str(failed/'activation/config.private.json'),'config_sha256':selection.digest(failed_config_raw),
            'authority_file':'/control/recovery-session-'+'a'*32+'/token','logical_project':'marty-selfhost-synthetic',
            'services_image':model['services']['signing-keys']['image'],'candidate_only':True}
        if failed_fault=='selected':failed_intent['selected_sha256']='0'*64
        (failed/'intent.json').write_bytes(selection.packed(failed_intent))
        (failed/'result.json').write_bytes(b'')
        (failed/'publication.pending.json').write_bytes(b'')
        failed_raw={name:b'' for name in selection._stage_names() if name!='intent.json'}
        for name in ('authority.started.json','authority.completed.json','current.started.json'):
            p,e,_=name.split('.');failed_raw[name]=selection.packed({'phase':p,'event':e,'metadata':{}})
        for name,body in failed_raw.items():(failed/name).write_bytes(body)
        failed_proof={'schema':'marty.windows-failed-current-proof/v1','project':cfg['project'],'sequence':1,
            'data_sha256':record['data_sha256'],'guard_sha256':selection.digest((failed/'intent.json').read_bytes()),
            'receipt_sha256':failed_current_receipts(failed_raw),'guard_retained':True,'credential_admission':False}
        stage={'schema':'marty.windows-expired-renewal-staging/v1','failed_proof':failed_proof,'failed_root':str(failed),
            'root':str(attempt),'logical_project':'marty-selfhost-synthetic','config_sha256':selection.digest(selection.packed(staged)),
            'operator_admission':admission,'credential_admission':False,'rollback_to_expired':False}
        (attempt/'intent.json').write_bytes(selection.packed(stage))
        receipts={f'{p}.{e}.json':selection.packed({'phase':p,'event':e,'metadata':{}})
                  for p in RECOVERY_PHASES for e in ('started','completed')}
        for p in ('prepare','tls','keycloak'):
            metadata={'id':{'prepare':'b','tls':'c','keycloak':'d'}[p]*64,
                'name':cfg['project']+'-renew-'+p+'-'+'e'*32,
                'image':model['services']['signing-keys']['image'] if p=='tls' else cfg['native']['helper_image']}
            receipts[p+'.helper.json']=selection.packed({'phase':p,'event':'helper','metadata':metadata})
            if p=='tls':receipts['tls.created.json']=selection.packed({'phase':p,'event':'created','metadata':metadata})
        for name,body in receipts.items():(attempt/name).write_bytes(body)
        with ExitStack() as held:
            values,snapshots=selection._inputs(staged,held)
            fingerprint=selection.fingerprint(values['new'])
        publication={'schema':'marty.windows-recovery-candidate-publication/v1','guard_sha256':selection.digest(selection.packed(stage)),
            'config_sha256':stage['config_sha256'],'receipt_sha256':{n:selection.digest(b) for n,b in receipts.items()},
            'generation_sha256':fingerprint,'sequence':1,'data_sha256':record['data_sha256'],
            'credential_admission':False,'guards_retained':True}
        (attempt/'publication.json').write_bytes(selection.packed(publication))
        activation=attempt/'activation';activation.mkdir()
        files=[Path(staged[n]) for n in ('intent','result','new_log','rollback_log')]
        files += [Path(p) for step in staged['step_receipts'] for p in step.values()]
        for file in files:file.write_bytes(b'')
        intent={'schema':'marty.windows-recovery-activation/v1','project':cfg['project'],
            'publication_sha256':selection.digest(selection.packed(publication)),
            'data_mounts_before':data,'layers':layers,'rollback_to_expired':False}
        Path(staged['intent']).write_bytes(selection.packed(intent))
        result={'schema':intent['schema'],'project':cfg['project'],'result':'activated-unselected','secret_mounts':1,
            'data_sha256':record['data_sha256'],'guards_retained':True,'rollback_to_expired':False,'credential_admission':False}
        Path(staged['result']).write_bytes(selection.packed(result))
        for index,layer in enumerate(layers):
            for event in ('started','completed'):
                Path(staged['step_receipts'][index]['new_'+event]).write_bytes(selection.packed({'roles':layer,'event':event}))
        ordinary=recovery.successor_configuration(staged,attempt)
        (attempt/'selection.config.private.json').write_bytes(selection.packed(ordinary))
        (attempt/'selection').mkdir()
        for file in [*(ordinary[n] for n in ('intent','result','new_log','rollback_log')),
                     *(p for step in ordinary['step_receipts'] for p in step.values())]:Path(file).write_bytes(b'')
        target=root/('.'+cfg['project']+'.generation-recovery-'+'e'*32)
        evidence={p.relative_to(attempt).as_posix():selection.digest(p.read_bytes()) for p in attempt.rglob('*') if p.is_file()}
        marker={'schema':recovery.SCHEMA,'project':cfg['project'],'engine_id':cfg['engine_id'],
            'source_dir':str(journal),'target_dir':str(target),'source_sha256':{n:selection.digest(b) for n,b in raw.items()},
            'attempt_dir':str(attempt),'config_sha256':stage['config_sha256'],'generation_sequence':1,
            'evidence_sha256':evidence,'candidate_only':True}
        if commit_owner!='replay':
            from contextlib import contextmanager
            import selfhost_windows_recovery_finish as finisher
            import selfhost_windows_recovery_operator as admission_owner
            monkeypatch.setattr(native,'require_recovery_capability',lambda *args:None)
            @contextmanager
            def admitted(previous,*args,**kwargs):
                successor=dict(previous)
                for key in recovery.OPERATOR_FIELDS:successor[key]=staged['native'][key]
                yield successor,admission
            monkeypatch.setattr(admission_owner,'admitted_operator',admitted)
            option=dict(assets='PUBLIC',expected={},gh='PUBLIC',cosign='PUBLIC',verifier_sha256={}) if operator_successor else None
            guard=selection.renewal.recovery_guard(cfg)
            failed_guard=selection.renewal.renewal_staging_guard(cfg)
            guard.write_bytes(selection.packed(stage))
            failed_guard.write_bytes((failed/'intent.json').read_bytes())
            phase['active']=candidate
            if commit_owner=='guard-failure':
                failed_guard.write_bytes(b'PUBLIC_CHANGED_GUARD')
                with pytest.raises(ValueError):finisher.finish(path,journal,attempt,operator_successor=option)
                assert not (journal/recovery.INTENT).exists() and not target.exists()
                return
            if commit_owner=='proof-failure':
                def refuse(*args,**kwargs):raise ValueError('PUBLIC_PROOF_REFUSAL')
                monkeypatch.setattr(selection,'_prove',refuse)
                with pytest.raises(ValueError):finisher.finish(path,journal,attempt,operator_successor=option)
                assert not (journal/recovery.INTENT).exists() and not target.exists()
                return
            if commit_owner=='resume':
                append=selection._append
                def stop_pending(directory,raw,name,value,stack):
                    if name==recovery.PENDING:raise RuntimeError('PUBLIC_INTERRUPTION')
                    return append(directory,raw,name,value,stack)
                monkeypatch.setattr(selection,'_append',stop_pending)
                with pytest.raises(RuntimeError):finisher.finish(path,journal,attempt,operator_successor=option)
                assert (journal/recovery.INTENT).is_file() and not (journal/recovery.DECISION).exists()
                with pytest.raises(ValueError),selection.selected_inputs(path):pass
                monkeypatch.setattr(selection,'_append',append)
            if commit_owner=='empty-pending':
                append=selection._append
                def stop_empty(directory,raw,name,value,stack):
                    if name==recovery.PENDING:
                        (directory/name).write_bytes(b'')
                        raw[name]=b''
                        raise RuntimeError('PUBLIC_INTERRUPTED_EMPTY_WRITE')
                    return append(directory,raw,name,value,stack)
                monkeypatch.setattr(selection,'_append',stop_empty)
                with pytest.raises(RuntimeError):finisher.finish(path,journal,attempt,operator_successor=option)
                monkeypatch.setattr(selection,'_append',append)
                with pytest.raises(ValueError):finisher.finish(path,journal,attempt,operator_successor=option)
                assert guard.is_file() and failed_guard.is_file() and not (journal/recovery.DECISION).exists()
                assert (journal/recovery.PENDING).read_bytes()==b''
                return
            if commit_owner in ('namespace-race','pending-race'):
                session=selection._session
                calls=[]
                @contextmanager
                def race(*args,**kwargs):
                    with session(*args,**kwargs) as lease:yield lease
                    calls.append(True)
                    with pytest.raises(ValueError),selection.renewal.hold_private_input(
                            root/f'.{cfg["project"]}.renewal.lock',exclusive=True):pass
                    if commit_owner=='namespace-race':
                        for directory in (journal,target):
                            with pytest.raises(OSError):directory.rename(directory.with_name(directory.name+'-replaced'))
                    else:(journal/recovery.PENDING).write_bytes(b'PUBLIC_CHANGED_PENDING')
                monkeypatch.setattr(selection,'_session',race)
                if commit_owner=='pending-race':
                    with pytest.raises(ValueError):finisher.finish(path,journal,attempt,operator_successor=option)
                    assert calls==[True] and guard.is_file() and failed_guard.is_file()
                    assert not (journal/recovery.DECISION).exists()
                    return
            result=finisher.finish(path,journal,attempt,operator_successor=option)
            if commit_owner=='namespace-race':monkeypatch.setattr(selection,'_session',session)
            assert result['result']=='selected-guarded' and result['guards_retained']
            assert finisher.finish(path,journal,attempt,operator_successor=option)==result
            assert guard.is_file() and failed_guard.is_file() and not (journal/recovery.PENDING).exists()
            if commit_owner=='finish':
                prove=selection._prove
                def fail_final_proof(*args,**kwargs):raise ValueError('PUBLIC_FINAL_PROOF_REFUSAL')
                monkeypatch.setattr(selection,'_prove',fail_final_proof)
                with pytest.raises(ValueError):finisher.finalize(path,journal,attempt,operator_successor=option)
                assert guard.is_file() and failed_guard.is_file()
                monkeypatch.setattr(selection,'_prove',prove)
            if commit_owner=='resume':
                import selfhost_windows_inputs as inputs
                held=inputs._held_private_input
                renames=[]
                @contextmanager
                def interrupt_second_archive(file,**kwargs):
                    if kwargs.get('_rename_to') is not None:
                        renames.append(file)
                        if len(renames)==2:raise RuntimeError('PUBLIC_SECOND_ARCHIVE_INTERRUPTED')
                    with held(file,**kwargs) as value:yield value
                monkeypatch.setattr(inputs,'_held_private_input',interrupt_second_archive)
                with pytest.raises(RuntimeError):finisher.finalize(path,journal,attempt,operator_successor=option)
                assert not guard.exists() and failed_guard.is_file()
                with pytest.raises(ValueError),selection.selected_inputs(path):pass
                monkeypatch.setattr(inputs,'_held_private_input',held)
            finalized=finisher.finalize(path,journal,attempt,operator_successor=option)
            assert finalized['result']=='recovery-finalized'
            assert finisher.finalize(path,journal,attempt,operator_successor=option)==finalized
            assert not guard.exists() and not failed_guard.exists()
            assert len(list(root.glob('.'+cfg['project']+'.*-retired-'+'e'*32+'.json')))==2
        raw[recovery.INTENT]=selection.packed(marker)
        if commit_owner=='replay':(journal/recovery.INTENT).write_bytes(raw[recovery.INTENT])
        if failed_fault:
            with pytest.raises(ValueError), ExitStack() as held:
                recovery.seed(raw,expected,{'compose_file':cfg['compose_file'],'compose_sha256':cfg['compose_sha256']},marker,held)
            assert not target.exists()
            return
        with ExitStack() as held:initial=recovery.seed(raw,expected,{'compose_file':cfg['compose_file'],'compose_sha256':cfg['compose_sha256']},marker,held)
        if commit_owner=='replay':
            target.mkdir()
            for name,body in initial.items():(target/name).write_bytes(body)
            (journal/recovery.DECISION).write_bytes(selection.packed(recovery.decision(marker,initial)))
        phase['active']=candidate
        with selection.selected_inputs(path) as lease:
            assert lease.secrets_dir==candidate and lease.sequence==1 and lease.generation_sequence==2
            assert lease.check_current()==record['data_sha256']
        assert Path(ordinary['intent']).read_bytes()==b''
        assert Path(staged['intent']).read_bytes()==selection.packed(intent)
        # Exercise the real ordinary staging owner after recovery resolution.
        # As in the other NTFS tests, only Docker/native effects are replaced.
        observed={'docker':SimpleNamespace(prefix=['PUBLIC_DOCKER']), 'services':roles,'model':model,
                  'context':SimpleNamespace(check=lambda **kwargs:[])}
        monkeypatch.setattr(selection,'_inspect',lambda *args,**kwargs:observed)
        monkeypatch.setattr(native,'reauthenticate',lambda config,project,prefix,directory:directory+'/token')
        monkeypatch.setattr(native,'preflight',lambda *args:None)
        def produce(config,current,logical,cycle,image,checkpoint):
            for p in ('prepare','tls','keycloak','export'):
                checkpoint(p,'started',{})
                if p!='export':
                    metadata={'id':{'prepare':'b','tls':'c','keycloak':'d'}[p]*64,
                        'name':cfg['project']+'-renew-'+p+'-'+cycle,
                        'image':image if p=='tls' else config['native']['helper_image']}
                    if p=='tls':checkpoint(p,'created',metadata)
                    checkpoint(p,'helper',metadata)
                checkpoint(p,'completed',{})
            return {name:b'' if not value else b'PUBLIC_NEXT_'+name.encode() for name,value in current.items()}
        monkeypatch.setattr(native,'produce_generation',produce)
        next_attempt=root/('windows-renewal-'+'c'*32);next_attempt.mkdir()
        with selection.selected_inputs(path) as lease:
            next_stage=lease.stage_renewal(next_attempt,'marty-selfhost-synthetic')
        assert next_stage['changed_files']>0
        next_config=selection.decode(Path(next_stage['next_config']).read_bytes())
        assert next_config['current_secrets']==str(candidate)
        assert Path(next_config['intent']).read_bytes()==b''
        # The next transaction enters through its newly staged configuration,
        # whose admitted operator differs from the original journal owner.
        with selection._session(Path(next_stage['next_config'])) as (_cfg,_raw,_owner,active,_entries,_stack):
            assert active==target
        next_path=Path(next_stage['next_config']);next_raw=next_path.read_bytes()
        if commit_owner=='replay':
            faults=['operator','control','model']+(['stale-operator'] if operator_successor else [])
            for fault in faults:
                bad=selection.decode(next_raw)
                if fault=='operator':bad['native']['source_sha']='f'*40
                elif fault=='control':bad['native']['control_volume']='PUBLIC_UNADMITTED_CONTROL'
                elif fault=='model':bad['compose_sha256']='f'*64
                else:
                    for key in recovery.OPERATOR_FIELDS:bad['native'][key]=cfg['native'][key]
                next_path.write_bytes(selection.packed(bad))
                with pytest.raises(ValueError),selection._session(next_path):pass
                next_path.write_bytes(next_raw)
        monkeypatch.setattr(selection.renewal,'native_preflight',lambda *args:None)
        monkeypatch.setattr(selection.renewal,'Docker',lambda *args:SimpleNamespace(prefix=['PUBLIC_DOCKER']))
        assert selection.prepare(next_path,staging_sha256=next_stage['guard_sha256'],
                                 authority_file=next_stage['authority_file'])==2
        assert not selection.renewal.renewal_staging_guard(cfg).exists()
        with ExitStack() as held:
            values,_=selection._inputs(next_config,held)
            with selection.activation_admission(next_config,values['old'],values['new'],
                    Path(next_config['current_env']).read_bytes(),Path(next_config['renewed_env']).read_bytes()):pass
        # Runtime effects are substituted, but registration, activation admission,
        # completion and both historical/current entrypoints use their real owners.
        outcome(next_config,'activated')
        Path(next_config['intent']).write_bytes(b'PUBLIC_NEXT_ACTIVATION')
        phase['active']=Path(next_config['renewed_secrets'])
        assert selection.complete(next_path)['sequence']==2
        for entrypoint in (path,next_path):
            with selection.selected_inputs(entrypoint) as lease:
                assert lease.generation_sequence==3 and lease.sequence==2
                assert lease.secrets_dir==phase['active'] and lease.check_current()==record['data_sha256']
