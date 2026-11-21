"""Prepare-only origin/replay contracts; all host and native operations doubled.

Portable cases use explicit filesystem handle doubles, not NTFS qualification.
Public certificate parsing is real; no network, subprocess, Docker or credentials
are used. The separate Windows fixture below retains actual private handles.
"""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
from pathlib import Path
import os
import ssl
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import selfhost_windows_expired_origin as origin
import selfhost_windows_inputs as inputs
import selfhost_windows_renewal_native as native
import selfhost_windows_selection as selection
import selfhost_windows_staging_recovery as staging
from test_selfhost_windows_renewal import model, states, PROJECT

FIXTURES=Path(__file__).resolve().parent/'fixtures'
NOW=int(ssl.cert_time_to_seconds('Nov 21 20:00:00 2026 GMT'))


def public_bytes():
    leaf=(FIXTURES/'acme/le-first-shortlived-leaf.pem').read_bytes()
    ca=(FIXTURES/'selfhost_ca_issuer_public.pem').read_bytes()
    return {name:ca if name==origin.CA_FILE else leaf for name in origin.RENEWED_CERT_FILES}


def build_owner(monkeypatch,tmp_path,*,real_handles=False):
    """Real selection replay and origin logic with explicit safe boundary doubles."""
    status={'events':[],'fail_exit':None,'context_fail':None,'context_calls':0,'native':'lifetime-refused',
            'holds':[],'promotions':[]}
    @contextmanager
    def held(path, *, directory=False, mutable_directory=False, _rename_to=None, **_kwargs):
        path=Path(path)
        before={p.name for p in path.iterdir()} if directory else path.read_bytes()
        status['holds'].append(path)
        try:
            yield b'' if directory else before
            after={p.name for p in path.iterdir()} if directory else path.read_bytes()
            if not mutable_directory:assert before==after, 'Synthetic held input changed'
            if status['fail_exit'] and status['fail_exit'](path):
                raise ValueError('PUBLIC_SYNTHETIC_EXIT_REFUSAL')
            if _rename_to is not None:
                assert path.name in (origin.PENDING,'publication.pending.json') and not Path(_rename_to).exists()
                # Selected configuration/generation/namespace holds have closed.
                assert all(p.name.endswith('.renewal.lock') or p==path for p in status['holds'])
                status['promotions'].append(path)
                path.rename(_rename_to)
        finally:status['holds'].remove(path)
    @contextmanager
    def namespace(path):
        assert Path(path).exists()
        yield
        if status['fail_exit'] and status['fail_exit'](Path(path)):
            raise ValueError('PUBLIC_SYNTHETIC_NAMESPACE_EXIT_REFUSAL')
    @contextmanager
    def generation(path,names):
        with held(path,directory=True),ExitStack() as stack:
            selection.require({p.name for p in Path(path).iterdir()}==set(names))
            yield {name:stack.enter_context(held(Path(path,name))) for name in names}
    def write(path,text):
        assert Path(path).read_bytes()==b''
        Path(path).write_bytes(text.encode())
    if not real_handles:
        monkeypatch.setattr(selection,'_held_private_input',held)
        monkeypatch.setattr(inputs,'_held_private_input',held)
        monkeypatch.setattr(selection.renewal,'hold_private_input',held)
        monkeypatch.setattr(selection.renewal,'hold_storage_namespace',namespace)
        monkeypatch.setattr(selection.renewal,'hold_private_generation',generation)
        monkeypatch.setattr(selection.renewal,'read_private_bytes',lambda path:Path(path).read_bytes())
        monkeypatch.setattr(selection.renewal,'write_empty_private_file',write)
    monkeypatch.setattr(origin.time,'time',lambda:NOW)
    def forbidden(*_args,**_kwargs):pytest.fail('Real external operation or credential producer invoked')
    monkeypatch.setattr(selection.renewal,'run_owned_mutation',forbidden)
    monkeypatch.setattr(selection.renewal,'Docker',forbidden)
    monkeypatch.setattr(native,'produce_generation',forbidden)
    monkeypatch.setattr(native,'produce_recovery_generation',forbidden)
    monkeypatch.setattr(native,'preflight_current',forbidden)
    current=tmp_path/'generation0';current.mkdir()
    renewed=tmp_path/'generation1';renewed.mkdir()
    m=model(current)
    for name in origin.RENEWED_CERT_FILES:
        m['secrets'][name]={'file':str(current/name)}
    model_file=tmp_path/'compose.json';model_file.write_bytes(selection.packed(m))
    for number,root in enumerate((current,renewed)):
        for name in m['secrets']:
            value=public_bytes().get(name,b'PUBLIC_SYNTHETIC_'+str(number).encode()+b'_'+name.encode())
            # Distinct retained public bytes make a wrong old-root replay fail
            # even though both generations decode to the same certificate dates.
            if number==0 and name in origin.RENEWED_CERT_FILES:value+=b'\n'
            (root/name).write_bytes(value)
        (tmp_path/f'generation{number}.env').write_text('SELFHOST_SECRET_DIR='+root.as_posix()+'\nFIXED_SETTING=test\n')
    cfg={'schema':selection.renewal.SCHEMA,'candidate_only':True,'project':PROJECT,
        'docker_host':'SYNTHETIC_PIPE','engine_id':'PUBLIC_SYNTHETIC_ENGINE',
        'compose_file':str(model_file),'compose_sha256':selection.digest(model_file.read_bytes()),
        'current_env':str(tmp_path/'generation0.env'),'renewed_env':str(tmp_path/'generation1.env'),
        'current_secrets':str(current),'renewed_secrets':str(renewed),
        'native':{'binary':'PUBLIC_BINARY','binary_sha256':'1'*64,'source_sha':'1'*40,'release_tag':'v1.2.3',
            'helper_image':'python@sha256:'+'2'*64,'control_volume':PROJECT+'-renewal-control',
            'network':PROJECT+'_default','bao_addr':'https://openbao:8200','ca_file':'PUBLIC_CA',
            'minimum_ttl':3600,'current':'/control/generation0','renewed':'/control/generation1',
            'token_file':'/control/session/token'}}
    tx=tmp_path/'tx';tx.mkdir()
    for name in ('intent','result','new_log','rollback_log'):
        p=tx/name;p.write_bytes(b'');cfg[name]=str(p)
    cfg['step_receipts']=[{}]
    for name in ('new_started','new_completed','rollback_started','rollback_completed'):
        p=tx/name;p.write_bytes(b'');cfg['step_receipts'][0][name]=str(p)
    Path(cfg['intent']).write_bytes(b'PUBLIC_ORIGINAL_INTENT')
    Path(cfg['result']).write_bytes(selection.packed({'schema':selection.renewal.SCHEMA,'project':PROJECT,
        'result':'activated','candidate_only':True,'production_admission':False,'automatic_lifecycle':False}))
    path=tx/'config.json';path.write_bytes(selection.packed(cfg))
    (tmp_path/f'.{PROJECT}.renewal.lock').write_bytes(b'')
    roles={row['Service'] for row in states(m)}
    data={role:{'image':'PUBLIC_IMAGE','mounts':[]} for role in roles}
    data_hash=selection.digest(selection.packed(data))
    status['data']=data;status['data_sha256']=data_hash
    monkeypatch.setattr(selection,'_prove',lambda *_a,**_kw:data_hash)
    selection.adopt(path)
    def context_check(**options):
        assert options=={'before_intent':True}
        status['context_calls']+=1
        if status['context_fail']==status['context_calls']:
            raise ValueError('PUBLIC_UNSTABLE_CUSTODY')
        return []
    def inspect(_cfg,_choice,_values,_stack,**options):
        assert options=={'expected_data':data_hash,'require_ready':False}
        return {'model':deepcopy(m),'services':roles,'docker':SimpleNamespace(prefix=['SYNTHETIC']),
                'context':SimpleNamespace(check=context_check),'data_sha256':data_hash}
    monkeypatch.setattr(selection,'_inspect',inspect)
    def authority(_cfg,_project,_prefix,session):
        assert selection.renewal.renewal_staging_guard(cfg).is_file()
        status['events'].append('authority')
        if status['native']=='authority-error':raise ValueError('PRIVATE_SYNTHETIC_AUTHORITY')
        return session+'/token'
    def certificate(_cfg,_project,values,_prefix):
        assert _cfg['current']=='/control/generation1' and _cfg['renewed']==_cfg['current']
        assert _cfg['token_file'].startswith('/control/recovery-session-')
        assert values=={p.name:p.read_bytes() for p in renewed.iterdir()}
        status['events'].append('certificates')
        if status['native']=='unknown':raise ValueError('PRIVATE_SYNTHETIC_UNKNOWN')
        return native.certificate_inspection_result(status['native'])
    monkeypatch.setattr(native,'reauthenticate',authority)
    monkeypatch.setattr(native,'inspect_current_certificates',certificate)
    output=tmp_path/('windows-renewal-'+'a'*32);output.mkdir()
    return SimpleNamespace(root=tmp_path,path=path,cfg=cfg,output=output,state=status,held=held)


@pytest.fixture
def owner(monkeypatch,tmp_path,request):
    if getattr(request,'param',None)=='ntfs':
        if os.name!='nt':pytest.skip('Actual private NTFS synthetic fixture')
        from test_selfhost_windows_inputs import private_fixture
        with private_fixture() as (root,_):
            yield build_owner(monkeypatch,root,real_handles=True)
    else:yield build_owner(monkeypatch,tmp_path)


def prepare(case):return origin.prepare_selected(case.path,case.output,'marty-selfhost-synthetic')


def test_prepare_promotes_after_all_selected_exits_and_inspection_replays_exact_typed_origin(owner):
    before={p.name:p.read_bytes() for p in selection.directory(owner.cfg).iterdir()}
    with selection.selected_inputs(owner.path) as lease:
        result=lease.prepare_expired_current(owner.output,'marty-selfhost-synthetic')
        assert (owner.output/origin.PENDING).read_bytes() and not (owner.output/origin.REFUSED).exists()
        assert result['schema']==origin.PROOF_SCHEMA
        assert result['tokens_examined'] is False and result['whole_current_proof'] is False
        assert (owner.output/'current.started.json').read_bytes()==b''
        assert (owner.output/'current.completed.json').read_bytes()==b''
        with pytest.raises(ValueError):lease.check_current()
        with pytest.raises(ValueError):lease.stage_renewal(owner.output,'marty-selfhost-synthetic')
    assert not (owner.output/origin.PENDING).exists() and (owner.output/origin.REFUSED).is_file()
    assert owner.state['events']==['authority','certificates'] and len(owner.state['promotions'])==1
    assert staging.inspect_failed_current(owner.path)==result
    assert before=={p.name:p.read_bytes() for p in selection.directory(owner.cfg).iterdir()}
    assert not owner.state['holds']
    with pytest.raises(ValueError):lease.prepare_expired_current(owner.output,'marty-selfhost-synthetic')
    with pytest.raises(ValueError),selection.selected_inputs(owner.path):pass
    next_path=Path(selection.decode((owner.output/'intent.json').read_bytes())['config_path'])
    with pytest.raises(ValueError):selection.prepare(next_path,staging_sha256=result['guard_sha256'])


@pytest.mark.parametrize('outcome',['unknown','authority-error','completed'])
def test_uncertain_or_unexpected_success_keeps_guard_without_qualifying_refusal(owner,outcome):
    owner.state['native']=outcome
    with pytest.raises(ValueError):prepare(owner)
    assert selection.renewal.renewal_staging_guard(owner.cfg).is_file()
    assert not owner.state['promotions'] and not (owner.output/origin.REFUSED).exists()
    assert (owner.output/origin.PENDING).read_bytes()==b''
    assert (owner.output/'current.completed.json').read_bytes()==b''
    completed=(owner.output/origin.COMPLETED).read_bytes()
    if outcome=='completed':
        assert selection.decode(completed)['metadata']==native.certificate_inspection_result('completed')
    else:assert completed==b''
    with pytest.raises((ValueError,FileNotFoundError)):staging.inspect_failed_current(owner.path)


@pytest.mark.parametrize('boundary',['selected-file','selected-directory','attempt','config','pending','caller'])
def test_late_outer_input_or_namespace_failure_prevents_promotion(owner,boundary):
    selected=Path(owner.cfg['renewed_secrets'])
    target={'selected-file':selected/'gateway_workload_client_cert','selected-directory':selected,
            'attempt':owner.output,'config':owner.output/'activation/config.private.json',
            'pending':owner.output/origin.PENDING}.get(boundary)
    with pytest.raises(ValueError):
        with selection.selected_inputs(owner.path) as lease:
            lease.prepare_expired_current(owner.output,'marty-selfhost-synthetic')
            if boundary=='caller':raise ValueError('PUBLIC_CALLER_FAILED')
            owner.state['fail_exit']=lambda path:path==target
    assert not owner.state['promotions'] and not (owner.output/origin.REFUSED).exists()
    assert selection.renewal.renewal_staging_guard(owner.cfg).is_file()
    assert (owner.output/origin.PENDING).read_bytes()


@pytest.mark.parametrize('call',[1,2,3,4])
def test_strict_custody_refusal_never_stops_retries_or_claims_preparation(owner,call):
    owner.state['context_fail']=call
    with pytest.raises(ValueError):prepare(owner)
    assert not owner.state['promotions']
    if call==1:
        assert not list(owner.output.iterdir()) and not owner.state['events']
        assert not selection.renewal.renewal_staging_guard(owner.cfg).exists()
    else:
        assert selection.renewal.renewal_staging_guard(owner.cfg).exists()
        assert not (owner.output/origin.REFUSED).exists()


@pytest.mark.parametrize('fault',['guard','selected','config','receipt-operation','receipt-bool','ordinary-current',
    'producer','activation','candidate','extra','date','future-observation','native-pin','pending-only'])
def test_reader_rejects_changed_origin_history_without_new_authority(owner,fault):
    prepare(owner)
    stage=selection.decode((owner.output/'intent.json').read_bytes())
    config=selection.decode(Path(stage['config_path']).read_bytes())
    if fault in ('selected','date','future-observation'):
        if fault=='selected':stage['selected_sha256']='0'*64
        elif fault=='date':stage['certificate_evidence']['certificates']['gateway_workload_client_cert']['not_after']-=1
        else:stage['certificate_evidence']['observed_at']=NOW+1
        for path in (owner.output/'intent.json',selection.renewal.renewal_staging_guard(owner.cfg)):
            path.write_bytes(selection.packed(stage))
        (owner.output/origin.REFUSED).write_bytes(selection.packed(origin.refusal_receipt(stage,config)))
    elif fault=='guard':selection.renewal.renewal_staging_guard(owner.cfg).write_bytes(b'{}')
    elif fault=='config':Path(stage['config_path']).write_bytes(b'{}')
    elif fault in ('receipt-operation','receipt-bool','native-pin'):
        receipt=selection.decode((owner.output/origin.REFUSED).read_bytes())
        if fault=='receipt-operation':receipt['inspection']['operation']='activation-tokens'
        elif fault=='receipt-bool':receipt['inspection']['tokens_examined']=0
        else:receipt['operator']['source_sha']='b'*40
        (owner.output/origin.REFUSED).write_bytes(selection.packed(receipt))
    elif fault=='ordinary-current':(owner.output/'current.started.json').write_bytes(b'{}')
    elif fault=='producer':(owner.output/'prepare.started.json').write_bytes(b'{}')
    elif fault=='activation':Path(config['intent']).write_bytes(b'{}')
    elif fault=='candidate':(Path(config['renewed_secrets'])/'unexpected').write_bytes(b'PUBLIC')
    elif fault=='pending-only':(owner.output/origin.REFUSED).rename(owner.output/origin.PENDING)
    else:(owner.output/'unexpected').write_bytes(b'PUBLIC')
    with pytest.raises((ValueError,KeyError,FileNotFoundError)):staging.inspect_failed_current(owner.path)
    assert owner.state['events']==['authority','certificates']


def test_offline_observation_parses_only_all_allowlisted_public_files(owner,monkeypatch):
    actual=origin.ssl._ssl._test_decode_cert;seen=[]
    def parse(path):
        seen.append(Path(path).name)
        assert Path(path).name in origin.RENEWED_CERT_FILES
        return actual(path)
    monkeypatch.setattr(origin.ssl._ssl,'_test_decode_cert',parse)
    prepare(owner)
    assert set(seen)==origin.RENEWED_CERT_FILES and len(origin.RENEWED_CERT_FILES)==19


@pytest.mark.parametrize('fault',['malformed','no-expired','future-leaf','expired-ca','future-ca','clock-rollback'])
def test_bad_offline_dates_refuse_before_authority_or_guard(owner,monkeypatch,fault):
    actual=origin.ssl._ssl._test_decode_cert
    def parse(path):
        result=actual(path);name=Path(path).name
        if fault=='malformed' and name!='workload_identity_ca_cert':raise ssl.SSLError('PUBLIC_BAD_CERT')
        if fault=='no-expired' and name!=origin.CA_FILE:result['notAfter']='Nov 22 20:00:00 2026 GMT'
        if fault=='future-leaf' and name!=origin.CA_FILE:
            result.update(notBefore='Nov 22 20:00:00 2026 GMT',notAfter='Nov 23 20:00:00 2026 GMT')
        if fault=='expired-ca' and name==origin.CA_FILE:result['notAfter']='Nov 21 19:00:00 2026 GMT'
        if fault=='future-ca' and name==origin.CA_FILE:result['notBefore']='Nov 22 20:00:00 2026 GMT'
        return result
    monkeypatch.setattr(origin.ssl._ssl,'_test_decode_cert',parse)
    if fault=='clock-rollback':
        times=iter((NOW,NOW-1))
        monkeypatch.setattr(origin.time,'time',lambda:next(times))
    with pytest.raises((ValueError,ssl.SSLError)):prepare(owner)
    assert not owner.state['events'] and not list(owner.output.iterdir())
    assert not selection.renewal.renewal_staging_guard(owner.cfg).exists()


def test_initial_current_and_caught_failure_seal_prepare_lease(owner,monkeypatch):
    actual=origin.start
    def initial(cfg,choice,values,record,*args):
        return actual(cfg,choice,values,dict(record,_initial_current_origin=True),*args)
    monkeypatch.setattr(origin,'start',initial)
    with selection.selected_inputs(owner.path) as lease:
        with pytest.raises(ValueError):lease.prepare_expired_current(owner.output,'marty-selfhost-synthetic')
        for call in (lease.check_current,lease.check_configuration,lease.continue_journal):
            with pytest.raises(ValueError):call()
        with pytest.raises(ValueError):lease.prepare_expired_current(owner.output,'marty-selfhost-synthetic')
    assert not owner.state['events'] and not list(owner.output.iterdir())


def recovery_candidate(owner,monkeypatch,*,native_refuses=False):
    """Exercise existing stage/publication owners with explicit native doubles."""
    events=[]
    monkeypatch.setattr(native,'require_recovery_capability',lambda *_args:events.append('capability'))
    def produce(config,current,logical,cycle,image,checkpoint):
        events.append('producer')
        assert logical=='marty-selfhost-synthetic'
        assert selection.renewal.recovery_guard(owner.cfg).is_file()
        for phase in ('prepare','tls','keycloak','export'):
            checkpoint(phase,'started',{})
            if phase in ('prepare','tls','keycloak'):
                item={'id':{'prepare':'b','tls':'c','keycloak':'d'}[phase]*64,
                    'name':PROJECT+'-renew-'+phase+'-'+cycle,
                    'image':image if phase=='tls' else config['native']['helper_image']}
                if phase=='tls':checkpoint(phase,'created',item)
                checkpoint(phase,'helper',item)
            checkpoint(phase,'completed',{})
        return {name:raw+b'\n' for name,raw in current.items()}
    def preflight(_native,_project,old,new,_prefix):
        events.append('candidate-proof')
        assert set(old)==set(new) and any(old[n]!=new[n] for n in old)
        if native_refuses:raise ValueError('PUBLIC_NATIVE_CANDIDATE_REFUSAL')
    monkeypatch.setattr(native,'produce_recovery_generation',produce)
    monkeypatch.setattr(native,'preflight_recovery',preflight)
    root=owner.root/('windows-renewal-'+'e'*32);root.mkdir()
    result=staging.stage_recovery_generation(owner.path,root,'marty-selfhost-synthetic')
    assert result['credential_admission'] is False
    publication=staging.publish_recovery_candidate(owner.path,root)
    assert events==['capability','producer','candidate-proof',
                   'capability','candidate-proof','capability','candidate-proof']
    return root,publication


def test_existing_candidate_native_admission_remains_mandatory(owner,monkeypatch):
    prepare(owner)
    with pytest.raises(ValueError):recovery_candidate(owner,monkeypatch,native_refuses=True)
    root=owner.root/('windows-renewal-'+'e'*32)
    assert (root/'candidate.started.json').read_bytes() and not (root/'candidate.completed.json').read_bytes()
    assert not (root/'publication.json').exists()
    assert selection.renewal.recovery_guard(owner.cfg).is_file()
    assert selection.renewal.renewal_staging_guard(owner.cfg).is_file()


@pytest.mark.parametrize('fault',[None,'date','whole-proof-schema','receipt-operation','producer'])
def test_historical_recovery_seed_replays_typed_origin_and_original_selected_bytes(owner,monkeypatch,fault):
    import selfhost_windows_recovery_journal as journal
    prepare(owner)
    root,publication=recovery_candidate(owner,monkeypatch)
    config=selection.decode((root/'config.private.json').read_bytes())
    model_value=selection.decode(Path(config['compose_file']).read_bytes())
    roles=set(owner.state['data'])
    layers=selection.renewal.dependency_layers(model_value,roles,selection.renewal.owned_roles(model_value,roles))
    env=Path(config['current_env']).read_bytes().splitlines(keepends=True)
    Path(config['renewed_env']).write_bytes(b''.join(
        b'SELFHOST_SECRET_DIR='+Path(config['renewed_secrets']).as_posix().encode()+b'\n'
        if line.startswith(b'SELFHOST_SECRET_DIR=') else line for line in env))
    (root/'activation').mkdir()
    files=[Path(config[name]) for name in ('intent','result','new_log','rollback_log')]
    files += [Path(path) for step in config['step_receipts'] for path in step.values()]
    for path in files:path.write_bytes(b'')
    activation={'schema':'marty.windows-recovery-activation/v1','project':PROJECT,
        'publication_sha256':selection.digest(selection.packed(publication)),
        'data_mounts_before':owner.state['data'],'layers':layers,'rollback_to_expired':False}
    Path(config['intent']).write_bytes(selection.packed(activation))
    Path(config['result']).write_bytes(selection.packed({'schema':activation['schema'],'project':PROJECT,
        'result':'activated-unselected','secret_mounts':1,'data_sha256':owner.state['data_sha256'],
        'guards_retained':True,'rollback_to_expired':False,'credential_admission':False}))
    for index,layer in enumerate(layers):
        for event in ('started','completed'):
            Path(config['step_receipts'][index]['new_'+event]).write_bytes(selection.packed({'roles':layer,'event':event}))
    successor=journal.successor_configuration(config,root)
    (root/'selection.config.private.json').write_bytes(selection.packed(successor));(root/'selection').mkdir()
    for name in ('intent','result','new_log','rollback_log'):Path(successor[name]).write_bytes(b'')
    for step in successor['step_receipts']:
        for path in step.values():Path(path).write_bytes(b'')
    source=selection.directory(owner.cfg)
    raw={p.name:p.read_bytes() for p in source.iterdir()};expected=selection.binding(owner.cfg)
    if fault:
        stage=selection.decode((root/'intent.json').read_bytes())
        failed=selection.decode((owner.output/'intent.json').read_bytes())
        if fault=='date':
            failed['certificate_evidence']['certificates']['gateway_workload_client_cert']['not_after']-=1
            (owner.output/'intent.json').write_bytes(selection.packed(failed))
            (owner.output/origin.REFUSED).write_bytes(selection.packed(origin.refusal_receipt(failed,owner.cfg)))
            stage['failed_proof']['guard_sha256']=selection.digest(selection.packed(failed))
            stage['failed_proof']['receipt_sha256'][origin.REFUSED]=selection.digest((owner.output/origin.REFUSED).read_bytes())
        elif fault=='whole-proof-schema':stage['failed_proof']['schema']='marty.windows-failed-current-proof/v1'
        elif fault=='receipt-operation':
            receipt=selection.decode((owner.output/origin.REFUSED).read_bytes())
            receipt['inspection']['operation']='activation-tokens'
            (owner.output/origin.REFUSED).write_bytes(selection.packed(receipt))
            stage['failed_proof']['receipt_sha256'][origin.REFUSED]=selection.digest(selection.packed(receipt))
        else:
            (owner.output/'prepare.started.json').write_bytes(b'{}')
            stage['failed_proof']['receipt_sha256']['prepare.started.json']=selection.digest(b'{}')
        (root/'intent.json').write_bytes(selection.packed(stage))
    marker={'schema':journal.SCHEMA,'project':PROJECT,'engine_id':owner.cfg['engine_id'],
        'source_dir':str(source),'target_dir':str(owner.root/('.'+PROJECT+'.generation-recovery-'+'e'*32)),
        'source_sha256':{name:selection.digest(body) for name,body in raw.items()},'attempt_dir':str(root),
        'config_sha256':selection.digest(selection.packed(config)),'generation_sequence':1,
        'evidence_sha256':{p.relative_to(root).as_posix():selection.digest(p.read_bytes()) for p in root.rglob('*') if p.is_file()},
        'candidate_only':True}
    raw[journal.INTENT]=selection.packed(marker)
    with ExitStack() as stack:
        if fault:
            with pytest.raises(ValueError):journal.seed(raw,expected,
                {'compose_file':config['compose_file'],'compose_sha256':config['compose_sha256']},marker,stack)
        else:
            result=journal.seed(raw,expected,
                {'compose_file':config['compose_file'],'compose_sha256':config['compose_sha256']},marker,stack)
            assert selection.decode(result['000001.selection.json'])['decision']=='recovered-new'
    assert owner.state['events']==['authority','certificates','authority']


@pytest.mark.parametrize('owner',['ntfs'],indirect=True)
def test_actual_private_ntfs_prepare_and_typed_inspection(owner):
    result=prepare(owner)
    assert result['schema']==origin.PROOF_SCHEMA and result['tokens_examined'] is False
    assert staging.inspect_failed_current(owner.path)==result
    assert (owner.output/origin.REFUSED).is_file() and not (owner.output/origin.PENDING).exists()
    assert owner.state['events']==['authority','certificates']
    assert selection.renewal.renewal_staging_guard(owner.cfg).exists()


@pytest.mark.parametrize('owner',['ntfs'],indirect=True)
@pytest.mark.parametrize('boundary',['generation','lock','config','phase','namespace'])
def test_actual_private_ntfs_late_exit_failure_blocks_refusal_publication(owner,monkeypatch,boundary):
    original=selection.renewal.hold_private_input
    original_generation=selection.renewal.hold_private_generation
    original_namespace=selection.renewal.hold_storage_namespace
    def ready():return (owner.output/origin.PENDING).is_file() and bool((owner.output/origin.PENDING).read_bytes())
    @contextmanager
    def file_hold(path,**kwargs):
        with original(path,**kwargs) as raw:yield raw
        target={'lock':owner.root/f'.{PROJECT}.renewal.lock',
                'config':owner.output/'activation/config.private.json',
                'phase':owner.output/origin.PENDING}.get(boundary)
        if Path(path)==target and ready():raise ValueError('PUBLIC_LATE_NTFS_EXIT')
    @contextmanager
    def generation_hold(*args,**kwargs):
        with original_generation(*args,**kwargs) as value:yield value
        if ready():raise ValueError('PUBLIC_LATE_NTFS_GENERATION_EXIT')
    @contextmanager
    def namespace_hold(path):
        with original_namespace(path):yield
        if Path(path)==owner.output and ready():raise ValueError('PUBLIC_LATE_NTFS_NAMESPACE_EXIT')
    if boundary=='generation':monkeypatch.setattr(selection.renewal,'hold_private_generation',generation_hold)
    elif boundary=='namespace':monkeypatch.setattr(selection.renewal,'hold_storage_namespace',namespace_hold)
    else:monkeypatch.setattr(selection.renewal,'hold_private_input',file_hold)
    with pytest.raises(ValueError):prepare(owner)
    assert not (owner.output/origin.REFUSED).exists() and (owner.output/origin.PENDING).read_bytes()
    assert selection.renewal.renewal_staging_guard(owner.cfg).is_file()
