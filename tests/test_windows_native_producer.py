"""Fixed native producer command/phase ownership; no Docker or credentials."""
import hashlib
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from subprocess import CompletedProcess

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import selfhost_windows_renewal as renewal
import selfhost_windows_renewal_native as native


@pytest.fixture
def producer(monkeypatch):
    project='marty-production-synthetic';cycle='a'*32
    binary=b'PUBLIC_SYNTHETIC_OPERATOR'
    cfg={'project':project,'docker_host':'SYNTHETIC_PIPE','engine_id':'SYNTHETIC_ENGINE',
        'native':{'binary':'synthetic-tool','ca_file':'synthetic-ca','binary_sha256':hashlib.sha256(binary).hexdigest(),
            'source_sha':'1'*40,'release_tag':'v1.2.3','minimum_ttl':3600,
            'helper_image':'python@sha256:'+'2'*64,'control_volume':project+'-renewal-control',
            'network':project+'_default','bao_addr':'https://openbao:8200',
            'renewed':'/control/windows-renewal-'+cycle+'/generation',
            'token_file':'/control/recovery-session-'+cycle+'/token'}}
    current={'field_'+str(n):b'SYNTHETIC_PRIVATE_CURRENT' for n in range(40)}
    changed={n:(value if n=='field_0' else b'SYNTHETIC_PRIVATE_RENEWED') for n,value in current.items()}
    image='registry/services@sha256:'+'3'*64;events=[];calls=[];state={'fault':None}
    @contextmanager
    def hold(path,**_kw):yield binary if path.name=='synthetic-tool' else b'PUBLIC_CA'
    monkeypatch.setattr(native,'hold_private_input',hold)
    class Docker:
        prefix=['docker','--host','SYNTHETIC_PIPE']
        def __init__(self,*_args):pass
        def json(self,args):
            assert args[0]=='inspect';name=args[1]
            item={'Id':'c'*64,'Name':'/'+name,'RestartCount':0,'State':{'Status':'exited','ExitCode':0},
                'Config':{'Image':image if '-tls-' in name else cfg['native']['helper_image'],
                    'Labels':{'marty.windows.renewal':cycle}},'HostConfig':{'LogConfig':{'Type':'none'}}}
            if state['fault']=='foreign-helper':item['Config']['Labels']['marty.windows.renewal']='b'*32
            if state['fault']=='rebound-tls' and '-tls-' in name:item['Id']='d'*64
            return [item]
    monkeypatch.setattr(renewal,'Docker',Docker)
    def run(args,**kw):
        command=args[3];calls.append(args)
        assert args[:3]==Docker.prefix
        assert not any('SYNTHETIC_PRIVATE_CURRENT' in a for a in args)
        if command in {'run','create'}:
            assert '--name' in args and '--rm' not in args and '--pull' in args and 'never' in args
            assert args[args.index('--log-driver')+1]=='none' and '--read-only' in args
        if state['fault']=='uncertain':
            error=renewal.UncertainComposeMutation('SYNTHETIC_PRIVATE_CURRENT')
            error.stdout=error.stderr=b'SYNTHETIC_PRIVATE_CURRENT';error.owned_processes_zero=True
            raise error
        if command=='create':return CompletedProcess(args,0,b'c'*64,b'')
        if command=='wait':return CompletedProcess(args,0,b'7' if state['fault']=='tls-exit' else b'0',b'')
        if command in {'start','rm'}:return CompletedProcess(args,0,b'',b'')
        assert command=='run'
        request=json.loads(kw['stdin_bytes'])
        state.setdefault('requests', []).append(request)
        if args[-1]==native.PRODUCER_PREPARE:
            assert request['root']=='/control/windows-renewal-'+cycle
            assert args[args.index('--network')+1]=='none'
            value={'prepared':True}
        else:
            assert args[-1]==native.PRODUCER_ASSEMBLE and request['files']==40
            value={'files':40,'changed_files':39,'native_verified':True}
            if request.get('recovery') and state['fault']!='missing-recovery-receipt':value['recovery']=True
        return CompletedProcess(args,0,json.dumps(value).encode(),b'')
    monkeypatch.setattr(renewal,'run_owned_mutation',run)
    monkeypatch.setattr(native,'export_generation',lambda *_a:changed)
    def checkpoint(phase,event,metadata):events.append((phase,event,metadata))
    return cfg,current,cycle,image,checkpoint,events,calls,state


def invoke(producer):
    cfg,current,cycle,image,checkpoint,*_=producer
    return native.produce_generation(cfg,current,'marty-selfhost-synthetic',cycle,image,checkpoint)


def test_fixed_producers_have_named_custody_and_complete_only_after_removal(producer,capsys):
    values=invoke(producer);_cfg,_current,_cycle,_image,_cp,events,calls,_state=producer
    assert len(values)==40 and capsys.readouterr()==('','')
    assert [phase for phase,event,_ in events if event=='completed']==['prepare','tls','keycloak','export']
    assert sum(args[3]=='rm' for args in calls)==3
    assert [event for phase,event,_ in events if phase=='tls']==['started','created','helper','completed']


@pytest.mark.parametrize('fault', [None, 'missing-recovery-receipt', 'short-ttl'])
def test_recovery_producer_requires_explicit_admission_receipt(producer, fault):
    cfg,current,cycle,image,checkpoint,events,calls,state=producer
    state['fault']=fault
    if fault=='short-ttl':cfg['native']['minimum_ttl']=3599
    def recover():
        return native.produce_recovery_generation(cfg,current,'marty-selfhost-synthetic',cycle,image,checkpoint)
    if fault:
        with pytest.raises(ValueError):recover()
        assert not any(phase=='export' for phase,_,_ in events)
        if fault=='short-ttl':assert not calls
    else:
        assert len(recover())==40
        assert state['requests'][-1]['recovery'] is True
        assert [phase for phase,event,_ in events if event=='completed']==['prepare','tls','keycloak','export']


@pytest.mark.parametrize('fault',['uncertain','tls-exit','foreign-helper','rebound-tls'])
def test_unknown_or_invalid_helper_never_advances_or_removes_unproved_work(producer,fault):
    producer[-1]['fault']=fault
    with pytest.raises((ValueError,renewal.UncertainComposeMutation)) as error:invoke(producer)
    assert not any(phase=='export' for phase,_event,_ in producer[5])
    assert error.value.__context__ is None and error.value.__cause__ is None
    assert 'SYNTHETIC_PRIVATE' not in repr(error.value.args)
    if fault=='uncertain':
        assert error.value.stdout==error.value.stderr==b'' and error.value.owned_processes_zero
        assert not any(args[3]=='rm' for args in producer[6])
    if fault=='rebound-tls':
        assert sum(args[3]=='rm' for args in producer[6])==1 # prepare only
        assert not any(phase=='tls' and event=='helper' for phase,event,_ in producer[5])


@pytest.mark.parametrize('field',['project','helper','binary','mirror'])
def test_invalid_producer_binding_refuses_before_any_command(producer,field):
    cfg=producer[0]
    if field=='project':cfg['project']='foreign'
    elif field=='helper':cfg['native']['helper_image']='python:latest'
    elif field=='binary':cfg['native']['binary_sha256']='0'*64
    else:cfg['native']['renewed']='/control/identity'
    with pytest.raises(ValueError):invoke(producer)
    assert not producer[6]
