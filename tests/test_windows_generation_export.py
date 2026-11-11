"""Bounded private chunk protocol, independently of Docker/Windows handles."""
import base64
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

PROJECT='marty-production-synthetic'
MIRROR='/control/next-r4/application-mail-generation'


@pytest.fixture
def transport(monkeypatch):
    values={'empty':b'','leaf_cert':'synthetic\u00e9'.encode(),'a_token':b'SYNTHETIC_PRIVATE_SENTINEL'+b'x'*45000}
    names=sorted(values)
    model=json.dumps({'secrets':{name:{} for name in names}}).encode()
    cfg={'project':PROJECT,'docker_host':'SYNTHETIC_PIPE','engine_id':'SYNTHETIC_ENGINE',
        'compose_file':'synthetic.json','compose_sha256':hashlib.sha256(model).hexdigest(),
        'native':{'control_volume':PROJECT+'-renewal-control','helper_image':'python@sha256:'+'1'*64}}
    @contextmanager
    def hold(path,**kw):
        assert path==Path('synthetic.json') and kw=={'max_bytes':2*1024*1024}
        yield model
    monkeypatch.setattr(native,'hold_private_input',hold)
    class Docker:
        prefix=['docker','--host','SYNTHETIC_PIPE']
        def __init__(self,host,engine):assert (host,engine)==('SYNTHETIC_PIPE','SYNTHETIC_ENGINE')
        def json(self,args):
            assert args==['volume','inspect',PROJECT+'-renewal-control']
            return state['volumes']
    monkeypatch.setattr(renewal,'Docker',Docker)
    state={'volumes':[{'Name':PROJECT+'-renewal-control','Driver':'local','Options':None}],
        'calls':[],'fault':None,'values':values,'manifest':None,'wire_values':None}
    def run(args,**kw):
        assert args[:4]==['docker','--host','SYNTHETIC_PIPE','run']
        assert args[-1]==native.EXPORT_WORKER and '--read-only' in args
        assert args[args.index('--network')+1]=='none'
        assert args[args.index('--log-driver')+1]=='none'
        assert args[args.index('--mount')+1].endswith('dst=/control,readonly,volume-nocopy')
        assert '--pull' in args and 'never' in args and not any('SYNTHETIC_PRIVATE_SENTINEL' in x for x in args)
        assert 0<kw['timeout']<=60
        request=json.loads(kw['stdin_bytes']);state['calls'].append(request)
        assert request['names']==names and request['mirror']==MIRROR
        if state['fault']=='uncertain' or state['fault']=='late-uncertain' and request['part']==1:
            try:
                first=renewal.UncertainComposeMutation('SYNTHETIC_PRIVATE_SENTINEL')
                first.stdout=first.stderr=b'SYNTHETIC_PRIVATE_SENTINEL'
                raise first
            except renewal.UncertainComposeMutation:
                error=renewal.UncertainComposeMutation('synthetic uncertain read')
                error.stdout=error.stderr=b'SYNTHETIC_PRIVATE_SENTINEL';error.owned_processes_zero=True
                raise error
        wire=state['wire_values'] or {k:base64.b64encode(v).decode() for k,v in state['values'].items()}
        payload=json.dumps(wire,sort_keys=True,separators=(',',':')).encode()
        digest=hashlib.sha256(payload).hexdigest()
        if request['part'] is None:
            response={'length':len(payload),'sha256':digest,'parts':(len(payload)+11999)//12000}
            if state['manifest']:response.update(state['manifest'])
        else:
            index=request['part'];assert request['sha256']==digest
            response={'sha256':digest,'part':index,'chunk':payload[index*12000:(index+1)*12000].decode()}
            if state['fault']=='digest':response['sha256']='0'*64
            elif state['fault']=='index':response['part']=index+1
            elif state['fault']=='boolean-index':response['part']=False
            elif state['fault']=='short':response['chunk']=response['chunk'][:-1]
            elif state['fault']=='non-ascii':response['chunk']='\u00e9'
            elif state['fault']=='tamper':response['chunk']='X'+response['chunk'][1:]
        if state['fault']=='duplicate':return CompletedProcess(args,0,b'{"length":1,"length":2}',b'')
        if state['fault']=='bad-json':return CompletedProcess(args,0,b'{"SYNTHETIC_PRIVATE_SENTINEL":',b'')
        return CompletedProcess(args,1 if state['fault']=='return-code' else 0,json.dumps(response).encode(),b'')
    monkeypatch.setattr(renewal,'run_owned_mutation',run)
    return cfg,state


def test_export_returns_exact_empty_utf8_and_multichunk_bytes_without_output(transport,capsys):
    cfg,state=transport
    assert native.export_generation(cfg,MIRROR)==state['values']
    assert len(state['calls'])>3 and capsys.readouterr()==('','')


@pytest.mark.parametrize('fault',['digest','index','boolean-index','short','non-ascii','duplicate','return-code','tamper'])
def test_bad_chunk_or_response_never_returns_a_partial_generation(transport,fault,capsys):
    cfg,state=transport;state['fault']=fault
    with pytest.raises(ValueError):native.export_generation(cfg,MIRROR)
    assert capsys.readouterr()==('','')


@pytest.mark.parametrize('manifest',[{'length':True},{'length':0},{'length':8388609},
    {'parts':True},{'parts':999},{'sha256':'BAD'}])
def test_manifest_bounds_refuse_before_requesting_any_chunk(transport,manifest):
    cfg,state=transport;state['manifest']=manifest
    with pytest.raises(ValueError):native.export_generation(cfg,MIRROR)
    assert len(state['calls'])==1


@pytest.mark.parametrize('fault',['base64','binary','private-key','oversized','unknown-name'])
def test_decoded_material_requires_exact_leaf_inventory_and_utf8_bounds(transport,fault):
    cfg,state=transport
    if fault=='base64':state['wire_values']={**{k:base64.b64encode(v).decode() for k,v in state['values'].items()},'empty':'!!!'}
    elif fault=='unknown-name':state['values']['foreign']=b'PUBLIC'
    else:state['values']['empty']={'binary':b'\0','private-key':b'PRIVATE KEY','oversized':b'x'*65537}[fault]
    with pytest.raises(ValueError):native.export_generation(cfg,MIRROR)


@pytest.mark.parametrize('fault',['uncertain','late-uncertain'])
def test_uncertainty_returns_no_private_tails_chain_or_adapter_chunk_frames(transport,fault):
    cfg,state=transport;state['fault']=fault
    with pytest.raises(renewal.UncertainComposeMutation) as error:native.export_generation(cfg,MIRROR)
    assert error.value.stdout==error.value.stderr==b''
    assert error.value.owned_processes_zero is True
    assert error.value.__context__ is None and error.value.__cause__ is None
    assert 'SYNTHETIC_PRIVATE_SENTINEL' not in repr(error.value.args)
    trace=error.value.__traceback__
    while trace:
        name=trace.tb_frame.f_code.co_name
        assert name not in {'_export_generation','fetch','run'}
        if name=='export_generation':
            assert not {'chunks','payload','encoded','values','p','error'} & trace.tb_frame.f_locals.keys()
        trace=trace.tb_next
    if fault=='late-uncertain':assert len(state['calls'])==3


@pytest.mark.parametrize('fault',['utf8','bad-json'])
def test_private_parser_exceptions_do_not_escape_even_in_exception_objects(transport,fault,capsys):
    cfg,state=transport
    if fault=='utf8':state['values']['empty']=b'SYNTHETIC_PRIVATE_SENTINEL\xff'
    else:state['fault']=fault
    with pytest.raises(ValueError) as error:native.export_generation(cfg,MIRROR)
    assert type(error.value) is ValueError
    assert error.value.__cause__ is None and error.value.__context__ is None
    assert 'SYNTHETIC_PRIVATE_SENTINEL' not in str(error.value)+repr(error.value)+repr(error.value.args)
    assert not hasattr(error.value,'object') and not hasattr(error.value,'doc')
    assert capsys.readouterr()==('','')


def test_deadline_is_rechecked_after_the_held_model_exit(transport,monkeypatch):
    cfg,_state=transport;now=[0];actual=native.hold_private_input
    @contextmanager
    def delayed_exit(*args,**kwargs):
        with actual(*args,**kwargs) as value:yield value
        now[0]=601
    monkeypatch.setattr(native,'hold_private_input',delayed_exit)
    monkeypatch.setattr(native.time,'monotonic',lambda:now[0])
    with pytest.raises(ValueError):native.export_generation(cfg,MIRROR)


@pytest.mark.parametrize('fault',['missing-volume','driver','options','hash','helper','mirror'])
def test_wrong_binding_refuses_before_any_helper(transport,fault):
    cfg,state=transport;mirror=MIRROR
    if fault=='missing-volume':state['volumes']=[]
    elif fault=='driver':state['volumes'][0]['Driver']='nfs'
    elif fault=='options':state['volumes'][0]['Options']={'type':'nfs'}
    elif fault=='hash':cfg['compose_sha256']='0'*64
    elif fault=='helper':cfg['native']['helper_image']='python:latest'
    else:mirror='/control/identity/../generation'
    with pytest.raises(ValueError):native.export_generation(cfg,mirror)
    assert not state['calls']
