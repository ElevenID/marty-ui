"""Private NTFS transport bounds for fresh scoped authority, no real Docker."""
import hashlib
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from subprocess import CompletedProcess

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import selfhost_windows_renewal as renewal
import selfhost_windows_renewal_native as native
from test_selfhost_windows_inputs import private_fixture

PROJECT='marty-production-synthetic'
SESSION='/control/recovery-session-'+'a'*32


@contextmanager
def transport(monkeypatch):
    with private_fixture() as (root,_):
        binary=root/'operator';binary.write_bytes(b'PUBLIC_SYNTHETIC_NATIVE')
        ca=root/'ca.crt';ca.write_bytes(b'PUBLIC_SYNTHETIC_CA')
        cfg={'control_volume':PROJECT+'-renewal-control','network':PROJECT+'_default',
            'bao_addr':'https://openbao:8200','binary':str(binary),'ca_file':str(ca),
            'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'source_sha':'1'*40,
            'release_tag':'v1.2.3','helper_image':'python@sha256:'+'2'*64}
        volume={'Name':cfg['control_volume'],'Driver':'local','Options':None}
        calls=[]
        def inspect(args,**_kw):
            assert args[-3:]==['volume','inspect',cfg['control_volume']]
            return CompletedProcess(args,0,json.dumps([volume]).encode(),b'')
        def run(args,**kw):
            calls.append((args,kw))
            request=json.loads(kw['stdin_bytes'])
            assert request['session_dir']==SESSION and request['binary_sha256']==cfg['binary_sha256']
            assert all('PUBLIC_SYNTHETIC_NATIVE' not in arg for arg in args)
            assert '--read-only' in args and '--pull' in args and 'never' in args
            assert args[args.index('--network')+1]==cfg['network']
            return CompletedProcess(args,0,json.dumps({'authority':True,'policy_count':21,'token_file':SESSION+'/token'}).encode(),b'')
        monkeypatch.setattr(native.subprocess,'run',inspect)
        monkeypatch.setattr(renewal,'run_owned_mutation',run)
        yield cfg,volume,calls


def test_scoped_authority_uses_verified_asset_and_only_returns_private_uri(monkeypatch):
    with transport(monkeypatch) as (cfg,_volume,calls):
        assert native.reauthenticate(cfg,PROJECT,['docker','--host','SYNTHETIC'],SESSION)==SESSION+'/token'
        assert len(calls)==1


@pytest.mark.parametrize('bad',['volume-name','network','http','image','binary','source','tag','session'])
def test_invalid_scoped_binding_refuses_before_helper(monkeypatch,bad):
    with transport(monkeypatch) as (cfg,_volume,calls):
        session=SESSION
        if bad=='volume-name':cfg['control_volume']='foreign-control'
        elif bad=='network':cfg['network']='foreign_default'
        elif bad=='http':cfg['bao_addr']='http://openbao:8200'
        elif bad=='image':cfg['helper_image']='python:latest'
        elif bad=='binary':cfg['binary_sha256']='0'*64
        elif bad=='source':cfg['source_sha']='unknown'
        elif bad=='tag':cfg['release_tag']='latest'
        else:session='/control/identity/../token'
        with pytest.raises(ValueError):native.reauthenticate(cfg,PROJECT,['docker','--host','SYNTHETIC'],session)
        assert not calls


@pytest.mark.parametrize('bad',['absent','driver','options'])
def test_missing_or_nonlocal_control_never_auto_creates_volume(monkeypatch,bad):
    with transport(monkeypatch) as (cfg,volume,calls):
        if bad=='absent':
            monkeypatch.setattr(native.subprocess,'run',lambda args,**_kw:CompletedProcess(args,1,b'',b''))
        elif bad=='driver':volume['Driver']='remote'
        else:volume['Options']={'type':'nfs'}
        with pytest.raises(ValueError):native.reauthenticate(cfg,PROJECT,['docker','--host','SYNTHETIC'],SESSION)
        assert not calls
