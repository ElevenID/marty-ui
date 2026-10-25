"""Authenticated checkpoint return, never fabricated installed acceptance."""
import copy
import os
from pathlib import Path
import sys
import pytest
pytest.importorskip('fcntl')
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_installer_candidate_rendezvous import scenario
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import installer_acceptance_return as p
import installer_acceptance_runner as runner
import installer_release as r
import installer_candidate_rendezvous as t


@pytest.fixture
def ready(scenario):
    args,descriptor,receipt,client=scenario
    t.receive(**args,descriptor=descriptor,receipt_output=receipt)
    auth=args['authorization'].read_bytes();inv=args['inventory'].read_bytes();consumed=receipt.read_bytes()
    context=r.decode(auth);target={k:r.decode(consumed)[k] for k in runner.dispatch.TARGET_FIELDS}
    value=dict(schema=runner.SCHEMA,repository=r.REPOSITORY,workflow=r.acceptance.WORKFLOW,
        **{k:context[k] for k in ('source_sha','release_tag','harness_source_sha','run_id','run_attempt','phase','nonce')},
        target=target,authorization_sha256=r.digest(auth),receipt_sha256=r.digest(consumed),inventory_sha256=r.digest(inv),
        cases={k:('passed' if k=='artifact-verification' else 'blocked') for k in r.acceptance.CASES},
        host_observation_sha256='a'*64,host_preflight='passed',dispatch='failed_or_incomplete',
        trust_info_sha256=None,status_observation_sha256=None,trust_inspection='unavailable',
        acceptance=False,installation_ready=False,observed_at=100000)
    raw=r.encode(value)
    client.items.append(dict(id=789,name=runner.NAME,state='uploaded',size=len(raw),digest='sha256:'+r.digest(raw),
        uploader=dict(id=12345,type='User',login='controller'),created_at='fixed',updated_at='fixed'))
    old_request=client.request
    def request(method,path,body=None):
        if '/actions/runs/' in path:
            return dict(repository=dict(full_name=r.REPOSITORY),id=99,run_attempt=3,path=r.acceptance.WORKFLOW,
                head_sha='c'*40,head_branch='main',event='workflow_dispatch',status='in_progress',conclusion=None)
        return old_request(method,path,body)
    client.request=request;client.checkpoint=raw
    def download(ident,size):
        assert ident==789
        if client.on_download:client.on_download()
        assert size==len(client.checkpoint);return client.checkpoint
    client.download=download
    options=dict(args,receipt=receipt,descriptor=descriptor,output=receipt.parent/'checkpoint')
    return options,client


def test_return_after_grant_expiry_is_historical_consumption_only(ready):
    options,client=ready;options['clock']=lambda:104000
    result=p.receive(**options)
    assert result['acceptance'] is False
    assert options['output'].read_bytes()==client.checkpoint
    evidence=r.decode(Path(str(options['output'])+'.transport.json').read_bytes())
    assert evidence['controller_user_id']==12345 and evidence['asset']['id']==789
    assert not any(method!='GET' for method,_,_ in client.calls[1:])


@pytest.mark.parametrize('kind',['nonce','case','ready','receipt','uploader','original'])
def test_rejects_return_substitution(ready,kind):
    options,client=ready;value=r.decode(client.checkpoint)
    if kind=='nonce':value['nonce']='f'*64
    if kind=='case':value['cases']['issue']='passed'
    if kind=='ready':value['installation_ready']=True
    if kind=='receipt':value['receipt_sha256']='f'*64
    if kind=='uploader':client.items[1]['uploader']['id']=99
    if kind=='original':client.items[0]['digest']='sha256:'+'f'*64
    client.checkpoint=r.encode(value);client.items[1].update(size=len(client.checkpoint),digest='sha256:'+r.digest(client.checkpoint))
    with pytest.raises(ValueError):p.receive(**options)
    assert not options['output'].exists()


def test_changed_asset_and_expired_return_refused(ready):
    options,client=ready;client.on_download=lambda:client.items[1].update(id=790)
    with pytest.raises(ValueError):p.receive(**options)
    client.on_download=None;options['clock']=lambda:107201
    with pytest.raises(ValueError):p.receive(**options)
    assert not options['output'].exists()


def test_workflow_checkpoint_never_uses_acceptance_artifact_name():
    import yaml
    root=Path(__file__).resolve().parents[1]
    workflow=yaml.safe_load((root/'.github/workflows/installer-acceptance.yml').read_text())
    # PyYAML 1.1 treats the unchanged unquoted on key as True.
    trigger=workflow.get('on',workflow.get(True))
    assert trigger['workflow_dispatch']['inputs']['execute']['default'] is False
    steps=workflow['jobs']['prepare-staged-grant']['steps']
    step=next(s for s in steps if s.get('name')=='Refuse incomplete execution as installed acceptance')
    assert 'exit 1' in step['run'] and step['if']=='inputs.execute'
    assert any(s.get('with',{}).get('name','').startswith('installer-incomplete-checkpoint-') for s in steps)
    assert not any(s.get('with',{}).get('name','').startswith('installer-acceptance-staged-') for s in steps)


def test_production_transport_allows_only_exact_read_only_run_endpoint(monkeypatch):
    client=t.Client('synthetic-token');calls=[]
    monkeypatch.setattr(client,'_read',lambda url,**kwargs:(calls.append((url,kwargs)) or b'{"id":99}'))
    assert client.request('GET',t.REPO+'/actions/runs/99')==dict(id=99)
    assert calls==[('https://api.github.com'+t.REPO+'/actions/runs/99',dict(method='GET',body=None))]
    for method,path,body in [('POST',t.REPO+'/actions/runs/99',None),('GET',t.REPO+'/actions/runs/99',{}),
        ('GET',t.REPO+'/actions/runs/0',None),('GET',t.REPO+'/actions/runs/099',None),
        ('GET',t.REPO+'/actions/runs/99/jobs',None),('GET',t.REPO+'/actions/runs/99?token=x',None),
        ('GET','/repos/other/repo/actions/runs/99',None),('GET',t.REPO+'/actions/runs/'+str(2**53),None)]:
        with pytest.raises(ValueError):client.request(method,path,body)
    assert len(calls)==1
