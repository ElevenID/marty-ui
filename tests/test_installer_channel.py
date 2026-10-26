"""Synthetic Git object and release API tests; no GitHub publication is performed."""
import base64
import copy
import hashlib
import os
from pathlib import Path
import sys
import pytest
import yaml
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_installer_promote import evidence
from test_installer_publish_admission import GitHub
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import installer_channel as c
import installer_release as r
import installer_promote as p


class Git:
    def __init__(self):
        self.head = None
        self.commits = {}
        self.trees = {}
        self.blobs = {}
        self.calls = []
        self.bad_tree = False
        self.bad_parent = False
        self.conflict = False
        self.protected = True

    def tree(self, files):
        entries = []
        for name, raw in sorted(files.items()):
            sha = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            self.blobs[sha] = dict(sha=sha, encoding='base64', size=len(raw), content=base64.b64encode(raw).decode())
            entries.append(dict(path=name, mode='100644', type='blob', sha=sha))
        sha = hashlib.sha1(r.encode(dict(entries=entries))).hexdigest()
        self.trees[sha] = dict(sha=sha, truncated=False, tree=entries)
        return sha

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, copy.deepcopy(body)))
        if path.endswith('/rules/branches/installer-channel'):
            return [dict(type=t) for t in ('deletion','non_fast_forward')] if self.protected else []
        if path == c.REF:
            return None if self.head is None else dict(ref='refs/heads/installer-channel',object=dict(type='commit',sha=self.head))
        if '/git/trees/' in path:
            return copy.deepcopy(self.trees[path.rsplit('/',1)[1].split('?')[0]])
        if '/git/blobs/' in path:
            return copy.deepcopy(self.blobs[path.rsplit('/',1)[1]])
        if method=='POST' and path.endswith('/git/trees'):
            files = {} if 'base_tree' not in body else c.tree_files(self,body['base_tree'])
            for e in body['tree']: files[e['path']] = e['content'].encode()
            if self.bad_tree: files['stable.json'] = pointer('stable',99)
            return dict(sha=self.tree(files))
        if method=='POST' and path.endswith('/git/commits'):
            sha='b'*40
            self.commits[sha]=dict(sha=sha,tree=dict(sha=body['tree']),parents=[dict(sha=s) for s in body['parents']])
            if self.bad_parent: self.commits[sha]['parents']=[dict(sha='f'*40)]
            return dict(sha=sha)
        if '/git/commits/' in path: return copy.deepcopy(self.commits[path.rsplit('/',1)[1]])
        if method=='POST' and path.endswith('/git/refs'):
            assert body['ref']=='refs/heads/installer-channel'
            if self.conflict or self.head is not None: raise ValueError('reference conflict')
            self.head=body['sha'];return {}
        if method=='PATCH' and path.endswith('/git/refs/heads/installer-channel'):
            assert body['force'] is False
            if self.conflict: raise ValueError('non-fast-forward')
            assert self.commits[body['sha']]['parents']==[dict(sha=self.head)]
            self.head=body['sha'];return {}
        raise AssertionError((method,path))


def pointer(channel, generation=1):
    return r.encode(dict(schema='elevenid.installer-channel-pointer/v1',repository=r.REPOSITORY,
                         channel=channel,generation=generation,record_sha256='a'*64))


@pytest.fixture
def prepared(evidence, monkeypatch):
    options,_=evidence
    p.promote(**options)
    accepted=options['output'].read_bytes()
    record=r.channel(accepted,channel_name='stable',previous_bytes=None,promotion_source_sha='d'*40,
                     promotion_run_id=200,promotion_run_attempt=1,now=1000)
    root=options['output'].parent.parent
    for name in ('channel-assets','channel-work','channel-evidence'): (root/name).mkdir(mode=0o700)
    assets=root/'channel-assets'
    raw=r.encode(record)
    context=dict(schema=c.CONTEXT_SCHEMA,repository=r.REPOSITORY,channel='stable',record_sha256=r.digest(raw),
        expected_head=None,previous_pointer_sha256=None,promotion_source_sha='d'*40,promotion_run_id=200,promotion_run_attempt=1)
    for name,value in [('installer-channel.json',raw),('installer-channel-context.json',r.encode(context))]:
        (assets/name).write_bytes(value)
        for suffix in p.SUFFIXES[1:]: (assets/(name+suffix)).write_bytes(b'synthetic proof')
    monkeypatch.setattr(c,'verify',lambda *a,**k: None)
    monkeypatch.setattr(c,'admission',lambda *a,**k: accepted)
    monkeypatch.setattr(c,'prior',lambda *a,**k: None)
    monkeypatch.setattr(c,'publish_generation',lambda *a: 77)
    return dict(client=Git(),work=root/'channel-work',assets=assets,evidence=root/'channel-evidence',
        gh=options['gh'],cosign=options['cosign'],source_sha='a'*40,release_tag='v1.2.3',
        promotion_source_sha='d'*40,promotion_run_id=200,promotion_run_attempt=1,clock=lambda:1001)


def test_initial_cas_and_evidence(prepared):
    result=c.publish(**prepared)
    assert result['commit']=='b'*40 and result['generation']==1
    assert (prepared['evidence']/'channel-cas-intent.json').exists()
    assert (prepared['evidence']/'channel-publication-result.json').exists()
    assert prepared['client'].commits['b'*40]['parents']==[]


def test_existing_parent_preserves_other_channel(prepared):
    client=prepared['client'];tree=client.tree({'nightly.json':pointer('nightly')})
    client.head='e'*40;client.commits[client.head]=dict(sha=client.head,tree=dict(sha=tree),parents=[])
    path=prepared['assets']/'installer-channel-context.json';ctx=r.decode(path.read_bytes());ctx['expected_head']=client.head;path.write_bytes(r.encode(ctx))
    c.publish(**prepared)
    assert client.commits['b'*40]['parents']==[dict(sha='e'*40)]
    assert c.branch(client)[2]['nightly.json']==pointer('nightly')


@pytest.mark.parametrize('fault',['bad_tree','bad_parent','protected'])
def test_no_reference_mutation_on_invalid_objects_or_policy(prepared,fault):
    setattr(prepared['client'],fault,fault!='protected')
    with pytest.raises(ValueError): c.publish(**prepared)
    assert not any(m in ('POST','PATCH') and '/git/refs' in path for m,path,_ in prepared['client'].calls)


def test_conflict_retains_intent_no_force_or_retry(prepared):
    prepared['client'].conflict=True
    with pytest.raises(ValueError): c.publish(**prepared)
    assert (prepared['evidence']/'channel-cas-intent.json').exists()
    assert not (prepared['evidence']/'channel-publication-result.json').exists()
    assert len([1 for m,path,_ in prepared['client'].calls if m=='POST' and path.endswith('/git/refs')])==1


def test_stale_expected_head_refuses_before_mutations(prepared):
    path=prepared['assets']/'installer-channel-context.json';ctx=r.decode(path.read_bytes());ctx['expected_head']='f'*40;path.write_bytes(r.encode(ctx))
    with pytest.raises(ValueError): c.publish(**prepared)
    assert all(m=='GET' for m,_,_ in prepared['client'].calls)


def test_expiry_after_metadata_does_not_update_pointer(prepared,monkeypatch):
    ticks=iter([1001,1001,700000]);prepared['clock']=lambda:next(ticks)
    with pytest.raises(ValueError): c.publish(**prepared)
    assert not any('/git/refs' in path for _,path,_ in prepared['client'].calls)


@pytest.mark.parametrize('generation',[0,-1,True,2**53,1.5])
def test_pointer_integer_matches_consumer(generation):
    with pytest.raises(ValueError): c.pointer(pointer('stable',generation),'stable')


def test_generation_publication_actual_tag_binding(tmp_path):
    tmp_path.chmod(0o700);client=GitHub()
    record=dict(channel='stable',generation=1,promotion_source_sha='d'*40)
    files={stem:b'synthetic '+stem.encode() for stem in ('installer-channel.json','installer-channel.json.sigstore.json','installer-channel.json.provenance.jsonl')}
    assert c.publish_generation(client,record,files,tmp_path)==77
    count=len(client.calls);assert c.publish_generation(client,record,files,tmp_path)==77
    assert all(m=='GET' for m,_,_ in client.calls[count:])
    client.tag='f'*40
    with pytest.raises(ValueError): c.publish_generation(client,record,files,tmp_path)


def test_workflow_trust_and_mandatory_chain():
    root=Path(__file__).resolve().parents[1]
    signer=yaml.safe_load((root/'.github/workflows/installer-promote.yml').read_text())
    assert 'inputs.operation' in signer['jobs']['admit-installer']['if']
    job=signer['jobs']['sign-channel'];assert job['permissions']['contents']=='read'
    assert "github.ref == 'refs/heads/main'" in job['if']
    text=str(job);assert 'installer_channel.py produce' in text and 'sign-blob' in text
    publisher=yaml.safe_load((root/'.github/workflows/installer-publish-channel.yml').read_text())
    assert publisher['concurrency']==dict(group='installer-channel-publication',**{'cancel-in-progress':False})
    job=publisher['jobs']['publish-channel'];assert job['permissions']['contents']=='write'
    assert "github.ref == 'refs/heads/main'" in job['if']
    assert 'installer_channel.py publish' in str(job)


def test_existing_branch_patch_conflict_keeps_intent_and_other_pointer(prepared):
    client=prepared['client'];original={'nightly.json':pointer('nightly')}
    tree=client.tree(original);client.head='e'*40
    client.commits[client.head]=dict(sha=client.head,tree=dict(sha=tree),parents=[])
    path=prepared['assets']/'installer-channel-context.json'
    context=r.decode(path.read_bytes());context['expected_head']=client.head;path.write_bytes(r.encode(context))
    client.conflict=True
    with pytest.raises(ValueError): c.publish(**prepared)
    patches=[body for method,path,body in client.calls if method=='PATCH' and path.endswith('/git/refs/heads/installer-channel')]
    assert patches==[dict(sha='b'*40,force=False)]
    assert (prepared['evidence']/'channel-cas-intent.json').exists()
    assert not (prepared['evidence']/'channel-publication-result.json').exists()
    assert c.branch(client)[2]==original and client.head=='e'*40


@pytest.mark.parametrize('field,value',[('record_sha256','f'*64),('promotion_run_id',201)])
def test_signed_context_cannot_substitute_record_or_invocation(prepared,field,value):
    path=prepared['assets']/'installer-channel-context.json'
    context=r.decode(path.read_bytes());context[field]=value;path.write_bytes(r.encode(context))
    with pytest.raises(ValueError): c.publish(**prepared)
    assert prepared['client'].calls==[]


@pytest.mark.parametrize('changed',[False,True])
def test_producer_binds_current_invocation_and_stable_head(prepared,monkeypatch,changed):
    client=prepared['client'];request=client.request
    def api(method,path,body=None,**kwargs):
        if '/actions/runs/' in path:
            return dict(repository=dict(full_name=r.REPOSITORY),id=200,run_attempt=1,
                path=r.PROMOTION_WORKFLOW,head_sha='d'*40,head_branch='main',event='workflow_dispatch',
                status='in_progress',conclusion=None)
        return request(method,path,body,**kwargs)
    client.request=api
    if changed:
        snapshots=iter([(None,None,{}),('f'*40,None,{})])
        monkeypatch.setattr(c,'branch',lambda *_:next(snapshots))
    output=prepared['work']/'output';output.mkdir(mode=0o700)
    options={k:v for k,v in prepared.items() if k not in ('assets','evidence')}
    if changed:
        with pytest.raises(ValueError): c.produce(**options,output=output)
        assert list(output.iterdir())==[]
    else:
        record=c.produce(**options,output=output)
        context=r.decode((output/'installer-channel-context.json').read_bytes())
        assert context['record_sha256']==r.digest((output/'installer-channel.json').read_bytes())
        assert context['expected_head'] is None and record['generation']==1
        assert context['promotion_run_id']==200
