"""Mock transport contracts, never remote mutation or acceptance evidence."""
import copy
import io
import json
import os
from pathlib import Path
import sys
import urllib.error
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import installer_candidate_rendezvous as t
import installer_candidate_receipt_upload as uploader
import installer_candidate_grant_receive as grant_receiver
import installer_candidate_initial_grant as initial_grant
import installer_release as r
pytestmark=pytest.mark.skipif(os.name!="posix",reason="private Linux output contract")

class Fake:
    def __init__(self): self.remote=None; self.items=[]; self.raw=b""; self.calls=[]; self.on_download=None
    def request(self,method,path,body=None):
        self.calls.append((method,path,body))
        if method=="POST": self.remote=dict(body,id=123,author=dict(id=41898282)); return copy.deepcopy(self.remote)
        return copy.deepcopy(self.items if "/assets?" in path else self.remote)
    def download(self,asset_id,size):
        assert asset_id==456 and size==len(self.raw)
        if self.on_download: self.on_download()
        return self.raw

@pytest.fixture
def scenario(tmp_path):
    tmp_path.chmod(0o700)
    fixture=json.loads((Path(__file__).resolve().parents[1]/"rust/crates/deployment-catalog/tests/fixtures/installer-candidate-records.json").read_text())
    a,i=fixture["authorization"].encode(),fixture["inventory"].encode()
    auth,inv=tmp_path/"authorization",tmp_path/"inventory"
    auth.write_bytes(a); inv.write_bytes(i)
    client=Fake()
    args=dict(client=client,authorization=auth,inventory=inv,harness_source_sha="c"*40,
              run_id=99,run_attempt=3,controller_user_id=12345,clock=lambda:100000)
    descriptor=tmp_path/"descriptor"
    t.prepare(**args,descriptor_output=descriptor)
    context={key:r.decode(a)[key] for key in r.CONTEXT_FIELDS}
    receipt=r.controller_consumption(a,i,expected=context,guest_id="12345678-1234-4234-8234-123456789abc",
        disk_id="d"*64,engine_id="test-engine-12345678",installation_id="22345678-1234-4234-8234-123456789abc",
        consumed_at=100000,now=100000)
    client.raw=r.encode(receipt)
    client.items=[dict(id=456,name=t.RECEIPT,state="uploaded",size=len(client.raw),digest="sha256:"+r.digest(client.raw),
        uploader=dict(id=12345,type="User",login="controller"),created_at="fixed",updated_at="fixed")]
    return args,descriptor,tmp_path/"receipt",client

def receive(scenario):
    args,descriptor,out,client=scenario
    return t.receive(**args,descriptor=descriptor,receipt_output=out)

def test_create_bound_draft_and_receive_exact_bytes(scenario):
    args,descriptor,out,client=scenario
    result=receive(scenario)
    assert result==r.decode(client.raw) and out.read_bytes()==client.raw
    d=r.decode(descriptor.read_bytes()); assert d["release"]["id"]==123
    assert client.remote["draft"] is True and client.remote["prerelease"] is True
    assert Path(str(descriptor)+".intent.json").is_file()
    assert out.stat().st_mode & 0o777==0o600
    evidence=r.decode(Path(str(out)+".transport.json").read_bytes())
    assert evidence["asset"]["id"]==456 and evidence["asset"]["uploader_id"]==12345
    assert evidence["receipt_sha256"]==r.digest(client.raw)
    assert "uploader" not in evidence["asset"] and "login" not in json.dumps(evidence)
    with pytest.raises(FileExistsError): t.prepare(**args,descriptor_output=descriptor)
    assert sum(method=="POST" for method,_,_ in client.calls)==1


def test_published_grant_receipt_transport_keeps_phase_binding(scenario):
    args,_,_,client=scenario
    auth=r.decode(args['authorization'].read_bytes());auth['phase']='published'
    published=r.encode(auth)
    args['authorization'].write_bytes(published)
    descriptor=args['authorization'].parent/'published-descriptor'
    output=args['authorization'].parent/'published-receipt'
    t.prepare(**args,descriptor_output=descriptor)
    context={key:auth[key] for key in r.CONTEXT_FIELDS}
    receipt=r.encode(r.controller_consumption(published,args['inventory'].read_bytes(),expected=context,
        guest_id='12345678-1234-4234-8234-123456789abc',disk_id='d'*64,
        engine_id='test-engine-12345678',installation_id='22345678-1234-4234-8234-123456789abc',
        consumed_at=100000,now=100000))
    client.raw=receipt
    client.items[0].update(size=len(receipt),digest='sha256:'+r.digest(receipt))
    result=t.receive(**args,descriptor=descriptor,receipt_output=output)
    assert result['phase']=='published' and output.read_bytes()==receipt

@pytest.mark.parametrize("field,value",[("id",True),("size",65537),("name","other"),("state","starter"),("digest","sha256:"+"0"*64)])
def test_wrong_asset_refused(scenario,field,value):
    scenario[3].items[0][field]=value
    with pytest.raises(ValueError): receive(scenario)
    assert not scenario[2].exists()

@pytest.mark.parametrize("field,value",[("id",7),("type","Bot"),("login","github-actions[bot]")])
def test_wrong_uploader_refused(scenario,field,value):
    scenario[3].items[0]["uploader"][field]=value
    with pytest.raises(ValueError): receive(scenario)

def test_asset_replacement_and_draft_publication_refused(scenario):
    client=scenario[3]
    client.on_download=lambda:client.items[0].update(id=457)
    with pytest.raises(ValueError): receive(scenario)
    client.items[0]["id"]=456
    client.on_download=lambda:client.remote.update(draft=False)
    with pytest.raises(ValueError): receive(scenario)
    assert not scenario[2].exists()

def test_receipt_context_substitution_refused(scenario):
    client=scenario[3]; receipt=r.decode(client.raw); receipt["nonce"]="b"*64
    client.raw=r.encode(receipt); client.items[0].update(size=len(client.raw),digest="sha256:"+r.digest(client.raw))
    with pytest.raises(ValueError): receive(scenario)

def test_poll_timeout_is_bounded(scenario):
    args,descriptor,out,client=scenario; client.items=[]; now=[100000]
    args["clock"]=lambda:now[0]
    def sleep(seconds): now[0]+=seconds
    with pytest.raises(ValueError,match="deadline"):
        t.receive(**args,descriptor=descriptor,receipt_output=out,sleep=sleep)
    assert now[0]==100900 and not out.exists()

def test_shared_bot_and_wrong_run_refused_before_remote(scenario):
    args,_,out,client=scenario
    for replacement in (dict(controller_user_id=t.SHARED_ACTIONS_BOT),dict(run_attempt=4)):
        changed=dict(args,**replacement)
        count=len(client.calls)
        with pytest.raises(ValueError): t.prepare(**changed,descriptor_output=out)
        assert len(client.calls)==count

def test_failed_create_keeps_intent_and_never_retries(scenario):
    args,_,out,client=scenario
    def failure(*_): raise ValueError("uncertain")
    client.request=failure
    with pytest.raises(ValueError): t.prepare(**args,descriptor_output=out)
    assert Path(str(out)+".intent.json").is_file() and not out.exists()
    with pytest.raises(FileExistsError): t.prepare(**args,descriptor_output=out)

class Response(io.BytesIO):
    def read1(self,n): return self.read(n)

class Opener:
    def __init__(self,target,payload): self.target=target; self.payload=payload; self.requests=[]
    def open(self,request,timeout):
        self.requests.append(request)
        if len(self.requests)==1:
            raise urllib.error.HTTPError(request.full_url,302,"redirect",{"Location":self.target},None)
        return Response(self.payload)


def test_published_release_metadata_bound_is_exact_and_endpoint_specific():
    class Direct:
        def __init__(self, payload):
            self.payload = payload
            self.requests = []
        def open(self, request, timeout):
            self.requests.append(request)
            return Response(self.payload)
    path = t.REPO + "/releases/tags/v1.1.263-nightly.20261027.40597099479"
    prefix, suffix = b'{"x":"', b'"}'
    exact = prefix + b"a" * (t.MAX_PUBLISHED_RELEASE_METADATA_BYTES
                            - len(prefix) - len(suffix)) + suffix
    assert len(exact) == t.MAX_PUBLISHED_RELEASE_METADATA_BYTES
    client = t.Client("synthetic-token")
    client.opener = Direct(exact)
    assert len(client.request("GET", path)["x"]) > t.MAX_BYTES
    assert len(client.opener.requests) == 1
    request = client.opener.requests[0]
    assert request.full_url == "https://api.github.com" + path
    assert request.get_method() == "GET" and request.data is None
    assert request.get_header("Authorization") == "Bearer synthetic-token"

    client.opener = Direct(exact + b" ")
    with pytest.raises(ValueError, match="transport response exceeds bound"):
        client.request("GET", path)
    assert len(client.opener.requests) == 1

    client.opener = Direct(prefix + b"a" * (t.MAX_BYTES - len(prefix) - len(suffix) + 1) + suffix)
    with pytest.raises(ValueError, match="transport response exceeds bound"):
        client.request("GET", t.REPO + "/releases/123")
    with pytest.raises(ValueError, match="transport response exceeds bound"):
        t.json_bytes(prefix + b"a" * (t.MAX_BYTES - len(prefix) - len(suffix) + 1) + suffix)

    client.opener = Direct(b"{}")
    for method, candidate, body in (
        ("POST", path, {"unexpected": True}),
        ("GET", "https://evil.example" + path, None),
        ("GET", t.REPO + "/other/tags/v1.2.3", None),
    ):
        with pytest.raises(ValueError):
            client.request(method, candidate, body)
    assert client.opener.requests == []

    observed = []
    def read(url, **kwargs):
        observed.append((url, kwargs["maximum"]))
        return b"{}"
    client._read = read
    client.request("GET", path + "/extra")
    assert observed == [("https://api.github.com" + path + "/extra", t.MAX_BYTES)]

def test_download_drops_bearer_on_fixed_release_host():
    client=t.Client("synthetic-token")
    client.opener=Opener("https://release-assets.githubusercontent.com/fixed?signature=opaque",b"abc")
    assert client.download(456,3)==b"abc"
    first,second=client.opener.requests
    assert first.get_header("Authorization")=="Bearer synthetic-token"
    assert second.get_header("Authorization") is None

@pytest.mark.parametrize("target",["https://evil.example/file","http://release-assets.githubusercontent.com/file",
    "https://user@release-assets.githubusercontent.com/file","https://release-assets.githubusercontent.com:444/file"])
def test_untrusted_redirect_refused(target):
    client=t.Client("synthetic-token"); client.opener=Opener(target,b"abc")
    with pytest.raises(ValueError): client.download(456,3)
    assert len(client.opener.requests)==1

def test_oversized_download_refused():
    client=t.Client("synthetic-token")
    client.opener=Opener("https://release-assets.githubusercontent.com/fixed",b"abcd")
    with pytest.raises(ValueError): client.download(456,3)

def test_failed_receipt_write_preserves_transport_evidence(scenario,monkeypatch):
    out=scenario[2]; original=t.write_exclusive
    def fail_receipt(path,raw):
        if path==out: raise OSError("synthetic output failure")
        return original(path,raw)
    monkeypatch.setattr(t,"write_exclusive",fail_receipt)
    with pytest.raises(OSError): receive(scenario)
    assert Path(str(out)+".transport.json").is_file() and not out.exists()
    monkeypatch.setattr(t,"write_exclusive",original)
    with pytest.raises(FileExistsError): receive(scenario)
    assert not out.exists()


def upload_scenario(scenario,monkeypatch):
    args,descriptor,_,client=scenario
    receipt=r.decode(client.raw)
    ledger=descriptor.parent/(receipt['nonce']+'.json')
    ledger.write_bytes(client.raw)
    monkeypatch.setattr(uploader,'authenticate',lambda authorization,inventory,assets,gh,cosign,runner:
        (authorization.read_bytes(),inventory.read_bytes()))
    client.items=[]
    client.whoami=lambda:dict(id=12345,type='User',login='controller')
    original=client.request
    def request(method,path,body=None):
        if '/actions/runs/' in path:
            return dict(repository=dict(full_name=r.REPOSITORY),id=99,run_attempt=3,
                path=r.acceptance.WORKFLOW,head_sha='c'*40,head_branch='main',
                event='workflow_dispatch',status='in_progress',conclusion=None)
        return original(method,path,body)
    client.request=request
    def upload(release_id,raw):
        assert release_id==123 and raw==ledger.read_bytes()
        client.items=[dict(id=456,name=t.RECEIPT,state='uploaded',size=len(raw),
            digest='sha256:'+r.digest(raw),uploader=dict(id=12345,type='User',login='controller'),
            created_at='fixed',updated_at='fixed')]
        client.raw=raw
        client.calls.append(('UPLOAD',release_id,None))
        return copy.deepcopy(client.items[0])
    client.upload_receipt=upload
    return dict(args,descriptor=descriptor,ledger=ledger,output=descriptor.parent/'upload',
        assets=descriptor.parent,gh=descriptor.parent/'gh',cosign=descriptor.parent/'cosign'),client


def test_controller_upload_exact_durable_ledger(scenario,monkeypatch):
    kwargs,client=upload_scenario(scenario,monkeypatch)
    result=uploader.upload(**kwargs)
    assert result['receipt_sha256']==r.digest(client.raw)
    assert r.decode(kwargs['output'].read_bytes())==result
    assert (kwargs['ledger'].parent/(r.decode(kwargs['ledger'].read_bytes())['nonce']+'.upload-intent.json')).is_file()
    assert sum(method=='UPLOAD' for method,_,_ in client.calls)==1
    with pytest.raises(ValueError,match='already has assets'): uploader.upload(**kwargs)
    assert sum(method=='UPLOAD' for method,_,_ in client.calls)==1


def test_controller_upload_wrong_actor_and_existing_asset_refused(scenario,monkeypatch):
    kwargs,client=upload_scenario(scenario,monkeypatch)
    client.whoami=lambda:dict(id=12,type='User',login='other')
    with pytest.raises(ValueError): uploader.upload(**kwargs)
    intent=kwargs['ledger'].parent/(r.decode(client.raw)['nonce']+'.upload-intent.json')
    assert not intent.exists()
    client.whoami=lambda:dict(id=12345,type='User',login='controller')
    client.items=[dict(name='unexpected')]
    with pytest.raises(ValueError): uploader.upload(**kwargs)
    assert not intent.exists()


def test_controller_upload_uncertain_post_keeps_intent(scenario,monkeypatch):
    kwargs,client=upload_scenario(scenario,monkeypatch)
    def uncertain(*_): raise ValueError('uncertain')
    client.upload_receipt=uncertain
    with pytest.raises(ValueError): uploader.upload(**kwargs)
    assert (kwargs['ledger'].parent/(r.decode(client.raw)['nonce']+'.upload-intent.json')).is_file()
    assert not kwargs['output'].exists()
    with pytest.raises(FileExistsError): uploader.upload(**dict(kwargs,output=kwargs['output'].parent/'alternate'))


def test_controller_upload_changed_download_refused(scenario,monkeypatch):
    kwargs,client=upload_scenario(scenario,monkeypatch)
    client.on_download=lambda:setattr(client,'raw',b'wrong')
    with pytest.raises(ValueError): uploader.upload(**kwargs)
    assert (kwargs['ledger'].parent/(r.decode(kwargs['ledger'].read_bytes())['nonce']+'.upload-intent.json')).is_file()
    assert not kwargs['output'].exists()


def test_controller_upload_expired_during_preflight_retains_intent(scenario,monkeypatch):
    kwargs,client=upload_scenario(scenario,monkeypatch)
    grant=r.decode(kwargs['authorization'].read_bytes())
    moment=[100000]
    kwargs['clock']=lambda:moment[0]
    original=client.request
    asset_reads=[0]
    def slow(method,path,body=None):
        value=original(method,path,body)
        if '/assets?' in path:
            asset_reads[0]+=1
            if asset_reads[0]==2:moment[0]=grant['expires_at']-t.RESERVE
        return value
    client.request=slow
    with pytest.raises(ValueError,match='expired before controller upload'):
        uploader.upload(**kwargs)
    assert (kwargs['ledger'].parent/(r.decode(client.raw)['nonce']+'.upload-intent.json')).is_file()
    assert sum(method=='UPLOAD' for method,_,_ in client.calls)==0


def test_upload_http_boundary_is_fixed_and_never_redirects():
    client=t.Client('synthetic-token')
    class UploadResponse(io.BytesIO):
        status=201
    class UploadOpener:
        def __init__(self): self.requests=[]
        def open(self,request,timeout):
            self.requests.append(request)
            return UploadResponse(b'{}')
    client.opener=UploadOpener()
    assert client.upload_receipt(123,b'ledger')=={}
    req=client.opener.requests[0]
    assert req.full_url=='https://uploads.github.com/repos/ElevenID/marty-ui/releases/123/assets?name=installer-controller-consumption.json'
    assert req.get_method()=='POST' and req.data==b'ledger'
    assert req.get_header('Authorization')=='Bearer synthetic-token'
    assert req.get_header('Content-type')=='application/octet-stream'


def grant_scenario(scenario,monkeypatch):
    import hashlib, zipfile
    args,descriptor,_,client=scenario
    home=descriptor.parent
    authorization=args['authorization'];inventory=args['inventory']
    nonce=r.decode(client.raw)['nonce']
    ledger=home/(nonce+'.json');ledger.write_bytes(client.raw)
    context={key:r.decode(authorization.read_bytes())[key] for key in r.CONTEXT_FIELDS}
    target={key:r.decode(client.raw)[key] for key in ('guest_id','disk_id','engine_id','installation_id')}
    context_file=home/'context.json';context_file.write_bytes(r.encode(context))
    target_file=home/'target.json';target_file.write_bytes(r.encode(target))
    transport=r.encode(dict(receipt_sha256=r.digest(client.raw),authorization_sha256=r.digest(authorization.read_bytes()),
        inventory_sha256=r.digest(inventory.read_bytes()),context_sha256=r.candidate_context_sha256(context),
        controller_user_id=12345))
    members={name:b'proof' for name in grant_receiver.NAMES}
    members.update({'candidate-authorization.json':authorization.read_bytes(),
        'controller-consumption.json':client.raw,'controller-transport.json':descriptor.read_bytes(),
        'controller-consumption.json.transport.json':transport})
    raw_zip=io.BytesIO()
    with zipfile.ZipFile(raw_zip,'w') as bundle:
        for name,data in members.items():bundle.writestr(name,data)
    zip_bytes=raw_zip.getvalue()
    item=dict(id=789,name='installer-candidate-execution-grant-99-3',size_in_bytes=len(zip_bytes),
        digest='sha256:'+hashlib.sha256(zip_bytes).hexdigest(),expired=False,
        created_at='fixed',updated_at='fixed',workflow_run=dict(id=99,repository_id=1140864197,
        head_repository_id=1140864197,head_branch='main',head_sha='c'*40))
    class API:
        token='synthetic-token'
        def __init__(self):self.item=copy.deepcopy(item);self.calls=[]
        def request(self,method,path):
            self.calls.append((method,path))
            if '/actions/runs/99/artifacts?' in path:return dict(total_count=1,artifacts=[copy.deepcopy(self.item)])
            if '/actions/artifacts/' in path:return copy.deepcopy(self.item)
            return dict(repository=dict(full_name=r.REPOSITORY),id=99,run_attempt=3,
                path=r.acceptance.WORKFLOW,head_sha='c'*40,head_branch='main',
                event='workflow_dispatch',status='in_progress',conclusion=None)
    api=API()
    monkeypatch.setattr(uploader,'authenticate',lambda *a,**k:(authorization.read_bytes(),inventory.read_bytes()))
    monkeypatch.setattr(grant_receiver.dispatch,'verify',lambda **k:None)
    def download(_gh,_token,_id,path,held):
        assert _id==789
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=held)
        with os.fdopen(fd,'wb') as stream:stream.write(zip_bytes)
    kwargs=dict(client=api,authorization=authorization,inventory=inventory,assets=home,
        descriptor=descriptor,ledger=ledger,context_file=context_file,target_file=target_file,
        gh=home/'gh',cosign=home/'cosign',output=home/'signed-grant',
        harness_source_sha='c'*40,run_id=99,run_attempt=3,controller_user_id=12345,
        clock=lambda:100000,downloader=download)
    return kwargs,api,zip_bytes


def test_receive_same_run_signed_grant_without_dispatch(scenario,monkeypatch):
    kwargs,api,zip_bytes=grant_scenario(scenario,monkeypatch)
    result=grant_receiver.receive(**kwargs)
    assert result['guest_dispatched'] is False and result['acceptance'] is False
    assert result['receipt_sha256']==r.digest(kwargs['ledger'].read_bytes())
    assert {p.name for p in kwargs['output'].iterdir()}==grant_receiver.NAMES
    assert Path(str(kwargs['output'])+'.archive.zip').read_bytes()==zip_bytes
    assert Path(str(kwargs['output'])+'.verified.json').is_file()
    assert any('/actions/artifacts/789' in path for _,path in api.calls)


@pytest.mark.parametrize('completed_from', [1, 2])
def test_grant_receiver_accepts_successful_completion_at_either_boundary(scenario,monkeypatch,completed_from):
    kwargs,api,_=grant_scenario(scenario,monkeypatch)
    original=api.request
    observed=[]
    def request(method,path):
        value=original(method,path)
        if path.endswith('/actions/runs/99'):
            if len(observed)+1 >= completed_from:
                value.update(status='completed',conclusion='success')
            observed.append(value['status'])
        return value
    api.request=request
    result=grant_receiver.receive(**kwargs)
    assert observed == (['completed','completed'] if completed_from==1 else ['in_progress','completed'])
    assert result['guest_dispatched'] is False and result['acceptance'] is False
    assert Path(str(kwargs['output'])+'.verified.json').is_file()


@pytest.mark.parametrize('boundary', [1, 2])
@pytest.mark.parametrize('change', [
    {'status':'completed','conclusion':outcome}
    for outcome in ('failure','cancelled','timed_out','skipped')
] + [{'status':'completed','conclusion':'success','head_sha':'d'*40},
     {'status':'completed','conclusion':'success','run_attempt':4}])
def test_grant_receiver_refuses_failed_or_foreign_run_at_both_boundaries(scenario,monkeypatch,boundary,change):
    kwargs,api,_=grant_scenario(scenario,monkeypatch)
    original=api.request
    count=[0]
    ledger=kwargs['ledger'].read_bytes()
    def request(method,path):
        value=original(method,path)
        if path.endswith('/actions/runs/99'):
            count[0]+=1
            if count[0]==boundary:value.update(change)
        return value
    api.request=request
    with pytest.raises(ValueError):grant_receiver.receive(**kwargs)
    assert count[0]==boundary
    assert kwargs['output'].exists() == (boundary==2)
    assert not Path(str(kwargs['output'])+'.verified.json').exists()
    assert kwargs['ledger'].read_bytes()==ledger


def test_grant_receiver_refuses_ambiguous_artifact_before_download(scenario,monkeypatch):
    kwargs,api,_=grant_scenario(scenario,monkeypatch)
    original=api.request
    def duplicate(method,path):
        value=original(method,path)
        if '/artifacts?' in path:return dict(total_count=2,artifacts=[api.item,api.item])
        return value
    api.request=duplicate
    with pytest.raises(ValueError,match='ambiguous'):grant_receiver.receive(**kwargs)
    assert not kwargs['output'].exists()


def test_grant_zip_rejects_extra_and_traversal_members(tmp_path):
    import zipfile
    tmp_path.chmod(0o700)
    for extra in ('unexpected.json','../escape'):
        archive=tmp_path/(extra.replace('/','_')+'.zip')
        with zipfile.ZipFile(archive,'w') as bundle:
            for name in grant_receiver.NAMES:bundle.writestr(name,b'x')
            bundle.writestr(extra,b'bad')
        with pytest.raises(ValueError,match='closure'):
            with archive.open('rb') as stream:
                held=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
                try:grant_receiver.extract_exact(stream,tmp_path/('out-'+extra.replace('/','_')),held)
                finally:os.close(held)


def test_credential_download_kills_descendants_before_reaping(tmp_path,monkeypatch):
    import hashlib,time
    tmp_path.chmod(0o700)
    child=tmp_path/'child.pid'
    script=tmp_path/'gh'
    script.write_text('#!/bin/sh\nsleep 30 &\necho $! > '+str(child)+'\nprintf zip\nexit 0\n')
    script.chmod(0o700)
    monkeypatch.setitem(grant_receiver.dispatch.TOOLS,'gh',
        (hashlib.sha256(script.read_bytes()).hexdigest(),script.stat().st_size))
    held=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
    try:
        grant_receiver.download_archive(script,'synthetic-token',789,tmp_path/'archive.zip',held,timeout=2)
    finally:os.close(held)
    assert (tmp_path/'archive.zip').read_bytes()==b'zip'
    pid=int(child.read_text())
    time.sleep(0.05)
    status=Path(f'/proc/{pid}/stat')
    assert not status.exists() or status.read_text().split()[2]=='Z'


def test_grant_receiver_expiry_during_verification_retains_files(scenario,monkeypatch):
    kwargs,api,_=grant_scenario(scenario,monkeypatch)
    original=api.request
    def completed(method,path):
        value=original(method,path)
        if path.endswith('/actions/runs/99'):
            value.update(status='completed',conclusion='success')
        return value
    api.request=completed
    moment=[100000]
    kwargs['clock']=lambda:moment[0]
    expiry=r.decode(kwargs['authorization'].read_bytes())['expires_at']
    def slow_verify(**_):moment[0]=expiry-t.RESERVE
    monkeypatch.setattr(grant_receiver.dispatch,'verify',slow_verify)
    with pytest.raises(ValueError,match='expired'):
        grant_receiver.receive(**kwargs)
    assert kwargs['output'].is_dir()
    assert not Path(str(kwargs['output'])+'.verified.json').exists()


def test_grant_receiver_refuses_returned_receipt_not_in_ledger(scenario,monkeypatch):
    import hashlib,zipfile
    kwargs,api,original_zip=grant_scenario(scenario,monkeypatch)
    source=io.BytesIO(original_zip)
    with zipfile.ZipFile(source) as bundle:
        members={name:bundle.read(name) for name in grant_receiver.NAMES}
    members['controller-consumption.json']=b'{}'
    altered=io.BytesIO()
    with zipfile.ZipFile(altered,'w') as bundle:
        for name,data in members.items():bundle.writestr(name,data)
    raw=altered.getvalue()
    api.item['size_in_bytes']=len(raw)
    api.item['digest']='sha256:'+hashlib.sha256(raw).hexdigest()
    def download(_gh,_token,_id,path,held):
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=held)
        with os.fdopen(fd,'wb') as stream:stream.write(raw)
    kwargs['downloader']=download
    with pytest.raises(ValueError,match='bytes differ'):
        grant_receiver.receive(**kwargs)
    assert kwargs['output'].is_dir()
    assert not Path(str(kwargs['output'])+'.verified.json').exists()


def test_grant_receiver_refuses_replaced_staging_parent(scenario,monkeypatch):
    kwargs,_,_=grant_scenario(scenario,monkeypatch)
    original=kwargs['downloader']
    parent=kwargs['output'].parent
    moved=parent.with_name(parent.name+'-moved')
    def replace(*args):
        original(*args)
        os.rename(parent,moved)
    kwargs['downloader']=replace
    try:
        with pytest.raises((ValueError,OSError)):
            grant_receiver.receive(**kwargs)
        assert (moved/(kwargs['output'].name+'.archive.zip')).is_file()
    finally:
        if moved.exists():os.rename(moved,parent)
    assert not Path(str(kwargs['output'])+'.verified.json').exists()


def initial_scenario(scenario,monkeypatch):
    import hashlib,zipfile
    prior,api,raw=grant_scenario(scenario,monkeypatch)
    with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
        members={name:bundle.read(name) for name in initial_grant.NAMES}
    initial_zip=io.BytesIO()
    with zipfile.ZipFile(initial_zip,'w') as bundle:
        for name,data in members.items():bundle.writestr(name,data)
    archive=initial_zip.getvalue()
    api.item['name']='installer-staged-grant-99-3'
    api.item['size_in_bytes']=len(archive)
    api.item['digest']='sha256:'+hashlib.sha256(archive).hexdigest()
    auth=r.decode(prior['authorization'].read_bytes())
    (prior['assets']/'installer-inventory.json').write_bytes(prior['inventory'].read_bytes())
    def download(_gh,_token,_id,path,held):
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=held)
        with os.fdopen(fd,'wb') as stream:stream.write(archive)
    kwargs=dict(client=api,assets=prior['assets'],gh=prior['gh'],cosign=prior['cosign'],
        output=prior['output'].parent/'initial-grant',phase='staged',
        source_sha=auth['source_sha'],release_tag=auth['release_tag'],
        build_run_id=auth['build_run_id'],build_run_attempt=auth['build_run_attempt'],
        harness_source_sha='c'*40,run_id=99,run_attempt=3,
        controller_user_id=12345,clock=lambda:100000,downloader=download)
    monkeypatch.setattr(initial_grant.staged_assets,'verify_acquisition',
                        lambda **unused:{'artifact':'synthetic-staged-transport'})
    return kwargs,api


def test_initial_grant_acquired_without_nonce_consumption(scenario,monkeypatch):
    kwargs,api=initial_scenario(scenario,monkeypatch)
    result=initial_grant.acquire(**kwargs)
    assert result['nonce_consumed'] is False and result['guest_dispatched'] is False
    assert {p.name for p in kwargs['output'].iterdir()}==initial_grant.NAMES
    assert Path(str(kwargs['output'])+'.verified.json').is_file()
    assert any('/actions/artifacts/789' in path for _,path in api.calls)
    assert result['staged_transport_sha256']==r.digest(r.encode({'artifact':'synthetic-staged-transport'}))


def test_initial_grant_refuses_independent_build_mismatch(scenario,monkeypatch):
    kwargs,_=initial_scenario(scenario,monkeypatch)
    kwargs['source_sha']='b'*40
    with pytest.raises(ValueError,match='independent candidate'):
        initial_grant.acquire(**kwargs)
    assert kwargs['output'].is_dir()
    assert not Path(str(kwargs['output'])+'.verified.json').exists()


def test_initial_published_grant_keeps_four_file_closure(scenario,monkeypatch):
    args,_,receipt,client=scenario
    auth=r.decode(args['authorization'].read_bytes());auth['phase']='published'
    args['authorization'].write_bytes(r.encode(auth))
    descriptor=args['authorization'].parent/'published-initial-descriptor'
    t.prepare(**args,descriptor_output=descriptor)
    kwargs,api=initial_scenario((args,descriptor,receipt,client),monkeypatch)
    kwargs['phase']='published'
    api.item['name']='installer-published-grant-99-3'
    observations=[]
    downloads=[]
    monkeypatch.setattr(initial_grant.public_release,'observe',
                        lambda api,tag,source:observations.append((tag,source)) or {'id':123})
    monkeypatch.setattr(initial_grant.public_release,'verify_downloads',
                        lambda identity,assets:downloads.append((identity,assets)))
    result=initial_grant.acquire(**kwargs)
    assert result['phase']=='published' and result['nonce_consumed'] is False
    assert {p.name for p in kwargs['output'].iterdir()}==initial_grant.NAMES
    assert len(observations)==2 and len(downloads)==2
    assert result['published_release_observation_sha256']==r.digest(r.encode({'id':123}))


def test_initial_published_grant_refuses_changed_release_identity(scenario,monkeypatch):
    args,_,receipt,client=scenario
    auth=r.decode(args['authorization'].read_bytes());auth['phase']='published'
    args['authorization'].write_bytes(r.encode(auth))
    descriptor=args['authorization'].parent/'published-changing-descriptor'
    t.prepare(**args,descriptor_output=descriptor)
    kwargs,api=initial_scenario((args,descriptor,receipt,client),monkeypatch)
    kwargs['phase']='published'
    api.item['name']='installer-published-grant-99-3'
    observations=iter(({'id':123},{'id':124}))
    monkeypatch.setattr(initial_grant.public_release,'observe',lambda *a:next(observations))
    monkeypatch.setattr(initial_grant.public_release,'verify_downloads',lambda *a:None)
    with pytest.raises(ValueError,match='published release identity changed'):
        initial_grant.acquire(**kwargs)
    assert not Path(str(kwargs['output'])+'.verified.json').exists()


def test_initial_published_grant_refuses_expiry_during_final_release_check(scenario,monkeypatch):
    args,_,receipt,client=scenario
    auth=r.decode(args['authorization'].read_bytes());auth['phase']='published'
    args['authorization'].write_bytes(r.encode(auth))
    descriptor=args['authorization'].parent/'published-expiry-descriptor'
    t.prepare(**args,descriptor_output=descriptor)
    kwargs,api=initial_scenario((args,descriptor,receipt,client),monkeypatch)
    kwargs['phase']='published'
    api.item['name']='installer-published-grant-99-3'
    moment=[100000]
    kwargs['clock']=lambda:moment[0]
    expiry=r.decode((kwargs['assets']/'authorization').read_bytes())['expires_at']
    monkeypatch.setattr(initial_grant.public_release,'observe',lambda *a:{'id':123})
    calls=[0]
    def verify(*args):
        calls[0]+=1
        if calls[0]==2:moment[0]=expiry-t.RESERVE
    monkeypatch.setattr(initial_grant.public_release,'verify_downloads',verify)
    with pytest.raises(ValueError,match='expires too soon'):
        initial_grant.acquire(**kwargs)
    assert calls[0]==2 and kwargs['output'].is_dir()
    assert not Path(str(kwargs['output'])+'.verified.json').exists()


def test_initial_grant_expiry_during_authentication_retains_archive(scenario,monkeypatch):
    kwargs,_=initial_scenario(scenario,monkeypatch)
    moment=[100000]
    kwargs['clock']=lambda:moment[0]
    expiry=r.decode((kwargs['assets']/'authorization').read_bytes())['expires_at']
    def slow_auth(authorization,inventory,assets,gh,cosign,runner):
        moment[0]=expiry-t.RESERVE
        return authorization.read_bytes(),inventory.read_bytes()
    monkeypatch.setattr(uploader,'authenticate',slow_auth)
    with pytest.raises(ValueError,match='expires too soon'):
        initial_grant.acquire(**kwargs)
    assert Path(str(kwargs['output'])+'.archive.zip').is_file()
    assert kwargs['output'].is_dir()
    assert not Path(str(kwargs['output'])+'.verified.json').exists()


def test_initial_grant_refuses_run_attempt_change_after_download(scenario,monkeypatch):
    kwargs,api=initial_scenario(scenario,monkeypatch)
    original=api.request
    seen=[0]
    def changed(method,path):
        result=original(method,path)
        if path.endswith('/actions/runs/99'):
            seen[0]+=1
            if seen[0]==2:result['run_attempt']=4
        return result
    api.request=changed
    with pytest.raises(ValueError,match='run identity'):
        initial_grant.acquire(**kwargs)
    assert kwargs['output'].is_dir()
    assert not Path(str(kwargs['output'])+'.verified.json').exists()


def test_initial_grant_repeat_refuses_existing_staging(scenario,monkeypatch):
    kwargs,_=initial_scenario(scenario,monkeypatch)
    initial_grant.acquire(**kwargs)
    with pytest.raises(ValueError,match='already exists'):
        initial_grant.acquire(**kwargs)
