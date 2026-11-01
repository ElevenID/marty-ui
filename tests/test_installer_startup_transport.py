"""Actual verifier adapter and owned transport with synthetic API/tool results.

No GitHub mutation, authentic signature, browser run or installed pass is claimed.
"""
import copy
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_installer_startup_observation import startup_case, put, staged
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import installer_release as r
import installer_acceptance_startup as startup
import installer_startup_transport as transport
import installer_candidate_rendezvous as rendezvous
import installer_acceptance_return as entry


class FakeClient:
    def __init__(self, case):
        self.case=case
        self.run=case.active
        self.release=rendezvous.identity(r.decode(case.authorization),17,12345)
        self.items=[self.metadata(rendezvous.RECEIPT,case.receipt,18)]
        self.raw=None
        self.on_download=None
        self.on_upload=None
        self.requests=[]
        self.uploads=0
    @staticmethod
    def metadata(name,raw,identifier):
        return dict(id=identifier,name=name,state='uploaded',size=len(raw),digest='sha256:'+r.digest(raw),
            uploader=dict(id=12345,type='User',login='controller'),created_at='2026-11-01T00:00:00Z',updated_at='2026-11-01T00:00:00Z')
    def request(self,method,path,body=None):
        self.requests.append((method,path,body))
        assert method=='GET' and body is None
        if '/actions/runs/' in path:return copy.deepcopy(self.run)
        if path.endswith('/assets?per_page=100'):return copy.deepcopy(self.items)
        assert path==rendezvous.REPO+'/releases/17'
        return {**self.release,'author':{'id':12345}}
    def whoami(self):return dict(id=12345,type='User',login='controller')
    def upload_startup(self,identifier,raw):
        assert identifier==17
        self.uploads+=1;self.raw=raw
        metadata=self.metadata(startup.NAME,raw,19)
        self.items.append(metadata)
        if self.on_upload:self.on_upload()
        return copy.deepcopy(metadata)
    def download_startup(self,identifier,size):
        assert identifier==19 and size==len(self.raw)
        if self.on_download:self.on_download()
        return self.raw


@pytest.fixture
def exchange(startup_case):
    c=startup_case;client=FakeClient(c)
    directory=c.root/'startup';directory.mkdir(mode=0o700)
    report=put(directory/startup.NAME,r.encode(c.report))
    descriptor=put(c.root/'context/descriptor.json',r.encode(dict(schema=rendezvous.SCHEMA,
        authorization_sha256=r.digest(c.authorization),inventory_sha256=r.digest(c.inventory),
        context_sha256=r.candidate_context_sha256(c.context),controller_user_id=12345,
        **{k:c.context[k] for k in ('nonce','run_id','run_attempt','harness_source_sha')},release=client.release)))
    options=dict(client=client,authorization=c.auth_path,receipt=c.receipt_path,
        inventory=c.options['assets']/'installer-inventory.json',assets=c.options['assets'],
        gh=c.options['gh'],cosign=c.options['cosign'],descriptor=descriptor,
        harness_source_sha=c.context['harness_source_sha'],run_id=c.context['run_id'],run_attempt=c.context['run_attempt'],
        controller_user_id=12345,clock=lambda:100020,verifier=c.verifier)
    return c,client,report,options


def receive_options(c, options):
    directory=c.root/'returned';directory.mkdir(mode=0o700)
    return dict(options,output=directory/startup.NAME)


def test_active_return_reverifies_all_seven_subjects_and_exact_report_artifact_proofs(exchange):
    c,client,report,options=exchange
    client.upload_startup(17,report.read_bytes())
    values=receive_options(c,options)
    result=transport.receive(**values)
    assert result==c.report and values['output'].read_bytes()==report.read_bytes()
    assert len(c.verification_calls)==14
    gh=[argv for argv in c.verification_calls if Path(argv[0]).name=='gh']
    assert len(gh)==7
    assert {Path(argv[3]).name for argv in gh}=={'candidate-authorization.json','controller-consumption.json',
        'installer-inventory.json','marty-deploy-linux-amd64','install.sh','prepared-selfhost-bundle.zip','prepared-selfhost-images.json'}
    assert sum('--signer-workflow' in argv and argv[argv.index('--signer-workflow')+1].endswith(r.acceptance.WORKFLOW) for argv in gh)==2
    metadata=r.decode(Path(str(values['output'])+'.transport.json').read_bytes())
    assert metadata['startup_sha256']==r.digest(report.read_bytes())
    assert metadata['installation_ready'] is metadata['functional_recovery_qualified'] is False


def test_upload_is_exact_original_draft_and_uncertain_post_cannot_be_replayed(exchange):
    c,client,report,options=exchange
    values=dict(options,report=report,ledger=c.options['ledger'],output=c.root/'upload-result.json')
    def lost():raise ValueError('simulated lost accepted upload response')
    client.on_upload=lost
    with pytest.raises(ValueError):transport.upload(**values)
    assert client.uploads==1
    intent=c.options['ledger'].parent/(c.context['nonce']+'.startup.upload-intent.json')
    assert intent.is_file() and not values['output'].exists()
    # Even if a human removes the remote orphan asset, the durable intent holds.
    client.items=client.items[:1];client.on_upload=None
    with pytest.raises(FileExistsError):transport.upload(**values)
    assert client.uploads==1


def test_successful_fixed_upload_reads_back_exact_bytes_and_retains_public_result(exchange):
    c,client,report,options=exchange
    values=dict(options,report=report,ledger=c.options['ledger'],output=c.root/'upload-result.json')
    result=transport.upload(**values)
    assert client.raw==report.read_bytes() and client.uploads==1
    assert result['startup_sha256']==r.digest(client.raw)
    assert values['output'].exists()


@pytest.mark.parametrize('mutation',['operator','proof','same-inode-write','same-bytes-replace','parent-replace','parent-away-back','tool'])
def test_changed_exact_files_or_parent_custody_during_external_verifier_refuse(exchange,mutation):
    c,client,report,options=exchange
    client.upload_startup(17,report.read_bytes())
    values=receive_options(c,options)
    triggered=False
    def verifier(argv,**kwargs):
        nonlocal triggered
        result=c.verifier(argv,**kwargs)
        if not triggered:
            triggered=True
            target=c.options['assets']/'marty-deploy-linux-amd64'
            if mutation=='proof':target=Path(str(c.receipt_path)+'.sigstore.json')
            if mutation=='tool':target=c.options['gh']
            if mutation in ('operator','proof','tool'):target.write_bytes(target.read_bytes()+b' changed')
            elif mutation=='same-inode-write':
                raw=target.read_bytes();target.write_bytes(raw)
            elif mutation=='same-bytes-replace':
                raw=target.read_bytes();target.rename(target.with_name('moved'));put(target,raw)
            else:
                parent=target.parent;old=parent.with_name('moved-assets');parent.rename(old)
                if mutation=='parent-away-back':old.rename(parent)
                else:parent.mkdir(mode=0o700)
        return result
    values['verifier']=verifier
    with pytest.raises((ValueError,OSError)):transport.receive(**values)
    assert not values['output'].exists()


@pytest.mark.parametrize('mutation',['uploader','receipt','extra-asset','changed-asset','proof-map','artifact-proof','completed','wrong-run'])
def test_active_signer_rejects_transport_authority_and_owner_proof_substitution(exchange,mutation):
    c,client,report,options=exchange
    value=copy.deepcopy(c.report)
    if mutation=='proof-map':value['authority']['authenticated_evidence_sha256']['installer-controller-consumption.json.sigstore.json']='f'*64
    elif mutation=='artifact-proof':
        artifact=r.decode(value['owner_records']['artifacts']['record'].encode())
        artifact['subjects']['install.sh']['signature_sha256']='f'*64
        raw=r.encode(artifact);value['owner_records']['artifacts']=dict(sha256=r.digest(raw),record=raw.decode())
        # Matching generated case refs still cannot override independent verification.
        records={key:item['record'].encode() for key,item in value['owner_records'].items()}
        value['proofs']=startup._proofs(value['scope'],value['selection'],records,artifact['started_at'],c.after['completed_at'])
    client.upload_startup(17,r.encode(value))
    if mutation=='uploader':client.items[1]['uploader']['id']=999
    elif mutation=='receipt':client.items[0]['digest']='sha256:'+'f'*64
    elif mutation=='extra-asset':client.items.append(dict(client.items[1],id=20,name='foreign.json'))
    elif mutation=='changed-asset':client.on_download=lambda:client.items[1].update(id=20)
    elif mutation=='completed':client.run=c.completed
    elif mutation=='wrong-run':client.run=dict(c.active,run_attempt=4)
    values=receive_options(c,options)
    with pytest.raises(ValueError):transport.receive(**values)
    assert not values['output'].exists()


def final_options(exchange):
    c,client,report,options=exchange
    client.run=c.completed
    signature=put(Path(str(report)+'.sigstore.json'),b'synthetic final signature')
    proof=put(Path(str(report)+'.provenance.jsonl'),b'synthetic final provenance')
    return dict(client=client,report=report,signature_bundle=signature,provenance=proof,
        inventory=options['inventory'],gh=options['gh'],cosign=options['cosign'],verifier=c.verifier)


def test_final_return_verifies_inventory_and_signed_startup_only_after_completed_success(exchange):
    c,client,report,_=exchange
    values=final_options(exchange)
    result=transport.verify_return(**values)
    assert len(c.verification_calls)==4
    assert result['startup_observed'] is True
    assert result['installation_ready'] is result['functional_recovery_qualified'] is result['load_characterized'] is False
    assert result['startup_sha256']==r.digest(report.read_bytes())


@pytest.mark.parametrize('mutation',['active','failure','source','attempt','proof-during-verify','report-during-verify'])
def test_final_return_refuses_active_wrong_run_and_post_verification_change(exchange,mutation):
    c,client,report,_=exchange
    values=final_options(exchange)
    if mutation=='active':client.run=c.active
    elif mutation=='failure':client.run=dict(c.completed,conclusion='failure')
    elif mutation=='source':client.run=dict(c.completed,head_sha='f'*40)
    elif mutation=='attempt':client.run=dict(c.completed,run_attempt=4)
    else:
        def changed(argv,**kwargs):
            output=c.verifier(argv,**kwargs)
            target=values['provenance'] if mutation=='proof-during-verify' else report
            target.write_bytes(target.read_bytes()+b' ')
            return output
        values['verifier']=changed
    with pytest.raises(ValueError):transport.verify_return(**values)


def test_fixed_upload_and_download_never_accept_other_names_hosts_or_oversized_bytes(monkeypatch):
    client=transport.Client('test-only-token');calls=[]
    monkeypatch.setattr(client,'_read',lambda url,**kwargs:(calls.append((url,kwargs)) or b'{}'))
    assert client.download_startup(19,2)==b'{}'
    assert calls==[('https://api.github.com'+rendezvous.REPO+'/releases/assets/19',dict(binary=True,maximum=2))]
    for identifier,size in [(0,2),(19,0),(19,True),(19,startup.MAX_BYTES+1)]:
        with pytest.raises(ValueError):client.download_startup(identifier,size)
    with pytest.raises(ValueError):client.upload_startup(17,b'x'*(startup.MAX_BYTES+1))


def test_cli_exposes_explicit_startup_operations_without_changing_legacy_receive(monkeypatch,tmp_path):
    seen=[]
    monkeypatch.setattr(transport,'Client',lambda token:object())
    monkeypatch.setattr(transport,'receive',lambda **kwargs:seen.append(kwargs))
    paths=['authorization','inventory','receipt','descriptor','output','assets','gh','cosign']
    argv=['receive-startup-payload']
    for name in paths:argv+=['--'+name,str(tmp_path/name)]
    argv+=['--harness-source-sha','c'*40,'--run-id','99','--run-attempt','3','--controller-user-id','12345']
    assert entry.main(argv)==0 and len(seen)==1
    assert seen[0]['output']==tmp_path/'output'
    with pytest.raises(SystemExit):entry.main(['receive-startup-payload','--allow-active'])
