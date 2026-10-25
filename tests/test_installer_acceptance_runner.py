"""Fixed probe routing with synthetic subprocesses; not installed qualification."""
import copy
import json
import os
from pathlib import Path
import sys
import pytest
pytest.importorskip('fcntl')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import installer_acceptance_runner as a
import installer_release as r


def host():
    return dict(schema='elevenid.installer-host-observation/v1',acceptance=False,engine_id='test-engine-12345678',
        docker_memory_bytes=32*1024**3,guest_memory_bytes=32*1024**3,docker_data_filesystem=dict(free_bytes=20*1024**3),
        predicates=dict(capacity=True,initial_docker_clean=True),resource_counts=dict(containers=0,images=0,volumes=0,networks=3),
        credential_environment_names=[],credential_file_presence=dict(docker_config=False,containers_auth=False,runtime_containers_auth=False),
        development_tool_presence=dict.fromkeys(a.DEVTOOLS,False))


@pytest.fixture
def candidate(tmp_path,monkeypatch):
    tmp_path.chmod(0o700)
    fixture=json.loads((Path(__file__).resolve().parents[1]/'rust/crates/deployment-catalog/tests/fixtures/installer-candidate-records.json').read_text())
    auth,inv=fixture['authorization'].encode(),fixture['inventory'].encode()
    context={k:r.decode(auth)[k] for k in r.CONTEXT_FIELDS}
    target=dict(guest_id='12345678-1234-4234-8234-123456789abc',disk_id='d'*64,engine_id='test-engine-12345678',installation_id='22345678-1234-4234-8234-123456789abc')
    receipt=r.encode(r.controller_consumption(auth,inv,expected=context,**target,consumed_at=100000,now=100000))
    for name,value in [('context',r.encode(context)),('target',r.encode(target)),('ledger',receipt),('key',b'private synthetic key'),('hosts',b'pinned synthetic host')]:
        (tmp_path/name).write_bytes(value);(tmp_path/name).chmod(0o600)
    output=tmp_path/'output';output.mkdir(mode=0o700)
    monkeypatch.setattr(a.dispatch,'executable',lambda _:None)
    monkeypatch.setattr(a.dispatch,'verify',lambda **_: (auth,receipt,inv,{}))
    calls=[]
    def execute(argv,**kwargs):
        calls.append(('probe',argv,kwargs));return r.encode(host())
    def dispatch(**kwargs):calls.append(('dispatch',kwargs))
    args=dict(output=output,assets=tmp_path/'assets',grants=tmp_path/'grants',context_file=tmp_path/'context',
        target_file=tmp_path/'target',ledger=tmp_path/'ledger',gh=tmp_path/'gh',cosign=tmp_path/'cosign',
        ssh=Path('/usr/bin/ssh'),scp=Path('/usr/bin/scp'),key=tmp_path/'key',known_hosts=tmp_path/'hosts',
        host='127.0.0.1',port=2222,user='installer',home='/home/installer',clock=lambda:100000,execute=execute,candidate_dispatch=dispatch)
    return args,calls,context,target,auth,receipt,inv


def test_real_probe_before_dispatch_and_never_claims_acceptance(candidate):
    args,calls,*_=candidate
    result=a.run(**args)
    assert [v[0] for v in calls]==['probe','dispatch']
    assert calls[0][1][:2]==['/usr/bin/ssh','-F']
    assert 'env -i HOME=/home/installer PATH=/usr/bin:/bin /usr/bin/python3 -c' in calls[0][1][-1]
    assert set(calls[0][2]['env'])=={'HOME','PATH','LANG','LC_ALL'}
    assert calls[0][2]['timeout']==120
    assert result['dispatch']=='returned_zero_unqualified' and result['acceptance'] is False
    assert all(v=='blocked' for k,v in result['cases'].items() if k!='artifact-verification')
    assert (args['output']/a.NAME).exists() and not (args['output']/'installer-acceptance.json').exists()
    with pytest.raises(FileExistsError):a.run(**args)
    assert len(calls)==2


@pytest.mark.parametrize('mutation',['ram','images','credentials','engine','missing_keys'])
def test_host_refusal_prevents_any_installation(candidate,mutation):
    args,calls,*_=candidate;value=host()
    if mutation=='ram':value['guest_memory_bytes']=4*1024**3
    if mutation=='images':value['resource_counts']['images']=1
    if mutation=='credentials':value['credential_file_presence']['docker_config']=True
    if mutation=='engine':value['engine_id']='other'
    if mutation=='missing_keys':value['development_tool_presence']={}
    args['execute']=lambda *a,**k:r.encode(value)
    result=a.run(**args)
    assert calls==[] and result['host_preflight']=='failed' and result['dispatch']=='not_attempted'
    assert result['acceptance'] is False


def test_native_incomplete_error_is_retained_without_raw_diagnostics(candidate):
    args,calls,*_=candidate
    def fail(**kwargs):raise ValueError('private-token-must-not-appear')
    args['candidate_dispatch']=fail
    result=a.run(**args)
    assert result['dispatch']=='failed_or_incomplete'
    assert b'private-token' not in (args['output']/a.NAME).read_bytes()
    assert all(v=='blocked' for k,v in result['cases'].items() if k!='artifact-verification')


def test_checkpoint_cannot_upgrade_unimplemented_cases(candidate):
    args,_,context,target,auth,receipt,inv=candidate
    result=a.run(**args);result['cases']['browser-tls-login']='passed'
    with pytest.raises(ValueError):a.validate(result,context=context,target=target,authorization=auth,receipt=receipt,inventory=inv)


def test_probe_source_fixed_bounded_regular_file(tmp_path,monkeypatch):
    monkeypatch.setattr(a,'__file__',str(tmp_path/'runner.py'))
    source=tmp_path/'installer_host_probe.py';source.write_bytes(b'pass')
    assert a.probe_source()==b'pass'
    source.write_bytes(b'x'*65537)
    with pytest.raises(ValueError):a.probe_source()
    source.unlink();target=tmp_path/'other';target.write_bytes(b'pass');source.symlink_to(target)
    with pytest.raises(ValueError):a.probe_source()


@pytest.mark.parametrize('which',['target','context','ledger','key','known_hosts','asset','verifier'])
def test_probe_custody_change_refuses_dispatch_and_checkpoint(candidate,monkeypatch,which):
    args,calls,_,_,auth,receipt,inv=candidate
    if which in ('asset','verifier'):
        path=args['output'].parent/which;path.write_bytes(b'original')
        executable=which=='verifier';path.chmod(0o700 if executable else 0o600)
        if executable:args['gh']=path
        files={path:a.dispatch.private_file(path,65536,executable=executable)}
        monkeypatch.setattr(a.dispatch,'verify',lambda **_: (auth,receipt,inv,files))
    else:path=args[{'target':'target_file','context':'context_file','ledger':'ledger','key':'key','known_hosts':'known_hosts'}[which]]
    def mutate(*pos,**kwargs):path.write_bytes(b'changed');return r.encode(host())
    args['execute']=mutate
    with pytest.raises(ValueError):a.run(**args)
    assert calls==[]
    assert (args['output']/'runner-intent.json').exists()
    assert (args['output']/'host-observation.json').exists()
    assert not (args['output']/a.NAME).exists()


def test_post_dispatch_custody_change_preserves_uncertainty_without_checkpoint(candidate):
    args,_,*_=candidate
    def mutate(**kwargs):args['target_file'].write_bytes(b'changed')
    args['candidate_dispatch']=mutate
    with pytest.raises(ValueError):a.run(**args)
    assert (args['output']/'runner-intent.json').exists()
    assert not (args['output']/a.NAME).exists()
