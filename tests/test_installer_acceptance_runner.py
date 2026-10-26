"""Fixed probe routing with synthetic subprocesses; not installed qualification."""
import base64
import copy
import hashlib
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


def trust(installation_id='22345678-1234-4234-8234-123456789abc'):
    pem=(Path(__file__).resolve().parents[1]/'rust/crates/deployment-catalog/tests/fixtures/installer-log-public-ca.txt').read_text()
    der=base64.b64decode(''.join(pem.splitlines()[1:-1]),validate=True)
    return dict(schema='elevenid.installer-trust-info/v2',installation_id=installation_id,
        origin='https://localhost:18443',ca_certificate_pem=pem,
        ca_der_sha256=hashlib.sha256(der).hexdigest(),certificate_der_sha256='c'*64,
        ca_expires_at=200000,certificate_expires_at=200000,
        recorded_token_expires_at=200000,evidence_sha256=dict.fromkeys(a.TRUST_EVIDENCE,'b'*64),
        recorded_startup_containers=30,runtime_observed=False,host_trust_observed=False,
        host_trust_modified=False,installation_ready=False,pending=['browser trust','business journey','recovery'])


def status(context,target,auth,inv):
    claim=dict(nonce=context['nonce'],authorization_sha256=r.digest(auth),
        context_sha256=r.candidate_context_sha256(context),installation_id=target['installation_id'],
        engine_id=target['engine_id'])
    consumption=r.digest(json.dumps(dict(schema='elevenid.installer-candidate-consumption/v1',
        scope='guest-local',claim=claim),separators=(',',':')).encode())
    return dict(scope='installation-journal',runtime_observed=False,
        journal=dict(schema='elevenid.installer-state/v1',installation_id=target['installation_id'],
            identity=dict(source_sha=context['source_sha'],release_tag=context['release_tag'],
                inventory_sha256='sha256:'+r.digest(inv)),phase='provisioning',revision=2,
            runtime=dict(docker_host='unix:///var/run/docker.sock',engine_id=target['engine_id'],openbao_port=18442),
            scope=dict(kind='acceptance-only',authorization_sha256=r.digest(auth),
                context_sha256=r.candidate_context_sha256(context),consumption_id=consumption)),
        cleanup=dict(state='not_started',runtime_observed=False))


def tls(target,trust_value):
    return dict(schema='elevenid.installer-live-tls-observation/v1',
        installation_id=target['installation_id'],engine_id=target['engine_id'],
        origin=trust_value['origin'],ca_der_sha256=trust_value['ca_der_sha256'],
        peer_der_sha256='c'*64,tls_version='TLSv1.3',root_status=200,discovery_status=200,
        discovery_sha256='d'*64,issuer=trust_value['origin']+'/realms/11id',observed_at=100000,
        browser_login_observed=False,host_trust_modified=False)


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
    monkeypatch.setattr(a.dispatch,'verified_harness_script',
        lambda source,name:(Path(__file__).resolve().parents[1]/'scripts'/name).read_text())
    calls=[]
    def execute(argv,**kwargs):
        if ' status --install-dir ' in argv[-1]:
            calls.append(('status',argv,kwargs));return r.encode(status(context,target,auth,inv))
        if 'trust-info' in argv[-1]:
            calls.append(('trust',argv,kwargs));return r.encode(trust())
        if 'installer-live-tls-probe' in argv[-1]:
            calls.append(('tls',argv,kwargs));return r.encode(tls(target,trust()))
        calls.append(('probe',argv,kwargs));return r.encode(host())
    def dispatch(**kwargs):calls.append(('dispatch',kwargs))
    args=dict(output=output,assets=tmp_path/'assets',grants=tmp_path/'grants',context_file=tmp_path/'context',
        target_file=tmp_path/'target',ledger=tmp_path/'ledger',gh=tmp_path/'gh',cosign=tmp_path/'cosign',
        ssh=Path('/usr/bin/ssh'),scp=Path('/usr/bin/scp'),key=tmp_path/'key',known_hosts=tmp_path/'hosts',
        host='127.0.0.1',port=2222,user='installer',home='/home/installer',clock=lambda:100000,execute=execute,candidate_dispatch=dispatch)
    return args,calls,context,target,auth,receipt,inv


def test_real_probe_before_dispatch_and_never_claims_acceptance(candidate):
    args,calls,context,target,auth,receipt,inv=candidate
    a.status_observation(r.encode(status(context,target,auth,inv)),context,target,auth,inv)
    a.trust_observation(r.encode(trust()),target,100000)
    result=a.run(**args)
    assert [v[0] for v in calls]==['probe','dispatch','status','trust','status','tls','status','trust']
    assert calls[0][1][:2]==['/usr/bin/ssh','-F']
    assert 'env -i HOME=/home/installer PATH=/usr/bin:/bin /usr/bin/python3 -c' in calls[0][1][-1]
    assert set(calls[0][2]['env'])=={'HOME','PATH','LANG','LC_ALL'}
    assert calls[0][2]['timeout']==120
    assert result['dispatch']=='returned_zero_unqualified' and result['acceptance'] is False
    assert result['trust_inspection']=='verified_public_record'
    assert result['tls_inspection']=='verified_local_https'
    assert result['tls_observation_sha256']==r.digest((args['output']/a.TLS_NAME).read_bytes())
    assert result['trust_info_sha256']==r.digest((args['output']/a.TRUST_NAME).read_bytes())
    assert result['status_observation_sha256']==r.digest((args['output']/a.STATUS_NAME).read_bytes())
    assert all(v=='blocked' for k,v in result['cases'].items() if k!='artifact-verification')
    assert (args['output']/a.NAME).exists() and not (args['output']/'installer-acceptance.json').exists()
    with pytest.raises(FileExistsError):a.run(**args)
    assert len(calls)==8


@pytest.mark.parametrize('field,value', [('host_preflight', 'failed'),
                                         ('dispatch', 'not_attempted')])
def test_extracted_observer_refuses_unadmitted_or_unattempted_checkpoint(
        candidate, field, value):
    args,calls,context,target,auth,receipt,inv=candidate
    checkpoint=a.run(**args)
    checkpoint[field]=value
    seen=len(calls)
    def unexpected(*_args, **_kwargs):
        raise AssertionError('post-dispatch guard or remote operation ran')
    with pytest.raises(ValueError):
        a.observe_after_dispatch(
            checkpoint=checkpoint, output=args['output'], context=context,
            target=target, authorization=auth, receipt=receipt, inventory=inv,
            ssh=args['ssh'], key=args['key'], known_hosts=args['known_hosts'],
            port=args['port'], host=args['host'], user=args['user'], home=args['home'],
            bootstrap_source=None, tls_source='', unchanged=unexpected,
            guarded_execute=unexpected, clock=args['clock'])
    assert len(calls)==seen


def test_host_probe_must_match_signed_harness(candidate,monkeypatch):
    args,calls,*_=candidate
    monkeypatch.setattr(a.dispatch,'verified_harness_script',lambda source,name:'print("drift")')
    with pytest.raises(ValueError):a.run(**args)
    assert calls==[]
    assert not (args['output']/a.NAME).exists()


def test_tls_probe_must_match_signed_harness(candidate,monkeypatch):
    args,calls,*_=candidate
    actual=a.dispatch.verified_harness_script
    monkeypatch.setattr(a.dispatch,'verified_harness_script',
        lambda source,name:(_ for _ in ()).throw(ValueError('signed source unavailable'))
        if name=='installer_live_tls_probe.py' else actual(source,name))
    with pytest.raises(ValueError):a.run(**args)
    assert calls==[] and not (args['output']/a.NAME).exists()


@pytest.mark.parametrize('mutation',['peer','engine','browser','ca','origin','stale'])
def test_live_tls_record_refuses_substitution(candidate,mutation):
    args,calls,context,target,auth,receipt,inv=candidate
    original=args['execute']
    def execute(argv,**kwargs):
        if 'installer-live-tls-probe' not in argv[-1]:return original(argv,**kwargs)
        value=tls(target,trust())
        if mutation=='peer':value['peer_der_sha256']='f'*64
        if mutation=='engine':value['engine_id']='other-engine'
        if mutation=='browser':value['browser_login_observed']=True
        if mutation=='ca':value['ca_der_sha256']='f'*64
        if mutation=='origin':value['origin']='https://evil.example:18443'
        if mutation=='stale':value['observed_at']=99800
        return r.encode(value)
    args['execute']=execute
    result=a.run(**args)
    assert result['tls_inspection']=='unavailable' and result['tls_observation_sha256'] is None
    assert not (args['output']/a.TLS_NAME).exists()
    assert result['cases']['browser-tls-login']=='blocked'


def test_unavailable_tls_preserves_trust_record_and_incomplete_scope(candidate):
    args,calls,*_=candidate
    original=args['execute']
    def execute(argv,**kwargs):
        if 'installer-live-tls-probe' in argv[-1]:raise ValueError('private diagnostic')
        return original(argv,**kwargs)
    args['execute']=execute
    result=a.run(**args)
    assert result['trust_inspection']=='verified_public_record'
    assert result['tls_inspection']=='unavailable'
    assert b'private diagnostic' not in (args['output']/a.NAME).read_bytes()
    assert result['acceptance'] is False


def test_published_checkpoint_uses_public_guest_operator_without_claiming_acceptance(candidate,monkeypatch):
    args,calls,context,target,auth,receipt,inv=candidate
    changed=r.decode(auth);changed['phase']='published';auth=r.encode(changed)
    context={key:changed[key] for key in r.CONTEXT_FIELDS}
    receipt=r.encode(r.controller_consumption(auth,inv,expected=context,**target,
        consumed_at=100000,now=100000))
    args['context_file'].write_bytes(r.encode(context))
    args['ledger'].write_bytes(receipt)
    monkeypatch.setattr(a.dispatch,'verify',lambda **_: (auth,receipt,inv,{}))
    monkeypatch.setattr(a.dispatch,'verified_bootstrap',lambda source:'synthetic authenticated source')
    def execute(argv,**kwargs):
        if ' status --install-dir ' in argv[-1]:
            calls.append(('status',argv,kwargs));return r.encode(status(context,target,auth,inv))
        if 'trust-info' in argv[-1]:
            calls.append(('trust',argv,kwargs));return r.encode(trust())
        if 'installer-live-tls-probe' in argv[-1]:
            calls.append(('tls',argv,kwargs));return r.encode(tls(target,trust()))
        calls.append(('probe',argv,kwargs));return r.encode(host())
    args['execute']=execute
    result=a.run(**args)
    assert [v[0] for v in calls]==['probe','dispatch','status','trust','status','tls','status','trust']
    assert all('/bootstrap/marty-deploy-linux-amd64' in v[1][-1]
        for v in calls if v[0] in ('status','trust'))
    assert result['phase']=='published' and result['acceptance'] is False
    assert result['installation_ready'] is False
    assert all(v=='blocked' for k,v in result['cases'].items() if k!='artifact-verification')


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
    assert result['trust_inspection']=='verified_public_record'
    assert b'private-token' not in (args['output']/a.NAME).read_bytes()
    assert all(v=='blocked' for k,v in result['cases'].items() if k!='artifact-verification')


@pytest.mark.parametrize('mutation',['identity','ready','origin','expiry','private_ca','ca_hash','malformed_ca'])
def test_untrusted_or_incomplete_trust_observation_cannot_be_recorded(candidate,mutation):
    args,calls,context,target,auth,receipt,inv=candidate
    def execute(argv,**kwargs):
        if ' status --install-dir ' in argv[-1]:
            return r.encode(status(context,target,auth,inv))
        if 'trust-info' not in argv[-1]:return r.encode(host())
        value=trust()
        if mutation=='identity':value['installation_id']='32345678-1234-4234-8234-123456789abc'
        if mutation=='ready':value['installation_ready']=True
        if mutation=='origin':value['origin']='https://foreign.example:18443'
        if mutation=='expiry':value['ca_expires_at']=100000
        if mutation=='private_ca':value['ca_certificate_pem']+='-----BEGIN PRIVATE KEY-----\nsecret\n'
        if mutation=='ca_hash':value['ca_der_sha256']='f'*64
        if mutation=='malformed_ca':value['ca_certificate_pem']=value['ca_certificate_pem'].replace('MIIB','bad!')
        return r.encode(value)
    args['execute']=execute
    result=a.run(**args)
    assert result['trust_inspection']=='unavailable' and result['trust_info_sha256'] is None
    assert not (args['output']/a.TRUST_NAME).exists()
    assert result['acceptance'] is False


@pytest.mark.parametrize('mutation',['engine','scope','authorization','consumption','identity','inventory','cleanup','phase'])
def test_wrong_candidate_status_cannot_bind_trust_record(candidate,mutation):
    args,_,context,target,auth,receipt,inv=candidate
    def execute(argv,**kwargs):
        if ' status --install-dir ' not in argv[-1]:return r.encode(host())
        value=status(context,target,auth,inv)
        journal=value['journal']
        if mutation=='engine':journal['runtime']['engine_id']='other-engine-12345'
        if mutation=='scope':journal['scope']={'kind':'unclassified'}
        if mutation=='authorization':journal['scope']['authorization_sha256']='f'*64
        if mutation=='consumption':journal['scope']['consumption_id']='f'*64
        if mutation=='identity':journal['identity']['source_sha']='f'*40
        if mutation=='inventory':journal['identity']['inventory_sha256']='sha256:'+'f'*64
        if mutation=='cleanup':value['cleanup']['state']='in_progress'
        if mutation=='phase':journal['phase']='ready';journal['revision']=4
        return r.encode(value)
    args['execute']=execute
    result=a.run(**args)
    assert result['trust_inspection']=='unavailable'
    assert result['trust_info_sha256'] is None and result['status_observation_sha256'] is None
    assert not (args['output']/a.TRUST_NAME).exists()
    assert result['acceptance'] is False


def test_missing_poststart_status_retains_incomplete_checkpoint(candidate):
    args,_,*_=candidate
    def execute(argv,**kwargs):
        if ' status --install-dir ' in argv[-1]:raise ValueError('private diagnostic')
        return r.encode(host())
    args['execute']=execute
    result=a.run(**args)
    assert result['dispatch']=='returned_zero_unqualified'
    assert result['trust_inspection']=='unavailable'
    assert result['acceptance'] is False
    assert b'private diagnostic' not in (args['output']/a.NAME).read_bytes()


def test_status_change_across_trust_export_refuses_paired_record(candidate):
    args,_,context,target,auth,receipt,inv=candidate
    reads=0
    def execute(argv,**kwargs):
        nonlocal reads
        if ' status --install-dir ' in argv[-1]:
            reads+=1
            value=status(context,target,auth,inv)
            if reads==2:value['journal']['phase']='provisioned';value['journal']['revision']=3
            return r.encode(value)
        if 'trust-info' in argv[-1]:return r.encode(trust())
        return r.encode(host())
    args['execute']=execute
    result=a.run(**args)
    assert reads==2 and result['trust_inspection']=='unavailable'
    assert not (args['output']/a.TRUST_NAME).exists()


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
