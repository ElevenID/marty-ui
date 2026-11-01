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
    return dict(schema='elevenid.installer-trust-info/v4',installation_id=installation_id,
        origin='https://marty.example.test',local_probe_address='127.0.0.1:18443',
        certificate_scope='public-ingress',public_endpoint_observed=False,ca_certificate_pem=pem,
        ca_der_sha256=hashlib.sha256(der).hexdigest(),certificate_der_sha256='c'*64,
        ca_expires_at=200000,certificate_expires_at=200000,
        recorded_token_expires_at=200000,evidence_sha256=dict.fromkeys(a.TRUST_EVIDENCE|a.HOSTING_EVIDENCE,'b'*64),
        recorded_startup_containers=30,runtime_observed=False,host_trust_observed=False,
        host_trust_modified=False,installation_ready=False,pending=['browser trust','business journey','recovery'])


def public_trust():
    value=trust()
    value.update(schema='elevenid.installer-trust-info/v5',trust_source='mozilla-public-roots')
    for key in ('ca_certificate_pem','ca_der_sha256','ca_expires_at'):value.pop(key)
    value['evidence_sha256'].pop('installer-ingress.json')
    value['public_certificate_admission']=dict(
        schema='elevenid.installer-external-certificate/v1',installation_id=value['installation_id'],
        transit_key_name='installer-ingress-'+value['installation_id'].replace('-',''),transit_key_version=1,
        public_spki_sha256='a'*64,dns_names=['marty.example.test'],ip_addresses=[],
        private_key_exported=False,activation_performed=False,installation_ready=False,
        trust_class='production_public',trust_store='mozilla_webpki_roots',trust_store_sha256='e'*64,
        trust_anchor_spki_value_sha256='f'*64,public_chain_validated=True,observed_at=90000,
        not_before=80000,not_after=200000,minimum_remaining_seconds=3600,maximum_validity_seconds=8640000,
        leaf_der_sha256='c'*64,fullchain_pem_sha256='d'*64,intermediate_count=1,
        revocation_status='not_checked',browser_acceptance='not_assessed')
    return value


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
            runtime=dict(docker_host='unix:///run/user/1000/docker.sock',engine_id=target['engine_id'],
                openbao_port=18442,profile='rootless'),hosting_selection_sha256='b'*64,
            scope=dict(kind='acceptance-only',authorization_sha256=r.digest(auth),
                context_sha256=r.candidate_context_sha256(context),consumption_id=consumption)),
        cleanup=dict(operations=dict.fromkeys(('start','stop','down'),'not_started'),
            next_operations={action:action+'-0001' for action in ('start','stop','down')},
            historical_evidence_only=True,automatic_retry=False,
            host_data_credentials_images_and_named_volumes_retained=True))


def tls(target,trust_value):
    return dict(schema='elevenid.installer-live-tls-observation/v2',
        installation_id=target['installation_id'],engine_id=target['engine_id'],
        origin=trust_value['origin'],ca_der_sha256=trust_value['ca_der_sha256'],
        local_probe_address=trust_value['local_probe_address'],certificate_scope=trust_value['certificate_scope'],
        public_endpoint_observed=False,
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
        lambda source,name:(Path(__file__).resolve().parents[1]/'scripts'/name)
        .read_bytes().decode('utf-8'))
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
        host='127.0.0.1',port=2222,user='installer',home='/home/installer',clock=lambda:100000,execute=execute,candidate_dispatch=dispatch,
        resource_profile=a.STARTUP_PROFILE)
    return args,calls,context,target,auth,receipt,inv


def test_real_probe_before_dispatch_and_never_claims_acceptance(candidate):
    args,calls,context,target,auth,receipt,inv=candidate
    a.status_observation(r.encode(status(context,target,auth,inv)),context,target,auth,inv)
    a.trust_observation(r.encode(trust()),target,100000,journal=status(context,target,auth,inv)['journal'])
    result=a.run(**args)
    assert [v[0] for v in calls]==['probe','dispatch','status','trust','status','tls','status','trust']
    assert calls[0][1][:2]==['/usr/bin/ssh','-F']
    assert 'env -i HOME=/home/installer PATH=/usr/bin:/bin /usr/bin/python3 -c' in calls[0][1][-1]
    assert set(calls[0][2]['env'])=={'HOME','PATH','LANG','LC_ALL'}
    assert calls[0][2]['timeout']==120
    assert result['dispatch']=='returned_zero_unqualified' and result['acceptance'] is False
    assert result['resource_profile']==a.STARTUP_PROFILE
    assert result['functional_recovery_qualified'] is False and result['load_characterized'] is False
    assert result['trust_inspection']=='verified_public_record'
    assert result['tls_inspection']=='verified_local_https'
    assert result['tls_observation_sha256']==r.digest((args['output']/a.TLS_NAME).read_bytes())
    assert result['trust_info_sha256']==r.digest((args['output']/a.TRUST_NAME).read_bytes())
    assert result['status_observation_sha256']==r.digest((args['output']/a.STATUS_NAME).read_bytes())
    assert all(v=='blocked' for k,v in result['cases'].items() if k!='artifact-verification')
    assert (args['output']/a.NAME).exists() and not (args['output']/'installer-acceptance.json').exists()
    with pytest.raises(FileExistsError):a.run(**args)
    assert len(calls)==8



@pytest.mark.parametrize('mutation',[None,'uid','proof'])
def test_versioned_checkpoint_binds_real_probe_uid_and_authenticated_file_digests(candidate,monkeypatch,mutation):
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    from test_installer_host_admission import observed_rootless_host_with_neighbors
    args,calls,context,target,auth,receipt,inv=candidate
    files={}
    for directory,source,raw in [(args['grants'],'candidate-authorization.json',auth),
        (args['grants'],'controller-consumption.json',receipt),(args['assets'],'installer-inventory.json',inv)]:
        directory.mkdir(mode=0o700,exist_ok=True)
        for suffix in a.dispatch.SUFFIXES:
            path=directory/(source+suffix)
            data=raw if not suffix else ('synthetic proof '+source+suffix).encode()
            path.write_bytes(data);path.chmod(0o600)
            files[path]=(r.digest(data),len(data))
    pins=a.authenticated_source_digests(files,args['assets'],args['grants'])
    monkeypatch.setattr(a.dispatch,'verify',lambda **_: (auth,receipt,inv,files))
    original=args['execute']
    host_value=observed_rootless_host_with_neighbors()
    def execute(argv,**kwargs):
        if ' status --install-dir ' in argv[-1]:
            value=r.decode(original(argv,**kwargs))
            value['journal']['scope']['authenticated_evidence_sha256']=dict(pins)
            if mutation=='uid':value['journal']['runtime']['docker_host']='unix:///run/user/1001/docker.sock'
            if mutation=='proof':value['journal']['scope']['authenticated_evidence_sha256']['installer-controller-consumption.json']='f'*64
            return r.encode(value)
        if 'installer-host-probe' in argv[-1]:
            calls.append(('probe',argv,kwargs));return r.encode(host_value)
        return original(argv,**kwargs)
    args.update(resource_profile=a.ROOTLESS_STARTUP_PROFILE,execute=execute)
    result=a.run(**args)
    assert result['schema']==a.SCHEMA_V5 and result['host_preflight']=='passed'
    assert result['authenticated_evidence_sha256']==pins
    assert result['host_runtime']['uid']==1000
    assert result['host_resources_sha256']==r.digest(r.encode(host_value['resources']))
    assert result['installation_ready'] is result['acceptance'] is result['functional_recovery_qualified'] is False
    assert set(result['cases'])==set(a.qualification.FUNCTIONAL_CASES)
    assert all(result['cases'][case]=='blocked' for case in result['cases'] if case!='artifact-verification')
    assert result['trust_inspection']==('verified_public_record' if mutation is None else 'unavailable')


def test_selected_generation_evidence_requires_one_sequence_and_one_positive_attempt():
    kinds={'intent','public-ingress-plan','helper','candidate','binding','activation-intent','activation','session','selection'}
    base={'application-generation-current.json':'a'*64}
    for attempt in [None,1,99]:
        prefix='generation-'+f'{3:020}-'+('' if attempt is None else f'attempt-{attempt:020}-')
        proof={**base,**{prefix+kind+'.json':'b'*64 for kind in kinds}}
        a.selected_generation_evidence(proof)
        for bad_prefix in ['generation-'+f'{4:020}-', 'generation-'+f'{3:020}-attempt-{0:020}-',
                           'generation-'+f'{3:020}-attempt-{2:020}-']:
            mixed=dict(proof);mixed.pop(prefix+'binding.json');mixed[bad_prefix+'binding.json']='b'*64
            with pytest.raises(ValueError):a.selected_generation_evidence(mixed)


def test_8gib_startup_checkpoint_never_becomes_functional_or_load_evidence(candidate):
    args,calls,*_=candidate
    original=args['execute']
    def execute(argv,**kwargs):
        if 'installer-host-probe' in argv[-1]:
            value=host()
            value.update(docker_memory_bytes=8*1024**3,guest_memory_bytes=8*1024**3-256*1024**2)
            value['predicates']['capacity']=False
            return r.encode(value)
        return original(argv,**kwargs)
    args['execute']=execute
    result=a.run(**args)
    observed=r.decode((args['output']/'host-observation.json').read_bytes())
    assert observed['guest_memory_bytes']==8*1024**3-256*1024**2
    assert result['resource_profile']=='startup-8gib' and result['host_preflight']=='passed'
    assert result['functional_recovery_qualified'] is False and result['load_characterized'] is False
    assert result['acceptance'] is False and result['installation_ready'] is False
    assert result['cases']['issue']=='blocked'


def test_imported_trust_bundle_uses_native_evidence_and_nullable_token_expiry(candidate):
    _,_,context,target,auth,_,inv=candidate
    value=trust()
    value['ca_der_sha256s']=[value['ca_der_sha256']]
    value['recorded_token_expires_at']=None
    value['certificate_scope']='backend'
    value['evidence_sha256'].pop('installer-ingress.json')
    value['evidence_sha256'].pop('generation-observation.json')
    value['evidence_sha256']['foundation-selection.json']='c'*64
    journal=status(context,target,auth,inv)['journal']
    assert a.trust_observation(r.encode(value),target,100000,journal=journal)==value
    value['ca_der_sha256s']=['a'*64]
    with pytest.raises(ValueError,match='trust roots differ'):
        a.trust_observation(r.encode(value),target,100000,journal=journal)


def test_legacy_rootful_status_is_historical_observation_only(candidate):
    _,_,context,target,auth,_,inv=candidate
    value=status(context,target,auth,inv)
    value['journal']['runtime'].pop('profile')
    value['journal']['runtime']['docker_host']='unix:///var/run/docker.sock'
    assert a.status_observation(r.encode(value),context,target,auth,inv)==value
    assert value['runtime_observed'] is False


def test_public_v5_trust_keeps_native_roots_and_no_fabricated_ca(candidate):
    _,_,context,target,auth,_,inv=candidate
    journal=status(context,target,auth,inv)['journal']
    value=public_trust()
    assert a.trust_observation(r.encode(value),target,100000,journal=journal)==value
    for key,wrong in [('trust_class','staging_test'),('public_chain_validated',False),
                      ('leaf_der_sha256','0'*64),('not_after',100000),('transit_key_version',2),
                      ('installation_id','32345678-1234-4234-8234-123456789abc'),
                      ('private_key_exported',True),('browser_acceptance','passed')]:
        changed=copy.deepcopy(value);changed['public_certificate_admission'][key]=wrong
        with pytest.raises(ValueError):a.trust_observation(r.encode(changed),target,100000,journal=journal)
    for key in ('ca_certificate_pem','ca_der_sha256','ca_expires_at'):
        changed=copy.deepcopy(value);changed[key]=trust()[key]
        with pytest.raises(ValueError):a.trust_observation(r.encode(changed),target,100000,journal=journal)


def test_v5_configured_ca_and_current_cleanup_schema_remain_observational(candidate):
    _,_,context,target,auth,_,inv=candidate
    observed=status(context,target,auth,inv)
    observed['cleanup']['pending_operations']={}
    assert a.status_observation(r.encode(observed),context,target,auth,inv)==observed
    value=trust();value.update(schema='elevenid.installer-trust-info/v5',trust_source='configured-ca')
    assert a.trust_observation(r.encode(value),target,100000,journal=observed['journal'])==value
    observed['cleanup']['pending_operations']['start']='start-0001'
    with pytest.raises(ValueError):a.status_observation(r.encode(observed),context,target,auth,inv)


def test_selected_generation_requires_exact_common_sequence_and_selector(candidate):
    _,_,context,target,auth,_,inv=candidate
    value=public_trust()
    kinds=('intent','public-ingress-plan','helper','candidate','binding','activation-intent',
           'activation','session','selection')
    evidence={f'generation-{1:020}-{kind}.json':'d'*64 for kind in kinds}
    evidence['application-generation-current.json']='e'*64
    value['selected_generation']=evidence
    journal=status(context,target,auth,inv)['journal']
    assert a.trust_observation(r.encode(value),target,100000,journal=journal)==value
    for change in ('missing_selector','mixed_sequence','unknown','bad_digest'):
        changed=copy.deepcopy(value)
        evidence=changed['selected_generation']
        if change=='missing_selector':evidence.pop('application-generation-current.json')
        elif change=='mixed_sequence':evidence[f'generation-{2:020}-binding.json']=evidence.pop(f'generation-{1:020}-binding.json')
        elif change=='unknown':evidence[f'generation-{1:020}-unreviewed.json']=evidence.pop(f'generation-{1:020}-binding.json')
        else:evidence['application-generation-current.json']='invalid'
        with pytest.raises(ValueError):a.trust_observation(r.encode(changed),target,100000,journal=journal)


def test_public_probe_records_its_own_store_and_exact_selected_leaf(candidate):
    _,_,_,target,_,_,_=candidate
    native=public_trust()
    observed=tls(target,trust())
    observed.pop('ca_der_sha256')
    observed.update(schema='elevenid.installer-live-tls-observation/v3',
        probe_trust_source='ubuntu-system-ca-bundle',probe_trust_bundle_sha256='a'*64)
    assert a.tls_observation(r.encode(observed),native,target,100000)==observed
    for key,wrong in [('probe_trust_source','explicit_staging_roots'),('peer_der_sha256','f'*64),
                      ('public_endpoint_observed',True),('browser_login_observed',True)]:
        changed=copy.deepcopy(observed);changed[key]=wrong
        with pytest.raises(ValueError):a.tls_observation(r.encode(changed),native,target,100000)


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


@pytest.mark.parametrize('mutation',['peer','engine','browser','ca','origin','stale','address','scope','public'])
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
        if mutation=='address':value['local_probe_address']='127.0.0.1:18444'
        if mutation=='scope':value['certificate_scope']='backend'
        if mutation=='public':value['public_endpoint_observed']=True
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


@pytest.mark.parametrize('mutation',['identity','ready','origin','expiry','private_ca','ca_hash','malformed_ca',
    'hosting','missing_generation','public','scope','address'])
def test_untrusted_or_incomplete_trust_observation_cannot_be_recorded(candidate,mutation):
    args,calls,context,target,auth,receipt,inv=candidate
    def execute(argv,**kwargs):
        if ' status --install-dir ' in argv[-1]:
            return r.encode(status(context,target,auth,inv))
        if 'trust-info' not in argv[-1]:return r.encode(host())
        value=trust()
        if mutation=='identity':value['installation_id']='32345678-1234-4234-8234-123456789abc'
        if mutation=='ready':value['installation_ready']=True
        if mutation=='origin':value['origin']='https://foreign.example:18443/path'
        if mutation=='expiry':value['ca_expires_at']=100000
        if mutation=='private_ca':value['ca_certificate_pem']+='-----BEGIN PRIVATE KEY-----\nsecret\n'
        if mutation=='ca_hash':value['ca_der_sha256']='f'*64
        if mutation=='malformed_ca':value['ca_certificate_pem']=value['ca_certificate_pem'].replace('MIIB','bad!')
        if mutation=='hosting':value['evidence_sha256']['hosting-selection.json']='e'*64
        if mutation=='missing_generation':value['evidence_sha256'].pop('generation-observation.json')
        if mutation=='public':value['public_endpoint_observed']=True
        if mutation=='scope':value['certificate_scope']='browser'
        if mutation=='address':value['local_probe_address']='marty.example.test:18443'
        return r.encode(value)
    args['execute']=execute
    result=a.run(**args)
    assert result['trust_inspection']=='unavailable' and result['trust_info_sha256'] is None
    assert not (args['output']/a.TRUST_NAME).exists()
    assert result['acceptance'] is False


@pytest.mark.parametrize('mutation',['engine','scope','authorization','consumption','identity','inventory','cleanup','phase',
    'socket','runtime_profile','missing_hosting_binding'])
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
        if mutation=='cleanup':value['cleanup']['operations']['down']='uncertain'
        if mutation=='phase':journal['phase']='ready';journal['revision']=4
        if mutation=='socket':journal['runtime']['docker_host']='unix:///var/run/docker.sock'
        if mutation=='runtime_profile':journal['runtime']['profile']='rootful'
        if mutation=='missing_hosting_binding':journal['hosting_addon_sha256']=journal.pop('hosting_selection_sha256')
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


@pytest.mark.parametrize('field',['functional_recovery_qualified','load_characterized'])
def test_checkpoint_cannot_claim_functional_or_load_qualification(candidate,field):
    args,_,context,target,auth,receipt,inv=candidate
    result=a.run(**args);result[field]=True
    with pytest.raises(ValueError,match='checkpoint scope differs'):
        a.validate(result,context=context,target=target,authorization=auth,receipt=receipt,inventory=inv)


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


@pytest.mark.parametrize('public,mutation', [(False, value) for value in (None,'origin','input-bytes','trust-class')]
    + [(True, value) for value in (None,'origin','input-bytes','trust-class','ip-alias','staging')])
def test_signed_hosting_readback_binds_origin_raw_input_source_and_public_alias(public, mutation):
    fixture=json.loads((Path(__file__).resolve().parents[1]/
        'rust/crates/deployment-catalog/tests/fixtures/installer-candidate-hosting-v2.json').read_text())
    binding=r.decode(fixture[1 if public else 0]['authorization'].encode())['hosting']
    binding['public_entry_origin']='https://8.8.4.4'
    value=public_trust() if public else trust()
    value.update(schema='elevenid.installer-trust-info/v5',origin=binding['public_origin'],
                 trust_source='mozilla-public-roots' if public else 'configured-ca')
    value['evidence_sha256']['hosting-input.json']=binding['input_sha256']
    if public:
        value['public_certificate_admission']['dns_names']=['marty.example.com']
        value['public_certificate_admission']['ip_addresses']=['8.8.4.4']
    journal=dict(installation_id=value['installation_id'],hosting_selection_sha256='b'*64)
    if mutation=='origin':binding['public_origin']='https://different.example.com'
    elif mutation=='input-bytes':binding['input_sha256']='f'*64
    elif mutation=='trust-class':
        binding['certificate_source']='managed-ca' if public else 'acme'
        binding['acme_environment']=None if public else 'production'
        binding['acme_terms_url']=None if public else 'https://letsencrypt.org/documents/fixture-terms.pdf'
    elif mutation=='ip-alias':
        binding['public_entry_origin']='https://8.8.8.8'
    elif mutation=='staging':
        binding['acme_environment']='staging'
        binding['staging_trust']={'sha256':'f'*64,'size_bytes':128}
    target={'installation_id':value['installation_id']}
    if mutation is None:
        assert a.trust_observation(r.encode(value),target,100000,journal=journal,bound_hosting=binding)==value
    else:
        with pytest.raises(ValueError):
            a.trust_observation(r.encode(value),target,100000,journal=journal,bound_hosting=binding)
