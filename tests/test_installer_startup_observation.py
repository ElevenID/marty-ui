"""Closed owner/transport adapter regressions, not installed or cryptographic proof.

Native/browser fixture facts below are synthetic. Production invokes the signed
native owner, real Chromium and pinned external verifiers; these tests exercise
their record closure, refusal and orchestration boundaries only.
"""
import copy
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import installer_acceptance_runner as runner
import installer_acceptance_startup as startup
import installer_acceptance_v2 as v2
import installer_browser_runtime as runtime
import installer_candidate_dispatch as dispatch
import installer_candidate_rendezvous as rendezvous
import installer_release as r
import installer_startup_browser as browser
import installer_startup_observation as native
import installer_startup_transport as transport
import verify_installer_provenance as provenance
from test_installer_candidate_dispatch import staged
from test_installer_candidate_hosting import configuration, encoded
from test_installer_host_admission import observed_rootless_host_with_neighbors
from test_installer_acceptance_runner import public_trust

ACTUAL_VERIFY_SUBJECT = provenance.verify_subject


def put(path, raw, mode=0o600):
    path.write_bytes(raw)
    path.chmod(mode)
    return path


@pytest.fixture
def startup_case(staged, monkeypatch):
    options, calls, proofs = staged
    monkeypatch.setattr(provenance, 'verify_subject', ACTUAL_VERIFY_SUBJECT)
    root = options['assets'].parent
    config = configuration('acme')
    config['public_entry_origin'] = 'https://8.8.4.4'
    hosting_bytes = encoded(config)
    grant = r.decode((options['grants']/'candidate-authorization.json').read_bytes())
    grant.update(schema=r.CANDIDATE_SCHEMA_V2, hosting=r.candidate_hosting.from_bytes(hosting_bytes))
    authorization = r.encode(grant)
    context = r.candidate_context(grant)
    target = r.decode(options['target_file'].read_bytes())
    inventory = (options['assets']/'installer-inventory.json').read_bytes()
    receipt = r.encode(r.controller_consumption(authorization, inventory, expected=context, **target,
        consumed_at=100001, now=100001))
    auth_path = put(options['grants']/'candidate-authorization.json', authorization)
    receipt_path = put(options['grants']/'controller-consumption.json', receipt)
    put(options['grants']/r.candidate_hosting.NAME, hosting_bytes)
    put(options['ledger'], receipt)
    put(options['context_file'], r.encode(context))
    files = {}
    for directory, names in ((options['assets'], dispatch.SUBJECTS),
                              (options['grants'], ('candidate-authorization.json','controller-consumption.json'))):
        for name in names:
            for suffix in dispatch.SUFFIXES:
                path=directory/(name+suffix)
                files[path]=(r.digest(path.read_bytes()),path.stat().st_size)
    pins=runner.authenticated_source_digests(files,options['assets'],options['grants'])
    artifact=native.artifact_record(files=files,assets=options['assets'],grants=options['grants'],context=context,
        target=target,authorization=authorization,receipt=receipt,inventory=inventory,started_at=100002,completed_at=100005)
    host=observed_rootless_host_with_neighbors()
    host['engine_id']=target['engine_id']
    selection=dict(kind='current',sequence=0,attempt=0,current_binding_sha256='5'*64,
        session_sha256='6'*64,configuration_sha256='7'*64,
        selected_evidence_sha256={key:'5'*64 for key in native.INITIAL_EVIDENCE})
    trust=public_trust()
    trust['installation_id']=target['installation_id']
    trust['origin']=context['hosting']['public_origin']
    trust['evidence_sha256'].update({'hosting-input.json':context['hosting']['input_sha256'],
        'hosting-selection.json':'8'*64,'compose-session.json':'5'*64,'application-generation-selection.json':'5'*64})
    admission=trust['public_certificate_admission']
    admission.update(installation_id=target['installation_id'],
        transit_key_name='installer-ingress-'+target['installation_id'].replace('-',''),
        dns_names=['marty.example.com'],ip_addresses=['8.8.4.4'])
    page=dict(origin=context['hosting']['public_entry_origin'],app_name='Actual fixture brand',
        alias_api_isolation_observed=True,assets=[])
    for path in sorted(('/', '/runtime-config.js','/startup.js','/config.json','/assets/main-123.js')):
        raw=('fixture public asset '+path).encode()
        page['assets'].append(dict(path=path,media_type='text/html' if path=='/' else
            'application/json' if path=='/config.json' else 'application/javascript',size_bytes=len(raw),sha256=r.digest(raw)))
    resources=dict(containers={'gateway':dict(id='9'*64,service='gateway',image=r.decode(inventory)['images']['gateway'],
        config_hash='0'*64,setup=False,setup_execution=None,health_required=True,cap_add=[],cap_drop=[],
        read_only=False,memory_limit=268435456)},networks={'default':'f'*64},volumes=['owned-app-data'])
    services=dict(services_observed=True,all_expected_states_observed=True,not_atomic_snapshot=True,installation_ready=False,
        services={'gateway':dict(container_id='9'*64,status='running',health='healthy',exit_code=0,expected='healthy',
            expected_state_observed=True,configuration_verified=True,observation_source='docker_compose_ps',
            oom_kill_history_observed=False,restart_history_observed=False)})
    bundle=dict(schema='elevenid.installer-bundle-validation/v1',file_count=42,directory_count=4,
        marker_sha256='a'*64,image_lock_sha256=next(i['sha256'] for i in r.decode(inventory)['artifacts']
                                                   if i['name']=='prepared-selfhost-images.json'),runtime_observed=False)
    base=dict(schema=native.NATIVE_SCHEMA,status='startup_observed',installation_id=target['installation_id'],
        engine_id=target['engine_id'],operator_sha256=context['operator_sha256'],context_sha256=r.candidate_context_sha256(context),
        authority=dict(authorization_sha256=r.digest(authorization),controller_consumption_sha256=r.digest(receipt),
            inventory_sha256=r.digest(inventory),consumption_id=native.consumption_id(context,target,authorization),
            authenticated_evidence_sha256=pins,consumed_at=100001),
        runtime=dict(profile='rootless',uid=1000,docker_host='unix:///run/user/1000/docker.sock',no_new_privileges=True),
        hosting=grant['hosting'],selection=selection,canary_evidence_sha256={**dict.fromkeys(native.CANARY_EVIDENCE,'e'*64),**pins},
        bundle_validation=bundle,bundle_validation_sha256=r.digest(r.encode(bundle)),resources=resources,services=services,
        trust=trust,page=page,not_atomic_snapshot=True,installation_ready=False,functional_recovery_qualified=False,load_characterized=False)

    def observed(started_at):
        value=copy.deepcopy(base)
        value.update(request=dict(observation_id=str(uuid.uuid4()),challenge='a'*64),started_at=started_at,completed_at=started_at+1)
        validation_id=str(uuid.uuid4())
        record=dict(schema='elevenid.deployment-validation/v1',validation_id=validation_id,installation_id=target['installation_id'],
            release=dict(source_sha=context['source_sha'],release_tag=context['release_tag'],inventory_sha256='sha256:'+r.digest(inventory)),
            engine_id=target['engine_id'],scope='read_only_deployment',observed_at=started_at,elapsed_ms=100,status='passed',
            checks=[dict(name=name,required=name!='Credential journey',status='skip' if name=='Credential journey' else 'pass',
                code='isolated_test_fixtures_required' if name=='Credential journey' else
                'local_listener_observation' if name==native.VALIDATION_CHECKS[-1] else 'observed')
                for name in (*native.VALIDATION_CHECKS,'Credential journey')],
            not_atomic_snapshot=True,installation_ready=False,host_trust_observed=False,qualification='not_assessed',
            browser_rendering_observed=False,public_network_reachability_observed=False,container_security_posture=None,
            trust_evidence_sha256=value['trust']['evidence_sha256'])
        raw=r.encode(record)
        value['validation']=dict(name='validation-'+validation_id+'.json',record=raw.decode(),sha256=r.digest(raw))
        return value
    before,after=observed(100010),observed(100014)
    runtime_identity=dict(runtime._load_policy().identity)
    request=browser.request(r.encode(before),before,runtime_identity)
    browser_value={key:request[key] for key in ('request','native_sha256','installation_id','engine_id','operator_sha256',
        'context_sha256','selection_sha256','runtime','canonical_origin','public_entry_origin')}
    browser_value.update(schema=browser.SCHEMA,started_at=100012,completed_at=100013,https_errors_ignored=False,
        installation_ready=False,functional_recovery_qualified=False,load_characterized=False,
        observations=dict(ip_requests=15,ip_session_requests=0,ip_credential_headers=0,ip_response_cookies=0,
            ip_stored_cookies=0,page_errors=0,failed_asset_requests=0),
        landing=dict(url=request['public_entry_origin']+'/',heading_count=1,branding_visible=True,image_count=1,images_loaded=True,
            screenshot_sha256='1'*64,assets=[dict(item,status=200) for item in page['assets']],
            certificate_der_sha256=trust['certificate_der_sha256']),
        actions={name:dict(selector=selector,source_url=request['public_entry_origin']+'/',
            document_requests=[dict(origin=request['canonical_origin'],path=path,method='GET')],
            final_origin=request['canonical_origin'],final_path='/login',certificate_der_sha256=trust['certificate_der_sha256'])
            for name,selector,path in [('sign_in','login-button','/v1/auth/login'),('console','public-entry-console','/console')]})
    host_after=copy.deepcopy(host)
    host_after['resources']['containers'].append('9'*64)
    host_after['resources']['volumes'].append('owned-app-data')
    host_after['resources']['networks'].append(dict(id='f'*64,name='owned-default',driver='bridge',attached_count=1))
    for key in ('containers','images','volumes'):host_after['resources'][key].sort()
    for name in host_after['resources']:host_after['resource_counts'][name]=len(host_after['resources'][name])
    records=dict(artifacts=r.encode(artifact),native_before=r.encode(before),native_after=r.encode(after),
                 browser=r.encode(browser_value),host_after=r.encode(host_after))
    report=startup._assemble(records=records,context=context,target=target,authorization=authorization,receipt=receipt,
        inventory=inventory,pins=pins,host_raw=r.encode(host),observed_at=100016)
    active=dict(repository=dict(full_name=r.REPOSITORY),path=r.acceptance.WORKFLOW,event='workflow_dispatch',head_branch='main',
        head_sha=context['harness_source_sha'],id=context['run_id'],run_attempt=context['run_attempt'],status='in_progress',conclusion=None)
    completed=dict(active,status='completed',conclusion='success')
    verification_calls=[]
    def verifier(argv,**kwargs):
        verification_calls.append(argv)
        if Path(argv[0]).name=='cosign':return 'mocked signature success, not cryptographic evidence'
        workflow=argv[argv.index('--signer-workflow')+1].removeprefix(r.REPOSITORY+'/')
        source=argv[argv.index('--source-digest')+1]
        run_id,attempt=(context['run_id'],context['run_attempt']) if workflow==r.acceptance.WORKFLOW else (42,2)
        cert=dict(issuer=provenance.ISSUER,runnerEnvironment='github-hosted',sourceRepositoryURI='https://github.com/'+r.REPOSITORY,
            sourceRepositoryIdentifier=provenance.REPOSITORY_ID,sourceRepositoryDigest=source,sourceRepositoryRef='refs/heads/main',
            runInvocationURI=f'https://github.com/{r.REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}',
            buildSignerURI=f'https://github.com/{r.REPOSITORY}/{workflow}@refs/heads/main')
        return json.dumps([dict(attestation={},verificationResult=dict(signature=dict(certificate=cert)))])
    return SimpleNamespace(options=options,root=root,context=context,target=target,authorization=authorization,receipt=receipt,
        inventory=inventory,pins=pins,host=host,host_after=host_after,before=before,after=after,browser=browser_value,
        artifact=artifact,records=records,report=report,active=active,completed=completed,verifier=verifier,
        verification_calls=verification_calls,auth_path=auth_path,receipt_path=receipt_path)


def expected(case):
    return dict(inventory_bytes=case.inventory,source_sha=case.context['source_sha'],
                release_tag=case.context['release_tag'],phase=case.context['phase'])


def native_expected(case):
    return dict(context=case.context,target=case.target,authorization=case.authorization,receipt=case.receipt,
                inventory=case.inventory,pins=case.pins,observed_at=100020,host_runtime=case.host['runtime'])


def test_five_derived_cases_require_closed_owner_records_and_keep_full_qualification_closed(startup_case):
    c=startup_case
    assert startup.validate_active_payload(c.report,run=c.active,**expected(c))==c.report
    assert startup.validate_completed_return(c.report,run=c.completed,**expected(c))==c.report
    assert set(c.report['cases'])==set(v2.STARTUP_CASES)
    assert c.report['selection']['selected_evidence_sha256']
    assert all(c.report[key] is False for key in ('installation_ready','functional_recovery_qualified','load_characterized'))
    assert c.report['neighbor_preservation']['neighbor_data_qualified'] is False
    with pytest.raises(ValueError,match='startup evidence cannot promote'):
        r.acceptance.validate(c.report,run=c.completed,**expected(c))


@pytest.mark.parametrize('mode',['completed-production','active-consumption','failed-consumption','wrong-attempt','wrong-source','other-workflow','pull-request'])
def test_active_writer_and_completed_consumer_authorities_are_distinct(startup_case,mode):
    c=startup_case
    production=mode=='completed-production'
    run=copy.deepcopy(c.active if production or mode=='active-consumption' else c.completed)
    if mode=='completed-production':run=c.completed
    elif mode=='failed-consumption':run['conclusion']='failure'
    elif mode=='wrong-attempt':run['run_attempt']+=1
    elif mode=='wrong-source':run['head_sha']='e'*40
    elif mode=='other-workflow':run['path']='.github/workflows/ci.yml'
    elif mode=='pull-request':run['event']='pull_request'
    with pytest.raises(ValueError):
        (startup.validate_active_payload if production else startup.validate_completed_return)(c.report,run=run,**expected(c))


@pytest.mark.parametrize('mutation',['scope','ready','functional','challenge','root','socket','missing-pin','canary','image','container',
    'setup','validation','expiry','staging','alias','asset','brand','isolated-api','current','initial-missing'])
def test_native_owner_refuses_scope_runtime_trust_and_current_selection_substitutions(startup_case,mutation):
    c=startup_case;value=copy.deepcopy(c.before)
    if mutation=='scope':value['installation_id']=str(uuid.uuid4())
    elif mutation=='ready':value['installation_ready']=True
    elif mutation=='functional':value['functional_recovery_qualified']=True
    elif mutation=='challenge':value['request']['challenge']='not-a-sha'
    elif mutation=='root':value['runtime']['uid']=0
    elif mutation=='socket':value['runtime']['docker_host']='unix:///var/run/docker.sock'
    elif mutation=='missing-pin':value['authority']['authenticated_evidence_sha256'].pop('installer-inventory.json.sigstore.json')
    elif mutation=='canary':value['canary_evidence_sha256']['installer-controller-consumption.json']='b'*64
    elif mutation=='image':value['resources']['containers']['gateway']['image']='ghcr.io/other@sha256:'+'c'*64
    elif mutation=='container':value['services']['services']['gateway']['container_id']='a'*64
    elif mutation=='setup':value['resources']['containers']['gateway']['setup']=True
    elif mutation=='validation':value['validation']['record']+=' '
    elif mutation=='expiry':value['trust']['certificate_expires_at']=100010
    elif mutation=='staging':value['trust']['public_certificate_admission']['trust_class']='staging_test'
    elif mutation=='alias':value['page']['origin']=value['hosting']['public_origin']
    elif mutation=='asset':value['page']['assets'][1]['path']='/v1/auth/me'
    elif mutation=='brand':value['page']['app_name']=None
    elif mutation=='isolated-api':value['page']['alias_api_isolation_observed']=False
    elif mutation=='current':value['selection']['kind']='rollback'
    elif mutation=='initial-missing':value['selection']['selected_evidence_sha256']={}
    with pytest.raises(ValueError):native.native(r.encode(value),**native_expected(c))


@pytest.mark.parametrize('mutation',['cookies','session','credential-header','javascript','missing-asset','asset-body','tls','runtime',
    'native','selection','early','late','no-click','ip-click','registration','console','redirect','leaf','branding'])
def test_real_browser_adapter_refuses_missing_action_asset_session_and_public_tls_facts(startup_case,mutation):
    c=startup_case;value=copy.deepcopy(c.browser)
    if mutation=='cookies':value['observations']['ip_stored_cookies']=1
    elif mutation=='session':value['observations']['ip_session_requests']=1
    elif mutation=='credential-header':value['observations']['ip_credential_headers']=1
    elif mutation=='javascript':value['observations']['page_errors']=1
    elif mutation=='missing-asset':value['landing']['assets'].pop()
    elif mutation=='asset-body':value['landing']['assets'][0]['sha256']='0'*64
    elif mutation=='tls':value['https_errors_ignored']=True
    elif mutation=='runtime':value['runtime']['chromium_version']='unreviewed'
    elif mutation=='native':value['native_sha256']='0'*64
    elif mutation=='selection':value['selection_sha256']='0'*64
    elif mutation=='early':value['started_at']=100009
    elif mutation=='late':value['completed_at']=100163
    elif mutation=='no-click':value['actions']['sign_in']['document_requests']=[]
    elif mutation=='ip-click':value['actions']['sign_in']['document_requests'][0]['origin']=value['public_entry_origin']
    elif mutation=='registration':value['actions']['registration']=value['actions']['sign_in']
    elif mutation=='console':value['actions']['console']['document_requests'][0]['path']='/v1/auth/login'
    elif mutation=='redirect':value['actions']['sign_in']['document_requests'].append(dict(origin='https://foreign.example',path='/login',method='GET'))
    elif mutation=='leaf':value['actions']['console']['certificate_der_sha256']='0'*64
    elif mutation=='branding':value['landing']['branding_visible']=False
    with pytest.raises(ValueError):browser.validate(r.encode(value),native_raw=c.records['native_before'],native=c.before,now=100020)


@pytest.mark.parametrize('mutation',['generic-case','missing-owner','changed-native','rewritten-owner','neighbor','engine','proof-reference','extra-case'])
def test_whole_report_does_not_accept_caller_passes_or_splice_owner_windows(startup_case,mutation):
    c=startup_case;value=copy.deepcopy(c.report)
    if mutation=='generic-case':value['proofs']['ip-entry-browser']=dict(status='passed')
    elif mutation=='missing-owner':value['owner_records'].pop('native_after')
    elif mutation=='changed-native':value['owner_records']['native_after']['record']+=' '
    elif mutation=='rewritten-owner':
        native_value=copy.deepcopy(c.after);native_value['selection']['configuration_sha256']='0'*64
        raw=r.encode(native_value);value['owner_records']['native_after']=dict(record=raw.decode(),sha256=r.digest(raw))
    elif mutation=='neighbor':value['neighbor_preservation']['neighbor_data_qualified']=True
    elif mutation=='engine':value['scope']['engine_id']='foreign-engine'
    elif mutation=='proof-reference':value['proofs']['startup-runtime']['sha256']='0'*64
    elif mutation=='extra-case':value['cases']['backup-restore']='passed'
    with pytest.raises(ValueError):startup.validate_active_payload(value,run=c.active,**expected(c))


@pytest.mark.parametrize('attempt',[0,3])
def test_public_successor_evidence_pins_one_sequence_attempt_plan_and_current_selector(startup_case,attempt):
    value=copy.deepcopy(startup_case.before['selection'])
    value.update(sequence=2,attempt=attempt)
    prefix=f'generation-{2:020}'+(f'-attempt-{attempt:020}' if attempt else '')
    kinds=('intent','public-ingress-plan','helper','candidate','binding','activation-intent','activation','session','selection')
    value['selected_evidence_sha256']={prefix+'-'+kind+'.json':'5'*64 for kind in kinds}
    value['selected_evidence_sha256']['application-generation-current.json']='6'*64
    assert native.current_selection(value)==value
    for mutation in ('mixed-attempt','mixed-sequence','managed-plan','empty'):
        wrong=copy.deepcopy(value);records=wrong['selected_evidence_sha256']
        if mutation=='empty':records.clear()
        elif mutation=='managed-plan':records[prefix+'-managed-renewal-plan.json']=records.pop(prefix+'-public-ingress-plan.json')
        else:
            key=prefix+'-binding.json';new=(f'generation-{3:020}' if mutation=='mixed-sequence' else f'generation-{2:020}-attempt-{4:020}')+'-binding.json'
            records[new]=records.pop(key)
        with pytest.raises(ValueError):native.current_selection(wrong)


@pytest.mark.parametrize('mode',['typed','empty','nonzero','ready','wrong-installation'])
def test_signed_dispatch_requires_the_typed_native_owner_output_and_retains_uncertainty(startup_case,mode):
    c=startup_case;options=dict(c.options)
    value=copy.deepcopy(c.before)
    if mode=='ready':value['installation_ready']=True
    elif mode=='wrong-installation':value['installation_id']=str(uuid.uuid4())
    calls=[]
    def execute(argv,**kwargs):
        calls.append(argv)
        if 'install-candidate' in argv[-1]:
            if mode=='nonzero':raise ValueError('simulated nonzero native result')
            return b'' if mode=='empty' else r.encode(value)
        return b''
    options.update(clock=lambda:100020,verifier=c.verifier,run=execute)
    if mode=='typed':
        result=dispatch.dispatch(**options)
        assert result['schema']=='elevenid.installer-candidate-dispatch-result/v2'
        assert result['installation_ready'] is result['acceptance_report'] is False
        assert result['native_startup_observation_sha256']==r.digest(r.encode(value))
        assert (options['ledger'].parent/result['native_startup_observation_name']).read_bytes()==r.encode(value)
    else:
        with pytest.raises(ValueError):dispatch.dispatch(**options)
        assert Path(str(options['ledger'])+'.invoke.json').is_file()
        assert not Path(str(options['ledger'])+'.dispatch-result.json').exists()
    assert len(calls)==6
    with pytest.raises(FileExistsError):dispatch.dispatch(**options)
    assert len(calls)==6
