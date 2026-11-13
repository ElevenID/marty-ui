"""Protected component boundaries; synthetic public fixtures are not guest proof."""
import copy
import json
import os
from pathlib import Path
import shlex
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_acceptance_acquisition as acquisition
import installer_acceptance_runner as runner
import installer_acceptance_v2 as v2
import installer_candidate_dispatch as dispatch
import installer_release as r
from test_installer_candidate_dispatch import staged

SOURCE = Path(__file__).resolve().parents[1] / 'rust/crates/deployment-catalog/tests/fixtures/installer-public-acquisition.json'


def put(path, raw, mode=0o600):
    path.write_bytes(raw); path.chmod(mode)


def public_case():
    fixture = json.loads(SOURCE.read_text())
    authorization = fixture['authorization'].encode(); receipt = fixture['controller'].encode()
    inventory = fixture['inventory'].encode(); auth = r.decode(authorization); consumed = r.decode(receipt)
    context = r.candidate_context(auth); target = {k: consumed[k] for k in dispatch.TARGET_FIELDS}
    payloads = {k: v.encode() for k, v in fixture['payloads'].items()}
    pins = {}
    for name, raw in (('installer-candidate-authorization.json', authorization),
                      ('installer-controller-consumption.json', receipt), ('installer-inventory.json', inventory)):
        pins[name] = r.digest(raw)
        for suffix in dispatch.SUFFIXES[1:]:
            pins[name + suffix] = r.digest(payloads.get(name + suffix, b'synthetic public grant proof'))
    common = dict(context_sha256=r.candidate_context_sha256(context), authorization_sha256=r.digest(authorization),
                  controller_consumption_sha256=r.digest(receipt))
    intent = dict(schema='elevenid.installer-public-acquisition-intent/v1', **common, started_at=100004, installation_ready=False)
    receipts = [dict(asset=name, bytes=len(raw), sha256=r.digest(raw), hash_verified=name in r.ARTIFACTS)
                for name, raw in sorted(payloads.items())]
    completion = dict(schema='elevenid.installer-public-acquisition-result/v2', phase='published', **common,
        inventory_sha256=r.digest(inventory), intent_sha256=r.digest(r.encode(intent)), started_at=100004,
        completed_at=100005, receipts=receipts, installation_ready=False)
    bootstrap = dict(schema='elevenid.installer-public-bootstrap-intent/v1', context_sha256=common['context_sha256'],
        authorization_sha256=common['authorization_sha256'], receipt_sha256=r.digest(receipt), started_at=100002, installation_ready=False)
    verified = dict(schema='elevenid.installer-public-bootstrap-verified/v1', context_sha256=common['context_sha256'],
        authorization_sha256=common['authorization_sha256'], receipt_sha256=r.digest(receipt),
        inventory_sha256=r.digest(inventory), operator_sha256=context['operator_sha256'], verified_at=100003, installation_ready=False)
    records = {name: dict(sha256=r.digest(r.encode(value)), record=r.encode(value).decode())
               for name, value in dict(intent=intent, completion=completion, bootstrap_intent=bootstrap, bootstrap_verified=verified).items()}
    request = dict(observation_id='44444444-4444-4444-8444-444444444444', challenge='4'*64)
    value = dict(schema=acquisition.SCHEMA, phase='published', request=request,
        **{k: context[k] for k in ('source_sha','release_tag','harness_source_sha','run_id','run_attempt','operator_sha256')},
        **{k: auth[k] for k in ('build_run_id','build_run_attempt')}, **target, **common,
        inventory_sha256=r.digest(inventory), authenticated_evidence_sha256=pins, started_at=100010, completed_at=100011,
        owner_records=records, receipts=receipts, installation_ready=False, acceptance=False, functional_recovery_qualified=False)
    args = dict(context=context, target=target, authorization=authorization, receipt=receipt, inventory=inventory, pins=pins,
        verified_assets={name: dict(sha256=r.digest(raw), bytes=len(raw)) for name, raw in payloads.items()},
        expected_request=request, observed_at=100012)
    return SimpleNamespace(value=value, args=args, payloads=payloads, authorization=authorization, receipt=receipt,
                          inventory=inventory, context=context, target=target, pins=pins)


def test_component_reader_binds_all_fifteen_guest_receipts_without_admission():
    c=public_case(); value=acquisition.validate_native(r.encode(c.value), **c.args)
    assert len(value['receipts'])==15
    assert all(value[k] is False for k in ('acceptance','installation_ready','functional_recovery_qualified'))
    assert 'anonymous-download' in v2.missing_writers(v2.FUNCTIONAL_PROFILE)
    assert v2.IMPLEMENTED_INSTALLED_WRITERS==frozenset(v2.STARTUP_CASES)
    assert len(v2.STARTUP_CASES)==5


@pytest.mark.parametrize('mutation', ['phase','source','tag','operator','build-run','build-attempt','harness','run','attempt',
    'guest','disk','engine','installation','context','grant','consumption','inventory','pins','challenge','request-id',
    'ready','acceptance','qualified','extra','future','expired','controller-only'])
def test_wrong_scope_replay_or_claim_cannot_enter_component_reader(mutation):
    c=public_case(); value=copy.deepcopy(c.value); args=copy.deepcopy(c.args)
    field={'phase':'phase','source':'source_sha','tag':'release_tag','operator':'operator_sha256','build-run':'build_run_id',
        'build-attempt':'build_run_attempt','harness':'harness_source_sha','run':'run_id','attempt':'run_attempt',
        'guest':'guest_id','disk':'disk_id','engine':'engine_id','installation':'installation_id','context':'context_sha256',
        'grant':'authorization_sha256','consumption':'controller_consumption_sha256','inventory':'inventory_sha256'}.get(mutation)
    if field:value[field]=value[field]+1 if type(value[field]) is int else 'wrong'
    elif mutation=='pins':value['authenticated_evidence_sha256']['installer-inventory.json']='f'*64
    elif mutation=='challenge':value['request']['challenge']='f'*64
    elif mutation=='request-id':value['request']['observation_id']='55555555-5555-4555-8555-555555555555'
    elif mutation in ('ready','acceptance','qualified'):value[{'ready':'installation_ready','acceptance':'acceptance','qualified':'functional_recovery_qualified'}[mutation]]=True
    elif mutation=='extra':value['passed']=True
    elif mutation=='future':value['completed_at']=100013
    elif mutation=='expired':args['observed_at']=103600
    elif mutation=='controller-only':value['schema']='elevenid.installer-controller-published-assets/v1'
    with pytest.raises((ValueError,KeyError,TypeError)):acquisition.validate_native(r.encode(value),**args)


@pytest.mark.parametrize('mutation',['missing-owner','owner-digest','legacy-completion','completion-phase','old-intent',
    'bootstrap-operator','bootstrap-order','completion-clock','duplicate-receipt','missing-receipt','extra-receipt',
    'payload-digest','sidecar-digest','receipt-size','receipt-flag','bool-size','receipt-extra','outer-receipts'])
def test_changed_native_owner_closure_refuses_even_if_caller_rehashes_json(mutation):
    c=public_case();value=copy.deepcopy(c.value)
    if mutation=='missing-owner':value['owner_records'].pop('bootstrap_intent')
    elif mutation=='owner-digest':value['owner_records']['completion']['sha256']='f'*64
    else:
        name='bootstrap_verified' if mutation.startswith('bootstrap-') else 'completion'
        record=r.decode(value['owner_records'][name]['record'].encode())
        if mutation=='legacy-completion':record['schema']='elevenid.installer-public-acquisition-result/v1'
        elif mutation=='completion-phase':record['phase']='staged'
        elif mutation=='old-intent':record['intent_sha256']='f'*64
        elif mutation=='bootstrap-operator':record['operator_sha256']='f'*64
        elif mutation=='bootstrap-order':record['verified_at']=100006
        elif mutation=='completion-clock':record['completed_at']=100011
        elif mutation=='duplicate-receipt':record['receipts'][1]=copy.deepcopy(record['receipts'][0])
        elif mutation=='missing-receipt':record['receipts'].pop()
        elif mutation=='extra-receipt':record['receipts'].append(copy.deepcopy(record['receipts'][0]))
        elif mutation in ('payload-digest','sidecar-digest'):
            item=next(v for v in record['receipts'] if v['asset']==('install.sh' if mutation=='payload-digest' else 'install.sh.sigstore.json'))
            item['sha256']='f'*64
        elif mutation=='receipt-size':record['receipts'][0]['bytes']+=1
        elif mutation=='receipt-flag':record['receipts'][0]['hash_verified']=not record['receipts'][0]['hash_verified']
        elif mutation=='bool-size':record['receipts'][0]['bytes']=True
        elif mutation=='receipt-extra':record['receipts'][0]['passed']=True
        elif mutation=='outer-receipts':value['receipts']=[]
        encoded=r.encode(record);value['owner_records'][name]=dict(sha256=r.digest(encoded),record=encoded.decode())
        if name=='completion' and mutation!='outer-receipts':value['receipts']=record['receipts']
    with pytest.raises((ValueError,KeyError,TypeError)):acquisition.validate_native(r.encode(value),**c.args)


@pytest.mark.parametrize('failure,through_runner', [(failure, False) for failure in
    [None,'staged','wrong-challenge','old-run','expired','same-byte-inode','parent-replaced','source-changed','existing']]
    + [(None, True)])
def test_collector_holds_inputs_and_runs_only_the_challenged_readonly_guest_owner(tmp_path,monkeypatch,failure,through_runner):
    c=public_case();tmp_path.chmod(0o700)
    for name in ('assets','grants','output','keys'):(tmp_path/name).mkdir(mode=0o700)
    assets=tmp_path/'assets';output=tmp_path/'output';files={}
    for name,raw in c.payloads.items():
        path=assets/name;put(path,raw);files[path]=(r.digest(raw),len(raw))
    for name,raw in (('candidate-authorization.json',c.authorization),('controller-consumption.json',c.receipt)):
        for suffix in dispatch.SUFFIXES:
            value=raw if not suffix else b'synthetic public grant proof';path=tmp_path/'grants'/(name+suffix)
            put(path,value);files[path]=(r.digest(value),len(value))
    key=tmp_path/'keys/key';known=tmp_path/'keys/known_hosts';put(key,b'synthetic key');put(known,b'synthetic host pin')
    if failure=='existing':put(output/acquisition.NAME,b'retained original component')
    calls=[];checks=[]
    class Sources:
        def __init__(self,sha):assert sha==c.context['harness_source_sha']
        def check(self):
            checks.append(True)
            if failure=='source-changed' and calls:raise ValueError('synthetic source changed')
        def __enter__(self):return self
        def __exit__(self,*_):pass
    monkeypatch.setattr(acquisition.startup,'HarnessSources',Sources)
    active=dict(repository=dict(full_name=r.REPOSITORY),path=r.acceptance.WORKFLOW,event='workflow_dispatch',
        head_branch='main',head_sha=c.context['harness_source_sha'],id=c.context['run_id'],run_attempt=c.context['run_attempt'],
        status='in_progress',conclusion=None)
    class Client:
        def request(self,method,path):
            assert method=='GET' and path.endswith('/actions/runs/99')
            value=copy.deepcopy(active)
            if failure=='old-run' and calls:value['run_attempt']-=1
            return value
    def execute(argv,**options):
        if through_runner and 'installer-host-probe' in argv[-1]:
            from test_installer_host_admission import observed_rootless_host_with_neighbors
            host_value=observed_rootless_host_with_neighbors();host_value['engine_id']=c.target['engine_id']
            return r.encode(host_value)
        if through_runner and ' status --install-dir ' in argv[-1]:
            raise ValueError('synthetic guest status is unavailable; acquisition grants no readiness')
        calls.append((argv,options));args=shlex.split(argv[-1])
        assert '--observe-acquisition' in args
        assert args[args.index('-c')+1]=='fixed public source'
        assert '/usr/bin/python3' in args and '-I' in args and '--no-new-privs' in args
        assert 'chmod' not in argv[-1] and 'sha256sum' not in argv[-1]
        assert 'install-candidate' not in args and 'fetch-published-candidate' not in args
        assert args[args.index('--install-dir')+1]=='/home/installer/marty-install-'+c.target['installation_id']
        value=copy.deepcopy(c.value);value['request']=dict(observation_id=args[args.index('--observation-id')+1],challenge=args[args.index('--challenge')+1])
        if failure=='wrong-challenge':value['request']['challenge']='f'*64
        if failure=='same-byte-inode':
            path=assets/'install.sh';raw=path.read_bytes();path.unlink();put(path,raw)
        if failure=='parent-replaced':
            output.rename(tmp_path/'old-output');output.mkdir(mode=0o700)
        return r.encode(value)
    context=copy.deepcopy(c.context)
    if failure=='staged':context['phase']='staged'
    def clock():return 103600 if failure=='expired' and calls else 100012
    args=dict(output=output,assets=assets,files=files,context=context,target=c.target,authorization=c.authorization,
        receipt=c.receipt,inventory=c.inventory,pins=c.pins,ssh=Path('/usr/bin/ssh'),key=key,known_hosts=known,
        port=2222,host='127.0.0.1',user='installer',home='/home/installer',bootstrap_source='fixed public source',
        unchanged=lambda:None,guarded_execute=execute,client=Client(),clock=clock)
    if failure:
        with pytest.raises((ValueError,OSError)):acquisition.collect(**args)
        if failure=='existing':assert (output/acquisition.NAME).read_bytes()==b'retained original component'
        else:assert not (output/acquisition.NAME).exists()
    else:
        if through_runner:
            for name,raw in [('context',r.encode(c.context)),('target',r.encode(c.target)),('ledger',c.receipt)]:
                put(tmp_path/'keys'/name,raw)
            monkeypatch.setattr(dispatch,'executable',lambda _:None)
            monkeypatch.setattr(dispatch,'verify',lambda **_: (c.authorization,c.receipt,c.inventory,files))
            monkeypatch.setattr(dispatch,'verified_bootstrap',lambda _: 'fixed public source')
            monkeypatch.setattr(dispatch,'verified_harness_script',lambda _,name:
                (Path(__file__).resolve().parents[1]/'scripts'/name).read_text())
            dispatches=[]
            def original_dispatch(**options):
                dispatches.append(options)
                return dict(command_returned_zero=True,installation_ready=False,acceptance_report=False)
            checkpoint=runner.run(output=output,assets=assets,grants=tmp_path/'grants',
                context_file=tmp_path/'keys/context',target_file=tmp_path/'keys/target',ledger=tmp_path/'keys/ledger',
                gh=tmp_path/'gh',cosign=tmp_path/'cosign',ssh=args['ssh'],scp=Path('/usr/bin/scp'),key=key,
                known_hosts=known,host=args['host'],port=args['port'],user=args['user'],home=args['home'],
                clock=clock,execute=execute,candidate_dispatch=original_dispatch,resource_profile=runner.ROOTLESS_STARTUP_PROFILE,
                startup_client=Client(),observe_published_acquisition=True)
            assert len(dispatches)==1 and checkpoint['dispatch']=='returned_zero_unqualified'
            assert checkpoint['host_preflight']=='passed' and checkpoint['trust_inspection']=='unavailable'
            assert all(checkpoint[k] is False for k in ('acceptance','installation_ready','functional_recovery_qualified'))
            assert all(value=='blocked' for case,value in checkpoint['cases'].items() if case!='artifact-verification')
            assert not (output/'installer-acceptance.json').exists()
            result=r.decode((output/acquisition.NAME).read_bytes())
        else:
            result=acquisition.collect(**args)
        assert r.decode((output/acquisition.NAME).read_bytes())==result
        assert os.stat(output/acquisition.NAME).st_mode & 0o777==0o600
        with pytest.raises(ValueError,match='already retained'):acquisition.collect(**args)
        assert len(calls)==1
        assert calls[0][1]['timeout']==150 and calls[0][1]['limit']==65536
        assert 'IdentityAgent=none' in calls[0][0] and 'StrictHostKeyChecking=yes' in calls[0][0]
    if failure in ('staged','existing'):assert calls==[]


def test_runner_rejects_staged_optin_before_verification_or_guest_action(staged,tmp_path):
    options,calls,proofs=staged;options=dict(options);options['execute']=options.pop('run')
    options['output']=tmp_path/'output';options['output'].mkdir(mode=0o700)
    with pytest.raises(ValueError,match='rootless published candidate'):
        runner.run(**options,observe_published_acquisition=True)
    assert calls==[] and proofs==[] and list(options['output'].iterdir())==[]


def test_collector_is_pinned_in_existing_source_closure():
    assert 'scripts/installer_acceptance_acquisition.py' in acquisition.startup.HARNESS_FILES
