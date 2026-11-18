"""Closed adapters for the real signed native startup observer.

These readers admit public owner outputs. Only the signed controller runner
invokes the owners; caller-supplied booleans are never installed case evidence.
"""
from __future__ import annotations

import json
import re
import uuid

import installer_release as r

NATIVE_SCHEMA = 'elevenid.installer-signed-startup-observation/v1'
ARTIFACT_SCHEMA = 'elevenid.installer-startup-artifact-verification/v1'
INITIAL_EVIDENCE = {'application-generation.json', 'application-generation-pending.json',
                    'application-generation-selection.json', 'compose-session.json'}
CANARY_EVIDENCE = {'rootless-canary-' + name + '.json' for name in (
    'pull-intent', 'intent', 'created', 'transition-container', 'restore-container',
    'start-intent', 'foreign-observed', 'restore-intent', 'result', 'remove-intent',
    'transition-removed', 'restore-removed', 'complete')}
VALIDATION_CHECKS = ('Containers and migrations', 'Bound local TLS', 'Gateway',
                     'Required public services', 'Credential issuer metadata',
                     'Authorization metadata', 'Application entry document and main assets',
                     'Configured IP entry and API isolation')


def integer(value, *, minimum=0, maximum=2**53-1):
    r.require(type(value) is int and minimum <= value <= maximum, 'startup integer bound differs')
    return value


def uuid4(value):
    r.require(type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).version == 4,
              'startup observation UUID differs')
    return value


def request(value):
    r.exact(value, {'observation_id', 'challenge'}, 'startup request')
    uuid4(value['observation_id']); r.sha(value['challenge'], 64)
    return value


def hashes(value, names=None):
    r.require(type(value) is dict and (names is None or set(value) == names), 'startup evidence closure differs')
    for digest in value.values(): r.sha(digest, 64)
    return value


def current_selection(value):
    r.exact(value, {'kind', 'sequence', 'attempt', 'current_binding_sha256', 'session_sha256',
                    'configuration_sha256', 'selected_evidence_sha256'}, 'startup current selection')
    r.require(value['kind'] == 'current', 'startup needs a current selection')
    integer(value['sequence']); integer(value['attempt'])
    for key in ('current_binding_sha256', 'session_sha256', 'configuration_sha256'): r.sha(value[key], 64)
    evidence = value['selected_evidence_sha256']
    if value['sequence'] == 0:
        r.require(value['attempt'] == 0, 'initial selection cannot name an attempt')
        hashes(evidence, INITIAL_EVIDENCE)
        r.require(evidence['application-generation.json'] == evidence['application-generation-pending.json']
                  == value['current_binding_sha256'], 'initial binding bytes differ')
    else:
        from installer_acceptance_runner import selected_generation_evidence
        selected_generation_evidence(evidence)
        prefix = f"generation-{value['sequence']:020}"
        if value['attempt']: prefix += f"-attempt-{value['attempt']:020}"
        expected = {prefix + '-' + kind + '.json' for kind in (
            'intent', 'public-ingress-plan', 'helper', 'candidate', 'binding',
            'activation-intent', 'activation', 'session', 'selection')}
        hashes(evidence, expected | {'application-generation-current.json'})
        r.require(evidence[prefix + '-binding.json'] == value['current_binding_sha256'],
                  'selected successor binding differs')
    return value


def consumption_id(context, target, authorization):
    claim = dict(nonce=context['nonce'], authorization_sha256=r.digest(authorization),
                 context_sha256=r.candidate_context_sha256(context),
                 installation_id=target['installation_id'], engine_id=target['engine_id'])
    raw = json.dumps(dict(schema='elevenid.installer-candidate-consumption/v1',
                         scope='guest-local', claim=claim), separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return r.digest(raw)


def authority(*, context, target, authorization, receipt, inventory, pins, now):
    auth = r.decode(authorization)
    r.require(auth.get('schema') == r.CANDIDATE_SCHEMA_V2, 'startup needs authenticated v2 hosting')
    consumed = r.decode(receipt)
    r.bind_controller_consumption(receipt, authorization, inventory, expected=context,
                                 expected_engine=target['engine_id'], now=consumed['consumed_at'])
    r.require(all(consumed[key] == target[key] for key in ('guest_id', 'disk_id', 'engine_id', 'installation_id')),
              'startup target differs from authenticated consumption')
    integer(now, minimum=consumed['consumed_at'], maximum=consumed['consumed_at']+7200-1)
    r.validate_candidate_evidence(pins)
    for name, raw in [('installer-candidate-authorization.json', authorization),
                      ('installer-controller-consumption.json', receipt), ('installer-inventory.json', inventory)]:
        r.require(pins[name] == r.digest(raw), 'startup authenticated source bytes changed')
    hosting = auth['hosting']
    r.candidate_hosting.validate(hosting)
    r.require(hosting['certificate_source'] == 'acme' and hosting['acme_environment'] == 'production'
              and hosting['public_entry_origin'] is not None and hosting['staging_trust'] is None,
              'startup browser observation requires exact public production trust and IP entry')
    return auth, consumed


def artifact_record(*, files, assets, grants, context, target, authorization, receipt, inventory,
                    started_at, completed_at):
    """Called immediately after dispatch.verify returned its actually verified closure."""
    import installer_candidate_dispatch as dispatch
    subjects = {}
    for name in dispatch.SUBJECTS:
        values = [files.get(assets/(name+suffix)) for suffix in dispatch.SUFFIXES]
        r.require(all(type(item) is tuple and len(item) == 2 for item in values),
                  'actual verifier subject closure missing')
        subjects[name] = dict(sha256=values[0][0], size_bytes=values[0][1],
            signature_sha256=values[1][0], provenance_sha256=values[2][0])
    from installer_acceptance_runner import authenticated_source_digests
    pins = authenticated_source_digests(files, assets, grants)
    value = dict(schema=ARTIFACT_SCHEMA, installation_id=target['installation_id'],
        engine_id=target['engine_id'], operator_sha256=context['operator_sha256'],
        context_sha256=r.candidate_context_sha256(context),
        authorization_sha256=r.digest(authorization), controller_consumption_sha256=r.digest(receipt),
        authenticated_evidence_sha256=pins, subjects=subjects,
        verifier_pins={name: dict(sha256=item[0], size_bytes=item[1]) for name,item in dispatch.TOOLS.items()},
        started_at=started_at, completed_at=completed_at)
    validate_artifacts(value, context=context, target=target, inventory=inventory, pins=pins,
                       authorization=authorization, receipt=receipt, now=completed_at)
    return value


def validate_artifacts(value, *, context, target, inventory, pins, authorization, receipt, now):
    import installer_candidate_dispatch as dispatch
    r.exact(value, {'schema', 'installation_id', 'engine_id', 'operator_sha256', 'context_sha256',
                    'authorization_sha256', 'controller_consumption_sha256', 'authenticated_evidence_sha256',
                    'subjects', 'verifier_pins', 'started_at', 'completed_at'}, 'actual artifact verification')
    r.require(value['schema'] == ARTIFACT_SCHEMA and value['installation_id'] == target['installation_id']
        and value['engine_id'] == target['engine_id'] and value['operator_sha256'] == context['operator_sha256']
        and value['context_sha256'] == r.candidate_context_sha256(context)
        and value['authorization_sha256'] == r.digest(authorization)
        and value['controller_consumption_sha256'] == r.digest(receipt)
        and value['authenticated_evidence_sha256'] == pins, 'artifact owner scope differs')
    integer(value['started_at'], minimum=r.decode(receipt)['consumed_at'])
    integer(value['completed_at'], minimum=value['started_at'], maximum=now)
    r.require(value['verifier_pins'] == {name:dict(sha256=item[0], size_bytes=item[1])
        for name,item in dispatch.TOOLS.items()}, 'verifier trust anchors differ')
    inv = r.decode(inventory); r.validate_inventory(inv)
    expected = {entry['name']: entry for entry in inv['artifacts']}
    expected['installer-inventory.json'] = dict(sha256=r.digest(inventory), size=len(inventory))
    r.exact(value['subjects'], set(expected), 'verified subject closure')
    for name, item in value['subjects'].items():
        r.exact(item, {'sha256','size_bytes','signature_sha256','provenance_sha256'}, 'verified subject')
        for key in ('sha256','signature_sha256','provenance_sha256'): r.sha(item[key], 64)
        r.require(item['sha256'] == expected[name]['sha256'] and type(item['size_bytes']) is int
                  and item['size_bytes'] == expected[name]['size'], 'verified payload differs')
    for suffix, key in [('', 'sha256'), ('.sigstore.json', 'signature_sha256'), ('.provenance.jsonl', 'provenance_sha256')]:
        r.require(value['subjects']['installer-inventory.json'][key] == pins['installer-inventory.json'+suffix],
                  'verified inventory proof differs from installed authority')
    r.require(value['subjects']['marty-deploy-linux-amd64']['sha256'] == context['operator_sha256'],
              'verified operator differs')
    return value


def _resources(value, services, inventory):
    r.exact(value, {'containers','networks','volumes'}, 'native resources')
    containers = value['containers']
    r.require(type(containers) is dict and 1 <= len(containers) <= 96, 'native container census differs')
    r.exact(services, {'services_observed','all_expected_states_observed','services',
                       'not_atomic_snapshot','installation_ready'}, 'native live services')
    r.require(services['services_observed'] is True and services['all_expected_states_observed'] is True
        and services['not_atomic_snapshot'] is True and services['installation_ready'] is False,
        'native services are not currently healthy')
    r.exact(services['services'], set(containers), 'native live service closure')
    ids = set()
    images = set(r.decode(inventory)['images'].values())
    for role, item in containers.items():
        r.require(re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', role) is not None, 'native service role differs')
        r.exact(item, {'id','service','image','config_hash','setup','setup_execution','health_required',
                      'cap_add','cap_drop','read_only','memory_limit'}, 'native identity')
        r.sha(item['id'], 64); r.sha(item['config_hash'], 64)
        r.require(item['id'] not in ids and item['service'] == role and item['image'] in images,
                  'native image or identity differs'); ids.add(item['id'])
        for key in ('setup','health_required','read_only'): r.require(type(item[key]) is bool, 'native boolean differs')
        integer(item['memory_limit'])
        for key in ('cap_add','cap_drop'):
            r.require(type(item[key]) is list and item[key] == sorted(set(item[key]))
                      and all(type(v) is str and re.fullmatch(r'[A-Z_]{1,64}',v) for v in item[key]),
                      'native capabilities differ')
        observed = services['services'][role]
        r.exact(observed, {'container_id','status','health','exit_code','expected','expected_state_observed',
                          'configuration_verified','observation_source','oom_kill_history_observed','restart_history_observed'},
                'live service observation')
        r.require(observed['container_id'] == item['id'] and observed['expected_state_observed'] is True
            and observed['configuration_verified'] is True and observed['observation_source'] == 'docker_compose_ps'
            and observed['oom_kill_history_observed'] is False and observed['restart_history_observed'] is False,
            'native service observation differs')
        integer(observed['exit_code'], maximum=255)
        expected = 'exited_zero' if item['setup'] else ('healthy' if item['health_required'] else 'running_only')
        r.require(observed['expected'] == expected and observed['status'] == ('exited' if item['setup'] else 'running')
            and (not item['setup'] or observed['exit_code'] == 0)
            and (not item['health_required'] or item['setup'] or observed['health'] == 'healthy'),
            'native service state does not satisfy the real model')
        if item['setup']:
            execution = r.exact(item['setup_execution'], {'started_at','finished_at','completed_without_restart'}, 'native setup execution')
            r.require(execution['completed_without_restart'] is True
                and all(type(execution[k]) is str and 0 < len(execution[k]) <= 64 for k in ('started_at','finished_at')),
                'setup execution incomplete')
        else: r.require(item['setup_execution'] is None, 'runtime cannot claim a setup execution')
    r.require(type(value['networks']) is dict and 1 <= len(value['networks']) <= 8, 'native network census differs')
    for name, identifier in value['networks'].items():
        r.require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,255}',name), 'native network name differs')
        r.sha(identifier,64)
    r.require(type(value['volumes']) is list and value['volumes'] == sorted(set(value['volumes']))
        and len(value['volumes']) <= 32 and all(type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,255}',name)
                                              for name in value['volumes']), 'native volume census differs')


def _page(value, hosting):
    r.exact(value, {'origin','assets','app_name','alias_api_isolation_observed'}, 'native page observation')
    r.require(value['origin'] == hosting['public_entry_origin'] and value['alias_api_isolation_observed'] is True
        and type(value['app_name']) is str and 0 < len(value['app_name']) <= 256
        and not any(ord(c) < 32 for c in value['app_name']), 'native alias page differs')
    r.require(type(value['assets']) is list and 5 <= len(value['assets']) <= 52, 'native page asset count differs')
    paths = []
    for item in value['assets']:
        r.exact(item, {'path','media_type','size_bytes','sha256'}, 'native asset')
        r.require(item['path'] in ('/','/runtime-config.js','/startup.js','/config.json')
            or re.fullmatch(r'/assets/[A-Za-z0-9_-]+\.(?:js|css)', item['path']) is not None, 'native asset path differs')
        expected = ('text/html' if item['path'] == '/' else 'application/json' if item['path'] == '/config.json'
                    else 'text/css' if item['path'].endswith('.css') else 'application/javascript')
        r.require(item['media_type'] == expected, 'native asset media type differs')
        integer(item['size_bytes'], minimum=1, maximum=4*1024**2); r.sha(item['sha256'],64)
        paths.append(item['path'])
    r.require(paths == sorted(set(paths)) and {'/','/runtime-config.js','/startup.js','/config.json'} <= set(paths)
        and any(path.startswith('/assets/') and path.endswith('.js') for path in paths)
        and sum(item['size_bytes'] for item in value['assets']) <= 16*1024**2, 'native page closure differs')


def native(raw, *, context, target, authorization, receipt, inventory, pins, observed_at,
           expected_request=None, host_runtime=None):
    """Validate exact native output; stdout from the fixed signed binary is the owner."""
    from installer_acceptance_runner import trust_observation
    value = r.decode(raw)
    r.exact(value, {'schema','status','request','installation_id','engine_id','operator_sha256','context_sha256',
        'authority','runtime','hosting','selection','canary_evidence_sha256','bundle_validation',
        'bundle_validation_sha256','resources','services','validation','trust','page','started_at','completed_at',
        'not_atomic_snapshot','installation_ready','functional_recovery_qualified','load_characterized'}, 'signed native startup')
    auth, consumed = authority(context=context,target=target,authorization=authorization,receipt=receipt,
        inventory=inventory,pins=pins,now=observed_at)
    request(value['request'])
    r.require(expected_request is None or value['request'] == expected_request, 'native observation challenge differs')
    r.require(value['schema'] == NATIVE_SCHEMA and value['status'] == 'startup_observed'
        and value['installation_id'] == target['installation_id'] and value['engine_id'] == target['engine_id']
        and value['operator_sha256'] == context['operator_sha256']
        and value['context_sha256'] == r.candidate_context_sha256(context)
        and value['hosting'] == auth['hosting'] and value['not_atomic_snapshot'] is True
        and all(value[k] is False for k in ('installation_ready','functional_recovery_qualified','load_characterized')),
        'native startup scope or completion differs')
    integer(value['started_at'], minimum=consumed['consumed_at'])
    integer(value['completed_at'], minimum=value['started_at'], maximum=min(observed_at,value['started_at']+120))
    r.require(value['authority'] == dict(authorization_sha256=r.digest(authorization),
        controller_consumption_sha256=r.digest(receipt),inventory_sha256=r.digest(inventory),
        consumption_id=consumption_id(context,target,authorization),authenticated_evidence_sha256=pins,
        consumed_at=consumed['consumed_at']), 'native retained authority differs')
    runtime = r.exact(value['runtime'], {'profile','uid','docker_host','no_new_privileges'}, 'native rootless process')
    integer(runtime['uid'],minimum=1,maximum=4294967294)
    r.require(runtime['profile'] == 'rootless' and runtime['no_new_privileges'] is True
        and runtime['docker_host'] == f"unix:///run/user/{runtime['uid']}/docker.sock", 'native rootless process differs')
    if host_runtime is not None:
        r.require(all(runtime[k] == host_runtime[k] for k in ('profile','uid','docker_host')), 'native host UID/socket differs')
    current_selection(value['selection'])
    hashes(value['canary_evidence_sha256'],CANARY_EVIDENCE | set(pins))
    r.require(all(value['canary_evidence_sha256'][k] == v for k,v in pins.items()), 'native canary authority differs')
    bundle = r.exact(value['bundle_validation'], {'schema','file_count','directory_count','marker_sha256','image_lock_sha256','runtime_observed'},
                     'native bundle validation')
    integer(bundle['file_count'],minimum=1,maximum=16384); integer(bundle['directory_count'],maximum=16384)
    r.sha(bundle['marker_sha256'],64); r.sha(value['bundle_validation_sha256'],64)
    image_lock = next(item['sha256'] for item in r.decode(inventory)['artifacts'] if item['name']=='prepared-selfhost-images.json')
    r.require(bundle['schema']=='elevenid.installer-bundle-validation/v1' and bundle['runtime_observed'] is False
        and bundle['image_lock_sha256'] == image_lock, 'native bundle/image lock differs')
    _resources(value['resources'],value['services'],inventory)
    trust = value['trust']
    journal = dict(installation_id=target['installation_id'],hosting_selection_sha256=trust.get('evidence_sha256',{}).get('hosting-selection.json'))
    trust_observation(r.encode(trust),target,value['completed_at'],journal=journal,bound_hosting=auth['hosting'])
    if value['selection']['sequence']:
        r.require(trust.get('selected_generation') == value['selection']['selected_evidence_sha256'], 'native selected trust differs')
    else:
        r.require('selected_generation' not in trust and all(trust['evidence_sha256'][key] == value['selection']['selected_evidence_sha256'][key]
            for key in ('compose-session.json','application-generation-selection.json')), 'native initial trust differs')
    _page(value['page'],auth['hosting'])
    validation = r.exact(value['validation'], {'name','sha256','record'}, 'native validation receipt')
    r.require(type(validation['record']) is str and re.fullmatch(r'validation-[0-9a-f-]{36}\.json',validation['name']) is not None,
              'native validation filename differs')
    uuid4(validation['name'][11:-5]); r.sha(validation['sha256'],64)
    encoded = validation['record'].encode()
    r.require(r.digest(encoded)==validation['sha256'], 'native validation bytes changed')
    record = r.decode(encoded)
    r.exact(record, {'schema','validation_id','installation_id','release','engine_id','scope','observed_at','elapsed_ms',
        'status','checks','not_atomic_snapshot','installation_ready','host_trust_observed','qualification',
        'browser_rendering_observed','public_network_reachability_observed','container_security_posture','trust_evidence_sha256'},
        'deployment validation owner')
    r.require(record['schema']=='elevenid.deployment-validation/v1'
        and record['validation_id']==validation['name'][11:-5] and record['installation_id']==target['installation_id']
        and record['engine_id']==target['engine_id'] and record['scope']=='read_only_deployment' and record['status']=='passed'
        and record['release']==dict(source_sha=context['source_sha'],release_tag=context['release_tag'],inventory_sha256='sha256:'+r.digest(inventory))
        and record['not_atomic_snapshot'] is True and record['qualification']=='not_assessed'
        and all(record[k] is False for k in ('installation_ready','host_trust_observed','browser_rendering_observed','public_network_reachability_observed'))
        and record['trust_evidence_sha256']==trust['evidence_sha256'], 'deployment validation scope differs')
    integer(record['observed_at'],minimum=value['started_at'],maximum=value['completed_at']);integer(record['elapsed_ms'],maximum=90000)
    r.require(type(record['checks']) is list and len(record['checks'])==9, 'deployment validation checks differ')
    for item,name in zip(record['checks'],(*VALIDATION_CHECKS,'Credential journey'),strict=True):
        r.exact(item,{'name','required','status','code'},'deployment validation check')
        r.require(item['name']==name and item['required'] is (name!='Credential journey')
            and item['status']==('skip' if name=='Credential journey' else 'pass')
            and item['code']==('isolated_test_fixtures_required' if name=='Credential journey'
                else 'local_listener_observation' if name==VALIDATION_CHECKS[-1] else 'observed'), 'deployment validation check failed')
    return value


def stable_native(before, after):
    # Observation timestamps, request challenges and fresh validation UUIDs are
    # intentionally different. Every retained authority/resource/page binding is
    # compared, including setup execution identities and the public leaf.
    for key in ('installation_id','engine_id','operator_sha256','context_sha256','authority','runtime','hosting','selection',
                'canary_evidence_sha256','bundle_validation','bundle_validation_sha256','resources','services','trust','page'):
        r.require(before[key]==after[key], 'installed selection changed across browser observation')
    r.require(before['completed_at'] <= after['started_at'], 'native observation order differs')
