"""Qualify and seal the live Windows website successor under its existing owner."""
from copy import deepcopy
from pathlib import Path
import re
import ssl
import time

from selfhost_windows_inputs import _held_private_input
import selfhost_windows_product_deploy as product_deploy
import selfhost_windows_product_journal as product_journal
import selfhost_windows_selection as selection
import selfhost_windows_website_edge as edge
import selfhost_windows_website_plan as contract
import selfhost_windows_website_stage as stage
import selfhost_windows_website_store as store
import selfhost_windows_website_verify as verify


SCHEMA = 'marty.windows-website-forward-candidate/v1'
require = selection.require
renewal = selection.renewal
MODEL_LIMIT = 2 * 1024 * 1024


def _session_cookie(state, host, model):
    require(type(state) is dict and set(state) == {'cookies', 'origins'} and state['origins'] == [])
    require(type(state['cookies']) is list and 0 < len(state['cookies']) <= 16)
    name = model['services']['auth'].get('environment', {}).get('AUTH_SESSION_COOKIE_NAME', 'sessionId')
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,48}', name))
    matches = [cookie for cookie in state['cookies'] if cookie.get('name') == name]
    require(len(matches) == 1)
    cookie = matches[0]
    require(cookie.get('domain') == host and cookie.get('path') == '/' and cookie.get('secure') is True
            and cookie.get('httpOnly') is True and 'partitionKey' not in cookie
            and isinstance(cookie.get('value'), str) and re.fullmatch(r'[A-Za-z0-9._~%+=/-]{16,2048}', cookie['value']))
    expires = cookie.get('expires', -1)
    require(type(expires) in {int, float} and (expires == -1 or expires > time.time()))
    return name, cookie['value']


def _authenticated(host, model, state, expected_account_sha256, expected_organization_sha256):
    require(contract.sha(expected_account_sha256) and contract.sha(expected_organization_sha256))
    cookie = _session_cookie(state, host, model)
    addresses = verify._public_addresses(host)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    deadline = time.monotonic() + 35
    account = verify._request(host, verify.SESSION, addresses, 443, context, deadline, session_cookie=cookie)
    profile = verify._json(account)
    require(profile.get('authenticated') is True and 'no-store' in account.header('Cache-Control').lower())
    identity = profile['user']['id']
    require(isinstance(identity, str) and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', identity)
            and selection.digest(identity.encode()) == expected_account_sha256)
    organizations = verify._request(host, verify.ORGANIZATIONS, addresses, 443, context, deadline, session_cookie=cookie)
    require(organizations.status == 200 and organizations.header('Content-Type').split(';')[0].strip().lower() == 'application/json')
    rows = selection.decode(organizations.body)
    require(type(rows) is list and 0 < len(rows) <= 4096
            and all(type(row) is dict and isinstance(row.get('id'), str) for row in rows))
    require(sum(selection.digest(row['id'].encode()) == expected_organization_sha256 for row in rows) == 1
            and verify._public_addresses(host) == addresses)
    # Keep transport and successful assertions only. The session and user/org response bodies stay in memory.
    return {'account_matched': True, 'organization_matched': True, 'account_tls': account.peer,
            'organization_tls': organizations.peer, 'authenticated_application_exercised': True}


def _immutable_bytes(path, body, maximum, held):
    if renewal.namespace_entry_exists(path):
        require(held.enter_context(renewal.hold_private_input(path, max_bytes=maximum)) == body)
    else:
        product_deploy._copy_subject(path, body, maximum, held)


def _directory(path, held):
    if not renewal.namespace_entry_exists(path):
        path.mkdir()
    held.enter_context(renewal.hold_storage_namespace(path))
    held.enter_context(_held_private_input(path, directory=True, mutable_directory=True))


def _inventory(path, names, held):
    def check():
        require({item.name for item in path.iterdir()} == names)
    check()
    held.callback(check)


def _candidate_layout(config, values, context, proposal, attempt, held):
    """Render the persisted single source and both original overlay layouts."""
    docker = context.docker
    source = Path(config['compose_file'])
    config_source = deepcopy(proposal['models']['split'])
    volumes = config_source['services']['edge']['volumes']
    route, = [item for item in volumes if item['target'] == contract.ROUTE_TARGET]
    route['bind'] = {'create_host_path': False}
    cycle = attempt.name.removeprefix('windows-website-')
    candidate = source.with_name('website-' + cycle + '.compose.json')
    require(candidate != source)
    held.enter_context(renewal.hold_storage_namespace(source.parent))
    held.enter_context(_held_private_input(source.parent, directory=True, mutable_directory=True))
    raw = selection.packed(config_source)
    _immutable_bytes(candidate, raw, MODEL_LIMIT, held)
    resolved = {}
    for choice, generation in (('old', 'current'), ('new', 'renewed')):
        env = Path(config[generation + '_env'])
        original = docker.compose(config['project'], env, source)
        model = docker.json(original[len(docker.prefix):] + ['--profile', '*', 'config', '--format', 'json'])
        staged = stage._stage_model(docker, original, model, proposal, attempt, held)
        _overlay, expected, hashes = edge._split_model(docker, *staged, proposal, attempt, held)
        single = docker.compose(config['project'], env, candidate)
        normalized = docker.json(single[len(docker.prefix):] + ['--profile', '*', 'config', '--format', 'json'])
        require(normalized == expected and docker.hashes(single) == hashes)
        resolved[choice] = (normalized, hashes)
    renewal.checked_models(resolved['old'][0], resolved['new'][0], Path(config['current_secrets']),
                           Path(config['renewed_secrets']), sorted(values['old']))
    return {'compose_file': str(candidate), 'compose_sha256': selection.digest(raw)}, resolved


def _retain_successor(config, model_binding, attempt, assets, plan, status, record, resolved, held):
    root = attempt / 'successor'
    _directory(root, held)
    new_config = product_journal.successor_configuration(config, model_binding, root)
    config_path = root / 'config.private.json'
    stage._material(config_path, new_config, held)
    outputs = root / 'activation'
    _directory(outputs, held)
    names = [Path(new_config[name]) for name in ('intent', 'result', 'new_log', 'rollback_log')]
    names.extend(Path(path) for step in new_config['step_receipts'] for path in step.values())
    require(len(set(names)) == len(names) and all(path.parent == outputs for path in names))
    for path in names:
        if not renewal.namespace_entry_exists(path):
            selection._new_private(path, b'')
        require(held.enter_context(renewal.hold_private_input(path)) == b'')
    _inventory(outputs, {path.name for path in names}, held)

    proofs = root / 'proofs'
    _directory(proofs, held)
    for name, expected in plan['proof_sha256'].items():
        maximum = 256*1024*1024 if name == 'web-composition.zip' else 4*1024*1024
        body = held.enter_context(renewal.hold_private_input(Path(assets) / name, max_bytes=maximum))
        require(selection.digest(body) == expected)
        _immutable_bytes(proofs / name, body, maximum, held)
    _inventory(proofs, set(plan['proof_sha256']), held)

    candidate = {'schema': SCHEMA, 'plan_sha256': plan['plan_sha256'], 'guard_sha256': status['guard_sha256'],
                 'verified_tail_sha256': status['tail_sha256'], 'verified_anchor_sha256': status['anchor_sha256'],
                 'owner': plan['owner'], 'configuration': {'path': str(config_path), 'sha256': contract.digest(new_config)},
                 'combined': {'compose_file': config['compose_file'], 'compose_sha256': config['compose_sha256'],
                              'data_sha256': record['data_sha256']},
                 'split': {**model_binding, 'data_sha256': plan['states']['split']['data_sha256']},
                 'normalized_sha256': {side: contract.digest(model) for side, (model, _hashes) in resolved.items()},
                 'configuration_hashes': {side: hashes for side, (_model, hashes) in resolved.items()},
                 'activation_outputs': {str(path): selection.digest(b'') for path in names},
                 'proof_directory': str(proofs), 'proof_sha256': plan['proof_sha256'], 'publication_supported': False}
    stage._material(root / 'candidate.json', candidate, held)
    _inventory(root, {'config.private.json', 'activation', 'proofs', 'candidate.json'}, held)
    return root, new_config, candidate


def _qualify(config, choice, values, record, plan, status, *, assets, gh, cosign, registry_config,
             session_state_file, expected_account_sha256, expected_organization_sha256, authority_file, held,
             candidate_status):
    context, proposal, verified, check_routes = edge._prepare(config, choice, values, record, plan, status,
        prior_phase='verify-website', current='split', target='split', create_routes=False, candidate_ready=True,
        assets=assets, gh=gh, cosign=cosign, registry_config=registry_config, authority_file=authority_file,
        held=held, include_http=True)
    routed = store.read_evidence(plan, expected_anchor_sha256=status['anchor_sha256'], held=held,
        references={'route-website-after.json': (edge.FORWARD, 'completed')})['route-website-after.json']
    require(routed['runtime_after'] == verified['runtime_after'] and routed['mounted_template'] == plan['edge_template'])
    items = context.check(before_intent=True)
    installed = edge._edge(edge._owned(items, config['project']))
    _command, layout, _hashes = context.layouts['split']
    route = edge._probe(context.docker, installed, proposal, 'split')
    require(route == routed['edge_configuration'])
    host, _port = verify._installed_ingress(installed, layout)
    public, anonymous = verify._observe(installed, layout, proposal['http'], 'split')
    raw_state = held.enter_context(renewal.hold_private_input(Path(session_state_file).absolute()))
    authenticated = _authenticated(host, layout, selection.decode(raw_state), expected_account_sha256, expected_organization_sha256)

    attempt = Path(plan['attempt_directory'])
    binding, resolved = _candidate_layout(config, values, context, proposal, attempt, held)
    require(resolved[choice] == (layout, context.layouts['split'][2]))
    root, new_config, candidate = _retain_successor(config, binding, attempt, assets, plan, candidate_status, record, resolved, held)
    observed = selection._inspect(new_config, choice, values, held, expected_data=plan['states']['split']['data_sha256'])
    require(observed['model'] == resolved[choice][0]
            and renewal.context_snapshot(observed['owned']) == verified['runtime_after'])
    require(selection._inputs(new_config, held)[0] == values)
    final = observed['context'].check(before_intent=True)
    owned = edge._owned(final, config['project'])
    require(renewal.context_snapshot(owned) == verified['runtime_after']
            and edge._probe(context.docker, edge._edge(owned), proposal, 'split') == route)
    check_routes()
    qualification = {'schema': SCHEMA, 'candidate_sha256': contract.digest(candidate),
        'runtime_sha256': contract.digest(verified['runtime_after']), 'public_routes_sha256': contract.digest(public),
        'anonymous_handoff_sha256': contract.digest(anonymous), 'authenticated_application': authenticated,
        'authenticated_account_sha256': expected_account_sha256,
        'authenticated_organization_sha256': expected_organization_sha256,
        'native_sha256': plan['owner']['native_sha256'], 'selected_sha256': plan['owner']['selected_sha256'],
        'foreign_storage_sha256': observed['context'].proof_sha256, 'foreign_storage_changes': observed['context'].proof_count}
    return root, qualification, final, route, verified['runtime_after']


def prepare(config, choice, values, record, plan, status, *, held, **options):
    """Qualify a forward candidate at the verified split boundary."""
    require(status['classification'] == 'phase-boundary' and status['model_state'] == 'split'
            and status['completed_phases'] == list(store.journal.FORWARD[:-1])
            and set(status['permitted_record_phases']) == {'seal-forward', 'restore-combined'})
    root, qualification, _, _, _ = _qualify(config, choice, values, record, plan, status, held=held,
                                            candidate_status=status, **options)
    pin = contract.digest(qualification)
    stage._material(root.parent / ('forward-qualification-' + pin + '.json'), qualification, held)
    return {**status, 'result': 'forward-candidate-prepared', 'candidate_directory': str(root),
            'candidate_sha256': qualification['candidate_sha256'], 'qualification_sha256': pin,
            'authenticated_application_exercised': True}


def _pinned_qualification(attempt, candidate_sha256, qualification_sha256, held):
    require(contract.sha(candidate_sha256) and contract.sha(qualification_sha256))
    qualification_file = attempt / ('forward-qualification-' + qualification_sha256 + '.json')
    for path, pin in ((attempt / 'successor' / 'candidate.json', candidate_sha256),
                      (qualification_file, qualification_sha256)):
        raw = held.enter_context(renewal.hold_private_input(path))
        value = selection.decode(raw)
        require(raw == selection.packed(value) and selection.digest(raw) == pin and value['schema'] == SCHEMA)
    require(value['candidate_sha256'] == candidate_sha256
            and all(value['authenticated_application'][key] is True for key in (
                'account_matched', 'organization_matched', 'authenticated_application_exercised')))
    return value


def _recheck(config, choice, values, record, plan, status, *, candidate_sha256, qualification_sha256, held, **options):
    """Re-run all acceptance checks against the original independently pinned candidate."""
    attempt = Path(plan['attempt_directory'])
    pinned = _pinned_qualification(attempt, candidate_sha256, qualification_sha256, held)
    prefix = store.forward_verification_prefix(plan, expected_anchor_sha256=status['anchor_sha256'])
    _, fresh, inventory, routes, runtime = _qualify(config, choice, values, record, plan, status, held=held,
        candidate_status={**prefix, 'guard_sha256': status['guard_sha256']}, **options)
    verify_qualification(fresh, pinned)
    return runtime, routes, {
        'engine_id': plan['owner']['engine_id'], 'inventory_sha256': contract.digest(renewal.context_snapshot(inventory)),
        'changes_sha256': fresh['foreign_storage_sha256'], 'changes': fresh['foreign_storage_changes'],
    }, fresh


def verify_qualification(fresh, pinned):
    require(set(fresh) == set(pinned) and all(fresh[key] == pinned[key] for key in (
        'schema', 'candidate_sha256', 'runtime_sha256', 'native_sha256', 'selected_sha256',
        'authenticated_account_sha256', 'authenticated_organization_sha256', 'foreign_storage_sha256', 'foreign_storage_changes')))
    require(all(contract.sha(fresh[key]) for key in ('public_routes_sha256', 'anonymous_handoff_sha256'))
            and all(fresh['authenticated_application'][key] is True for key in (
                'account_matched', 'organization_matched', 'authenticated_application_exercised')))


def seal(config, choice, values, record, plan, status, *, candidate_sha256, qualification_sha256, held, **options):
    """Anchor live acceptance and allow prepublication backout from the sealed state."""
    require(status['completed_phases'] == list(store.journal.FORWARD[:-1])
            and status['model_state'] == 'split' and status['pending_phase'] in (None, 'seal-forward'))
    phase = 'seal-forward'
    runtime, routes, foreign, _qualification = _recheck(config, choice, values, record, plan, status, held=held,
        candidate_sha256=candidate_sha256, qualification_sha256=qualification_sha256, **options)
    native = {key: plan['owner'][key] for key in ('native_sha256', 'selected_sha256')}
    before = {'owner_lease': {'owner': plan['owner'], 'guard_sha256': status['guard_sha256']},
              'runtime_before': {'containers': runtime, 'edge_configuration': routes},
              'native_custody': native, 'foreign_storage': foreign}
    after = {'runtime_after': runtime, 'native_custody': native, 'foreign_storage': foreign,
             'successor_candidate': {'candidate_sha256': candidate_sha256, 'qualification_sha256': qualification_sha256}}
    attempt = Path(plan['attempt_directory'])
    start = stage._evidence(attempt / (phase + '-before.json'), before, held)
    end = stage._evidence(attempt / (phase + '-after.json'), after, held)
    anchor = status['anchor_sha256']
    if status['pending_phase'] is None:
        started = store.append(plan, expected_anchor_sha256=anchor, phase=phase, event='started', evidence_sha256=start)
        anchor = started['anchor_sha256']
    else:
        recorded = store.read_evidence(plan, expected_anchor_sha256=anchor, held=held,
            references={phase + '-before.json': (phase, 'started')})
        require(recorded[phase + '-before.json'] == before)
    sealed = store.append(plan, expected_anchor_sha256=anchor, phase=phase, event='completed', evidence_sha256=end)
    return {**sealed, 'result': 'website-forward-sealed', 'guard_sha256': status['guard_sha256'],
            **after['successor_candidate']}


def check_publication(config, choice, values, record, plan, link, *, guard_sha256, held, **options):
    """Refresh live acceptance through the exact terminal owner evidence."""
    status = store.inspect(plan, expected_anchor_sha256=link['terminal_sha256'])
    require(status['classification'] == 'forward-evidence-complete')
    status['guard_sha256'] = guard_sha256
    _, _, _, qualification = _recheck(config, choice, values, record, plan, status, held=held,
        candidate_sha256=link['candidate_sha256'], qualification_sha256=link['qualification_sha256'], **options)
    return qualification
