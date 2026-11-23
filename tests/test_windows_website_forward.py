"""Windows forward successor preparation, with no change to the owner journal."""
from contextlib import ExitStack
from email.message import Message
import json
from pathlib import Path
import ssl
import subprocess
from types import SimpleNamespace

import os

import pytest

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows private website forward evidence')

from tests.test_package_web_composition import candidate as candidate
from tests.test_windows_website_plan import planned, propose, rehash
from tests.test_windows_website_store import paths
import selfhost_windows_website_forward as forward


selection, stage, store, renewal = forward.selection, forward.stage, forward.store, forward.renewal
contract, edge, verify = forward.contract, forward.edge, forward.verify
HOST = 'www.example.test'
ACCOUNT = '11111111-1212-1313-1414-151515151515'
ORG = '21212121-2222-2323-2424-252525252525'
COOKIE = 'synthetic-test-session-0123456789'


def session_state():
    return {'cookies': [{'name':'sessionId','value':COOKIE,'domain':HOST,'path':'/',
                         'secure':True,'httpOnly':True,'expires':-1}], 'origins': []}


def wire(body, status=200):
    headers = Message()
    headers['Content-Type'] = 'application/json'
    headers['Cache-Control'] = 'no-store, max-age=0'
    return verify.Response(status, headers, selection.packed(body), {'address':'8.8.8.8',
                           'version':'TLSv1.3','leaf_sha256':'c'*64})


@pytest.mark.parametrize('fault',[None,'wrong-host','insecure','expired','redirect','other-account','empty-organizations','other-organization'])
def test_authenticated_acceptance_scopes_cookie_and_preserves_no_secret_response(monkeypatch, fault):
    state = session_state()
    value = state['cookies'][0]
    if fault=='wrong-host': value['domain'] = '.example.test'
    if fault=='insecure': value['secure'] = False
    if fault=='expired': value['expires'] = 1
    calls = []
    monkeypatch.setattr(verify, '_public_addresses', lambda host: ('8.8.8.8',) if host == HOST else ())

    def get(host, path, addresses, port, context, deadline, *, session_cookie):
        assert host==HOST and port==443 and addresses==('8.8.8.8',) and session_cookie==('sessionId',COOKIE)
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        calls.append(path)
        if path == verify.SESSION:
            return wire({'authenticated':True, 'user': {'id': ACCOUNT if fault!='other-account' else ORG,
                       'email':'unretained@example.test'}}, 302 if fault=='redirect' else 200)
        expected = [] if fault=='empty-organizations' else [{'id': ORG if fault!='other-organization' else ACCOUNT}]
        return wire(expected)

    monkeypatch.setattr(verify, '_request', get)
    args = (HOST, {'services': {'auth': {}}}, state, selection.digest(ACCOUNT.encode()), selection.digest(ORG.encode()))
    if fault:
        with pytest.raises(ValueError):
            forward._authenticated(*args)
        if fault in {'wrong-host','insecure','expired'}:
            assert calls==[]
        return
    result = forward._authenticated(*args)
    assert result['authenticated_application_exercised'] and result['organization_matched']
    assert calls == [verify.SESSION, verify.ORGANIZATIONS]
    serialized = json.dumps(result)
    assert not any(item in serialized for item in (ACCOUNT, ORG, COOKIE, 'unretained'))


def test_transport_refuses_cookie_on_plain_http_and_non_application_paths():
    with pytest.raises(ValueError):
        verify._request(HOST, verify.SESSION, ('127.0.0.1',), 80, None, 0, session_cookie=('sessionId',COOKIE))
    with pytest.raises(ValueError):
        verify._request(HOST, '/', ('127.0.0.1',), 443, ssl.create_default_context(), 0, session_cookie=('sessionId',COOKIE))


def test_real_compose_compiles_one_source_identical_to_admitted_overlays_for_both_generations(paths, planned, monkeypatch):
    import selfhost_windows_website_current_backout as backout

    plan, records, _anchors = paths
    attempt = records.parent
    proposal = propose(planned)
    combined = proposal['models']['combined']
    for model in proposal['models'].values():
        model['secrets'] = {name:{'file':'${SELFHOST_SECRET_DIR}/'+name} for name in combined['secrets']}
    root = attempt.parent
    config = {'project': plan['owner']['project'], 'compose_file': str(root/'data-source.json')}
    Path(config['compose_file']).write_bytes(selection.packed(combined))
    for side in ('current','renewed'):
        path = root/(side+'.env')
        secret_root = root/side
        path.write_text('SELFHOST_SECRET_DIR='+secret_root.as_posix()+'\n',encoding='ascii')
        config[side+'_env'], config[side+'_secrets'] = str(path), str(secret_root)

    class Docker:
        prefix = ['docker']

        def json(self, args):
            return json.loads(subprocess.check_output([*self.prefix,*args], timeout=30))

        def compose(self, project, env, source):
            return [*self.prefix,'compose','--project-name',project,'--env-file',str(env),'-f',str(source)]

        def hashes(self, command):
            output = subprocess.check_output([*command,'--profile','*','config','--hash','*'], timeout=30)
            return dict(line.split() for line in output.decode().splitlines())

    values = {'old':{name:None for name in combined['secrets']}}
    with ExitStack() as held:
        binding, resolved = forward._candidate_layout(config, values, SimpleNamespace(docker=Docker()), proposal, attempt, held)
    assert Path(binding['compose_file']).parent == root and Path(binding['compose_file']).is_file()
    assert Path(config['compose_file']).read_bytes() == selection.packed(combined)
    for key in ('old','new'):
        normalized, hashes = resolved[key]
        assert contract.SLOT in normalized['services'] and contract.sha(hashes[contract.SLOT])
        assert [row['target'] for row in normalized['services']['edge']['volumes']].count(contract.ROUTE_TARGET) == 1

    # Reuse the published source and both retained overlays after ordinary renewal.
    # Docker Compose renders the two replacement environments from their actual files.
    config.update(docker_host=plan['owner']['docker_host'], engine_id=plan['owner']['engine_id'])
    for generation in ('current', 'renewed'):
        secret_root = root / ('later-' + generation)
        env = root / ('later-' + generation + '.env')
        env.write_text('SELFHOST_SECRET_DIR=' + secret_root.as_posix() + '\n', encoding='ascii')
        config[generation + '_env'], config[generation + '_secrets'] = str(env), str(secret_root)
    monkeypatch.setattr(renewal, 'Docker', lambda *_: Docker())
    monkeypatch.setattr(edge.website, 'inspect_composition', lambda *_, **_kw: (plan, proposal))
    selected = dict(config, **binding)
    with ExitStack() as held:
        _, layouts, _ = backout._layouts(selected, config, 'new', values, {}, plan, attempt, planned['data_before'],
            held, assets=root/'assets', gh=None, cosign=None, registry_config=None)
    for side in ('old', 'new'):
        assert layouts[side]['split'][1]['secrets'] != resolved[side][0]['secrets']
        assert layouts[side]['split'][1]['secrets'] == layouts[side]['combined'][1]['secrets']
        assert contract.SLOT not in layouts[side]['combined'][1]['services']
    route_overlay = attempt / 'route.compose.json'
    route_overlay.rename(attempt / 'saved-route.compose.json')
    with pytest.raises(ValueError, match='absent or not private'), ExitStack() as held:
        backout._layouts(selected, config, 'new', values, {}, plan, attempt, planned['data_before'],
            held, assets=root/'assets', gh=None, cosign=None, registry_config=None)
    assert not route_overlay.exists()


@pytest.mark.parametrize('fault',[None,'application','changed-proof','unverified',
                                   'changed-account','stale-qualification','interrupted-seal'])
def test_forward_candidate_preserves_rollback_and_retains_exact_original_ownership(paths, planned, monkeypatch, fault):
    plan, records, _anchors = paths
    attempt = records.parent
    proposal = propose(planned)
    layout = proposal['models']['split']
    credentials = {'old':{'synthetic-secret': 'original'},'new':{'synthetic-secret': 'renewed'}}
    project = plan['owner']['project']
    assets=attempt.parent/'assets'
    assets.mkdir()
    for name in plan['proof_sha256']:
        (assets/name).write_bytes(name.encode())
        plan['proof_sha256'][name] = selection.digest(name.encode())
    rehash(plan)
    config = {'project':project, 'compose_file':str(attempt.parent/'combined.json'), 'compose_sha256':'e'*64,
              'current_env':'old.env','renewed_env':'new.env','current_secrets':'old','renewed_secrets':'new',
              'native':{'current':'/control/current','renewed':'/control/renewed'},'step_receipts':[{'new_started':'old-intent'}]}
    record = {'data_sha256':plan['owner']['data_sha256'], 'selected':{'secrets_dir':plan['owner']['root']}}
    original = {'Id':'a'*64,'Image':'sha256:'+'b'*64,'Mounts':[],'RestartCount':0,'State':{'Status':'running','StartedAt':'fixture'},
        'Config':{'Labels':{'com.docker.compose.project':project,'com.docker.compose.service':'edge'}}}
    runtime = renewal.context_snapshot([original])
    configuration = {'container_id':original['Id'],'routes_sha256':plan['states']['split']['routes_sha256']}
    status = store.initialize(plan)
    with ExitStack() as held:
        for phase, fields in (('stage-candidate', {'image_metadata':{},'candidate_health':{}}),
                              ('route-website', {'mounted_template':plan['edge_template'],'edge_configuration':configuration}),
                              ('verify-website', {'public_routes':{},'application_handoffs':{}})):
            if fault=='unverified' and phase=='verify-website':
                break
            status = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=phase,
                event='started', evidence_sha256={key:'d'*64 for key in store.journal.START_EVIDENCE})
            status = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=phase,
                event='completed', evidence_sha256=stage._evidence(attempt/(('stage' if phase=='stage-candidate' else phase)+'-after.json'),
                    {'runtime_after':runtime, **fields},held))
    status={**status,'guard_sha256':'f'*64}
    ctx = SimpleNamespace(docker=object(), layouts={'split':([],layout,{'edge':'f'*64})},
                          proof_sha256=None, proof_count=0, check=lambda **_: [original])
    checks=[]

    def prepare(*_args, **options):
        assert options['prior_phase']=='verify-website' and options['candidate_ready']
        checks.append('qualified-split')
        return ctx, {**proposal,'http':{'signed-fixture':True}}, {'runtime_after':runtime}, lambda: checks.append('route-path')

    def authenticated(*_args):
        if fault=='application':
            raise ValueError('synthetic application refusal')
        return {'authenticated_application_exercised':True,'account_matched':True,'organization_matched':True}

    monkeypatch.setattr(edge,'_prepare',prepare)
    monkeypatch.setattr(edge,'_probe',lambda *_:configuration)
    monkeypatch.setattr(verify,'_installed_ingress',lambda *_:(HOST,29382))
    monkeypatch.setattr(verify,'_observe',lambda *_:({'public':'verified'},{'anonymous':'verified'}))
    monkeypatch.setattr(forward,'_authenticated',authenticated)
    monkeypatch.setattr(forward,'_candidate_layout',lambda *_: (
        {'compose_file':str(attempt.parent/'split.json'),'compose_sha256':'a'*64},
        {'old':(layout,{'edge':'f'*64}),'new':(layout,{'edge':'f'*64})}))
    monkeypatch.setattr(selection,'_inspect',lambda *_args,**_kw:{'model':layout,'owned':[original],'context':ctx})
    monkeypatch.setattr(selection,'_inputs',lambda *_:(credentials,{}))
    session=attempt.parent/'test-session-state.json'
    session.write_bytes(selection.packed(session_state()))
    if fault=='changed-proof':
        (assets/'web-composition.zip').write_bytes(b'wrong synthetic proof')
    preparation_fault = fault in {'application', 'changed-proof', 'unverified'}
    with ExitStack() as held:
        arguments=(config,'new',credentials,record,plan,status)
        options=dict(assets=assets,gh=None,cosign=None,registry_config=None,session_state_file=session,
                     expected_account_sha256='c'*64,expected_organization_sha256='d'*64,authority_file=None)
        if preparation_fault:
            with pytest.raises(ValueError):
                forward.prepare(*arguments,held=held,**options)
        else:
            result=forward.prepare(*arguments,held=held,**options)
    readback=store.inspect(plan,expected_anchor_sha256=status['anchor_sha256'])
    assert readback['completed_phases']==status['completed_phases'] and 'restore-combined' in readback['permitted_record_phases']
    if preparation_fault:
        assert not (attempt/'successor/candidate.json').exists()
        return
    assert result['result']=='forward-candidate-prepared' and result['authenticated_application_exercised']
    assert checks==['qualified-split','route-path']
    root=attempt/'successor'
    candidate_record=selection.decode((root/'candidate.json').read_bytes())
    assert contract.digest(candidate_record)==result['candidate_sha256']
    assert candidate_record['combined']['compose_sha256']==config['compose_sha256']
    assert candidate_record['owner']==plan['owner'] and candidate_record['publication_supported'] is False
    assert {name: selection.digest((root/'proofs'/name).read_bytes()) for name in plan['proof_sha256']}==plan['proof_sha256']
    assert all(item.read_bytes()==b'' for item in (root/'activation').iterdir())
    assert COOKIE.encode() not in b''.join(item.read_bytes() for item in attempt.glob('forward-qualification-*.json'))

    pins = {key: result[key] for key in ('candidate_sha256', 'qualification_sha256')}
    if fault == 'changed-account':
        options['expected_account_sha256'] = 'a'*64
    elif fault == 'stale-qualification':
        pins['qualification_sha256'] = 'a'*64
    if fault in ('changed-account', 'stale-qualification'):
        with ExitStack() as held, pytest.raises((ValueError, OSError)):
            forward.seal(*arguments, held=held, **options, **pins)
        assert store.inspect(plan, expected_anchor_sha256=status['anchor_sha256']) == readback
        assert not (attempt / 'seal-forward-before.json').exists()
        return

    if fault == 'interrupted-seal':
        append = store.append

        def interrupt(plan, **next_record):
            if next_record['phase'] == 'seal-forward' and next_record['event'] == 'completed':
                raise RuntimeError('Fixture interrupted the anchored seal')
            return append(plan, **next_record)

        with monkeypatch.context() as injected:
            injected.setattr(store, 'append', interrupt)
            with ExitStack() as held, pytest.raises(RuntimeError, match='anchored seal'):
                forward.seal(*arguments, held=held, **options, **pins)
        start = _anchors / store._tail_name(status['record_count'] + 1)
        pin = selection.digest(start.read_bytes())
        started = store.inspect(plan, expected_anchor_sha256=pin)
        assert started['pending_phase'] == 'seal-forward'
        arguments = (*arguments[:-1], {**started, 'guard_sha256': status['guard_sha256']})
    with ExitStack() as held:
        sealed = forward.seal(*arguments, held=held, **options, **pins)
    assert sealed['classification'] == 'forward-evidence-complete'
    assert sealed['permitted_record_phases'] == ['restore-combined']
    assert sealed['completed_phases'] == list(store.journal.FORWARD)

    link = {**pins, 'terminal_sha256': sealed['anchor_sha256']}
    with ExitStack() as held:
        forward.check_publication(*arguments[:5], link, guard_sha256=status['guard_sha256'], held=held, **options)
    assert (root / 'candidate.json').read_bytes() == selection.packed(candidate_record)
