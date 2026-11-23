"""Managed public ingress, OIDC, and protected application observations."""
from contextlib import ExitStack
from email.message import Message
import json
from pathlib import Path
import socket
import ssl
import time
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from tests.test_installer_live_tls_probe import cert, serve
from tests.test_package_web_composition import candidate as candidate
from tests.test_windows_website_plan import planned
from tests.test_windows_website_store import paths, publish
import selfhost_windows_website_verify as verify


HOST = 'www.example.test'
ORIGIN = 'https://' + HOST
SOURCE = 'a'*40
COMMERCE = 'b'*40
REVISION = SOURCE + '-' + COMMERCE
PREFIX = '/_website/' + REVISION + '/'
SIGNED = {'website': {'revision': REVISION, 'source_sha': SOURCE, 'commerce_extension': {'source_sha': COMMERCE}},
          'application': {'release_version': '1.1.274', 'marty_ui_sha': 'c'*40},
          'routes': {'website': {'exact_paths': ['/', '/product', '/pricing', '/pricing/', verify.WEBSITE_MARKER],
                                 'path_prefixes': ['/_website/']}}}
EDGE = {'Config': {'Env': ['PUBLIC_DOMAIN=' + HOST]}, 'NetworkSettings': {
    'Ports': {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '29382'}]}}}
MODEL = {'services': {'edge': {'environment': {'PUBLIC_DOMAIN': HOST}, 'ports': [
    {'target': 80, 'host_ip': '127.0.0.1', 'published': '29382', 'protocol': 'tcp'}]}}}


def response(status=200, body=b'', *, content='', revision='', location='', peer=None):
    headers = Message()
    for name, value in (('Content-Type', content), ('X-Marty-Website-Revision', revision), ('Location', location)):
        if value:
            headers[name] = value
    if isinstance(body, dict):
        body = json.dumps(body).encode()
        headers['Content-Type'] = 'application/json'
    return verify.Response(status, headers, body, peer)


def html(script, *, revision=''):
    return response(body=f'<script type="module" src="{script}"></script>'.encode(), content='text/html', revision=revision)


@pytest.fixture
def transport(monkeypatch):
    def install(state, fault=None):
        calls = []
        dns_calls = []
        dns = {HOST: ('8.8.8.8', '2001:4860:4860::8888'), HOST[4:]: ('8.8.4.4',)}

        def resolve(host):
            dns_calls.append(host)
            if fault == 'dns-changed' and len(dns_calls) > 2:
                return ('1.1.1.1',)
            return dns[host]

        def fetch(host, path, addresses, port, context, deadline):
            calls.append((host, path, port))
            assert time.monotonic() < deadline
            if context:
                assert addresses == dns[host] and context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
                assert context.minimum_version == ssl.TLSVersion.TLSv1_2
                assert port == 443
            else:
                assert addresses == ('127.0.0.1',) and port == 29382
            if host != HOST:
                assert host == HOST[4:] and path == '/'
                entry = response(308, location=ORIGIN+'/' if fault != 'apex' else 'https://elsewhere.test/')
            elif path == verify.APPLICATION_MARKER:
                marker = SIGNED['application'] if fault != 'application-marker' or port != 443 else {'release_version': 'other'}
                entry = response(body=marker)
            elif path == '/console':
                entry = html('/assets/console-def.js' if fault != 'console' or port != 443 else PREFIX+'wrong.js')
            elif path == verify.READY:
                entry = response(body={'status': 'ready', 'service': 'api-gateway', 'services': {'auth': {'status': 'healthy'}}})
                if fault == 'gateway':
                    entry = response(502)
            elif path == verify.DISCOVERY_PATH:
                issuer = ORIGIN + verify.ISSUER_PATH
                entry = response(body={'issuer': issuer if fault != 'issuer' else 'https://elsewhere.test',
                    'authorization_endpoint': ORIGIN + verify.AUTH, 'token_endpoint': issuer+'/protocol/openid-connect/token',
                    'jwks_uri': issuer+'/protocol/openid-connect/certs'})
            elif path == verify.LOGIN:
                fields = {'client_id': 'marty-ui', 'response_type': 'code', 'redirect_uri': ORIGIN+'/v1/auth/callback',
                          'state': 'masked_test_state_a234567890', 'code_challenge': 'masked_test_challenge_b23456789',
                          'code_challenge_method': 'S256'}
                if fault == 'login':
                    fields['redirect_uri'] = '/wrong'
                entry = response(302, location=ORIGIN + verify.AUTH + '?' + urlencode(fields))
                entry.headers['Set-Cookie'] = 'synthetic=never-record'
            elif path == verify.SESSION:
                entry = response(body={'authenticated': fault == 'anonymous-session'})
            elif path == '/product':
                entry = response(301, location=path + '/')
            elif state == 'staged':
                entry = html('/assets/combined-123.js')
                if port == 443 and path == '/':
                    entry = response(body=entry.body+b'<script src="/cdn-cgi/scripts/email.min.js"></script>', content='text/html')
                if path == verify.WEBSITE_MARKER and fault == 'lingering-website':
                    entry = response(body=SIGNED['website'], revision=REVISION)
            elif path == verify.WEBSITE_MARKER:
                entry = response(body=SIGNED['website'], revision=REVISION if fault != 'revision' else 'wrong')
            elif path in ('/pricing', '/pricing/'):
                entry = response(404, revision=REVISION)
                if path == '/pricing' and port == 443 and fault == 'pricing-published':
                    entry = html(PREFIX+'pricing.js', revision=REVISION)
                if path == '/pricing/' and port != 443 and fault == 'pricing-redirect':
                    entry = response(302, revision=REVISION, location='/pricing/checkout')
                if path == '/pricing' and port != 443 and fault == 'pricing-owner':
                    entry = response(404)
            elif path in ('/', '/product/'):
                entry = html(PREFIX + ('home.js' if path == '/' else 'other-entry.js'), revision=REVISION)
            elif path.endswith('/missing.js'):
                entry = response(200 if fault == 'unknown-revision' else 404)
            else:
                script = b'var qualified = 1;' if fault != 'asset' or port == 443 else b'wrong bytes'
                entry = response(body=script, revision=REVISION, content='application/javascript')
            if context:
                entry = verify.Response(entry.status, entry.headers, entry.body, {
                    'address': addresses[0], 'version': 'TLSv1.3', 'leaf_sha256': 'd'*64})
            return entry

        monkeypatch.setattr(verify, '_public_addresses', resolve)
        monkeypatch.setattr(verify, '_request', fetch)
        return calls
    return install


@pytest.mark.parametrize('state', ['split','staged'])
def test_public_acceptance_binds_assets_to_local_and_application_to_original(transport, state):
    calls = transport(state)
    routes, application = verify._observe(EDGE, MODEL, SIGNED, state)
    assert routes['origin'] == ORIGIN and routes['apex_redirect']['status'] == 308
    assert routes['routes']['public']['/']['tls']['address'] == '8.8.8.8'
    assert application['release']['public']['body_sha256'] == application['release']['loopback']['body_sha256']
    assert application['authorization']['callback_path'] == '/v1/auth/callback'
    assert application['authenticated_application_exercised'] is False
    evidence = json.dumps([routes, application])
    assert all(value not in evidence for value in ('masked_test_state', 'masked_test_challenge', 'never-record'))
    if state == 'split':
        assert (HOST, PREFIX+'home.js', 443) in calls and (HOST, PREFIX+'home.js', 29382) in calls
        for origin in ('public', 'loopback'):
            for path in ('/pricing', '/pricing/'):
                assert routes['routes'][origin][path]['status'] == 404


@pytest.mark.parametrize('fault', ['apex', 'application-marker', 'gateway', 'issuer', 'login', 'anonymous-session',
    'console', 'asset', 'unknown-revision', 'revision', 'dns-changed', 'lingering-website',
    'pricing-published', 'pricing-redirect', 'pricing-owner'])
def test_public_acceptance_fails_closed_on_wrong_route_or_application(transport, fault):
    state = 'staged' if fault == 'lingering-website' else 'split'
    transport(state, fault)
    with pytest.raises(ValueError):
        verify._observe(EDGE, MODEL, SIGNED, state)


def test_dns_observation_rejects_local_address_mixed_with_public_response(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *_, **_kw: [(None, None, None, None, ('8.8.8.8', 443)),
        (None, None, None, None, ('127.0.0.1', 443))])
    with pytest.raises(ValueError):
        verify._public_addresses(HOST)


def test_transport_validates_real_tls_server_name(tmp_path):
    certificate, key = cert(tmp_path, 'server', HOST)
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
    requests = []
    worker = serve(certificate, key, port, ORIGIN, requests)
    context = ssl.create_default_context(cafile=str(certificate))
    try:
        result = verify._request(HOST, '/', ('127.0.0.1',), port, context, time.monotonic()+5)
        assert result.body == b'OK' and result.peer['version'] in {'TLSv1.2','TLSv1.3'}
        assert ('Host: '+HOST).encode() in requests[0]
        with pytest.raises(ssl.SSLCertVerificationError):
            verify._request('wrong.example.test', '/', ('127.0.0.1',), port, context, time.monotonic()+5)
    finally:
        with socket.create_connection(('127.0.0.1', port), timeout=2):
            pass
        worker.join(timeout=2)


@pytest.mark.parametrize('phase,fault', [('verify-website', None), ('verify-combined', None),
    ('verify-website', 'gateway'), ('verify-website', 'edge-drift')])
def test_failed_public_probe_leaves_backout_eligible_and_success_anchors_receipts(paths, transport, monkeypatch, phase, fault):
    plan, records, _anchors = paths
    project = plan['owner']['project']
    state, prior = verify.PHASES[phase]
    status = verify.store.initialize(plan)
    for name in ('stage-candidate', prior):
        status = publish(plan, status, name)
        status = publish(plan, status, name, 'completed')
    pin = 'e'*64
    status = {**status, 'guard_sha256': pin}
    installed = dict(EDGE, **{'Id': 'a'*64, 'Image': 'sha256:'+'d'*64, 'Mounts': [], 'RestartCount': 0,
        'State': {'Status': 'running', 'StartedAt': 'fixture'}, 'Config': {**EDGE['Config'], 'Labels': {
            'com.docker.compose.project': project, 'com.docker.compose.service': 'edge'}}})
    context = SimpleNamespace(project=project, docker=object(), layouts={state:([], MODEL, {})},
                              proof_sha256=None, proof_count=0, check=lambda **_: [installed])
    checked = []
    nginx = {'container_id': installed['Id'], 'default_sha256': 'a'*64}

    def prepare(*_, **options):
        assert options['include_http'] and options['prior_phase'] == prior and options['target'] == state
        return context, {'http': SIGNED}, {'edge_configuration': nginx}, lambda: checked.append('route-inputs')

    def probe(*_):
        checked.append('nginx')
        return {} if fault == 'edge-drift' and checked.count('nginx') == 2 else nginx

    monkeypatch.setattr(verify.edge, '_prepare', prepare)
    monkeypatch.setattr(verify.edge, '_probe', probe)
    transport(state, fault)
    with ExitStack() as held:
        args = ({}, 'new', {}, {}, plan, status, phase)
        kwargs = dict(assets=Path('.'), gh=None, cosign=None, registry_config=None, authority_file=None, held=held)
        if fault:
            with pytest.raises(ValueError):
                verify.run(*args, **kwargs)
        else:
            completed = verify.run(*args, **kwargs)
    if fault:
        assert set(verify.store.inspect(plan, expected_anchor_sha256=status['anchor_sha256'])['permitted_record_phases']) == {
            'restore-combined', 'verify-website'}
        assert not (records.parent / (phase + '-after.json')).exists()
        return
    assert completed['completed_phases'][-1] == phase and checked == ['nginx', 'nginx', 'route-inputs']
    with ExitStack() as held:
        evidence = verify.store.read_evidence(plan, expected_anchor_sha256=completed['anchor_sha256'], held=held,
            references={phase+'-after.json': (phase, 'completed')})[phase+'-after.json']
    assert evidence['application_handoffs']['authenticated_application_exercised'] is False
    assert evidence['public_routes']['origin'] == ORIGIN
