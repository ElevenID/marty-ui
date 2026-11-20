"""Public health preserves issuer and source binding without provider lifecycle code."""
import json
from urllib.parse import urlencode

import pytest

from scripts import beta_public_health as health


def test_public_release_binding_preserves_both_markers_and_auth_check(monkeypatch):
    marker = {'release_version': 'synthetic-release', 'marty_ui_sha': 'a' * 40}
    seen = []
    def get(url):
        seen.append(url)
        return 200, b'ready' if url.endswith('/ready') else json.dumps(marker).encode()
    auth = []
    monkeypatch.setattr(health, 'get', get)
    monkeypatch.setattr(health, 'assert_public_auth_redirect', lambda: auth.append(True))
    assert health.assert_beta() == {'release_version': marker['release_version'], 'source_id': 'a' * 40}
    assert auth == [True]
    assert seen == [health.BETA_ORIGIN + path for path in
                    ['/ready', '/.well-known/marty-release', '/marty-ui-release.json']]


@pytest.mark.parametrize('field', ['release_version', 'marty_ui_sha'])
def test_public_release_binding_rejects_different_ui_source(monkeypatch, field):
    marker = {'release_version': 'synthetic-release', 'marty_ui_sha': 'a' * 40}
    def get(url):
        value = {**marker, field: 'different'} if url.endswith('/marty-ui-release.json') else marker
        return 200, b'ready' if url.endswith('/ready') else json.dumps(value).encode()
    monkeypatch.setattr(health, 'get', get)
    with pytest.raises(RuntimeError, match='release markers differ'):
        health.assert_beta(browser_ready=False)


def test_unready_beta_stops_before_auth_or_release_reads(monkeypatch):
    seen = []
    def get(url):
        seen.append(url)
        return 503, b'not ready'
    monkeypatch.setattr(health, 'get', get)
    monkeypatch.setattr(health, 'assert_public_auth_redirect', lambda: pytest.fail('Unready beta reached auth'))
    with pytest.raises(RuntimeError, match='readiness check failed'):
        health.assert_beta()
    assert seen == [health.BETA_ORIGIN + '/ready']


@pytest.mark.parametrize('mutate,accepted', [
    (lambda url: url, True),
    (lambda url: url.replace('beta.elevenidllc.com', 'foreign.invalid', 1), False),
    (lambda url: url.replace('/realms/11id/', '/realms/foreign/'), False),
    (lambda url: url + '&state=duplicate', False),
    (lambda url: url + '#fragment', False),
    (lambda url: url.replace('response_type=code', 'response_type=token'), False),
])
def test_auth_redirect_remains_bound_to_public_issuer_without_following_state(monkeypatch, mutate, accepted):
    target = health.BETA_ORIGIN + '/realms/11id/protocol/openid-connect/auth?' + urlencode({
        'client_id': 'synthetic-client', 'state': 'synthetic-state', 'code_challenge': 'synthetic-pkce',
        'response_type': 'code', 'redirect_uri': health.BETA_ORIGIN + '/v1/auth/callback',
    })
    class Response:
        status = 302
        headers = {'Location': mutate(target)}
        def __enter__(self): return self
        def __exit__(self, *args): pass
    class Opener:
        def open(self, request, timeout):
            assert request.full_url == health.BETA_ORIGIN + '/v1/auth/login?redirect_uri=%2Fconsole'
            assert timeout == 20
            return Response()
    def opener(handler):
        assert isinstance(handler, health._NoRedirect)
        assert handler.redirect_request(None) is None
        return Opener()
    monkeypatch.setattr(health.urllib.request, 'build_opener', opener)
    if accepted:
        health.assert_public_auth_redirect()
    else:
        with pytest.raises(RuntimeError, match='canonical issuer'):
            health.assert_public_auth_redirect()
