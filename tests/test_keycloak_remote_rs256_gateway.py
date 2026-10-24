"""The disposable browser probe must use its own Docker bridge gateway."""

from pathlib import Path
import sys
from http.cookiejar import Cookie
from urllib.request import Request

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import probe_keycloak_remote_rs256 as probe  # noqa: E402


def test_loopback_browser_returns_secure_cookie_only_to_owned_loopback_origin():
    cookie = Cookie(
        version=0, name="AUTH_SESSION_ID", value="synthetic-session",
        port=None, port_specified=False, domain="127.0.0.1",
        domain_specified=False, domain_initial_dot=False, path="/realms/master",
        path_specified=True, secure=True, expires=None, discard=True,
        comment=None, comment_url=None, rest={}, rfc2109=False,
    )
    jar = probe.browser_cookie_jar()
    jar.set_cookie(cookie)
    loopback = Request("http://127.0.0.1:8180/realms/master/login-actions/authenticate")
    jar.add_cookie_header(loopback)
    assert loopback.get_header("Cookie") == "AUTH_SESSION_ID=synthetic-session"
    policy = probe.LoopbackBrowserCookiePolicy()
    assert not policy.return_ok_secure(
        cookie, Request("http://127.0.0.2:8180/realms/master/login-actions/authenticate")
    )
    assert policy.return_ok_secure(
        cookie, Request("https://example.com/realms/master/login-actions/authenticate")
    )


def test_host_callback_alias_uses_exact_owned_bridge(monkeypatch):
    observed = []

    def network_inspect(*args):
        observed.append(args)
        return '[{"Subnet":"172.27.0.0/16","Gateway":"172.27.0.1"}]'

    monkeypatch.setattr(probe, "run", network_inspect)
    assert probe.host_gateway_alias("marty-keycloak-kms-net-owned") == (
        "host.docker.internal:172.27.0.1"
    )
    assert observed == [(
        "docker", "network", "inspect", "--format", "{{json .IPAM.Config}}",
        "marty-keycloak-kms-net-owned",
    )]


def test_host_callback_alias_accepts_dual_stack_with_one_ipv4_gateway(monkeypatch):
    monkeypatch.setattr(
        probe,
        "run",
        lambda *_args: '[{"Gateway":"fd00::1"},{"Gateway":"172.27.0.1"}]',
    )
    assert probe.host_gateway_alias("marty-keycloak-kms-net-owned") == (
        "host.docker.internal:172.27.0.1"
    )


@pytest.mark.parametrize("network_config", [
    "null", "[]", '[{"Gateway":"invalid IP"}]',
    '[{"Gateway":"127.0.0.1"}]', '[{"Gateway":"8.8.8.8"}]',
    '[{"Gateway":"::1"}]',
    '[{"Gateway":"172.27.0.1"},{"Gateway":"172.28.0.1"}]',
])
def test_host_callback_alias_rejects_unowned_or_ambiguous_gateway(
    monkeypatch, network_config
):
    monkeypatch.setattr(probe, "run", lambda *_args: network_config)
    with pytest.raises(RuntimeError, match="gateway"):
        probe.host_gateway_alias("marty-keycloak-kms-net-owned")
