"""Read-only public beta health and release-binding checks.

These checks do not mutate deployments or qualify a production release. They are
platform-owned and have no provider lifecycle or container-management dependency.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

BETA_ORIGIN = "https://beta.elevenidllc.com"


def get(url: str) -> tuple[int, bytes]:
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache", "User-Agent": "marty-public-beta-health/1"})
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - fixed public origins
        return response.status, response.read()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args):
        return None


def assert_public_auth_redirect() -> None:
    """Require public auth initiation without following OIDC state."""
    request = urllib.request.Request(
        f"{BETA_ORIGIN}/v1/auth/login?redirect_uri=%2Fconsole",
        headers={"Cache-Control": "no-cache", "User-Agent": "marty-public-beta-health/1"},
    )
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=20) as response:
            status, location = response.status, response.headers.get("Location")
    except urllib.error.HTTPError as error:
        status, location = error.code, error.headers.get("Location")
        error.close()
    if status not in (302, 303) or not location:
        raise RuntimeError("public beta auth redirect is unavailable")
    target = urllib.parse.urlsplit(location)
    query = urllib.parse.parse_qs(target.query, keep_blank_values=True)
    expected = urllib.parse.urlsplit(BETA_ORIGIN)
    if (target.scheme != "https" or target.netloc != expected.netloc
            or target.path != "/realms/11id/protocol/openid-connect/auth"
            or target.fragment or any(len(query.get(key, [])) != 1 or not query[key][0]
                                   for key in ("client_id", "state", "code_challenge"))
            or query.get("response_type") != ["code"]
            or query.get("redirect_uri") != [f"{BETA_ORIGIN}/v1/auth/callback"]):
        raise RuntimeError("public beta auth redirect is not bound to the canonical issuer")


def assert_beta(*, browser_ready: bool = True) -> dict[str, str]:
    status, ready = get(f"{BETA_ORIGIN}/ready")
    if status != 200:
        raise RuntimeError("beta readiness check failed")
    if browser_ready:
        assert_public_auth_redirect()
    services = json.loads(get(f"{BETA_ORIGIN}/.well-known/marty-release")[1])
    ui = json.loads(get(f"{BETA_ORIGIN}/marty-ui-release.json")[1])
    if services.get("release_version") != ui.get("release_version") or services.get("marty_ui_sha") != ui.get("marty_ui_sha"):
        raise RuntimeError("beta UI and services release markers differ")
    return {"release_version": services["release_version"], "source_id": services["marty_ui_sha"]}
