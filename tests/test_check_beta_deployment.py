from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_beta_deployment",
    ROOT / "scripts" / "check-beta-deployment.py",
)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class _Response:
    def __init__(self, payload: dict[str, str]) -> None:
        self.status = 200
        self.headers: dict[str, str] = {}
        self._body = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, limit: int) -> bytes:
        assert limit == 1_048_577
        return io.BytesIO(self._body).read(limit)


def test_oidc_discovery_requires_the_exact_canonical_issuer(monkeypatch) -> None:
    monkeypatch.setattr(
        CHECK.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(
            {
                "issuer": "http://beta.elevenidllc.com:8080/realms/11id",
                "jwks_uri": "http://beta.elevenidllc.com:8080/realms/11id/protocol/openid-connect/certs",
            }
        ),
    )

    ready, detail = CHECK.oidc_discovery_ready(
        "https://beta.elevenidllc.com/realms/11id/.well-known/openid-configuration",
        "https://beta.elevenidllc.com/realms/11id",
    )

    assert ready is False
    assert "issuer mismatch" in detail


def test_oidc_discovery_accepts_the_canonical_issuer_and_jwks(monkeypatch) -> None:
    issuer = "https://beta.elevenidllc.com/realms/11id"
    monkeypatch.setattr(
        CHECK.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(
            {
                "issuer": issuer,
                "jwks_uri": f"{issuer}/protocol/openid-connect/certs",
            }
        ),
    )

    ready, detail = CHECK.oidc_discovery_ready(
        f"{issuer}/.well-known/openid-configuration",
        issuer,
    )

    assert ready is True
    assert detail == "HTTP 200, canonical issuer"


def test_internal_oidc_discovery_rejects_proxy_dependent_issuer(monkeypatch) -> None:
    class _Result:
        stdout = json.dumps(
            {
                "issuer": "http://beta.elevenidllc.com:8080/realms/11id",
                "jwks_uri": "http://beta.elevenidllc.com:8080/realms/11id/protocol/openid-connect/certs",
            }
        )

    monkeypatch.setattr(CHECK.subprocess, "run", lambda *_args, **_kwargs: _Result())

    ready, detail = CHECK.internal_oidc_discovery_ready(
        "auth-container",
        "https://beta.elevenidllc.com/realms/11id",
    )

    assert ready is False
    assert "internal issuer mismatch" in detail


def test_internal_oidc_discovery_accepts_canonical_server_to_server_metadata(monkeypatch) -> None:
    issuer = "https://beta.elevenidllc.com/realms/11id"

    class _Result:
        stdout = json.dumps(
            {
                "issuer": issuer,
                "jwks_uri": f"{issuer}/protocol/openid-connect/certs",
            }
        )

    monkeypatch.setattr(CHECK.subprocess, "run", lambda *_args, **_kwargs: _Result())

    ready, detail = CHECK.internal_oidc_discovery_ready("auth-container", issuer)

    assert ready is True
    assert detail == "canonical issuer"
