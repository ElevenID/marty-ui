import base64
import json
from pathlib import Path
from types import SimpleNamespace

from starlette.requests import Request

from services.auth.domain.entities import AuthenticatedUser, Session
from services.auth.infrastructure.adapters import http_adapter


_FIXTURE = json.loads(
    (Path(__file__).parents[3] / "contracts" / "auth-http-kernels-behavior.json").read_text(
        encoding="utf-8"
    )
)


def _request(host: str, proto: str) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/v1/auth/login",
            "raw_path": b"/v1/auth/login",
            "query_string": b"",
            "headers": [
                (b"host", b"edge"),
                (b"x-forwarded-host", host.encode()),
                (b"x-forwarded-proto", proto.encode()),
            ],
            "client": ("127.0.0.1", 443),
            "server": ("edge", 80),
        }
    )


def test_redirect_and_origin_selection_shared_vectors(monkeypatch):
    assert _FIXTURE["schema_version"] == 1
    for case in _FIXTURE["redirect_cases"]:
        assert (
            http_adapter._sanitize_redirect_uri(case["redirect_uri"], case["ui_base_url"])
            == case["sanitized"]
        )
        assert (
            http_adapter._resolve_post_auth_redirect(
                case["redirect_uri"], case["ui_base_url"]
            )
            == case["resolved"]
        )
        assert (
            http_adapter._build_ui_redirect_url(case["redirect_uri"], case["ui_base_url"])
            == case["absolute"]
        )

    for case in _FIXTURE["origin_cases"]:
        monkeypatch.setattr(http_adapter, "_ui_base_url", case["primary"])
        monkeypatch.setenv("UI_ADDITIONAL_BASE_URLS", ",".join(case["additional"]))
        monkeypatch.delenv("AUTH_ADDITIONAL_UI_BASE_URLS", raising=False)
        monkeypatch.delenv("CORS_ORIGINS", raising=False)
        selected = http_adapter._request_ui_base_url(
            _request(case["forwarded_host"], case["forwarded_proto"])
        )
        assert selected == case["selected"]
        assert http_adapter._oidc_callback_url(selected) == f"{case['selected']}/v1/auth/callback"


def test_impersonation_shared_vectors():
    for case in _FIXTURE["impersonation_cases"]:
        session = Session.create(
            user=AuthenticatedUser(
                user_id=case["user_id"],
                email=case["email"],
                organization_id=case["organization_id"],
                organization_name=case["organization_name"],
            ),
            oidc_claims=case["claims"],
        )
        handoff = case["handoff"]
        cookie = (
            base64.urlsafe_b64encode(json.dumps(handoff).encode()).decode().rstrip("=")
            if handoff is not None
            else None
        )
        request = SimpleNamespace(
            cookies={"marty_impersonation_handoff": cookie} if cookie else {}
        )
        actual = http_adapter._build_session_impersonation(session, request)
        expected = case["expected"]
        if expected is None:
            assert actual is None
            continue
        assert actual is not None
        assert actual.active is True
        for field, value in expected.items():
            assert getattr(actual, field) == value
