import base64
import json
from types import SimpleNamespace

from services.auth.domain.entities import AuthenticatedUser, Session
from services.auth.infrastructure.adapters.http_adapter import _build_session_impersonation


def _encode_base64url(payload: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")


def _build_jwt(claims: dict) -> str:
    return ".".join([
        _encode_base64url({"alg": "none", "typ": "JWT"}),
        _encode_base64url(claims),
        "signature",
    ])


def test_build_session_impersonation_uses_handoff_cookie_for_matching_target():
    user = AuthenticatedUser(
        user_id="vendor-1",
        email="vendor@example.com",
        organization_id="org-1",
        organization_name="Vendor Org",
    )
    session = Session.create(user=user)
    cookie_payload = {
        "admin_user_id": "admin-1",
        "admin_username": "admin",
        "admin_email": "admin@example.com",
        "admin_display_name": "Admin User",
        "target_user_id": "vendor-1",
        "target_email": "vendor@example.com",
        "organization_id": "org-1",
        "organization_name": "Vendor Org",
        "launch_mode": "new-tab",
        "started_at": "2026-04-16T02:00:00.000Z",
    }
    request = SimpleNamespace(cookies={
        "marty_impersonation_handoff": _encode_base64url(cookie_payload),
    })

    impersonation = _build_session_impersonation(session, request)

    assert impersonation is not None
    assert impersonation.active is True
    assert impersonation.admin_user_id == "admin-1"
    assert impersonation.admin_email == "admin@example.com"
    assert impersonation.target_user_id == "vendor-1"
    assert impersonation.organization_name == "Vendor Org"
    assert impersonation.launch_mode == "new-tab"


def test_build_session_impersonation_uses_native_keycloak_claims_when_present():
    user = AuthenticatedUser(
        user_id="vendor-1",
        email="vendor@example.com",
        organization_id="org-1",
        organization_name="Vendor Org",
    )
    session = Session.create(
        user=user,
        id_token=_build_jwt({
            "sub": "vendor-1",
            "email": "vendor@example.com",
            "IMPERSONATOR_ID": "admin-2",
            "IMPERSONATOR_USERNAME": "support.admin",
        }),
    )
    request = SimpleNamespace(cookies={})

    impersonation = _build_session_impersonation(session, request)

    assert impersonation is not None
    assert impersonation.admin_user_id == "admin-2"
    assert impersonation.admin_username == "support.admin"
    assert impersonation.target_user_id == "vendor-1"
    assert impersonation.organization_id == "org-1"
