import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, quote, urlparse
from uuid import uuid4

import pytest
import redis.asyncio as redis
from starlette.requests import Request
from starlette.responses import Response
from common.webhook_signatures import (
    AUTH_CALLBACK_AUDIENCE,
    payload_digest,
    sign_event,
)

from services.auth.infrastructure.adapters import http_adapter
from services.auth.domain.entities import AuthenticatedUser
from services.auth.infrastructure.adapters.http_adapter import (
    _build_ui_redirect_url,
    _CREDENTIAL_LOGIN_CSS,
    _CREDENTIAL_LOGIN_JS,
    _credential_login_failure_payload,
    _oidc_callback_url,
    _request_ui_base_url,
    _resolve_post_auth_redirect,
    _build_canvas_lti_user,
    _build_credential_login_wallet_options,
    _render_credential_login_page,
    credential_login_finalize,
    credential_login_status,
    get_current_user,
)
from services.auth.infrastructure.adapters.oidc_adapter import build_oidc_user_info


def _build_request(*, referer: str = "") -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if referer:
        headers.append((b"referer", referer.encode("utf-8")))

    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": "/v1/auth/credential-login",
            "raw_path": b"/v1/auth/credential-login",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 443),
            "server": ("elevenidllc.com", 443),
        }
    )


def _build_forwarded_request(
    *,
    host: str,
    proto: str = "https",
    method: str = "GET",
    authorization: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> Request:
    headers = [
        (b"host", b"edge"),
        (b"x-forwarded-host", host.encode("utf-8")),
        (b"x-forwarded-proto", proto.encode("utf-8")),
    ]
    if authorization:
        headers.append((b"authorization", authorization.encode("utf-8")))
    for name, value in (extra_headers or {}).items():
        headers.append((name.lower().encode("ascii"), value.encode("utf-8")))
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": "/v1/auth/login",
            "raw_path": b"/v1/auth/login",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 443),
            "server": ("edge", 80),
        }
    )


def test_build_oidc_user_info_merges_keycloak_roles_and_org_claims():
    id_claims = {
        "sub": "kc-user-1",
        "email": "alice@example.com",
        "given_name": "Alice",
        "family_name": "Smith",
        "preferred_username": "alice",
        "organization": {
            "org-1": {"name": "Acme"},
            "org-2": {"name": "Beta"},
        },
    }
    access_claims = {
        "realm_access": {"roles": ["vendor"]},
        "resource_access": {
            "marty-ui": {"roles": ["organization-admin"]},
            "marty-api": {"roles": ["api-user"]},
        },
        "roles": ["administrator"],
    }

    oidc_user = build_oidc_user_info(id_claims, access_claims)

    assert oidc_user.sub == "kc-user-1"
    assert oidc_user.organization == {
        "org-1": {"name": "Acme"},
        "org-2": {"name": "Beta"},
    }
    assert oidc_user.organization_id == "org-1"
    assert oidc_user.organization_name == "Acme"
    assert oidc_user.roles == ["administrator", "vendor", "organization-admin", "api-user"]


@pytest.mark.asyncio
async def test_get_current_user_includes_raw_keycloak_organization_claim():
    user = AuthenticatedUser(
        user_id="user-1",
        email="alice@example.com",
        roles=["applicant"],
        organization_id="org-1",
        organization_name="Acme",
        organization={"org-1": {"name": "Acme"}},
        default_organization_id="org-1",
        default_organization_name="Acme",
        organizations=[{"id": "org-1", "name": "Acme", "display_name": "Acme"}],
    )

    response = await get_current_user(Response(), user)

    assert response.authenticated is True
    assert response.user is not None
    assert response.user.organization == {"org-1": {"name": "Acme"}}
    assert response.user.default_organization_id == "org-1"
    assert response.user.organizations == [{"id": "org-1", "name": "Acme", "display_name": "Acme"}]


def test_root_post_auth_redirects_land_in_console_entry():
    ui_base_url = "https://elevenidllc.com"

    assert _resolve_post_auth_redirect("/", ui_base_url) == "/console"
    assert _resolve_post_auth_redirect("https://elevenidllc.com/", ui_base_url) == "/console"
    assert _resolve_post_auth_redirect("/console/org", ui_base_url) == "/console/org"
    assert _build_ui_redirect_url("/", ui_base_url) == "https://elevenidllc.com/console"


def test_request_ui_base_url_allows_configured_beta_origin(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(http_adapter, "_ui_base_url", "https://elevenidllc.com")
    monkeypatch.setenv("UI_ADDITIONAL_BASE_URLS", "https://beta.elevenidllc.com")

    request_ui_base_url = _request_ui_base_url(
        _build_forwarded_request(host="beta.elevenidllc.com")
    )

    assert request_ui_base_url == "https://beta.elevenidllc.com"
    assert _oidc_callback_url(request_ui_base_url) == "https://beta.elevenidllc.com/v1/auth/callback"


def test_request_ui_base_url_normalizes_trusted_origin_proto(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(http_adapter, "_ui_base_url", "https://elevenidllc.com")
    monkeypatch.setenv("UI_ADDITIONAL_BASE_URLS", "https://beta.elevenidllc.com")

    request_ui_base_url = _request_ui_base_url(
        _build_forwarded_request(host="beta.elevenidllc.com", proto="http")
    )

    assert request_ui_base_url == "https://beta.elevenidllc.com"
    assert _oidc_callback_url(request_ui_base_url) == "https://beta.elevenidllc.com/v1/auth/callback"


def test_request_ui_base_url_allows_configured_cors_origin(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(http_adapter, "_ui_base_url", "https://elevenidllc.com")
    monkeypatch.delenv("UI_ADDITIONAL_BASE_URLS", raising=False)
    monkeypatch.delenv("AUTH_ADDITIONAL_UI_BASE_URLS", raising=False)
    monkeypatch.setenv("CORS_ORIGINS", "https://elevenidllc.com,https://beta.elevenidllc.com")

    request_ui_base_url = _request_ui_base_url(
        _build_forwarded_request(host="beta.elevenidllc.com")
    )

    assert request_ui_base_url == "https://beta.elevenidllc.com"
    assert _oidc_callback_url(request_ui_base_url) == "https://beta.elevenidllc.com/v1/auth/callback"


def test_request_ui_base_url_rejects_untrusted_forwarded_origin(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(http_adapter, "_ui_base_url", "https://elevenidllc.com")
    monkeypatch.delenv("UI_ADDITIONAL_BASE_URLS", raising=False)
    monkeypatch.delenv("AUTH_ADDITIONAL_UI_BASE_URLS", raising=False)
    monkeypatch.delenv("CORS_ORIGINS", raising=False)

    request_ui_base_url = _request_ui_base_url(
        _build_forwarded_request(host="attacker.example")
    )

    assert request_ui_base_url == "https://elevenidllc.com"


class _FakeRedis:
    def __init__(self, payload: str | None):
        self._payload = payload
        self.deleted_keys: list[str] = []
        self.completed_payloads: list[dict] = []
        self.claimed_keys: set[str] = set()
        self.values: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        if key in self.values:
            return self.values[key]
        if key in self.deleted_keys or key.startswith(http_adapter._CALLBACK_CLAIM_KEY):
            return None
        return self._payload

    async def getdel(self, key: str) -> str | None:
        payload = self._payload
        self._payload = None
        self.deleted_keys.append(key)
        return payload

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.completed_payloads.append(json.loads(value))
        self.values[key] = value

    async def delete(self, key: str) -> None:
        self.deleted_keys.append(key)

    async def set(
        self,
        key: str,
        value: str,
        *,
        ex: int,
        nx: bool = False,
    ) -> bool:
        assert ex in {
            http_adapter._CALLBACK_CLAIM_LEASE_SECONDS,
            http_adapter._PENDING_TTL,
        }
        if nx and key in self.claimed_keys:
            return False
        self.claimed_keys.add(key)
        self.values[key] = value
        return True


class _FakeSessionRepository:
    def __init__(self):
        self.saved = []

    async def save(self, session) -> None:
        self.saved.append(session)


_CALLBACK_SECRET = "test-flow-webhook-secret-at-least-32-bytes"


def _credential_verified_payload(
    **overrides,
) -> http_adapter.CredentialVerifiedPayload:
    basis = {
        "flow_instance_id": "flow-1",
        "result": "passed",
        "decision": "allow",
        "decision_reason": "",
        "verified_claims": {"email": "alice@example.com"},
        "presentation_policy_id": "policy-1",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "evidence_digest": "a" * 64,
    }
    basis.update(overrides)
    basis["decision_digest"] = payload_digest(basis)
    return http_adapter.CredentialVerifiedPayload(**basis)


def _signed_credential_callback_request(
    payload: http_adapter.CredentialVerifiedPayload,
    *,
    timestamp: datetime | None = None,
) -> Request:
    event = "flow.verification_completed"
    event_timestamp = (timestamp or datetime.now(timezone.utc)).isoformat()
    signature = sign_event(
        _CALLBACK_SECRET,
        audience=AUTH_CALLBACK_AUDIENCE,
        event=event,
        event_id=payload.flow_instance_id,
        timestamp=event_timestamp,
        payload=payload.model_dump(mode="json"),
    )
    return _build_forwarded_request(
        host="elevenidllc.com",
        method="POST",
        extra_headers={
            "x-mip-event": event,
            "x-mip-audience": AUTH_CALLBACK_AUDIENCE,
            "x-mip-event-id": payload.flow_instance_id,
            "x-mip-timestamp": event_timestamp,
            "x-mip-signature": signature,
        },
    )


def test_flow_webhook_secret_rejects_weak_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLOW_WEBHOOK_SECRET", "weak-secret")
    monkeypatch.delenv("FLOW_WEBHOOK_SECRET_FILE", raising=False)

    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        http_adapter._read_flow_webhook_secret()


def test_credential_callback_session_id_is_stable_and_event_bound() -> None:
    first = http_adapter._credential_callback_session_id(
        _CALLBACK_SECRET,
        flow_instance_id="flow-1",
        nonce="nonce-1",
    )
    retry = http_adapter._credential_callback_session_id(
        _CALLBACK_SECRET,
        flow_instance_id="flow-1",
        nonce="nonce-1",
    )
    other_event = http_adapter._credential_callback_session_id(
        _CALLBACK_SECRET,
        flow_instance_id="flow-2",
        nonce="nonce-1",
    )

    assert first == retry
    assert first != other_event


def _canvas_lti_session_payload() -> dict:
    return {
        "organization_id": "00000000-0000-0000-0000-000000000001",
        "canvas_account_id": "canvas-account-1",
        "learner_key": "c3b3d1c3314a1ba18a2f3a165a3ecaa443ca9f3ef1b95b4f7f6d18b8c011aa11",
        "learner_display_name": "Canvas Learner",
        "roles": ["Learner"],
    }


def test_build_canvas_lti_user_creates_stable_constrained_applicant_identity(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CANVAS_LTI_ORGANIZATION_NAME", raising=False)
    monkeypatch.delenv("MARTY_ORG_NAME", raising=False)

    user = _build_canvas_lti_user(_canvas_lti_session_payload())
    second_user = _build_canvas_lti_user(_canvas_lti_session_payload())

    assert user.user_id == second_user.user_id
    assert user.user_id.startswith("canvas-lti-")
    assert user.email.startswith("canvas-")
    assert user.email.endswith("@canvas.lti.local")
    assert user.username == user.email.split("@", 1)[0]
    assert user.given_name == "Canvas"
    assert user.family_name == "Learner"
    assert user.user_type.value == "applicant"
    assert user.roles == ["applicant", "canvas_lti_learner"]
    assert user.organization_id == "00000000-0000-0000-0000-000000000001"
    assert user.organization_name == "Canvas learner organization"
    assert user.organization is None


@pytest.mark.asyncio
async def test_canvas_lti_finalize_sets_canvas_user_session_cookie(monkeypatch: pytest.MonkeyPatch):
    fake_repo = _FakeSessionRepository()

    async def fake_fetch(token: str) -> dict:
        assert token == "experience-token"
        return _canvas_lti_session_payload()

    monkeypatch.setattr(http_adapter, "_fetch_current_canvas_lti_experience_session", fake_fetch)
    monkeypatch.setattr(http_adapter, "_session_repository", fake_repo)
    monkeypatch.setattr(http_adapter, "_applicant_profile_provisioner", None)
    monkeypatch.setattr(http_adapter, "_ui_base_url", "https://elevenidllc.com")
    monkeypatch.setattr(http_adapter, "_cookie_config", {
        "key": "sessionId",
        "httponly": True,
        "secure": True,
        "samesite": "lax",
        "max_age": 86400,
        "path": "/",
    })
    monkeypatch.setenv("UI_ADDITIONAL_BASE_URLS", "https://beta.elevenidllc.com")

    response = await http_adapter.canvas_lti_finalize(
        request=_build_forwarded_request(
            host="beta.elevenidllc.com",
            method="POST",
            authorization="Bearer experience-token",
        ),
    )

    assert response.status_code == 200
    assert json.loads(response.body) == {
        "authenticated": True,
        "expires_in": http_adapter._canvas_lti_session_ttl_seconds,
    }
    assert "sessionId=" in response.headers.get("set-cookie", "")
    assert len(fake_repo.saved) == 1
    assert fake_repo.saved[0].user.email.endswith("@canvas.lti.local")
    assert fake_repo.saved[0].user.roles == ["applicant", "canvas_lti_learner"]
    assert fake_repo.saved[0].user.organization_id == "00000000-0000-0000-0000-000000000001"


@pytest.mark.asyncio
async def test_credential_login_finalize_redirects_to_console_and_sets_cookie(monkeypatch: pytest.MonkeyPatch):
    fake_redis = _FakeRedis(json.dumps({
        "status": "completed",
        "session_id": "session-123",
    }))

    monkeypatch.setattr(http_adapter, "_redis_client", fake_redis)
    monkeypatch.setattr(http_adapter, "_ui_base_url", "https://elevenidllc.com")
    monkeypatch.setattr(http_adapter, "_cookie_config", {
        "key": "sessionId",
        "httponly": True,
        "secure": True,
        "samesite": "lax",
        "max_age": 86400,
        "path": "/",
    })

    response = await credential_login_finalize("nonce-123", Response())

    assert response.status_code == 302
    assert response.headers["location"] == "https://elevenidllc.com/console"
    assert "sessionId=session-123" in response.headers.get("set-cookie", "")
    assert fake_redis.deleted_keys == [f"{http_adapter._COMPLETE_KEY}nonce-123"]


@pytest.mark.asyncio
async def test_credential_login_finalize_atomically_issues_one_session_cookie(
    monkeypatch: pytest.MonkeyPatch,
):
    fake_redis = _FakeRedis(json.dumps({
        "status": "completed",
        "session_id": "session-123",
    }))

    monkeypatch.setattr(http_adapter, "_redis_client", fake_redis)
    monkeypatch.setattr(http_adapter, "_ui_base_url", "https://elevenidllc.com")
    monkeypatch.setattr(http_adapter, "_cookie_config", {
        "key": "sessionId",
        "httponly": True,
        "secure": True,
        "samesite": "lax",
        "max_age": 86400,
        "path": "/",
    })

    responses = await asyncio.gather(
        credential_login_finalize("nonce-123", Response()),
        credential_login_finalize("nonce-123", Response()),
    )

    authenticated = [
        response
        for response in responses
        if "sessionId=session-123" in response.headers.get("set-cookie", "")
    ]
    expired = [
        response
        for response in responses
        if "auth_error=Login+session+expired" in response.headers["location"]
    ]
    assert len(authenticated) == 1
    assert len(expired) == 1


@pytest.mark.asyncio
async def test_credential_login_finalize_has_one_real_redis_winner(
    monkeypatch: pytest.MonkeyPatch,
):
    redis_client = redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        decode_responses=True,
    )
    completion_key: str | None = None
    try:
        try:
            await redis_client.ping()
        except Exception as exc:
            pytest.skip(f"Redis is unavailable: {exc}")

        nonce = f"atomic-finalize-{uuid4()}"
        completion_key = f"{http_adapter._COMPLETE_KEY}{nonce}"
        await redis_client.set(
            completion_key,
            json.dumps({"status": "completed", "session_id": "session-123"}),
            ex=30,
        )
        monkeypatch.setattr(http_adapter, "_redis_client", redis_client)
        monkeypatch.setattr(http_adapter, "_ui_base_url", "https://elevenidllc.com")
        monkeypatch.setattr(http_adapter, "_cookie_config", {
            "key": "sessionId",
            "httponly": True,
            "secure": True,
            "samesite": "lax",
            "max_age": 86400,
            "path": "/",
        })

        responses = await asyncio.gather(
            *(credential_login_finalize(nonce, Response()) for _ in range(12))
        )

        authenticated = [
            response
            for response in responses
            if "sessionId=session-123" in response.headers.get("set-cookie", "")
        ]
        assert len(authenticated) == 1
        assert await redis_client.get(completion_key) is None
    finally:
        if completion_key is not None:
            await redis_client.delete(completion_key)
        await redis_client.aclose()


@pytest.mark.asyncio
async def test_credential_verified_allows_claim_only_login_without_keycloak_admin(monkeypatch: pytest.MonkeyPatch):
    fake_redis = _FakeRedis(json.dumps({
        "state": "pending",
        "flow_instance_id": "flow-1",
        "presentation_policy_id": "policy-1",
        "organization_id": "org-1",
    }))
    fake_repo = _FakeSessionRepository()

    monkeypatch.setattr(http_adapter, "_redis_client", fake_redis)
    monkeypatch.setattr(http_adapter, "_session_repository", fake_repo)
    monkeypatch.setattr(http_adapter, "_kc_admin_adapter", None)
    monkeypatch.setattr(http_adapter, "_user_provisioning", None)
    monkeypatch.setattr(http_adapter, "_applicant_profile_provisioner", None)
    monkeypatch.setattr(http_adapter, "_credential_login_require_existing_keycloak_user", False)
    monkeypatch.setattr(http_adapter, "_credential_login_create_users", False)
    monkeypatch.setattr(http_adapter, "_credential_login_policy_id", "policy-1")
    monkeypatch.setattr(http_adapter, "_credential_login_organization_id", "org-1")
    monkeypatch.setenv("FLOW_WEBHOOK_SECRET", _CALLBACK_SECRET)
    payload = _credential_verified_payload(
        verified_claims={
            "email": "alice@example.com",
            "given_name": "Alice",
            "role": "administrator",
            "organization_id": "attacker-org",
        },
    )

    result = await http_adapter.credential_verified(
        payload=payload,
        nonce="nonce-claim-only",
        request=_signed_credential_callback_request(payload),
    )

    assert result["status"] == "completed"
    assert len(fake_repo.saved) == 1
    assert fake_repo.saved[0].user.email == "alice@example.com"
    assert fake_repo.saved[0].user.roles == ["applicant"]
    assert fake_repo.saved[0].user.organization_id == "org-1"
    assert fake_redis.completed_payloads[0]["status"] == "completed"


@pytest.mark.asyncio
async def test_credential_verified_denies_without_keycloak_admin_when_existing_user_required(
    monkeypatch: pytest.MonkeyPatch,
):
    fake_redis = _FakeRedis(json.dumps({
        "state": "pending",
        "flow_instance_id": "flow-1",
        "presentation_policy_id": "policy-1",
        "organization_id": "org-1",
    }))
    fake_repo = _FakeSessionRepository()

    monkeypatch.setattr(http_adapter, "_redis_client", fake_redis)
    monkeypatch.setattr(http_adapter, "_session_repository", fake_repo)
    monkeypatch.setattr(http_adapter, "_kc_admin_adapter", None)
    monkeypatch.setattr(http_adapter, "_credential_login_require_existing_keycloak_user", True)
    monkeypatch.setattr(http_adapter, "_credential_login_create_users", False)
    monkeypatch.setattr(http_adapter, "_credential_login_policy_id", "policy-1")
    monkeypatch.setattr(http_adapter, "_credential_login_organization_id", "org-1")
    monkeypatch.setenv("FLOW_WEBHOOK_SECRET", _CALLBACK_SECRET)
    payload = _credential_verified_payload()

    result = await http_adapter.credential_verified(
        payload=payload,
        nonce="nonce-existing-required",
        request=_signed_credential_callback_request(payload),
    )

    assert result["status"] == "denied"
    assert fake_repo.saved == []
    assert fake_redis.completed_payloads[0]["reason_code"] == "keycloak_admin_unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["unsigned", "stale", "wrong_flow", "wrong_policy"])
async def test_credential_verified_rejects_unauthenticated_or_unbound_callbacks(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
):
    fake_redis = _FakeRedis(json.dumps({
        "flow_instance_id": "flow-1",
        "presentation_policy_id": "policy-1",
        "organization_id": "org-1",
    }))
    fake_repo = _FakeSessionRepository()
    monkeypatch.setattr(http_adapter, "_redis_client", fake_redis)
    monkeypatch.setattr(http_adapter, "_session_repository", fake_repo)
    monkeypatch.setattr(http_adapter, "_credential_login_policy_id", "policy-1")
    monkeypatch.setattr(http_adapter, "_credential_login_organization_id", "org-1")
    monkeypatch.setenv("FLOW_WEBHOOK_SECRET", _CALLBACK_SECRET)

    payload = _credential_verified_payload(
        flow_instance_id="flow-2" if failure == "wrong_flow" else "flow-1",
        verified_claims={"email": "attacker@example.com"},
        presentation_policy_id="policy-2" if failure == "wrong_policy" else "policy-1",
    )
    request = (
        _build_forwarded_request(host="elevenidllc.com", method="POST")
        if failure == "unsigned"
        else _signed_credential_callback_request(
            payload,
            timestamp=(
                datetime.now(timezone.utc) - timedelta(minutes=10)
                if failure == "stale"
                else None
            ),
        )
    )

    with pytest.raises(http_adapter.HTTPException) as exc_info:
        await http_adapter.credential_verified(
            payload=payload,
            nonce="nonce-attack",
            request=request,
        )

    assert exc_info.value.status_code in {401, 409}
    assert fake_repo.saved == []
    assert fake_redis.claimed_keys == set()


@pytest.mark.asyncio
async def test_credential_verified_retries_are_idempotent(monkeypatch: pytest.MonkeyPatch):
    fake_redis = _FakeRedis(json.dumps({
        "flow_instance_id": "flow-1",
        "presentation_policy_id": "policy-1",
        "organization_id": "org-1",
    }))
    fake_repo = _FakeSessionRepository()
    monkeypatch.setattr(http_adapter, "_redis_client", fake_redis)
    monkeypatch.setattr(http_adapter, "_session_repository", fake_repo)
    monkeypatch.setattr(http_adapter, "_kc_admin_adapter", None)
    monkeypatch.setattr(http_adapter, "_user_provisioning", None)
    monkeypatch.setattr(http_adapter, "_applicant_profile_provisioner", None)
    monkeypatch.setattr(http_adapter, "_credential_login_require_existing_keycloak_user", False)
    monkeypatch.setattr(http_adapter, "_credential_login_create_users", False)
    monkeypatch.setattr(http_adapter, "_credential_login_policy_id", "policy-1")
    monkeypatch.setattr(http_adapter, "_credential_login_organization_id", "org-1")
    monkeypatch.setenv("FLOW_WEBHOOK_SECRET", _CALLBACK_SECRET)
    payload = _credential_verified_payload()
    request = _signed_credential_callback_request(payload)

    first = await http_adapter.credential_verified(payload, "nonce-once", request)
    retry = await http_adapter.credential_verified(payload, "nonce-once", request)

    assert first["status"] == "completed"
    assert retry == {"ok": True, "status": "already_processed"}
    assert len(fake_repo.saved) == 1


def test_credential_login_failure_payload_maps_trust_mismatch_to_user_friendly_message():
    payload = _credential_login_failure_payload(
        "Credential verification failed: Issuer did:web:elevenidllc.com:orgs:marty does not match any trust source issuer identifier in Trust Profile 60000000-0000-0000-0000-000000000001"
    )

    assert payload["reason_code"] == "issuer_not_trusted"
    assert "does not trust" in payload["message"]
    assert "did:web:elevenidllc.com:orgs:marty" in payload["detail"]


def test_credential_login_failure_payload_maps_missing_revocation_check():
    payload = _credential_login_failure_payload(
        "Credential verification failed: Revocation status was not checked by the verifier"
    )

    assert payload["reason_code"] == "revocation_not_checked"
    assert "still active" in payload["message"]


@pytest.mark.asyncio
async def test_credential_login_status_surfaces_failure_message_and_detail(monkeypatch: pytest.MonkeyPatch):
    fake_redis = _FakeRedis(json.dumps({
        "status": "failed",
        "reason": "Credential verification failed: Issuer did:web:elevenidllc.com:orgs:marty does not match any trust source issuer identifier in Trust Profile 60000000-0000-0000-0000-000000000001",
    }))

    monkeypatch.setattr(http_adapter, "_redis_client", fake_redis)

    response = await credential_login_status("nonce-123")

    assert response["status"] == "failed"
    assert response["reason_code"] == "issuer_not_trusted"
    assert "does not trust" in response["message"]
    assert "did:web:elevenidllc.com:orgs:marty" in response["detail"]


@pytest.mark.asyncio
async def test_credential_login_finalize_redirects_failed_login_with_reason(monkeypatch: pytest.MonkeyPatch):
    fake_redis = _FakeRedis(json.dumps({
        "status": "failed",
        "reason": "Credential verification failed: Issuer did:web:elevenidllc.com:orgs:marty does not match any trust source issuer identifier in Trust Profile 60000000-0000-0000-0000-000000000001",
    }))

    monkeypatch.setattr(http_adapter, "_redis_client", fake_redis)
    monkeypatch.setattr(http_adapter, "_ui_base_url", "https://elevenidllc.com")

    response = await credential_login_finalize("nonce-123", Response())
    redirect_url = urlparse(response.headers["location"])
    query = parse_qs(redirect_url.query)

    assert response.status_code == 302
    assert redirect_url.scheme == "https"
    assert redirect_url.netloc == "elevenidllc.com"
    assert query["auth_error_code"] == ["issuer_not_trusted"]
    assert "does not trust" in query["auth_error"][0]
    assert "did:web:elevenidllc.com:orgs:marty" in query["auth_error_detail"][0]


def test_build_credential_login_wallet_options_defaults_to_protocol_sprucekit_then_lissi(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_ANDROID_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_IOS_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_IOS_UNIVERSAL_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_ANDROID_PACKAGE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_SPRUCEKIT_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_SPRUCEKIT_IOS_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_PACKAGE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_LUCY_DEEP_LINK_TEMPLATE", raising=False)

    oid4vp_uri = (
        "openid4vp://authorize?"
        "client_id=decentralized_identifier%3Adid%3Aweb%3Averifier.example%3Aoid4vp&"
        "request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1"
    )
    options = _build_credential_login_wallet_options(
        oid4vp_uri=oid4vp_uri,
        request_uri=oid4vp_uri,
    )

    assert [option["id"] for option in options] == ["sprucekit", "lissi"]
    assert [option["label"] for option in options] == ["SpruceKit", "LISSI Wallet"]
    expected_client_ids = [
        "decentralized_identifier:did:web:verifier.example:oid4vp",
        "did:web:verifier.example:oid4vp",
    ]
    expected_request_uris = [
        "https://issuer.example/request/1",
        "https://issuer.example/request/1?compat=lissi",
    ]
    for option, expected_client_id, expected_request_uri in zip(
        options,
        expected_client_ids,
        expected_request_uris,
        strict=True,
    ):
        for link_name in ("href", "android_href", "ios_href"):
            link_query = parse_qs(urlparse(option[link_name]).query)
            assert link_query["client_id"] == [expected_client_id]
            assert link_query["request_uri"] == [expected_request_uri]

    assert "package=com.spruceid.mobilesdkexample" in options[0]["android_href"]
    assert "package=" not in options[1]["android_href"]


def test_lissi_wallet_option_matches_bare_did_request_object_client_id(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_IOS_DEEP_LINK_TEMPLATE", raising=False)
    oid4vp_uri = (
        "openid4vp://authorize?"
        "client_id=decentralized_identifier%3Adid%3Aweb%3Averifier.example%3Aoid4vp&"
        "request_uri=https%3A%2F%2Fverifier.example%2Frequest%2F1"
    )

    sprucekit, lissi = _build_credential_login_wallet_options(
        oid4vp_uri=oid4vp_uri,
        request_uri=oid4vp_uri,
    )
    sprucekit_query = parse_qs(urlparse(sprucekit["href"]).query)
    lissi_query = parse_qs(urlparse(lissi["href"]).query)
    sprucekit_android_query = parse_qs(urlparse(sprucekit["android_href"]).query)
    lissi_android_query = parse_qs(urlparse(lissi["android_href"]).query)

    assert sprucekit_query["client_id"] == [
        "decentralized_identifier:did:web:verifier.example:oid4vp",
    ]
    assert lissi_query["client_id"] == ["did:web:verifier.example:oid4vp"]
    assert sprucekit_android_query["client_id"] == sprucekit_query["client_id"]
    assert lissi_android_query["client_id"] == lissi_query["client_id"]
    assert lissi_query["request_uri"] == [
        "https://verifier.example/request/1?compat=lissi",
    ]


@pytest.mark.parametrize("request_uri_method", ["get", "post"])
def test_explicit_request_uri_method_survives_every_reconstructed_wallet_link(
    monkeypatch: pytest.MonkeyPatch,
    request_uri_method: str,
):
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_DEEP_LINK_TEMPLATE",
        "walletapp://authorize?request_uri={request_uri_encoded}",
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE",
        "intent://authorize?request_uri={request_uri_encoded}"
        "#Intent;scheme=openid4vp;{android_package_param}end",
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE",
        "https://wallet.example/openid4vp?request_uri={request_uri_encoded}",
    )
    client_id = "decentralized_identifier:did:web:verifier.example:oid4vp"
    oid4vp_uri = (
        "openid4vp://authorize?"
        f"client_id={quote(client_id, safe='')}&"
        "request_uri=https%3A%2F%2Fverifier.example%2Frequest%2F1&"
        f"request_uri_method={request_uri_method}"
    )

    options = _build_credential_login_wallet_options(
        oid4vp_uri=oid4vp_uri,
        request_uri=oid4vp_uri,
    )

    assert [option["id"] for option in options] == ["sprucekit", "lissi"]
    for option in options:
        for link_name in ("href", "android_href", "ios_href"):
            query_pairs = parse_qs(urlparse(option[link_name]).query)
            assert query_pairs["request_uri_method"] == [request_uri_method]
    for link_name in ("href", "android_href", "ios_href"):
        query_pairs = parse_qs(urlparse(options[0][link_name]).query)
        assert query_pairs == {
            "request_uri": ["https://verifier.example/request/1"],
            "client_id": [client_id],
            "request_uri_method": [request_uri_method],
        }


def test_reconstructed_wallet_link_collapses_stale_protocol_duplicates(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE",
        "intent://authorize?request_uri=stale&request_uri=other&"
        "client_id=wrong&client_id=also-wrong&request_uri_method=get"
        "#Intent;scheme=openid4vp;end",
    )
    client_id = "decentralized_identifier:did:web:verifier.example:oid4vp"
    oid4vp_uri = (
        "openid4vp://authorize?"
        f"client_id={quote(client_id, safe='')}&"
        "request_uri=https%3A%2F%2Fverifier.example%2Frequest%2F1&"
        "request_uri_method=post"
    )

    [sprucekit, *_] = _build_credential_login_wallet_options(
        oid4vp_uri=oid4vp_uri,
        request_uri=oid4vp_uri,
    )
    query_pairs = parse_qs(urlparse(sprucekit["android_href"]).query)

    assert query_pairs == {
        "request_uri": ["https://verifier.example/request/1"],
        "client_id": [client_id],
        "request_uri_method": ["post"],
    }


def test_omitted_outer_parameters_remove_stale_values_from_custom_links(
    monkeypatch: pytest.MonkeyPatch,
):
    stale_query = (
        "request_uri={request_uri_encoded}&client_id=stale-one&client_id=stale-two&"
        "request_uri_method=post&request_uri_method=get"
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_DEEP_LINK_TEMPLATE",
        f"walletapp://authorize?{stale_query}",
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE",
        f"intent://authorize?{stale_query}#Intent;scheme=openid4vp;end",
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE",
        f"https://wallet.example/openid4vp?{stale_query}",
    )
    oid4vp_uri = (
        "openid4vp://authorize?"
        "request_uri=https%3A%2F%2Fverifier.example%2Frequest%2F1"
    )

    options = _build_credential_login_wallet_options(
        oid4vp_uri=oid4vp_uri,
        request_uri=oid4vp_uri,
    )

    assert [option["id"] for option in options] == ["sprucekit"]
    for link_name in ("href", "android_href", "ios_href"):
        query_pairs = parse_qs(urlparse(options[0][link_name]).query)
        assert query_pairs == {
            "request_uri": ["https://verifier.example/request/1"],
        }


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ("client_id=did%3Aweb%3Averifier.example", "request_uri exactly once"),
        (
            "request_uri=https%3A%2F%2Fverifier.example%2Fone&"
            "request_uri=https%3A%2F%2Fverifier.example%2Ftwo",
            "request_uri exactly once",
        ),
        (
            "request_uri=https%3A%2F%2Fverifier.example%2Fone&"
            "client_id=did%3Aweb%3Aone&client_id=did%3Aweb%3Atwo",
            "client_id at most once",
        ),
        (
            "request_uri=https%3A%2F%2Fverifier.example%2Fone&"
            "request_uri_method=post&request_uri_method=post",
            "request_uri_method at most once",
        ),
        (
            "request_uri=https%3A%2F%2Fverifier.example%2Fone&"
            "request_uri_method=",
            "must equal 'get' or 'post'",
        ),
        (
            "request_uri=https%3A%2F%2Fverifier.example%2Fone&"
            "request_uri_method=GET",
            "must equal 'get' or 'post'",
        ),
        (
            "request_uri=https%3A%2F%2Fverifier.example%2Fone&"
            "request_uri_method=put",
            "must equal 'get' or 'post'",
        ),
    ],
)
def test_wallet_links_reject_ambiguous_or_unsupported_outer_parameters(
    query: str,
    message: str,
):
    with pytest.raises(ValueError, match=message):
        _build_credential_login_wallet_options(
            oid4vp_uri=f"openid4vp://authorize?{query}",
            request_uri=f"openid4vp://authorize?{query}",
        )


def test_wallet_links_reject_request_uri_disagreement():
    oid4vp_uri = (
        "openid4vp://authorize?"
        "request_uri=https%3A%2F%2Fverifier.example%2Frequest%2Fexpected"
    )

    with pytest.raises(ValueError, match="must match the validated outer request"):
        _build_credential_login_wallet_options(
            oid4vp_uri=oid4vp_uri,
            request_uri="https://verifier.example/request/different",
        )


@pytest.mark.parametrize(
    "client_id",
    [
        "https://verifier.example/v1/flows/instances/flow-1/submit",
        "x509_hash:certificate-thumbprint",
    ],
)
def test_lissi_wallet_option_is_hidden_for_non_did_client_identity(
    monkeypatch: pytest.MonkeyPatch,
    client_id: str,
):
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_IOS_DEEP_LINK_TEMPLATE", raising=False)
    oid4vp_uri = (
        "openid4vp://authorize?"
        f"client_id={quote(client_id, safe='')}&"
        "request_uri=https%3A%2F%2Fverifier.example%2Frequest%2F1"
    )

    options = _build_credential_login_wallet_options(
        oid4vp_uri=oid4vp_uri,
        request_uri=oid4vp_uri,
    )

    assert [option["id"] for option in options] == ["sprucekit"]
    assert parse_qs(urlparse(options[0]["href"]).query)["client_id"] == [client_id]


@pytest.mark.parametrize(
    ("environment_name", "template", "link_name"),
    [
        (
            "CREDENTIAL_LOGIN_SPRUCEKIT_DEEP_LINK_TEMPLATE",
            "walletapp://authorize?request_uri={request_uri_encoded}",
            "href",
        ),
        (
            "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE",
            "https://wallet.example/openid4vp?request_uri={request_uri_encoded}",
            "ios_href",
        ),
    ],
)
def test_legacy_custom_wallet_template_preserves_required_client_id(
    monkeypatch: pytest.MonkeyPatch,
    environment_name: str,
    template: str,
    link_name: str,
):
    monkeypatch.setenv(environment_name, template)
    client_id = "decentralized_identifier:did:web:verifier.example:oid4vp"
    oid4vp_uri = (
        "openid4vp://authorize?"
        f"client_id={quote(client_id, safe='')}&"
        "request_uri=https%3A%2F%2Fverifier.example%2Frequest%2F1"
    )

    options = _build_credential_login_wallet_options(
        oid4vp_uri=oid4vp_uri,
        request_uri=oid4vp_uri,
    )
    rendered_query = parse_qs(urlparse(options[0][link_name]).query)

    assert rendered_query["client_id"] == [client_id]
    assert rendered_query["request_uri"] == ["https://verifier.example/request/1"]


def test_build_credential_login_wallet_options_honors_sprucekit_template_override(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_DEEP_LINK_TEMPLATE",
        "walletapp://authorize?request_uri={request_uri}",
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE",
        "intent://custom?request_uri={request_uri_encoded}#Intent;scheme=openid4vp;end",
    )
    monkeypatch.setenv("CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_PACKAGE", "com.example.wallet")

    options = _build_credential_login_wallet_options(
        oid4vp_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
        request_uri="https://issuer.example/request/1",
    )

    assert parse_qs(urlparse(options[0]["href"]).query) == {
        "request_uri": ["https://issuer.example/request/1"],
    }
    assert options[0]["android_href"] == "intent://custom?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1#Intent;scheme=openid4vp;end"


def test_build_credential_login_wallet_options_renders_android_package_placeholder(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE",
        "intent://authorize?request_uri={request_uri_encoded}#Intent;scheme=openid4vp;{android_package_param}end",
    )
    monkeypatch.setenv("CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_PACKAGE", "com.example.wallet")

    options = _build_credential_login_wallet_options(
        oid4vp_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
        request_uri="https://issuer.example/request/1",
    )

    assert options[0]["android_href"] == "intent://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1#Intent;scheme=openid4vp;package=com.example.wallet;end"


def test_build_credential_login_wallet_options_honors_ios_universal_link_templates(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_LISSI_IOS_DEEP_LINK_TEMPLATE",
        "lissi://unused?request_uri={request_uri_encoded}",
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_LISSI_IOS_UNIVERSAL_LINK_TEMPLATE",
        "https://lissi.example/openid4vp?request_uri={request_uri_encoded}",
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_DEEP_LINK_TEMPLATE",
        "spruceid://unused?request_uri={request_uri_encoded}",
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE",
        "https://spruceid.example/openid4vp?request_uri={request_uri_encoded}",
    )

    oid4vp_uri = (
        "openid4vp://authorize?"
        "client_id=decentralized_identifier%3Adid%3Aweb%3Averifier.example%3Aoid4vp&"
        "request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1"
    )
    options = _build_credential_login_wallet_options(
        oid4vp_uri=oid4vp_uri,
        request_uri=oid4vp_uri,
    )

    sprucekit_query = parse_qs(urlparse(options[0]["ios_href"]).query)
    lissi_query = parse_qs(urlparse(options[1]["ios_href"]).query)
    assert sprucekit_query == {
        "request_uri": ["https://issuer.example/request/1"],
        "client_id": ["decentralized_identifier:did:web:verifier.example:oid4vp"],
    }
    assert lissi_query == {
        "request_uri": ["https://issuer.example/request/1?compat=lissi"],
        "client_id": ["did:web:verifier.example:oid4vp"],
    }


def test_render_credential_login_page_includes_wallet_selector():
    oid4vp_uri = (
        "openid4vp://authorize?"
        "client_id=decentralized_identifier%3Adid%3Aweb%3Averifier.example%3Aoid4vp&"
        "request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1"
    )
    wallet_options = _build_credential_login_wallet_options(
        oid4vp_uri=oid4vp_uri,
        request_uri=oid4vp_uri,
    )
    html = _render_credential_login_page(
        nonce="nonce-123",
        flow_instance_id="flow-123",
        qr_encoded="openid4vp%3A%2F%2Fauthorize",
        oid4vp_uri=oid4vp_uri,
        request_uri=oid4vp_uri,
    )

    assert 'Select wallet app' in html
    assert '/v1/auth/credential-login/assets/styles.css?v=' in html
    assert '/v1/auth/credential-login/assets/app.js?v=' in html
    assert 'id="platform-select"' in html
    assert 'Auto-detect' in html
    assert 'Android' in html
    assert 'iOS' in html
    assert 'value="lissi"' in html
    assert 'value="sprucekit"' in html
    assert html.index('value="sprucekit"') < html.index('value="lissi"')
    for wallet_option in wallet_options:
        assert f'data-link="{wallet_option["href"].replace("&", "&amp;")}"' in html
        assert f'data-android-link="{wallet_option["android_href"].replace("&", "&amp;")}"' in html
        assert f'data-ios-link="{wallet_option["ios_href"].replace("&", "&amp;")}"' in html
    assert f'href="{wallet_options[0]["href"].replace("&", "&amp;")}"' in html
    assert 'spruceid://credential-offer' not in html
    assert 'lissi://openid4vp' not in html
    assert 'id="wallet-select"' in html
    assert 'Open wallet' in html
    assert 'Open Lucy' not in html
    assert 'data-dc-api-request-url="/v1/flows/instances/flow-123/request?transport=dc_api"' in html
    assert 'data-dc-api-submit-url="/v1/flows/instances/flow-123/submit/dc-api"' in html
    assert 'data-dc-api-protocol="openid4vp-v1-signed"' in html
    assert html.index('id="wallet-select"') < html.index('id="mobile-section"')


@pytest.mark.asyncio
async def test_credential_login_returns_friendly_html_when_policy_is_missing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(http_adapter, "_credential_login_policy_id", "")
    monkeypatch.setattr(http_adapter, "_ui_base_url", "https://elevenidllc.com")

    response = await http_adapter.credential_login(
        _build_request(
            referer=(
                "https://elevenidllc.com/realms/11id/login-actions/authenticate"
                "?session_code=test"
            )
        )
    )

    body = response.body.decode("utf-8")

    assert response.status_code == 503
    assert response.headers["Cache-Control"] == "no-store, max-age=0"
    assert "Open Badge sign-in is not configured yet" in body
    assert "CREDENTIAL_LOGIN_POLICY_ID" in body
    assert "50000000-0000-0000-0000-000000000004" in body
    assert "Back to sign in" in body


def test_credential_login_js_persists_wallet_and_platform_preferences():
    js = _CREDENTIAL_LOGIN_JS
    assert "marty.credential_login.wallet" in js
    assert "marty.credential_login.platform" in js
    assert "restoreWalletPreference" in js
    assert "persistPlatformPreference" in js
    assert "renderVerificationFailure" in js
    assert "escapeHtml" in js


def test_credential_login_css_styles_status_detail():
    assert ".status-detail" in _CREDENTIAL_LOGIN_CSS


def test_build_credential_login_wallet_options_uses_ios_universal_link_when_env_set(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE",
        "https://wallet.spruceid.example/openid4vp?request_uri={request_uri_encoded}",
    )

    options = _build_credential_login_wallet_options(
        oid4vp_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
        request_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
    )

    spruce = options[0]
    assert spruce["id"] == "sprucekit"
    assert spruce["ios_href"] == (
        "https://wallet.spruceid.example/openid4vp?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1"
    )
    # Generic + Android still use the protocol scheme so that other transports stay intact.
    assert spruce["href"].startswith("openid4vp://")
    assert spruce["android_href"].startswith("intent://")
