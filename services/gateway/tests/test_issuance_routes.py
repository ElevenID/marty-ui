"""Tests for gateway issuance route header injection (X-Issuer-Did)."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from gateway.routes import issuance


def _build_request(
    redis_client: AsyncMock | None = None,
    session_org_id: str | None = "org_123",
) -> object:
    """Minimal request stub for gateway issuance helpers."""
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/v1/issuance",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("testclient", 1234),
        "server": ("testserver", 80),
        "state": {},
        "app": SimpleNamespace(state=SimpleNamespace(redis_client=redis_client)),
    }

    from starlette.requests import Request

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive)
    request.state.session_organization_id = session_org_id
    return request


@pytest.mark.asyncio
async def test_resolve_issuer_did_returns_active_profile_did(monkeypatch: pytest.MonkeyPatch):
    """_resolve_issuer_did should return the DID from the first active profile."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    profiles_doc = json.dumps({
        "profiles": [
            {
                "id": "ip-1",
                "name": "Draft Profile",
                "issuer_did": "did:web:draft",
                "signing_service_id": "svc-1",
                "status": "draft",
            },
            {
                "id": "ip-2",
                "name": "Active Profile",
                "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
                "signing_service_id": "svc-2",
                "status": "active",
            },
        ]
    })

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=profiles_doc)

    request = _build_request(redis_client=redis_mock, session_org_id="org_acme")
    result = await issuance._resolve_issuer_did(request, "org_acme")

    assert result == "did:web:beta.elevenidllc.com:orgs:acme"

    identity = await issuance._resolve_issuer_identity(request, "org_acme")
    assert identity == {
        "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
        "signing_service_id": "svc-2",
        "signing_key_reference": "",
        "verification_method_id": "",
        "key_purpose": "vc_jwt_issuer",
        "algorithm": "",
    }


@pytest.mark.asyncio
async def test_resolve_issuer_identity_prefers_format_scoped_profile(monkeypatch: pytest.MonkeyPatch):
    """_resolve_issuer_identity should not inject a VC profile for mDoc issuance."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    profiles_doc = json.dumps({
        "profiles": [
            {
                "id": "ip-vc",
                "name": "VC Profile",
                "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
                "signing_service_id": "svc-vc",
                "signing_key_reference": "cred-issuer-acme-es256",
                "verification_method_id": "did:web:beta.elevenidllc.com:orgs:acme#cred-issuer-acme-es256",
                "key_purpose": "vc_jwt_issuer",
                "status": "active",
            },
            {
                "id": "ip-mdoc",
                "name": "mDoc Profile",
                "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
                "signing_service_id": "svc-mdoc",
                "signing_key_reference": "cred-dsc-acme-primary",
                "verification_method_id": "did:web:beta.elevenidllc.com:orgs:acme#cred-dsc-acme-primary",
                "key_purpose": "mdoc_dsc",
                "status": "active",
            },
        ]
    })

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=profiles_doc)

    request = _build_request(redis_client=redis_mock, session_org_id="org_acme")
    identity = await issuance._resolve_issuer_identity(
        request,
        "org_acme",
        credential_format="mso_mdoc",
    )

    assert identity["signing_service_id"] == "svc-mdoc"
    assert identity["signing_key_reference"] == "cred-dsc-acme-primary"
    assert identity["verification_method_id"] == "did:web:beta.elevenidllc.com:orgs:acme#cred-dsc-acme-primary"
    assert identity["key_purpose"] == "mdoc_dsc"


@pytest.mark.asyncio
async def test_resolve_issuer_did_returns_none_when_no_active(monkeypatch: pytest.MonkeyPatch):
    """_resolve_issuer_did should return None when no active profile exists."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    profiles_doc = json.dumps({
        "profiles": [
            {"id": "ip-1", "issuer_did": "did:web:x", "status": "draft"},
        ]
    })

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=profiles_doc)

    request = _build_request(redis_client=redis_mock, session_org_id="org_x")
    result = await issuance._resolve_issuer_did(request, "org_x")

    assert result is None


@pytest.mark.asyncio
async def test_resolve_issuer_did_returns_none_when_no_profiles(monkeypatch: pytest.MonkeyPatch):
    """_resolve_issuer_did should return None when no profiles exist at all."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)

    request = _build_request(redis_client=redis_mock, session_org_id="org_empty")
    result = await issuance._resolve_issuer_did(request, "org_empty")

    assert result is None
