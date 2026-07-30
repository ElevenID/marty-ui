from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from services.credential_template import main as credential_template


ISSUER_DID = "did:web:issuer.example:orgs:org-1"
_require_active_issuer_profile = credential_template._require_active_issuer_profile


def _resolved_identity(**updates: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": True,
        "organization_id": "org-1",
        "issuer_did": ISSUER_DID,
        "verification_method_id": f"{ISSUER_DID}#credential-key",
        "issuer_profile": {
            "id": "profile-1",
            "status": "active",
            "issuer_did": ISSUER_DID,
            "signing_service_id": "managed-openbao",
            "signing_key_reference": "credential-key",
            "key_purpose": "vc_jwt_issuer",
            "algorithm": "ES256",
        },
        "signing_service": {
            "id": "managed-openbao",
            "key_reference": "credential-key",
            "algorithm": "ES256",
        },
    }
    payload.update(updates)
    return payload


class _FakeAsyncClient:
    def __init__(
        self,
        response: httpx.Response | None = None,
        error: httpx.HTTPError | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.request: dict[str, Any] | None = None

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def get(
        self,
        url: str,
        *,
        params: dict[str, Any],
        headers: dict[str, str],
    ) -> httpx.Response:
        self.request = {"url": url, "params": params, "headers": headers}
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response


def _install_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status_code: int = 200,
    payload: dict[str, Any] | None = None,
    error: httpx.HTTPError | None = None,
) -> _FakeAsyncClient:
    response = (
        httpx.Response(
            status_code,
            json=payload if payload is not None else _resolved_identity(),
            request=httpx.Request("GET", "http://gateway/internal/signing-keys"),
        )
        if error is None
        else None
    )
    client = _FakeAsyncClient(response=response, error=error)
    monkeypatch.setattr(
        credential_template.httpx,
        "AsyncClient",
        lambda **_kwargs: client,
    )
    return client


def _request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(request_id="request-1"))


@pytest.mark.asyncio
async def test_resolves_did_without_public_profile_selector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SIGNING_KEYS_INTERNAL_URL",
        "http://gateway:8000/internal/signing-keys/",
    )
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "service-secret")
    client = _install_client(monkeypatch)

    payload = await _require_active_issuer_profile(
        _request(),
        organization_id="org-1",
        issuer_did=ISSUER_DID,
        credential_format="sd_jwt_vc",
        algorithm="ES256",
    )

    assert payload["issuer_profile"]["id"] == "profile-1"
    assert client.request == {
        "url": "http://gateway:8000/internal/signing-keys/resolve-issuer-did",
        "params": {
            "organization_id": "org-1",
            "issuer_did": ISSUER_DID,
            "key_purpose": "vc_jwt_issuer",
            "credential_format": "dc+sd-jwt",
            "algorithm": "ES256",
        },
        "headers": {
            "X-API-Key": "service-secret",
            "X-Request-ID": "request-1",
        },
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("sd_jwt_vc", "dc+sd-jwt"),
        ("w3c_vcdm_v2_sd_jwt", "dc+sd-jwt"),
        ("dc+sd-jwt", "dc+sd-jwt"),
        ("jwt_vc", "jwt_vc_json"),
        ("w3c_vcdm_v2_jwt_vc", "jwt_vc_json"),
        ("mdoc", "mso_mdoc"),
        ("mso_mdoc", "mso_mdoc"),
        ("ldp_vc", "ldp_vc"),
        ("zk_mdoc", "zk_mdoc"),
        (None, None),
    ],
)
def test_signing_format_uses_managed_service_capability_names(
    value: str | None,
    expected: str | None,
) -> None:
    assert credential_template.payload_format_to_signing_wire(value) == expected


def test_public_template_request_rejects_profile_selector() -> None:
    with pytest.raises(ValueError, match="issuer_profile_id"):
        credential_template.CreateCredentialTemplateRequest.model_validate(
            {"issuer_profile_id": "attacker-selected-profile"}
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "expected_status", "expected_detail"),
    [
        (404, 422, "not an active managed-custody issuer identity"),
        (409, 409, "does not resolve to exactly one active issuer profile"),
        (422, 422, "could not be resolved"),
        (500, 503, "resolution failed with status 500"),
    ],
)
async def test_resolution_failures_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    expected_status: int,
    expected_detail: str,
) -> None:
    _install_client(monkeypatch, status_code=status_code, payload={"detail": "private"})

    with pytest.raises(credential_template.HTTPException) as exc_info:
        await _require_active_issuer_profile(
            _request(),
            organization_id="org-1",
            issuer_did=ISSUER_DID,
        )

    assert exc_info.value.status_code == expected_status
    assert expected_detail in exc_info.value.detail
    assert "private" not in exc_info.value.detail


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        _resolved_identity(organization_id="org-other"),
        _resolved_identity(issuer_did="did:web:issuer.example:orgs:org-other"),
        _resolved_identity(issuer_profile={}),
        _resolved_identity(
            issuer_profile={
                **_resolved_identity()["issuer_profile"],
                "status": "inactive",
            }
        ),
        _resolved_identity(
            issuer_profile={
                **_resolved_identity()["issuer_profile"],
                "signing_service_id": "",
                "signing_key_reference": "",
            },
            signing_service={},
        ),
    ],
)
async def test_incomplete_or_cross_tenant_identity_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, Any],
) -> None:
    _install_client(monkeypatch, payload=payload)

    with pytest.raises(credential_template.HTTPException) as exc_info:
        await _require_active_issuer_profile(
            _request(),
            organization_id="org-1",
            issuer_did=ISSUER_DID,
        )

    assert exc_info.value.status_code == 422
    assert "complete organization-owned" in exc_info.value.detail


@pytest.mark.asyncio
async def test_resolution_outage_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_client(
        monkeypatch,
        error=httpx.ConnectError("gateway unavailable"),
    )

    with pytest.raises(credential_template.HTTPException) as exc_info:
        await _require_active_issuer_profile(
            _request(),
            organization_id="org-1",
            issuer_did=ISSUER_DID,
        )

    assert exc_info.value.status_code == 503
    assert "Unable to resolve issuer_did" in exc_info.value.detail
