from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

from gateway.routes import signing_keys


def _format_iso_datetime(dt: datetime) -> str:
    """Format datetime to ISO string with Z suffix (UTC)."""
    iso_str = dt.isoformat()
    if iso_str.endswith("+00:00"):
        iso_str = iso_str[:-6]  # Remove +00:00
    return iso_str + "Z"


def _build_request(
    session_org_id: str | None = "org_123",
    redis_client: AsyncMock | None = None,
) -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/v1/signing-keys",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("testclient", 1234),
        "server": ("testserver", 80),
        "state": {},
        "app": SimpleNamespace(state=SimpleNamespace(redis_client=redis_client)),
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive)
    request.state.session_organization_id = session_org_id
    return request


def _http_status_error(status_code: int, payload: dict, url: str = "http://openbao.test/v1/transit/keys/test") -> httpx.HTTPStatusError:
    request = httpx.Request("POST", url)
    response = httpx.Response(status_code, json=payload, request=request)
    return httpx.HTTPStatusError("request failed", request=request, response=response)


@pytest.mark.asyncio
async def test_list_signing_keys_uses_session_org_fallback(monkeypatch: pytest.MonkeyPatch):
    request = _build_request("org_fallback")
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")
    monkeypatch.setenv("HSM_PROVIDER", "openbao")

    async def fake_snapshot(resolved_org_id: str | None):
        assert resolved_org_id == "org_fallback"
        return {
            "keys": [
                {
                    "id": "cred-issuer-marty-es256",
                    "name": "Marty ES256 issuer key",
                    "algorithm": "ES256",
                    "status": "active",
                }
            ],
            "provider_metadata": {
                "provider": "openbao",
                "status": "configured",
                "managed_by": "OpenBao transit service",
                "supports_rotation": False,
                "supports_upload": False,
                "supports_delete": False,
                "key_count": 1,
            },
            "config": {
                "hsm_enabled": True,
                "hsm_settings": {
                    "provider": "openbao",
                    "service_url": "http://openbao:8200",
                },
                "vault_enabled": False,
                "vault_settings": {},
            },
            "message": None,
        }

    monkeypatch.setattr(signing_keys, "_load_signing_key_snapshot", fake_snapshot)

    response = await signing_keys.list_signing_keys(request=request, organization_id=None)

    assert response.status_code == 200
    assert b'"cred-issuer-marty-es256"' in response.body
    assert b'"provider":"openbao"' in response.body
    assert b'"status":"configured"' in response.body
    assert b'"public_domain":"beta.elevenidllc.com"' in response.body


@pytest.mark.asyncio
async def test_get_signing_key_config_returns_service_registry(monkeypatch: pytest.MonkeyPatch):
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(
        return_value=json.dumps(
            {
                "default_service_id": "svc-aws",
                "services": [
                    {
                        "id": "svc-aws",
                        "name": "AWS signing key",
                        "service_type": "aws-kms",
                        "provider": "aws",
                        "provider_label": "AWS KMS",
                        "protocol": "aws-kms",
                        "region": "us-west-2",
                        "key_reference": "arn:aws:kms:example",
                        "algorithms": ["ES256"],
                    }
                ],
            }
        )
    )
    request = _build_request("org_fallback", redis_client=redis_mock)

    async def fake_snapshot(resolved_org_id: str | None):
        assert resolved_org_id == "org_fallback"
        return {
            "keys": [],
            "provider_metadata": {
                "provider": "openbao",
                "status": "configured",
                "managed_by": "OpenBao transit service",
                "supports_rotation": False,
                "supports_upload": False,
                "supports_delete": False,
                "key_count": 4,
            },
            "config": {
                "hsm_enabled": True,
                "hsm_settings": {
                    "provider": "openbao",
                    "service_url": "http://openbao:8200",
                    "mount": "transit",
                    "signing_key_count": 4,
                },
                "vault_enabled": False,
                "vault_settings": {},
            },
            "message": None,
        }

    monkeypatch.setattr(signing_keys, "_load_signing_key_snapshot", fake_snapshot)

    response = await signing_keys.get_signing_key_config(request=request, organization_id=None)

    assert response.status_code == 200
    assert b'"service_type_catalog"' in response.body
    assert b'"services"' in response.body
    assert b'"managed-openbao-transit"' in response.body
    assert b'"svc-aws"' in response.body
    assert b'"default_service_id":"svc-aws"' in response.body
    assert b'"supports_native_key_management":false' in response.body


@pytest.mark.asyncio
async def test_update_signing_key_config_persists_registered_services(monkeypatch: pytest.MonkeyPatch):
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.set = AsyncMock()
    request = _build_request("org_fallback", redis_client=redis_mock)

    async def fake_snapshot(resolved_org_id: str | None):
        return {
            "keys": [],
            "provider_metadata": {
                "provider": "openbao",
                "status": "configured",
                "managed_by": "OpenBao transit service",
                "supports_rotation": False,
                "supports_upload": False,
                "supports_delete": False,
                "key_count": 1,
            },
            "config": {
                "hsm_enabled": True,
                "hsm_settings": {
                    "provider": "openbao",
                    "service_url": "http://openbao:8200",
                    "mount": "transit",
                    "signing_key_count": 1,
                },
                "vault_enabled": False,
                "vault_settings": {},
            },
            "message": None,
        }

    monkeypatch.setattr(signing_keys, "_load_signing_key_snapshot", fake_snapshot)

    response = await signing_keys.update_signing_key_config(
        request=request,
        organization_id=None,
        body={
            "services": [
                {
                    "id": "managed-openbao-transit",
                    "name": "Marty managed OpenBao transit",
                    "managed": True,
                    "read_only": True,
                },
                {
                    "id": "svc-custom",
                    "name": "Customer signer",
                    "service_type": "custom-transit-compatible",
                    "endpoint": "https://signer.example.com",
                    "mount": "transit",
                    "auth_mode": "mtls",
                    "key_reference": "cred-issuer-prod",
                    "algorithms": ["ES256", "EdDSA"],
                },
            ],
            "default_service_id": "svc-custom",
        },
    )

    assert response.status_code == 200
    redis_mock.set.assert_awaited_once()
    saved_payload = json.loads(redis_mock.set.await_args.args[1])
    assert saved_payload["default_service_id"] == "svc-custom"
    assert len(saved_payload["services"]) == 1
    service = saved_payload["services"][0]
    assert service["id"] == "svc-custom"
    assert service["service_type"] == "custom-transit-compatible"
    assert service["provider"] == "custom"
    assert service["endpoint"] == "https://signer.example.com"
    assert service["key_reference"] == "cred-issuer-prod"
    assert service["algorithms"] == ["ES256", "EdDSA"]
    assert service["rotation_policy"] == {
        "rotation_interval_days": 0,
        "overlap_days": 0,
        "auto_publish": False,
    }
    assert service["discovered_capabilities"] == {}
    assert service["country_code"] == ""
    assert service["authority_name"] == ""
    assert b'"svc-custom"' in response.body
    assert b'"managed-openbao-transit"' in response.body


@pytest.mark.asyncio
async def test_validate_signing_key_service_returns_gateway_checks(monkeypatch: pytest.MonkeyPatch):
    async def fake_validate(body: dict):
        assert body["service_type"] == "custom-transit-compatible"
        assert body["endpoint"] == "https://signer.example.com"
        return {
            "ok": True,
            "checks": [
                {
                    "name": "Provider connectivity",
                    "status": "pass",
                    "detail": "Connected to signer endpoint.",
                    "source": "live",
                }
            ],
            "validated_at": "2026-04-16T00:00:00+00:00",
        }

    monkeypatch.setattr(signing_keys, "_run_service_validation", fake_validate)
    request = _build_request("org_123")

    response = await signing_keys.validate_signing_key_service(
        request=request,
        body={
            "service_type": "custom-transit-compatible",
            "endpoint": "https://signer.example.com",
            "mount": "transit",
            "auth_mode": "token",
            "auth_reference": "vault-token",
            "key_reference": "cred-issuer-prod",
            "algorithms": ["ES256"],
        }
    )

    assert response.status_code == 200
    assert b'"ok":true' in response.body
    assert b'"Provider connectivity"' in response.body
    assert b'"source":"live"' in response.body


@pytest.mark.asyncio
async def test_validate_signing_key_service_marks_missing_key_reference_as_failure():
    request = _build_request("org_123")
    response = await signing_keys.validate_signing_key_service(
        request=request,
        body={
            "service_type": "aws-kms",
            "auth_mode": "iam_role",
            "algorithms": ["ES256"],
        }
    )

    assert response.status_code == 200
    assert b'"ok":false' in response.body
    assert b'"name":"Key reference"' in response.body
    assert b'"status":"fail"' in response.body


@pytest.mark.asyncio
async def test_validate_signing_key_service_checks_provider_key_reference_format():
    request = _build_request("org_123")
    response = await signing_keys.validate_signing_key_service(
        request=request,
        body={
            "service_type": "aws-kms",
            "provider": "aws",
            "auth_mode": "iam_role",
            "key_reference": "not-an-arn",
            "algorithms": ["ES256"],
        }
    )

    assert response.status_code == 200
    assert b'"ok":false' in response.body
    assert b'"name":"Provider key format"' in response.body
    assert b'AWS key reference should be a key ARN' in response.body


@pytest.mark.asyncio
async def test_validate_signing_key_service_uses_cloud_validator_bridge(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(signing_keys, "_cloud_validator_url", lambda provider: "http://validator" if provider == "aws" else "")
    request = _build_request("org_123")

    async def fake_probe(payload: dict, validator_url: str):
        assert payload["provider"] == "aws"
        assert payload["key_reference"] == "arn:aws:kms:us-west-2:123456789012:key/abc123"
        assert validator_url == "http://validator"
        return True, None

    monkeypatch.setattr(signing_keys, "_run_cloud_validator_probe", fake_probe)

    response = await signing_keys.validate_signing_key_service(
        request=request,
        body={
            "service_type": "aws-kms",
            "provider": "aws",
            "auth_mode": "iam_role",
            "key_reference": "arn:aws:kms:us-west-2:123456789012:key/abc123",
            "algorithms": ["ES256"],
        }
    )

    assert response.status_code == 200
    assert b'"ok":true' in response.body
    assert b'"Connected to provider validator bridge."' in response.body
    assert b'"Validator bridge completed a remote sign-capability probe."' in response.body


@pytest.mark.asyncio
async def test_validate_signing_key_service_uses_adapter_when_no_validator(monkeypatch: pytest.MonkeyPatch):
    class FakeAdapter:
        async def verify_connection(self, payload: dict):
            assert payload["service_type"] == "aws-kms"
            return SimpleNamespace(
                ok=True,
                checks=[
                    {
                        "name": "Connectivity",
                        "status": "pass",
                        "detail": "Adapter reached AWS.",
                        "source": "adapter",
                    }
                ],
                error=None,
            )

    monkeypatch.setattr(signing_keys, "_cloud_validator_url", lambda provider: "")
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda payload: FakeAdapter())
    request = _build_request("org_123")

    response = await signing_keys.validate_signing_key_service(
        request=request,
        body={
            "service_type": "aws-kms",
            "provider": "aws",
            "auth_mode": "iam_role",
            "key_reference": "arn:aws:kms:us-west-2:123456789012:key/abc123",
            "algorithms": ["ES256"],
        }
    )

    assert response.status_code == 200
    assert b'"ok":true' in response.body
    assert b'"Adapter reached AWS."' in response.body
    assert b'"source":"adapter"' in response.body


@pytest.mark.asyncio
async def test_validate_signing_key_service_falls_back_when_no_validator_or_adapter(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(signing_keys, "_cloud_validator_url", lambda provider: "")
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda payload: None)
    request = _build_request("org_123")

    response = await signing_keys.validate_signing_key_service(
        request=request,
        body={
            "service_type": "aws-kms",
            "provider": "aws",
            "auth_mode": "iam_role",
            "key_reference": "arn:aws:kms:us-west-2:123456789012:key/abc123",
            "algorithms": ["ES256"],
        }
    )

    assert response.status_code == 200
    assert b'"No aws validator bridge is configured' in response.body
    assert b'"Gateway could not run a live sign test for this provider type."' in response.body


# =============================================================================
# GAP-002 / GAP-007 — key purpose routing, capabilities, resolver
# =============================================================================


def test_normalize_registered_service_persists_key_purposes_and_formats():
    """_normalize_registered_service should store key_purposes and derive credential_formats."""
    result = signing_keys._normalize_registered_service(
        {
            "id": "svc-mdoc",
            "name": "mdoc DSC",
            "service_type": "aws-kms",
            "provider": "aws",
            "auth_mode": "iam_role",
            "key_reference": "arn:aws:kms:us-east-1:000000000000:key/aaaa",
            "algorithms": ["ES256"],
            "key_purposes": ["mdoc_dsc"],
        }
    )
    assert result is not None
    assert result["key_purposes"] == ["mdoc_dsc"]
    # credential_formats derived from mdoc_dsc purpose
    assert "mso_mdoc" in result["credential_formats"]
    assert "zk_mdoc" in result["credential_formats"]


def test_normalize_registered_service_explicit_credential_formats():
    """Explicit credential_formats should be stored as-is."""
    result = signing_keys._normalize_registered_service(
        {
            "id": "svc-jwt",
            "name": "JWT issuer",
            "service_type": "openbao-transit",
            "key_reference": "cred-issuer-jwt",
            "algorithms": ["RS256"],
            "key_purposes": ["vc_jwt_issuer"],
            "credential_formats": ["jwt_vc_json"],
        }
    )
    assert result is not None
    assert result["credential_formats"] == ["jwt_vc_json"]


def test_normalize_registered_service_aws_capabilities():
    """AWS KMS service should have DER signature encoding and hardware_attestation=True."""
    result = signing_keys._normalize_registered_service(
        {
            "id": "svc-aws",
            "service_type": "aws-kms",
            "provider": "aws",
            "auth_mode": "iam_role",
            "key_reference": "arn:aws:kms:us-east-1:000000000000:key/aaaa",
            "algorithms": ["ES256"],
        }
    )
    assert result is not None
    assert result["signature_encoding"] == "der"
    assert result["capabilities"]["hardware_attestation"] is True
    assert result["capabilities"]["public_key_export"] is True
    assert "ES256" in result["capabilities"]["supported_algorithms"]


def test_normalize_registered_service_openbao_capabilities():
    """OpenBao service should advertise DER ECDSA signatures and no hardware attestation."""
    result = signing_keys._normalize_registered_service(
        {
            "id": "svc-bao",
            "service_type": "openbao-transit",
            "key_reference": "cred-issuer",
            "algorithms": ["ES256"],
        }
    )
    assert result is not None
    assert result["signature_encoding"] == "der"
    assert result["capabilities"]["hardware_attestation"] is False
    assert result["capabilities"]["rotate_keys"] is True


def test_resolve_service_returns_global_default(monkeypatch: pytest.MonkeyPatch):
    """_resolve_service_for_format should fall back to global default when no other match."""
    registry = {
        "services": [
            {
                "id": "svc-default",
                "name": "Default signer",
                "service_type": "openbao-transit",
                "key_reference": "key",
                "algorithms": ["ES256"],
                "key_purposes": [],
                "credential_formats": [],
            }
        ],
        "default_service_id": "svc-default",
        "format_defaults": {},
        "type_defaults": {},
    }
    # Re-run normalization so id/shape is consistent
    registry["services"] = [signing_keys._normalize_registered_service(svc) for svc in registry["services"]]

    result = signing_keys._resolve_service_for_format(registry, "mso_mdoc", None, None)
    assert result is not None
    assert result["id"] == "svc-default"


def test_resolve_service_format_defaults_win_over_global():
    """format_defaults should take priority over global default_service_id."""
    svc_global = signing_keys._normalize_registered_service(
        {"id": "svc-global", "service_type": "openbao-transit", "key_reference": "k", "algorithms": ["ES256"]}
    )
    svc_jwt = signing_keys._normalize_registered_service(
        {"id": "svc-jwt", "service_type": "openbao-transit", "key_reference": "k2", "algorithms": ["RS256"]}
    )
    registry = {
        "services": [svc_global, svc_jwt],
        "default_service_id": "svc-global",
        "format_defaults": {"jwt_vc_json": "svc-jwt"},
        "type_defaults": {},
    }
    result = signing_keys._resolve_service_for_format(registry, "jwt_vc_json", None, None)
    assert result is not None
    assert result["id"] == "svc-jwt"


def test_resolve_service_type_defaults_beat_format_defaults():
    """type_defaults should win over format_defaults."""
    svc_a = signing_keys._normalize_registered_service(
        {"id": "svc-a", "service_type": "openbao-transit", "key_reference": "a", "algorithms": ["ES256"]}
    )
    svc_b = signing_keys._normalize_registered_service(
        {"id": "svc-b", "service_type": "aws-kms", "auth_mode": "iam_role",
         "key_reference": "arn:aws:kms:us-east-1:000000000000:key/b", "algorithms": ["ES256"]}
    )
    registry = {
        "services": [svc_a, svc_b],
        "default_service_id": "svc-a",
        "format_defaults": {"mso_mdoc": "svc-a"},
        "type_defaults": {"mdoc_dsc": "svc-b"},
    }
    result = signing_keys._resolve_service_for_format(registry, "mso_mdoc", "mdoc_dsc", None)
    assert result is not None
    assert result["id"] == "svc-b"


def test_resolve_service_returns_none_when_no_services():
    result = signing_keys._resolve_service_for_format(
        {"services": [], "default_service_id": None, "format_defaults": {}, "type_defaults": {}},
        "jwt_vc_json",
        None,
        None,
    )
    assert result is None


@pytest.mark.asyncio
async def test_resolve_endpoint_returns_matching_service(monkeypatch: pytest.MonkeyPatch):
    """POST /v1/signing-keys/config/resolve should return the resolved service."""
    svc = signing_keys._normalize_registered_service(
        {
            "id": "svc-mdoc",
            "name": "mdoc DSC",
            "service_type": "aws-kms",
            "provider": "aws",
            "auth_mode": "iam_role",
            "key_reference": "arn:aws:kms:us-east-1:000000000000:key/abc",
            "algorithms": ["ES256"],
            "key_purposes": ["mdoc_dsc"],
        }
    )

    async def fake_registry(request, org_id):
        return {
            "services": [svc],
            "default_service_id": "svc-mdoc",
            "format_defaults": {},
            "type_defaults": {},
        }

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_registry)

    request = _build_request("org_123")
    response = await signing_keys.resolve_signing_service(
        request=request,
        body={"credential_format": "mso_mdoc", "key_purpose": "mdoc_dsc"},
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["service"]["id"] == "svc-mdoc"
    assert data["resolved_by"]["credential_format"] == "mso_mdoc"
    assert data["resolved_by"]["key_purpose"] == "mdoc_dsc"


@pytest.mark.asyncio
async def test_resolve_endpoint_returns_404_when_no_service(monkeypatch: pytest.MonkeyPatch):
    async def fake_registry(request, org_id):
        return {"services": [], "default_service_id": None, "format_defaults": {}, "type_defaults": {}}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_registry)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.resolve_signing_service(
            request=request,
            body={"credential_format": "mso_mdoc"},
            organization_id=None,
        )
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_list_key_purposes_proxies_to_signing_keys_service(monkeypatch: pytest.MonkeyPatch):
    proxy = AsyncMock(return_value=JSONResponse({"purposes": []}))
    registry = Mock()
    registry.get_service_url.return_value = "http://signing-keys:8017"
    monkeypatch.setattr(signing_keys, "proxy_request", proxy)
    monkeypatch.setattr(signing_keys, "get_registry", lambda: registry)
    request = _build_request("org_123")

    await signing_keys.list_key_purposes(request)

    proxy.assert_awaited_once_with(
        request,
        "http://signing-keys:8017",
        "/v1/signing-keys/config/purposes",
    )


@pytest.mark.asyncio
async def test_list_service_capabilities_proxies_to_signing_keys_service(monkeypatch: pytest.MonkeyPatch):
    proxy = AsyncMock(return_value=JSONResponse({"service_capabilities": []}))
    registry = Mock()
    registry.get_service_url.return_value = "http://signing-keys:8017"
    monkeypatch.setattr(signing_keys, "proxy_request", proxy)
    monkeypatch.setattr(signing_keys, "get_registry", lambda: registry)
    request = _build_request("org_123")

    await signing_keys.list_service_capabilities(request)

    proxy.assert_awaited_once_with(
        request,
        "http://signing-keys:8017",
        "/v1/signing-keys/config/service-capabilities",
    )


def test_baseline_validation_warns_on_purpose_algorithm_mismatch():
    """RS256 is not allowed for mdoc_dsc — validation should produce a warning."""
    checks: list[dict] = []
    signing_keys._append_baseline_validation_checks(
        {
            "auth_mode": "iam_role",
            "auth_reference": "",
            "key_reference": "arn:aws:kms:us-east-1:000000000000:key/abc",
            "algorithms": ["RS256"],
            "key_purposes": ["mdoc_dsc"],
        },
        checks,
    )
    purpose_check = next((c for c in checks if c["name"] == "Key purpose algorithm fit"), None)
    assert purpose_check is not None
    assert purpose_check["status"] == "warning"
    assert "RS256" in purpose_check["detail"]


def test_baseline_validation_passes_on_compatible_purpose_algorithm():
    """ES256 is valid for mdoc_dsc — no warning expected."""
    checks: list[dict] = []
    signing_keys._append_baseline_validation_checks(
        {
            "auth_mode": "token",
            "auth_reference": "mytoken",
            "key_reference": "cred-dsc-key",
            "algorithms": ["ES256"],
            "key_purposes": ["mdoc_dsc"],
        },
        checks,
    )
    purpose_check = next((c for c in checks if c["name"] == "Key purpose algorithm fit"), None)
    assert purpose_check is not None
    assert purpose_check["status"] == "pass"


def test_lti_tool_signing_is_distinct_and_rs256_only():
    assert "lti_tool_signing" in signing_keys.KEY_PURPOSES
    assert signing_keys.KEY_PURPOSE_ALGORITHM_CONSTRAINTS["lti_tool_signing"] == frozenset({"RS256"})
    assert signing_keys.KEY_PURPOSE_CREDENTIAL_FORMATS["lti_tool_signing"] == ()


def test_normalize_requested_registry_persists_format_and_type_defaults():
    """format_defaults and type_defaults should be preserved through registry normalization."""
    result = signing_keys._normalize_requested_registry(
        {
            "services": [],
            "default_service_id": None,
            "format_defaults": {"mso_mdoc": "svc-dsc", "jwt_vc_json": "svc-jwt"},
            "type_defaults": {"mdoc_dsc": "svc-dsc"},
        }
    )
    assert result is not None
    assert result["format_defaults"] == {"mso_mdoc": "svc-dsc", "jwt_vc_json": "svc-jwt"}
    assert result["type_defaults"] == {"mdoc_dsc": "svc-dsc"}


# ---------------------------------------------------------------------------
# Certificate Lifecycle Tests (GAP-004)
# ---------------------------------------------------------------------------


def test_extract_cert_expiry_date_parses_valid_certificate():
    """_extract_cert_expiry_date should extract and format expiry from PEM certificate."""
    # Create a minimal valid certificate for testing
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timezone, timedelta
    
    # Generate a self-signed cert
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256(), default_backend())
    )
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    result = signing_keys._extract_cert_expiry_date(cert_pem)
    
    assert result is not None
    assert result.endswith("Z")
    assert "T" in result  # ISO format check


def test_extract_cert_expiry_date_returns_none_for_invalid_pem():
    """_extract_cert_expiry_date should return None for invalid PEM."""
    result = signing_keys._extract_cert_expiry_date("not a certificate")
    assert result is None


def test_normalize_service_includes_certificate_fields():
    """_normalize_registered_service should include cert_pem, cert_chain_pem, cert_expires_at."""
    service = {
        "service_type": "aws-kms",
        "name": "AWS DSC",
        "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIC...",
        "cert_chain_pem": "-----BEGIN CERTIFICATE-----\nMIIC...",
        "cert_expires_at": "2025-12-31T23:59:59Z",
    }
    
    result = signing_keys._normalize_registered_service(service)
    
    assert result is not None
    assert result["cert_pem"] == "-----BEGIN CERTIFICATE-----\nMIIC..."
    assert result["cert_chain_pem"] == "-----BEGIN CERTIFICATE-----\nMIIC..."
    assert result["cert_expires_at"] == "2025-12-31T23:59:59Z"


def test_normalize_service_certificate_fields_default_to_none():
    """_normalize_registered_service should set cert fields to None if not provided."""
    service = {
        "service_type": "aws-kms",
        "name": "AWS DSC",
    }
    
    result = signing_keys._normalize_registered_service(service)
    
    assert result is not None
    assert result["cert_pem"] is None
    assert result["cert_chain_pem"] is None
    assert result["cert_expires_at"] is None


@pytest.mark.asyncio
async def test_store_service_certificate_saves_and_extracts_expiry(monkeypatch: pytest.MonkeyPatch):
    """Storing a certificate should extract and save the expiry date."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timezone, timedelta
    
    # Generate a test certificate
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test-dsc.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    
    test_service = {
        "id": "svc-dsc-1",
        "service_type": "custom-transit-compatible",
        "name": "Test DSC",
    }
    
    async def fake_load_registry(request, org_id):
        assert org_id == "org_123"
        return {"services": [test_service], "default_service_id": None}
    
    saved_registry = {}
    
    async def fake_save_registry(request, org_id, registry):
        assert org_id == "org_123"
        saved_registry["data"] = registry
    
    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_save_registered_service_registry", fake_save_registry)
    
    request = _build_request("org_123")
    response = await signing_keys.store_service_certificate(
        request=request,
        service_id="svc-dsc-1",
        body={"cert_pem": cert_pem, "cert_chain_pem": "chain"},
        organization_id=None,
    )
    
    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    assert data["cert_expires_at"] is not None
    assert "T" in data["cert_expires_at"]
    
    # Check that registry was saved with updated certificate
    assert saved_registry["data"]["services"][0]["cert_pem"] == cert_pem
    assert saved_registry["data"]["services"][0]["cert_chain_pem"] == "chain"
    assert saved_registry["data"]["services"][0]["cert_expires_at"] is not None


@pytest.mark.asyncio
async def test_get_service_certificate_returns_stored_data(monkeypatch: pytest.MonkeyPatch):
    """Getting a service certificate should return cert, chain, and expiry."""
    test_service = {
        "id": "svc-dsc-1",
        "service_type": "custom-transit-compatible",
        "name": "Test DSC",
        "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIC...",
        "cert_chain_pem": "-----BEGIN CERTIFICATE-----\nMIIC...",
        "cert_expires_at": "2025-12-31T23:59:59Z",
    }
    
    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}
    
    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    
    request = _build_request("org_123")
    response = await signing_keys.get_service_certificate(
        request=request,
        service_id="svc-dsc-1",
        organization_id=None,
    )
    
    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["service_id"] == "svc-dsc-1"
    assert data["cert_pem"] == "-----BEGIN CERTIFICATE-----\nMIIC..."
    assert data["cert_chain_pem"] == "-----BEGIN CERTIFICATE-----\nMIIC..."
    assert data["cert_expires_at"] == "2025-12-31T23:59:59Z"


@pytest.mark.asyncio
async def test_get_service_certificate_404_when_no_cert(monkeypatch: pytest.MonkeyPatch):
    """Getting a certificate for a service without one should return 404."""
    test_service = {
        "id": "svc-no-cert",
        "service_type": "custom-transit-compatible",
        "name": "No Cert",
    }
    
    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}
    
    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    
    from fastapi import HTTPException as FastAPIHTTPException
    
    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.get_service_certificate(
            request=request,
            service_id="svc-no-cert",
            organization_id=None,
        )
    
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_list_certificate_expiry_alerts_filters_by_threshold(monkeypatch: pytest.MonkeyPatch):
    """list_certificate_expiry_alerts should filter services by expiry threshold."""
    from datetime import timedelta
    
    now = datetime.now(timezone.utc)
    expiring_soon = _format_iso_datetime(now + timedelta(days=5))
    expiring_later = _format_iso_datetime(now + timedelta(days=60))
    
    test_services = [
        {
            "id": "svc-expiring-soon",
            "service_type": "custom-transit-compatible",
            "name": "Expiring Soon",
            "cert_expires_at": expiring_soon,
        },
        {
            "id": "svc-expiring-later",
            "service_type": "custom-transit-compatible",
            "name": "Expiring Later",
            "cert_expires_at": expiring_later,
        },
        {
            "id": "svc-no-cert",
            "service_type": "custom-transit-compatible",
            "name": "No Cert",
        },
    ]
    
    async def fake_load_registry(request, org_id):
        assert org_id == "org_123"
        return {"services": test_services, "default_service_id": None}
    
    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    
    request = _build_request("org_123")
    response = await signing_keys.list_certificate_expiry_alerts(
        request=request,
        days_until_expiry=30,
        organization_id=None,
    )
    
    assert response.status_code == 200
    data = json.loads(response.body)
    alerts = data["alerts"]
    
    # Should only include svc-expiring-soon (within 30 days)
    assert len(alerts) == 1
    assert alerts[0]["service_id"] == "svc-expiring-soon"
    assert alerts[0]["status"] == "critical"  # 5 days is critical (<=7)


@pytest.mark.asyncio
async def test_list_certificate_expiry_alerts_marks_critical_status(monkeypatch: pytest.MonkeyPatch):
    """Certificates expiring within 7 days should be marked as critical."""
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    critical = _format_iso_datetime(now + timedelta(days=3))
    warning = _format_iso_datetime(now + timedelta(days=15))
    
    test_services = [
        {
            "id": "svc-critical",
            "service_type": "custom-transit-compatible",
            "name": "Critical",
            "cert_expires_at": critical,
        },
        {
            "id": "svc-warning",
            "service_type": "custom-transit-compatible",
            "name": "Warning",
            "cert_expires_at": warning,
        },
    ]
    
    async def fake_load_registry(request, org_id):
        return {"services": test_services, "default_service_id": None}
    
    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    
    request = _build_request("org_123")
    response = await signing_keys.list_certificate_expiry_alerts(
        request=request,
        days_until_expiry=30,
        organization_id=None,
    )
    
    assert response.status_code == 200
    data = json.loads(response.body)
    alerts = data["alerts"]
    
    critical_alert = next((a for a in alerts if a["service_id"] == "svc-critical"), None)
    warning_alert = next((a for a in alerts if a["service_id"] == "svc-warning"), None)
    
    assert critical_alert is not None
    assert critical_alert["status"] == "critical"
    assert warning_alert is not None
    assert warning_alert["status"] == "warning"


@pytest.mark.asyncio
async def test_list_certificate_expiry_alerts_sorted_by_urgency(monkeypatch: pytest.MonkeyPatch):
    """list_certificate_expiry_alerts should return alerts sorted by urgency (soonest first)."""
    from datetime import timedelta
    
    now = datetime.now(timezone.utc)
    very_soon = _format_iso_datetime(now + timedelta(days=2))
    soon = _format_iso_datetime(now + timedelta(days=10))
    later = _format_iso_datetime(now + timedelta(days=20))
    
    test_services = [
        {
            "id": "svc-3",
            "service_type": "custom-transit-compatible",
            "name": "Service 3",
            "cert_expires_at": later,
        },
        {
            "id": "svc-1",
            "service_type": "custom-transit-compatible",
            "name": "Service 1",
            "cert_expires_at": very_soon,
        },
        {
            "id": "svc-2",
            "service_type": "custom-transit-compatible",
            "name": "Service 2",
            "cert_expires_at": soon,
        },
    ]
    
    async def fake_load_registry(request, org_id):
        return {"services": test_services, "default_service_id": None}
    
    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    
    request = _build_request("org_123")
    response = await signing_keys.list_certificate_expiry_alerts(
        request=request,
        days_until_expiry=30,
        organization_id=None,
    )
    
    assert response.status_code == 200
    data = json.loads(response.body)
    alerts = data["alerts"]
    
    # Should be sorted by days_until_expiry ascending
    assert alerts[0]["service_id"] == "svc-1"  # 2 days
    assert alerts[1]["service_id"] == "svc-2"  # 10 days
    assert alerts[2]["service_id"] == "svc-3"  # 20 days


@pytest.mark.asyncio
async def test_store_certificate_requires_cert_pem(monkeypatch: pytest.MonkeyPatch):
    """Storing a certificate without cert_pem should return 400."""
    test_service = {"id": "svc-1", "service_type": "aws-kms", "name": "Test"}
    
    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}
    
    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    
    from fastapi import HTTPException as FastAPIHTTPException
    
    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.store_service_certificate(
            request=request,
            service_id="svc-1",
            body={},  # Missing cert_pem
            organization_id=None,
        )
    
    assert exc_info.value.status_code == 400
    assert "cert_pem is required" in str(exc_info.value.detail)


# =============================================================================
# GAP-004-ext — generate_csr
# =============================================================================


@pytest.mark.asyncio
async def test_generate_csr_returns_404_when_service_not_found(monkeypatch: pytest.MonkeyPatch):
    """generate_csr should return 404 when the service_id is not in the registry."""
    async def fake_load_registry(request, org_id):
        return {"services": [], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.generate_csr(request=request, service_id="missing", organization_id=None)

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_generate_csr_returns_501_when_generation_unavailable(monkeypatch: pytest.MonkeyPatch):
    """generate_csr should fail explicitly until remote-KMS CSR signing is implemented."""
    test_service = {
        "id": "svc-1",
        "service_type": "custom-transit-compatible",
        "name": "Test",
        "key_reference": "mykey",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: None)

    request = _build_request("org_123")

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.generate_csr(request=request, service_id="svc-1", organization_id=None)

    assert exc_info.value.status_code == 501
    assert exc_info.value.detail["error"] == "kms_csr_generation_unavailable"
    assert exc_info.value.detail["service_id"] == "svc-1"


# =============================================================================
# GAP-005 — Public Key Publication
# =============================================================================


@pytest.mark.asyncio
async def test_publish_service_to_jwks_returns_404_when_service_not_found(monkeypatch: pytest.MonkeyPatch):
    """publish_service_to_jwks should return 404 when service_id is missing."""
    async def fake_load_registry(request, org_id):
        return {"services": [], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.publish_service_to_jwks(request=request, service_id="missing", organization_id=None)

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_create_signing_key_creates_managed_openbao_key(monkeypatch: pytest.MonkeyPatch):
    async def fake_load_registry(request, org_id):
        return {"services": [], "default_service_id": None}

    async def fake_snapshot(resolved_org_id: str | None):
        return {
            "keys": [],
            "provider_metadata": {
                "provider": "openbao",
                "status": "configured",
                "managed_by": "OpenBao transit service",
                "supports_rotation": False,
                "supports_upload": False,
                "supports_delete": False,
                "key_count": 0,
            },
            "config": {
                "hsm_enabled": True,
                "hsm_settings": {
                    "provider": "openbao",
                    "service_url": "http://openbao:8200",
                    "mount": "transit",
                    "managed_by": "Marty service stack",
                },
                "vault_enabled": False,
                "vault_settings": {},
            },
            "message": None,
        }

    async def fake_create(service: dict, key_reference: str, algorithm: str):
        assert service["service_type"] == "openbao-transit"
        assert key_reference == "cred-issuer-my-first-es256"
        assert algorithm == "ES256"
        return {
            "type": "ecdsa-p256",
            "latest_version": 1,
            "supports_signing": True,
            "keys": {
                "1": {"creation_time": "2026-04-18T00:00:00Z"},
            },
        }

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_load_signing_key_snapshot", fake_snapshot)
    monkeypatch.setattr(signing_keys, "_create_managed_openbao_transit_key", fake_create)

    request = _build_request("org_123")
    response = await signing_keys.create_signing_key(
        request=request,
        body={
            "service_id": signing_keys.MANAGED_OPENBAO_SERVICE_ID,
            "name": "my first",
            "algorithm": "ES256",
            "key_purpose": "vc_jwt_issuer",
        },
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    assert data["service_id"] == signing_keys.MANAGED_OPENBAO_SERVICE_ID
    assert data["provider_key_name"] == "cred-issuer-my-first-es256"
    assert data["key"]["provider_key_name"] == "cred-issuer-my-first-es256"
    assert data["key"]["name"] == "my first"


@pytest.mark.asyncio
async def test_create_managed_openbao_key_enables_missing_transit_mount(monkeypatch: pytest.MonkeyPatch):
    calls: list[tuple[str, dict]] = []

    async def fake_post_json(path: str, payload: dict, **kwargs):
        calls.append((path, payload))
        if path == "/v1/transit/keys/cred-issuer-test" and len(calls) == 1:
            raise _http_status_error(
                404,
                {"errors": ['no handler for route "transit/keys/cred-issuer-test". route entry not found.']},
            )
        return {}

    async def fake_get_json(path: str, **kwargs):
        assert path == "/v1/transit/keys/cred-issuer-test"
        return {"data": {"type": "ecdsa-p256", "latest_version": 1}}

    monkeypatch.setattr(signing_keys, "_openbao_post_json", fake_post_json)
    monkeypatch.setattr(signing_keys, "_openbao_get_json", fake_get_json)
    monkeypatch.setattr(signing_keys, "_bao_token", lambda: "dev-token")

    created = await signing_keys._create_managed_openbao_transit_key(
        {"endpoint": "http://openbao:8200", "mount": "transit"},
        "cred-issuer-test",
        "ES256",
    )

    assert created["type"] == "ecdsa-p256"
    assert calls == [
        ("/v1/transit/keys/cred-issuer-test", {"type": "ecdsa-p256"}),
        ("/v1/sys/mounts/transit", {"type": "transit"}),
        ("/v1/transit/keys/cred-issuer-test", {"type": "ecdsa-p256"}),
    ]


@pytest.mark.asyncio
async def test_publish_service_to_jwks_returns_400_when_no_adapter(monkeypatch: pytest.MonkeyPatch):
    """publish_service_to_jwks should return 400 when no adapter is available."""
    test_service = {
        "id": "svc-aws",
        "service_type": "aws-kms",
        "key_reference": "arn:aws:kms:us-east-1:000000000000:key/abc",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: None)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.publish_service_to_jwks(request=request, service_id="svc-aws", organization_id=None)

    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_publish_service_to_jwks_returns_jwk_on_success(monkeypatch: pytest.MonkeyPatch):
    """publish_service_to_jwks should return the JWK from the adapter."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    class FakeAdapter:
        async def get_public_key_jwk(self, config: dict):
            return {"provider": "openbao", "key_reference": "cred-issuer-es256", "public_key_pem": "---"}

    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAdapter())

    request = _build_request("org_123")
    response = await signing_keys.publish_service_to_jwks(request=request, service_id="svc-bao", organization_id=None)

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    assert data["service_id"] == "svc-bao"
    assert data["jwk"]["key_reference"] == "cred-issuer-es256"
    assert "published_at" in data


@pytest.mark.asyncio
async def test_publish_service_to_jwks_uses_key_reference_override(monkeypatch: pytest.MonkeyPatch):
    """JWKS publication must publish the selected issuer key, not the service default."""
    observed_configs: list[dict] = []
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-old-default",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    class FakeAdapter:
        async def get_public_key_jwk(self, config: dict):
            observed_configs.append(config)
            return {
                "kty": "EC",
                "crv": "P-256",
                "x": "abc",
                "y": "def",
            }

    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAdapter())

    request = _build_request("org_123")
    response = await signing_keys.publish_service_to_jwks(
        request=request,
        service_id="svc-bao",
        body={"key_reference": "cred-issuer-new-selected"},
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert observed_configs[0]["key_reference"] == "cred-issuer-new-selected"
    assert data["jwk"]["kid"] == "cred-issuer-new-selected"
    assert data["jwk"]["key_reference"] == "cred-issuer-new-selected"


@pytest.mark.asyncio
async def test_publish_service_to_jwks_returns_503_when_adapter_raises(monkeypatch: pytest.MonkeyPatch):
    """publish_service_to_jwks should return 503 when the adapter throws."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    class FailingAdapter:
        async def get_public_key_jwk(self, config: dict):
            raise RuntimeError("KMS unreachable")

    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FailingAdapter())

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.publish_service_to_jwks(request=request, service_id="svc-bao", organization_id=None)

    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_publish_service_to_did_returns_verification_method(monkeypatch: pytest.MonkeyPatch):
    """publish_service_to_did should build and return a verificationMethod from the adapter JWK."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    class FakeAdapter:
        async def get_public_key_jwk(self, config: dict):
            return {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}

    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAdapter())

    request = _build_request("org_123")
    response = await signing_keys.publish_service_to_did(
        request=request,
        service_id="svc-bao",
        body={"fragment": "issuer-key"},
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    assert "verification_method" in data
    vm = data["verification_method"]
    assert vm["type"] == "JsonWebKey"
    assert "issuer-key" in vm["id"]
    assert vm["publicKeyJwk"]["kty"] == "EC"


@pytest.mark.asyncio
async def test_publish_service_to_did_resolves_managed_openbao_service(monkeypatch: pytest.MonkeyPatch):
    async def fake_load_registry(request, org_id):
        return {"services": [], "default_service_id": None}

    async def fake_snapshot(resolved_org_id: str | None):
        return {
            "keys": [],
            "provider_metadata": {
                "provider": "openbao",
                "status": "configured",
                "managed_by": "OpenBao transit service",
                "supports_rotation": False,
                "supports_upload": False,
                "supports_delete": False,
                "key_count": 0,
            },
            "config": {
                "hsm_enabled": True,
                "hsm_settings": {
                    "provider": "openbao",
                    "service_url": "http://openbao:8200",
                    "mount": "transit",
                    "managed_by": "Marty service stack",
                },
                "vault_enabled": False,
                "vault_settings": {},
            },
            "message": None,
        }

    monkeypatch.setattr(signing_keys, "_bao_token", lambda: "bao-service-token")

    class FakeAdapter:
        async def get_public_key_jwk(self, config: dict):
            assert config["key_reference"] == "cred-issuer-my-first-es256"
            assert config["auth_mode"] == "service_token"
            assert config["auth_reference"] == "bao-service-token"
            return {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_load_signing_key_snapshot", fake_snapshot)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAdapter())

    request = _build_request("org_123")
    response = await signing_keys.publish_service_to_did(
        request=request,
        service_id=signing_keys.MANAGED_OPENBAO_SERVICE_ID,
        body={"fragment": "issuer-key", "key_reference": "cred-issuer-my-first-es256"},
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    assert data["service_id"] == signing_keys.MANAGED_OPENBAO_SERVICE_ID
    assert data["verification_method"]["publicKeyJwk"]["kty"] == "EC"


@pytest.mark.asyncio
async def test_publish_service_to_did_returns_404_when_service_not_found(monkeypatch: pytest.MonkeyPatch):
    async def fake_load_registry(request, org_id):
        return {"services": [], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.publish_service_to_did(
            request=request, service_id="missing", body={}, organization_id=None
        )

    assert exc_info.value.status_code == 404


# =============================================================================
# GAP-006 — Public Key Verification
# =============================================================================


@pytest.mark.asyncio
async def test_verify_service_public_key_returns_404_when_service_missing(monkeypatch: pytest.MonkeyPatch):
    """verify_service_public_key should return 404 when service_id is not in registry."""
    async def fake_load_registry(request, org_id):
        return {"services": [], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.verify_service_public_key(request=request, service_id="missing", organization_id=None)

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_verify_service_public_key_runs_checks_on_adapter_jwk(monkeypatch: pytest.MonkeyPatch):
    """verify_service_public_key should run structural checks on the JWK from the adapter."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    class FakeAdapter:
        async def get_public_key_jwk(self, config: dict):
            return {"kty": "EC", "use": "sig", "alg": "ES256", "crv": "P-256"}

    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAdapter())

    request = _build_request("org_123")
    response = await signing_keys.verify_service_public_key(
        request=request, service_id="svc-bao", organization_id=None
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["service_id"] == "svc-bao"
    assert "key_valid" in data
    assert "checks" in data
    assert data["checks"]["key_present"] is True
    assert data["checks"]["required_fields_present"] is True
    assert data["checks"]["algorithm_supported"] is True
    assert data["key_valid"] is True
    assert "verified_at" in data


@pytest.mark.asyncio
async def test_verify_service_public_key_fails_on_unsupported_algorithm(monkeypatch: pytest.MonkeyPatch):
    """verify_service_public_key should mark key_valid=False for unsupported algorithm."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    class FakeAdapter:
        async def get_public_key_jwk(self, config: dict):
            return {"kty": "EC", "use": "sig", "alg": "HS256"}  # HS256 not supported

    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAdapter())

    request = _build_request("org_123")
    response = await signing_keys.verify_service_public_key(
        request=request, service_id="svc-bao", organization_id=None
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["checks"]["algorithm_supported"] is False
    assert data["key_valid"] is False


@pytest.mark.asyncio
async def test_rotate_service_key_updates_rotation_state(monkeypatch: pytest.MonkeyPatch):
    registry = {
        "services": [
            {
                "id": "svc-bao",
                "name": "OpenBao signer",
                "service_type": "openbao-transit",
                "provider": "openbao",
                "endpoint": "http://openbao:8200",
                "mount": "transit",
                "auth_mode": "service_token",
                "key_reference": "cred-issuer-es256",
                "algorithms": ["ES256"],
            }
        ],
        "default_service_id": "svc-bao",
    }

    async def fake_load_registry(request, org_id):
        return registry

    save_registry = AsyncMock()

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_save_registered_service_registry", save_registry)

    async def fake_rotate(service: dict):
        assert service["id"] == "svc-bao"
        return {"ok": True, "version": 2}

    monkeypatch.setattr(signing_keys, "_rotate_openbao_transit_key", fake_rotate)

    async def fake_publish_jwks(**kwargs):
        return None

    async def fake_publish_did(**kwargs):
        return None

    monkeypatch.setattr(signing_keys, "publish_service_to_jwks", fake_publish_jwks)
    monkeypatch.setattr(signing_keys, "publish_service_to_did", fake_publish_did)

    request = _build_request("org_123")
    response = await signing_keys.rotate_service_key(
        request=request,
        service_id="svc-bao",
        body={"overlap_days": 14, "publish_updates": True},
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["service_id"] == "svc-bao"
    assert data["rotation_state"]["overlap_days"] == 14
    assert data["rotation_state"]["provider_rotation"]["ok"] is True
    assert data["publication"]["jwks"] is True
    assert data["publication"]["did"] is True
    save_registry.assert_awaited_once()


@pytest.mark.asyncio
async def test_register_and_list_holder_keys(monkeypatch: pytest.MonkeyPatch):
    store: dict[str, dict] = {}

    async def fake_load_doc(request, storage_key, default):
        return store.get(storage_key, dict(default))

    async def fake_save_doc(request, storage_key, doc):
        store[storage_key] = doc

    monkeypatch.setattr(signing_keys, "_load_json_document", fake_load_doc)
    monkeypatch.setattr(signing_keys, "_save_json_document", fake_save_doc)

    request = _build_request("org_123")
    register_response = await signing_keys.register_holder_key(
        request=request,
        body={
            "device_id": "device-1",
            "credential_id": "cred-1",
            "key_purpose": "holder_binding",
            "public_jwk": {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"},
        },
        organization_id=None,
    )
    assert register_response.status_code == 200

    list_response = await signing_keys.list_holder_keys(request=request, organization_id=None, device_id="device-1")
    assert list_response.status_code == 200
    data = json.loads(list_response.body)
    assert len(data["keys"]) == 1
    assert data["keys"][0]["credential_id"] == "cred-1"
    assert data["keys"][0]["key_purpose"] == "holder_binding"


@pytest.mark.asyncio
async def test_register_vdsnc_service_derives_key_reference(monkeypatch: pytest.MonkeyPatch):
    registry = {"services": [], "default_service_id": None}

    async def fake_load_registry(request, org_id):
        return registry

    save_registry = AsyncMock()
    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_save_registered_service_registry", save_registry)

    request = _build_request("org_123")
    response = await signing_keys.register_vdsnc_service(
        request=request,
        body={
            "country_code": "US",
            "authority_name": "US CBP",
            "role": "dsc",
            "generation": 3,
        },
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    assert data["service"]["country_code"] == "US"
    assert data["service"]["authority_name"] == "US CBP"
    assert data["service"]["key_reference"].startswith("cred:vdsnc:US:dsc:3")


@pytest.mark.asyncio
async def test_verify_service_public_key_returns_400_when_no_adapter(monkeypatch: pytest.MonkeyPatch):
    """verify_service_public_key should return 400 when no adapter is registered."""
    test_service = {
        "id": "svc-aws",
        "service_type": "aws-kms",
        "key_reference": "arn:aws:kms:us-east-1:000000000000:key/abc",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: None)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.verify_service_public_key(request=request, service_id="svc-aws", organization_id=None)

    assert exc_info.value.status_code == 400


# =============================================================================
# GAP-007 — Audit and Compliance
# =============================================================================


@pytest.mark.asyncio
async def test_get_key_audit_log_returns_404_when_service_not_found(monkeypatch: pytest.MonkeyPatch):
    """get_key_audit_log should return 404 when service_id is not in the registry."""
    async def fake_load_registry(request, org_id):
        return {"services": [], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.get_key_audit_log(
            request=request, service_id="missing", limit=100, offset=0, organization_id=None
        )

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_get_key_audit_log_returns_unavailable_when_storage_is_not_implemented(monkeypatch: pytest.MonkeyPatch):
    """get_key_audit_log should not return fabricated audit events."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    request = _build_request("org_123")
    response = await signing_keys.get_key_audit_log(
        request=request, service_id="svc-bao", limit=10, offset=0, organization_id=None
    )

    assert response.status_code == 501
    data = json.loads(response.body)
    assert data["error"] == "key_audit_log_unavailable"
    assert data["organization_id"] == "org_123"
    assert data["service_id"] == "svc-bao"
    assert "message_id" in data


@pytest.mark.asyncio
async def test_get_key_audit_log_requires_org_id(monkeypatch: pytest.MonkeyPatch):
    """get_key_audit_log should fail fast instead of loading a global registry."""
    load_registry = AsyncMock()
    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", load_registry)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request(None)
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.get_key_audit_log(
            request=request, service_id="svc-bao", limit=10, offset=0, organization_id=None
        )

    assert exc_info.value.status_code == 422
    load_registry.assert_not_called()


@pytest.mark.asyncio
async def test_get_keys_compliance_summary_returns_unavailable_without_live_source():
    """get_keys_compliance_summary should not return synthetic perfect-compliance metrics."""

    request = _build_request("org_123")
    response = await signing_keys.get_keys_compliance_summary(request=request, organization_id=None)

    assert response.status_code == 501
    data = json.loads(response.body)
    assert data["error"] == "key_compliance_summary_unavailable"
    assert data["organization_id"] == "org_123"
    assert "message_id" in data


@pytest.mark.asyncio
async def test_get_keys_compliance_summary_requires_org_id(monkeypatch: pytest.MonkeyPatch):
    """get_keys_compliance_summary should fail fast without an organization context."""
    load_registry = AsyncMock()
    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", load_registry)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request(None)
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.get_keys_compliance_summary(request=request, organization_id=None)

    assert exc_info.value.status_code == 422
    load_registry.assert_not_called()


# =============================================================================
# GAP-003 Extended — Sign Payload Endpoint
# =============================================================================


@pytest.mark.asyncio
async def test_sign_payload_with_service_returns_404_when_service_not_found(monkeypatch: pytest.MonkeyPatch):
    """sign_payload_with_service should return 404 when service_id is not in registry."""
    async def fake_load_registry(request, org_id):
        return {"services": [], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.sign_payload_with_service(
            request=request,
            service_id="missing",
            body={"payload_b64": "SGVsbG8gV29ybGQ="},  # "Hello World"
            organization_id=None,
        )

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_sign_payload_requires_payload_input(monkeypatch: pytest.MonkeyPatch):
    """sign_payload_with_service should return 400 when neither payload_b64 nor payload_hex is provided."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.sign_payload_with_service(
            request=request,
            service_id="svc-bao",
            body={},  # Missing payload
            organization_id=None,
        )

    assert exc_info.value.status_code == 400
    assert "payload_b64 or payload_hex" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_sign_payload_accepts_base64_payload(monkeypatch: pytest.MonkeyPatch):
    """sign_payload_with_service should accept and decode base64url-encoded payloads."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    signed_payload = b"fake-signature-bytes"

    class FakeAdapter:
        provider = "openbao"
        signature_encoding = "raw_ieee_p1363"

        async def sign(self, config: dict, payload: bytes):
            assert payload == b"Hello World"
            return signed_payload

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAdapter())

    request = _build_request("org_123")
    response = await signing_keys.sign_payload_with_service(
        request=request,
        service_id="svc-bao",
        body={"payload_b64": "SGVsbG8gV29ybGQ="},  # "Hello World" in base64url
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    assert data["service_id"] == "svc-bao"
    assert data["signature_encoding"] == "raw_ieee_p1363"
    assert data["payload_length"] == 11  # "Hello World" is 11 bytes
    assert "signature_b64" in data
    assert "signature_hex" in data


@pytest.mark.asyncio
async def test_sign_payload_enforces_requested_key_purpose(
    monkeypatch: pytest.MonkeyPatch,
):
    test_service = {
        "id": "svc-canvas-lti",
        "service_type": "openbao-transit",
        "key_reference": "canvas-lti-rs256",
        "algorithms": ["RS256"],
        "key_purposes": ["lti_tool_signing"],
    }

    async def fake_load_registry(request, org_id):
        return {
            "services": [test_service],
            "default_service_id": None,
            "key_reference_purposes": {
                "svc-canvas-lti": {
                    "canvas-lti-rs256": ["lti_tool_signing"],
                },
            },
        }

    class FakeAdapter:
        provider = "openbao"
        signature_encoding = "raw_ieee_p1363"

        async def sign(self, config: dict, payload: bytes):
            return b"signature"

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAdapter())
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)
    request = _build_request("org_123", redis_client=redis_mock)

    response = await signing_keys.sign_payload_with_service(
        request=request,
        service_id="svc-canvas-lti",
        body={
            "payload_b64": "dGVzdA==",
            "algorithm": "RS256",
            "key_purpose": "lti_tool_signing",
            "key_reference": "canvas-lti-rs256",
        },
        organization_id=None,
    )
    assert response.status_code == 200

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.sign_payload_with_service(
            request=request,
            service_id="svc-canvas-lti",
            body={
                "payload_b64": "dGVzdA==",
                "algorithm": "RS256",
                "key_purpose": "vc_jwt_issuer",
                "key_reference": "canvas-lti-rs256",
            },
            organization_id=None,
        )
    assert exc_info.value.status_code == 409
    assert "reserved exclusively" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_lti_signing_uses_distinct_key_within_multi_key_openbao_service(
    monkeypatch: pytest.MonkeyPatch,
):
    service = {
        "id": signing_keys.MANAGED_OPENBAO_SERVICE_ID,
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-marty-rs256",
        "key_aliases": ["cred-issuer-marty-rs256", "lti-tool-marty-rs256"],
        "algorithms": ["RS256"],
        "key_purposes": ["vc_jwt_issuer", "lti_tool_signing"],
    }
    registry = {
        "services": [service],
        "default_service_id": signing_keys.MANAGED_OPENBAO_SERVICE_ID,
        "key_reference_purposes": {
            signing_keys.MANAGED_OPENBAO_SERVICE_ID: {
                "cred-issuer-marty-rs256": ["vc_jwt_issuer"],
                "lti-tool-marty-rs256": ["lti_tool_signing"],
            },
        },
    }
    signed_with: list[str] = []

    async def fake_load_registry(request, org_id):
        return registry

    class FakeAdapter:
        signature_encoding = "der"

        async def sign(self, config: dict, payload: bytes):
            signed_with.append(config["key_reference"])
            return b"signature"

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAdapter())
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)
    request = _build_request("org_123", redis_client=redis_mock)

    response = await signing_keys.sign_payload_with_service(
        request=request,
        service_id=signing_keys.MANAGED_OPENBAO_SERVICE_ID,
        body={
            "payload_b64": "dGVzdA==",
            "algorithm": "RS256",
            "key_purpose": "lti_tool_signing",
            "key_reference": "lti-tool-marty-rs256",
        },
        organization_id=None,
    )

    assert response.status_code == 200
    assert signed_with == ["lti-tool-marty-rs256"]

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException, match="reserved exclusively"):
        await signing_keys.sign_payload_with_service(
            request=request,
            service_id=signing_keys.MANAGED_OPENBAO_SERVICE_ID,
            body={
                "payload_b64": "dGVzdA==",
                "algorithm": "RS256",
                "key_purpose": "vc_jwt_issuer",
                "key_reference": "lti-tool-marty-rs256",
            },
            organization_id=None,
        )

    with pytest.raises(FastAPIHTTPException, match="not registered exclusively") as exc_info:
        await signing_keys.sign_payload_with_service(
            request=request,
            service_id=signing_keys.MANAGED_OPENBAO_SERVICE_ID,
            body={
                "payload_b64": "dGVzdA==",
                "algorithm": "RS256",
                "key_purpose": "lti_tool_signing",
                "key_reference": "cred-issuer-marty-rs256",
            },
            organization_id=None,
        )
    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_lti_signing_fails_closed_without_explicit_key_binding(
    monkeypatch: pytest.MonkeyPatch,
):
    service = {
        "id": "shared-kms",
        "service_type": "openbao-transit",
        "key_reference": "credential-default",
        "algorithms": ["RS256"],
        "key_purposes": ["vc_jwt_issuer", "lti_tool_signing"],
    }

    async def fake_load_registry(request, org_id):
        return {
            "services": [service],
            "default_service_id": "shared-kms",
            "key_reference_purposes": {},
        }

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    request = _build_request("org_123")

    from fastapi import HTTPException as FastAPIHTTPException

    for body, expected in (
        (
            {
                "payload_b64": "dGVzdA==",
                "algorithm": "RS256",
                "key_purpose": "lti_tool_signing",
            },
            "explicit key_reference",
        ),
        (
            {
                "payload_b64": "dGVzdA==",
                "algorithm": "RS256",
                "key_purpose": "lti_tool_signing",
                "key_reference": "unbound-lti-key",
            },
            "not registered exclusively",
        ),
    ):
        with pytest.raises(FastAPIHTTPException, match=expected) as exc_info:
            await signing_keys.sign_payload_with_service(
                request=request,
                service_id="shared-kms",
                body=body,
                organization_id=None,
            )
        assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_lti_signing_rejects_key_assigned_to_issuer_profile(
    monkeypatch: pytest.MonkeyPatch,
):
    key_reference = "shared-rs256-key"
    service = {
        "id": "shared-kms",
        "service_type": "openbao-transit",
        "key_reference": key_reference,
        "algorithms": ["RS256"],
        "key_purposes": ["vc_jwt_issuer", "lti_tool_signing"],
    }

    async def fake_load_registry(request, org_id):
        return {
            "services": [service],
            "key_reference_purposes": {
                "shared-kms": {key_reference: ["lti_tool_signing"]},
            },
        }

    async def fake_issuer_references(request, organization_id):
        return {key_reference}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(
        signing_keys,
        "_credential_issuer_key_references",
        fake_issuer_references,
    )

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException, match="credential issuer profile") as exc_info:
        await signing_keys.sign_payload_with_service(
            request=_build_request("org_123"),
            service_id="shared-kms",
            body={
                "payload_b64": "dGVzdA==",
                "algorithm": "RS256",
                "key_purpose": "lti_tool_signing",
                "key_reference": key_reference,
            },
            organization_id=None,
        )
    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_lti_signing_fails_closed_when_issuer_profile_registry_is_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = {
        "id": "shared-kms",
        "service_type": "openbao-transit",
        "key_reference": "lti-key",
        "algorithms": ["RS256"],
        "key_purposes": ["lti_tool_signing"],
    }

    async def fake_load_registry(request, org_id):
        return {
            "services": [service],
            "key_reference_purposes": {
                "shared-kms": {"lti-key": ["lti_tool_signing"]},
            },
        }

    monkeypatch.setattr(
        signing_keys,
        "_load_registered_service_registry",
        fake_load_registry,
    )
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value="not-json")

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException, match="registry is invalid") as exc_info:
        await signing_keys.sign_payload_with_service(
            request=_build_request("org_123", redis_client=redis_mock),
            service_id="shared-kms",
            body={
                "payload_b64": "dGVzdA==",
                "algorithm": "RS256",
                "key_purpose": "lti_tool_signing",
                "key_reference": "lti-key",
            },
            organization_id=None,
        )
    assert exc_info.value.status_code == 503


def test_lti_key_creation_uses_protocol_specific_namespace() -> None:
    assert signing_keys._normalize_requested_openbao_key_name(
        "Canvas production",
        "lti_tool_signing",
        "RS256",
    ).startswith("lti-tool-")
    assert signing_keys._normalize_requested_openbao_key_name(
        "cred-issuer-canvas-production",
        "lti_tool_signing",
        "RS256",
    ) == "lti-tool-canvas-production-rs256"
    assert signing_keys._normalize_requested_openbao_key_name(
        "lti-tool-canvas-production",
        "vc_jwt_issuer",
        "RS256",
    ) == "cred-issuer-canvas-production-rs256"

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException, match="cannot combine"):
        signing_keys._validate_lti_key_reference_bindings(
            {
                "shared-kms": {
                    "reused-key": ["vc_jwt_issuer", "lti_tool_signing"],
                },
            }
        )

    with pytest.raises(FastAPIHTTPException, match="reserved for LTI"):
        signing_keys._assert_issuer_profile_key_compatible(
            {
                "signing_service_id": "shared-kms",
                "signing_key_reference": "lti-key",
                "key_purpose": "vc_jwt_issuer",
            },
            {
                "key_reference_purposes": {
                    "shared-kms": {"lti-key": ["lti_tool_signing"]},
                },
            },
        )


@pytest.mark.asyncio
async def test_lti_key_creation_rejects_non_rs256_algorithm() -> None:
    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException, match="must use RS256") as exc_info:
        await signing_keys.create_signing_key(
            request=_build_request("org_123"),
            body={
                "name": "Canvas production",
                "algorithm": "ES256",
                "key_purpose": "lti_tool_signing",
            },
            organization_id=None,
        )
    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
async def test_sign_payload_accepts_hex_payload(monkeypatch: pytest.MonkeyPatch):
    """sign_payload_with_service should accept and decode hex-encoded payloads."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    signed_payload = b"fake-signature"

    class FakeAdapter:
        provider = "openbao"
        signature_encoding = "raw_ieee_p1363"

        async def sign(self, config: dict, payload: bytes):
            assert payload == bytes.fromhex("48656c6c6f")  # "Hello" in hex
            return signed_payload

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAdapter())

    request = _build_request("org_123")
    response = await signing_keys.sign_payload_with_service(
        request=request,
        service_id="svc-bao",
        body={"payload_hex": "48656c6c6f"},  # "Hello" in hex
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    assert data["payload_length"] == 5


@pytest.mark.asyncio
async def test_sign_payload_returns_der_signature_from_aws_adapter(monkeypatch: pytest.MonkeyPatch):
    """sign_payload_with_service should indicate DER encoding when adapter returns DER."""
    test_service = {
        "id": "svc-aws",
        "service_type": "aws-kms",
        "key_reference": "arn:aws:kms:us-east-1:000000000000:key/abc",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    # Fake DER signature (r, s components)
    der_signature = bytes.fromhex("30440220" + "aa" * 32 + "0220" + "bb" * 32)

    class FakeAwsAdapter:
        provider = "aws"
        signature_encoding = "der"

        async def sign(self, config: dict, payload: bytes):
            return der_signature

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAwsAdapter())

    request = _build_request("org_123")
    response = await signing_keys.sign_payload_with_service(
        request=request,
        service_id="svc-aws",
        body={"payload_b64": "dGVzdA=="},  # "test" in base64url
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    assert data["signature_encoding"] == "der"
    assert "signature_b64" in data  # DER-encoded
    assert "signature_raw_b64" in data  # Transcoded raw format
    assert "signature_raw_hex" in data


@pytest.mark.asyncio
async def test_sign_payload_returns_algorithm_in_response(monkeypatch: pytest.MonkeyPatch):
    """sign_payload_with_service should return the algorithm used for signing."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    class FakeAdapter:
        provider = "openbao"
        signature_encoding = "raw_ieee_p1363"

        async def sign(self, config: dict, payload: bytes):
            return b"signature"

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAdapter())

    request = _build_request("org_123")
    response = await signing_keys.sign_payload_with_service(
        request=request,
        service_id="svc-bao",
        body={"payload_b64": "dGVzdA=="},
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["algorithm"] == "ES256"


@pytest.mark.asyncio
async def test_sign_payload_returns_503_when_adapter_fails(monkeypatch: pytest.MonkeyPatch):
    """sign_payload_with_service should return 503 when the adapter raises an error."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    class FailingAdapter:
        provider = "openbao"
        signature_encoding = "raw_ieee_p1363"

        async def sign(self, config: dict, payload: bytes):
            raise RuntimeError("Transit service unreachable")

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FailingAdapter())

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.sign_payload_with_service(
            request=request,
            service_id="svc-bao",
            body={"payload_b64": "dGVzdA=="},
            organization_id=None,
        )

    assert exc_info.value.status_code == 503
    assert "Signing failed" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_sign_payload_auto_creates_missing_managed_openbao_key(monkeypatch: pytest.MonkeyPatch):
    normalized_service = {
        "id": signing_keys.MANAGED_OPENBAO_SERVICE_ID,
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-marty-es256",
        "algorithms": ["ES256"],
    }
    sign_attempts = 0
    created: list[tuple[str, str]] = []

    async def fake_resolve_effective_service(request, resolved_org_id, service_id, *, key_reference_override=None):
        assert service_id == signing_keys.MANAGED_OPENBAO_SERVICE_ID
        return {}, normalized_service, normalized_service, False

    class MissingKeyThenSuccessAdapter:
        provider = "openbao"
        signature_encoding = "raw_ieee_p1363"

        async def sign(self, config: dict, payload: bytes):
            nonlocal sign_attempts
            sign_attempts += 1
            if sign_attempts == 1:
                raise _http_status_error(
                    404,
                    {"errors": ['no handler for route "transit/sign/cred-issuer-marty-es256". route entry not found.']},
                )
            assert payload == b"hello"
            return b"signature"

    async def fake_create(service: dict, key_reference: str, algorithm: str):
        created.append((key_reference, algorithm))
        assert service is normalized_service
        return {"type": "ecdsa-p256"}

    monkeypatch.setattr(signing_keys, "_resolve_effective_service", fake_resolve_effective_service)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: MissingKeyThenSuccessAdapter())
    monkeypatch.setattr(signing_keys, "_create_managed_openbao_transit_key", fake_create)

    request = _build_request("org_123")
    response = await signing_keys.sign_payload_with_service(
        request=request,
        service_id=signing_keys.MANAGED_OPENBAO_SERVICE_ID,
        body={"payload_b64": "aGVsbG8", "algorithm": "ES256"},
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    assert data["signature_encoding"] == "raw_ieee_p1363"
    assert sign_attempts == 2
    assert created == [("cred-issuer-marty-es256", "ES256")]


@pytest.mark.asyncio
async def test_sign_payload_rejects_invalid_base64(monkeypatch: pytest.MonkeyPatch):
    """sign_payload_with_service should return 400 for invalid base64."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.sign_payload_with_service(
            request=request,
            service_id="svc-bao",
            body={"payload_b64": "!@#$%invalid"},
            organization_id=None,
        )

    assert exc_info.value.status_code == 400
    assert "payload_b64" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_sign_payload_returns_400_when_no_adapter(monkeypatch: pytest.MonkeyPatch):
    """sign_payload_with_service should return 400 when no adapter is available."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: None)

    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request("org_123")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.sign_payload_with_service(
            request=request,
            service_id="svc-bao",
            body={"payload_b64": "dGVzdA=="},
            organization_id=None,
        )

    assert exc_info.value.status_code == 400
    assert "No adapter found" in str(exc_info.value.detail)


# =============================================================================
# Public did:web resolution endpoints
# =============================================================================


def _build_public_request(
    redis_client: AsyncMock | None = None,
    path: str = "/orgs/acme/did.json",
) -> Request:
    """Build a request for public (no auth) did:web resolution endpoints."""
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": path,
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("testclient", 1234),
        "server": ("testserver", 80),
        "state": {},
        "app": SimpleNamespace(state=SimpleNamespace(redis_client=redis_client)),
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


@pytest.mark.asyncio
async def test_resolve_did_web_by_slug_returns_404_when_no_mapping(monkeypatch: pytest.MonkeyPatch):
    """resolve_did_web_by_slug should 404 when the slug has no Redis mapping."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)

    request = _build_public_request(redis_client=redis_mock)

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.resolve_did_web_by_slug(request=request, org_slug="unknown-org")

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_resolve_did_web_by_slug_returns_did_document(monkeypatch: pytest.MonkeyPatch):
    """resolve_did_web_by_slug should return the stored DID document."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    did_doc = {
        "id": "did:web:beta.elevenidllc.com:orgs:acme",
        "controller": "did:web:beta.elevenidllc.com:orgs:acme",
        "verificationMethod": [{"id": "#key-1", "type": "JsonWebKey"}],
        "assertionMethod": ["#key-1"],
    }

    redis_mock = AsyncMock()

    async def fake_get(key):
        if key == "did-web-slug:acme":
            return "org_acme_123"
        if key == "org:org_acme_123:signing-key-did-document":
            return json.dumps(did_doc)
        return None

    redis_mock.get = AsyncMock(side_effect=fake_get)
    request = _build_public_request(redis_client=redis_mock)

    response = await signing_keys.resolve_did_web_by_slug(request=request, org_slug="acme")

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["id"] == "did:web:beta.elevenidllc.com:orgs:acme"
    assert len(data["verificationMethod"]) == 1
    assert response.headers.get("content-type") == "application/did+json"
    assert "max-age=300" in response.headers.get("cache-control", "")


@pytest.mark.asyncio
async def test_resolve_did_web_by_slug_rejects_invalid_slug(monkeypatch: pytest.MonkeyPatch):
    """resolve_did_web_by_slug should 400 on slugs with invalid characters."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    redis_mock = AsyncMock()
    request = _build_public_request(redis_client=redis_mock)

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.resolve_did_web_by_slug(request=request, org_slug="../../etc/passwd")

    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_resolve_did_web_root_returns_404_when_no_default_org(monkeypatch: pytest.MonkeyPatch):
    """resolve_did_web_root should 404 when DEFAULT_ORG_ID is not set."""
    monkeypatch.delenv("DEFAULT_ORG_ID", raising=False)
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    redis_mock = AsyncMock()
    request = _build_public_request(redis_client=redis_mock, path="/.well-known/did.json")

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.resolve_did_web_root(request=request)

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_resolve_did_web_root_returns_document_when_configured(monkeypatch: pytest.MonkeyPatch):
    """resolve_did_web_root should return the DID document when DEFAULT_ORG_ID is set."""
    monkeypatch.setenv("DEFAULT_ORG_ID", "org_root")
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    did_doc = {
        "id": "did:web:beta.elevenidllc.com",
        "controller": "did:web:beta.elevenidllc.com",
        "verificationMethod": [],
        "assertionMethod": [],
    }

    redis_mock = AsyncMock()

    async def fake_get(key):
        if key == "org:org_root:signing-key-did-document":
            return json.dumps(did_doc)
        return None

    redis_mock.get = AsyncMock(side_effect=fake_get)
    request = _build_public_request(redis_client=redis_mock, path="/.well-known/did.json")

    response = await signing_keys.resolve_did_web_root(request=request)

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["id"] == "did:web:beta.elevenidllc.com"
    assert response.headers.get("content-type") == "application/did+json"


@pytest.mark.asyncio
async def test_resolve_did_web_root_retargets_org_scoped_document(monkeypatch: pytest.MonkeyPatch):
    """Root did:web resolution should remain valid when the org stores a path DID."""
    monkeypatch.setenv("DEFAULT_ORG_ID", "org_root")
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    did_doc = {
        "id": "did:web:beta.elevenidllc.com:orgs:marty",
        "controller": "did:web:beta.elevenidllc.com:orgs:marty",
        "verificationMethod": [
            {
                "id": "did:web:beta.elevenidllc.com:orgs:marty#cred-issuer-marty-es256",
                "type": "JsonWebKey",
                "controller": "did:web:beta.elevenidllc.com:orgs:marty",
                "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
            }
        ],
        "assertionMethod": ["did:web:beta.elevenidllc.com:orgs:marty#cred-issuer-marty-es256"],
    }

    redis_mock = AsyncMock()

    async def fake_get(key):
        if key == "org:org_root:signing-key-did-document":
            return json.dumps(did_doc)
        return None

    redis_mock.get = AsyncMock(side_effect=fake_get)
    request = _build_public_request(redis_client=redis_mock, path="/.well-known/did.json")

    response = await signing_keys.resolve_did_web_root(request=request)

    data = json.loads(response.body)
    assert data["id"] == "did:web:beta.elevenidllc.com"
    assert data["verificationMethod"][0]["id"] == "did:web:beta.elevenidllc.com#cred-issuer-marty-es256"
    assert data["verificationMethod"][0]["controller"] == "did:web:beta.elevenidllc.com"
    assert data["assertionMethod"] == ["did:web:beta.elevenidllc.com#cred-issuer-marty-es256"]


@pytest.mark.asyncio
async def test_publish_service_to_did_stores_slug_mapping(monkeypatch: pytest.MonkeyPatch):
    """publish_service_to_did should store the did-web-slug mapping when org_slug is provided."""
    test_service = {
        "id": "svc-bao",
        "service_type": "openbao-transit",
        "key_reference": "cred-issuer-es256",
        "algorithms": ["ES256"],
    }

    async def fake_load_registry(request, org_id):
        return {"services": [test_service], "default_service_id": None}

    monkeypatch.setattr(signing_keys, "_load_registered_service_registry", fake_load_registry)
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    class FakeAdapter:
        async def get_public_key_jwk(self, config: dict):
            return {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}

    monkeypatch.setattr(signing_keys, "_get_adapter", lambda cfg: FakeAdapter())

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)
    redis_mock.set = AsyncMock()

    request = _build_request("org_123", redis_client=redis_mock)
    response = await signing_keys.publish_service_to_did(
        request=request,
        service_id="svc-bao",
        body={"org_slug": "acme-corp", "fragment": "issuer-key"},
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True

    # Verify that the slug mapping was stored via redis_mock.set
    set_calls = redis_mock.set.call_args_list
    slug_key_stored = any(
        "did-web-slug:acme-corp" in str(call) for call in set_calls
    )
    assert slug_key_stored, f"Expected slug mapping in redis.set calls: {set_calls}"


# =============================================================================
# Issuer Profile CRUD
# =============================================================================


@pytest.mark.asyncio
async def test_create_issuer_profile_stores_profile(monkeypatch: pytest.MonkeyPatch):
    """create_issuer_profile should persist a new profile in Redis."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    stored = {}
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)

    async def fake_set(key, value):
        stored[key] = value

    redis_mock.set = AsyncMock(side_effect=fake_set)

    async def fake_resolve_effective_service(*args, **kwargs):
        return (
            {"services": []},
            {"id": "svc-bao"},
            {"id": "svc-bao", "key_reference": "cred-issuer-test-es256"},
            True,
        )

    async def fake_publish_service_to_did(*args, **kwargs):
        from fastapi.responses import JSONResponse

        return JSONResponse(content={"ok": True})

    monkeypatch.setattr(signing_keys, "_resolve_effective_service", fake_resolve_effective_service)
    monkeypatch.setattr(signing_keys, "publish_service_to_did", fake_publish_service_to_did)

    request = _build_request("org_issuer", redis_client=redis_mock)
    response = await signing_keys.create_issuer_profile(
        request=request,
        body={
            "name": "My Issuer",
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
            "signing_service_id": "svc-bao",
            "key_purpose": "vc_jwt_issuer",
            "status": "active",
        },
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    profile = data["profile"]
    assert profile["name"] == "My Issuer"
    assert profile["issuer_did"] == "did:web:beta.elevenidllc.com:orgs:acme"
    assert profile["signing_service_id"] == "svc-bao"
    assert profile["issuer_mode"] == "org_managed"
    assert profile["status"] == "active"
    assert profile["id"].startswith("ip-")

    # Verify stored in Redis
    assert "org:org_issuer:issuer-profiles" in stored


@pytest.mark.asyncio
async def test_create_issuer_profile_duplicate_tuple_returns_existing_without_republishing(
    monkeypatch: pytest.MonkeyPatch,
):
    """Duplicate DID/service/key/purpose creates should be idempotent."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    stored: dict[str, str] = {}
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(side_effect=lambda key: stored.get(key))

    async def fake_set(key, value):
        stored[key] = value

    redis_mock.set = AsyncMock(side_effect=fake_set)

    async def fake_resolve_effective_service(*args, **kwargs):
        return (
            {"services": []},
            {"id": "svc-bao"},
            {"id": "svc-bao", "key_reference": "cred-issuer-test-es256"},
            True,
        )

    publish_count = 0

    async def fake_publish_service_to_did(*args, **kwargs):
        nonlocal publish_count
        publish_count += 1
        from fastapi.responses import JSONResponse

        return JSONResponse(
            content={
                "ok": True,
                "verification_method": {
                    "id": "did:web:beta.elevenidllc.com:orgs:acme#cred-issuer-test-es256",
                },
            }
        )

    monkeypatch.setattr(signing_keys, "_resolve_effective_service", fake_resolve_effective_service)
    monkeypatch.setattr(signing_keys, "publish_service_to_did", fake_publish_service_to_did)

    request = _build_request("org_issuer", redis_client=redis_mock)
    body = {
        "name": "My Issuer",
        "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
        "signing_service_id": "svc-bao",
        "key_purpose": "vc_jwt_issuer",
        "status": "active",
    }

    first = await signing_keys.create_issuer_profile(request=request, body=body, organization_id=None)
    second = await signing_keys.create_issuer_profile(
        request=request,
        body={**body, "name": "Same Key, New Label"},
        organization_id=None,
    )

    first_body = json.loads(first.body)
    second_body = json.loads(second.body)
    assert first_body["created"] is True
    assert second_body["created"] is False
    assert second_body["profile"]["id"] == first_body["profile"]["id"]
    assert second_body["profile"]["name"] == "My Issuer"
    assert publish_count == 1
    saved_profiles = json.loads(stored["org:org_issuer:issuer-profiles"])["profiles"]
    assert len(saved_profiles) == 1


@pytest.mark.asyncio
async def test_create_issuer_profile_duplicate_repairs_stale_draft(
    monkeypatch: pytest.MonkeyPatch,
):
    """Duplicate active creates should repair a stale draft tuple instead of adding another profile."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    storage_key = "org:org_issuer:issuer-profiles"
    stored: dict[str, str] = {
        storage_key: json.dumps(
            {
                "profiles": [
                    {
                        "id": "ip-stale",
                        "organization_id": "org_issuer",
                        "name": "Stale Draft",
                        "issuer_mode": "org_managed",
                        "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
                        "signing_service_id": "svc-bao",
                        "signing_key_reference": "",
                        "verification_method_id": "",
                        "algorithm": "",
                        "status": "draft",
                        "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-01T00:00:00Z",
                    }
                ]
            }
        )
    }
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(side_effect=lambda key: stored.get(key))

    async def fake_set(key, value):
        stored[key] = value

    redis_mock.set = AsyncMock(side_effect=fake_set)

    async def fake_resolve_effective_service(*args, **kwargs):
        return (
            {"services": []},
            {"id": "svc-bao"},
            {"id": "svc-bao", "key_reference": "cred-issuer-test-es256"},
            True,
        )

    publish_count = 0

    async def fake_publish_service_to_did(*args, **kwargs):
        nonlocal publish_count
        publish_count += 1
        from fastapi.responses import JSONResponse

        return JSONResponse(
            content={
                "ok": True,
                "verification_method": {
                    "id": "did:web:beta.elevenidllc.com:orgs:acme#cred-issuer-test-es256",
                },
            }
        )

    monkeypatch.setattr(signing_keys, "_resolve_effective_service", fake_resolve_effective_service)
    monkeypatch.setattr(signing_keys, "publish_service_to_did", fake_publish_service_to_did)

    request = _build_request("org_issuer", redis_client=redis_mock)
    response = await signing_keys.create_issuer_profile(
        request=request,
        body={
            "name": "Activated Issuer",
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
            "signing_service_id": "svc-bao",
            "key_purpose": "vc_jwt_issuer",
            "status": "active",
        },
        organization_id=None,
    )

    response_body = json.loads(response.body)
    assert response_body["created"] is False
    assert response_body["profile"]["id"] == "ip-stale"
    assert response_body["profile"]["status"] == "active"
    assert response_body["profile"]["signing_key_reference"] == "cred-issuer-test-es256"
    assert response_body["profile"]["key_purpose"] == "vc_jwt_issuer"
    assert response_body["profile"]["verification_method_id"] == "did:web:beta.elevenidllc.com:orgs:acme#cred-issuer-test-es256"
    assert publish_count == 1

    saved_profiles = json.loads(stored[storage_key])["profiles"]
    assert len(saved_profiles) == 1
    assert saved_profiles[0]["id"] == "ip-stale"
    assert saved_profiles[0]["status"] == "active"
    assert saved_profiles[0]["key_purpose"] == "vc_jwt_issuer"
    assert saved_profiles[0]["verification_method_id"] == "did:web:beta.elevenidllc.com:orgs:acme#cred-issuer-test-es256"


@pytest.mark.asyncio
async def test_create_issuer_profile_rejects_missing_did(monkeypatch: pytest.MonkeyPatch):
    """create_issuer_profile should 422 when issuer_did is absent."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    redis_mock = AsyncMock()
    request = _build_request("org_issuer", redis_client=redis_mock)

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.create_issuer_profile(
            request=request,
            body={"name": "Missing DID", "signing_service_id": "svc-bao"},
            organization_id=None,
        )

    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
async def test_list_issuer_profiles_returns_all(monkeypatch: pytest.MonkeyPatch):
    """list_issuer_profiles should return all stored profiles."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    profiles_doc = json.dumps({
        "profiles": [
            {"id": "ip-1", "name": "A", "issuer_did": "did:web:a", "signing_service_id": "svc-1"},
            {"id": "ip-2", "name": "B", "issuer_did": "did:web:b", "signing_service_id": "svc-2"},
        ]
    })

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=profiles_doc)

    request = _build_request("org_issuer", redis_client=redis_mock)
    response = await signing_keys.list_issuer_profiles(request=request, organization_id=None)

    assert response.status_code == 200
    data = json.loads(response.body)
    assert len(data["profiles"]) == 2
    assert data["profiles"][0]["id"] == "ip-1"


@pytest.mark.asyncio
async def test_get_issuer_profile_returns_single(monkeypatch: pytest.MonkeyPatch):
    """get_issuer_profile should return a single profile by ID."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    profiles_doc = json.dumps({
        "profiles": [
            {"id": "ip-1", "name": "A", "issuer_did": "did:web:a", "signing_service_id": "svc-1"},
            {"id": "ip-2", "name": "B", "issuer_did": "did:web:b", "signing_service_id": "svc-2"},
        ]
    })

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=profiles_doc)

    request = _build_request("org_issuer", redis_client=redis_mock)
    response = await signing_keys.get_issuer_profile(
        request=request, profile_id="ip-2", organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["profile"]["id"] == "ip-2"
    assert data["profile"]["name"] == "B"


@pytest.mark.asyncio
async def test_get_issuer_profile_returns_404_when_missing(monkeypatch: pytest.MonkeyPatch):
    """get_issuer_profile should 404 for unknown profile_id."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)

    request = _build_request("org_issuer", redis_client=redis_mock)

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.get_issuer_profile(
            request=request, profile_id="ip-nope", organization_id=None,
        )

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_update_issuer_profile_patches_fields(monkeypatch: pytest.MonkeyPatch):
    """update_issuer_profile should update only supplied fields."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    existing = {
        "profiles": [{
            "id": "ip-1",
            "organization_id": "org_issuer",
            "name": "Old Name",
            "issuer_did": "did:web:a",
            "signing_service_id": "svc-1",
            "key_purpose": "vc_jwt_issuer",
            "status": "draft",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }]
    }

    stored = {}
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=json.dumps(existing))

    async def fake_set(key, value):
        stored[key] = value

    redis_mock.set = AsyncMock(side_effect=fake_set)

    async def fake_resolve_effective_service(*args, **kwargs):
        registry = {
            "key_reference_purposes": {
                "svc-1": {"cred-issuer-test-es256": ["vc_jwt_issuer"]},
            }
        }
        service = {
            "id": "svc-1",
            "service_type": "openbao-transit",
            "key_reference": "cred-issuer-test-es256",
            "key_purposes": ["vc_jwt_issuer"],
            "algorithms": ["ES256"],
        }
        return registry, service, service, True

    monkeypatch.setattr(
        signing_keys,
        "_resolve_effective_service",
        fake_resolve_effective_service,
    )

    request = _build_request("org_issuer", redis_client=redis_mock)
    response = await signing_keys.update_issuer_profile(
        request=request,
        profile_id="ip-1",
        body={"name": "New Name", "status": "active"},
        organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["profile"]["name"] == "New Name"
    assert data["profile"]["status"] == "active"
    # Preserved fields
    assert data["profile"]["issuer_did"] == "did:web:a"
    assert data["profile"]["created_at"] == "2026-01-01T00:00:00Z"


@pytest.mark.asyncio
async def test_delete_issuer_profile_removes_entry(monkeypatch: pytest.MonkeyPatch):
    """delete_issuer_profile should remove the profile and persist."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    existing = {
        "profiles": [
            {"id": "ip-1", "name": "Keep"},
            {"id": "ip-2", "name": "Delete"},
        ]
    }

    stored = {}
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=json.dumps(existing))

    async def fake_set(key, value):
        stored[key] = json.loads(value)

    redis_mock.set = AsyncMock(side_effect=fake_set)

    request = _build_request("org_issuer", redis_client=redis_mock)
    response = await signing_keys.delete_issuer_profile(
        request=request, profile_id="ip-2", organization_id=None,
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["deleted"] == "ip-2"

    # Verify only ip-1 remains
    saved_profiles = stored["org:org_issuer:issuer-profiles"]["profiles"]
    assert len(saved_profiles) == 1
    assert saved_profiles[0]["id"] == "ip-1"


@pytest.mark.asyncio
async def test_delete_issuer_profile_returns_404_when_missing(monkeypatch: pytest.MonkeyPatch):
    """delete_issuer_profile should 404 for unknown profile_id."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=json.dumps({"profiles": []}))

    request = _build_request("org_issuer", redis_client=redis_mock)

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.delete_issuer_profile(
            request=request, profile_id="ip-ghost", organization_id=None,
        )

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_internal_resolve_issuer_context_uses_explicit_profile(monkeypatch: pytest.MonkeyPatch):
    """Explicit issuer_profile_id should select that profile instead of first active."""
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-internal-key")
    docs = {
        "org:org_issuer:issuer-profiles": {
            "profiles": [
                {
                    "id": "ip-first",
                    "organization_id": "org_issuer",
                    "issuer_mode": "org_managed",
                    "issuer_did": "did:web:beta.elevenidllc.com:orgs:first",
                    "signing_service_id": "svc-first",
                    "key_purpose": "vc_jwt_issuer",
                    "status": "active",
                },
                {
                    "id": "ip-selected",
                    "organization_id": "org_issuer",
                    "issuer_mode": "elevenid_managed",
                    "issuer_did": "did:web:beta.elevenidllc.com:orgs:elevenid",
                    "signing_service_id": "svc-selected",
                    "signing_key_reference": "cred-issuer-elevenid-es256",
                    "key_purpose": "vc_jwt_issuer",
                    "status": "active",
                },
            ]
        },
        "org:org_issuer:signing-key-services": {
            "services": [
                {
                    "id": "svc-first",
                    "service_type": "custom-transit-compatible",
                    "key_reference": "cred-issuer-first-es256",
                    "key_purposes": ["vc_jwt_issuer"],
                    "credential_formats": ["dc+sd-jwt"],
                    "algorithms": ["ES256"],
                },
                {
                    "id": "svc-selected",
                    "service_type": "custom-transit-compatible",
                    "key_reference": "cred-issuer-elevenid-es256",
                    "key_purposes": ["vc_jwt_issuer"],
                    "credential_formats": ["dc+sd-jwt"],
                    "algorithms": ["ES256"],
                },
            ],
            "default_service_id": "svc-first",
        },
    }
    redis_mock = AsyncMock()

    async def fake_get(key):
        value = docs.get(key)
        return json.dumps(value) if value is not None else None

    redis_mock.get = AsyncMock(side_effect=fake_get)
    request = _build_request("org_issuer", redis_client=redis_mock)
    monkeypatch.setattr(
        signing_keys,
        "_service_x5c_chain",
        lambda service: ["issuer-leaf-x5c", "issuer-intermediate-x5c"],
    )

    response = await signing_keys.internal_resolve_issuer_context(
        request=request,
        organization_id="org_issuer",
        issuer_profile_id="ip-selected",
        issuer_mode="org_managed",
        credential_format="dc+sd-jwt",
        key_purpose="vc_jwt_issuer",
        algorithm="ES256",
        x_api_key="test-internal-key",
    )

    data = json.loads(response.body)
    assert data["ok"] is True
    assert data["issuer_profile_id"] == "ip-selected"
    assert data["issuer_mode"] == "elevenid_managed"
    assert data["issuer_did"] == "did:web:beta.elevenidllc.com:orgs:elevenid"
    assert data["signing_service_id"] == "svc-selected"
    assert data["mdoc_x5c"] == ["issuer-leaf-x5c", "issuer-intermediate-x5c"]


@pytest.mark.asyncio
async def test_internal_resolve_issuer_context_defaults_to_org_managed_mode(monkeypatch: pytest.MonkeyPatch):
    """Hosted ElevenID profiles must not become implicit defaults."""
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-internal-key")
    docs = {
        "org:org_issuer:issuer-profiles": {
            "profiles": [
                {
                    "id": "ip-hosted",
                    "organization_id": "org_issuer",
                    "issuer_mode": "elevenid_managed",
                    "issuer_did": "did:web:beta.elevenidllc.com:orgs:elevenid",
                    "signing_service_id": "svc-hosted",
                    "key_purpose": "vc_jwt_issuer",
                    "status": "active",
                },
                {
                    "id": "ip-org",
                    "organization_id": "org_issuer",
                    "issuer_mode": "org_managed",
                    "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
                    "signing_service_id": "svc-org",
                    "key_purpose": "vc_jwt_issuer",
                    "status": "active",
                },
            ]
        },
        "org:org_issuer:signing-key-services": {
            "services": [
                {
                    "id": "svc-hosted",
                    "service_type": "custom-transit-compatible",
                    "key_reference": "cred-issuer-elevenid-es256",
                    "key_purposes": ["vc_jwt_issuer"],
                    "credential_formats": ["dc+sd-jwt"],
                    "algorithms": ["ES256"],
                },
                {
                    "id": "svc-org",
                    "service_type": "custom-transit-compatible",
                    "key_reference": "cred-issuer-acme-es256",
                    "key_purposes": ["vc_jwt_issuer"],
                    "credential_formats": ["dc+sd-jwt"],
                    "algorithms": ["ES256"],
                },
            ],
            "default_service_id": "svc-hosted",
        },
    }
    redis_mock = AsyncMock()

    async def fake_get(key):
        value = docs.get(key)
        return json.dumps(value) if value is not None else None

    redis_mock.get = AsyncMock(side_effect=fake_get)
    request = _build_request("org_issuer", redis_client=redis_mock)

    response = await signing_keys.internal_resolve_issuer_context(
        request=request,
        organization_id="org_issuer",
        issuer_profile_id=None,
        issuer_mode="org_managed",
        credential_format="dc+sd-jwt",
        key_purpose="vc_jwt_issuer",
        algorithm="ES256",
        x_api_key="test-internal-key",
    )

    data = json.loads(response.body)
    assert data["issuer_profile_id"] == "ip-org"
    assert data["issuer_mode"] == "org_managed"
    assert data["issuer_did"] == "did:web:beta.elevenidllc.com:orgs:acme"
    assert data["signing_service_id"] == "svc-org"


@pytest.mark.asyncio
async def test_internal_resolve_issuer_context_rejects_unknown_explicit_profile(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-internal-key")
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=json.dumps({"profiles": []}))
    request = _build_request("org_issuer", redis_client=redis_mock)

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.internal_resolve_issuer_context(
            request=request,
            organization_id="org_issuer",
            issuer_profile_id="ip-missing",
            issuer_mode="org_managed",
            credential_format="dc+sd-jwt",
            key_purpose="vc_jwt_issuer",
            algorithm="ES256",
            x_api_key="test-internal-key",
        )

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_internal_resolve_issuer_context_rejects_profile_without_requested_key_purpose(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-internal-key")
    docs = {
        "org:org_issuer:issuer-profiles": {
            "profiles": [
                {
                    "id": "ip-unscoped",
                    "organization_id": "org_issuer",
                    "issuer_mode": "org_managed",
                    "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
                    "signing_service_id": "svc-org",
                    "status": "active",
                },
            ]
        },
        "org:org_issuer:signing-key-services": {
            "services": [
                {
                    "id": "svc-org",
                    "service_type": "custom-transit-compatible",
                    "key_reference": "cred-issuer-acme-es256",
                    "key_purposes": ["vc_jwt_issuer"],
                    "credential_formats": ["dc+sd-jwt"],
                    "algorithms": ["ES256"],
                },
            ],
            "default_service_id": "svc-org",
        },
    }
    redis_mock = AsyncMock()

    async def fake_get(key):
        value = docs.get(key)
        return json.dumps(value) if value is not None else None

    redis_mock.get = AsyncMock(side_effect=fake_get)
    request = _build_request("org_issuer", redis_client=redis_mock)

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.internal_resolve_issuer_context(
            request=request,
            organization_id="org_issuer",
            issuer_profile_id="ip-unscoped",
            issuer_mode="org_managed",
            credential_format="dc+sd-jwt",
            key_purpose="vc_jwt_issuer",
            algorithm="ES256",
            x_api_key="test-internal-key",
        )

    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_internal_resolve_issuer_did_returns_org_scoped_public_key(monkeypatch: pytest.MonkeyPatch):
    """Internal DID resolver should use the org issuer profile and DID document."""
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-internal-key")
    issuer_did = "did:web:beta.elevenidllc.com:orgs:acme"
    vm_id = f"{issuer_did}#cred-issuer-acme-es256"
    docs = {
        "org:org_issuer:issuer-profiles": {
            "profiles": [
                {
                    "id": "ip-1",
                    "organization_id": "org_issuer",
                    "issuer_did": issuer_did,
                    "signing_service_id": "svc-bao",
                    "signing_key_reference": "cred-issuer-acme-es256",
                    "verification_method_id": vm_id,
                    "key_purpose": "vc_jwt_issuer",
                    "algorithm": "ES256",
                    "status": "active",
                }
            ]
        },
        "org:org_issuer:signing-key-services": {
            "services": [
                {
                    "id": "svc-bao",
                    "name": "Acme issuer signer",
                    "service_type": "custom-transit-compatible",
                    "key_reference": "cred-issuer-acme-es256",
                    "key_purposes": ["vc_jwt_issuer"],
                    "credential_formats": ["dc+sd-jwt"],
                    "algorithms": ["ES256"],
                }
            ],
            "default_service_id": "svc-bao",
        },
        "org:org_issuer:signing-key-did-document": {
            "id": issuer_did,
            "controller": issuer_did,
            "verificationMethod": [
                {
                    "id": vm_id,
                    "type": "JsonWebKey",
                    "controller": issuer_did,
                    "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
                }
            ],
            "assertionMethod": [vm_id],
        },
    }

    redis_mock = AsyncMock()

    async def fake_get(key):
        value = docs.get(key)
        return json.dumps(value) if value is not None else None

    redis_mock.get = AsyncMock(side_effect=fake_get)
    request = _build_request("org_issuer", redis_client=redis_mock)

    response = await signing_keys.internal_resolve_issuer_did(
        request=request,
        organization_id="org_issuer",
        issuer_did=issuer_did,
        verification_method_id=vm_id,
        credential_format="dc+sd-jwt",
        key_purpose="vc_jwt_issuer",
        algorithm="ES256",
        x_api_key="test-internal-key",
    )

    assert response.status_code == 200
    data = json.loads(response.body)
    assert data["ok"] is True
    assert data["issuer_did"] == issuer_did
    assert data["verification_method_id"] == vm_id
    assert data["public_jwk"]["kid"] == vm_id
    assert data["public_jwk"]["kty"] == "EC"
    assert data["signing_service"]["id"] == "svc-bao"
    assert "auth_reference" not in data["signing_service"]


@pytest.mark.asyncio
async def test_internal_resolve_issuer_did_rejects_unscoped_profile_for_requested_key_purpose(monkeypatch: pytest.MonkeyPatch):
    """Internal DID resolver should not use an unscoped issuer profile for a purpose-specific path."""
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-internal-key")
    issuer_did = "did:web:beta.elevenidllc.com:orgs:acme"
    docs = {
        "org:org_issuer:issuer-profiles": {
            "profiles": [
                {
                    "id": "ip-unscoped",
                    "organization_id": "org_issuer",
                    "issuer_did": issuer_did,
                    "signing_service_id": "svc-bao",
                    "signing_key_reference": "cred-issuer-acme-es256",
                    "status": "active",
                }
            ]
        },
    }

    redis_mock = AsyncMock()

    async def fake_get(key):
        value = docs.get(key)
        return json.dumps(value) if value is not None else None

    redis_mock.get = AsyncMock(side_effect=fake_get)
    request = _build_request("org_issuer", redis_client=redis_mock)

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.internal_resolve_issuer_did(
            request=request,
            organization_id="org_issuer",
            issuer_did=issuer_did,
            verification_method_id=None,
            credential_format="dc+sd-jwt",
            key_purpose="vc_jwt_issuer",
            algorithm="ES256",
            x_api_key="test-internal-key",
        )

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_internal_resolve_issuer_did_rejects_unknown_org_issuer(monkeypatch: pytest.MonkeyPatch):
    """Internal DID resolver should fail closed when issuer DID is not active for org."""
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-internal-key")
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=json.dumps({"profiles": []}))
    request = _build_request("org_issuer", redis_client=redis_mock)

    from fastapi import HTTPException as FastAPIHTTPException

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await signing_keys.internal_resolve_issuer_did(
            request=request,
            organization_id="org_issuer",
            issuer_did="did:web:beta.elevenidllc.com:orgs:other",
            verification_method_id=None,
            credential_format="dc+sd-jwt",
            key_purpose="vc_jwt_issuer",
            algorithm="ES256",
            x_api_key="test-internal-key",
        )

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("route_name", "kwargs"),
    [
        ("list_signing_keys", {}),
        ("create_signing_key", {"body": {"name": "issuer", "algorithm": "ES256"}}),
        ("get_signing_key_config", {}),
        ("update_signing_key_config", {"body": {"services": []}}),
        ("generate_csr", {"service_id": "svc-1"}),
        ("store_service_certificate", {"service_id": "svc-1", "body": {"cert_pem": "cert"}}),
        ("get_service_certificate", {"service_id": "svc-1"}),
        ("list_certificate_expiry_alerts", {"days_until_expiry": 30}),
        ("publish_service_to_jwks", {"service_id": "svc-1", "body": {}}),
        ("publish_service_to_did", {"service_id": "svc-1", "body": {}}),
        ("sign_payload_with_service", {"service_id": "svc-1", "body": {"payload_b64": "dGVzdA"}}),
        ("rotate_service_key", {"service_id": "svc-1", "body": {}}),
        ("verify_service_public_key", {"service_id": "svc-1"}),
        ("get_key_audit_log", {"service_id": "svc-1"}),
        ("get_keys_compliance_summary", {}),
        ("get_signing_key", {"key_id": "key-1"}),
        ("update_signing_key", {"key_id": "key-1", "body": {"name": "Issuer"}}),
        ("delete_signing_key", {"key_id": "key-1"}),
    ],
)
async def test_org_scoped_signing_key_routes_require_org_context(route_name: str, kwargs: dict):
    """Org-scoped signing-key routes must fail before touching default/global storage."""
    from fastapi import HTTPException as FastAPIHTTPException

    request = _build_request(session_org_id=None)
    route = getattr(signing_keys, route_name)

    with pytest.raises(FastAPIHTTPException) as exc_info:
        await route(request=request, organization_id=None, **kwargs)

    assert exc_info.value.status_code == 422
    assert "organization_id is required" in str(exc_info.value.detail)
