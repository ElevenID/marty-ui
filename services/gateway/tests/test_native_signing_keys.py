from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest

from gateway import proxy
from gateway.native_signing_keys import (
    get_native_kms_adapter,
    validate_native_signing_service,
)
from gateway.registry import ServiceRegistry


@pytest.fixture
def restore_proxy_globals(monkeypatch: pytest.MonkeyPatch):
    original_client = proxy._http_client
    original_registry = proxy._registry
    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "test-internal-api-key")
    yield
    proxy._http_client = original_client
    proxy._registry = original_registry


@pytest.mark.asyncio
async def test_native_adapter_routes_signing_and_preserves_both_encodings(
    restore_proxy_globals,
):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["json"] = __import__("json").loads(request.content)
        captured["api_key"] = request.headers.get("x-api-key")
        return httpx.Response(
            200,
            json={
                "signature_b64": "MAYCAQECAQI",
                "signature_encoding": "der",
                "transcoded_signature_b64": base64.urlsafe_b64encode(b"r" * 64)
                .decode()
                .rstrip("="),
            },
            request=request,
        )

    proxy._registry = ServiceRegistry()
    proxy._registry._services["signing-keys"] = "http://rust-signing"
    proxy._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        adapter = get_native_kms_adapter(
            {"service_type": "aws-kms", "key_reference": "key"}
        )
        assert adapter is not None
        signature = await adapter.sign(
            {"service_type": "aws-kms", "key_reference": "key"}, b"payload"
        )
    finally:
        await proxy._http_client.aclose()

    assert captured["path"] == "/internal/kms/sign"
    assert captured["json"]["payload_b64"] == "cGF5bG9hZA"
    assert captured["api_key"] == "test-internal-api-key"
    assert signature == bytes.fromhex("3006020101020102")
    assert adapter.transcoded_signature == b"r" * 64
    assert adapter.signature_encoding == "der"


@pytest.mark.asyncio
async def test_native_adapter_proxies_public_key_and_capability_results(
    restore_proxy_globals,
):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/public-key"):
            return httpx.Response(
                200,
                json={"kty": "OKP", "crv": "Ed25519", "x": "AQ"},
                request=request,
            )
        return httpx.Response(
            200,
            json={
                "ok": False,
                "checks": [
                    {
                        "name": "Authentication",
                        "status": "fail",
                        "detail": "unauthorized",
                        "source": "adapter",
                    }
                ],
            },
            request=request,
        )

    proxy._registry = ServiceRegistry()
    proxy._registry._services["signing-keys"] = "http://rust-signing"
    proxy._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        adapter = get_native_kms_adapter({"service_type": "gcp-cloud-kms"})
        assert adapter is not None
        jwk = await adapter.get_public_key_jwk({"service_type": "gcp-cloud-kms"})
        result = await adapter.verify_connection({"service_type": "gcp-cloud-kms"})
    finally:
        await proxy._http_client.aclose()

    assert jwk["kty"] == "OKP"
    assert result.ok is False
    assert result.checks[0]["name"] == "Authentication"


def test_native_adapter_support_matrix_is_fail_closed():
    for service_type in [
        "openbao-transit",
        "hashicorp-vault-transit",
        "aws-kms",
        "azure-key-vault",
        "gcp-cloud-kms",
    ]:
        assert get_native_kms_adapter({"service_type": service_type}) is not None
    assert get_native_kms_adapter({"service_type": "unknown"}) is None


@pytest.mark.asyncio
async def test_native_validation_forwards_language_neutral_vector(
    restore_proxy_globals,
):
    fixture_path = (
        Path(__file__).parents[3]
        / "rust"
        / "services"
        / "signing-keys"
        / "tests"
        / "fixtures"
        / "service_validation_vectors.json"
    )
    vector = json.loads(fixture_path.read_text(encoding="utf-8"))[0]
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        captured["api_key"] = request.headers.get("x-api-key")
        return httpx.Response(
            200,
            json={
                "ok": vector["expected_ok"],
                "checks": vector["expected_checks"],
                "validated_at": "2026-08-14T00:00:00Z",
            },
            request=request,
        )

    proxy._registry = ServiceRegistry()
    proxy._registry._services["signing-keys"] = "http://rust-signing"
    proxy._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        result = await validate_native_signing_service(vector["input"])
    finally:
        await proxy._http_client.aclose()

    assert captured == {
        "path": "/internal/config/validate",
        "body": vector["input"],
        "api_key": "test-internal-api-key",
    }
    assert result["ok"] is True
    assert result["checks"] == vector["expected_checks"]
