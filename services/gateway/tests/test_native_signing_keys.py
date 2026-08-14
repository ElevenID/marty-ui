from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest

from gateway import proxy
from gateway.native_signing_keys import (
    bind_native_issuer_profile_registry,
    calculate_native_certificate_alerts,
    delete_native_signing_jwk,
    delete_native_issuer_profile,
    find_native_duplicate_issuer_profile,
    find_native_issuer_profiles,
    get_native_certificate_overrides,
    get_native_signing_jwks,
    get_native_signing_service_catalog,
    get_native_kms_adapter,
    get_native_issuer_profile,
    inspect_native_signing_certificate,
    load_native_signing_did_document,
    load_native_signing_registry,
    list_native_issuer_profiles,
    normalize_native_issuer_profile,
    normalize_native_signing_registry,
    normalize_native_signing_service,
    publish_native_signing_did,
    publish_native_signing_jwk,
    resolve_native_did_web_slug,
    resolve_native_profile_custody_format,
    resolve_native_signing_registry,
    save_native_signing_registry,
    save_native_issuer_profile,
    store_native_signing_certificate,
    update_native_signing_jwk,
    validate_native_signing_service,
    validate_native_issuer_profile_binding,
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


@pytest.mark.asyncio
async def test_native_registry_wrappers_forward_language_neutral_vectors(
    restore_proxy_globals,
):
    fixture_path = (
        Path(__file__).parents[3]
        / "rust"
        / "services"
        / "signing-keys"
        / "tests"
        / "fixtures"
        / "registry_vectors.json"
    )
    vectors = json.loads(fixture_path.read_text(encoding="utf-8"))
    normalize_service_case = vectors["normalize_service_cases"][0]
    normalize_registry_case = vectors["normalize_registry_cases"][0]
    resolve_case = vectors["resolve_cases"][0]
    captured: list[tuple[str, dict | None, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content) if request.content else None
        captured.append((request.url.path, payload, request.headers.get("x-api-key")))
        responses = {
            "/internal/registry/normalize-service": {
                "service": normalize_service_case["expected"]
            },
            "/internal/registry/normalize": {
                "registry": normalize_registry_case["expected"]
            },
            "/internal/registry/resolve": resolve_case["expected"],
            "/internal/registry/catalog": {
                "service_types": [{"id": "aws-kms", "label": "AWS KMS"}]
            },
            "/internal/registry/org/alpha": normalize_registry_case["expected"],
        }
        return httpx.Response(200, json=responses[request.url.path], request=request)

    proxy._registry = ServiceRegistry()
    proxy._registry._services["signing-keys"] = "http://rust-signing"
    proxy._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        service = await normalize_native_signing_service(
            normalize_service_case["input"]
        )
        registry = await normalize_native_signing_registry(
            normalize_registry_case["input"], mode=normalize_registry_case["mode"]
        )
        resolved = await resolve_native_signing_registry(**resolve_case["input"])
        catalog = await get_native_signing_service_catalog()
        loaded = await load_native_signing_registry("org/alpha")
        saved = await save_native_signing_registry(
            "org/alpha", normalize_registry_case["input"]
        )
    finally:
        await proxy._http_client.aclose()

    assert service == normalize_service_case["expected"]
    assert registry == normalize_registry_case["expected"]
    assert resolved == (
        resolve_case["expected"]["service"],
        resolve_case["expected"]["key_reference"],
    )
    assert catalog == [{"id": "aws-kms", "label": "AWS KMS"}]
    assert loaded == normalize_registry_case["expected"]
    assert saved == normalize_registry_case["expected"]
    assert [entry[0] for entry in captured] == [
        "/internal/registry/normalize-service",
        "/internal/registry/normalize",
        "/internal/registry/resolve",
        "/internal/registry/catalog",
        "/internal/registry/org/alpha",
        "/internal/registry/org/alpha",
    ]
    assert all(entry[2] == "test-internal-api-key" for entry in captured)
    assert captured[-1][1] == {"registry": normalize_registry_case["input"]}


@pytest.mark.asyncio
async def test_native_profile_wrappers_forward_language_neutral_vectors(
    restore_proxy_globals,
):
    fixture_path = (
        Path(__file__).parents[3]
        / "rust"
        / "services"
        / "signing-keys"
        / "tests"
        / "fixtures"
        / "issuer_profile_vectors.json"
    )
    vectors = json.loads(fixture_path.read_text(encoding="utf-8"))
    profile = vectors["normalize"]["expected"]
    captured: list[tuple[str, str, dict | None, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content) if request.content else None
        captured.append(
            (
                request.method,
                request.url.path,
                payload,
                request.headers.get("x-api-key"),
            )
        )
        path = request.url.path
        if path.endswith("/normalize"):
            response = {"profile": profile}
        elif path.endswith("/validate-binding"):
            response = {"ok": True}
        elif path.endswith("/custody-format"):
            response = {"wire_format": "lti_tool_jwt"}
        elif path.endswith("/find-duplicate"):
            response = {"profile": vectors["duplicate"]["expected"], "found": True}
        elif path.endswith("/find"):
            response = {"profiles": [profile]}
        elif path.endswith("/bind-profile"):
            response = {"services": [], "key_reference_purposes": {}}
        elif request.method == "GET" and path.endswith("/ip/vector"):
            response = {"profile": profile}
        elif request.method == "PUT":
            response = {"profile": profile}
        elif request.method == "DELETE":
            response = {"deleted": "ip/vector"}
        else:
            response = {"profiles": [profile]}
        return httpx.Response(200, json=response, request=request)

    proxy._registry = ServiceRegistry()
    proxy._registry._services["signing-keys"] = "http://rust-signing"
    proxy._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        assert (
            await normalize_native_issuer_profile(
                "org/alpha", vectors["normalize"]["body"], profile_id="ip/vector"
            )
            == profile
        )
        await validate_native_issuer_profile_binding("org/alpha", **vectors["binding"])
        assert (
            await resolve_native_profile_custody_format(
                "org/alpha", "SD_JWT_VC", "lti_tool_signing"
            )
            == "lti_tool_jwt"
        )
        assert await list_native_issuer_profiles("org/alpha") == [profile]
        assert await get_native_issuer_profile("org/alpha", "ip/vector") == profile
        assert await save_native_issuer_profile("org/alpha", profile) == profile
        assert await find_native_issuer_profiles(
            "org/alpha", vectors["find"]["request"]
        ) == [profile]
        duplicate, found = await find_native_duplicate_issuer_profile(
            "org/alpha", **vectors["duplicate"]["request"]
        )
        assert found and duplicate == vectors["duplicate"]["expected"]
        assert await bind_native_issuer_profile_registry("org/alpha", profile) == {
            "services": [],
            "key_reference_purposes": {},
        }
        assert (
            await delete_native_issuer_profile("org/alpha", "ip/vector") == "ip/vector"
        )
    finally:
        await proxy._http_client.aclose()

    assert all(entry[3] == "test-internal-api-key" for entry in captured)
    assert [entry[:2] for entry in captured] == [
        ("POST", "/internal/profiles/org/alpha/normalize"),
        ("POST", "/internal/profiles/org/alpha/validate-binding"),
        ("POST", "/internal/profiles/org/alpha/custody-format"),
        ("GET", "/internal/profiles/org/alpha"),
        ("GET", "/internal/profiles/org/alpha/ip/vector"),
        ("PUT", "/internal/profiles/org/alpha/ip-vector"),
        ("POST", "/internal/profiles/org/alpha/find"),
        ("POST", "/internal/profiles/org/alpha/find-duplicate"),
        ("POST", "/internal/registry/org/alpha/bind-profile"),
        ("DELETE", "/internal/profiles/org/alpha/ip/vector"),
    ]


@pytest.mark.asyncio
async def test_native_document_wrappers_forward_language_neutral_vectors(
    restore_proxy_globals,
):
    fixture_path = (
        Path(__file__).parents[3]
        / "rust"
        / "services"
        / "signing-keys"
        / "tests"
        / "fixtures"
        / "document_vectors.json"
    )
    vectors = json.loads(fixture_path.read_text(encoding="utf-8"))
    certificate = vectors["certificate"]
    captured: list[tuple[str, str, dict | None, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content) if request.content else None
        captured.append(
            (
                request.method,
                request.url.path,
                payload,
                request.headers.get("x-api-key"),
            )
        )
        path = request.url.path
        if path == "/internal/documents/certificate/inspect":
            response = {
                "expires_at": certificate["expected_expiry"],
                "public_jwk": certificate["expected_jwk"],
                "x5c": [certificate["expected_x5c"]],
            }
        elif path == "/internal/documents/certificate-alerts":
            response = {"alerts": vectors["certificate_alerts"]["expected"]}
        elif path == "/internal/documents/org/alpha/certificates":
            response = {"services": {}}
        elif path.endswith("/certificates/svc/a"):
            response = {
                "cert_pem": certificate["cert_pem"],
                "cert_chain_pem": "",
                "cert_expires_at": certificate["expected_expiry"],
            }
        elif path == "/internal/documents/org/alpha/jwks":
            response = {"organization_id": "org/alpha", "keys": []}
        elif path.endswith("/jwks/svc/a") and request.method == "PUT":
            response = {
                "jwk": vectors["jwks"]["expected_jwk"],
                "document": {"keys": [vectors["jwks"]["expected_jwk"]]},
                "key_count": 1,
            }
        elif path.endswith("/jwks/key/a") and request.method == "PATCH":
            response = {"updated": ["name"]}
        elif path.endswith("/jwks/key/a") and request.method == "DELETE":
            response = {"removed": True}
        elif path.endswith("/did/load"):
            response = {
                "document": {"id": vectors["did"]["expected_did"]},
                "found": True,
            }
        elif path.endswith("/did/svc/a"):
            response = {
                "did_id": vectors["did"]["expected_did"],
                "verification_method": {"id": vectors["did"]["expected_method_id"]},
                "document": {"id": vectors["did"]["expected_did"]},
            }
        elif path == "/internal/documents/did-web/acme":
            response = {"organization_id": "org/alpha"}
        else:  # pragma: no cover - makes an unexpected native route explicit
            raise AssertionError(f"unexpected request: {request.method} {path}")
        return httpx.Response(200, json=response, request=request)

    proxy._registry = ServiceRegistry()
    proxy._registry._services["signing-keys"] = "http://rust-signing"
    proxy._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        await inspect_native_signing_certificate(certificate["cert_pem"])
        await calculate_native_certificate_alerts(
            vectors["certificate_alerts"]["input"]["services"], 30
        )
        await get_native_certificate_overrides("org/alpha")
        await store_native_signing_certificate(
            "org/alpha", "svc/a", cert_pem=certificate["cert_pem"]
        )
        await get_native_signing_jwks("org/alpha")
        await publish_native_signing_jwk(
            "org/alpha",
            "svc/a",
            jwk=vectors["jwks"]["request"]["jwk"],
            key_reference="key-a",
        )
        assert await update_native_signing_jwk(
            "org/alpha", "key/a", {"name": "Issuer key"}
        ) == ["name"]
        assert await delete_native_signing_jwk("org/alpha", "key/a") is True
        document, found = await load_native_signing_did_document(
            "org/alpha", did_id=vectors["did"]["expected_did"]
        )
        assert found and document["id"] == vectors["did"]["expected_did"]
        await publish_native_signing_did(
            "org/alpha", "svc/a", vectors["did"]["request"]
        )
        assert await resolve_native_did_web_slug("acme") == "org/alpha"
    finally:
        await proxy._http_client.aclose()

    assert all(entry[3] == "test-internal-api-key" for entry in captured)
    assert [entry[:2] for entry in captured] == [
        ("POST", "/internal/documents/certificate/inspect"),
        ("POST", "/internal/documents/certificate-alerts"),
        ("GET", "/internal/documents/org/alpha/certificates"),
        ("PUT", "/internal/documents/org/alpha/certificates/svc/a"),
        ("GET", "/internal/documents/org/alpha/jwks"),
        ("PUT", "/internal/documents/org/alpha/jwks/svc/a"),
        ("PATCH", "/internal/documents/org/alpha/jwks/key/a"),
        ("DELETE", "/internal/documents/org/alpha/jwks/key/a"),
        ("POST", "/internal/documents/org/alpha/did/load"),
        ("PUT", "/internal/documents/org/alpha/did/svc/a"),
        ("GET", "/internal/documents/did-web/acme"),
    ]
