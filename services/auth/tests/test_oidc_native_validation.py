import json
from types import ModuleType
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from services.auth.infrastructure.adapters import oidc_adapter
from services.auth import main as auth_main
from services.auth.infrastructure.adapters.oidc_adapter import (
    KeycloakOIDCAdapter,
    OIDCConfig,
    OIDCNativeValidator,
)
from common import native_backend


class FakeOidcValidationError(ValueError):
    pass


class FakeNativeBackend:
    OidcValidationError = FakeOidcValidationError

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.key_not_found_once = False

    def oidc_validate_id_token(self, request_json: str) -> str:
        request = json.loads(request_json)
        self.requests.append(request)
        if self.key_not_found_once:
            self.key_not_found_once = False
            raise self.OidcValidationError("OIDC.KEY_NOT_FOUND: rotated-key")
        if request["compact_jwt"] == "id-token":
            return json.dumps(
                {
                    "iss": request["expected_issuer"],
                    "sub": "user-1",
                    "aud": request["expected_audience"],
                    "email": "alice@example.com",
                    "nonce": request["expected_nonce"],
                }
            )
        if request["compact_jwt"] == "access-token":
            return json.dumps(
                {
                    "iss": request["expected_issuer"],
                    "sub": "user-1",
                    "aud": request["expected_audience"],
                    "realm_access": {"roles": ["vendor"]},
                }
            )
        raise self.OidcValidationError("OIDC.INVALID_SIGNATURE: invalid token")


def _config() -> OIDCConfig:
    return OIDCConfig(
        issuer_url="http://keycloak:8080/realms/11id",
        external_issuer_url="https://login.example/realms/11id",
        client_id="marty-ui",
        access_token_audience="marty-ui",
    )


def _install_provider_transport(monkeypatch: pytest.MonkeyPatch, *, issuer: str | None = None):
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": issuer or "https://login.example/realms/11id",
                    "jwks_uri": "https://login.example/realms/11id/protocol/openid-connect/certs",
                },
            )
        if request.url.path.endswith("/protocol/openid-connect/certs"):
            return httpx.Response(200, json={"keys": [{"kid": "provider-key"}]})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def client_factory(**_kwargs):
        return real_client(transport=transport)

    monkeypatch.setattr(oidc_adapter.httpx, "AsyncClient", client_factory)
    return requested_urls


@pytest.mark.asyncio
async def test_validates_id_and_access_tokens_with_one_native_backend(monkeypatch: pytest.MonkeyPatch):
    requested_urls = _install_provider_transport(monkeypatch)
    native = FakeNativeBackend()
    validator = OIDCNativeValidator(_config(), native_backend=native)

    identity = await validator.validate_identity("id-token", "access-token", "nonce-1")

    assert identity.user_info.sub == "user-1"
    assert identity.user_info.roles == ["vendor"]
    assert identity.id_token_claims["nonce"] == "nonce-1"
    assert len(native.requests) == 2
    assert native.requests[0]["expected_nonce"] == "nonce-1"
    assert native.requests[0]["access_token"] == "access-token"
    assert native.requests[1]["expected_nonce"] is None
    assert requested_urls == [
        "http://keycloak:8080/realms/11id/.well-known/openid-configuration",
        "http://keycloak:8080/realms/11id/protocol/openid-connect/certs",
    ]


@pytest.mark.asyncio
async def test_key_rotation_forces_one_jwks_refresh(monkeypatch: pytest.MonkeyPatch):
    requested_urls = _install_provider_transport(monkeypatch)
    native = FakeNativeBackend()
    native.key_not_found_once = True
    validator = OIDCNativeValidator(_config(), native_backend=native)

    identity = await validator.validate_identity("id-token", None, "nonce-1")

    assert identity.user_info.sub == "user-1"
    assert len(native.requests) == 2
    assert len(requested_urls) == 4


@pytest.mark.asyncio
async def test_discovery_issuer_mismatch_fails_before_native_validation(
    monkeypatch: pytest.MonkeyPatch,
):
    _install_provider_transport(monkeypatch, issuer="https://attacker.example/realms/11id")
    native = FakeNativeBackend()
    validator = OIDCNativeValidator(_config(), native_backend=native)

    with pytest.raises(ValueError, match="issuer does not match"):
        await validator.validate_identity("id-token", None, "nonce-1")

    assert native.requests == []


def test_authorization_and_registration_urls_bind_nonce():
    adapter = KeycloakOIDCAdapter(_config(), native_backend=FakeNativeBackend())

    for url in (
        adapter.get_authorization_url("state", "challenge", "nonce-1"),
        adapter.get_registration_url("state", "challenge", "nonce-1"),
    ):
        assert parse_qs(urlparse(url).query)["nonce"] == ["nonce-1"]


def test_required_native_backend_failure_is_typed(monkeypatch: pytest.MonkeyPatch):
    module = ModuleType("marty_rs")
    monkeypatch.setitem(__import__("sys").modules, "marty_rs", module)

    with pytest.raises(native_backend.NativeBackendUnavailable):
        native_backend.load_marty_rs(required_capability="oidc_id_token_validation")


def test_required_native_capability_is_enforced(monkeypatch: pytest.MonkeyPatch):
    extension = ModuleType("_marty_rs")
    extension.native_backend_diagnostics = lambda: json.dumps(
        {"available": True, "backend": "_marty_rs", "version": "1.0", "capabilities": []}
    )
    package = ModuleType("marty_rs")
    package._marty_rs = extension
    monkeypatch.setitem(__import__("sys").modules, "marty_rs", package)

    with pytest.raises(native_backend.NativeBackendUnavailable, match="lacks required capability"):
        native_backend.load_marty_rs(required_capability="oidc_id_token_validation")


@pytest.mark.asyncio
async def test_native_backend_diagnostics_are_exposed_for_health_checks():
    app = auth_main.create_app()
    diagnostics = {
        "available": True,
        "backend": "_marty_rs",
        "version": "1.2.3",
        "capabilities": ["oidc_id_token_validation"],
    }
    app.state.native_backend_diagnostics = diagnostics
    endpoint = next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", None) == "/health/native-backend"
    )

    response = await endpoint()

    assert response == {"status": "ready", **diagnostics}


@pytest.mark.asyncio
async def test_oversized_jwks_is_rejected_before_native_validation(
    monkeypatch: pytest.MonkeyPatch,
):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": "https://login.example/realms/11id",
                    "jwks_uri": "https://login.example/realms/11id/protocol/openid-connect/certs",
                },
            )
        return httpx.Response(
            200,
            content=b"{}",
            headers={"Content-Length": str(oidc_adapter._JWKS_MAX_BYTES + 1)},
        )

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        oidc_adapter.httpx,
        "AsyncClient",
        lambda **_kwargs: real_client(transport=transport),
    )
    native = FakeNativeBackend()
    validator = OIDCNativeValidator(_config(), native_backend=native)

    with pytest.raises(ValueError, match="JWKS document exceeds the size limit"):
        await validator.validate_identity("id-token", None, "nonce-1")

    assert native.requests == []
