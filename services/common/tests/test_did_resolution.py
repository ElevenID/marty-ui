from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from common import did_resolution


def _document(did: str) -> dict:
    method_id = f"{did}#key-1"
    return {
        "id": did,
        "verificationMethod": [
            {
                "id": method_id,
                "controller": did,
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "abc"},
            }
        ],
        "assertionMethod": [method_id],
    }


async def _resolve_with_handler(
    did: str, handler
) -> did_resolution.DidResolutionResult:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with patch.object(did_resolution.httpx, "AsyncClient", return_value=client):
        return await did_resolution.resolve_did_document(did)


@pytest.mark.asyncio
async def test_resolves_did_jwk_without_network() -> None:
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": "abc"}
    encoded = base64.urlsafe_b64encode(json.dumps(jwk).encode()).rstrip(b"=").decode()

    result = await did_resolution.resolve_did_document(f"did:jwk:{encoded}")

    assert result.source == "embedded:did:jwk"
    assert result.document["verificationMethod"][0]["publicKeyJwk"] == jwk
    assert len(result.content_sha256) == 64


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "jwk",
    [
        {"kty": "OKP", "crv": "Ed25519", "x": "abc", "d": "private"},
        {"kty": "oct", "k": "symmetric-secret"},
        {"kty": "EC", "crv": "P-256", "x": "missing-y"},
    ],
)
async def test_rejects_did_jwk_without_a_complete_public_key(jwk: dict) -> None:
    encoded = base64.urlsafe_b64encode(json.dumps(jwk).encode()).rstrip(b"=").decode()

    with pytest.raises(did_resolution.DidResolutionError, match="public|private"):
        await did_resolution.resolve_did_document(f"did:jwk:{encoded}")


@pytest.mark.asyncio
async def test_rejects_noncanonical_did_jwk_base64url() -> None:
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": "abc"}
    encoded = base64.urlsafe_b64encode(json.dumps(jwk).encode()).rstrip(b"=").decode()

    with pytest.raises(did_resolution.DidResolutionError, match="canonical"):
        await did_resolution.resolve_did_document(f"did:jwk:{encoded}!")


@pytest.mark.asyncio
async def test_prefers_configured_internal_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    did = "did:web:issuer.example:orgs:tenant-a"
    requested: list[str] = []
    monkeypatch.setenv("DID_RESOLUTION_BASE_URL", "http://resolver:8080")

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(
            200,
            json=_document(did),
            headers={"content-type": "application/did+json"},
        )

    result = await _resolve_with_handler(did, handler)

    assert result.source == "configured_internal_resolver"
    assert requested == ["http://resolver:8080/orgs/tenant-a/did.json"]


@pytest.mark.asyncio
async def test_public_fallback_is_disabled_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    did = "did:web:issuer.example"
    monkeypatch.delenv(did_resolution.PUBLIC_FALLBACK_ENV, raising=False)

    with pytest.raises(did_resolution.DidResolutionError, match="fallback is disabled"):
        await _resolve_with_handler(
            did,
            lambda _request: httpx.Response(
                404,
                headers={"content-type": "application/json"},
            ),
        )


@pytest.mark.asyncio
async def test_public_fallback_requires_exact_host_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    did = "did:web:issuer.example"
    monkeypatch.setenv(did_resolution.PUBLIC_FALLBACK_ENV, "true")
    monkeypatch.setenv(did_resolution.PUBLIC_HOST_ALLOWLIST_ENV, "other.example")

    with pytest.raises(did_resolution.DidResolutionError, match="fallback allowlist"):
        await _resolve_with_handler(
            did,
            lambda _request: httpx.Response(
                404,
                headers={"content-type": "application/json"},
            ),
        )


@pytest.mark.asyncio
async def test_public_fallback_pins_validated_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    did = "did:web:issuer.example"
    requests: list[httpx.Request] = []
    monkeypatch.setenv(did_resolution.PUBLIC_FALLBACK_ENV, "true")
    monkeypatch.setenv(did_resolution.PUBLIC_HOST_ALLOWLIST_ENV, "issuer.example")
    monkeypatch.setattr(
        did_resolution,
        "_public_addresses",
        AsyncMock(return_value=("93.184.216.34",)),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "gateway":
            return httpx.Response(404, headers={"content-type": "application/json"})
        return httpx.Response(
            200,
            json=_document(did),
            headers={"content-type": "application/did+json"},
        )

    result = await _resolve_with_handler(did, handler)

    assert result.source == "allowlisted_public_did_web"
    assert str(requests[-1].url) == "https://93.184.216.34/.well-known/did.json"
    assert requests[-1].headers["host"] == "issuer.example"


@pytest.mark.asyncio
async def test_rejects_private_dns_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        did_resolution.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("10.0.0.8", 443))],
    )

    with pytest.raises(did_resolution.DidResolutionError, match="non-public address"):
        await did_resolution._public_addresses("issuer.example")


@pytest.mark.asyncio
async def test_rejects_redirect_and_oversized_documents() -> None:
    did = "did:web:issuer.example"
    redirect_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                302, headers={"location": "http://metadata"}
            )
        )
    )
    with pytest.raises(did_resolution.DidResolutionError, match="redirects"):
        await did_resolution._fetch(redirect_client, "http://resolver/did.json", did)
    await redirect_client.aclose()

    oversized_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                content=b"x" * (did_resolution.MAX_DID_DOCUMENT_BYTES + 1),
                headers={"content-type": "application/did+json"},
            )
        )
    )
    with pytest.raises(did_resolution.DidResolutionError, match="response limit"):
        await did_resolution._fetch(oversized_client, "http://resolver/did.json", did)
    await oversized_client.aclose()


@pytest.mark.asyncio
async def test_rejects_unsafe_path_and_duplicate_methods() -> None:
    with pytest.raises(did_resolution.DidResolutionError, match="path is malformed"):
        await did_resolution.resolve_did_document(
            "did:web:issuer.example:orgs%2Finternal"
        )

    did = "did:web:issuer.example"
    duplicate = _document(did)
    duplicate["verificationMethod"].append(duplicate["verificationMethod"][0].copy())
    with pytest.raises(
        did_resolution.DidResolutionError, match="duplicate verification method"
    ):
        did_resolution._validate_document(duplicate, did)
