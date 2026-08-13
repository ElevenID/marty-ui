from __future__ import annotations

import hashlib
import json
import time
from types import SimpleNamespace

import pytest

from common import did_resolution
from common.native_backend import NativeBackendUnavailable


def _native_result(did: str, *, source: str = "embedded:did:jwk") -> str:
    document = {
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#0",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "x-value",
                    "y": "y-value",
                    "d": None,
                    "kid": None,
                },
            }
        ],
        "authentication": [f"{did}#0"],
        "assertionMethod": [f"{did}#0"],
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return json.dumps(
        {
            "document": document,
            "source": source,
            "retrieved_at": "2026-08-13T00:00:00Z",
            "content_sha256": hashlib.sha256(canonical).hexdigest(),
        }
    )


@pytest.mark.asyncio
async def test_native_adapter_preserves_result_and_egress_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict]] = []

    def resolve(did: str, **kwargs: object) -> str:
        calls.append((did, kwargs))
        return _native_result(did, source="configured_internal_resolver")

    def load(*, required_capability: str) -> SimpleNamespace:
        assert required_capability == "did_resolution"
        return SimpleNamespace(didcomm_resolve_did_with_metadata=resolve)

    monkeypatch.setattr(did_resolution, "load_marty_rs", load)
    monkeypatch.setenv("DID_RESOLUTION_BASE_URL", "http://resolver:8080")
    monkeypatch.setenv(did_resolution.PUBLIC_FALLBACK_ENV, "true")
    monkeypatch.setenv(
        did_resolution.PUBLIC_HOST_ALLOWLIST_ENV, "issuer.example, holder.example"
    )

    result = await did_resolution.resolve_did_document("did:web:issuer.example")

    assert result.source == "configured_internal_resolver"
    public_jwk = result.document["verificationMethod"][0]["publicKeyJwk"]
    assert public_jwk == {
        "kty": "EC",
        "crv": "P-256",
        "x": "x-value",
        "y": "y-value",
    }
    canonical = json.dumps(
        result.document, sort_keys=True, separators=(",", ":")
    ).encode()
    assert result.content_sha256 == hashlib.sha256(canonical).hexdigest()
    assert calls == [
        (
            "did:web:issuer.example",
            {
                "universal_resolver_url": None,
                "did_web_internal_base_urls": [
                    "http://resolver:8080",
                    "http://gateway:8000",
                ],
                "did_web_allowed_hosts": ["issuer.example", "holder.example"],
            },
        )
    ]


@pytest.mark.asyncio
async def test_public_hosts_are_not_passed_without_explicit_enablement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def resolve(did: str, **kwargs: object) -> str:
        captured.update(kwargs)
        return _native_result(did)

    monkeypatch.setattr(
        did_resolution,
        "load_marty_rs",
        lambda **_kwargs: SimpleNamespace(didcomm_resolve_did_with_metadata=resolve),
    )
    monkeypatch.setenv(did_resolution.PUBLIC_HOST_ALLOWLIST_ENV, "issuer.example")
    monkeypatch.delenv(did_resolution.PUBLIC_FALLBACK_ENV, raising=False)

    await did_resolution.resolve_did_document("did:jwk:public")

    assert captured["did_web_allowed_hosts"] == []


@pytest.mark.asyncio
async def test_missing_native_backend_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(**_kwargs: object) -> None:
        raise NativeBackendUnavailable("missing native backend")

    monkeypatch.setattr(did_resolution, "load_marty_rs", unavailable)

    with pytest.raises(NativeBackendUnavailable, match="missing native backend"):
        await did_resolution.resolve_did_document("did:jwk:public")


@pytest.mark.asyncio
async def test_invalid_native_result_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = SimpleNamespace(
        didcomm_resolve_did_with_metadata=lambda *_args, **_kwargs: json.dumps(
            {
                "document": {"id": "did:jwk:public"},
                "source": "embedded:did:jwk",
                "retrieved_at": "2026-08-13T00:00:00Z",
                "content_sha256": "0" * 64,
            }
        )
    )
    monkeypatch.setattr(did_resolution, "load_marty_rs", lambda **_kwargs: backend)

    with pytest.raises(did_resolution.DidResolutionError, match="provenance hash"):
        await did_resolution.resolve_did_document("did:jwk:public")


def test_private_native_jwk_fails_closed() -> None:
    did = "did:jwk:public"
    document = {
        "id": did,
        "verificationMethod": [
            {"id": f"{did}#0", "publicKeyJwk": {"kty": "EC", "d": "private"}}
        ],
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    raw = json.dumps(
        {
            "document": document,
            "source": "embedded:did:jwk",
            "retrieved_at": "2026-08-13T00:00:00Z",
            "content_sha256": hashlib.sha256(canonical).hexdigest(),
        }
    )

    with pytest.raises(did_resolution.DidResolutionError, match="private key material"):
        did_resolution._decode_result(raw)


def test_did_jwk_default_method_preserves_compatibility_identifier() -> None:
    did = "did:jwk:public"

    result = did_resolution._decode_result(_native_result(did))

    assert result.document["verificationMethod"][0]["id"] == did
    assert result.document["authentication"] == [did]
    assert result.document["assertionMethod"] == [did]


@pytest.mark.asyncio
async def test_timeout_is_enforced_around_native_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def slow(*_args: object, **_kwargs: object) -> str:
        time.sleep(0.05)
        return _native_result("did:jwk:public")

    monkeypatch.setattr(
        did_resolution,
        "load_marty_rs",
        lambda **_kwargs: SimpleNamespace(didcomm_resolve_did_with_metadata=slow),
    )

    with pytest.raises(did_resolution.DidResolutionError, match="timed out"):
        await did_resolution.resolve_did_document("did:jwk:public", timeout=0.001)


@pytest.mark.asyncio
async def test_invalid_timeout_is_rejected() -> None:
    with pytest.raises(ValueError, match="positive finite"):
        await did_resolution.resolve_did_document("did:jwk:public", timeout=0)
