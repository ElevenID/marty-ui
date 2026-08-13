"""Thin fail-closed adapter for the canonical Rust DID resolver."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
from dataclasses import dataclass
from typing import Any

from common.native_backend import NativeBackendUnavailable, load_marty_rs

PUBLIC_FALLBACK_ENV = "DID_PUBLIC_FALLBACK_ENABLED"
PUBLIC_HOST_ALLOWLIST_ENV = "DID_WEB_ALLOWED_HOSTS"
_PRIVATE_JWK_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}


class DidResolutionError(RuntimeError):
    """The native resolver rejected a DID or returned an invalid result."""


@dataclass(frozen=True)
class DidResolutionResult:
    document: dict[str, Any]
    source: str
    retrieved_at: str
    content_sha256: str

    @property
    def provenance(self) -> dict[str, str]:
        return {
            "source": self.source,
            "retrieved_at": self.retrieved_at,
            "content_sha256": self.content_sha256,
        }


def _enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _csv(name: str) -> list[str]:
    return [
        item.strip() for item in os.environ.get(name, "").split(",") if item.strip()
    ]


def _internal_base_urls() -> list[str]:
    urls: list[str] = []
    for value in (os.environ.get("DID_RESOLUTION_BASE_URL"), "http://gateway:8000"):
        if value and value not in urls:
            urls.append(value)
    return urls


def _normalize_did_jwk_method_ids(document: dict[str, Any]) -> None:
    did = document.get("id")
    if not isinstance(did, str) or not did.startswith("did:jwk:"):
        return
    native_default_ids = {f"{did}#0", "#0"}
    methods = document.get("verificationMethod")
    if isinstance(methods, list):
        for method in methods:
            if isinstance(method, dict) and method.get("id") in native_default_ids:
                method["id"] = did
    for relationship in ("authentication", "assertionMethod"):
        entries = document.get(relationship)
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if isinstance(entry, str) and entry in native_default_ids:
                entries[index] = did
            elif isinstance(entry, dict) and entry.get("id") in native_default_ids:
                entry["id"] = did


def _normalize_public_jwks(document: dict[str, Any]) -> None:
    methods = document.get("verificationMethod")
    if not isinstance(methods, list):
        return
    for method in methods:
        if not isinstance(method, dict):
            continue
        public_jwk = method.get("publicKeyJwk")
        if not isinstance(public_jwk, dict):
            continue
        if any(public_jwk.get(member) is not None for member in _PRIVATE_JWK_MEMBERS):
            raise DidResolutionError(
                "Native DID resolution returned private key material"
            )
        method["publicKeyJwk"] = {
            key: value for key, value in public_jwk.items() if value is not None
        }


def _decode_result(raw: Any) -> DidResolutionResult:
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise DidResolutionError(
            "Native DID resolution returned invalid JSON"
        ) from error
    if not isinstance(payload, dict):
        raise DidResolutionError("Native DID resolution returned a non-object result")

    document = payload.get("document")
    source = payload.get("source")
    retrieved_at = payload.get("retrieved_at")
    content_sha256 = payload.get("content_sha256")
    if (
        not isinstance(document, dict)
        or not isinstance(source, str)
        or not source
        or not isinstance(retrieved_at, str)
        or not retrieved_at
        or not isinstance(content_sha256, str)
        or len(content_sha256) != 64
    ):
        raise DidResolutionError("Native DID resolution result is incomplete")

    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(canonical).hexdigest() != content_sha256.lower():
        raise DidResolutionError("Native DID resolution provenance hash is invalid")
    _normalize_did_jwk_method_ids(document)
    _normalize_public_jwks(document)
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return DidResolutionResult(
        document=document,
        source=source,
        retrieved_at=retrieved_at,
        content_sha256=hashlib.sha256(canonical).hexdigest(),
    )


def _resolve_native(did: str) -> DidResolutionResult:
    backend = load_marty_rs(required_capability="did_resolution")
    resolver = getattr(backend, "didcomm_resolve_did_with_metadata", None)
    if not callable(resolver):
        raise NativeBackendUnavailable(
            "The Marty Rust backend lacks didcomm_resolve_did_with_metadata"
        )

    allowed_hosts = (
        _csv(PUBLIC_HOST_ALLOWLIST_ENV) if _enabled(PUBLIC_FALLBACK_ENV) else []
    )
    try:
        raw = resolver(
            did,
            universal_resolver_url=None,
            did_web_internal_base_urls=_internal_base_urls(),
            did_web_allowed_hosts=allowed_hosts,
        )
    except NativeBackendUnavailable:
        raise
    except Exception as error:
        raise DidResolutionError("Native DID resolution failed") from error
    return _decode_result(raw)


async def resolve_did_document(
    did: str, *, timeout: float = 5.0
) -> DidResolutionResult:
    """Resolve a DID through the sole supported native implementation."""
    if (
        not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("timeout must be a positive finite number")
    try:
        return await asyncio.wait_for(asyncio.to_thread(_resolve_native, did), timeout)
    except TimeoutError as error:
        raise DidResolutionError("Native DID resolution timed out") from error
