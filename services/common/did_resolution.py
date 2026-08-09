"""Controlled DID resolution for verification services.

Network-derived DID identifiers are untrusted input. This module keeps direct
egress policy, bounded retrieval, document validation, and provenance in one
place so format verifiers do not implement their own HTTP fallback behavior.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import httpx

MAX_DID_DOCUMENT_BYTES = 1024 * 1024
MAX_DID_DOCUMENT_DEPTH = 32
PUBLIC_FALLBACK_ENV = "DID_PUBLIC_FALLBACK_ENABLED"
PUBLIC_HOST_ALLOWLIST_ENV = "DID_WEB_ALLOWED_HOSTS"
_CONTENT_TYPES = {"application/did+json", "application/json", "application/ld+json"}


class DidResolutionError(RuntimeError):
    """A DID could not be resolved under the active egress policy."""


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


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DidResolutionError("DID document contains duplicate JSON members")
        result[key] = value
    return result


def _json_depth(value: Any, depth: int = 0) -> int:
    if depth > MAX_DID_DOCUMENT_DEPTH:
        return depth
    if isinstance(value, dict):
        return max(
            (_json_depth(item, depth + 1) for item in value.values()), default=depth
        )
    if isinstance(value, list):
        return max((_json_depth(item, depth + 1) for item in value), default=depth)
    return depth


def _absolute_method_id(did: str, value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return f"{did}{value}" if value.startswith("#") else value


def _relationship_ids(document: dict[str, Any], relationship: str) -> set[str]:
    did = str(document.get("id") or "")
    entries = document.get(relationship)
    if not isinstance(entries, list):
        return set()
    result: set[str] = set()
    for entry in entries:
        value = entry.get("id") if isinstance(entry, dict) else entry
        method_id = _absolute_method_id(did, value)
        if method_id:
            result.add(method_id)
    return result


def _validate_document(document: Any, did: str) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise DidResolutionError("DID document must be a JSON object")
    if _json_depth(document) > MAX_DID_DOCUMENT_DEPTH:
        raise DidResolutionError("DID document exceeds the nesting limit")
    if document.get("id") != did:
        raise DidResolutionError(
            "Resolved DID document id does not match the requested DID"
        )

    methods = document.get("verificationMethod")
    if not isinstance(methods, list) or not methods:
        raise DidResolutionError("DID document has no verification methods")
    method_ids: set[str] = set()
    for method in methods:
        if not isinstance(method, dict):
            raise DidResolutionError(
                "DID document contains an invalid verification method"
            )
        method_id = _absolute_method_id(did, method.get("id"))
        if not method_id or not (method_id == did or method_id.startswith(f"{did}#")):
            raise DidResolutionError(
                "DID verification method is outside the requested DID"
            )
        if method_id in method_ids:
            raise DidResolutionError(
                "DID document contains duplicate verification method ids"
            )
        if method.get("controller") != did:
            raise DidResolutionError(
                "DID verification method controller does not match the DID"
            )
        method_ids.add(method_id)

    relationships = _relationship_ids(document, "assertionMethod") | _relationship_ids(
        document, "authentication"
    )
    if not relationships or not relationships.issubset(method_ids):
        raise DidResolutionError("DID document has invalid verification relationships")
    return document


def _result(document: dict[str, Any], source: str) -> DidResolutionResult:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return DidResolutionResult(
        document=document,
        source=source,
        retrieved_at=datetime.now(UTC).isoformat(),
        content_sha256=hashlib.sha256(canonical).hexdigest(),
    )


def _resolve_did_jwk(did: str) -> DidResolutionResult:
    encoded = did[len("did:jwk:") :]
    if not encoded or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in encoded
    ):
        raise DidResolutionError("did:jwk payload is not canonical base64url")
    try:
        padding = "=" * (-len(encoded) % 4)
        decoded = base64.b64decode(
            encoded + padding,
            altchars=b"-_",
            validate=True,
        )
        if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != encoded:
            raise DidResolutionError("did:jwk payload is not canonical base64url")
        jwk = json.loads(
            decoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (binascii.Error, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise DidResolutionError("did:jwk payload is invalid") from exc
    if not isinstance(jwk, dict):
        raise DidResolutionError("did:jwk payload is not a public JWK")
    if {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}.intersection(jwk):
        raise DidResolutionError("did:jwk payload contains private key material")
    kty = jwk.get("kty")
    required_members = {
        "OKP": ("crv", "x"),
        "EC": ("crv", "x", "y"),
        "RSA": ("n", "e"),
    }.get(kty)
    if required_members is None or any(
        not isinstance(jwk.get(member), str) or not jwk[member]
        for member in required_members
    ):
        raise DidResolutionError("did:jwk payload is not a supported public JWK")
    document = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": did,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
        "authentication": [did],
        "assertionMethod": [did],
    }
    return _result(_validate_document(document, did), "embedded:did:jwk")


def _did_web_parts(did: str) -> tuple[str, str]:
    if not did.startswith("did:web:"):
        raise DidResolutionError("Unsupported DID method")
    parts = did[len("did:web:") :].split(":")
    if not parts or not parts[0]:
        raise DidResolutionError("did:web identifier is malformed")
    authority = unquote(parts[0])
    if any(character in authority for character in "/\\@?#"):
        raise DidResolutionError("did:web authority is malformed")
    try:
        parsed = urlsplit(f"https://{authority}")
        port = parsed.port
    except ValueError as exc:
        raise DidResolutionError("did:web authority is malformed") from exc
    if not parsed.hostname or parsed.username or parsed.password or parsed.path:
        raise DidResolutionError("did:web authority is malformed")
    if port not in {None, 443}:
        raise DidResolutionError(
            "did:web public resolution requires the default HTTPS port"
        )
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise DidResolutionError("did:web IP literals are not permitted")
    try:
        host = parsed.hostname.lower().rstrip(".").encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DidResolutionError("did:web hostname is malformed") from exc

    path: list[str] = []
    for raw_segment in parts[1:]:
        segment = unquote(raw_segment)
        if (
            not segment
            or segment in {".", ".."}
            or any(character in segment for character in "/\\?#")
            or any(ord(character) < 0x20 for character in segment)
        ):
            raise DidResolutionError("did:web path is malformed")
        path.append(quote(segment, safe="-._~"))
    resolution_path = f"/{'/'.join(path)}/did.json" if path else "/.well-known/did.json"
    return host, resolution_path


def _configured_internal_urls(path: str) -> list[str]:
    urls: list[str] = []
    for raw_base in (os.environ.get("DID_RESOLUTION_BASE_URL"), "http://gateway:8000"):
        if not raw_base:
            continue
        parsed = urlsplit(raw_base)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise DidResolutionError("Configured DID resolver URL is invalid")
        url = f"{raw_base.rstrip('/')}{path}"
        if url not in urls:
            urls.append(url)
    return urls


def _public_host_allowlist() -> frozenset[str]:
    hosts: set[str] = set()
    for raw_host in os.environ.get(PUBLIC_HOST_ALLOWLIST_ENV, "").split(","):
        host = raw_host.strip().lower().rstrip(".")
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise DidResolutionError(
                f"{PUBLIC_HOST_ALLOWLIST_ENV} does not accept IP literals"
            )
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise DidResolutionError(
                f"{PUBLIC_HOST_ALLOWLIST_ENV} contains an invalid hostname"
            ) from exc
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.isalnum() or character == "-" for character in label)
            for label in ascii_host.split(".")
        ):
            raise DidResolutionError(
                f"{PUBLIC_HOST_ALLOWLIST_ENV} contains an invalid hostname"
            )
        hosts.add(ascii_host)
    return frozenset(hosts)


async def _public_addresses(host: str) -> tuple[str, ...]:
    try:
        addresses = await asyncio.to_thread(
            socket.getaddrinfo,
            host,
            443,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise DidResolutionError("did:web hostname could not be resolved") from exc
    resolved = sorted({str(address[4][0]).split("%", 1)[0] for address in addresses})
    if not resolved:
        raise DidResolutionError("did:web hostname resolved to no addresses")
    if any(not ipaddress.ip_address(address).is_global for address in resolved):
        raise DidResolutionError("did:web hostname resolves to a non-public address")
    return tuple(resolved)


def _pin_url(url: str, address: str) -> tuple[str, dict[str, Any]]:
    parsed = urlsplit(url)
    ip = ipaddress.ip_address(address)
    netloc = f"[{ip}]" if ip.version == 6 else str(ip)
    pinned = urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    assert parsed.hostname is not None
    return pinned, {"sni_hostname": parsed.hostname.encode("idna").decode("ascii")}


async def _read_document(response: httpx.Response, did: str) -> dict[str, Any]:
    if 300 <= response.status_code < 400:
        raise DidResolutionError("DID resolver redirects are not permitted")
    if response.status_code != 200:
        raise DidResolutionError("DID resolver did not return a document")
    content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
    if content_type not in _CONTENT_TYPES:
        raise DidResolutionError("DID resolver returned an unsupported media type")
    length = response.headers.get("content-length")
    if length:
        try:
            parsed_length = int(length)
        except ValueError as exc:
            raise DidResolutionError(
                "DID resolver returned an invalid Content-Length"
            ) from exc
        if parsed_length < 0 or parsed_length > MAX_DID_DOCUMENT_BYTES:
            raise DidResolutionError("DID document exceeds the response limit")
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > MAX_DID_DOCUMENT_BYTES:
            raise DidResolutionError("DID document exceeds the response limit")
    try:
        document = json.loads(body, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DidResolutionError("DID resolver returned invalid JSON") from exc
    return _validate_document(document, did)


async def _fetch(
    client: httpx.AsyncClient,
    url: str,
    did: str,
    *,
    address: str | None = None,
) -> dict[str, Any]:
    request_url = url
    extensions: dict[str, Any] = {}
    parsed = urlsplit(url)
    headers = {"Accept": "application/did+json, application/json"}
    if address is not None:
        request_url, extensions = _pin_url(url, address)
        headers["Host"] = parsed.netloc
    try:
        async with client.stream(
            "GET",
            request_url,
            headers=headers,
            extensions=extensions,
        ) as response:
            return await _read_document(response, did)
    except DidResolutionError:
        raise
    except httpx.HTTPError as exc:
        raise DidResolutionError("DID resolver request failed") from exc


async def resolve_did_document(
    did: str, *, timeout: float = 5.0
) -> DidResolutionResult:
    """Resolve a DID under deployment-owned internal/public egress policy."""
    if did.startswith("did:jwk:"):
        return _resolve_did_jwk(did)
    host, path = _did_web_parts(did)

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        for internal_url in _configured_internal_urls(path):
            try:
                document = await _fetch(client, internal_url, did)
                return _result(document, "configured_internal_resolver")
            except DidResolutionError:
                continue

        if not _enabled(PUBLIC_FALLBACK_ENV):
            raise DidResolutionError("Public DID fallback is disabled")
        if host not in _public_host_allowlist():
            raise DidResolutionError(
                "did:web host is not in the public fallback allowlist"
            )
        addresses = await _public_addresses(host)
        public_url = f"https://{host}{path}"
        document = await _fetch(client, public_url, did, address=addresses[0])
        return _result(document, "allowlisted_public_did_web")
