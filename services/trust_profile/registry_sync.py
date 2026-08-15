"""HTTP/storage adapters for the canonical Rust trust-registry sync kernel."""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

from common.native_backend import NativeOperationError
from trust_profile import native

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PAGES = 100
SYNC_PROTOCOL = "MARTY_TRUST_REGISTRY_SYNC_V1"
PRIVATE_HOST_ALLOWLIST_ENV = "TRUST_REGISTRY_PRIVATE_HOST_ALLOWLIST"
TLS_CA_FILE_ENV = "TRUST_REGISTRY_TLS_CA_FILE"


class RegistrySyncError(RuntimeError):
    """An external registry failed validation and changed no effective trust."""


@dataclass(frozen=True)
class RegistryFeed:
    sync_token: str
    sequence: int
    entries: list[dict[str, Any]]
    has_more: bool
    generated_at: datetime
    raw: dict[str, Any] = field(repr=False, compare=False)

    @classmethod
    def from_native(cls, value: dict[str, Any]) -> "RegistryFeed":
        try:
            generated_at = datetime.fromisoformat(str(value["generated_at"]))
            entries = value.get("entries", [])
            if generated_at.tzinfo is None or not isinstance(entries, list):
                raise ValueError
            return cls(
                sync_token=str(value["sync_token"]),
                sequence=int(value["sequence"]),
                entries=entries,
                has_more=bool(value.get("has_more", False)),
                generated_at=generated_at,
                raw=value,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise RegistrySyncError(
                "registry response violates the sync contract"
            ) from error


@dataclass(frozen=True)
class ImportedRegistryEntry:
    entry_id: str
    anchor_type: Literal["CSCA", "DSC"]
    country_code: str
    certificate_pem: str
    source: Literal["ICAO_PKD", "AAMVA", "EUDI_LOTL", "MANUAL"]
    subject_key_id: str | None = None
    not_before: str | None = None
    not_after: str | None = None

    def to_storage(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "anchor_type": self.anchor_type,
            "country_code": self.country_code,
            "certificate_pem": self.certificate_pem,
            "source": self.source,
            "subject_key_id": self.subject_key_id,
            "not_before": self.not_before,
            "not_after": self.not_after,
        }

    @classmethod
    def from_storage(cls, value: dict[str, Any]) -> "ImportedRegistryEntry":
        return cls(
            entry_id=str(value["entry_id"]),
            anchor_type=value["anchor_type"],
            country_code=str(value["country_code"]),
            certificate_pem=str(value["certificate_pem"]),
            source=value["source"],
            subject_key_id=value.get("subject_key_id"),
            not_before=value.get("not_before"),
            not_after=value.get("not_after"),
        )


@dataclass(frozen=True)
class RegistryImportState:
    sync_token: str | None = None
    sequence: int = 0
    entries: dict[str, ImportedRegistryEntry] = field(default_factory=dict)
    synchronized_at: datetime | None = None


@dataclass(frozen=True)
class RegistryImportResult:
    state: RegistryImportState
    pages: int


DestinationValidator = Callable[[str], Awaitable[str | None]]


def registry_tls_context() -> ssl.SSLContext:
    """Build normal Web PKI trust plus an optional operator-owned CA bundle."""
    context = ssl.create_default_context()
    ca_file = os.environ.get(TLS_CA_FILE_ENV, "").strip()
    if ca_file:
        try:
            context.load_verify_locations(cafile=ca_file)
        except (OSError, ssl.SSLError) as exc:
            raise RegistrySyncError(f"{TLS_CA_FILE_ENV} could not be loaded") from exc
    return context


def validate_registry_url_structure(url: str) -> str:
    """Validate the stable public URL shape in the native policy kernel."""
    try:
        return native.validate_url(url)
    except NativeOperationError as error:
        raise ValueError(str(error)) from error


async def require_public_registry_destination(url: str) -> str:
    """Resolve a destination and let Rust enforce public/private address policy."""
    validate_registry_url_structure(url)
    private_host_allowlist = os.environ.get(PRIVATE_HOST_ALLOWLIST_ENV, "")
    try:
        native.validate_private_host_allowlist(private_host_allowlist)
    except NativeOperationError as error:
        raise RegistrySyncError(str(error)) from error
    parsed = urlsplit(url)
    assert parsed.hostname is not None
    try:
        records = await asyncio.to_thread(
            socket.getaddrinfo,
            parsed.hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise RegistrySyncError("registry hostname could not be resolved") from exc
    addresses = sorted({str(record[4][0]) for record in records})
    try:
        decision = native.destination_decision(
            url,
            addresses,
            private_host_allowlist,
        )
    except NativeOperationError as error:
        raise RegistrySyncError(str(error)) from error
    return str(decision["address"])


async def _read_bounded_response(response: httpx.Response) -> bytes:
    content_length = response.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_RESPONSE_BYTES:
                raise RegistrySyncError("registry response exceeds the size limit")
        except ValueError as exc:
            raise RegistrySyncError(
                "registry returned an invalid Content-Length"
            ) from exc

    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > MAX_RESPONSE_BYTES:
            raise RegistrySyncError("registry response exceeds the size limit")
    return bytes(body)


async def fetch_registry_page(
    url: str,
    token: str | None,
    *,
    client: httpx.AsyncClient,
    validate_destination: DestinationValidator = require_public_registry_destination,
) -> RegistryFeed:
    resolved_address = await validate_destination(url)
    try:
        request = native.request_plan(url, token, resolved_address)
    except NativeOperationError as error:
        raise RegistrySyncError(str(error)) from error
    extensions = (
        {"sni_hostname": request["sni_hostname"]}
        if resolved_address is not None
        else {}
    )
    try:
        async with client.stream(
            "GET",
            request["request_url"],
            headers={"Accept": "application/json", "Host": request["host_header"]},
            extensions=extensions,
        ) as response:
            if 300 <= response.status_code < 400:
                raise RegistrySyncError("registry redirects are not permitted")
            response.raise_for_status()
            content_type = response.headers.get("content-type", "").lower()
            if "application/json" not in content_type:
                raise RegistrySyncError("registry response must be application/json")
            body = await _read_bounded_response(response)
    except RegistrySyncError:
        raise
    except httpx.HTTPError as exc:
        raise RegistrySyncError("registry request failed") from exc

    try:
        validated = native.validate_feed(body.decode("utf-8"))
        return RegistryFeed.from_native(validated)
    except UnicodeDecodeError as error:
        raise RegistrySyncError(
            "registry response violates the sync contract"
        ) from error
    except NativeOperationError as error:
        raise RegistrySyncError(str(error)) from error


def _state_to_native(state: RegistryImportState) -> dict[str, Any]:
    return {
        "sync_token": state.sync_token,
        "sequence": state.sequence,
        "entries": {
            entry_id: entry.to_storage() for entry_id, entry in state.entries.items()
        },
        "synchronized_at": (
            state.synchronized_at.isoformat() if state.synchronized_at else None
        ),
    }


def _state_from_native(value: dict[str, Any]) -> RegistryImportState:
    try:
        synchronized_at_raw = value.get("synchronized_at")
        synchronized_at = (
            datetime.fromisoformat(str(synchronized_at_raw))
            if synchronized_at_raw is not None
            else None
        )
        if synchronized_at is not None and synchronized_at.tzinfo is None:
            raise ValueError
        raw_entries = value.get("entries", {})
        if not isinstance(raw_entries, dict):
            raise TypeError
        entries = {
            str(entry_id): ImportedRegistryEntry.from_storage(entry)
            for entry_id, entry in raw_entries.items()
        }
        return RegistryImportState(
            sync_token=value.get("sync_token"),
            sequence=int(value.get("sequence", 0)),
            entries=entries,
            synchronized_at=synchronized_at,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise RegistrySyncError("stored registry state is invalid") from error


def validate_current_registry_entries(
    entries: dict[str, ImportedRegistryEntry],
    *,
    now: datetime | None = None,
) -> dict[str, ImportedRegistryEntry]:
    """Revalidate persisted entries natively before they influence trust."""
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    state = RegistryImportState(entries=entries)
    try:
        validated = native.revalidate_state(
            _state_to_native(state),
            effective_now.isoformat(),
        )
    except NativeOperationError as error:
        raise RegistrySyncError(str(error)) from error
    return _state_from_native(validated).entries


async def synchronize_registry(
    url: str,
    previous: RegistryImportState,
    *,
    client: httpx.AsyncClient,
    validate_destination: DestinationValidator = require_public_registry_destination,
    now: datetime | None = None,
) -> RegistryImportResult:
    """Fetch pages while Rust evaluates one atomic replacement state."""
    validate_registry_url_structure(url)
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    previous_native = _state_to_native(previous)
    pages: list[dict[str, Any]] = []
    token = previous.sync_token

    for _page_number in range(1, MAX_PAGES + 1):
        feed = await fetch_registry_page(
            url,
            token,
            client=client,
            validate_destination=validate_destination,
        )
        pages.append(feed.raw)
        try:
            evaluation = native.evaluate_pages(
                previous_native,
                pages,
                effective_now.isoformat(),
            )
        except NativeOperationError as error:
            raise RegistrySyncError(str(error)) from error
        if evaluation["complete"]:
            state = evaluation.get("state")
            if not isinstance(state, dict):
                raise RegistrySyncError("Rust registry result omitted completed state")
            return RegistryImportResult(
                state=_state_from_native(state),
                pages=int(evaluation["pages"]),
            )
        token = str(evaluation["next_token"])

    raise RegistrySyncError("registry pagination exceeded the page limit")


def state_from_storage(
    *,
    sync_token: str | None,
    sequence: int,
    entries: dict[str, dict[str, Any]],
    synchronized_at: datetime | None,
) -> RegistryImportState:
    candidate = {
        "sync_token": sync_token,
        "sequence": sequence,
        "entries": entries,
        "synchronized_at": synchronized_at.isoformat() if synchronized_at else None,
    }
    try:
        return _state_from_native(native.validate_state(candidate))
    except NativeOperationError as error:
        raise RegistrySyncError(str(error)) from error
