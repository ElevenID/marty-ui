"""Fail-closed importer for the public Marty Trust Registry Sync v1 feed."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID

import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_PAGES = 100
SYNC_PROTOCOL = "MARTY_TRUST_REGISTRY_SYNC_V1"


class RegistrySyncError(RuntimeError):
    """An external registry failed validation and changed no effective trust."""


class RegistryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry_id: UUID
    anchor_type: Literal["CSCA", "DSC"]
    operation: Literal["ADD", "REMOVE"]
    country_code: str = Field(pattern=r"^[A-Z]{2,3}$")
    certificate_pem: str | None = Field(default=None, max_length=64 * 1024)
    subject_key_id: str | None = Field(default=None, max_length=512)
    not_before: AwareDatetime | None = None
    not_after: AwareDatetime | None = None
    source: Literal["ICAO_PKD", "AAMVA", "EUDI_LOTL", "MANUAL"]

    @model_validator(mode="after")
    def validate_operation_material(self) -> "RegistryEntry":
        if self.operation == "ADD" and self.certificate_pem is None:
            raise ValueError("ADD registry entries require certificate_pem")
        if self.operation == "REMOVE" and self.certificate_pem is not None:
            raise ValueError("REMOVE registry entries must not include certificate_pem")
        return self


class RegistryFeed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sync_token: str = Field(min_length=1, max_length=2048)
    sequence: int = Field(ge=0)
    entries: list[RegistryEntry] = Field(default_factory=list, max_length=10_000)
    has_more: bool = False
    generated_at: AwareDatetime


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


def validate_registry_url_structure(url: str) -> str:
    """Validate the stable public URL shape before it is persisted."""
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("registry URL is invalid") from exc
    if parsed.scheme.lower() != "https":
        raise ValueError("registry URL must use HTTPS")
    if not parsed.hostname:
        raise ValueError("registry URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("registry URL must not contain credentials")
    if port not in {None, 443}:
        raise ValueError("registry URL must use the standard HTTPS port")
    if parsed.query or parsed.fragment:
        raise ValueError("registry URL must not contain a query or fragment")
    return url


async def require_public_registry_destination(url: str) -> str:
    """Resolve one public address that the HTTPS request must use."""
    parsed = urlsplit(validate_registry_url_structure(url))
    assert parsed.hostname is not None
    try:
        addresses = await asyncio.to_thread(
            socket.getaddrinfo,
            parsed.hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise RegistrySyncError("registry hostname could not be resolved") from exc
    if not addresses:
        raise RegistrySyncError("registry hostname resolved to no addresses")
    for address in addresses:
        candidate = ipaddress.ip_address(address[4][0])
        if not candidate.is_global:
            raise RegistrySyncError(
                "registry hostname resolves to a non-public network address"
            )
    return sorted({address[4][0] for address in addresses})[0]


def _with_sync_token(url: str, token: str | None) -> str:
    if token is None:
        return url
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("since", token))
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
    )


def _pin_request_destination(
    url: str, address: str | None
) -> tuple[str, dict[str, Any]]:
    if address is None:
        return url, {}
    parsed = urlsplit(url)
    ip = ipaddress.ip_address(address)
    netloc = f"[{ip}]" if ip.version == 6 else str(ip)
    pinned_url = urlunsplit(
        (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
    )
    assert parsed.hostname is not None
    return pinned_url, {"sni_hostname": parsed.hostname.encode("idna").decode("ascii")}


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
    original_request_url = _with_sync_token(url, token)
    request_url, extensions = _pin_request_destination(
        original_request_url, resolved_address
    )
    original_authority = urlsplit(url).netloc
    try:
        async with client.stream(
            "GET",
            request_url,
            headers={"Accept": "application/json", "Host": original_authority},
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
        raw: object = json.loads(body)
        return RegistryFeed.model_validate(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RegistrySyncError("registry response violates the sync contract") from exc


def _certificate_time(certificate: x509.Certificate, name: str) -> datetime:
    utc_name = f"{name}_utc"
    value = getattr(certificate, utc_name, None)
    if value is None:
        value = getattr(certificate, name)
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _validate_certificate(entry: RegistryEntry, now: datetime) -> ImportedRegistryEntry:
    assert entry.certificate_pem is not None
    try:
        certificate = x509.load_pem_x509_certificate(entry.certificate_pem.encode())
    except ValueError as exc:
        raise RegistrySyncError(
            "registry entry contains an invalid certificate"
        ) from exc

    not_before = _certificate_time(certificate, "not_valid_before")
    not_after = _certificate_time(certificate, "not_valid_after")
    if now < not_before or now >= not_after:
        raise RegistrySyncError("registry entry certificate is not currently valid")
    if entry.not_before and abs((entry.not_before - not_before).total_seconds()) > 1:
        raise RegistrySyncError(
            "registry entry not_before does not match its certificate"
        )
    if entry.not_after and abs((entry.not_after - not_after).total_seconds()) > 1:
        raise RegistrySyncError(
            "registry entry not_after does not match its certificate"
        )

    try:
        basic_constraints = certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        key_usage = certificate.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
    except x509.ExtensionNotFound as exc:
        raise RegistrySyncError(
            "registry certificate lacks required X.509 constraints"
        ) from exc

    if entry.anchor_type == "CSCA":
        if not basic_constraints.ca or not key_usage.key_cert_sign:
            raise RegistrySyncError("CSCA entry is not a certificate-signing CA")
    elif basic_constraints.ca or not key_usage.digital_signature:
        raise RegistrySyncError("DSC entry is not a document-signing certificate")

    return ImportedRegistryEntry(
        entry_id=str(entry.entry_id),
        anchor_type=entry.anchor_type,
        country_code=entry.country_code,
        certificate_pem=entry.certificate_pem,
        source=entry.source,
        subject_key_id=entry.subject_key_id,
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
    )


def validate_current_registry_entries(
    entries: dict[str, ImportedRegistryEntry],
    *,
    now: datetime | None = None,
) -> dict[str, ImportedRegistryEntry]:
    """Revalidate persisted entries before they can influence trust."""
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    validated: dict[str, ImportedRegistryEntry] = {}
    for storage_id, imported in entries.items():
        if storage_id != imported.entry_id:
            raise RegistrySyncError("stored registry entry identity is inconsistent")
        try:
            candidate = RegistryEntry.model_validate(
                {
                    "entry_id": imported.entry_id,
                    "anchor_type": imported.anchor_type,
                    "operation": "ADD",
                    "country_code": imported.country_code,
                    "certificate_pem": imported.certificate_pem,
                    "subject_key_id": imported.subject_key_id,
                    "not_before": imported.not_before,
                    "not_after": imported.not_after,
                    "source": imported.source,
                }
            )
        except ValueError as exc:
            raise RegistrySyncError("stored registry entry is invalid") from exc
        validated[storage_id] = _validate_certificate(candidate, effective_now)
    return validated


async def synchronize_registry(
    url: str,
    previous: RegistryImportState,
    *,
    client: httpx.AsyncClient,
    validate_destination: DestinationValidator = require_public_registry_destination,
    now: datetime | None = None,
) -> RegistryImportResult:
    """Fetch all pages and return an atomic replacement state."""
    validate_registry_url_structure(url)
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    initial_sync = previous.sync_token is None
    entries = {} if initial_sync else dict(previous.entries)
    token = previous.sync_token
    previous_page_token: str | None = None
    current_sequence = previous.sequence
    seen_in_sync: set[str] = set()

    for page_number in range(1, MAX_PAGES + 1):
        feed = await fetch_registry_page(
            url,
            token,
            client=client,
            validate_destination=validate_destination,
        )
        if feed.sequence < current_sequence:
            raise RegistrySyncError("registry sequence rollback was rejected")
        if (
            page_number == 1
            and not initial_sync
            and feed.entries
            and feed.sequence == previous.sequence
        ):
            raise RegistrySyncError("registry changes did not advance the sequence")
        if previous_page_token is not None and feed.sync_token == previous_page_token:
            raise RegistrySyncError("registry repeated a pagination token")

        for remote in feed.entries:
            entry_id = str(remote.entry_id)
            if entry_id in seen_in_sync:
                raise RegistrySyncError("registry sync contains a duplicate entry")
            seen_in_sync.add(entry_id)
            if remote.operation == "REMOVE":
                if initial_sync:
                    raise RegistrySyncError("initial registry sync contains a removal")
                if entry_id not in entries:
                    raise RegistrySyncError("registry removed an unknown source entry")
                del entries[entry_id]
            else:
                entries[entry_id] = _validate_certificate(remote, effective_now)

        current_sequence = feed.sequence
        previous_page_token = feed.sync_token
        token = feed.sync_token
        if not feed.has_more:
            entries = validate_current_registry_entries(
                entries,
                now=effective_now,
            )
            synchronized = RegistryImportState(
                sync_token=token,
                sequence=current_sequence,
                entries=entries,
                synchronized_at=effective_now,
            )
            return RegistryImportResult(state=synchronized, pages=page_number)

    raise RegistrySyncError("registry pagination exceeded the page limit")


def state_from_storage(
    *,
    sync_token: str | None,
    sequence: int,
    entries: dict[str, dict[str, Any]],
    synchronized_at: datetime | None,
) -> RegistryImportState:
    try:
        parsed = {
            entry_id: ImportedRegistryEntry.from_storage(value)
            for entry_id, value in entries.items()
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise RegistrySyncError("stored registry state is invalid") from exc
    return RegistryImportState(
        sync_token=sync_token,
        sequence=sequence,
        entries=parsed,
        synchronized_at=synchronized_at,
    )
