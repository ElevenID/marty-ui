"""Fail-closed destination handling for outbound notification webhooks."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

WEBHOOK_SECRET_ENV = "NOTIFICATION_WEBHOOK_SECRET"
WEBHOOK_SECRET_FILE_ENV = "NOTIFICATION_WEBHOOK_SECRET_FILE"
MIN_WEBHOOK_SECRET_LENGTH = 32


class WebhookDestinationError(Exception):
    """A safe, classified webhook destination failure."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True)
class PinnedWebhookDestination:
    """A URL pinned to an already-validated address for one request attempt."""

    url: str
    host_header: str
    extensions: dict[str, Any]


def valid_webhook_signing_secret(secret: str) -> bool:
    """Require a non-placeholder HMAC key with a useful security margin."""
    normalized = secret.strip()
    lowered = normalized.lower()
    return len(normalized) >= MIN_WEBHOOK_SECRET_LENGTH and not lowered.startswith(
        ("change-me", "change_me", "changeme")
    )


def load_direct_webhook_signing_secret() -> str | None:
    """Load the direct-webhook key from exactly one env or file source."""
    inline = os.environ.get(WEBHOOK_SECRET_ENV, "").strip()
    secret_file = os.environ.get(WEBHOOK_SECRET_FILE_ENV, "").strip()
    if inline and secret_file:
        return None
    if secret_file:
        try:
            with open(secret_file, encoding="utf-8") as secret_handle:
                inline = secret_handle.read().strip()
        except OSError:
            return None
    return inline if valid_webhook_signing_secret(inline) else None


def validate_webhook_url_structure(url: str) -> str:
    """Reject URL forms that make HTTPS destination validation ambiguous."""
    if not url or url != url.strip():
        raise WebhookDestinationError("WEBHOOK_DESTINATION_REJECTED")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise WebhookDestinationError("WEBHOOK_DESTINATION_REJECTED") from exc
    if parsed.scheme.lower() != "https":
        raise WebhookDestinationError("WEBHOOK_HTTPS_REQUIRED")
    if not parsed.hostname:
        raise WebhookDestinationError("WEBHOOK_DESTINATION_REJECTED")
    if parsed.username is not None or parsed.password is not None:
        raise WebhookDestinationError("WEBHOOK_DESTINATION_REJECTED")
    if parsed.fragment:
        raise WebhookDestinationError("WEBHOOK_DESTINATION_REJECTED")
    if port is not None and not 1 <= port <= 65535:
        raise WebhookDestinationError("WEBHOOK_DESTINATION_REJECTED")
    try:
        parsed.hostname.encode("idna")
    except UnicodeError as exc:
        raise WebhookDestinationError("WEBHOOK_DESTINATION_REJECTED") from exc

    try:
        literal_address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        if not literal_address.is_global:
            raise WebhookDestinationError("WEBHOOK_DESTINATION_REJECTED")
    return url


async def resolve_webhook_destination(url: str) -> PinnedWebhookDestination:
    """Resolve, validate, and pin one public address for a single attempt."""
    parsed = urlsplit(validate_webhook_url_structure(url))
    assert parsed.hostname is not None
    port = parsed.port or 443
    try:
        addresses = await asyncio.to_thread(
            socket.getaddrinfo,
            parsed.hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise WebhookDestinationError(
            "WEBHOOK_DESTINATION_UNAVAILABLE", retryable=True
        ) from exc
    if not addresses:
        raise WebhookDestinationError("WEBHOOK_DESTINATION_UNAVAILABLE", retryable=True)

    resolved: set[str] = set()
    for address in addresses:
        try:
            candidate = ipaddress.ip_address(address[4][0])
        except ValueError as exc:
            raise WebhookDestinationError("WEBHOOK_DESTINATION_REJECTED") from exc
        if not candidate.is_global:
            raise WebhookDestinationError("WEBHOOK_DESTINATION_REJECTED")
        resolved.add(candidate.compressed)

    selected = ipaddress.ip_address(sorted(resolved)[0])
    pinned_host = (
        f"[{selected.compressed}]" if selected.version == 6 else selected.compressed
    )
    pinned_netloc = f"{pinned_host}:{port}" if port != 443 else pinned_host
    pinned_url = urlunsplit(
        (parsed.scheme, pinned_netloc, parsed.path, parsed.query, "")
    )

    tls_hostname = parsed.hostname.encode("idna").decode("ascii")
    try:
        original_address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        host_name = tls_hostname
    else:
        host_name = (
            f"[{original_address.compressed}]"
            if original_address.version == 6
            else original_address.compressed
        )
    host_header = f"{host_name}:{port}" if port != 443 else host_name
    return PinnedWebhookDestination(
        url=pinned_url,
        host_header=host_header,
        extensions={"sni_hostname": tls_hostname},
    )
