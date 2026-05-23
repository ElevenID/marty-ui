"""Shared Marty runtime URL and DID defaults.

These helpers centralize the environment-derived URL conventions used by
runtime bootstrap code and reset-friendly seed paths. New code should prefer
them over embedding beta hostnames directly in migrations or services.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from .system_ids import (
    MARTY_DEFAULT_ORG_ID,
    MARTY_DEFAULT_ORG_SLUG,
    MARTY_DEFAULT_REVOCATION_PROFILE_ID,
)


DEFAULT_MARTY_ISSUER_BASE_URL = "https://beta.elevenidllc.com"
DEFAULT_MARTY_PUBLIC_DOMAIN = "beta.elevenidllc.com"


def resolve_marty_issuer_base_url() -> str:
    """Resolve the public issuer base URL for Marty-managed artifacts."""
    return (
        os.environ.get("MARTY_ISSUER_BASE_URL")
        or os.environ.get("ISSUER_BASE_URL")
        or os.environ.get("PUBLIC_API_URL")
        or DEFAULT_MARTY_ISSUER_BASE_URL
    ).rstrip("/")


def _normalize_org_slug(value: str | None) -> str:
    normalized = (value or "").strip().lower()
    if not normalized:
        return MARTY_DEFAULT_ORG_SLUG

    slug = "".join(ch for ch in normalized if ch.isalnum() or ch in "._-")
    return slug or MARTY_DEFAULT_ORG_SLUG


def resolve_marty_org_slug() -> str:
    """Resolve the Marty org slug used for DID derivation."""
    return _normalize_org_slug(os.environ.get("MARTY_ORG_SLUG", MARTY_DEFAULT_ORG_SLUG))


def resolve_marty_public_domain(issuer_base_url: str | None = None) -> str:
    """Resolve the public domain used for DID:web generation."""
    configured = (os.environ.get("PUBLIC_DOMAIN") or "").strip().strip("/")
    if configured:
        return configured

    parsed = urlparse((issuer_base_url or resolve_marty_issuer_base_url()).strip())
    return (parsed.netloc or DEFAULT_MARTY_PUBLIC_DOMAIN).strip().strip("/")


def resolve_marty_issuer_did(
    *,
    org_slug: str | None = None,
    issuer_base_url: str | None = None,
) -> str:
    """Resolve the default Marty DID:web issuer identifier."""
    configured = (os.environ.get("MARTY_ISSUER_DID") or "").strip()
    if configured:
        return configured

    did_web_domain = resolve_marty_public_domain(issuer_base_url).replace(":", "%3A").replace("/", ":")
    return f"did:web:{did_web_domain}:orgs:{_normalize_org_slug(org_slug or resolve_marty_org_slug())}"


def build_marty_status_list_base_url(
    *,
    organization_id: str = MARTY_DEFAULT_ORG_ID,
    revocation_profile_id: str = MARTY_DEFAULT_REVOCATION_PROFILE_ID,
    issuer_base_url: str | None = None,
) -> str:
    """Build the public status-list base URL for the Marty revocation profile."""
    base_url = (issuer_base_url or resolve_marty_issuer_base_url()).rstrip("/")
    return (
        f"{base_url}/v1/organizations/{organization_id}"
        f"/revocation-profiles/{revocation_profile_id}/status-lists/{{mechanism}}/{{purpose}}"
    )