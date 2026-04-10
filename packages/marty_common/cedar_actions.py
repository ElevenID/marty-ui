"""Route-to-Cedar action mapping for MIP gateway authorization.

Maps HTTP method + URL path to the canonical Cedar action strings defined
in the MIP Cedar schema (mip.cedarschema).

Supports both:
- classic org-scoped paths: ``/v1/organizations/{org_id}/...``
- top-level org-owned resources: ``/v1/application-templates/...``
"""

import re
from typing import Optional

# Maps the first path segment after /v1/organizations/{org_id}/ to Cedar actions.
# Tuple format: (read_action, write_action, delete_action, cedar_resource_type)
# cedar_resource_type must match an entity type in mip.cedarschema.
RESOURCE_ACTION_MAP: dict[str, tuple[str, str, str, str]] = {
    # Organization member & invitation management
    "members": ("users:read", "users:invite", "users:invite", "User"),
    "invitations": ("users:read", "users:invite", "users:invite", "Organization"),
    # API key management
    "api-keys": ("keys:read", "keys:write", "keys:write", "Organization"),
    # Role management
    "roles": ("roles:read", "roles:write", "roles:write", "Role"),
    # Organization settings (admin-only)
    "settings": ("admin:full", "admin:full", "admin:full", "Organization"),
    # Digital Identity Model — Configuration resources
    "credential-templates": ("templates:read", "templates:write", "templates:write", "CredentialTemplate"),
    "trust-profiles": ("trust:read", "trust:write", "trust:write", "TrustProfile"),
    "compliance-profiles": ("compliance:read", "compliance:write", "compliance:write", "ComplianceProfile"),
    "presentation-policies": ("trust:read", "trust:write", "trust:write", "PresentationPolicy"),
    "deployment-profiles": ("deployment:read", "deployment:write", "deployment:write", "DeploymentProfile"),
    "revocation-profiles": ("trust:read", "trust:admin", "trust:admin", "RevocationProfile"),
    # Digital Identity Model — Operational resources
    "flows": ("flows:read", "flows:write", "flows:write", "Flow"),
    "issuance": ("credentials:read", "credentials:issue", "credentials:revoke", "Credential"),
    "credentials": ("credentials:read", "credentials:issue", "credentials:revoke", "Credential"),
    "applications": ("applications:read", "applications:write", "applications:write", "Application"),
    "applicants": ("applications:read", "applications:write", "applications:write", "Application"),
    "application-templates": ("applications:read", "applications:write", "applications:write", "Application"),
    # Utility resources
    "webhooks": ("webhooks:read", "webhooks:write", "webhooks:write", "WebhookEndpoint"),
    "notifications": ("notifications:read", "notifications:send", "notifications:send", "Organization"),
    "audit-log": ("audit:read", "audit:read", "audit:read", "AuditEvent"),
    # Verification
    "verify": ("credentials:read", "credentials:verify", "credentials:verify", "Credential"),
    # Cedar policy management (admin-only for writes)
    "policy-sets": ("trust:read", "trust:admin", "trust:admin", "TrustProfile"),
}

# Regex to extract org_id and resource segment from org-scoped paths.
_ORG_PATH_RE = re.compile(r"^/v1/organizations/([a-f0-9\-]{36})/([^/]+)")
_TOP_LEVEL_PATH_RE = re.compile(r"^/v1/([^/]+)(?:/|$)")
_TOP_LEVEL_RESOURCE_RE = re.compile(r"^/v1/([^/]+)/([^/]+)(?:/|$)")


RESOURCE_LOOKUP_MAP: dict[str, tuple[str, str, set[str]]] = {
    "credential-templates": (
        "credential-templates",
        "/v1/credential-templates/{resource_id}",
        set(),
    ),
    "trust-profiles": (
        "trust-profiles",
        "/v1/trust-profiles/{resource_id}",
        set(),
    ),
    "issuer-entities": (
        "trust-profiles",
        "/v1/issuer-entities/{resource_id}",
        set(),
    ),
    "compliance-profiles": (
        "compliance-profiles",
        "/v1/compliance-profiles/{resource_id}",
        set(),
    ),
    "presentation-policies": (
        "presentation-policies",
        "/v1/presentation-policies/{resource_id}",
        set(),
    ),
    "deployment-profiles": (
        "deployment-profiles",
        "/v1/deployment-profiles/{resource_id}",
        set(),
    ),
    "revocation-profiles": (
        "revocation-profiles",
        "/v1/revocation-profiles/{resource_id}",
        set(),
    ),
    "flows": (
        "flows",
        "/v1/flows/{resource_id}",
        set(),
    ),
    "application-templates": (
        "issuance",
        "/v1/application-templates/{resource_id}",
        {"validate-artifacts"},
    ),
    "applications": (
        "issuance",
        "/v1/applications/{resource_id}",
        set(),
    ),
    "issued-credentials": (
        "issuance",
        "/v1/issued-credentials/{resource_id}",
        set(),
    ),
    "issuance": (
        "issuance",
        "/v1/issuance/transactions/{resource_id}",
        {
            "offers",
            "token",
            "credential",
            "nonce",
            "notification",
            "deferred-credential",
            "authorize",
            "par",
            "didcomm",
            "initiate",
            "transactions",
        },
    ),
}


def _resolve_actions_for_method(
    method: str,
    actions: tuple[str, str, str, str],
) -> tuple[str, str]:
    """Return the Cedar action/resource pair for the HTTP method."""
    read_action, write_action, delete_action, resource_type = actions
    if method in ("GET", "HEAD", "OPTIONS"):
        return (read_action, resource_type)
    if method == "DELETE":
        return (delete_action, resource_type)
    return (write_action, resource_type)


def resolve_action(method: str, path: str) -> Optional[str]:
    """Resolve an HTTP method + path to a Cedar action string.

    Returns the Cedar action (e.g. "credentials:read") for org-scoped paths,
    or None for paths that don't match an org-scoped pattern.
    """
    match = _ORG_PATH_RE.match(path)
    if not match:
        top_level = _TOP_LEVEL_PATH_RE.match(path)
        if not top_level:
            return None
        actions = RESOURCE_ACTION_MAP.get(top_level.group(1))
        if not actions:
            return None
        return _resolve_actions_for_method(method, actions)[0]

    resource_segment = match.group(2)
    actions = RESOURCE_ACTION_MAP.get(resource_segment)
    if not actions:
        # Unknown resource segment — require admin:full (fail-safe)
        return "admin:full"
    return _resolve_actions_for_method(method, actions)[0]


def resolve_action_and_resource(method: str, path: str) -> Optional[tuple[str, str]]:
    """Resolve an HTTP method + path to a Cedar action and resource type.

    Returns (action, resource_type) for org-scoped paths, e.g.
    ("credentials:read", "Credential"), or None for non-org paths.
    """
    match = _ORG_PATH_RE.match(path)
    if not match:
        top_level = _TOP_LEVEL_PATH_RE.match(path)
        if not top_level:
            return None
        actions = RESOURCE_ACTION_MAP.get(top_level.group(1))
        if not actions:
            return None
        return _resolve_actions_for_method(method, actions)

    resource_segment = match.group(2)
    actions = RESOURCE_ACTION_MAP.get(resource_segment)
    if not actions:
        return ("admin:full", "Organization")
    return _resolve_actions_for_method(method, actions)


def extract_org_id(path: str) -> Optional[str]:
    """Extract organization ID from an org-scoped path.

    Returns the org_id for paths like /v1/organizations/{uuid}/...,
    or None for non-org-scoped paths.
    """
    match = _ORG_PATH_RE.match(path)
    return match.group(1) if match else None


def resolve_resource_lookup(path: str) -> Optional[tuple[str, str]]:
    """Return the backend service/path used to look up a resource owner org.

    This is used for top-level resource routes where the organization is not
    embedded in the URL, e.g. ``/v1/application-templates/{id}``.
    """
    match = _TOP_LEVEL_RESOURCE_RE.match(path)
    if not match:
        return None

    resource_segment, resource_id = match.groups()
    lookup = RESOURCE_LOOKUP_MAP.get(resource_segment)
    if not lookup:
        return None

    service_name, lookup_template, reserved_segments = lookup
    if resource_id in reserved_segments:
        return None

    return (service_name, lookup_template.format(resource_id=resource_id))
