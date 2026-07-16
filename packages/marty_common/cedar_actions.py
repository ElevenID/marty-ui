"""Route-to-permission mapping for gateway organization authorization."""

from __future__ import annotations

import re
from typing import Optional


_UUID_RE = r"([a-f0-9\-]{36})"
_ORG_PATH_RE = re.compile(rf"^/v1/organizations/{_UUID_RE}(?:/|$)")
_TOP_LEVEL_RESOURCE_RE = re.compile(r"^/v1/([^/]+)/([^/]+)(?:/|$)")
_FLOW_RESOURCE_RE = re.compile(r"^/v1/flows/(definitions|instances)/([^/]+)(?:/|$)")
_CANVAS_PLATFORM_RESOURCE_RE = re.compile(
    r"^/v1/integrations/canvas/platforms/([^/]+)(?:/|$)"
)
_CANVAS_BINDING_RESOURCE_RE = re.compile(
    r"^/v1/integrations/canvas/program-bindings/([^/]+)(?:/|$)"
)


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
        {"definitions", "instances", "verify", "siop"},
    ),
    "application-templates": (
        "issuance",
        "/v1/application-templates/{resource_id}",
        {"validate-artifacts"},
    ),
    "issued-credentials": (
        "issuance",
        "/v1/issued-credentials/{resource_id}",
        {"mine"},
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
    "policy-sets": (
        "organizations",
        "/v1/policy-sets/{resource_id}",
        {"validate"},
    ),
}


SPECIAL_ROUTE_RULES: list[tuple[re.Pattern[str], dict[str, str], str]] = [
    (
        re.compile(r"^/v1/integrations/canvas/platforms/[^/]+/(?:registration-config|readiness)$"),
        {"GET": "integration-connector:view"},
        "integration-connector",
    ),
    (
        re.compile(r"^/v1/integrations/canvas/platforms/[^/]+/scope-discovery$"),
        {"POST": "integration-connector:view"},
        "integration-connector",
    ),
    (
        re.compile(r"^/v1/integrations/canvas/platforms/[^/]+/(?:sandbox-probe|jwks-refresh|oauth/start|oauth/authorizations)$"),
        {"POST": "integration-connector:edit"},
        "integration-connector",
    ),
    (
        re.compile(r"^/v1/integrations/canvas/platforms/[^/]+/lti-installation$"),
        {"PUT": "integration-connector:edit"},
        "integration-connector",
    ),
    (
        re.compile(r"^/v1/integrations/canvas/program-bindings/[^/]+/(?:validate|activate|deactivate)$"),
        {"POST": "integration-connector:edit"},
        "integration-connector",
    ),
    (
        re.compile(r"^/v1/integrations/canvas/applications/[^/]+/(?:approve|canvas-sync)$"),
        {"POST": "integration-connector:edit"},
        "integration-connector",
    ),
    (
        re.compile(r"^/v1/integrations/canvas/canvas-sync-jobs/[^/]+/(?:retry|resolve)$"),
        {"POST": "integration-connector:edit"},
        "integration-connector",
    ),
    (
        re.compile(r"^/v1/integrations/canvas/evidence-policy-reviews/[^/]+/resolve$"),
        {"POST": "integration-connector:edit"},
        "integration-connector",
    ),
    (
        re.compile(r"^/v1/integrations/canvas/platforms/[^/]+/oauth$"),
        {"DELETE": "integration-connector:edit"},
        "integration-connector",
    ),
    (
        re.compile(r"^/v1/integrations/canvas/canvas-credentials/validate$"),
        {"POST": "integration-connector:view"},
        "integration-connector",
    ),
    (
        re.compile(r"^/v1/credential-templates/[^/]+/activate$"),
        {"POST": "credential-template:activate"},
        "credential-template",
    ),
    (
        re.compile(r"^/v1/credential-templates/[^/]+/deprecate$"),
        {"POST": "credential-template:deprecate"},
        "credential-template",
    ),
    (
        re.compile(r"^/v1/credential-templates/[^/]+/new-version$"),
        {"POST": "credential-template:version"},
        "credential-template",
    ),
    (
        re.compile(r"^/v1/revocation-profiles/[^/]+/activate$"),
        {"POST": "revocation-profile:activate"},
        "revocation-profile",
    ),
    (
        re.compile(r"^/v1/issued-credentials/[^/]+/(revoke|suspend|reinstate)$"),
        {"POST": "issuance:revoke"},
        "issued-credential",
    ),
    (
        re.compile(r"^/v1/issued-credentials/[^/]+/renew$"),
        {"POST": "issuance:initiate"},
        "issued-credential",
    ),
    (
        re.compile(r"^/v1/issued-credentials(?:/[^/]+)?$"),
        {
            "GET": "issuance:view",
            "HEAD": "issuance:view",
            "OPTIONS": "issuance:view",
        },
        "issued-credential",
    ),
    (
        re.compile(r"^/v1/issuance/[^/]+/revoke$"),
        {"POST": "issuance:revoke"},
        "issued-credential",
    ),
    (
        re.compile(r"^/v1/issuance(?:/[^/]+)?$"),
        {
            "GET": "issuance:view",
            "POST": "issuance:initiate",
            "HEAD": "issuance:view",
            "OPTIONS": "issuance:view",
        },
        "issuance",
    ),
    (
        re.compile(r"^/v1/organizations/[^/]+/dashboard/applicant-stats$"),
        {"GET": "application:review"},
        "application",
    ),
    (
        re.compile(r"^/v1/organizations/[^/]+/applicants(?:/[^/]+)?/issue$"),
        {"POST": "issuance:initiate"},
        "application",
    ),
    (
        re.compile(r"^/v1/organizations/[^/]+/applicants/[^/]+/approve$"),
        {"POST": "application:approve"},
        "application",
    ),
    (
        re.compile(r"^/v1/organizations/[^/]+/applicants/[^/]+/reject$"),
        {"POST": "application:reject"},
        "application",
    ),
    (
        re.compile(r"^/v1/organizations/[^/]+/applicants(?:/.*)?$"),
        {
            "GET": "application:review",
            "POST": "application:review",
            "PATCH": "application:review",
            "DELETE": "application:review",
            "HEAD": "application:review",
            "OPTIONS": "application:review",
        },
        "application",
    ),
    (
        re.compile(r"^/v1/flows/verify$"),
        {"POST": "verification:execute"},
        "verification",
    ),
    (
        re.compile(r"^/v1/flows/definitions/[^/]+/activate$"),
        {"POST": "flow-definition:activate"},
        "flow-definition",
    ),
    (
        re.compile(r"^/v1/flows/instances(?:/[^/]+)?(?:/advance)?$"),
        {
            "GET": "flow-instance:view",
            "POST": "flow-instance:start",
            "HEAD": "flow-instance:view",
            "OPTIONS": "flow-instance:view",
        },
        "flow-instance",
    ),
    (
        re.compile(r"^/v1/flows/definitions(?:/[^/]+)?(?:/activate)?$"),
        {
            "GET": "flow-definition:view",
            "POST": "flow-definition:create",
            "PUT": "flow-definition:edit",
            "PATCH": "flow-definition:edit",
            "DELETE": "flow-definition:delete",
        },
        "flow-definition",
    ),
    (
        re.compile(rf"^/v1/organizations/{_UUID_RE}/transfer-ownership$"),
        {"POST": "organization:transfer-ownership"},
        "organization",
    ),
    (
        re.compile(rf"^/v1/organizations/{_UUID_RE}/members/me/permissions$"),
        {"GET": "organization:view"},
        "organization",
    ),
    (
        re.compile(rf"^/v1/organizations/{_UUID_RE}/members/[^/]+/roles(?:/[^/]+)?$"),
        {"PUT": "role:assign", "POST": "role:assign", "DELETE": "role:assign"},
        "role",
    ),
    (
        re.compile(rf"^/v1/organizations/{_UUID_RE}/roles(?:/[^/]+)?$"),
        {
            "GET": "role:view",
            "POST": "role:create",
            "PUT": "role:edit",
            "PATCH": "role:edit",
            "DELETE": "role:delete",
        },
        "role",
    ),
    (
        re.compile(rf"^/v1/organizations/{_UUID_RE}/permissions$"),
        {"GET": "role:view"},
        "role",
    ),
    (
        re.compile(rf"^/v1/organizations/{_UUID_RE}/members(?:/[^/]+)?$"),
        {
            "GET": "team:view",
            "POST": "team:invite",
            "PUT": "team:manage",
            "PATCH": "team:manage",
            "DELETE": "team:manage",
        },
        "team",
    ),
    (
        re.compile(rf"^/v1/organizations/{_UUID_RE}/api-keys(?:/[^/]+)?$"),
        {
            "GET": "api-key:view",
            "POST": "api-key:create",
            "PUT": "api-key:edit",
            "PATCH": "api-key:edit",
            "DELETE": "api-key:revoke",
        },
        "api-key",
    ),
    (
        re.compile(rf"^/v1(?:/organizations/{_UUID_RE})?/policy-sets/[^/]+/activate$"),
        {"POST": "policy-set:activate"},
        "policy-set",
    ),
    (
        re.compile(rf"^/v1(?:/organizations/{_UUID_RE})?/policy-sets/[^/]+/archive$"),
        {"POST": "policy-set:archive"},
        "policy-set",
    ),
    (
        re.compile(rf"^/v1(?:/organizations/{_UUID_RE})?/policy-sets/validate$"),
        {"POST": "policy-set:validate"},
        "policy-set",
    ),
    (
        re.compile(rf"^/v1(?:/organizations/{_UUID_RE})?/policy-sets/[^/]+/validate$"),
        {"POST": "policy-set:validate"},
        "policy-set",
    ),
    (
        re.compile(rf"^/v1/organizations/{_UUID_RE}/lifecycle$"),
        {"GET": "organization:view"},
        "organization",
    ),
    (
        re.compile(rf"^/v1/organizations/{_UUID_RE}/scim/v2/Users(?:/[^/]+)?$"),
        {
            "GET": "team:view",
            "POST": "team:invite",
            "PUT": "team:manage",
            "PATCH": "team:manage",
            "DELETE": "team:manage",
        },
        "team",
    ),
    (
        re.compile(rf"^/v1/organizations/{_UUID_RE}/scim/v2/Groups(?:/[^/]+)?$"),
        {
            "GET": "role:view",
            "POST": "role:create",
            "PUT": "role:edit",
            "PATCH": "role:edit",
            "DELETE": "role:delete",
        },
        "role",
    ),
    (
        re.compile(rf"^/v1/organizations/{_UUID_RE}/scim/v2/(ServiceProviderConfig|Schemas|ResourceTypes)$"),
        {"GET": "organization:view"},
        "organization",
    ),
]


GENERIC_RESOURCE_MAP: dict[str, tuple[str, str]] = {
    "credential-templates": ("credential-template", "credential-template"),
    "trust-profiles": ("trust-profile", "trust-profile"),
    "compliance-profiles": ("compliance-profile", "compliance-profile"),
    "presentation-policies": ("presentation-policy", "presentation-policy"),
    "revocation-profiles": ("revocation-profile", "revocation-profile"),
    "deployment-profiles": ("deployment-profile", "deployment-profile"),
    "flows": ("flow-definition", "flow-definition"),
    "flow-instances": ("flow-instance", "flow-instance"),
    "application-templates": ("application-template", "application-template"),
    "verification": ("verification", "verification"),
    "integrations": ("integration-connector", "integration-connector"),
    "policy-sets": ("policy-set", "policy-set"),
}


def _resolve_generic_org_permission(method: str, segment: str) -> Optional[tuple[str, str]]:
    mapping = GENERIC_RESOURCE_MAP.get(segment)
    if mapping is None:
        return None

    permission_resource, resource_name = mapping
    normalized_method = method.upper()
    if normalized_method in {"GET", "HEAD", "OPTIONS"}:
        return (f"{permission_resource}:view", resource_name)
    if normalized_method == "POST":
        if permission_resource == "verification":
            return (f"{permission_resource}:execute", resource_name)
        if permission_resource == "flow-instance":
            return (f"{permission_resource}:start", resource_name)
        return (f"{permission_resource}:create", resource_name)
    if normalized_method in {"PUT", "PATCH"}:
        if permission_resource == "verification":
            return (f"{permission_resource}:execute", resource_name)
        return (f"{permission_resource}:edit", resource_name)
    if normalized_method == "DELETE":
        return (f"{permission_resource}:delete", resource_name)
    return None


def resolve_action(method: str, path: str) -> Optional[str]:
    resolved = resolve_action_and_resource(method, path)
    return resolved[0] if resolved else None


def resolve_action_and_resource(method: str, path: str) -> Optional[tuple[str, str]]:
    for pattern, method_map, resource_name in SPECIAL_ROUTE_RULES:
        if pattern.match(path):
            permission_key = method_map.get(method.upper())
            if permission_key:
                return (permission_key, resource_name)
            return None

    org_match = re.match(rf"^/v1/organizations/{_UUID_RE}/([^/]+)", path)
    if org_match:
        return _resolve_generic_org_permission(method, org_match.group(2))

    top_level_match = re.match(r"^/v1/([^/]+)(?:/|$)", path)
    if top_level_match:
        return _resolve_generic_org_permission(method, top_level_match.group(1))

    return None


def extract_org_id(path: str) -> Optional[str]:
    match = _ORG_PATH_RE.match(path)
    if not match:
        return None
    uuid_match = re.match(rf"^/v1/organizations/{_UUID_RE}", path)
    return uuid_match.group(1) if uuid_match else None


def resolve_resource_lookup(path: str) -> Optional[tuple[str, str]]:
    canvas_platform_match = _CANVAS_PLATFORM_RESOURCE_RE.match(path)
    if canvas_platform_match:
        platform_id = canvas_platform_match.group(1)
        return ("issuance", f"/v1/integrations/canvas/platforms/{platform_id}")

    canvas_binding_match = _CANVAS_BINDING_RESOURCE_RE.match(path)
    if canvas_binding_match:
        binding_id = canvas_binding_match.group(1)
        return ("issuance", f"/v1/integrations/canvas/program-bindings/{binding_id}")

    flow_match = _FLOW_RESOURCE_RE.match(path)
    if flow_match:
        resource_type, resource_id = flow_match.groups()
        return ("flows", f"/v1/flows/{resource_type}/{resource_id}")

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
