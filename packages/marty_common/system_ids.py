"""Stable Marty system IDs shared by runtime defaults, docs, and new migrations.

These IDs are architectural glue across services. Treat them as immutable once a
release lands in a persistent environment. Historical migrations may still embed
literals; new runtime code, new migrations, and documentation should prefer this
module so the canonical set is easy to audit.

Important: IDs are namespaced by service/resource type. Numeric collisions can
exist across different services (for example deployment profile and revocation
profile both use the `70000000-...-0001` family value). Do not compare IDs
across resource types without also checking the service/table context.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final


MARTY_DEFAULT_ORG_ID: Final[str] = "00000000-0000-0000-0000-000000000001"
MARTY_DEFAULT_ORG_SLUG: Final[str] = "marty"

MARTY_SYSTEM_ORG_IDS = MappingProxyType({
    "marty_default": MARTY_DEFAULT_ORG_ID,
})

MARTY_SYSTEM_TEMPLATE_IDS = MappingProxyType({
    "member_sd_jwt": "50000000-0000-0000-0000-000000000010",
    "member_mdoc": "50000000-0000-0000-0000-000000000030",
    "verified_member_badge": "50000000-0000-0000-0000-000000000040",
    "canvas_mip_quiz_open_badge": "50000000-0000-0000-0000-000000000041",
})

MARTY_SYSTEM_APPLICATION_TEMPLATE_IDS = MappingProxyType({
    "verified_member_badge": "0ab66d45-0d84-5fbd-837f-25788d32279e",
    "canvas_mip_quiz_open_badge": "0ab66d45-0d84-5fbd-837f-25788d3227a1",
})

MARTY_SYSTEM_POLICY_IDS = MappingProxyType({
    "open_badge_login": "50000000-0000-0000-0000-000000000004",
})

MARTY_SYSTEM_TRUST_PROFILE_IDS = MappingProxyType({
    "login_default": "60000000-0000-0000-0000-000000000001",
    "icao_travel": "60000000-0000-0000-0000-000000000002",
    "mdl_aamva": "60000000-0000-0000-0000-000000000003",
})

MARTY_SYSTEM_TRUST_SOURCE_IDS = MappingProxyType({
    "login_trusted_issuer": "60000000-0000-0000-0000-000000000011",
    "trust_bundle": "60000000-0000-0000-0000-000000000021",
    "icao_marty_issuer": "60000000-0000-0000-0000-000000000031",
    "icao_pkd_registry": "60000000-0000-0000-0000-000000000032",
    "mdl_marty_issuer": "60000000-0000-0000-0000-000000000033",
    "mdl_aamva_registry": "60000000-0000-0000-0000-000000000034",
})

MARTY_SYSTEM_REVOCATION_PROFILE_IDS = MappingProxyType({
    "default": "70000000-0000-0000-0000-000000000001",
})

MARTY_SYSTEM_DEPLOYMENT_PROFILE_IDS = MappingProxyType({
    "login_default": "70000000-0000-0000-0000-000000000001",
})

MARTY_SYSTEM_FLOW_IDS = MappingProxyType({
    "credential_login": "71000000-0000-0000-0000-000000000001",
    "credential_login_instance": "71000000-0000-0000-0000-000000000101",
})

SYSTEM_ID_GROUPS = MappingProxyType({
    "organizations": MARTY_SYSTEM_ORG_IDS,
    "application_templates": MARTY_SYSTEM_APPLICATION_TEMPLATE_IDS,
    "credential_templates": MARTY_SYSTEM_TEMPLATE_IDS,
    "presentation_policies": MARTY_SYSTEM_POLICY_IDS,
    "trust_profiles": MARTY_SYSTEM_TRUST_PROFILE_IDS,
    "trust_sources": MARTY_SYSTEM_TRUST_SOURCE_IDS,
    "revocation_profiles": MARTY_SYSTEM_REVOCATION_PROFILE_IDS,
    "deployment_profiles": MARTY_SYSTEM_DEPLOYMENT_PROFILE_IDS,
    "flows": MARTY_SYSTEM_FLOW_IDS,
})

MARTY_MEMBER_SD_JWT_TEMPLATE_ID: Final[str] = MARTY_SYSTEM_TEMPLATE_IDS["member_sd_jwt"]
MARTY_MEMBER_MDOC_TEMPLATE_ID: Final[str] = MARTY_SYSTEM_TEMPLATE_IDS["member_mdoc"]
MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID: Final[str] = MARTY_SYSTEM_TEMPLATE_IDS["verified_member_badge"]
MARTY_VERIFIED_MEMBER_BADGE_APPLICATION_TEMPLATE_ID: Final[str] = MARTY_SYSTEM_APPLICATION_TEMPLATE_IDS["verified_member_badge"]
MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_TEMPLATE_ID: Final[str] = MARTY_SYSTEM_TEMPLATE_IDS["canvas_mip_quiz_open_badge"]
MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_APPLICATION_TEMPLATE_ID: Final[str] = MARTY_SYSTEM_APPLICATION_TEMPLATE_IDS["canvas_mip_quiz_open_badge"]
MARTY_OPEN_BADGE_LOGIN_POLICY_ID: Final[str] = MARTY_SYSTEM_POLICY_IDS["open_badge_login"]
MARTY_LOGIN_TRUST_PROFILE_ID: Final[str] = MARTY_SYSTEM_TRUST_PROFILE_IDS["login_default"]
MARTY_LOGIN_TRUSTED_ISSUER_ID: Final[str] = MARTY_SYSTEM_TRUST_SOURCE_IDS["login_trusted_issuer"]
MARTY_TRUST_BUNDLE_SOURCE_ID: Final[str] = MARTY_SYSTEM_TRUST_SOURCE_IDS["trust_bundle"]
MARTY_DEFAULT_REVOCATION_PROFILE_ID: Final[str] = MARTY_SYSTEM_REVOCATION_PROFILE_IDS["default"]
MARTY_DEFAULT_DEPLOYMENT_PROFILE_ID: Final[str] = MARTY_SYSTEM_DEPLOYMENT_PROFILE_IDS["login_default"]
MARTY_CREDENTIAL_LOGIN_FLOW_ID: Final[str] = MARTY_SYSTEM_FLOW_IDS["credential_login"]
MARTY_CREDENTIAL_LOGIN_FLOW_INSTANCE_ID: Final[str] = MARTY_SYSTEM_FLOW_IDS["credential_login_instance"]


def flatten_system_ids() -> dict[str, str]:
    """Return all known system IDs keyed by ``group.name``."""
    return {
        f"{group_name}.{item_name}": item_value
        for group_name, group in SYSTEM_ID_GROUPS.items()
        for item_name, item_value in group.items()
    }
