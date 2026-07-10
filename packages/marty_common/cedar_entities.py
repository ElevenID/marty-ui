"""Cedar entity builders for MIP authorization.

Builds the entity JSON structures that cedarpy expects for authorization
evaluation. Maps from Marty domain objects (users, orgs, roles, API keys)
to Cedar entity format.
"""

import time
from typing import Any, Optional


def build_user_entities(
    user_id: str,
    email: str,
    status: str,
    org_id: str,
    role: str,
) -> list[dict[str, Any]]:
    """Build Cedar entities for a session-authenticated user request.

    Returns a list containing the User, Organization, and Role entities
    with the correct parent hierarchy for Cedar evaluation.
    """
    role_id = role.lower()

    return [
        {
            "uid": {"type": "MIP::User", "id": user_id},
            "attrs": {
                "email": email or "",
                "status": status.upper(),
                "user_id": user_id,
            },
            "parents": [
                {"type": "MIP::Organization", "id": org_id},
                {"type": "MIP::Role", "id": role_id},
            ],
        },
        {
            "uid": {"type": "MIP::Organization", "id": org_id},
            "attrs": {},
            "parents": [],
        },
        {
            "uid": {"type": "MIP::Role", "id": role_id},
            "attrs": {"is_system_role": True},
            "parents": [
                {"type": "MIP::Organization", "id": org_id},
            ],
        },
    ]


def build_apikey_entities(
    api_key_id: str,
    org_id: str,
    scope_type: str,
    enabled: bool,
    deployment_profile_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Build Cedar entities for an API key principal.

    Returns a list containing the ApiKey, Organization, and optionally
    DeploymentProfile entities.
    """
    parents: list[dict[str, str]] = [
        {"type": "MIP::Organization", "id": org_id},
    ]
    if deployment_profile_id:
        parents.append({"type": "MIP::DeploymentProfile", "id": deployment_profile_id})

    entities: list[dict[str, Any]] = [
        {
            "uid": {"type": "MIP::ApiKey", "id": api_key_id},
            "attrs": {
                "scope_type": scope_type.upper(),
                "enabled": enabled,
            },
            "parents": parents,
        },
        {
            "uid": {"type": "MIP::Organization", "id": org_id},
            "attrs": {},
            "parents": [],
        },
    ]

    if deployment_profile_id:
        entities.append(
            {
                "uid": {"type": "MIP::DeploymentProfile", "id": deployment_profile_id},
                "attrs": {},
                "parents": [{"type": "MIP::Organization", "id": org_id}],
            }
        )

    return entities


def build_request_context(
    ip_address: str,
    mfa_authenticated: bool = False,
    session_id: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> dict[str, Any]:
    """Build a Cedar RequestContext for API authorization.

    Formats ip_address as a Cedar ipaddr extension type.
    """
    ctx: dict[str, Any] = {
        "ip_address": {"__extn": {"fn": "ip", "arg": ip_address or "0.0.0.0"}},
        "timestamp": int(time.time()),
        "mfa_authenticated": mfa_authenticated,
    }
    if session_id is not None:
        ctx["session_id"] = session_id
    if user_agent is not None:
        ctx["user_agent"] = user_agent
    return ctx
