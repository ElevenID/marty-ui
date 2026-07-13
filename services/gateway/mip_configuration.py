"""Canonical MIP 0.3.1 discovery document construction."""

from __future__ import annotations

from typing import Any, Iterable


_API_SURFACE_FIELDS = {
    "rel",
    "path_template",
    "org_scoped_path",
    "method",
    "auth_required",
    "discoverable",
    "response_schema_ref",
    "standard_ref",
}


def _active_profile_projection(profile: dict[str, Any]) -> dict[str, Any] | None:
    compliance_code = str(profile.get("compliance_code") or "").strip()
    if not compliance_code:
        return None
    api_surface = []
    for endpoint in profile.get("api_surface") or []:
        if not isinstance(endpoint, dict) or endpoint.get("discoverable") is False:
            continue
        projected = {key: endpoint[key] for key in _API_SURFACE_FIELDS if key in endpoint}
        projected.setdefault("discoverable", True)
        api_surface.append(projected)
    projected_profile: dict[str, Any] = {
        "compliance_code": compliance_code,
        "api_surface": api_surface,
    }
    for key in ("credential_format", "issuance_protocol"):
        value = str(profile.get(key) or "").strip()
        if value:
            projected_profile[key] = value
    return projected_profile


def mip_configuration_document(
    issuer_url: str,
    active_profiles: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    issuer_url = issuer_url.rstrip("/")
    projected_profiles = [
        projected
        for profile in active_profiles
        if isinstance(profile, dict)
        if (projected := _active_profile_projection(profile)) is not None
    ]
    projected_profiles.sort(key=lambda profile: profile["compliance_code"])
    compliance_codes = sorted({profile["compliance_code"] for profile in projected_profiles})
    return {
        "mip_version": "0.3.1",
        "issuer": issuer_url,
        "mip_configuration_endpoint": f"{issuer_url}/.well-known/mip-configuration",
        "supported_versions": ["0.3.1"],
        "implementation_classes": ["ISSUER", "VERIFIER", "REGISTRY"],
        "issuance_endpoint": f"{issuer_url}/v1/issuance",
        "openid_credential_issuer": f"{issuer_url}/.well-known/openid-credential-issuer",
        "presentation_endpoint": f"{issuer_url}/v1/flows/verify",
        "token_endpoint": f"{issuer_url}/v1/issuance/token",
        "authorization_endpoint": f"{issuer_url}/v1/issuance/authorize",
        "supported_credential_formats": ["MDOC", "SD_JWT_VC", "VC_JWT", "JSON_LD"],
        "supported_compliance_profiles": compliance_codes,
        "active_compliance_profiles": projected_profiles,
        "supported_flow_types": [
            "oid4vci_pre_authorized",
            "oid4vci_authorization_code",
            "application_approval_issuance",
            "credential_renewal",
            "credential_revocation",
            "oid4vp_presentation",
            "mdl_presentation",
        ],
        "supported_signing_algorithms": ["ES256", "ES384", "EdDSA"],
        "proximity_supported": False,
        "scim_endpoint": f"{issuer_url}/v1/organizations/{{org_id}}/scim/v2",
        "revocation_endpoint": f"{issuer_url}/v1/issuance/status-list",
        "jwks_uri": f"{issuer_url}/.well-known/jwks.json",
        "service_documentation": f"{issuer_url}/docs",
    }
