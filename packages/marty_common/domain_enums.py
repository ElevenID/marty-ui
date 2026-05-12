"""
Shared domain enums used across marty-ui microservices.

These canonical definitions prevent divergence between services.
Import from here instead of redefining per-service.
"""

from __future__ import annotations

from enum import Enum


class CredentialFormat(str, Enum):
    """Supported credential formats.

    Maps to marty-protocol enum: credential-formats.json
    """

    MDOC = "MDOC"
    SD_JWT_VC = "SD_JWT_VC"
    VC_JWT = "VC_JWT"
    JSON_LD = "JSON_LD"
    ZK_MDOC = "ZK_MDOC"
    VDS_NC = "VDS_NC"


# Wire-format / alternate-name aliases → canonical enum member.
# Keys are **lowercase** for case-insensitive lookup.
CREDENTIAL_FORMAT_WIRE_MAP: dict[str, CredentialFormat] = {
    # MDOC variants
    "mso_mdoc": CredentialFormat.MDOC,
    "mdoc": CredentialFormat.MDOC,
    # SD-JWT variants
    "dc+sd-jwt": CredentialFormat.SD_JWT_VC,
    "vc+sd-jwt": CredentialFormat.SD_JWT_VC,
    "spruce-vc+sd-jwt": CredentialFormat.SD_JWT_VC,
    "sd_jwt_vc": CredentialFormat.SD_JWT_VC,
    "sd-jwt": CredentialFormat.SD_JWT_VC,
    "sd-jwt-vc": CredentialFormat.SD_JWT_VC,
    # VC-JWT variants
    "jwt_vc_json": CredentialFormat.VC_JWT,
    "jwt_vc": CredentialFormat.VC_JWT,
    "jwt_vc_json-ld": CredentialFormat.VC_JWT,
    # JSON-LD variants
    "ldp_vc": CredentialFormat.JSON_LD,
    "jsonld": CredentialFormat.JSON_LD,
    "json_ld": CredentialFormat.JSON_LD,
    # ZK-MDOC variants
    "zk_mdoc": CredentialFormat.ZK_MDOC,
    "zk-mdoc": CredentialFormat.ZK_MDOC,
    "zkp_mdoc": CredentialFormat.ZK_MDOC,
    # VDS-NC variants (ICAO Visible Digital Seal – Non-Constrained)
    "vds_nc": CredentialFormat.VDS_NC,
    "vds-nc": CredentialFormat.VDS_NC,
    "vds_nc_barcode": CredentialFormat.VDS_NC,
}


def parse_credential_format(value: str | CredentialFormat) -> CredentialFormat:
    """Normalize a credential format value to the canonical enum.

    Accepts canonical names, upper/lower variants, and OID4VCI wire aliases.
    """
    if isinstance(value, CredentialFormat):
        return value
    stripped = str(value).strip()
    # Direct enum match (e.g. "SD_JWT_VC")
    try:
        return CredentialFormat(stripped.upper())
    except ValueError:
        pass
    # Alias lookup (case-insensitive)
    wire_hit = CREDENTIAL_FORMAT_WIRE_MAP.get(stripped.lower())
    if wire_hit:
        return wire_hit
    raise ValueError(f"Unknown credential format: {value!r}")
