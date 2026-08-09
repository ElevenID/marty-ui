"""
Credential Template Service gRPC Adapter (Inbound)

Implements the CredentialTemplateService gRPC servicer, delegating to the
same repository that backs the REST endpoints.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import grpc

from marty_proto.v1 import (
    credential_template_service_pb2 as ct_pb2,
    credential_template_service_pb2_grpc,
)

logger = logging.getLogger(__name__)


_PAYLOAD_FORMAT_WIRE_NAMES = {
    "SD_JWT_VC": "sd_jwt_vc",
    "MDOC": "mdoc",
    "VC_JWT": "jwt_vc",
    "JSON_LD": "ldp_vc",
    "ZK_MDOC": "zk_mdoc",
}


def _payload_format_to_wire(value: str | None) -> str:
    if not value:
        return ""
    normalized = str(value).strip()
    return _PAYLOAD_FORMAT_WIRE_NAMES.get(normalized.upper(), normalized)


def _has_managed_issuer_did(template: Any) -> bool:
    return str(getattr(template, "issuer_did", "") or "").strip().startswith("did:")


def _template_to_pb(template: Any, to_response_fn: Any) -> ct_pb2.TemplateResponse:
    """Map domain CredentialTemplate → protobuf TemplateResponse."""
    resp = to_response_fn(template)

    claim_type_map = {
        "STRING": "string",
        "INTEGER": "integer",
        "BOOLEAN": "boolean",
        "DATE": "date",
        "OBJECT": "object",
        "ARRAY": "array",
    }
    claims = [
        ct_pb2.ClaimDefinition(
            name=c["name"],
            display_name=c.get("display_name", c.get("display", {}).get("label", "")),
            description=c.get("description", ""),
            claim_type=c.get("claim_type", claim_type_map.get(c.get("type", ""), "")),
            required=c.get("required", False),
            selectively_disclosable=c.get("selectively_disclosable", False),
            derivable=c.get("derivable", "derived_from" in c),
            mdoc_namespace=c.get("mdoc_namespace", c.get("namespace", "")),
            mdoc_element_identifier=c.get(
                "mdoc_element_identifier",
                c.get("name", "") if c.get("mdoc_namespace") or c.get("namespace") else "",
            ),
            derived_from=c.get("derived_from", ""),
            display_icon=c.get("display", {}).get("icon", ""),
        )
        for c in resp.claims
    ]
    display_style_payload = getattr(resp, "display_style", {}) or {}
    display_style = ct_pb2.DisplayStyle(
        background_color=display_style_payload.get("background_color", ""),
        text_color=display_style_payload.get("text_color", ""),
        logo_url=display_style_payload.get("logo_url", ""),
        background_image_url=display_style_payload.get("background_image_url", ""),
        icon=display_style_payload.get("icon", ""),
    )
    validity_payload = getattr(resp, "validity_rules", {}) or {}
    ttl_seconds = validity_payload.get("ttl_seconds")
    reissue_within_seconds = validity_payload.get("reissue_within_seconds")
    validity_rules = ct_pb2.ValidityRules(
        default_validity_days=(ttl_seconds // 86400) if isinstance(ttl_seconds, int) else validity_payload.get("default_validity_days", 0),
        max_validity_days=validity_payload.get("max_validity_days", 0),
        renewable=validity_payload.get("renewable", False),
        renewal_window_days=(reissue_within_seconds // 86400) if isinstance(reissue_within_seconds, int) else validity_payload.get("renewal_window_days", 0),
        require_revalidation=validity_payload.get("require_revalidation", False),
        revalidation_interval_days=validity_payload.get("revalidation_interval_days", 0),
    )
    supported_formats = list(getattr(template, "supported_formats", []) or [])
    if not supported_formats:
        supported_formats = list(getattr(resp, "supported_formats", []) or [])
    if not supported_formats and getattr(resp, "credential_payload_format", None):
        supported_formats = [_payload_format_to_wire(resp.credential_payload_format)]

    privacy_posture = getattr(resp, "privacy_posture", None)
    if isinstance(privacy_posture, dict):
        if privacy_posture.get("prefer_predicates"):
            privacy_posture_value = "zero_knowledge"
        elif privacy_posture.get("default_disclose_all"):
            privacy_posture_value = "standard"
        else:
            privacy_posture_value = "selective_disclosure"
    else:
        privacy_posture_value = privacy_posture or ""

    return ct_pb2.TemplateResponse(
        id=resp.id,
        organization_id=resp.organization_id,
        name=resp.name,
        description=resp.description or "",
        credential_type=resp.credential_type or "",
        vct=resp.vct or "",
        doctype=getattr(template, "doctype", "") or getattr(resp, "doctype", "") or "",
        claims=claims,
        privacy_posture=privacy_posture_value,
        selective_disclosure_fields=list(getattr(resp, "selective_disclosure_fields", []) or []),
        zk_predicate_claims=list(getattr(resp, "zk_predicate_claims", []) or []),
        supported_formats=supported_formats,
        issuance_protocol=getattr(resp, "issuance_protocol", "") or "",
        credential_payload_format=_payload_format_to_wire(resp.credential_payload_format),
        display_style=display_style,
        validity_rules=validity_rules,
        status=resp.status,
        version=getattr(resp, "version", 0),
        created_at=resp.created_at,
        updated_at=resp.updated_at,
        wallet_configs_json=getattr(resp, "wallet_configs_json", None) or "[]",
        # ``to_response_fn`` deliberately returns the public-sanitized shape,
        # which omits signing-algorithm details.  This protobuf is the private
        # service-to-service contract used by issuance, so preserve the
        # algorithm that was resolved from the organization-owned issuer DID
        # and stored on the domain template.
        issuer_algorithm=(
            getattr(template, "issuer_algorithm", None)
            or getattr(resp, "issuer_algorithm", None)
            or ""
        ),
        revocation_profile_id=getattr(resp, "revocation_profile_id", None) or "",
        issuer_did=getattr(resp, "issuer_did", None) or "",
    )


class CredentialTemplateServiceGrpc(
    credential_template_service_pb2_grpc.CredentialTemplateServiceServicer,
):
    """gRPC inbound adapter for the credential-template service."""

    def __init__(self, repo: Any, to_response_fn: Any, wallet_repo: Any = None) -> None:
        self._repo = repo
        self._to_response_fn = to_response_fn
        self._wallet_repo = wallet_repo

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    async def GetTemplate(self, request, context):
        template = await self._repo.get(request.template_id)
        if not template:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Template {request.template_id} not found")
            return ct_pb2.TemplateResponse()
        return _template_to_pb(template, self._to_response_fn)

    async def ListTemplates(self, request, context):
        from credential_template.main import TemplateStatus

        status_filter = TemplateStatus(request.status) if request.status else None
        templates = await self._repo.list(
            request.organization_id or None,
            status_filter,
        )
        pb_templates = [_template_to_pb(t, self._to_response_fn) for t in templates]
        return ct_pb2.ListTemplatesResponse(
            templates=pb_templates,
        )

    async def GetCredentialConfigurations(self, request, context):
        from credential_template.main import TemplateStatus

        try:
            templates = await self._repo.list_all(status=TemplateStatus.ACTIVE)
        except Exception as exc:
            logger.warning("Failed to load templates for configurations: %s", exc)
            templates = []

        configs: dict[str, Any] = {}
        for t in templates:
            if not _has_managed_issuer_did(t):
                logger.warning(
                    "Skipping active credential template %s in credential configurations because it lacks a managed issuer DID",
                    getattr(t, "id", None) or getattr(t, "name", None) or "unknown",
                )
                continue
            cred_type = (t.credential_type or "").strip()
            if not cred_type:
                continue
            configs[cred_type] = {
                "format": "jwt_vc_json",
                "credential_type": cred_type,
                "name": t.name or cred_type,
            }

        return ct_pb2.GetCredentialConfigurationsResponse(
            configurations_json=json.dumps(configs),
        )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def HealthCheck(self, request, context):
        return ct_pb2.HealthCheckResponse(status="serving")

    # ------------------------------------------------------------------
    # Wallet Registry
    # ------------------------------------------------------------------

    def _wallet_to_pb(self, entry: Any) -> ct_pb2.WalletRegistryEntry:
        """Map domain WalletRegistryEntry → protobuf WalletRegistryEntry."""
        return ct_pb2.WalletRegistryEntry(
            id=entry.id,
            name=entry.name,
            logo_url=entry.logo_url or "",
            deep_link_template=entry.deep_link_template,
            supported_formats=list(entry.supported_formats),
            supported_protocols=list(entry.supported_protocols),
            platforms=list(entry.platforms),
            supports_qr=entry.supports_qr,
            supports_deeplink=entry.supports_deeplink,
            docs_url=entry.docs_url or "",
            is_active=entry.is_active,
            created_at=entry.created_at.isoformat() if hasattr(entry.created_at, 'isoformat') else str(entry.created_at),
            updated_at=entry.updated_at.isoformat() if hasattr(entry.updated_at, 'isoformat') else str(entry.updated_at),
        )

    async def ListWallets(self, request, context):
        if not self._wallet_repo:
            context.set_code(grpc.StatusCode.UNIMPLEMENTED)
            context.set_details("Wallet registry not configured")
            return ct_pb2.ListWalletsResponse()
        wallets = await self._wallet_repo.list(active_only=request.active_only)
        return ct_pb2.ListWalletsResponse(
            wallets=[self._wallet_to_pb(w) for w in wallets],
        )

    async def GetWallet(self, request, context):
        if not self._wallet_repo:
            context.set_code(grpc.StatusCode.UNIMPLEMENTED)
            context.set_details("Wallet registry not configured")
            return ct_pb2.WalletRegistryEntry()
        wallet = await self._wallet_repo.get(request.wallet_id)
        if not wallet:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Wallet {request.wallet_id} not found")
            return ct_pb2.WalletRegistryEntry()
        return self._wallet_to_pb(wallet)
