"""
Credential Template Service gRPC Adapter (Inbound)

Implements the CredentialTemplateService gRPC servicer, delegating to the
same repository that backs the REST endpoints.
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
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


def _has_kms_backed_issuer(template: Any) -> bool:
    issuer_profile_id = str(getattr(template, "issuer_profile_id", "") or "").strip()
    key_access_mode = str(getattr(template, "key_access_mode", "") or "").strip().upper()
    return bool(issuer_profile_id and key_access_mode == "REMOTE_SIGNING")


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
        doctype=getattr(resp, "doctype", "") or "",
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
        key_access_mode=getattr(resp, "key_access_mode", None) or "",
        issuer_key_id=getattr(resp, "issuer_key_id", None) or "",
        issuer_algorithm=getattr(resp, "issuer_algorithm", None) or "",
        remote_signing_config_json=json.dumps(getattr(resp, "remote_signing_config", None) or {}),
        issuer_profile_id=getattr(resp, "issuer_profile_id", None) or "",
        revocation_profile_id=getattr(resp, "revocation_profile_id", None) or "",
    )


async def _resolve_grpc_issuer_fields(
    *,
    context: Any,
    organization_id: str,
    issuer_profile_id: str | None,
    credential_payload_format: str | None,
    issuer_algorithm: str | None,
) -> dict[str, Any] | None:
    from credential_template.main import (  # noqa: PLC0415
        _canonical_issuer_fields,
        _require_active_issuer_profile,
        payload_format_to_wire,
    )

    try:
        issuer_context = await _require_active_issuer_profile(
            SimpleNamespace(state=SimpleNamespace()),
            organization_id=organization_id,
            issuer_profile_id=issuer_profile_id,
            credential_format=payload_format_to_wire(credential_payload_format),
            algorithm=issuer_algorithm or None,
        )
    except Exception as exc:  # noqa: BLE001
        status_code = getattr(exc, "status_code", 500)
        grpc_code = (
            grpc.StatusCode.INVALID_ARGUMENT
            if status_code in {400, 422}
            else grpc.StatusCode.UNAVAILABLE
        )
        context.set_code(grpc_code)
        context.set_details(str(getattr(exc, "detail", exc)))
        return None

    return _canonical_issuer_fields(
        issuer_context,
        requested_algorithm=issuer_algorithm or None,
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
            if not _has_kms_backed_issuer(t):
                logger.warning(
                    "Skipping active credential template %s in credential configurations because it lacks a KMS-backed issuer profile",
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
    # Commands
    # ------------------------------------------------------------------

    async def CreateTemplate(self, request, context):
        from credential_template.main import (
            ClaimDefinition,
            ClaimType,
            CredentialTemplate,
            DisplayStyle,
            PrivacyPosture,
            ValidityRules,
            normalize_credential_payload_format,
            normalize_credential_format,
        )

        try:
            supported_formats = [
                normalize_credential_format(f)
                for f in request.supported_formats
            ]
        except ValueError as exc:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(str(exc))
            return ct_pb2.TemplateResponse()

        try:
            credential_payload_format = normalize_credential_payload_format(
                request.credential_payload_format or None,
                supported_formats,
            )
        except ValueError as exc:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(str(exc))
            return ct_pb2.TemplateResponse()

        issuer_fields = await _resolve_grpc_issuer_fields(
            context=context,
            organization_id=request.organization_id,
            issuer_profile_id=getattr(request, "issuer_profile_id", "") or None,
            credential_payload_format=credential_payload_format,
            issuer_algorithm=getattr(request, "issuer_algorithm", "") or None,
        )
        if issuer_fields is None:
            return ct_pb2.TemplateResponse()

        template = CredentialTemplate(
            organization_id=request.organization_id,
            name=request.name,
            description=request.description or None,
            credential_type=request.credential_type,
            vct=request.vct or f"https://credentials.example.com/{request.credential_type}",
            doctype=request.doctype or "",
            privacy_posture=PrivacyPosture(request.privacy_posture) if request.privacy_posture else PrivacyPosture.SELECTIVE_DISCLOSURE,
            supported_formats=supported_formats,
            issuance_protocol=request.issuance_protocol or "oid4vci",
            credential_payload_format=credential_payload_format,
            selective_disclosure_fields=list(request.selective_disclosure_fields),
            zk_predicate_claims=list(request.zk_predicate_claims),
            issuer_profile_id=issuer_fields["issuer_profile_id"],
            issuer_key_id=issuer_fields["issuer_key_id"],
            issuer_algorithm=issuer_fields["issuer_algorithm"],
            key_access_mode=issuer_fields["key_access_mode"],
            remote_signing_config=issuer_fields["remote_signing_config"],
            issuer_did=issuer_fields["issuer_did"],
        )

        for c in request.claims:
            template.claims.append(ClaimDefinition(
                name=c.name,
                display_name=c.display_name,
                description=c.description or None,
                claim_type=ClaimType(c.claim_type) if c.claim_type else ClaimType.STRING,
                required=c.required,
                selectively_disclosable=c.selectively_disclosable,
                derivable=c.derivable,
                pattern=c.pattern or None,
                enum_values=list(c.enum_values) if c.enum_values else None,
                mdoc_namespace=c.mdoc_namespace or None,
                mdoc_element_identifier=c.mdoc_element_identifier or None,
            ))

        if request.HasField("display_style"):
            ds = request.display_style
            template.display_style = DisplayStyle(
                background_color=ds.background_color,
                text_color=ds.text_color,
                logo_url=ds.logo_url,
                background_image_url=ds.background_image_url,
                icon=ds.icon,
            )

        if request.HasField("validity_rules"):
            vr = request.validity_rules
            template.validity_rules = ValidityRules(
                default_validity_days=vr.default_validity_days,
                max_validity_days=vr.max_validity_days,
                renewable=vr.renewable,
                renewal_window_days=vr.renewal_window_days,
                require_revalidation=vr.require_revalidation,
                revalidation_interval_days=vr.revalidation_interval_days,
            )

        await self._repo.save(template)
        logger.info("gRPC CreateTemplate: %s", template.id)
        return _template_to_pb(template, self._to_response_fn)

    async def UpdateTemplate(self, request, context):
        from credential_template.main import TemplateStatus

        template = await self._repo.get(request.template_id)
        if not template:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Template {request.template_id} not found")
            return ct_pb2.TemplateResponse()

        if template.status != TemplateStatus.DRAFT:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details(
                "Only draft templates can be modified. Create a new version instead."
            )
            return ct_pb2.TemplateResponse()

        if request.name:
            template.name = request.name
        if request.description:
            template.description = request.description
        if request.supported_formats:
            from credential_template.main import (
                normalize_credential_format,
                normalize_credential_payload_format,
            )

            try:
                template.supported_formats = [
                    normalize_credential_format(f) for f in request.supported_formats
                ]
            except ValueError as exc:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details(str(exc))
                return ct_pb2.TemplateResponse()
            if not request.credential_payload_format:
                template.credential_payload_format = normalize_credential_payload_format(
                    None,
                    template.supported_formats,
                )

        if request.credential_payload_format:
            from credential_template.main import normalize_credential_payload_format

            try:
                template.credential_payload_format = normalize_credential_payload_format(
                    request.credential_payload_format,
                    template.supported_formats,
                )
            except ValueError as exc:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details(str(exc))
                return ct_pb2.TemplateResponse()

        if getattr(request, "issuer_profile_id", ""):
            template.issuer_profile_id = request.issuer_profile_id
        if getattr(request, "issuer_algorithm", ""):
            template.issuer_algorithm = request.issuer_algorithm

        if request.claims:
            from credential_template.main import ClaimDefinition, ClaimType

            template.claims = [
                ClaimDefinition(
                    name=c.name,
                    display_name=c.display_name,
                    description=c.description or None,
                    claim_type=ClaimType(c.claim_type) if c.claim_type else ClaimType.STRING,
                    required=c.required,
                    selectively_disclosable=c.selectively_disclosable,
                    derivable=c.derivable,
                )
                for c in request.claims
            ]

        if request.HasField("display_style"):
            from credential_template.main import DisplayStyle

            ds = request.display_style
            template.display_style = DisplayStyle(
                background_color=ds.background_color,
                text_color=ds.text_color,
                logo_url=ds.logo_url,
                background_image_url=ds.background_image_url,
                icon=ds.icon,
            )

        if request.HasField("validity_rules"):
            from credential_template.main import ValidityRules

            vr = request.validity_rules
            template.validity_rules = ValidityRules(
                default_validity_days=vr.default_validity_days,
                max_validity_days=vr.max_validity_days,
                renewable=vr.renewable,
                renewal_window_days=vr.renewal_window_days,
                require_revalidation=vr.require_revalidation,
                revalidation_interval_days=vr.revalidation_interval_days,
            )

        issuer_fields = await _resolve_grpc_issuer_fields(
            context=context,
            organization_id=template.organization_id,
            issuer_profile_id=getattr(template, "issuer_profile_id", None),
            credential_payload_format=template.credential_payload_format,
            issuer_algorithm=getattr(template, "issuer_algorithm", None),
        )
        if issuer_fields is None:
            return ct_pb2.TemplateResponse()
        template.issuer_profile_id = issuer_fields["issuer_profile_id"]
        template.issuer_key_id = issuer_fields["issuer_key_id"]
        template.issuer_algorithm = issuer_fields["issuer_algorithm"]
        template.key_access_mode = issuer_fields["key_access_mode"]
        template.remote_signing_config = issuer_fields["remote_signing_config"]
        template.issuer_did = issuer_fields["issuer_did"]

        from datetime import datetime, timezone

        template.updated_at = datetime.now(timezone.utc)
        await self._repo.save(template)
        logger.info("gRPC UpdateTemplate: %s", template.id)
        return _template_to_pb(template, self._to_response_fn)

    async def ActivateTemplate(self, request, context):
        template = await self._repo.get(request.template_id)
        if not template:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Template {request.template_id} not found")
            return ct_pb2.TemplateResponse()

        if not template.claims:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details("Template must have at least one claim")
            return ct_pb2.TemplateResponse()

        issuer_fields = await _resolve_grpc_issuer_fields(
            context=context,
            organization_id=template.organization_id,
            issuer_profile_id=getattr(template, "issuer_profile_id", None),
            credential_payload_format=template.credential_payload_format,
            issuer_algorithm=getattr(template, "issuer_algorithm", None),
        )
        if issuer_fields is None:
            return ct_pb2.TemplateResponse()
        template.issuer_profile_id = issuer_fields["issuer_profile_id"]
        template.issuer_key_id = issuer_fields["issuer_key_id"]
        template.issuer_algorithm = issuer_fields["issuer_algorithm"]
        template.key_access_mode = issuer_fields["key_access_mode"]
        template.remote_signing_config = issuer_fields["remote_signing_config"]
        template.issuer_did = issuer_fields["issuer_did"]

        template.activate()
        await self._repo.save(template)
        logger.info("gRPC ActivateTemplate: %s", template.id)
        return _template_to_pb(template, self._to_response_fn)

    async def DeprecateTemplate(self, request, context):
        template = await self._repo.get(request.template_id)
        if not template:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Template {request.template_id} not found")
            return ct_pb2.TemplateResponse()

        template.deprecate()
        await self._repo.save(template)
        logger.info("gRPC DeprecateTemplate: %s", template.id)
        return _template_to_pb(template, self._to_response_fn)

    async def NewVersion(self, request, context):
        template = await self._repo.get(request.template_id)
        if not template:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Template {request.template_id} not found")
            return ct_pb2.TemplateResponse()

        new_template = template.new_version()
        await self._repo.save(new_template)
        logger.info("gRPC NewVersion: %s → %s", template.id, new_template.id)
        return _template_to_pb(new_template, self._to_response_fn)

    async def DeleteTemplate(self, request, context):
        from credential_template.main import TemplateStatus

        template = await self._repo.get(request.template_id)
        if template and template.status != TemplateStatus.DRAFT:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details(
                "Only draft templates can be deleted. Deprecate active templates instead."
            )
            return ct_pb2.DeleteTemplateResponse(success=False)

        await self._repo.delete(request.template_id)
        logger.info("gRPC DeleteTemplate: %s", request.template_id)
        return ct_pb2.DeleteTemplateResponse(success=True)

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
