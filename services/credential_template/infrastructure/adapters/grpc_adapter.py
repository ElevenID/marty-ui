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


def _template_to_pb(template: Any, to_response_fn: Any) -> ct_pb2.TemplateResponse:
    """Map domain CredentialTemplate → protobuf TemplateResponse."""
    resp = to_response_fn(template)
    claims = [
        ct_pb2.ClaimDefinition(
            name=c["name"],
            display_name=c.get("display_name", ""),
            description=c.get("description", ""),
            claim_type=c.get("claim_type", ""),
            required=c.get("required", False),
            selectively_disclosable=c.get("selectively_disclosable", False),
            derivable=c.get("derivable", False),
        )
        for c in resp.claims
    ]
    display_style = ct_pb2.DisplayStyle(
        background_color=resp.display_style.get("background_color", ""),
        text_color=resp.display_style.get("text_color", ""),
        logo_url=resp.display_style.get("logo_url", ""),
        background_image_url=resp.display_style.get("background_image_url", ""),
        icon=resp.display_style.get("icon", ""),
    )
    validity_rules = ct_pb2.ValidityRules(
        default_validity_days=resp.validity_rules.get("default_validity_days", 0),
        max_validity_days=resp.validity_rules.get("max_validity_days", 0),
        renewable=resp.validity_rules.get("renewable", False),
        renewal_window_days=resp.validity_rules.get("renewal_window_days", 0),
        require_revalidation=resp.validity_rules.get("require_revalidation", False),
        revalidation_interval_days=resp.validity_rules.get("revalidation_interval_days", 0),
    )
    return ct_pb2.TemplateResponse(
        id=resp.id,
        organization_id=resp.organization_id,
        name=resp.name,
        description=resp.description or "",
        credential_type=resp.credential_type or "",
        vct=resp.vct or "",
        doctype=resp.doctype or "",
        claims=claims,
        privacy_posture=resp.privacy_posture,
        selective_disclosure_fields=list(resp.selective_disclosure_fields or []),
        zk_predicate_claims=list(resp.zk_predicate_claims or []),
        supported_formats=list(resp.supported_formats or []),
        issuance_protocol=resp.issuance_protocol or "",
        credential_payload_format=resp.credential_payload_format or "",
        display_style=display_style,
        validity_rules=validity_rules,
        status=resp.status,
        version=resp.version,
        created_at=resp.created_at,
        updated_at=resp.updated_at,
        wallet_configs_json=json.dumps(resp.wallet_configs) if resp.wallet_configs else "[]",
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
            credential_payload_format=request.credential_payload_format or "w3c_vcdm_v2_sd_jwt",
            selective_disclosure_fields=list(request.selective_disclosure_fields),
            zk_predicate_claims=list(request.zk_predicate_claims),
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
            from credential_template.main import normalize_credential_format

            try:
                template.supported_formats = [
                    normalize_credential_format(f) for f in request.supported_formats
                ]
            except ValueError as exc:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details(str(exc))
                return ct_pb2.TemplateResponse()

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
