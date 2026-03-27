"""
PostgreSQL adapter for Credential Template Repository.

Implements the repository pattern for credential template persistence.
"""

import json
from typing import Any, TYPE_CHECKING
from datetime import datetime, timezone

from sqlalchemy import select, delete, and_
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from credential_template.infrastructure.models import credential_templates_table, wallet_registry_table

if TYPE_CHECKING:
    from credential_template.main import (
        CredentialTemplate, ClaimDefinition, DisplayStyle, ValidityRules,
        IssuerRequirements, DerivedAttribute, TemplateStatus, CredentialFormat,
        PrivacyPosture, ClaimType, WalletConfig,
    )


class PostgresCredentialTemplateRepository:
    """PostgreSQL implementation of the credential template repository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory
    
    async def save(self, template: "CredentialTemplate") -> None:
        """Save or update a credential template."""
        from credential_template.main import ClaimDefinition, DisplayStyle, ValidityRules, IssuerRequirements, DerivedAttribute
        
        async with self._session_factory() as session:
            # Convert domain objects to JSON-serializable dicts
            claims_json = [
                {
                    "id": claim.id,
                    "name": claim.name,
                    "display_name": claim.display_name,
                    "description": claim.description,
                    "claim_type": claim.claim_type.value,
                    "required": claim.required,
                    "selectively_disclosable": claim.selectively_disclosable,
                    "derivable": claim.derivable,
                    "pattern": claim.pattern,
                    "enum_values": claim.enum_values,
                    "min_value": claim.min_value,
                    "max_value": claim.max_value,
                    "mdoc_namespace": claim.mdoc_namespace,
                    "mdoc_element_identifier": claim.mdoc_element_identifier,
                }
                for claim in template.claims
            ]
            
            display_style_json = {
                "background_color": template.display_style.background_color,
                "text_color": template.display_style.text_color,
                "logo_url": template.display_style.logo_url,
                "background_image_url": template.display_style.background_image_url,
                "icon": template.display_style.icon,
            }
            
            validity_rules_json = {
                "default_validity_days": template.validity_rules.default_validity_days,
                "max_validity_days": template.validity_rules.max_validity_days,
                "renewable": template.validity_rules.renewable,
                "renewal_window_days": template.validity_rules.renewal_window_days,
                "require_revalidation": template.validity_rules.require_revalidation,
                "revalidation_interval_days": template.validity_rules.revalidation_interval_days,
            }
            
            issuer_requirements_json = {
                "allowed_issuer_dids": template.issuer_requirements.allowed_issuer_dids,
                "trust_tier_required": template.issuer_requirements.trust_tier_required,
                "audit_level_required": template.issuer_requirements.audit_level_required,
            }
            
            derived_attributes_json = [
                {
                    "id": attr.id,
                    "name": attr.name,
                    "description": attr.description,
                    "source_claim": attr.source_claim,
                    "derivation_type": attr.derivation_type,
                    "parameters": attr.parameters,
                }
                for attr in template.derived_attributes
            ]
            
            # Check if template exists
            stmt = select(credential_templates_table).where(
                credential_templates_table.c.id == template.id
            )
            result = await session.execute(stmt)
            existing = result.first()
            
            template_data = {
                "id": template.id,
                "organization_id": template.organization_id,
                "name": template.name,
                "description": template.description,
                "status": template.status.value,
                "credential_type": template.credential_type,
                "vct": template.vct,
                "doctype": template.doctype,
                "claims": claims_json,
                "privacy_posture": template.privacy_posture.value,
                "selective_disclosure_fields": template.selective_disclosure_fields,
                "zk_predicate_claims": template.zk_predicate_claims,
                "derived_attributes": derived_attributes_json,
                "display_style": display_style_json,
                "validity_rules": validity_rules_json,
                "issuer_requirements": issuer_requirements_json,
                "supported_formats": [fmt.value for fmt in template.supported_formats],
                "credential_payload_format": template.credential_payload_format,
                "wallet_configs": [{k: v for k, v in {"wallet_id": wc.wallet_id, "deep_link_scheme": wc.deep_link_scheme, "format_variant": wc.format_variant}.items() if v is not None} for wc in template.wallet_configs],
                "version": template.version,
                "updated_at": template.updated_at,
            }
            
            if existing:
                # Update existing
                stmt = (
                    credential_templates_table.update()
                    .where(credential_templates_table.c.id == template.id)
                    .values(**template_data)
                )
                await session.execute(stmt)
            else:
                # Insert new
                template_data["created_at"] = template.created_at
                stmt = credential_templates_table.insert().values(**template_data)
                await session.execute(stmt)
            
            await session.commit()
    
    async def get(self, template_id: str) -> "CredentialTemplate | None":
        """Get a credential template by ID."""
        from credential_template.main import (
            CredentialTemplate, TemplateStatus, PrivacyPosture, CredentialFormat,
            ClaimDefinition, ClaimType, DisplayStyle, ValidityRules, 
            IssuerRequirements, DerivedAttribute, WalletConfig
        )
        
        async with self._session_factory() as session:
            stmt = select(credential_templates_table).where(
                credential_templates_table.c.id == template_id
            )
            result = await session.execute(stmt)
            row = result.first()
            
            if not row:
                return None
        # Convert JSON data back to domain objects
        claims = [
            ClaimDefinition(
                id=c["id"],
                name=c["name"],
                display_name=c["display_name"],
                description=c.get("description"),
                claim_type=ClaimType(c["claim_type"]),
                required=c["required"],
                selectively_disclosable=c.get("selectively_disclosable", True),
                derivable=c.get("derivable", False),
                pattern=c.get("pattern"),
                enum_values=c.get("enum_values"),
                min_value=c.get("min_value"),
                max_value=c.get("max_value"),
                mdoc_namespace=c.get("mdoc_namespace"),
                mdoc_element_identifier=c.get("mdoc_element_identifier"),
            )
            for c in row.claims
        ]
        
        display_style_data = row.display_style
        display_style = DisplayStyle(
            background_color=display_style_data.get("background_color", "#1a1a2e"),
            text_color=display_style_data.get("text_color", "#ffffff"),
            logo_url=display_style_data.get("logo_url"),
            background_image_url=display_style_data.get("background_image_url"),
            icon=display_style_data.get("icon"),
        )
        
        validity_rules_data = row.validity_rules
        validity_rules = ValidityRules(
            default_validity_days=validity_rules_data.get("default_validity_days", 365),
            max_validity_days=validity_rules_data.get("max_validity_days", 1095),
            renewable=validity_rules_data.get("renewable", True),
            renewal_window_days=validity_rules_data.get("renewal_window_days", 30),
            require_revalidation=validity_rules_data.get("require_revalidation", False),
            revalidation_interval_days=validity_rules_data.get("revalidation_interval_days"),
        )
        
        issuer_requirements_data = row.issuer_requirements
        issuer_requirements = IssuerRequirements(
            allowed_issuer_dids=issuer_requirements_data.get("allowed_issuer_dids", []),
            trust_tier_required=issuer_requirements_data.get("trust_tier_required"),
            audit_level_required=issuer_requirements_data.get("audit_level_required"),
        )
        
        derived_attributes = [
            DerivedAttribute(
                id=attr["id"],
                name=attr["name"],
                description=attr.get("description"),
                source_claim=attr["source_claim"],
                derivation_type=attr["derivation_type"],
                parameters=attr.get("parameters", {}),
            )
            for attr in row.derived_attributes
        ]
        
        return CredentialTemplate(
            id=row.id,
            organization_id=row.organization_id,
            name=row.name,
            description=row.description,
            status=TemplateStatus(row.status),
            credential_type=row.credential_type,
            vct=row.vct,
            doctype=row.doctype,
            claims=claims,
            privacy_posture=PrivacyPosture(row.privacy_posture),
            selective_disclosure_fields=row.selective_disclosure_fields,
            zk_predicate_claims=list(row.zk_predicate_claims or []),
            derived_attributes=derived_attributes,
            display_style=display_style,
            validity_rules=validity_rules,
            issuer_requirements=issuer_requirements,
            supported_formats=[
                CredentialFormat(fmt) for fmt in row.supported_formats
                if fmt in CredentialFormat._value2member_map_
            ],
            wallet_configs=[WalletConfig(wallet_id=wc.get("wallet_id", ""), deep_link_scheme=wc.get("deep_link_scheme", "openid-credential-offer://"), format_variant=wc.get("format_variant")) for wc in (row.wallet_configs or [])],
            credential_payload_format=row.credential_payload_format or "w3c_vcdm_v2_sd_jwt",
            version=row.version,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
    
    async def list(
        self, 
        org_id: str, 
        status: "TemplateStatus | None" = None
    ) -> list["CredentialTemplate"]:
        """List credential templates for an organization."""
        from credential_template.main import TemplateStatus
        
        async with self._session_factory() as session:
            conditions = [credential_templates_table.c.organization_id == org_id]
            if status:
                conditions.append(credential_templates_table.c.status == status.value)
            
            stmt = select(credential_templates_table).where(and_(*conditions))
            result = await session.execute(stmt)
            rows = result.all()
            
            # Use get() to convert each row
            templates = []
            for row in rows:
                template = await self.get(row.id)
                if template:
                    templates.append(template)
            
            return templates
    
    async def list_all(
        self,
        status: "TemplateStatus | None" = None,
    ) -> "list[CredentialTemplate]":
        """List all credential templates across all organizations (internal use only)."""
        from credential_template.main import TemplateStatus

        async with self._session_factory() as session:
            conditions = []
            if status:
                conditions.append(credential_templates_table.c.status == status.value)

            stmt = select(credential_templates_table)
            if conditions:
                stmt = stmt.where(and_(*conditions))

            result = await session.execute(stmt)
            rows = result.all()

            templates = []
            for row in rows:
                template = await self.get(row.id)
                if template:
                    templates.append(template)

            return templates

    async def delete(self, template_id: str) -> None:
        """Delete a credential template."""
        async with self._session_factory() as session:
            stmt = delete(credential_templates_table).where(
                credential_templates_table.c.id == template_id
            )
            await session.execute(stmt)
            await session.commit()


class PostgresWalletRegistryRepository:
    """PostgreSQL implementation of the wallet registry repository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory

    async def save(self, entry: "WalletRegistryEntry") -> None:
        from credential_template.main import WalletRegistryEntry  # avoid circular at module level
        entry.updated_at = datetime.now(timezone.utc)
        async with self._session_factory() as session:
            row = {
                "id": entry.id,
                "organization_id": entry.organization_id,
                "is_override": entry.is_override,
                "override_precedence": entry.override_precedence,
                "merge_strategy": entry.merge_strategy.value,
                "credential_format": entry.credential_format,
                "issuance_protocol": entry.issuance_protocol,
                "compliance_profile_code": entry.compliance_profile_code,
                "name": entry.name,
                "description": entry.description,
                "wallet_apps": entry.wallet_apps,
                "specifications": entry.specifications,
                "logo_url": entry.logo_url,
                "deep_link_template": entry.deep_link_template,
                "supported_formats": entry.supported_formats,
                "supported_protocols": entry.supported_protocols,
                "platforms": entry.platforms,
                "supports_qr": entry.supports_qr,
                "supports_deeplink": entry.supports_deeplink,
                "docs_url": entry.docs_url,
                "is_active": entry.is_active,
                "created_at": entry.created_at,
                "updated_at": entry.updated_at,
            }
            existing = await session.execute(
                select(wallet_registry_table).where(wallet_registry_table.c.id == entry.id)
            )
            if existing.first() is not None:
                await session.execute(
                    wallet_registry_table.update()
                    .where(wallet_registry_table.c.id == entry.id)
                    .values(**{k: v for k, v in row.items() if k != "id"})
                )
            else:
                await session.execute(wallet_registry_table.insert().values(**row))
            await session.commit()

    async def get(self, wallet_id: str) -> "WalletRegistryEntry | None":
        async with self._session_factory() as session:
            result = await session.execute(
                select(wallet_registry_table).where(wallet_registry_table.c.id == wallet_id)
            )
            row = result.first()
            return self._row_to_entry(row) if row else None

    async def list(self, active_only: bool = True) -> "list[WalletRegistryEntry]":
        async with self._session_factory() as session:
            stmt = select(wallet_registry_table)
            if active_only:
                stmt = stmt.where(wallet_registry_table.c.is_active == True)
            result = await session.execute(stmt)
            return [self._row_to_entry(row) for row in result.all()]

    async def delete(self, wallet_id: str) -> None:
        async with self._session_factory() as session:
            await session.execute(
                delete(wallet_registry_table).where(wallet_registry_table.c.id == wallet_id)
            )
            await session.commit()

    @staticmethod
    def _row_to_entry(row) -> "WalletRegistryEntry":
        from credential_template.main import WalletRegistryEntry, MergeStrategy
        return WalletRegistryEntry(
            id=row.id,
            organization_id=row.organization_id,
            is_override=row.is_override,
            override_precedence=row.override_precedence,
            merge_strategy=MergeStrategy(row.merge_strategy),
            credential_format=row.credential_format,
            issuance_protocol=row.issuance_protocol,
            compliance_profile_code=row.compliance_profile_code,
            name=row.name,
            description=row.description,
            wallet_apps=list(row.wallet_apps or []),
            specifications=list(row.specifications or []),
            logo_url=row.logo_url,
            deep_link_template=row.deep_link_template,
            supported_formats=list(row.supported_formats or []),
            supported_protocols=list(row.supported_protocols or ["OID4VCI_PRE_AUTH"]),
            platforms=list(row.platforms or []),
            supports_qr=row.supports_qr,
            supports_deeplink=row.supports_deeplink,
            docs_url=row.docs_url,
            is_active=row.is_active,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
