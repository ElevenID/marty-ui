"""
PostgreSQL adapter for Trust Profile Repository.

Implements the repository pattern for trust profile, trust framework,
and trusted issuer persistence.
"""

from typing import TYPE_CHECKING

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from trust_profile.infrastructure.models import (
    issuer_entities_table,
    organization_trust_profiles_table,
    trust_frameworks_table,
    trust_profiles_table,
    trust_profile_issuers_table,
    trust_registry_entries_table,
    trusted_issuers_table,
)

if TYPE_CHECKING:
    from trust_profile.main import IssuerEntity, OrganizationTrustProfile, TrustFramework, TrustProfile, TrustProfileIssuer, TrustRegistryEntry, TrustedIssuer


class PostgresTrustProfileRepository:
    """PostgreSQL implementation of trust profile repository."""
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory

    async def _delete_where(self, table, *conditions) -> None:
        async with self._session_factory() as session:
            await session.execute(delete(table).where(*conditions))
            await session.commit()

    # =========================================================================
    # Organization Trust Profile Operations
    # =========================================================================

    async def save_organization_trust_profile(self, profile: "OrganizationTrustProfile") -> None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(organization_trust_profiles_table).where(organization_trust_profiles_table.c.id == profile.id)
            )
            existing = result.first()

            profile_data = {
                "id": profile.id,
                "organization_id": profile.organization_id,
                "framework_id": profile.framework_id,
                "name": profile.name,
                "display_name": profile.display_name,
                "description": profile.description,
                "enabled": profile.enabled,
                "use_case_tags": profile.use_case_tags,
                "compliance_status": profile.compliance_status.value,
                "auto_generated": profile.auto_generated,
                "revocation_policy": profile.revocation_policy,
                "time_policy": profile.time_policy,
                "allowed_algorithms": profile.allowed_algorithms,
                "allowed_formats": [fmt.value for fmt in profile.allowed_formats] if profile.allowed_formats is not None else None,
                "allowed_issuers": profile.allowed_issuers,
                "denied_issuers": profile.denied_issuers,
                "jurisdiction_filter": profile.jurisdiction_filter,
                "metadata": profile.metadata,
                "updated_at": profile.updated_at,
            }

            if existing:
                stmt = (
                    organization_trust_profiles_table.update()
                    .where(organization_trust_profiles_table.c.id == profile.id)
                    .values(**profile_data)
                )
            else:
                profile_data["created_at"] = profile.created_at
                stmt = organization_trust_profiles_table.insert().values(**profile_data)

            await session.execute(stmt)
            await session.commit()

    async def get_organization_trust_profile(self, profile_id: str) -> "OrganizationTrustProfile | None":
        from trust_profile.main import ComplianceStatus, CredentialFormat, OrganizationTrustProfile

        async with self._session_factory() as session:
            result = await session.execute(
                select(organization_trust_profiles_table).where(organization_trust_profiles_table.c.id == profile_id)
            )
            row = result.first()
            if not row:
                return None

            return OrganizationTrustProfile(
                id=row.id,
                organization_id=row.organization_id,
                framework_id=row.framework_id,
                name=row.name,
                display_name=row.display_name,
                description=row.description,
                enabled=row.enabled,
                use_case_tags=row.use_case_tags or [],
                compliance_status=ComplianceStatus(row.compliance_status),
                auto_generated=row.auto_generated,
                revocation_policy=row.revocation_policy,
                time_policy=row.time_policy,
                allowed_algorithms=row.allowed_algorithms,
                allowed_formats=[CredentialFormat(fmt) for fmt in (row.allowed_formats or [])] if row.allowed_formats is not None else None,
                allowed_issuers=row.allowed_issuers,
                denied_issuers=row.denied_issuers,
                jurisdiction_filter=row.jurisdiction_filter,
                metadata=row.metadata or {},
                created_at=row.created_at,
                updated_at=row.updated_at,
            )

    async def list_organization_trust_profiles(self, organization_id: str) -> list["OrganizationTrustProfile"]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(organization_trust_profiles_table)
                .where(organization_trust_profiles_table.c.organization_id == organization_id)
                .order_by(organization_trust_profiles_table.c.created_at.asc(), organization_trust_profiles_table.c.id.asc())
            )
            rows = result.all()

        profiles = []
        for row in rows:
            profile = await self.get_organization_trust_profile(row.id)
            if profile:
                profiles.append(profile)
        return profiles

    async def delete_organization_trust_profile(self, profile_id: str) -> None:
        await self._delete_where(organization_trust_profiles_table, organization_trust_profiles_table.c.id == profile_id)

    # =========================================================================
    # Trust Registry Operations
    # =========================================================================

    async def save_registry_entry(self, entry: "TrustRegistryEntry") -> None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(trust_registry_entries_table).where(trust_registry_entries_table.c.id == entry.id)
            )
            existing = result.first()

            entry_data = {
                "id": entry.id,
                "anchor_type": entry.anchor_type.value,
                "operation": entry.operation.value,
                "country_code": entry.country_code,
                "certificate_pem": entry.certificate_pem,
                "subject_key_id": entry.subject_key_id,
                "not_before": entry.not_before,
                "not_after": entry.not_after,
                "source": entry.source.value,
                "framework_code": entry.framework_code,
                "sequence": entry.sequence,
                "is_current": entry.is_current,
                "updated_at": entry.updated_at,
            }

            if existing:
                stmt = (
                    trust_registry_entries_table.update()
                    .where(trust_registry_entries_table.c.id == entry.id)
                    .values(**entry_data)
                )
            else:
                entry_data["created_at"] = entry.created_at
                stmt = trust_registry_entries_table.insert().values(**entry_data)

            await session.execute(stmt)
            await session.commit()

    async def list_registry_entries(
        self,
        anchor_type: str | None = None,
        country_code: str | None = None,
        current_only: bool = True,
        since_sequence: int | None = None,
    ) -> list["TrustRegistryEntry"]:
        from trust_profile.main import TrustAnchorType, TrustRegistryEntry, TrustRegistryOperation, TrustRegistrySource

        async with self._session_factory() as session:
            stmt = select(trust_registry_entries_table)
            if anchor_type is not None:
                stmt = stmt.where(trust_registry_entries_table.c.anchor_type == anchor_type)
            if country_code is not None:
                stmt = stmt.where(trust_registry_entries_table.c.country_code == country_code.upper())
            if current_only:
                stmt = stmt.where(trust_registry_entries_table.c.is_current.is_(True))
            if since_sequence is not None:
                stmt = stmt.where(trust_registry_entries_table.c.sequence > since_sequence)
            stmt = stmt.order_by(
                trust_registry_entries_table.c.sequence.asc(),
                trust_registry_entries_table.c.country_code.asc(),
                trust_registry_entries_table.c.id.asc(),
            )
            result = await session.execute(stmt)
            rows = result.all()
            return [
                TrustRegistryEntry(
                    id=row.id,
                    anchor_type=TrustAnchorType(row.anchor_type),
                    operation=TrustRegistryOperation(row.operation),
                    country_code=row.country_code,
                    certificate_pem=row.certificate_pem,
                    subject_key_id=row.subject_key_id,
                    not_before=row.not_before,
                    not_after=row.not_after,
                    source=TrustRegistrySource(row.source),
                    framework_code=row.framework_code,
                    sequence=row.sequence,
                    is_current=row.is_current,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                )
                for row in rows
            ]

    async def get_registry_sequence(self) -> int:
        async with self._session_factory() as session:
            result = await session.execute(select(func.max(trust_registry_entries_table.c.sequence)))
            return int(result.scalar() or 0)

    async def get_registry_status(self) -> dict[str, int | None]:
        async with self._session_factory() as session:
            total_result = await session.execute(select(func.count()).select_from(trust_registry_entries_table))
            current_result = await session.execute(
                select(func.count()).select_from(trust_registry_entries_table).where(
                    trust_registry_entries_table.c.is_current.is_(True)
                )
            )
            csca_result = await session.execute(
                select(func.count()).select_from(trust_registry_entries_table).where(
                    trust_registry_entries_table.c.is_current.is_(True),
                    trust_registry_entries_table.c.anchor_type == "CSCA",
                )
            )
            dsc_result = await session.execute(
                select(func.count()).select_from(trust_registry_entries_table).where(
                    trust_registry_entries_table.c.is_current.is_(True),
                    trust_registry_entries_table.c.anchor_type == "DSC",
                )
            )
            seq_result = await session.execute(select(func.max(trust_registry_entries_table.c.sequence)))
            return {
                "total_entries": int(total_result.scalar() or 0),
                "current_entries": int(current_result.scalar() or 0),
                "csca_entries": int(csca_result.scalar() or 0),
                "dsc_entries": int(dsc_result.scalar() or 0),
                "current_sequence": int(seq_result.scalar() or 0),
            }

    # =========================================================================
    # Trust Framework Operations
    # =========================================================================

    async def save_framework(self, framework: "TrustFramework") -> None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(trust_frameworks_table).where(trust_frameworks_table.c.id == framework.id)
            )
            existing = result.first()

            framework_data = {
                "id": framework.id,
                "code": framework.code,
                "display_name": framework.display_name,
                "description": framework.description,
                "pkd_endpoints": framework.pkd_endpoints,
                "default_algorithms": framework.default_algorithms,
                "default_formats": framework.default_formats,
                "validation_ruleset": framework.validation_ruleset,
                "sync_config": framework.sync_config,
                "is_system": framework.is_system,
                "updated_at": framework.updated_at,
            }

            if existing:
                stmt = (
                    trust_frameworks_table.update()
                    .where(trust_frameworks_table.c.id == framework.id)
                    .values(**framework_data)
                )
            else:
                framework_data["created_at"] = framework.created_at
                stmt = trust_frameworks_table.insert().values(**framework_data)

            await session.execute(stmt)
            await session.commit()

    async def get_framework(self, framework_id: str) -> "TrustFramework | None":
        from trust_profile.main import TrustFramework

        async with self._session_factory() as session:
            result = await session.execute(
                select(trust_frameworks_table).where(trust_frameworks_table.c.id == framework_id)
            )
            row = result.first()
            if not row:
                return None

            return TrustFramework(
                id=row.id,
                code=row.code,
                display_name=row.display_name,
                description=row.description,
                pkd_endpoints=row.pkd_endpoints or [],
                default_algorithms=row.default_algorithms or [],
                default_formats=row.default_formats or [],
                validation_ruleset=row.validation_ruleset or {},
                sync_config=row.sync_config or {},
                is_system=row.is_system,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )

    async def get_framework_by_code(self, code: str) -> "TrustFramework | None":
        from trust_profile.main import TrustFramework

        async with self._session_factory() as session:
            result = await session.execute(
                select(trust_frameworks_table).where(trust_frameworks_table.c.code == code)
            )
            row = result.first()
            if not row:
                return None

            return TrustFramework(
                id=row.id,
                code=row.code,
                display_name=row.display_name,
                description=row.description,
                pkd_endpoints=row.pkd_endpoints or [],
                default_algorithms=row.default_algorithms or [],
                default_formats=row.default_formats or [],
                validation_ruleset=row.validation_ruleset or {},
                sync_config=row.sync_config or {},
                is_system=row.is_system,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )

    async def list_frameworks(self) -> list["TrustFramework"]:
        from trust_profile.main import TrustFramework

        async with self._session_factory() as session:
            result = await session.execute(
                select(trust_frameworks_table).order_by(
                    trust_frameworks_table.c.is_system.desc(),
                    trust_frameworks_table.c.code.asc(),
                )
            )
            rows = result.all()
            return [
                TrustFramework(
                    id=row.id,
                    code=row.code,
                    display_name=row.display_name,
                    description=row.description,
                    pkd_endpoints=row.pkd_endpoints or [],
                    default_algorithms=row.default_algorithms or [],
                    default_formats=row.default_formats or [],
                    validation_ruleset=row.validation_ruleset or {},
                    sync_config=row.sync_config or {},
                    is_system=row.is_system,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                )
                for row in rows
            ]
    
    # =========================================================================
    # Trust Profile Operations
    # =========================================================================
    
    async def save_profile(self, profile: "TrustProfile") -> None:
        """Save or update a trust profile."""
        from trust_profile.main import TrustProfileStatus, CredentialFormat
        
        async with self._session_factory() as session:
            # Check if profile exists
            stmt = select(trust_profiles_table).where(
                trust_profiles_table.c.id == profile.id
            )
            result = await session.execute(stmt)
            existing = result.first()
            
            # Serialize nested objects to JSON
            trust_sources_json = [
                {
                    "id": ts.id,
                    "name": ts.name,
                    "source_type": ts.source_type,
                    "url": ts.url,
                    "certificate_pem": ts.certificate_pem,
                    "issuer_did": ts.issuer_did,
                    "description": ts.description,
                    "pinned_certificates": ts.pinned_certificates,
                    "refresh_interval_hours": ts.refresh_interval_hours,
                    "enabled": ts.enabled,
                }
                for ts in profile.trust_sources
            ]
            
            validation_rules_json = {
                "allowed_algorithms": profile.validation_rules.allowed_algorithms,
                "min_key_size_rsa": profile.validation_rules.min_key_size_rsa,
                "min_key_size_ec": profile.validation_rules.min_key_size_ec,
                "require_key_usage": profile.validation_rules.require_key_usage,
                "max_chain_depth": profile.validation_rules.max_chain_depth,
                "allow_self_signed": profile.validation_rules.allow_self_signed,
                "profile_type": profile.profile_type.value,
                "compliance_status": profile.compliance_status.value,
                "allowed_issuers": profile.allowed_issuers,
                "denied_issuers": profile.denied_issuers,
                "system_issuer_overrides": profile.system_issuer_overrides,
                "compatible_compliance_codes": profile.compatible_compliance_codes,
                "verification_policy_set_id": profile.verification_policy_set_id,
                "auto_generated": profile.auto_generated,
            }
            
            revocation_policy_json = {
                "check_mode": profile.revocation_policy.check_mode.value,
                "check_ocsp": profile.revocation_policy.check_ocsp,
                "check_crl": profile.revocation_policy.check_crl,
                "check_status_list": profile.revocation_policy.check_status_list,
                "offline_grace_period_hours": profile.revocation_policy.offline_grace_period_hours,
                "cache_duration_hours": profile.revocation_policy.cache_duration_hours,
            }
            
            time_policy_json = {
                "max_clock_skew_seconds": profile.time_policy.max_clock_skew_seconds,
                "credential_freshness_hours": profile.time_policy.credential_freshness_hours,
                "require_not_before": profile.time_policy.require_not_before,
                "require_expiration": profile.time_policy.require_expiration,
            }
            
            profile_data = {
                "id": profile.id,
                "organization_id": profile.organization_id,
                "name": profile.name,
                "description": profile.description,
                "status": profile.status.value,
                "trust_sources": trust_sources_json,
                "validation_rules": validation_rules_json,
                "revocation_policy": revocation_policy_json,
                "revocation_profile_id": profile.revocation_profile_id,
                "time_policy": time_policy_json,
                "supported_formats": [fmt.value for fmt in profile.supported_formats],
                "updated_at": profile.updated_at,
            }
            
            if existing:
                # Update existing
                stmt = (
                    trust_profiles_table.update()
                    .where(trust_profiles_table.c.id == profile.id)
                    .values(**profile_data)
                )
                await session.execute(stmt)
            else:
                # Insert new
                profile_data["created_at"] = profile.created_at
                stmt = trust_profiles_table.insert().values(**profile_data)
                await session.execute(stmt)
            
            await session.commit()
    
    async def get_profile(self, profile_id: str) -> "TrustProfile | None":
        """Get a trust profile by ID."""
        from trust_profile.main import (
            ComplianceStatus,
            TrustProfile,
            TrustProfileStatus,
            TrustProfileType,
            TrustSource,
            ValidationRules,
            RevocationPolicy,
            RevocationCheckMode,
            TimePolicy,
            CredentialFormat,
        )
        
        async with self._session_factory() as session:
            stmt = select(trust_profiles_table).where(
                trust_profiles_table.c.id == profile_id
            )
            result = await session.execute(stmt)
            row = result.first()
            
            if not row:
                return None
            
            # Reconstruct nested objects from JSON
            trust_sources = [
                TrustSource(
                    id=ts["id"],
                    name=ts["name"],
                    source_type=ts["source_type"],
                    url=ts.get("url"),
                    certificate_pem=ts.get("certificate_pem"),
                    issuer_did=ts.get("issuer_did"),
                    description=ts.get("description"),
                    pinned_certificates=ts.get("pinned_certificates", []),
                    refresh_interval_hours=ts.get("refresh_interval_hours", 24),
                    enabled=ts.get("enabled", True),
                )
                for ts in row.trust_sources
            ]
            
            validation_rules = ValidationRules(
                allowed_algorithms=row.validation_rules.get("allowed_algorithms", ["ES256", "ES384", "EdDSA"]),
                min_key_size_rsa=row.validation_rules.get("min_key_size_rsa", 2048),
                min_key_size_ec=row.validation_rules.get("min_key_size_ec", 256),
                require_key_usage=row.validation_rules.get("require_key_usage", True),
                max_chain_depth=row.validation_rules.get("max_chain_depth", 5),
                allow_self_signed=row.validation_rules.get("allow_self_signed", False),
            )
            
            revocation_policy = RevocationPolicy(
                check_mode=RevocationCheckMode(row.revocation_policy.get("check_mode", "HARD_FAIL")),
                check_ocsp=row.revocation_policy.get("check_ocsp", True),
                check_crl=row.revocation_policy.get("check_crl", True),
                check_status_list=row.revocation_policy.get("check_status_list", True),
                offline_grace_period_hours=row.revocation_policy.get("offline_grace_period_hours", 24),
                cache_duration_hours=row.revocation_policy.get("cache_duration_hours", 1),
            )
            
            time_policy = TimePolicy(
                max_clock_skew_seconds=row.time_policy.get("max_clock_skew_seconds", 300),
                credential_freshness_hours=row.time_policy.get("credential_freshness_hours"),
                require_not_before=row.time_policy.get("require_not_before", True),
                require_expiration=row.time_policy.get("require_expiration", True),
            )
            
            supported_formats = [CredentialFormat(fmt) for fmt in row.supported_formats]
            
            return TrustProfile(
                id=row.id,
                organization_id=row.organization_id,
                name=row.name,
                description=row.description,
                status=TrustProfileStatus(row.status),
                profile_type=TrustProfileType(row.validation_rules.get("profile_type", "CUSTOM")),
                compliance_status=ComplianceStatus(row.validation_rules.get("compliance_status", "SETUP_REQUIRED")),
                trust_sources=trust_sources,
                validation_rules=validation_rules,
                allowed_issuers=row.validation_rules.get("allowed_issuers"),
                denied_issuers=row.validation_rules.get("denied_issuers"),
                system_issuer_overrides=row.validation_rules.get("system_issuer_overrides", {}),
                compatible_compliance_codes=row.validation_rules.get("compatible_compliance_codes", []),
                verification_policy_set_id=row.validation_rules.get("verification_policy_set_id"),
                auto_generated=row.validation_rules.get("auto_generated", False),
                revocation_policy=revocation_policy,
                revocation_profile_id=row.revocation_profile_id,
                time_policy=time_policy,
                supported_formats=supported_formats,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
    
    async def list_profiles(self, org_id: str) -> list["TrustProfile"]:
        """List trust profiles for an organization."""
        async with self._session_factory() as session:
            stmt = select(trust_profiles_table).where(
                trust_profiles_table.c.organization_id == org_id
            )
            result = await session.execute(stmt)
            rows = result.all()
            
            # Use get_profile to reconstruct each profile
            profiles = []
            for row in rows:
                profile = await self.get_profile(row.id)
                if profile:
                    profiles.append(profile)
            
            return profiles
    
    async def delete_profile(self, profile_id: str) -> None:
        """Delete a trust profile and associated issuers."""
        async with self._session_factory() as session:
            await session.execute(
                delete(trust_profile_issuers_table).where(
                    trust_profile_issuers_table.c.trust_profile_id == profile_id
                )
            )
            # Delete associated issuers first
            await session.execute(
                delete(trusted_issuers_table).where(
                    trusted_issuers_table.c.trust_profile_id == profile_id
                )
            )
            
            # Delete profile
            await session.execute(
                delete(trust_profiles_table).where(
                    trust_profiles_table.c.id == profile_id
                )
            )
            
            await session.commit()
    
    # =========================================================================
    # Issuer Registry Operations
    # =========================================================================

    async def save_issuer_entity(self, issuer_entity: "IssuerEntity") -> None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(issuer_entities_table).where(issuer_entities_table.c.id == issuer_entity.id)
            )
            existing = result.first()

            issuer_entity_data = {
                "id": issuer_entity.id,
                "organization_id": issuer_entity.organization_id,
                "issuer_id": issuer_entity.issuer_id,
                "issuer_type": issuer_entity.issuer_type.value,
                "display_name": issuer_entity.display_name,
                "description": issuer_entity.description,
                "is_system_issuer": issuer_entity.is_system_issuer,
                "compliance_status": issuer_entity.compliance_status.value,
                "accreditation_body": issuer_entity.accreditation_body,
                "accreditation_date": issuer_entity.accreditation_date,
                "valid_from": issuer_entity.valid_from,
                "valid_until": issuer_entity.valid_until,
                "trust_anchor_id": issuer_entity.trust_anchor_id,
                "revoked_at": issuer_entity.revoked_at,
                "revocation_reason": issuer_entity.revocation_reason,
                "revoked_by": issuer_entity.revoked_by,
                "metadata": issuer_entity.metadata,
                "updated_at": issuer_entity.updated_at,
            }

            if existing:
                stmt = (
                    issuer_entities_table.update()
                    .where(issuer_entities_table.c.id == issuer_entity.id)
                    .values(**issuer_entity_data)
                )
            else:
                issuer_entity_data["created_at"] = issuer_entity.created_at
                stmt = issuer_entities_table.insert().values(**issuer_entity_data)

            await session.execute(stmt)
            await session.commit()

    async def get_issuer_entity(self, issuer_entity_id: str) -> "IssuerEntity | None":
        from trust_profile.main import IssuerEntity, IssuerEntityComplianceStatus, IssuerEntityType

        async with self._session_factory() as session:
            result = await session.execute(
                select(issuer_entities_table).where(issuer_entities_table.c.id == issuer_entity_id)
            )
            row = result.first()
            if not row:
                return None

            return IssuerEntity(
                id=row.id,
                organization_id=row.organization_id,
                issuer_id=row.issuer_id,
                issuer_type=IssuerEntityType(row.issuer_type),
                display_name=row.display_name,
                description=row.description,
                is_system_issuer=row.is_system_issuer,
                compliance_status=IssuerEntityComplianceStatus(row.compliance_status),
                accreditation_body=row.accreditation_body,
                accreditation_date=row.accreditation_date,
                valid_from=row.valid_from,
                valid_until=row.valid_until,
                trust_anchor_id=row.trust_anchor_id,
                revoked_at=row.revoked_at,
                revocation_reason=row.revocation_reason,
                revoked_by=row.revoked_by,
                metadata=row.metadata or {},
                created_at=row.created_at,
                updated_at=row.updated_at,
            )

    async def find_issuer_entity_by_identifier(
        self,
        organization_id: str | None,
        issuer_id: str,
    ) -> "IssuerEntity | None":
        async with self._session_factory() as session:
            stmt = select(issuer_entities_table).where(issuer_entities_table.c.issuer_id == issuer_id)
            if organization_id is None:
                stmt = stmt.where(issuer_entities_table.c.organization_id.is_(None))
            else:
                stmt = stmt.where(issuer_entities_table.c.organization_id == organization_id)
            result = await session.execute(stmt)
            row = result.first()
            if not row:
                return None
        return await self.get_issuer_entity(row.id)

    async def list_issuer_entities(self, organization_id: str | None = None) -> list["IssuerEntity"]:
        async with self._session_factory() as session:
            stmt = select(issuer_entities_table)
            if organization_id is not None:
                stmt = stmt.where(
                    (issuer_entities_table.c.organization_id == organization_id)
                    | issuer_entities_table.c.organization_id.is_(None)
                    | issuer_entities_table.c.is_system_issuer.is_(True)
                )
            stmt = stmt.order_by(issuer_entities_table.c.display_name.asc(), issuer_entities_table.c.id.asc())
            result = await session.execute(stmt)
            rows = result.all()
        entities = []
        for row in rows:
            entity = await self.get_issuer_entity(row.id)
            if entity:
                entities.append(entity)
        return entities

    async def delete_issuer_entity(self, issuer_entity_id: str) -> None:
        async with self._session_factory() as session:
            await session.execute(
                delete(trust_profile_issuers_table).where(trust_profile_issuers_table.c.issuer_id == issuer_entity_id)
            )
            await session.execute(
                delete(issuer_entities_table).where(issuer_entities_table.c.id == issuer_entity_id)
            )
            await session.commit()

    async def save_profile_issuer(self, profile_issuer: "TrustProfileIssuer") -> None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(trust_profile_issuers_table).where(trust_profile_issuers_table.c.id == profile_issuer.id)
            )
            existing = result.first()

            profile_issuer_data = {
                "id": profile_issuer.id,
                "trust_profile_id": profile_issuer.trust_profile_id,
                "issuer_id": profile_issuer.issuer_id,
                "trust_level": profile_issuer.trust_level,
                "relationship_status": profile_issuer.relationship_status.value,
                "cascade_revocation_policy": profile_issuer.cascade_revocation_policy.value,
                "metadata": profile_issuer.metadata,
                "updated_at": profile_issuer.updated_at,
            }

            if existing:
                stmt = (
                    trust_profile_issuers_table.update()
                    .where(trust_profile_issuers_table.c.id == profile_issuer.id)
                    .values(**profile_issuer_data)
                )
            else:
                profile_issuer_data["created_at"] = profile_issuer.created_at
                stmt = trust_profile_issuers_table.insert().values(**profile_issuer_data)

            await session.execute(stmt)
            await session.commit()

    async def get_profile_issuer(self, profile_issuer_id: str) -> "TrustProfileIssuer | None":
        from trust_profile.main import CascadeRevocationPolicy, TrustProfileIssuer, TrustRelationshipStatus

        async with self._session_factory() as session:
            result = await session.execute(
                select(trust_profile_issuers_table).where(trust_profile_issuers_table.c.id == profile_issuer_id)
            )
            row = result.first()
            if not row:
                return None

            return TrustProfileIssuer(
                id=row.id,
                trust_profile_id=row.trust_profile_id,
                issuer_id=row.issuer_id,
                trust_level=row.trust_level,
                relationship_status=TrustRelationshipStatus(row.relationship_status),
                cascade_revocation_policy=CascadeRevocationPolicy(row.cascade_revocation_policy),
                metadata=row.metadata or {},
                created_at=row.created_at,
                updated_at=row.updated_at,
            )

    async def get_profile_issuer_by_pair(self, trust_profile_id: str, issuer_id: str) -> "TrustProfileIssuer | None":
        async with self._session_factory() as session:
            result = await session.execute(
                select(trust_profile_issuers_table).where(
                    trust_profile_issuers_table.c.trust_profile_id == trust_profile_id,
                    trust_profile_issuers_table.c.issuer_id == issuer_id,
                )
            )
            row = result.first()
            if not row:
                return None
        return await self.get_profile_issuer(row.id)

    async def list_profile_issuers(self, trust_profile_id: str) -> list["TrustProfileIssuer"]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(trust_profile_issuers_table)
                .where(trust_profile_issuers_table.c.trust_profile_id == trust_profile_id)
                .order_by(trust_profile_issuers_table.c.created_at.asc(), trust_profile_issuers_table.c.id.asc())
            )
            rows = result.all()
        links = []
        for row in rows:
            link = await self.get_profile_issuer(row.id)
            if link:
                links.append(link)
        return links

    async def delete_profile_issuer(self, profile_issuer_id: str) -> None:
        await self._delete_where(trust_profile_issuers_table, trust_profile_issuers_table.c.id == profile_issuer_id)

    # =========================================================================
    # Trusted Issuer Operations
    # =========================================================================
    
    async def save_issuer(self, issuer: "TrustedIssuer") -> None:
        """Save or update a trusted issuer."""
        from trust_profile.main import IssuerStatus
        
        async with self._session_factory() as session:
            # Check if issuer exists
            stmt = select(trusted_issuers_table).where(
                trusted_issuers_table.c.id == issuer.id
            )
            result = await session.execute(stmt)
            existing = result.first()
            
            issuer_data = {
                "id": issuer.id,
                "trust_profile_id": issuer.trust_profile_id,
                "name": issuer.name,
                "description": issuer.description,
                "issuer_did": issuer.issuer_did,
                "issuer_url": issuer.issuer_url,
                "status": issuer.status.value,
                "credential_template_ids": issuer.credential_template_ids,
                "verification_keys": issuer.verification_keys,
                "valid_from": issuer.valid_from,
                "valid_until": issuer.valid_until,
                "updated_at": issuer.updated_at,
            }
            
            if existing:
                # Update existing
                stmt = (
                    trusted_issuers_table.update()
                    .where(trusted_issuers_table.c.id == issuer.id)
                    .values(**issuer_data)
                )
                await session.execute(stmt)
            else:
                # Insert new
                issuer_data["created_at"] = issuer.created_at
                stmt = trusted_issuers_table.insert().values(**issuer_data)
                await session.execute(stmt)
            
            await session.commit()
    
    async def get_issuer(self, issuer_id: str) -> "TrustedIssuer | None":
        """Get a trusted issuer by ID."""
        from trust_profile.main import TrustedIssuer, IssuerStatus
        
        async with self._session_factory() as session:
            stmt = select(trusted_issuers_table).where(
                trusted_issuers_table.c.id == issuer_id
            )
            result = await session.execute(stmt)
            row = result.first()
            
            if not row:
                return None
            
            return TrustedIssuer(
                id=row.id,
                trust_profile_id=row.trust_profile_id,
                name=row.name,
                description=row.description,
                issuer_did=row.issuer_did,
                issuer_url=row.issuer_url,
                status=IssuerStatus(row.status),
                credential_template_ids=row.credential_template_ids or [],
                verification_keys=row.verification_keys or [],
                valid_from=row.valid_from,
                valid_until=row.valid_until,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
    
    async def list_issuers(self, profile_id: str) -> list["TrustedIssuer"]:
        """List trusted issuers for a trust profile."""
        async with self._session_factory() as session:
            stmt = select(trusted_issuers_table).where(
                trusted_issuers_table.c.trust_profile_id == profile_id
            )
            result = await session.execute(stmt)
            rows = result.all()
            
            # Use get_issuer to reconstruct each issuer
            issuers = []
            for row in rows:
                issuer = await self.get_issuer(row.id)
                if issuer:
                    issuers.append(issuer)
            
            return issuers
    
    async def delete_issuer(self, issuer_id: str) -> None:
        """Delete a trusted issuer."""
        await self._delete_where(trusted_issuers_table, trusted_issuers_table.c.id == issuer_id)
