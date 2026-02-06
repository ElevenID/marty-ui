"""
PostgreSQL adapter for Trust Profile Repository.

Implements the repository pattern for trust profile and trusted issuer persistence.
"""

import json
from typing import TYPE_CHECKING
from datetime import datetime, timezone

from sqlalchemy import select, delete, and_
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from trust_profile.infrastructure.models import trust_profiles_table, trusted_issuers_table

if TYPE_CHECKING:
    from trust_profile.main import TrustProfile, TrustedIssuer, TrustProfileStatus, IssuerStatus


class PostgresTrustProfileRepository:
    """PostgreSQL implementation of trust profile repository."""
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory
    
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
            TrustProfile, TrustProfileStatus, TrustSource, ValidationRules,
            RevocationPolicy, RevocationCheckMode, TimePolicy, CredentialFormat
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
                check_mode=RevocationCheckMode(row.revocation_policy.get("check_mode", "hard_fail")),
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
                trust_sources=trust_sources,
                validation_rules=validation_rules,
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
        async with self._session_factory() as session:
            stmt = delete(trusted_issuers_table).where(
                trusted_issuers_table.c.id == issuer_id
            )
            await session.execute(stmt)
            await session.commit()
