"""
PostgreSQL adapter for Revocation Profile Repository.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from revocation_profile.infrastructure.models import revocation_profiles_table

if TYPE_CHECKING:
    from revocation_profile.main import RevocationProfile


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PostgresRevocationProfileRepository:
    """PostgreSQL-backed repository for RevocationProfile."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, profile: "RevocationProfile") -> None:
        from revocation_profile.main import (
            IssuerRevocationConfig,
            VerifierRevocationConfig,
            RevocationAutomationConfig,
            StatusListStrategy,
            UpdateMode,
            RevocationCheckMode,
            RevocationTimingMode,
            RevocationMechanism,
            CredentialFormat,
        )

        issuer_cfg = {
            "status_list_strategy": profile.issuer_config.status_list_strategy.value,
            "status_list_base_url": profile.issuer_config.status_list_base_url,
            "status_list_size": profile.issuer_config.status_list_size,
            "update_mode": profile.issuer_config.update_mode.value,
            "batch_interval_seconds": profile.issuer_config.batch_interval_seconds,
            "enable_rotation": profile.issuer_config.enable_rotation,
            "rotation_threshold_percent": profile.issuer_config.rotation_threshold_percent,
            "enable_bitstring_status_list": profile.issuer_config.enable_bitstring_status_list,
            "enable_token_status_list": profile.issuer_config.enable_token_status_list,
            "enable_legacy_revocation_list": profile.issuer_config.enable_legacy_revocation_list,
        }
        verifier_cfg = {
            "check_mode": profile.verifier_config.check_mode.value,
            "timing_mode": profile.verifier_config.timing_mode.value,
            "mechanism_priority": [m.value for m in profile.verifier_config.mechanism_priority],
            "cache_status_lists": profile.verifier_config.cache_status_lists,
            "cache_ttl_seconds": profile.verifier_config.cache_ttl_seconds,
            "offline_grace_seconds": profile.verifier_config.offline_grace_seconds,
            "check_timeout_seconds": profile.verifier_config.check_timeout_seconds,
            "max_retries": profile.verifier_config.max_retries,
            "require_issuer_signature_on_status_list": profile.verifier_config.require_issuer_signature_on_status_list,
            "allow_third_party_registries": profile.verifier_config.allow_third_party_registries,
        }
        automation_cfg = {
            "auto_allocate_indices": profile.automation_config.auto_allocate_indices,
            "auto_publish": profile.automation_config.auto_publish,
            "auto_generate_status_list_credentials": profile.automation_config.auto_generate_status_list_credentials,
            "auto_discover_endpoints": profile.automation_config.auto_discover_endpoints,
            "use_format_defaults": profile.automation_config.use_format_defaults,
        }

        row_data = {
            "organization_id": profile.organization_id,
            "name": profile.name,
            "status": profile.status.value,
            "issuer_config": issuer_cfg,
            "verifier_config": verifier_cfg,
            "automation_config": automation_cfg,
            "supported_formats": [f.value for f in profile.supported_formats],
            "updated_at": profile.updated_at,
        }

        async with self._session_factory() as session:
            result = await session.execute(
                select(revocation_profiles_table).where(
                    revocation_profiles_table.c.id == profile.id
                )
            )
            existing = result.first()

            if existing:
                stmt = (
                    revocation_profiles_table.update()
                    .where(revocation_profiles_table.c.id == profile.id)
                    .values(**row_data)
                )
            else:
                row_data["id"] = profile.id
                row_data["created_at"] = profile.created_at
                stmt = revocation_profiles_table.insert().values(**row_data)

            await session.execute(stmt)
            await session.commit()

    async def get(self, profile_id: str) -> "RevocationProfile | None":
        async with self._session_factory() as session:
            result = await session.execute(
                select(revocation_profiles_table).where(
                    revocation_profiles_table.c.id == profile_id
                )
            )
            row = result.first()
            if not row:
                return None
            return self._row_to_domain(row)

    async def list(self, org_id: str) -> "list[RevocationProfile]":
        async with self._session_factory() as session:
            result = await session.execute(
                select(revocation_profiles_table).where(
                    revocation_profiles_table.c.organization_id == org_id
                )
            )
            return [self._row_to_domain(row) for row in result.all()]

    async def delete(self, profile_id: str) -> None:
        async with self._session_factory() as session:
            await session.execute(
                delete(revocation_profiles_table).where(
                    revocation_profiles_table.c.id == profile_id
                )
            )
            await session.commit()

    def _row_to_domain(self, row) -> "RevocationProfile":
        from revocation_profile.main import (
            RevocationProfile,
            RevocationProfileStatus,
            IssuerRevocationConfig,
            VerifierRevocationConfig,
            RevocationAutomationConfig,
            StatusListStrategy,
            UpdateMode,
            RevocationCheckMode,
            RevocationTimingMode,
            RevocationMechanism,
            CredentialFormat,
        )

        ic = row.issuer_config or {}
        vc = row.verifier_config or {}
        ac = row.automation_config or {}

        issuer_config = IssuerRevocationConfig(
            status_list_strategy=StatusListStrategy(ic.get("status_list_strategy", "auto")),
            status_list_base_url=ic.get("status_list_base_url"),
            status_list_size=ic.get("status_list_size", 131072),
            update_mode=UpdateMode(ic.get("update_mode", "sync")),
            batch_interval_seconds=ic.get("batch_interval_seconds", 300),
            enable_rotation=ic.get("enable_rotation", True),
            rotation_threshold_percent=ic.get("rotation_threshold_percent", 80),
            enable_bitstring_status_list=ic.get("enable_bitstring_status_list", True),
            enable_token_status_list=ic.get("enable_token_status_list", True),
            enable_legacy_revocation_list=ic.get("enable_legacy_revocation_list", False),
        )
        verifier_config = VerifierRevocationConfig(
            check_mode=RevocationCheckMode(vc.get("check_mode", "HARD_FAIL")),
            timing_mode=RevocationTimingMode(vc.get("timing_mode", "ALWAYS")),
            mechanism_priority=[
                RevocationMechanism(m) for m in vc.get("mechanism_priority", ["BITSTRING_STATUS_LIST"])
            ],
            cache_status_lists=vc.get("cache_status_lists", True),
            cache_ttl_seconds=vc.get("cache_ttl_seconds", 3600),
            offline_grace_seconds=vc.get("offline_grace_seconds", 86400),
            check_timeout_seconds=vc.get("check_timeout_seconds", 5),
            max_retries=vc.get("max_retries", 2),
            require_issuer_signature_on_status_list=vc.get("require_issuer_signature_on_status_list", True),
            allow_third_party_registries=vc.get("allow_third_party_registries", False),
        )
        automation_config = RevocationAutomationConfig(
            auto_allocate_indices=ac.get("auto_allocate_indices", True),
            auto_publish=ac.get("auto_publish", True),
            auto_generate_status_list_credentials=ac.get("auto_generate_status_list_credentials", True),
            auto_discover_endpoints=ac.get("auto_discover_endpoints", True),
            use_format_defaults=ac.get("use_format_defaults", True),
        )

        profile = RevocationProfile.__new__(RevocationProfile)
        profile.id = row.id
        profile.organization_id = row.organization_id
        profile.name = row.name
        profile.description = None
        profile.status = RevocationProfileStatus(row.status)
        profile.issuer_config = issuer_config
        profile.verifier_config = verifier_config
        profile.automation_config = automation_config
        profile.supported_formats = [
            CredentialFormat(f) for f in (row.supported_formats or ["SD_JWT_VC", "MDOC", "VC_JWT"])
        ]
        profile.created_at = row.created_at if isinstance(row.created_at, datetime) else datetime.fromisoformat(str(row.created_at))
        profile.updated_at = row.updated_at if isinstance(row.updated_at, datetime) else datetime.fromisoformat(str(row.updated_at))
        return profile
