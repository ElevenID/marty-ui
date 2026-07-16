"""
RevocationProfile Service gRPC Adapter (Inbound)

Implements the RevocationProfileService gRPC servicer, delegating to the
same repository and StatusListManager that back the REST endpoints.
"""

from __future__ import annotations

import logging
from typing import Any

import grpc

from marty_proto.v1 import (
    revocation_profile_service_pb2 as rp_pb2,
    revocation_profile_service_pb2_grpc,
)

logger = logging.getLogger(__name__)


def _issuer_config_to_pb(cfg: Any) -> rp_pb2.IssuerRevocationConfig:
    return rp_pb2.IssuerRevocationConfig(
        status_list_strategy=cfg.status_list_strategy.value if hasattr(cfg.status_list_strategy, "value") else str(cfg.status_list_strategy),
        status_list_base_url=cfg.status_list_base_url or "",
        status_list_size=cfg.status_list_size,
        update_mode=cfg.update_mode.value if hasattr(cfg.update_mode, "value") else str(cfg.update_mode),
        batch_interval_seconds=cfg.batch_interval_seconds,
        enable_rotation=cfg.enable_rotation,
        rotation_threshold_percent=cfg.rotation_threshold_percent,
        enable_bitstring_status_list=cfg.enable_bitstring_status_list,
        enable_token_status_list=cfg.enable_token_status_list,
        enable_legacy_revocation_list=cfg.enable_legacy_revocation_list,
    )


def _verifier_config_to_pb(cfg: Any) -> rp_pb2.VerifierRevocationConfig:
    return rp_pb2.VerifierRevocationConfig(
        check_mode=cfg.check_mode.value if hasattr(cfg.check_mode, "value") else str(cfg.check_mode),
        timing_mode=cfg.timing_mode.value if hasattr(cfg.timing_mode, "value") else str(cfg.timing_mode),
        mechanism_priority=[m.value if hasattr(m, "value") else str(m) for m in cfg.mechanism_priority],
        cache_status_lists=cfg.cache_status_lists,
        cache_ttl_seconds=cfg.cache_ttl_seconds,
        offline_grace_seconds=cfg.offline_grace_seconds,
        check_timeout_seconds=cfg.check_timeout_seconds,
        max_retries=cfg.max_retries,
        require_issuer_signature_on_status_list=cfg.require_issuer_signature_on_status_list,
        allow_third_party_registries=cfg.allow_third_party_registries,
    )


def _automation_config_to_pb(cfg: Any) -> rp_pb2.RevocationAutomationConfig:
    return rp_pb2.RevocationAutomationConfig(
        auto_allocate_indices=cfg.auto_allocate_indices,
        auto_publish=cfg.auto_publish,
        auto_generate_status_list_credentials=cfg.auto_generate_status_list_credentials,
        auto_discover_endpoints=cfg.auto_discover_endpoints,
        use_format_defaults=cfg.use_format_defaults,
    )


def _profile_to_pb(profile: Any) -> rp_pb2.RevocationProfileResponse:
    """Map domain RevocationProfile → protobuf RevocationProfileResponse."""
    return rp_pb2.RevocationProfileResponse(
        id=profile.id,
        organization_id=profile.organization_id,
        name=profile.name,
        description=profile.description or "",
        status=profile.status.value,
        issuer_config=_issuer_config_to_pb(profile.issuer_config),
        verifier_config=_verifier_config_to_pb(profile.verifier_config),
        automation_config=_automation_config_to_pb(profile.automation_config),
        supported_formats=[f.value for f in profile.supported_formats],
        created_at=profile.created_at.isoformat(),
        updated_at=profile.updated_at.isoformat(),
    )


class RevocationProfileServiceGrpc(
    revocation_profile_service_pb2_grpc.RevocationProfileServiceServicer,
):
    """gRPC inbound adapter for the revocation-profile service."""

    def __init__(self, repo: Any, status_list_manager: Any) -> None:
        self._repo = repo
        self._status_mgr = status_list_manager

    # ------------------------------------------------------------------
    # Public API — Queries
    # ------------------------------------------------------------------

    async def GetRevocationProfile(self, request, context):
        profile = await self._repo.get(request.profile_id)
        if not profile:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"RevocationProfile {request.profile_id} not found")
            return rp_pb2.RevocationProfileResponse()
        return _profile_to_pb(profile)

    async def ListRevocationProfiles(self, request, context):
        profiles = await self._repo.list(request.organization_id)
        return rp_pb2.ListRevocationProfilesResponse(
            profiles=[_profile_to_pb(p) for p in profiles],
        )

    # ------------------------------------------------------------------
    # Public API — Commands
    # ------------------------------------------------------------------

    async def CreateRevocationProfile(self, request, context):
        from revocation_profile.main import (
            CredentialFormat,
            IssuerRevocationConfig,
            RevocationAutomationConfig,
            RevocationProfile,
            StatusListStrategy,
            UpdateMode,
            RevocationCheckMode,
            RevocationTimingMode,
            RevocationMechanism,
            VerifierRevocationConfig,
        )

        profile = RevocationProfile(
            organization_id=request.organization_id,
            name=request.name,
            description=request.description or None,
        )

        if request.HasField("issuer_config"):
            ic = request.issuer_config
            profile.issuer_config = IssuerRevocationConfig(
                status_list_strategy=StatusListStrategy(ic.status_list_strategy) if ic.status_list_strategy else StatusListStrategy.AUTO,
                status_list_base_url=ic.status_list_base_url or None,
                status_list_size=ic.status_list_size or 131072,
                update_mode=UpdateMode(ic.update_mode) if ic.update_mode else UpdateMode.SYNC,
                batch_interval_seconds=ic.batch_interval_seconds or 300,
                enable_rotation=ic.enable_rotation,
                rotation_threshold_percent=ic.rotation_threshold_percent or 80,
                enable_bitstring_status_list=ic.enable_bitstring_status_list,
                enable_token_status_list=ic.enable_token_status_list,
                enable_legacy_revocation_list=ic.enable_legacy_revocation_list,
            )

        if request.HasField("verifier_config"):
            vc = request.verifier_config
            profile.verifier_config = VerifierRevocationConfig(
                check_mode=RevocationCheckMode(vc.check_mode) if vc.check_mode else RevocationCheckMode.HARD_FAIL,
                timing_mode=RevocationTimingMode(vc.timing_mode) if vc.timing_mode else RevocationTimingMode.ALWAYS,
                mechanism_priority=[RevocationMechanism(m) for m in vc.mechanism_priority] if vc.mechanism_priority else [RevocationMechanism.BITSTRING_STATUS_LIST],
                cache_status_lists=vc.cache_status_lists,
                cache_ttl_seconds=vc.cache_ttl_seconds or 3600,
                offline_grace_seconds=vc.offline_grace_seconds or 86400,
                check_timeout_seconds=vc.check_timeout_seconds or 5,
                max_retries=vc.max_retries or 2,
                require_issuer_signature_on_status_list=vc.require_issuer_signature_on_status_list,
                allow_third_party_registries=vc.allow_third_party_registries,
            )

        if request.HasField("automation_config"):
            ac = request.automation_config
            profile.automation_config = RevocationAutomationConfig(
                auto_allocate_indices=ac.auto_allocate_indices,
                auto_publish=ac.auto_publish,
                auto_generate_status_list_credentials=ac.auto_generate_status_list_credentials,
                auto_discover_endpoints=ac.auto_discover_endpoints,
                use_format_defaults=ac.use_format_defaults,
            )

        if request.supported_formats:
            profile.supported_formats = [CredentialFormat(f) for f in request.supported_formats]

        await self._repo.save(profile)
        logger.info("gRPC CreateRevocationProfile: %s", profile.id)
        return _profile_to_pb(profile)

    async def ActivateRevocationProfile(self, request, context):
        profile = await self._repo.get(request.profile_id)
        if not profile:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"RevocationProfile {request.profile_id} not found")
            return rp_pb2.RevocationProfileResponse()

        profile.activate()
        await self._repo.save(profile)
        logger.info("gRPC ActivateRevocationProfile: %s", request.profile_id)
        return _profile_to_pb(profile)

    async def DeleteRevocationProfile(self, request, context):
        profile = await self._repo.get(request.profile_id)
        if not profile:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"RevocationProfile {request.profile_id} not found")
            return rp_pb2.DeleteRevocationProfileResponse(success=False)

        await self._repo.delete(request.profile_id)
        logger.info("gRPC DeleteRevocationProfile: %s", request.profile_id)
        return rp_pb2.DeleteRevocationProfileResponse(success=True)

    # ------------------------------------------------------------------
    # Internal API — Service-to-Service
    # ------------------------------------------------------------------

    async def ProcessRevocation(self, request, context):
        from revocation_profile.main import RevocationProfileStatus
        from revocation_profile.status_list_manager import StatusListFormat
        from revocation_profile.main import _build_status_list_url, _status_list_purpose_for_status, _status_list_scope

        profile = await self._repo.get(request.profile_id)
        if not profile:
            return rp_pb2.ProcessRevocationResponse(
                success=False,
                error=f"RevocationProfile {request.profile_id} not found",
            )

        if profile.organization_id != request.organization_id:
            context.set_code(grpc.StatusCode.PERMISSION_DENIED)
            context.set_details("Revocation Profile belongs to another organization")
            return rp_pb2.ProcessRevocationResponse(
                success=False,
                error="Revocation Profile belongs to another organization",
            )

        if profile.status != RevocationProfileStatus.ACTIVE:
            return rp_pb2.ProcessRevocationResponse(
                success=False,
                error=f"RevocationProfile {request.profile_id} is not active (status: {profile.status.value})",
            )

        try:
            # Map credential format to status list format
            if request.credential_format.lower() == "mdoc":
                sl_format = StatusListFormat.TOKEN_STATUS_LIST
            else:
                sl_format = StatusListFormat.BITSTRING

            # Map status string to integer value
            if request.status == "revoked":
                status_value = 1
            elif request.status == "suspended":
                status_value = 2 if sl_format == StatusListFormat.TOKEN_STATUS_LIST else 1
            elif request.status == "reinstated":
                status_value = 0
            else:
                return rp_pb2.ProcessRevocationResponse(
                    success=False,
                    error=f"Unknown status: {request.status}",
                )

            success = await self._status_mgr.set_status(
                tenant_id=_status_list_scope(profile),
                index=request.index,
                status=status_value,
                format=sl_format,
            )

            if not success:
                return rp_pb2.ProcessRevocationResponse(
                    success=False,
                    error="Failed to update status list",
                )

            purpose = _status_list_purpose_for_status(request.status)
            status_list_url = _build_status_list_url(profile, sl_format, purpose)

            # Publish if auto-publish enabled
            if profile.automation_config.auto_publish:
                await self._status_mgr.publish(
                    tenant_id=_status_list_scope(profile),
                    format=sl_format,
                )

            logger.info(
                "gRPC ProcessRevocation: org=%s index=%d status=%d format=%s",
                profile.organization_id, request.index, status_value, sl_format.value,
            )

            return rp_pb2.ProcessRevocationResponse(
                success=True,
                status_list_url=status_list_url,
                index=request.index,
                organization_id=profile.organization_id,
            )

        except Exception as e:
            logger.error("gRPC ProcessRevocation error: %s", e, exc_info=True)
            return rp_pb2.ProcessRevocationResponse(
                success=False,
                error=str(e),
            )

    async def AllocateIndex(self, request, context):
        from revocation_profile.status_list_manager import StatusListFormat
        from revocation_profile.main import _build_status_list_url, _status_list_scope

        profile = await self._repo.get(request.profile_id)
        if not profile:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"RevocationProfile {request.profile_id} not found")
            return rp_pb2.AllocateIndexResponse()

        if profile.organization_id != request.organization_id:
            context.set_code(grpc.StatusCode.PERMISSION_DENIED)
            context.set_details("Revocation Profile belongs to another organization")
            return rp_pb2.AllocateIndexResponse()

        if not profile.automation_config.auto_allocate_indices:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details("Auto-allocation not enabled for this profile")
            return rp_pb2.AllocateIndexResponse()

        try:
            # Map credential format to status list format
            if request.credential_format.lower() == "mdoc":
                sl_format = StatusListFormat.TOKEN_STATUS_LIST
            else:
                sl_format = StatusListFormat.BITSTRING

            index = await self._status_mgr.allocate_index(
                tenant_id=_status_list_scope(profile),
                format=sl_format,
            )

            # Generate canonical status list URL
            status_list_url = _build_status_list_url(
                profile,
                sl_format,
                purpose="revocation",
            )

            if profile.automation_config.auto_publish:
                await self._status_mgr.get_or_create(
                    tenant_id=_status_list_scope(profile),
                    format=sl_format,
                )

            logger.info(
                "gRPC AllocateIndex: profile=%s format=%s index=%d",
                request.profile_id, request.credential_format, index,
            )

            return rp_pb2.AllocateIndexResponse(
                index=index,
                status_list_url=status_list_url,
                organization_id=profile.organization_id,
            )

        except Exception as e:
            logger.error("gRPC AllocateIndex error: %s", e, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return rp_pb2.AllocateIndexResponse()

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def HealthCheck(self, request, context):
        return rp_pb2.HealthCheckResponse(
            status="healthy",
            service="revocation-profile-service",
        )
