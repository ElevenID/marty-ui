"""
Presentation Policy Service gRPC Adapter (Inbound)

Implements the PresentationPolicyService gRPC servicer, delegating to the
same repository and evaluation logic that backs the REST endpoints.
Runs alongside the existing FastAPI application.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import grpc
from fastapi import HTTPException

from marty_proto.v1 import (
    presentation_policy_service_pb2,
    presentation_policy_service_pb2_grpc,
)

logger = logging.getLogger(__name__)


def _policy_to_pb(
    policy: Any,
    to_response_fn: Any,
) -> presentation_policy_service_pb2.PolicyResponse:
    """Map domain PresentationPolicy → protobuf PolicyResponse.

    Reads protocol fields from the REST response and legacy internal fields
    (status, display_metadata, credential_requirements, etc.) directly from
    the domain model so the proto retains full fidelity for internal callers.
    """
    resp = to_response_fn(policy)

    # Legacy fields read from the domain model (not in the protocol response)
    display_metadata = {
        "title": policy.display_metadata.title,
        "description": policy.display_metadata.description,
        "purpose": policy.display_metadata.purpose.value,
        "purpose_description": policy.display_metadata.purpose_description,
        "verifier_name": policy.display_metadata.verifier_name,
        "verifier_logo_url": policy.display_metadata.verifier_logo_url,
        "privacy_policy_url": policy.display_metadata.privacy_policy_url,
        "terms_of_service_url": policy.display_metadata.terms_of_service_url,
    }
    credential_requirements = [
        {
            "id": req.id,
            "credential_template_id": req.credential_template_id,
            "display_name": req.display_name,
            "required": req.required,
            "credential_payload_format": req.credential_payload_format,
            "requested_claims": [
                {
                    "id": rc.id,
                    "claim_name": rc.claim_name,
                    "display_name": rc.display_name,
                    "required": rc.required,
                    "selective_disclosure": rc.selective_disclosure,
                    "predicate_spec": rc.predicate_spec,
                }
                for rc in req.requested_claims
            ],
            "trust_profile_id": req.trust_profile_id,
            "max_age_seconds": req.max_age_seconds,
        }
        for req in policy.credential_requirements
    ]
    alternative_requirements = [
        {
            "id": alt.id,
            "name": alt.name,
            "min_satisfied": alt.min_satisfied,
            "credential_requirements": [
                {
                    "id": r.id,
                    "credential_template_id": r.credential_template_id,
                    "display_name": r.display_name,
                }
                for r in alt.credential_requirements
            ],
        }
        for alt in policy.alternative_requirements
    ]

    return presentation_policy_service_pb2.PolicyResponse(
        id=resp.id,
        organization_id=resp.organization_id,
        name=resp.name,
        description=resp.description or "",
        status=policy.status.value,
        display_metadata_json=json.dumps(display_metadata),
        credential_requirements_json=json.dumps(credential_requirements),
        alternative_requirements_json=json.dumps(alternative_requirements),
        compliance_profile_id=policy.compliance_profile_id or "",
        version=policy.version,
        created_at=resp.created_at,
        updated_at=resp.updated_at or "",
    )


class PresentationPolicyServiceGrpc(
    presentation_policy_service_pb2_grpc.PresentationPolicyServiceServicer,
):
    """gRPC inbound adapter for the presentation-policy service."""

    def __init__(self, repo: Any, evaluate_fn: Any, to_response_fn: Any) -> None:
        """
        Parameters
        ----------
        repo:
            The Presentation Policy repository instance.
        evaluate_fn:
            ``evaluate_presentation`` coroutine (the REST handler).
        to_response_fn:
            ``_policy_to_response`` helper.
        """
        self._repo = repo
        self._evaluate_fn = evaluate_fn
        self._to_response_fn = to_response_fn

    # -- GetPolicy -----------------------------------------------------------

    async def GetPolicy(self, request, context):
        policy = await self._repo.get(request.policy_id)
        if not policy:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Policy {request.policy_id} not found")
            return presentation_policy_service_pb2.PolicyResponse()
        return _policy_to_pb(policy, self._to_response_fn)

    # -- ListPolicies --------------------------------------------------------

    async def ListPolicies(self, request, context):
        policies = await self._repo.list(request.organization_id)
        pb_policies = [_policy_to_pb(p, self._to_response_fn) for p in policies]
        return presentation_policy_service_pb2.ListPoliciesResponse(
            policies=pb_policies,
            total=len(pb_policies),
        )

    # -- EvaluatePresentation ------------------------------------------------

    async def EvaluatePresentation(self, request, context):
        policy = await self._repo.get(request.policy_id)
        if not policy:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Policy {request.policy_id} not found")
            return presentation_policy_service_pb2.PolicyEvaluationResponse()

        # Build a mock request object compatible with the REST evaluate handler
        from presentation_policy.main import (
            EvaluatePresentationRequest as EvalReq,
            PolicyStatus,
        )

        if policy.status != PolicyStatus.ACTIVE:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details(f"Policy is not active (status: {policy.status.value})")
            return presentation_policy_service_pb2.PolicyEvaluationResponse()

        eval_req = EvalReq(
            vp_token=request.vp_token,
            nonce=request.nonce or None,
            audience=request.audience or None,
            trust_profile_id=request.trust_profile_id or None,
            context=json.loads(request.context_json) if request.context_json else {},
        )

        try:
            result = await self._evaluate_fn(
                policy_id=request.policy_id,
                request=eval_req,
                http_request=None,
                repo=self._repo,
            )
        except HTTPException as exc:
            status_mapping = {
                400: grpc.StatusCode.INVALID_ARGUMENT,
                401: grpc.StatusCode.UNAUTHENTICATED,
                403: grpc.StatusCode.PERMISSION_DENIED,
                404: grpc.StatusCode.NOT_FOUND,
                409: grpc.StatusCode.ABORTED,
                422: grpc.StatusCode.INVALID_ARGUMENT,
                503: grpc.StatusCode.UNAVAILABLE,
            }
            context.set_code(status_mapping.get(exc.status_code, grpc.StatusCode.INTERNAL))
            context.set_details(str(exc.detail))
            return presentation_policy_service_pb2.PolicyEvaluationResponse()
        except Exception as exc:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return presentation_policy_service_pb2.PolicyEvaluationResponse()

        return presentation_policy_service_pb2.PolicyEvaluationResponse(
            result=result.result,
            policy_id=result.policy_id,
            policy_name=result.policy_name,
            credential_results_json=json.dumps(
                [cr.model_dump() for cr in result.credential_results]
            ),
            total_requirements=result.total_requirements,
            satisfied_requirements=result.satisfied_requirements,
            required_satisfied=result.required_satisfied,
            required_total=result.required_total,
            decision=result.decision,
            decision_reason=result.decision_reason,
            verified_claims_json=json.dumps(result.verified_claims),
            evaluation_timestamp=result.evaluation_timestamp,
            nonce=result.nonce or "",
        )

    # -- HealthCheck ---------------------------------------------------------

    async def HealthCheck(self, request, context):
        return presentation_policy_service_pb2.HealthCheckResponse(status="serving")

    # -- CreatePolicy --------------------------------------------------------

    async def CreatePolicy(self, request, context):
        from datetime import datetime, timezone

        from presentation_policy.main import (
            AlternativeRequirement,
            DisplayMetadata,
            PresentationPolicy,
            RequestPurpose,
        )

        try:
            policy = PresentationPolicy(
                organization_id=request.organization_id,
                name=request.name,
                description=request.description or None,
                compliance_profile_id=request.compliance_profile_id or None,
                prefer_predicates=request.prefer_predicates,
                fallback_policy=request.fallback_policy or None,
            )

            if request.display_metadata_json:
                meta = json.loads(request.display_metadata_json)
                policy.display_metadata = DisplayMetadata(
                    title=meta.get("title", ""),
                    description=meta.get("description", ""),
                    purpose=RequestPurpose(meta.get("purpose", "authentication")),
                    purpose_description=meta.get("purpose_description", ""),
                    verifier_name=meta.get("verifier_name", ""),
                    verifier_logo_url=meta.get("verifier_logo_url", ""),
                    privacy_policy_url=meta.get("privacy_policy_url", ""),
                    terms_of_service_url=meta.get("terms_of_service_url", ""),
                )

            # credential_requirements and alternative_requirements are complex;
            # callers pass JSON matching the REST API structure. We skip deep
            # rebuild here — callers can use the REST endpoint for full
            # requirement wiring. Basic name/description creation is sufficient
            # for service-to-service use.

            await self._repo.save(policy)
            logger.info("gRPC CreatePolicy: %s", policy.id)
            return _policy_to_pb(policy, self._to_response_fn)
        except Exception as exc:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return presentation_policy_service_pb2.PolicyResponse()

    # -- UpdatePolicy --------------------------------------------------------

    async def UpdatePolicy(self, request, context):
        from datetime import datetime, timezone

        policy = await self._repo.get(request.policy_id)
        if not policy:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Policy {request.policy_id} not found")
            return presentation_policy_service_pb2.PolicyResponse()

        from presentation_policy.main import PolicyStatus

        if policy.status != PolicyStatus.DRAFT:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details("Only draft policies can be modified")
            return presentation_policy_service_pb2.PolicyResponse()

        if request.name:
            policy.name = request.name
        if request.description:
            policy.description = request.description
        if request.compliance_profile_id:
            policy.compliance_profile_id = request.compliance_profile_id

        policy.updated_at = datetime.now(timezone.utc)
        await self._repo.save(policy)
        return _policy_to_pb(policy, self._to_response_fn)

    # -- ActivatePolicy ------------------------------------------------------

    async def ActivatePolicy(self, request, context):
        policy = await self._repo.get(request.policy_id)
        if not policy:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Policy {request.policy_id} not found")
            return presentation_policy_service_pb2.PolicyResponse()

        try:
            policy.activate()
        except Exception as exc:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details(str(exc))
            return presentation_policy_service_pb2.PolicyResponse()

        await self._repo.save(policy)
        return _policy_to_pb(policy, self._to_response_fn)

    # -- SuspendPolicy -------------------------------------------------------

    async def SuspendPolicy(self, request, context):
        policy = await self._repo.get(request.policy_id)
        if not policy:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Policy {request.policy_id} not found")
            return presentation_policy_service_pb2.PolicyResponse()

        try:
            policy.suspend()
        except Exception as exc:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details(str(exc))
            return presentation_policy_service_pb2.PolicyResponse()

        await self._repo.save(policy)
        return _policy_to_pb(policy, self._to_response_fn)

    # -- NewVersionPolicy ----------------------------------------------------

    async def NewVersionPolicy(self, request, context):
        policy = await self._repo.get(request.policy_id)
        if not policy:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Policy {request.policy_id} not found")
            return presentation_policy_service_pb2.PolicyResponse()

        from presentation_policy.main import PresentationPolicy

        new_policy = PresentationPolicy(
            organization_id=policy.organization_id,
            name=policy.name,
            description=policy.description,
            display_metadata=policy.display_metadata,
            credential_requirements=policy.credential_requirements.copy(),
            alternative_requirements=policy.alternative_requirements.copy(),
            compliance_profile_id=policy.compliance_profile_id,
            version=policy.version + 1,
        )
        await self._repo.save(new_policy)
        logger.info("gRPC NewVersionPolicy: %s → %s", policy.id, new_policy.id)
        return _policy_to_pb(new_policy, self._to_response_fn)

    # -- DeletePolicy --------------------------------------------------------

    async def DeletePolicy(self, request, context):
        policy = await self._repo.get(request.policy_id)
        if not policy:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Policy {request.policy_id} not found")
            return presentation_policy_service_pb2.DeletePolicyResponse(success=False)

        from presentation_policy.main import PolicyStatus

        if policy.status != PolicyStatus.DRAFT:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details("Only draft policies can be deleted")
            return presentation_policy_service_pb2.DeletePolicyResponse(success=False)

        await self._repo.delete(request.policy_id)
        return presentation_policy_service_pb2.DeletePolicyResponse(success=True)
