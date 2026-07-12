"""PolicySet HTTP Adapter (FastAPI)

API endpoints for managing Cedar policy sets within an organization.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from marty_common import OrganizationContext, require_org_membership

from ...application.policy_set_use_cases import PolicySetUseCase

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/v1/organizations/{organization_id}",
    tags=["policy-sets"],
)


# =============================================================================
# Request / Response Models
# =============================================================================


class PolicySetResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None = None
    policy_type: str
    cedar_policies: list[dict[str, Any]] = Field(default_factory=list)
    cedar_schema_version: str
    status: str
    created_at: str
    updated_at: str


class CedarPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", max_length=128)
    effect: Literal["permit", "forbid"]
    cedar_text: str = Field(min_length=10)
    description: str | None = Field(None, max_length=512)
    enabled: bool = True


class CreatePolicySetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    cedar_policies: list[CedarPolicyRequest] = Field(min_length=1)
    policy_type: Literal["ACCESS_CONTROL", "CREDENTIAL_VERIFICATION", "APPROVAL_RULES", "CUSTOM"] = "CUSTOM"
    description: str | None = Field(None, max_length=1024)


class UpdatePolicySetRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    description: str | None = Field(None, max_length=1024)
    cedar_policies: list[CedarPolicyRequest] | None = None


class ValidatePoliciesRequest(BaseModel):
    cedar_policies: list[CedarPolicyRequest] = Field(min_length=1)


class ValidatePoliciesResponse(BaseModel):
    valid: bool
    errors: list[str]


POLICY_SET_TEMPLATES: list[dict[str, Any]] = [
    {
        "template_id": "approval_verified_evidence",
        "name": "Verified evidence approval",
        "description": "Approve when every required evidence check is satisfied.",
        "policy_type": "APPROVAL_RULES",
        "cedar_policies": [{
            "policy_id": "approve_verified_evidence",
            "effect": "permit",
            "description": "Permit approval after all evidence requirements pass.",
            "enabled": True,
            "cedar_text": '''@id("approve_verified_evidence")
permit (
    principal,
    action == MIP::Action::"applications:approve",
    resource
)
when {
    context.all_required_evidence_satisfied
};''',
        }],
    },
    {
        "template_id": "verification_valid_credential",
        "name": "Valid credential verification",
        "description": "Accept current, non-revoked credentials from trusted issuers.",
        "policy_type": "CREDENTIAL_VERIFICATION",
        "cedar_policies": [{
            "policy_id": "permit_valid_credential",
            "effect": "permit",
            "description": "Permit a valid credential with baseline issuer trust.",
            "enabled": True,
            "cedar_text": '''@id("permit_valid_credential")
permit (
    principal,
    action == MIP::Action::"credentials:verify",
    resource
)
when {
    !context.is_revoked &&
    !context.is_expired &&
    context.issuer_trust_level >= 50
};''',
        }],
    },
    {
        "template_id": "access_read_only",
        "name": "Read-only access",
        "description": "Permit read actions for organization viewers.",
        "policy_type": "ACCESS_CONTROL",
        "cedar_policies": [{
            "policy_id": "viewer_read_access",
            "effect": "permit",
            "description": "Permit read access for viewers.",
            "enabled": True,
            "cedar_text": '''@id("viewer_read_access")
permit (
    principal is MIP::User,
    action in [
        MIP::Action::"credentials:read",
        MIP::Action::"flows:read",
        MIP::Action::"applications:read"
    ],
    resource
)
when {
    principal in MIP::Role::"viewer"
};''',
        }],
    },
]


# =============================================================================
# Helpers
# =============================================================================


def _policy_set_response(ps) -> PolicySetResponse:
    policies = PolicySetUseCase.deserialize_policies(ps.cedar_policies)
    return PolicySetResponse(
        id=ps.id,
        organization_id=ps.organization_id,
        name=ps.name,
        description=ps.description,
        policy_type=ps.policy_type.value if hasattr(ps.policy_type, "value") else ps.policy_type,
        cedar_policies=policies,
        cedar_schema_version=ps.cedar_schema_version,
        status=ps.status.value if hasattr(ps.status, "value") else ps.status,
        created_at=ps.created_at.isoformat(),
        updated_at=ps.updated_at.isoformat(),
    )


# =============================================================================
# Endpoints
# =============================================================================


_use_case_holder: dict[str, PolicySetUseCase] = {}


def configure(use_case: PolicySetUseCase):
    """Wire the use case into this router (called during app startup)."""
    _use_case_holder["uc"] = use_case


def _get_use_case() -> PolicySetUseCase:
    uc = _use_case_holder.get("uc")
    if not uc:
        raise HTTPException(status_code=500, detail="PolicySet service not configured")
    return uc


@router.get("/policy-sets", response_model=list[PolicySetResponse], response_model_exclude_none=True)
async def list_policy_sets(
    organization_id: str,
    status: Optional[str] = Query(None, description="Filter by status (active/archived)"),
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """List all policy sets for this organization."""
    uc = _get_use_case()
    policy_sets = await uc.list_for_org(organization_id, status=status)
    return [_policy_set_response(ps) for ps in policy_sets]


@router.post("/policy-sets", response_model=PolicySetResponse, response_model_exclude_none=True, status_code=201)
async def create_policy_set(
    organization_id: str,
    body: CreatePolicySetRequest,
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """Create a new Cedar policy set."""
    uc = _get_use_case()

    # Validate the Cedar policies first
    policies = [policy.model_dump() for policy in body.cedar_policies]
    errors = uc.validate_policies(policies)
    if errors:
        raise HTTPException(
            status_code=422,
            detail={"message": "Invalid Cedar policies", "errors": errors},
        )

    ps = await uc.create(
        organization_id=organization_id,
        name=body.name,
        cedar_policies=policies,
        policy_type=body.policy_type,
        description=body.description,
        created_by=org_ctx.user_id,
    )
    return _policy_set_response(ps)


@router.get("/policy-sets/templates")
async def list_policy_set_templates(
    organization_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
) -> list[dict[str, Any]]:
    """Return guided starter policies for common MIP decisions."""
    return POLICY_SET_TEMPLATES


@router.get("/policy-sets/{policy_set_id}", response_model=PolicySetResponse, response_model_exclude_none=True)
async def get_policy_set(
    organization_id: str,
    policy_set_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """Get a specific policy set."""
    uc = _get_use_case()
    ps = await uc.get(policy_set_id, organization_id)
    if not ps:
        raise HTTPException(status_code=404, detail="Policy set not found")
    return _policy_set_response(ps)


@router.patch("/policy-sets/{policy_set_id}", response_model=PolicySetResponse, response_model_exclude_none=True)
async def update_policy_set(
    organization_id: str,
    policy_set_id: str,
    body: UpdatePolicySetRequest,
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """Update a policy set's name, description, or policies."""
    uc = _get_use_case()

    if body.cedar_policies is not None:
        policies = [policy.model_dump() for policy in body.cedar_policies]
        errors = uc.validate_policies(policies)
        if errors:
            raise HTTPException(
                status_code=422,
                detail={"message": "Invalid Cedar policies", "errors": errors},
            )

    ps = await uc.update(
        policy_set_id=policy_set_id,
        organization_id=organization_id,
        name=body.name,
        description=body.description,
        cedar_policies=(
            [policy.model_dump() for policy in body.cedar_policies]
            if body.cedar_policies is not None
            else None
        ),
    )
    if not ps:
        raise HTTPException(status_code=404, detail="Policy set not found")
    return _policy_set_response(ps)


@router.post("/policy-sets/{policy_set_id}/archive", response_model=PolicySetResponse, response_model_exclude_none=True)
async def archive_policy_set(
    organization_id: str,
    policy_set_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """Archive a policy set (soft delete)."""
    uc = _get_use_case()
    ps = await uc.archive(policy_set_id, organization_id)
    if not ps:
        raise HTTPException(status_code=404, detail="Policy set not found")
    return _policy_set_response(ps)


@router.post("/policy-sets/{policy_set_id}/activate", response_model=PolicySetResponse, response_model_exclude_none=True)
async def activate_policy_set(
    organization_id: str,
    policy_set_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """Activate an archived policy set."""
    uc = _get_use_case()
    try:
        ps = await uc.activate(policy_set_id, organization_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not ps:
        raise HTTPException(status_code=404, detail="Policy set not found")
    return _policy_set_response(ps)


@router.delete("/policy-sets/{policy_set_id}", status_code=204)
async def delete_policy_set(
    organization_id: str,
    policy_set_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """Permanently delete a policy set."""
    uc = _get_use_case()
    deleted = await uc.delete(policy_set_id, organization_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Policy set not found")


@router.post("/policy-sets/validate", response_model=ValidatePoliciesResponse, response_model_exclude_none=True)
async def validate_policies(
    organization_id: str,
    body: ValidatePoliciesRequest,
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """Validate Cedar policy text against the MIP schema without saving."""
    uc = _get_use_case()
    errors = uc.validate_policies([policy.model_dump() for policy in body.cedar_policies])
    return ValidatePoliciesResponse(valid=len(errors) == 0, errors=errors)
