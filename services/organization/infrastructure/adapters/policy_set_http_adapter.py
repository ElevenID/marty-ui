"""PolicySet HTTP Adapter (FastAPI)

API endpoints for managing Cedar policy sets within an organization.
"""

from __future__ import annotations

import logging
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel

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
    status: str
    cedar_policies: str
    cedar_schema_version: str
    created_by: str | None = None
    created_at: str
    updated_at: str


class CreatePolicySetRequest(BaseModel):
    name: str
    cedar_policies: str
    policy_type: str = "CUSTOM"
    description: str | None = None


class UpdatePolicySetRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    cedar_policies: str | None = None


class ValidatePoliciesRequest(BaseModel):
    cedar_policies: str


class ValidatePoliciesResponse(BaseModel):
    valid: bool
    errors: list[str]


# =============================================================================
# Helpers
# =============================================================================


def _policy_set_response(ps) -> PolicySetResponse:
    return PolicySetResponse(
        id=ps.id,
        organization_id=ps.organization_id,
        name=ps.name,
        description=ps.description,
        policy_type=ps.policy_type.value if hasattr(ps.policy_type, "value") else ps.policy_type,
        status=ps.status.value if hasattr(ps.status, "value") else ps.status,
        cedar_policies=ps.cedar_policies,
        cedar_schema_version=ps.cedar_schema_version,
        created_by=ps.created_by,
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


@router.get("/policy-sets", response_model=list[PolicySetResponse])
async def list_policy_sets(
    organization_id: str,
    status: Optional[str] = Query(None, description="Filter by status (active/archived)"),
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """List all policy sets for this organization."""
    uc = _get_use_case()
    policy_sets = await uc.list_for_org(organization_id, status=status)
    return [_policy_set_response(ps) for ps in policy_sets]


@router.post("/policy-sets", response_model=PolicySetResponse, status_code=201)
async def create_policy_set(
    organization_id: str,
    body: CreatePolicySetRequest,
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """Create a new Cedar policy set."""
    uc = _get_use_case()

    # Validate the Cedar policies first
    errors = uc.validate_policies(body.cedar_policies)
    if errors:
        raise HTTPException(
            status_code=422,
            detail={"message": "Invalid Cedar policies", "errors": errors},
        )

    ps = await uc.create(
        organization_id=organization_id,
        name=body.name,
        cedar_policies=body.cedar_policies,
        policy_type=body.policy_type,
        description=body.description,
        created_by=org_ctx.user_id,
    )
    return _policy_set_response(ps)


@router.get("/policy-sets/{policy_set_id}", response_model=PolicySetResponse)
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


@router.patch("/policy-sets/{policy_set_id}", response_model=PolicySetResponse)
async def update_policy_set(
    organization_id: str,
    policy_set_id: str,
    body: UpdatePolicySetRequest,
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """Update a policy set's name, description, or policies."""
    uc = _get_use_case()

    if body.cedar_policies is not None:
        errors = uc.validate_policies(body.cedar_policies)
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
        cedar_policies=body.cedar_policies,
    )
    if not ps:
        raise HTTPException(status_code=404, detail="Policy set not found")
    return _policy_set_response(ps)


@router.post("/policy-sets/{policy_set_id}/archive", response_model=PolicySetResponse)
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


@router.post("/policy-sets/{policy_set_id}/activate", response_model=PolicySetResponse)
async def activate_policy_set(
    organization_id: str,
    policy_set_id: str,
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """Activate an archived policy set."""
    uc = _get_use_case()
    ps = await uc.activate(policy_set_id, organization_id)
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


@router.post("/policy-sets/validate", response_model=ValidatePoliciesResponse)
async def validate_policies(
    organization_id: str,
    body: ValidatePoliciesRequest,
    org_ctx: OrganizationContext = Depends(require_org_membership),
):
    """Validate Cedar policy text against the MIP schema without saving."""
    uc = _get_use_case()
    errors = uc.validate_policies(body.cedar_policies)
    return ValidatePoliciesResponse(valid=len(errors) == 0, errors=errors)
