"""Tests for the Presentation Policy Service gRPC adapter."""

from __future__ import annotations

import json
from enum import Enum
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import grpc
import pytest

from presentation_policy.infrastructure.adapters.grpc_adapter import (
    PresentationPolicyServiceGrpc,
    _policy_to_pb,
)
from marty_proto.v1 import presentation_policy_service_pb2 as pp_pb2


def _make_policy_response(**overrides):
    """Create a fake domain-layer policy object.

    The gRPC adapter now reads protocol fields from the REST response and
    legacy fields (status, display_metadata, credential_requirements, etc.)
    directly from the domain model. Since the test's ``_to_response_fn`` is
    a passthrough, the same object must satisfy both access patterns.
    """
    status_enum = SimpleNamespace(value=overrides.pop("status", "active"))
    display_metadata = SimpleNamespace(
        title="Employee Check",
        description="Check employee credentials",
        purpose=SimpleNamespace(value="identity_verification"),
        purpose_description="Verify employee identity",
        verifier_name="Acme Corp",
        verifier_logo_url=None,
        privacy_policy_url=None,
        terms_of_service_url=None,
    )

    cred_claim = SimpleNamespace(
        id="rc-1", claim_name="employee_id", display_name="Employee ID",
        required=True, selective_disclosure=True, predicate_spec=None,
    )
    cred_req = SimpleNamespace(
        id="cr-1", credential_template_id="EmployeeCredential",
        display_name="Employee Credential", required=True,
        credential_payload_format="w3c_vcdm_v2_sd_jwt",
        requested_claims=[cred_claim],
        trust_profile_id=None, max_age_seconds=None,
    )

    defaults = dict(
        id="pol-1",
        organization_id="org-1",
        name="Employee Verification",
        description="Verify employee credentials",
        status=status_enum,
        display_metadata=display_metadata,
        credential_requirements=[cred_req],
        alternative_requirements=[],
        compliance_profile_id="cp-1",
        version=1,
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-02T00:00:00Z",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _to_response_fn(policy):
    """Fake converter — returns the policy itself."""
    return policy


def _build_servicer(**overrides) -> PresentationPolicyServiceGrpc:
    defaults = dict(
        repo=MagicMock(),
        evaluate_fn=AsyncMock(),
        to_response_fn=_to_response_fn,
    )
    defaults.update(overrides)
    return PresentationPolicyServiceGrpc(**defaults)


# ── GetPolicy ────────────────────────────────────────────────────────


class TestGetPolicy:
    async def test_found(self, ctx):
        policy = _make_policy_response()
        repo = MagicMock()
        repo.get = AsyncMock(return_value=policy)
        servicer = _build_servicer(repo=repo)

        req = pp_pb2.GetPolicyRequest(policy_id="pol-1")
        resp = await servicer.GetPolicy(req, ctx)

        assert resp.id == "pol-1"
        assert resp.name == "Employee Verification"
        assert resp.compliance_profile_id == "cp-1"
        display = json.loads(resp.display_metadata_json)
        assert display["title"] == "Employee Check"
        reqs = json.loads(resp.credential_requirements_json)
        assert reqs[0]["credential_template_id"] == "EmployeeCredential"
        assert ctx.code is None

    async def test_not_found(self, ctx):
        repo = MagicMock()
        repo.get = AsyncMock(return_value=None)
        servicer = _build_servicer(repo=repo)

        req = pp_pb2.GetPolicyRequest(policy_id="missing")
        resp = await servicer.GetPolicy(req, ctx)

        assert ctx.code == grpc.StatusCode.NOT_FOUND
        assert "missing" in ctx.details


# ── ListPolicies ─────────────────────────────────────────────────────


class TestListPolicies:
    async def test_returns_policies(self, ctx):
        policies = [
            _make_policy_response(id="pol-1", name="Policy A"),
            _make_policy_response(id="pol-2", name="Policy B"),
        ]
        repo = MagicMock()
        repo.list = AsyncMock(return_value=policies)
        servicer = _build_servicer(repo=repo)

        req = pp_pb2.ListPoliciesRequest(organization_id="org-1")
        resp = await servicer.ListPolicies(req, ctx)

        assert resp.total == 2
        assert resp.policies[0].id == "pol-1"
        assert resp.policies[1].name == "Policy B"

    async def test_empty_org(self, ctx):
        repo = MagicMock()
        repo.list = AsyncMock(return_value=[])
        servicer = _build_servicer(repo=repo)

        req = pp_pb2.ListPoliciesRequest(organization_id="org-empty")
        resp = await servicer.ListPolicies(req, ctx)

        assert resp.total == 0


# ── EvaluatePresentation ─────────────────────────────────────────────


class _PolicyStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class TestEvaluatePresentation:
    async def test_successful_evaluation(self, ctx):
        policy = SimpleNamespace(
            id="pol-1",
            status=_PolicyStatus.ACTIVE,
        )
        eval_result = SimpleNamespace(
            result="pass",
            policy_id="pol-1",
            policy_name="Employee Verification",
            credential_results=[],
            total_requirements=1,
            satisfied_requirements=1,
            required_satisfied=1,
            required_total=1,
            decision="allow",
            decision_reason="All requirements met",
            verified_claims={"email": "alice@example.com"},
            evaluation_timestamp="2026-03-14T12:00:00Z",
            nonce="nonce-abc",
        )
        repo = MagicMock()
        repo.get = AsyncMock(return_value=policy)
        evaluate_fn = AsyncMock(return_value=eval_result)
        servicer = _build_servicer(repo=repo, evaluate_fn=evaluate_fn)

        req = pp_pb2.EvaluatePresentationRequest(
            policy_id="pol-1",
            vp_token="eyJ...",
            nonce="nonce-abc",
        )

        with patch("presentation_policy.infrastructure.adapters.grpc_adapter.PolicyStatus", _PolicyStatus, create=True), \
             patch("presentation_policy.main.EvaluatePresentationRequest") as MockEvalReq, \
             patch("presentation_policy.main.PolicyStatus", _PolicyStatus):
            MockEvalReq.side_effect = lambda **kwargs: SimpleNamespace(**kwargs)
            resp = await servicer.EvaluatePresentation(req, ctx)

        assert resp.decision == "allow"
        assert resp.satisfied_requirements == 1
        claims = json.loads(resp.verified_claims_json)
        assert claims["email"] == "alice@example.com"
        assert ctx.code is None

    async def test_policy_not_found(self, ctx):
        repo = MagicMock()
        repo.get = AsyncMock(return_value=None)
        servicer = _build_servicer(repo=repo)

        req = pp_pb2.EvaluatePresentationRequest(
            policy_id="missing",
            vp_token="eyJ...",
        )
        resp = await servicer.EvaluatePresentation(req, ctx)

        assert ctx.code == grpc.StatusCode.NOT_FOUND

    async def test_inactive_policy(self, ctx):
        policy = SimpleNamespace(
            id="pol-2",
            status=_PolicyStatus.INACTIVE,
        )
        repo = MagicMock()
        repo.get = AsyncMock(return_value=policy)
        servicer = _build_servicer(repo=repo)

        req = pp_pb2.EvaluatePresentationRequest(
            policy_id="pol-2",
            vp_token="eyJ...",
        )
        with patch("presentation_policy.main.PolicyStatus", _PolicyStatus):
            resp = await servicer.EvaluatePresentation(req, ctx)

        assert ctx.code == grpc.StatusCode.FAILED_PRECONDITION
        assert "not active" in ctx.details

    async def test_evaluation_error(self, ctx):
        policy = SimpleNamespace(
            id="pol-3",
            status=_PolicyStatus.ACTIVE,
        )
        repo = MagicMock()
        repo.get = AsyncMock(return_value=policy)
        evaluate_fn = AsyncMock(side_effect=RuntimeError("verification engine failed"))
        servicer = _build_servicer(repo=repo, evaluate_fn=evaluate_fn)

        req = pp_pb2.EvaluatePresentationRequest(
            policy_id="pol-3",
            vp_token="eyJ...",
        )
        with patch("presentation_policy.main.EvaluatePresentationRequest") as MockEvalReq, \
             patch("presentation_policy.main.PolicyStatus", _PolicyStatus):
            MockEvalReq.side_effect = lambda **kwargs: SimpleNamespace(**kwargs)
            resp = await servicer.EvaluatePresentation(req, ctx)

        assert ctx.code == grpc.StatusCode.INTERNAL
        assert "verification engine failed" in ctx.details


# ── HealthCheck ──────────────────────────────────────────────────────


class TestHealthCheck:
    async def test_returns_serving(self, ctx):
        servicer = _build_servicer()
        req = pp_pb2.HealthCheckRequest()
        resp = await servicer.HealthCheck(req, ctx)
        assert resp.status == "serving"
