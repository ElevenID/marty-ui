"""Tests for the Credential Template Service gRPC adapter."""

from __future__ import annotations

import json
import sys
from enum import Enum
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import grpc
import pytest


# Pre-inject a lightweight stub for credential_template.main so the deferred
# import inside GetCredentialConfigurations doesn't pull in heavy deps.
class _TemplateStatus(str, Enum):
    ACTIVE = "active"
    DRAFT = "draft"


_ct_main_stub = SimpleNamespace(TemplateStatus=_TemplateStatus)
sys.modules.setdefault("credential_template.main", _ct_main_stub)

from credential_template.infrastructure.adapters.grpc_adapter import (
    CredentialTemplateServiceGrpc,
    _template_to_pb,
)
from marty_proto.v1 import credential_template_service_pb2 as ct_pb2


def _make_template_response(**overrides):
    """Create a fake REST-layer response object."""
    defaults = dict(
        id="tpl-1",
        organization_id="org-1",
        name="Employee Badge",
        description="Employee credential",
        credential_type="EmployeeCredential",
        vct="EmployeeCredential",
        doctype="",
        claims=[
            {"name": "given_name", "display_name": "First Name", "claim_type": "string", "required": True},
            {"name": "email", "display_name": "Email", "claim_type": "string", "required": True,
             "selectively_disclosable": True},
        ],
        privacy_posture="selective_disclosure",
        selective_disclosure_fields=["email"],
        zk_predicate_claims=[],
        supported_formats=["sd_jwt_vc"],
        issuance_protocol="oid4vci",
        credential_payload_format="sd_jwt_vc",
        display_style={"background_color": "#003366", "text_color": "#ffffff"},
        validity_rules={"default_validity_days": 365, "max_validity_days": 730, "renewable": True},
        status="active",
        version=1,
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-02T00:00:00Z",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _to_response_fn(template):
    """Fake converter that returns the template itself (already in response form)."""
    return template


def _build_servicer(**overrides) -> CredentialTemplateServiceGrpc:
    defaults = dict(
        repo=MagicMock(),
        to_response_fn=_to_response_fn,
    )
    defaults.update(overrides)
    return CredentialTemplateServiceGrpc(**defaults)


# ── GetTemplate ──────────────────────────────────────────────────────


class TestGetTemplate:
    async def test_found(self, ctx):
        template = _make_template_response()
        repo = MagicMock()
        repo.get = AsyncMock(return_value=template)
        servicer = _build_servicer(repo=repo)

        req = ct_pb2.GetTemplateRequest(template_id="tpl-1")
        resp = await servicer.GetTemplate(req, ctx)

        assert resp.id == "tpl-1"
        assert resp.name == "Employee Badge"
        assert resp.credential_type == "EmployeeCredential"
        assert len(resp.claims) == 2
        assert resp.claims[0].name == "given_name"
        assert resp.claims[1].selectively_disclosable is True
        assert resp.display_style.background_color == "#003366"
        assert resp.validity_rules.default_validity_days == 365
        assert ctx.code is None

    async def test_not_found(self, ctx):
        repo = MagicMock()
        repo.get = AsyncMock(return_value=None)
        servicer = _build_servicer(repo=repo)

        req = ct_pb2.GetTemplateRequest(template_id="missing")
        resp = await servicer.GetTemplate(req, ctx)

        assert ctx.code == grpc.StatusCode.NOT_FOUND
        assert "missing" in ctx.details


# ── ListTemplates ────────────────────────────────────────────────────


class TestListTemplates:
    async def test_returns_templates(self, ctx):
        templates = [
            _make_template_response(id="tpl-1", name="Badge A"),
            _make_template_response(id="tpl-2", name="Badge B"),
        ]
        repo = MagicMock()
        repo.list = AsyncMock(return_value=templates)
        servicer = _build_servicer(repo=repo)

        req = ct_pb2.ListTemplatesRequest(organization_id="org-1")
        resp = await servicer.ListTemplates(req, ctx)

        assert len(resp.templates) == 2
        assert resp.templates[0].id == "tpl-1"
        assert resp.templates[1].name == "Badge B"

    async def test_empty_list(self, ctx):
        repo = MagicMock()
        repo.list = AsyncMock(return_value=[])
        servicer = _build_servicer(repo=repo)

        req = ct_pb2.ListTemplatesRequest(organization_id="org-1")
        resp = await servicer.ListTemplates(req, ctx)

        assert len(resp.templates) == 0


# ── GetCredentialConfigurations ──────────────────────────────────────


class TestGetCredentialConfigurations:
    async def test_active_templates_produce_configs(self, ctx):
        t1 = SimpleNamespace(credential_type="EmployeeCredential", name="Employee Badge")
        t2 = SimpleNamespace(credential_type="MemberCredential", name="Member Badge")
        repo = MagicMock()
        repo.list_all = AsyncMock(return_value=[t1, t2])
        servicer = _build_servicer(repo=repo)

        req = ct_pb2.GetCredentialConfigurationsRequest()
        resp = await servicer.GetCredentialConfigurations(req, ctx)

        configs = json.loads(resp.configurations_json)
        assert "EmployeeCredential" in configs
        assert "MemberCredential" in configs
        assert configs["EmployeeCredential"]["name"] == "Employee Badge"

    async def test_empty_credential_type_skipped(self, ctx):
        t = SimpleNamespace(credential_type="", name="No Type")
        repo = MagicMock()
        repo.list_all = AsyncMock(return_value=[t])
        servicer = _build_servicer(repo=repo)

        req = ct_pb2.GetCredentialConfigurationsRequest()
        resp = await servicer.GetCredentialConfigurations(req, ctx)

        configs = json.loads(resp.configurations_json)
        assert len(configs) == 0

    async def test_repo_error_returns_empty(self, ctx):
        repo = MagicMock()
        repo.list_all = AsyncMock(side_effect=RuntimeError("db error"))
        servicer = _build_servicer(repo=repo)

        req = ct_pb2.GetCredentialConfigurationsRequest()
        resp = await servicer.GetCredentialConfigurations(req, ctx)

        configs = json.loads(resp.configurations_json)
        assert configs == {}


# ── HealthCheck ──────────────────────────────────────────────────────


class TestHealthCheck:
    async def test_returns_serving(self, ctx):
        servicer = _build_servicer()
        req = ct_pb2.HealthCheckRequest()
        resp = await servicer.HealthCheck(req, ctx)
        assert resp.status == "serving"
