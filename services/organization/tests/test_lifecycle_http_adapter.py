from __future__ import annotations

from datetime import datetime, timezone
import asyncio
import sys
import types
from unittest.mock import patch

from services.organization.domain.entities import Organization, OrganizationStatus


_fake_email_validator = types.ModuleType("email_validator")


class _FakeEmailNotValidError(ValueError):
    pass


_fake_email_validator.EmailNotValidError = _FakeEmailNotValidError
_fake_email_validator.validate_email = lambda value, *args, **kwargs: value
sys.modules.setdefault("email_validator", _fake_email_validator)

with patch("pydantic.networks.version", return_value="2.0.0"):
    from services.organization.infrastructure.adapters import http_adapter as adapter


def test_lifecycle_response_ignores_stale_hosted_pilot_retention_fields_for_standard_plan():
    org = Organization(
        id="org-1",
        name="Org 1",
        slug="org-1",
        owner_id="user-1",
        status=OrganizationStatus.ACTIVE,
        plan="professional",
        created_at=datetime(2026, 4, 1, tzinfo=timezone.utc),
        settings={
            "pilot_retention_enabled": False,
            "pilot_retention_days": 30,
            "pilot_retention_last_purged_at": "2026-04-13T12:00:00+00:00",
            "audit_retention_days": 30,
            "data_retention_mode": "standard",
        },
    )

    response = adapter._org_to_lifecycle_response(org)

    assert response.plan_tier == "professional"
    assert response.data_retention_mode == "standard"
    assert response.audit_retention_days == 90
    assert response.pilot_retention is None


def test_internal_lifecycle_route_uses_resource_id_without_user_context():
    org = Organization(
        id="org-1",
        name="Org 1",
        slug="org-1",
        owner_id="user-1",
        status=OrganizationStatus.ACTIVE,
        plan="professional",
        created_at=datetime(2026, 4, 1, tzinfo=timezone.utc),
    )

    class UseCase:
        async def get_organization(self, org_id):
            return org if org_id == org.id else None

    response = asyncio.run(adapter.get_internal_organization_lifecycle("org-1", UseCase()))

    assert response.plan_tier == "professional"
