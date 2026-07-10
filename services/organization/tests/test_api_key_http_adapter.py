"""Tests for API key HTTP response mapping."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from organization.infrastructure.adapters.http_adapter import _api_key_to_response


def test_api_key_response_mapper_stringifies_uuid_fields() -> None:
    api_key = SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        name="Partner key",
        description=None,
        key_prefix="mk_live_",
        scope_type="ORGANIZATION",
        deployment_profile_id=uuid4(),
        scopes=["flows:execute"],
        enabled=True,
        last_used_at=None,
        expires_at=None,
        created_at=datetime.now(timezone.utc),
        updated_at=None,
    )

    response = _api_key_to_response(api_key)

    assert response.id == str(api_key.id)
    assert response.organization_id == str(api_key.organization_id)
    assert response.deployment_profile_id == str(api_key.deployment_profile_id)
