"""Regression coverage for API-key persistence and gRPC transport types."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from marty_proto.v1 import organization_service_pb2
from organization.infrastructure.adapters.grpc_adapter import OrganizationServiceGrpc
from organization.infrastructure.adapters.postgres_adapter import PostgresApiKeyRepository


def _database_api_key_row() -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        name="Official conformance key",
        description=None,
        key_prefix="mk_test_",
        key_hash="a" * 64,
        scopes=["credentials:issue", "credentials:read"],
        status="active",
        rate_limit=None,
        created_by="conformance-admin",
        last_used_at=None,
        last_used_ip=None,
        expires_at=None,
        created_at=datetime.now(timezone.utc),
    )


def test_postgres_api_key_mapper_normalizes_uuid_identifiers() -> None:
    row = _database_api_key_row()
    repository = PostgresApiKeyRepository(session_factory=None)

    api_key = repository._row_to_entity(row)

    assert api_key.id == str(row.id)
    assert api_key.organization_id == str(row.organization_id)
    assert isinstance(api_key.id, str)
    assert isinstance(api_key.organization_id, str)


@pytest.mark.asyncio
async def test_validate_api_key_accepts_uuid_values_at_protobuf_boundary() -> None:
    row = _database_api_key_row()
    api_key_use_case = SimpleNamespace(
        validate_api_key=AsyncMock(
            return_value=SimpleNamespace(
                id=row.id,
                organization_id=row.organization_id,
                key_prefix=row.key_prefix,
                scopes=row.scopes,
            )
        )
    )
    adapter = OrganizationServiceGrpc(
        org_use_case=None,
        member_use_case=None,
        api_key_use_case=api_key_use_case,
        role_use_case=None,
    )

    response = await adapter.ValidateApiKey(
        organization_service_pb2.ValidateApiKeyRequest(api_key="mk_test_fixture"),
        context=SimpleNamespace(),
    )

    assert response.valid is True
    assert response.api_key_id == str(row.id)
    assert response.organization_id == str(row.organization_id)
    assert list(response.scopes) == row.scopes
