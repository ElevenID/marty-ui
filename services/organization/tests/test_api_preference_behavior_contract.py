import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from services.organization.application.ports import (
    CreateApiKeyCommand,
    UpsertConsoleContextPreferenceCommand,
)
from services.organization.application.use_cases import (
    ApiKeyUseCase,
    ConsoleContextPreferenceUseCase,
)
from services.organization.domain.entities import ConsoleContextPreference, ViewMode


def _fixture() -> dict:
    root = Path(__file__).resolve().parents[3]
    return json.loads(
        (root / "contracts" / "organization-api-preference-behavior.json").read_text(
            encoding="utf-8"
        )
    )


@pytest.mark.asyncio
async def test_api_key_validation_uses_shared_behavior() -> None:
    fixture = _fixture()
    assert fixture["schema_version"] == 1
    for case in fixture["api_key_cases"]:
        api_key_repo = SimpleNamespace(save=AsyncMock())
        use_case = ApiKeyUseCase(
            api_key_repo=api_key_repo,
            organization_repo=SimpleNamespace(
                get_by_id=AsyncMock(return_value=SimpleNamespace(name="Behavior Org"))
            ),
            event_publisher=SimpleNamespace(publish=AsyncMock()),
        )
        command = CreateApiKeyCommand(
            organization_id="11111111-1111-1111-1111-111111111111",
            name="contract-key",
            created_by="owner",
            scopes=case["scopes"],
            is_test=True,
            scope_type=case["scope_type"],
            deployment_profile_id=case["deployment_profile_id"],
            rate_limit=case["rate_limit"],
            expires_at=(
                datetime.fromisoformat(case["expires_at"].replace("Z", "+00:00"))
                if case["expires_at"]
                else None
            ),
        )
        if case["valid"]:
            api_key, raw_key = await use_case.create_api_key(command)
            assert raw_key.startswith("mk_test_")
            assert api_key.scope_type == case["scope_type"]
            assert api_key.deployment_profile_id == case["deployment_profile_id"]
            assert api_key.rate_limit == case["rate_limit"]
            api_key_repo.save.assert_awaited_once()
        else:
            with pytest.raises(ValueError):
                await use_case.create_api_key(command)
            api_key_repo.save.assert_not_awaited()


@pytest.mark.asyncio
async def test_preference_partial_updates_use_shared_behavior() -> None:
    for case in _fixture()["preference_cases"]:
        current = ConsoleContextPreference(
            user_id="subject",
            last_view_mode=ViewMode.ORG_ADMIN,
            last_active_org_id="11111111-1111-1111-1111-111111111111",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        repository = SimpleNamespace(
            get_by_user_id=AsyncMock(return_value=current),
            save=AsyncMock(),
        )
        use_case = ConsoleContextPreferenceUseCase(repository)
        operation = case["last_active_org"]["operation"]
        command = UpsertConsoleContextPreferenceCommand(
            user_id="subject",
            last_view_mode=(
                ViewMode(case["last_view_mode"])
                if case["last_view_mode"] is not None
                else None
            ),
            last_active_org_id=(
                case["last_active_org"].get("organization_id")
                if operation == "set"
                else None
            ),
            last_active_org_id_set=operation != "omitted",
        )
        updated = await use_case.upsert_preferences(command)
        assert updated.last_view_mode.value == case["expected_view_mode"], case["name"]
        assert updated.last_active_org_id == case["expected_active_org_id"], case["name"]
