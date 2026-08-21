import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from services.organization.application.policy_set_use_cases import PolicySetUseCase
from services.organization.domain.policy_set import PolicySet, PolicySetStatus, PolicySetType
from services.organization.infrastructure.adapters import audit_adapter


def _fixture() -> dict:
    root = Path(__file__).resolve().parents[3]
    return json.loads(
        (root / "contracts" / "organization-policy-audit-behavior.json").read_text(
            encoding="utf-8"
        )
    )


def _classify_policy_error(errors: list[str]) -> str | None:
    if not errors:
        return None
    if errors[0].startswith("Policy "):
        return "effect_mismatch"
    if errors[0].startswith("Duplicate policy_id"):
        return "duplicate_policy_id"
    if errors[0] == "At least one policy must be enabled":
        return "no_enabled_policy"
    return "invalid_cedar"


def _classify_time_error(message: str) -> str:
    if "use h, d, or w" in message:
        return "invalid_unit"
    if "positive" in message and "start" not in message:
        return "nonpositive"
    if "positive integer" in message:
        return "invalid_amount"
    raise AssertionError(f"unrecognized time-range error: {message}")


def test_policy_validation_and_legacy_projection_use_shared_behavior() -> None:
    fixture = _fixture()
    assert fixture["schema_version"] == 1
    from marty_common import CedarEngine

    use_case = PolicySetUseCase(repo=None, cedar_engine=CedarEngine.with_defaults())
    for case in fixture["policy_cases"]:
        errors = use_case.validate_policies(case["policies"])
        assert _classify_policy_error(errors) == case["expected_error"], case["name"]

    legacy = use_case.deserialize_policies(fixture["legacy_policy"]["source"])
    assert len(legacy) == 1
    assert legacy[0]["policy_id"] == fixture["legacy_policy"]["expected_policy_id"]
    assert legacy[0]["effect"] == fixture["legacy_policy"]["expected_effect"]


@pytest.mark.asyncio
async def test_policy_activation_preserves_one_active_set_per_type() -> None:
    fixture = _fixture()
    case = fixture["activation_case"]
    valid_policies = json.dumps(fixture["policy_cases"][0]["policies"])
    now = datetime.now(timezone.utc)
    policy_sets = {
        source["id"]: PolicySet(
            id=source["id"],
            organization_id="11111111-1111-1111-1111-111111111111",
            name=source["id"],
            description=None,
            policy_type=PolicySetType(source["policy_type"]),
            status=PolicySetStatus(source["status"]),
            cedar_policies=valid_policies,
            cedar_schema_version="MIP/1.0",
            created_by=None,
            created_at=now,
            updated_at=now,
        )
        for source in case["policy_sets"]
    }
    target = policy_sets[case["target_id"]]
    repository = SimpleNamespace(
        get_by_id=AsyncMock(return_value=target),
        list_by_org=AsyncMock(
            return_value=[
                policy_set
                for policy_set in policy_sets.values()
                if policy_set.status == PolicySetStatus.ACTIVE
            ]
        ),
        save=AsyncMock(),
    )
    from marty_common import CedarEngine

    use_case = PolicySetUseCase(repository, CedarEngine.with_defaults())
    activated = await use_case.activate(target.id, target.organization_id)

    assert activated.status == PolicySetStatus.ACTIVE
    assert {
        policy_set.id
        for policy_set in policy_sets.values()
        if policy_set.status == PolicySetStatus.ARCHIVED
        and policy_set.id in case["expected_archived_ids"]
    } == set(case["expected_archived_ids"])
    repository.list_by_org.assert_awaited_once_with(
        target.organization_id, status=PolicySetStatus.ACTIVE.value
    )


def test_audit_pagination_and_time_ranges_use_shared_behavior(monkeypatch) -> None:
    fixture = _fixture()
    fixed_now = datetime.fromisoformat(fixture["audit_now"].replace("Z", "+00:00"))

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now if tz is not None else fixed_now.replace(tzinfo=None)

    monkeypatch.setattr(audit_adapter, "datetime", FixedDateTime)
    for case in fixture["audit_pagination_cases"]:
        query = audit_adapter._query(
            organization_id="11111111-1111-1111-1111-111111111111",
            page=case["page"],
            per_page=case["per_page"],
            limit=case["legacy_limit"],
            offset=case["legacy_offset"],
            category=None,
            resource_type=None,
            resource_id=None,
            action=None,
            actor=None,
            severity=None,
            search=None,
            ip_address=None,
            time_range=None,
            start_date=None,
            end_date=None,
        )
        assert query.page == case["expected_page"], case["name"]
        assert query.per_page == case["expected_per_page"], case["name"]
        assert (query.page - 1) * query.per_page == case["expected_offset"], case["name"]

    for case in fixture["audit_time_range_cases"]:
        if case["expected_error"]:
            with pytest.raises(Exception) as captured:
                audit_adapter._start_date_from_time_range(case["time_range"])
            detail = captured.value.detail
            assert _classify_time_error(detail["message"]) == case["expected_error"], case["name"]
        else:
            actual = audit_adapter._start_date_from_time_range(case["time_range"])
            expected = case["expected_start"]
            if expected is None:
                assert actual is None, case["name"]
            else:
                assert datetime.fromisoformat(actual) == datetime.fromisoformat(
                    expected.replace("Z", "+00:00")
                ), case["name"]
