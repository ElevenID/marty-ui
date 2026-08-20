from __future__ import annotations

import json
from pathlib import Path

from gateway.models import (
    DeploymentProfileCreate,
    DeploymentProfileResponse,
    DeploymentProfileUpdate,
    LaneResponse,
)


CONTRACT = json.loads(
    (Path(__file__).parents[3] / "contracts" / "gateway-deployment-behavior.json").read_text(
        encoding="utf-8"
    )
)


def _project(model, value: dict) -> dict:
    fields = model.model_fields
    return model.model_validate({key: value[key] for key in fields if key in value}).model_dump(
        mode="json"
    )


def test_legacy_gateway_executes_shared_deployment_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    create = DeploymentProfileCreate.model_validate(CONTRACT["create_input"])
    assert create.model_dump(mode="json", exclude_none=True) == CONTRACT["expected_create"]
    update = DeploymentProfileUpdate.model_validate(CONTRACT["update_alias_input"])
    assert update.model_dump(mode="json", exclude_none=True) == CONTRACT["expected_update"]
    assert _project(DeploymentProfileResponse, CONTRACT["internal_profile"]) == CONTRACT["expected_profile"]
    assert _project(LaneResponse, CONTRACT["internal_lane"]) == CONTRACT["expected_lane"]
