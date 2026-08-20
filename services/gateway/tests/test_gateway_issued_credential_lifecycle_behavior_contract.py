from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from gateway.models import IssuedCredentialLifecycleRequest


CONTRACT = json.loads(
    (
        Path(__file__).parents[3]
        / "contracts"
        / "gateway-issued-credential-lifecycle-behavior.json"
    ).read_text(encoding="utf-8")
)


def test_legacy_gateway_executes_shared_lifecycle_request_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    request = IssuedCredentialLifecycleRequest.model_validate(CONTRACT["request_input"])
    assert request.model_dump(mode="json", exclude_none=True) == CONTRACT["expected_request"]
    for invalid in CONTRACT["invalid_requests"]:
        with pytest.raises(ValidationError):
            IssuedCredentialLifecycleRequest.model_validate(invalid)
