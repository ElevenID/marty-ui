from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi import Response
from pydantic import ValidationError

from gateway.models import PresentationPolicyCreate
from gateway.routes import verification


CONTRACT = json.loads(
    (
        Path(__file__).parents[3]
        / "contracts"
        / "gateway-presentation-policy-behavior.json"
    ).read_text(encoding="utf-8")
)


@pytest.mark.asyncio
async def test_legacy_gateway_executes_shared_presentation_policy_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CONTRACT["schema_version"] == 1
    body = PresentationPolicyCreate.model_validate(CONTRACT["create_input"])
    monkeypatch.setattr(
        verification,
        "_load_credential_template",
        AsyncMock(
            side_effect=lambda template_id, _request: {
                "id": template_id,
                "organization_id": "org-1",
                "credential_payload_format": CONTRACT["authoritative_formats"][template_id],
            }
        ),
    )
    canonical = json.loads(
        await verification._authoritative_policy_body(body, object())
    )
    assert canonical == CONTRACT["expected_create_internal"]
    proof = PresentationPolicyCreate.model_validate(CONTRACT["proof_only_input"])
    assert verification._validated_policy_payload(proof) == CONTRACT["expected_proof_only_internal"]
    for invalid in CONTRACT["invalid_requests"]:
        with pytest.raises(ValidationError):
            PresentationPolicyCreate.model_validate(invalid)
    response = verification._sanitize_presentation_policy_response(
        Response(content=json.dumps(CONTRACT["internal_response"]), media_type="application/json")
    )
    assert json.loads(response.body) == CONTRACT["expected_public_response"]
