from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from gateway.models import IssuanceCreate


CONTRACT = json.loads(
    (
        Path(__file__).parents[3]
        / "contracts"
        / "gateway-issuance-create-behavior.json"
    ).read_text(encoding="utf-8")
)


def test_legacy_gateway_executes_shared_issuance_create_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    for case in CONTRACT["valid_cases"]:
        request = IssuanceCreate.model_validate(case["input"])
        registration = None
        if request.authorized_client is not None:
            registration = {
                "organization_id": request.organization_id,
                "client_id": request.authorized_client.client_id,
                "jwks": request.authorized_client.jwks.model_dump(exclude_none=True),
                "redirect_uris": [],
                "active": True,
            }
        assert registration == case["expected_registration"], case["name"]

        downstream = request.model_dump(mode="json", exclude_none=True)
        if not request.claims:
            downstream.pop("claims", None)
        downstream["issuer_did"] = case["resolved_issuer_did"]
        if request.authorized_client is not None:
            client = downstream.pop("authorized_client")
            downstream["authorized_client_id"] = client["client_id"]
        assert downstream == case["expected_downstream"], case["name"]

    for case in CONTRACT["invalid_cases"]:
        with pytest.raises(ValidationError):
            IssuanceCreate.model_validate(case["input"])
