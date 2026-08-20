import json
from pathlib import Path

import pytest
from fastapi import HTTPException, Response
from pydantic import ValidationError

from gateway.models import DidcommDeliverRequest, DidcommDeliveryResponse
from gateway.routes.issuance import _sanitize_management_response


CONTRACT = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "contracts"
        / "gateway-didcomm-delivery-behavior.json"
    ).read_text(encoding="utf-8")
)


def test_python_didcomm_delivery_matches_language_neutral_contract() -> None:
    assert CONTRACT["schema_version"] == 1
    request = DidcommDeliverRequest.model_validate(CONTRACT["valid_request"])
    assert request.model_dump(mode="json") == CONTRACT["expected_request"]
    for invalid in CONTRACT["invalid_requests"]:
        with pytest.raises(ValidationError):
            DidcommDeliverRequest.model_validate(invalid)

    response = _sanitize_management_response(
        Response(
            content=json.dumps(CONTRACT["internal_response"]),
            media_type="application/json",
        ),
        DidcommDeliveryResponse,
    )
    assert json.loads(response.body) == CONTRACT["expected_response"]
    for invalid in CONTRACT["invalid_responses"]:
        with pytest.raises(HTTPException):
            _sanitize_management_response(
                Response(content=json.dumps(invalid), media_type="application/json"),
                DidcommDeliveryResponse,
            )
