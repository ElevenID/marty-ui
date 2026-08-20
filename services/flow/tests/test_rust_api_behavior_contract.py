"""Cross-language parity for the public Flow request boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from flow.main import (
    AdvanceFlowRequest,
    ApplicationApprovedWebhook,
    CreateFlowDefinitionRequest,
    DigitalCredentialSubmissionRequest,
    SiopSubmitRequest,
    StartFlowRequest,
    StartSiopFlowRequest,
    StartVerificationFlowRequest,
    SubmitVerificationRequest,
    UpdateFlowDefinitionRequest,
)


CONTRACT_PATH = (
    Path(__file__).parents[3] / "contracts" / "flow-api-behavior.json"
)

MODELS = {
    "create_definition": CreateFlowDefinitionRequest,
    "patch_definition": UpdateFlowDefinitionRequest,
    "start_flow": StartFlowRequest,
    "advance_flow": AdvanceFlowRequest,
    "start_verification": StartVerificationFlowRequest,
    "start_siop": StartSiopFlowRequest,
    "siop_submit": SiopSubmitRequest,
    "submit_verification": SubmitVerificationRequest,
    "digital_credential_submit": DigitalCredentialSubmissionRequest,
    "application_approved": ApplicationApprovedWebhook,
}


def _contract() -> dict:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def _validate(kind: str, payload: dict) -> None:
    model = MODELS[kind].model_validate(payload)
    # The legacy SIOP model performs this check in its route handler. Freeze
    # the externally observable behavior while Rust consolidates the boundary.
    if kind == "start_siop" and not str(model.organization_id or "").strip():
        raise ValueError("organization_id is required")


@pytest.mark.parametrize("vector", _contract()["valid_requests"])
def test_python_and_rust_accept_the_same_valid_request_vectors(vector: dict) -> None:
    _validate(vector["kind"], vector["payload"])


@pytest.mark.parametrize("vector", _contract()["invalid_requests"])
def test_python_and_rust_reject_the_same_invalid_request_vectors(vector: dict) -> None:
    with pytest.raises((ValidationError, ValueError)):
        _validate(vector["kind"], vector["payload"])
