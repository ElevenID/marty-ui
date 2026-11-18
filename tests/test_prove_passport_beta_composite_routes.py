"""Composite routing evidence must preserve actual Gateway and Flow provenance."""

from __future__ import annotations

import copy

import pytest

from scripts.probe_passport_beta_flow import PHYSICAL_STEPS
from scripts.probe_passport_beta_selected_flow import PASSPORT_FLOW_ROUTES
from scripts.prove_passport_beta_composite_routes import (
    CompositeRouteError, prove_composite_routes,
)


def fixture() -> tuple[dict, dict, dict, dict, dict, dict]:
    commitments = {
        name: str(index) * 64 for index, name in enumerate((
            "organization_commitment", "flow_definition_commitment",
            "flow_instance_commitment", "application_commitment",
            "source_job_commitment", "bureau_job_commitment"), start=1)
    }

    def probe(evidence):
        return {"verified": True, "evidence": evidence}

    selected = probe({
        "source_job_commitment": commitments["source_job_commitment"],
        "bureau_job_commitment": commitments["bureau_job_commitment"],
        "ordered_steps": list(PHYSICAL_STEPS), "completed_steps": 9,
        "flow_routes": [{"method": method, "path": path}
                        for method, path in PASSPORT_FLOW_ROUTES],
        "signed_simulator_callback_verified": True,
        "terminal_native_status": "ACTIVE", "callback_receipt_sha256": "a" * 64,
    })
    batch = probe({"provider_kind": "simulator", "selected_flow_in_two_job_batch": True,
                   "native_binding_verified": True,
                   "selected_source_job_commitment": commitments["source_job_commitment"],
                   "selected_bureau_job_commitment": commitments["bureau_job_commitment"]})
    routing = probe({"native_selectors": True, "flow_native_target": True,
                     "simulator_callback_gateway_target": True,
                     "webhook_owner": "issuance-native"})
    flow = probe({"flow_capability_route": "/v1/flows/capabilities",
                  "flow_http_status": 200, "physical_step_count": 9,
                  "unsigned_webhook_route": "/v1/passport/webhooks/personalization",
                  "unsigned_webhook_http_status": 422,
                  "unsigned_webhook_owner": "issuance-native",
                  "signature_denial_verified": True})
    capability = probe({"http_status": 200, "supported": True,
                        "signer_mode": "MANAGED_ISSUER_PROFILE"})
    return selected, commitments, batch, routing, flow, capability


def test_composite_receipt_distinguishes_gateway_and_flow_paths() -> None:
    result = prove_composite_routes(*fixture())
    assert result["verified"] is True
    assert len(result["evidence"]["routes"]) == 9
    assert result["evidence"]["route_provenance"]["job_operations"] == (
        "selected_flow_server_trace_to_native_issuance")
    assert result["evidence"]["source_job_commitment"] == "5" * 64
    assert "job_id" not in str(result)


@pytest.mark.parametrize("input_index,field,value", [
    (0, "flow_routes", []),
    (0, "callback_receipt_sha256", "bad"),
    (0, "signed_simulator_callback_verified", False),
    (2, "selected_source_job_commitment", "f" * 64),
    (3, "flow_native_target", False),
    (3, "simulator_callback_gateway_target", False),
    (4, "unsigned_webhook_http_status", 401),
    (5, "signer_mode", "LOCAL_KEY"),
])
def test_composite_receipt_rejects_unproven_route(input_index, field, value) -> None:
    arguments = list(copy.deepcopy(fixture()))
    arguments[input_index]["evidence"][field] = value
    with pytest.raises(CompositeRouteError):
        prove_composite_routes(*arguments)


def test_composite_receipt_rejects_unverified_probe() -> None:
    arguments = list(fixture())
    arguments[3]["verified"] = False
    with pytest.raises(CompositeRouteError):
        prove_composite_routes(*arguments)
