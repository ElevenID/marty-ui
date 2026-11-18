#!/usr/bin/env python3
"""Join the protected Gateway observations with one server-traced Flow job.

The nine public route names describe the supported surface. Seven job
operations run from Flow to native issuance; only capability and callback
traffic is observed at Gateway. This proof never claims the seven Flow calls
traversed Gateway.
"""

from __future__ import annotations

import re
from typing import Any

try:
    from .probe_passport_beta_flow import PHYSICAL_STEPS
    from .probe_passport_beta_selected_flow import PASSPORT_FLOW_ROUTES
except ImportError:
    from probe_passport_beta_flow import PHYSICAL_STEPS
    from probe_passport_beta_selected_flow import PASSPORT_FLOW_ROUTES


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ROUTES = (
    ("GET", "/v1/passport/capabilities"), *PASSPORT_FLOW_ROUTES,
    ("POST", "/v1/passport/webhooks/personalization"),
)
SELECTED_COMMITMENTS = (
    "organization_commitment", "flow_definition_commitment",
    "flow_instance_commitment", "application_commitment",
    "source_job_commitment", "bureau_job_commitment",
)


class CompositeRouteError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CompositeRouteError(message)


def _evidence(probe: dict[str, Any], name: str) -> dict[str, Any]:
    require(isinstance(probe, dict) and probe.get("verified") is True
            and isinstance(probe.get("evidence"), dict),
            f"Protected {name} evidence is unavailable")
    return probe["evidence"]


def prove_composite_routes(
    selected_flow: dict[str, Any],
    selected_commitments: dict[str, str],
    native_batch: dict[str, Any],
    native_route_ownership: dict[str, Any],
    flow_capability_and_webhook_denial: dict[str, Any],
    passport_capability: dict[str, Any],
) -> dict[str, Any]:
    """Return a bounded nine-route receipt with truthful per-route provenance."""
    selected = _evidence(selected_flow, "selected Flow")
    batch = _evidence(native_batch, "selected native batch")
    ownership = _evidence(native_route_ownership, "native route ownership")
    flow = _evidence(flow_capability_and_webhook_denial, "Flow capability and webhook")
    capability = _evidence(passport_capability, "passport capability")
    require(isinstance(selected_commitments, dict)
            and set(selected_commitments) == set(SELECTED_COMMITMENTS)
            and all(isinstance(selected_commitments[field], str)
                    and SHA256.fullmatch(selected_commitments[field]) is not None
                    for field in SELECTED_COMMITMENTS)
            and selected.get("source_job_commitment")
            == selected_commitments["source_job_commitment"]
            and selected.get("bureau_job_commitment")
            == selected_commitments["bureau_job_commitment"]
            and selected.get("ordered_steps") == list(PHYSICAL_STEPS)
            and selected.get("completed_steps") == len(PHYSICAL_STEPS)
            and selected.get("flow_routes") == [
                {"method": method, "path": path} for method, path in PASSPORT_FLOW_ROUTES]
            and selected.get("signed_simulator_callback_verified") is True
            and selected.get("terminal_native_status") == "ACTIVE"
            and isinstance(selected.get("callback_receipt_sha256"), str)
            and SHA256.fullmatch(selected["callback_receipt_sha256"]) is not None,
            "Selected server-traced Flow job is incomplete")
    require(batch.get("provider_kind") == "simulator"
            and batch.get("selected_flow_in_two_job_batch") is True
            and batch.get("native_binding_verified") is True
            and batch.get("selected_source_job_commitment")
            == selected_commitments["source_job_commitment"]
            and batch.get("selected_bureau_job_commitment")
            == selected_commitments["bureau_job_commitment"],
            "Selected Flow is absent from the native simulator batch")
    require(ownership.get("native_selectors") is True
            and ownership.get("flow_native_target") is True
            and ownership.get("simulator_callback_gateway_target") is True
            and ownership.get("webhook_owner") == "issuance-native"
            and flow.get("flow_capability_route") == "/v1/flows/capabilities"
            and flow.get("flow_http_status") == 200
            and flow.get("physical_step_count") == len(PHYSICAL_STEPS)
            and flow.get("unsigned_webhook_route")
            == "/v1/passport/webhooks/personalization"
            and flow.get("unsigned_webhook_http_status") == 422
            and flow.get("unsigned_webhook_owner") == "issuance-native"
            and flow.get("signature_denial_verified") is True
            and capability == {"http_status": 200, "supported": True,
                               "signer_mode": "MANAGED_ISSUER_PROFILE"},
            "Live Gateway capability, callback, or route owner is unproven")
    return {"verified": True, "evidence": {
        "routes": [{"method": method, "path": path} for method, path in ROUTES],
        "gateway_owner": "rust", "flow_owner": "rust",
        "ordered_steps": list(PHYSICAL_STEPS), "completed_steps": len(PHYSICAL_STEPS),
        "route_provenance": {
            "capability": "authenticated_gateway_response",
            "job_operations": "selected_flow_server_trace_to_native_issuance",
            "callback": "gateway_target_and_selected_signed_simulator_receipt",
        },
        **selected_commitments,
    }}
