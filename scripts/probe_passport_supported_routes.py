#!/usr/bin/env python3
"""Check the frozen nine route shapes and the simulator's same-job receipt.

The caller supplies an owned HTTPS Gateway request and an authenticated private
bureau poll. The caller must bind the signed receipt to the inspected private
Gateway callback route. Flow execution and physical personalization remain unproven.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any, Callable
import uuid

if __package__:
    from .probe_passport_beta_gateway import exercise as exercise_gateway
else:
    from probe_passport_beta_gateway import exercise as exercise_gateway


ROOT = Path(__file__).resolve().parents[1]
ROUTING_CONTRACT = ROOT / "contracts/passport-supported-consumer-routing.json"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
Request = Callable[[str, str, dict[str, Any] | None, str],
                   tuple[int, dict[str, Any]]]
PrivatePoll = Callable[[str], tuple[int, dict[str, Any]]]


class SupportedRouteProbeError(ValueError):
    pass


def _frozen_routes() -> set[tuple[str, str]]:
    payload = json.loads(ROUTING_CONTRACT.read_text(encoding="utf-8"))
    if (not isinstance(payload, dict)
        or payload.get("schema") != "marty.passport-supported-consumer-routing/v1"
        or not isinstance(payload.get("routes"), list)):
        raise SupportedRouteProbeError("Supported route contract is invalid")
    routes = payload["routes"]
    selected = {
        (item.get("method"), item.get("path"))
        for item in routes if isinstance(item, dict)
    }
    if (len(routes) != 9 or len(selected) != 9
        or any(not isinstance(method, str) or not isinstance(path, str)
               for method, path in selected)):
        raise SupportedRouteProbeError("Supported route contract is incomplete")
    return selected


def exercise(
    application: dict[str, Any], api_key: str, *,
    request: Request, private_poll: PrivatePoll,
    callback_via_gateway: bool,
    max_polls: int = 36,
    poll_interval_seconds: float = 5,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Require one managed lifecycle and a signed receipt from its bureau job."""
    expected = _frozen_routes()
    if ("POST", "/v1/passport/webhooks/personalization") not in expected:
        raise SupportedRouteProbeError("Supported webhook route is missing")
    status, capabilities = request("GET", "/v1/passport/capabilities", None, api_key)
    signer = capabilities.get("signer") if isinstance(capabilities, dict) else None
    if (status != 200 or not isinstance(capabilities, dict)
        or capabilities.get("supported") is not True
        or capabilities.get("blockers") != []
        or capabilities.get("bureau_configured") is not True
        or capabilities.get("encrypted_artifact_store") is not True
        or not isinstance(signer, dict)
        or signer.get("mode") != "MANAGED_ISSUER_PROFILE"):
        raise SupportedRouteProbeError("Managed passport capability is unavailable")

    bureau_job_id = None
    observed_public = None

    def watched(method: str, path: str, body: dict[str, Any] | None,
                authority: str) -> tuple[int, dict[str, Any]]:
        nonlocal bureau_job_id, observed_public
        observed_status, payload = request(method, path, body, authority)
        if not isinstance(payload, dict):
            raise SupportedRouteProbeError("Passport route response is invalid")
        if path.endswith("/submit-personalization") and observed_status == 200:
            candidate = payload.get("bureau_job_id")
            try:
                parsed = uuid.UUID(candidate) if isinstance(candidate, str) else None
            except (ValueError, AttributeError):
                parsed = None
            if parsed is None or str(parsed) != candidate:
                raise SupportedRouteProbeError("Simulator bureau job ID is invalid")
            bureau_job_id = candidate
        elif bureau_job_id is not None and payload.get("bureau_job_id") != bureau_job_id:
            raise SupportedRouteProbeError("Passport response changed bureau job")
        if path.endswith("/production-status") and observed_status == 200:
            observed_public = payload
        return observed_status, payload

    lifecycle = exercise_gateway(
        application, api_key, request=watched, max_polls=max_polls,
        poll_interval_seconds=poll_interval_seconds, sleep=sleep,
    )
    if bureau_job_id is None or not isinstance(observed_public, dict):
        raise SupportedRouteProbeError("Passport lifecycle has no same-job status")
    poll_status, private = private_poll(bureau_job_id)
    receipt = private.get("callback_receipt_sha256") if isinstance(private, dict) else None
    private_state = private.get("status") if isinstance(private, dict) else None
    tracking = private.get("tracking_number") if isinstance(private, dict) else None
    expected_tracking = "BETA-SIM-" + uuid.UUID(bureau_job_id).hex
    if (callback_via_gateway is not True
        or poll_status != 200 or private_state not in ("QUALITY_CHECK", "SHIPPED")
        or not isinstance(receipt, str) or HEX64.fullmatch(receipt) is None
        or (private_state == "SHIPPED" and tracking != expected_tracking)
        or (private_state == "QUALITY_CHECK" and tracking is not None)
        or (tracking is not None and tracking != expected_tracking)
        or observed_public.get("bureau_job_id") != bureau_job_id
        or observed_public.get("status") not in
        ("QUALITY_CHECK", "READY_FOR_ACTIVATION")):
        raise SupportedRouteProbeError("Simulator signed callback receipt is unproven")

    denial_status, _ = request(
        "POST", "/v1/passport/webhooks/personalization", {}, "",
    )
    if denial_status != 422:
        raise SupportedRouteProbeError("Unsigned webhook was not denied")
    routes = [
        {"method": "GET", "route": "/v1/passport/capabilities",
         "http_status": status},
        *lifecycle["evidence"]["routes"],
        {"method": "POST", "route": "/v1/passport/webhooks/personalization",
         "http_status": denial_status,
         "positive_gateway_path_verified": True,
         "signed_callback_observed_by": "authenticated-private-bureau-receipt"},
    ]
    observed = {(item["method"], item["route"]) for item in routes}
    if len(routes) < 9 or observed != expected:
        raise SupportedRouteProbeError("Passport routes differ from frozen contract")
    evidence = dict(lifecycle["evidence"])
    evidence["routes"] = routes
    evidence["callback_receipt_sha256"] = receipt
    evidence["callback_bureau_job_id_sha256"] = hashlib.sha256(
        bureau_job_id.encode("ascii")).hexdigest()
    evidence["callback_private_status"] = private_state
    evidence["unsigned_webhook_http_status"] = denial_status
    evidence["signed_callback_path"] = "simulator-to-gateway-to-native"
    evidence["signed_gateway_callback_verified"] = True
    evidence["physical_claim"] = "not_claimed"
    return {"verified": True, "evidence": evidence,
            "flow_execution_verified": False}
