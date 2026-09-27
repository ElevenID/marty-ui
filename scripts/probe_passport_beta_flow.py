#!/usr/bin/env python3
"""Probe public beta Flow capability and unsigned webhook denial via Gateway."""

from __future__ import annotations

import json
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


ORIGIN = "https://beta.elevenidllc.com"
FLOW_PATH = "/v1/flows/capabilities"
WEBHOOK_PATH = "/v1/passport/webhooks/personalization"
PHYSICAL_STEPS = (
    "accept_application", "validate_evidence", "approval_decision",
    "generate_data_groups", "sign_sod", "submit_to_personalization",
    "track_production", "quality_verify", "activate_credential",
)


class FlowProbeError(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def request_beta(method: str, path: str) -> tuple[int, dict[str, Any] | None]:
    if (method, path) not in (("GET", FLOW_PATH), ("POST", WEBHOOK_PATH)):
        raise FlowProbeError("Unexpected beta Flow or webhook route")
    url = ORIGIN + path
    body = b"{}" if method == "POST" else None
    headers = {"Accept": "application/json", "Cache-Control": "no-cache",
               "User-Agent": "passport-beta-acceptance/1"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=headers, method=method)
    try:
        with build_opener(NoRedirect).open(request, timeout=20) as response:
            if response.geturl() != url:
                raise FlowProbeError("Beta Flow or webhook route redirected")
            raw = response.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise FlowProbeError("Beta Flow capability response is oversized")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise FlowProbeError("Beta Flow capability response is invalid")
            return response.status, payload
    except HTTPError as exc:
        if path != WEBHOOK_PATH or exc.code not in (401, 422):
            return exc.code, None
        try:
            raw = exc.read(4097)
            if len(raw) > 4096:
                raise FlowProbeError("Unsigned webhook denial is oversized")
            denial = json.loads(raw)
        except (OSError, ValueError) as error:
            raise FlowProbeError("Unsigned webhook denial is invalid") from error
        details = denial.get("detail") if isinstance(denial, dict) else None
        if exc.code == 422:
            missing = (isinstance(details, list) and len(details) == 1
                       and isinstance(details[0], dict) and details[0].get("type") == "missing"
                       and details[0].get("loc") == ["header", "x-personalization-signature"])
            projection = {"missing_signature_header": missing}
        else:
            projection = {"invalid_signature": details == "Invalid personalization webhook signature"}
        # Return only this fixed boolean; never emit the HTTP response body.
        return exc.code, projection
    except (OSError, URLError, ValueError) as exc:
        raise FlowProbeError("Beta Flow or webhook request failed") from exc


def exercise(
    webhook_owner: str,
    request: Callable[[str, str], tuple[int, dict[str, Any] | None]] = request_beta,
) -> dict[str, Any]:
    if webhook_owner not in ("issuance-native", "passport-provider-ingress"):
        raise FlowProbeError("Selected beta webhook owner is invalid")
    status, capabilities = request("GET", FLOW_PATH)
    if status != 200 or not isinstance(capabilities, dict):
        raise FlowProbeError("Flow capability route is unavailable")
    physical = capabilities.get("physical_document_issuance")
    sequences = capabilities.get("sequences")
    if (not isinstance(physical, dict) or physical.get("supported") is not True
            or physical.get("blockers") != [] or not isinstance(sequences, dict)
            or sequences.get("physical_document_issuance") != list(PHYSICAL_STEPS)):
        raise FlowProbeError("Flow physical-document contract is unavailable")
    denial_status, denial = request("POST", WEBHOOK_PATH)
    expected = ((422, {"missing_signature_header": True}) if webhook_owner == "issuance-native"
                else (401, {"invalid_signature": True}))
    if (denial_status, denial) != expected:
        raise FlowProbeError("Unsigned bureau webhook was not rejected")
    return {"verified": True, "evidence": {
        "flow_capability_route": FLOW_PATH, "flow_http_status": status,
        "physical_step_count": len(PHYSICAL_STEPS),
        "unsigned_webhook_route": WEBHOOK_PATH,
        "unsigned_webhook_http_status": denial_status,
        "unsigned_webhook_owner": webhook_owner,
        "signature_denial_verified": True,
        "scope": "Flow capability and unsigned webhook denial only",
    }}
