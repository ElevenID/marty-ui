"""Partial Gateway/Flow evidence cannot claim signed webhook or full nine routes."""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError

import pytest

from scripts import probe_passport_beta_flow as flow_probe
from scripts.probe_passport_beta_flow import FLOW_PATH, PHYSICAL_STEPS, WEBHOOK_PATH, FlowProbeError


def capabilities() -> dict:
    return {"physical_document_issuance": {"supported": True, "blockers": []},
            "sequences": {"physical_document_issuance": list(PHYSICAL_STEPS)}}


def test_physical_steps_match_language_neutral_flow_contract() -> None:
    contract = json.loads((Path(__file__).resolve().parents[1] / "contracts/flow-service-behavior.json").read_text())
    assert contract["flow_types"]["physical_document_issuance"]["steps"] == list(PHYSICAL_STEPS)


def test_flow_contract_and_unsigned_webhook_denial_are_partial_only() -> None:
    calls = []

    def request(method: str, path: str) -> tuple[int, dict | None]:
        calls.append((method, path))
        return (200, capabilities()) if method == "GET" else (422, {"missing_signature_header": True})

    result = flow_probe.exercise("issuance-native", request)
    assert calls == [("GET", FLOW_PATH), ("POST", WEBHOOK_PATH)]
    assert result["verified"] is True
    assert result["evidence"]["scope"] == "Flow capability and unsigned webhook denial only"
    assert result["evidence"]["unsigned_webhook_http_status"] == 422
    assert result["evidence"]["unsigned_webhook_owner"] == "issuance-native"
    assert "signed" not in result["evidence"]


@pytest.mark.parametrize("flow_status,physical,sequence,webhook_status", [
    (503, {"supported": True, "blockers": []}, list(PHYSICAL_STEPS), 422),
    (200, {"supported": False, "blockers": []}, list(PHYSICAL_STEPS), 422),
    (200, {"supported": True, "blockers": ["missing"]}, list(PHYSICAL_STEPS), 422),
    (200, {"supported": True, "blockers": []}, list(PHYSICAL_STEPS[:-1]), 422),
    (200, {"supported": True, "blockers": []}, list(PHYSICAL_STEPS), 200),
    (200, {"supported": True, "blockers": []}, list(PHYSICAL_STEPS), 401),
])
def test_flow_and_webhook_fail_closed(flow_status, physical, sequence, webhook_status) -> None:
    def request(method: str, path: str) -> tuple[int, dict | None]:
        if method == "GET":
            return flow_status, {"physical_document_issuance": physical,
                                 "sequences": {"physical_document_issuance": sequence}}
        return webhook_status, {"missing_signature_header": True} if webhook_status == 422 else None

    with pytest.raises(FlowProbeError):
        flow_probe.exercise("issuance-native", request)


def test_selected_provider_ingress_requires_its_distinct_denial() -> None:
    def request(method: str, path: str) -> tuple[int, dict | None]:
        return ((200, capabilities()) if method == "GET"
                else (401, {"invalid_signature": True}))

    result = flow_probe.exercise("passport-provider-ingress", request)
    assert result["evidence"]["unsigned_webhook_http_status"] == 401
    assert result["evidence"]["unsigned_webhook_owner"] == "passport-provider-ingress"
    with pytest.raises(FlowProbeError, match="not rejected"):
        flow_probe.exercise("issuance-native", request)


def test_real_request_shape_never_sends_provider_signature_or_tenant_key(monkeypatch) -> None:
    seen = []
    handlers = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self):
            return seen[0].full_url

        def read(self, amount):
            return json.dumps(capabilities()).encode()

    class Opener:
        def open(self, request, timeout):
            seen.append(request)
            if request.get_method() == "POST":
                body = json.dumps({"detail": [{"type": "missing", "loc": ["header", "x-personalization-signature"],
                                                "msg": "Field required", "input": "secret-do-not-report"}]}).encode()
                raise HTTPError(request.full_url, 422, "Unprocessable", {}, BytesIO(body))
            return Response()

    def opener(*args):
        handlers.extend(args)
        return Opener()

    monkeypatch.setattr(flow_probe, "build_opener", opener)
    assert flow_probe.request_beta("GET", FLOW_PATH)[0] == 200
    request = seen[0]
    assert request.full_url == "https://beta.elevenidllc.com/v1/flows/capabilities"
    assert request.get_header("X-api-key") is None
    assert request.get_header("X-personalization-signature") is None
    assert request.get_header("Cookie") is None
    assert any(isinstance(handler, flow_probe.ProxyHandler)
               and handler.proxies == {} for handler in handlers)
    seen.clear()
    assert flow_probe.request_beta("POST", WEBHOOK_PATH) == (422, {"missing_signature_header": True})
    request = seen[0]
    assert request.full_url == "https://beta.elevenidllc.com/v1/passport/webhooks/personalization"
    assert request.data == b"{}"
    assert request.get_header("X-api-key") is None
    assert request.get_header("X-personalization-signature") is None
    assert "secret-do-not-report" not in str(flow_probe.exercise("issuance-native", lambda method, path: (
        (200, capabilities()) if method == "GET" else (422, {"missing_signature_header": True})
    )))


def test_generic_422_is_not_signed_webhook_evidence() -> None:
    with pytest.raises(FlowProbeError, match="not rejected"):
        flow_probe.exercise("issuance-native", lambda method, path: (
            (200, capabilities()) if method == "GET" else (422, {"missing_signature_header": False})
        ))


def test_provider_ingress_http_error_is_projected_without_body(monkeypatch) -> None:
    class Opener:
        def open(self, request, timeout):
            body = json.dumps({"detail": "Invalid personalization webhook signature"}).encode()
            raise HTTPError(request.full_url, 401, "Unauthorized", {}, BytesIO(body))

    monkeypatch.setattr(flow_probe, "build_opener", lambda *args: Opener())
    assert flow_probe.request_beta("POST", WEBHOOK_PATH) == (401, {"invalid_signature": True})
