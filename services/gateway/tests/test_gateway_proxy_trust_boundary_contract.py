from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Response
from starlette.requests import Request

from gateway.routes import (
    applicants,
    canvas_integrations,
    issuance,
    organizations,
    revocation,
)


CONTRACT = json.loads(
    (Path(__file__).parents[3] / "contracts" / "gateway-proxy-trust-boundary.json").read_text(
        encoding="utf-8"
    )
)


def _request(method: str, path: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],
            "query_string": b"",
            "server": ("gateway", 8000),
            "scheme": "http",
        }
    )


@pytest.mark.asyncio
async def test_legacy_routes_execute_shared_issuance_service_auth_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CONTRACT["schema_version"] == 1
    calls: list[dict] = []

    async def proxy_request(request, service_url, path, **kwargs):
        calls.append(
            {
                "request_path": request.url.path,
                "service_url": service_url,
                "path": path,
                "required": (kwargs.get("inject_headers") or {}).get("X-API-Key")
                == "service-secret",
            }
        )
        return Response(content=b"{}", status_code=500, media_type="application/json")

    registry = SimpleNamespace(
        get_service_url=lambda service: {
            "issuance": "http://issuance",
            "applicant": "http://applicant",
        }[service]
    )
    for module in (issuance, canvas_integrations, applicants):
        monkeypatch.setattr(module, "proxy_request", proxy_request)
        monkeypatch.setattr(module, "get_registry", lambda: registry)
        monkeypatch.setattr(module, "_ISSUANCE_HEADERS", {"X-API-Key": "service-secret"})

    invocations = {
        "wallet_token": lambda: issuance.exchange_token(
            _request("POST", "/v1/issuance/token")
        ),
        "wallet_offer": lambda: issuance.get_credential_offer(
            "tx-1", _request("GET", "/v1/issuance/offers/tx-1")
        ),
        "management_transaction": lambda: issuance.get_issuance(
            "tx-1", _request("GET", "/v1/issuance/tx-1")
        ),
        "application_template": lambda: issuance.get_application_template(
            "template-1", _request("GET", "/v1/application-templates/template-1")
        ),
        "issued_credential": lambda: issuance.get_issued_credential(
            "credential-1", _request("GET", "/v1/issued-credentials/credential-1")
        ),
        "canvas_platform_management": lambda: canvas_integrations.list_canvas_platforms(
            _request("GET", "/v1/integrations/canvas/platforms")
        ),
        "oauth_authorization": lambda: issuance.authorize_issuance(
            _request("GET", "/v1/issuance/authorize")
        ),
        "canvas_public_jwks": lambda: canvas_integrations.get_canvas_lti_tool_jwks(
            _request("GET", "/v1/integrations/canvas/lti/jwks")
        ),
        "canvas_oauth_callback": lambda: canvas_integrations.complete_canvas_oauth_connection(
            _request("GET", "/v1/integrations/canvas/oauth/callback")
        ),
        "canvas_signed_ingress": lambda: canvas_integrations.process_canvas_evidence_event(
            _request("POST", "/v1/integrations/canvas/evidence-events")
        ),
        "canvas_lti_launch": lambda: canvas_integrations.verify_canvas_lti_launch(
            "platform-1",
            _request("POST", "/v1/integrations/canvas/lti/platforms/platform-1/launch"),
        ),
        "holder_inventory": lambda: issuance.list_my_issued_credentials(
            _request("GET", "/v1/issued-credentials/mine")
        ),
    }

    for expected in CONTRACT["issuance_service_auth"]:
        calls.clear()
        await invocations[expected["name"]]()
        assert len(calls) == 1, expected["name"]
        assert calls[0]["required"] is expected["required"], expected["name"]


@pytest.mark.asyncio
async def test_legacy_routes_execute_shared_special_routing_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict] = []

    async def proxy_request(request, service_url, path, **kwargs):
        calls.append(
            {
                "service_url": service_url,
                "path": path,
                "required": (kwargs.get("inject_headers") or {}).get("X-API-Key")
                == "service-secret",
            }
        )
        return Response(content=b"{}", status_code=500, media_type="application/json")

    registry = SimpleNamespace(
        get_service_url=lambda service: f"http://{service}"
    )
    for module in (issuance, organizations, revocation, applicants):
        monkeypatch.setattr(module, "proxy_request", proxy_request)
        monkeypatch.setattr(module, "get_registry", lambda: registry)
    monkeypatch.setattr(applicants, "_ISSUANCE_HEADERS", {"X-API-Key": "service-secret"})

    invocations = {
        "/v1/me/preferences": lambda: organizations.get_preferences(
            _request("GET", "/v1/me/preferences")
        ),
        "/v1/issued-credentials/mine": lambda: issuance.list_my_issued_credentials(
            _request("GET", "/v1/issued-credentials/mine")
        ),
        "/v1/organizations/org-1/applicants": lambda: applicants.list_organization_applicants(
            "org-1", _request("GET", "/v1/organizations/org-1/applicants")
        ),
        "/v1/organizations/org-1/revocation-profiles/profile-1/status-lists/bitstring/revocation": lambda: revocation.get_status_list_document(
            "org-1",
            "profile-1",
            "bitstring",
            "revocation",
            _request(
                "GET",
                "/v1/organizations/org-1/revocation-profiles/profile-1/status-lists/bitstring/revocation",
            ),
        ),
        "/v1/organizations/org-1/applicants/app-1/evidence-summary": lambda: applicants.get_organization_applicant_evidence_summary(
            "org-1",
            "app-1",
            _request(
                "GET",
                "/v1/organizations/org-1/applicants/app-1/evidence-summary",
            ),
        ),
        "/v1/organizations/org-1/applicants/app-1/evidence-facts": lambda: applicants.list_organization_applicant_evidence_facts(
            "org-1",
            "app-1",
            _request(
                "GET",
                "/v1/organizations/org-1/applicants/app-1/evidence-facts",
            ),
        ),
        "/v1/organizations/org-1/applicants/app-1/evidence/api-checks/check-1/run": lambda: applicants.run_organization_applicant_evidence_check(
            "org-1",
            "app-1",
            "check-1",
            _request(
                "POST",
                "/v1/organizations/org-1/applicants/app-1/evidence/api-checks/check-1/run",
            ),
        ),
    }

    for expected in CONTRACT["special_ownership"]:
        if expected["gateway_owned"]:
            continue
        calls.clear()
        await invocations[expected["path"]]()
        assert calls == [
            {
                "service_url": f"http://{expected['service']}",
                "path": expected["upstream_path"],
                "required": expected["service"] == "issuance",
            }
        ]
