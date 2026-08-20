"""Run public gateway discovery fixtures against the Python baseline."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from gateway import main as gateway_main
from gateway.mip_configuration import mip_configuration_document
from gateway.release_metadata import release_metadata


CONTRACT = json.loads(
    (Path(__file__).parents[3] / "contracts" / "gateway-discovery-behavior.json").read_text(
        encoding="utf-8"
    )
)


def test_python_mip_and_release_documents_match_shared_contract(monkeypatch) -> None:
    assert CONTRACT["schema_version"] == 1
    assert mip_configuration_document(
        CONTRACT["base_url"], CONTRACT["compliance_profiles"]
    ) == CONTRACT["mip_configuration"]

    release_input = CONTRACT["release"]["input"]
    monkeypatch.setenv("MARTY_RELEASE_VERSION", release_input["release_version"])
    monkeypatch.setenv("ELEVENID_STACK_VERSION", release_input["stack_version"])
    monkeypatch.setenv("MARTY_UI_SHA", release_input["marty_ui_sha"])
    monkeypatch.setenv(
        "ELEVENID_IMAGE_DIGESTS_JSON", json.dumps(release_input["image_digests"])
    )
    assert release_metadata() == CONTRACT["release"]["expected"]

    metadata = CONTRACT["issuer_metadata"]
    assert gateway_main._normalize_oid4vci_issuer_metadata(metadata["input"]) == metadata[
        "default_expected"
    ]
    assert gateway_main._normalize_oid4vci_issuer_metadata(
        metadata["input"], wallet_variant="waltid"
    ) == metadata["waltid_expected"]


@pytest.mark.asyncio
async def test_python_openid_configuration_matches_shared_contract(monkeypatch) -> None:
    monkeypatch.setenv("ISSUER_BASE_URL", CONTRACT["base_url"])
    transport = httpx.ASGITransport(app=gateway_main.create_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/.well-known/openid-configuration")
    assert response.status_code == 200
    assert response.json() == CONTRACT["openid_configuration"]


@pytest.mark.asyncio
async def test_python_well_known_route_mapping_matches_shared_contract(monkeypatch) -> None:
    class Registry:
        @staticmethod
        def get_service_url(name: str) -> str:
            assert name == "issuance"
            return "http://issuance"

    requested: list[str] = []

    class Client:
        async def get(self, url: str, *, timeout: float):
            requested.append(url)
            assert timeout == 10.0
            return httpx.Response(
                200,
                json={"credential_configurations_supported": {}},
                headers={"content-type": "application/json"},
            )

    monkeypatch.setattr(gateway_main, "get_registry", lambda: Registry())
    monkeypatch.setattr(gateway_main, "get_http_client", lambda: Client())
    app = gateway_main.create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for case in CONTRACT["well_known_plans"]:
            response = await client.get(case["path"])
            assert response.status_code == 200, case["path"]
            assert requested[-1] == f"http://issuance{case['upstream_path']}"
