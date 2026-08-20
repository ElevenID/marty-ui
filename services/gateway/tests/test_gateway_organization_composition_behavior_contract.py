from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from gateway.models import OrganizationLifecycleResponse
from gateway.routes import organizations


CONTRACT = json.loads(
    (
        Path(__file__).parents[3]
        / "contracts"
        / "gateway-organization-composition-behavior.json"
    ).read_text(encoding="utf-8")
)


async def _runtime(service_name: str, path: str, **kwargs):
    mapping = {
        "credential-templates": CONTRACT["runtime_inputs"]["templates"],
        "presentation-policies": CONTRACT["runtime_inputs"]["policies"],
        "deployment-profiles": CONTRACT["runtime_inputs"]["deployments"],
        "flows": CONTRACT["runtime_inputs"]["flows"],
    }
    return mapping[service_name], None


def _project_lifecycle(value: dict) -> dict:
    fields = OrganizationLifecycleResponse.model_fields
    return OrganizationLifecycleResponse.model_validate(
        {key: value[key] for key in fields if key in value}
    ).model_dump(mode="json")


async def test_legacy_gateway_executes_shared_composition_contract(monkeypatch) -> None:
    assert CONTRACT["schema_version"] == 1
    monkeypatch.setattr(organizations, "_request_service_json_with_headers", _runtime)
    runtime, error = await organizations._load_runtime_status_payload("org-1")
    assert error is None
    assert runtime == CONTRACT["expected_runtime"]

    async def applicants(*args, **kwargs):
        return CONTRACT["applicants"], None

    monkeypatch.setattr(organizations, "_request_service_json_with_headers", applicants)
    stats, error = await organizations._load_applicant_stats_payload("org-1")
    assert error is None
    assert stats == CONTRACT["expected_applicant_stats"]

    async def lifecycle(service_name: str, path: str, **kwargs):
        return (
            CONTRACT["lifecycle"] if service_name == "organizations" else CONTRACT["retention_summary"],
            None,
        )

    monkeypatch.setattr(organizations, "_request_service_json_with_headers", lifecycle)
    composed, error = await organizations._load_organization_lifecycle_payload("org-1")
    assert error is None
    assert _project_lifecycle(composed) == CONTRACT["expected_lifecycle"]

    assert organizations._retention_window_days(CONTRACT["lifecycle"]) == 30
    now = organizations._parse_iso_timestamp(CONTRACT["sweep_now"])
    assert now == datetime.fromisoformat("2026-04-13T12:00:00+00:00")
