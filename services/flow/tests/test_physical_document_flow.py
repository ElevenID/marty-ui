from __future__ import annotations

import base64

import pytest

import flow.main as flow_main
from flow.main import (
    FlowDefinition,
    FlowInstance,
    FlowType,
    _execute_physical_document_step,
    _initialize_physical_document_job,
)


@pytest.mark.asyncio
async def test_physical_document_initialization_moves_sensitive_data_out_of_flow_context(monkeypatch):
    captured = {}

    async def fake_request(method, path, *, payload=None):
        captured.update({"method": method, "path": path, "payload": payload})
        return {
            "id": "job-1",
            "application_id": "application-1",
            "status": "DRAFT",
            "secure_artifact_reference": "physical-artifact://job-1",
        }

    monkeypatch.setattr(flow_main, "_physical_document_request", fake_request)
    flow = FlowDefinition(
        organization_id="org-1",
        flow_type=FlowType.PHYSICAL_DOCUMENT_ISSUANCE,
        application_template_id="application-template-1",
        credential_template_id="credential-template-1",
        delivery_destination_profile_id="bureau-1",
    )
    instance = FlowInstance(
        organization_id="org-1",
        context={
            "physical_document": {
                "country_code": "USA",
                "document_type": "TD3",
                "applicant": {"name": "Sensitive Name"},
                "mrz": {"line_1": "sensitive", "line_2": "sensitive"},
                "data_groups": {
                    "DG1": base64.b64encode(b"sensitive-dg1").decode(),
                    "DG2": base64.b64encode(b"sensitive-biometric").decode(),
                },
            },
        },
    )

    await _initialize_physical_document_job(instance, flow)

    assert "physical_document" not in instance.context
    assert instance.context["application_id"] == "application-1"
    assert instance.context["physical_document_job"]["secure_artifact_reference"] == "physical-artifact://job-1"
    assert captured["payload"]["applicant"]["name"] == "Sensitive Name"


@pytest.mark.asyncio
async def test_physical_document_step_dispatch_updates_only_safe_job_state(monkeypatch):
    calls = []

    async def fake_request(method, path, *, payload=None):
        calls.append((method, path, payload))
        return {
            "id": "job-1",
            "application_id": "application-1",
            "status": "SOD_SIGNED",
            "secure_artifact_reference": "physical-artifact://job-1",
        }

    monkeypatch.setattr(flow_main, "_physical_document_request", fake_request)
    instance = FlowInstance(context={
        "physical_document_job": {
            "id": "job-1",
            "application_id": "application-1",
            "status": "DATA_GENERATED",
        }
    })

    await _execute_physical_document_step(instance, "sign_sod", {})

    assert calls == [("POST", "/v1/passport/applications/application-1/generate-sod", None)]
    assert instance.context["physical_document_job"]["status"] == "SOD_SIGNED"
    assert "data_groups" not in instance.context["physical_document_job"]
