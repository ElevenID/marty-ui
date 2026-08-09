from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import flow.main as flow_main
from common.application_event_auth import ApplicationEventEvidence
from flow.infrastructure.models import (
    flow_definitions,
    flow_instance_artifacts,
    flow_instances,
)
from flow.main import (
    ApplicationApprovedWebhook,
    ApplicationOfferConflictError,
    FlowDefinition,
    FlowStatus,
    FlowType,
    InMemoryFlowRepository,
    handle_application_approved,
)


def _evidence() -> ApplicationEventEvidence:
    return ApplicationEventEvidence(
        producer="marty-applicant-service",
        audience="marty-flow-application-approved",
        event_id_sha256="a" * 64,
        payload_sha256="b" * 64,
        authenticated_at="2026-08-09T12:00:00+00:00",
    )


def _event() -> ApplicationApprovedWebhook:
    return ApplicationApprovedWebhook(
        event_type="application.approved",
        aggregate_id="application-1",
        aggregate_type="application",
        organization_id="org-1",
        timestamp="2026-08-09T12:00:00+00:00",
        data={
            "applicant_id": "applicant-1",
            "credential_template_id": "template-1",
            "claims": {"profile": {"level": 2}, "roles": ["student", "member"]},
        },
    )


def _flow() -> FlowDefinition:
    flow = FlowDefinition(
        organization_id="org-1",
        name="Application issuance",
        status=FlowStatus.ACTIVE,
        flow_type=FlowType.CUSTOM,
        credential_template_id="template-1",
        trigger={
            "trigger_type": "WEBHOOK",
            "config": {"event_type": "APPLICATION_APPROVED"},
        },
        extension={
            "extension_uri": "urn:elevenid:test:application-offer-idempotency",
            "extension_version": "1.0.0",
            "extends_flow_type": FlowType.OID4VCI_PRE_AUTHORIZED.value,
            "entry_step_id": "create_offer",
            "steps": [{"step_id": "create_offer", "action": "create_offer"}],
            "transitions": [],
            "config": {},
        },
    )
    return flow


def _issuance_response() -> dict[str, object]:
    return {
        "id": "transaction-1",
        "credential_offer_uri": "openid-credential-offer://?credential_offer=one",
        "credential_offer_uris": {
            "default": "openid-credential-offer://?credential_offer=one"
        },
        "credential_offer_labels": {"default": "Any wallet"},
        "pre_auth_code": "pre-authorized-1",
        "expires_at": "2026-08-10T12:00:00+00:00",
        "status": "pending",
    }


@pytest.mark.asyncio
async def test_same_application_and_flow_recover_one_instance_and_artifact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    async def initiate(_instance, _flow_definition):
        nonlocal calls
        calls += 1
        return _issuance_response()

    monkeypatch.setattr(flow_main, "_initiate_credential_layer_issuance", initiate)
    repo = InMemoryFlowRepository()
    flow = _flow()
    await repo.save_definition(flow)

    first = await handle_application_approved(_event(), repo, _evidence())
    second = await handle_application_approved(_event(), repo, _evidence())

    assert calls == 1
    assert first["instance_ids"] == second["instance_ids"]
    assert first["offers"] == second["offers"]
    assert len(await repo.list_instances("org-1")) == 1
    assert len(await repo.list_artifacts(first["instance_ids"][0])) == 1


@pytest.mark.asyncio
async def test_retry_recovers_after_instance_commit_before_artifact_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    original_save_artifact = InMemoryFlowRepository.save_artifact

    async def initiate(_instance, _flow_definition):
        nonlocal calls
        calls += 1
        return _issuance_response()

    async def fail_first_artifact_save(self, artifact):
        monkeypatch.setattr(
            InMemoryFlowRepository,
            "save_artifact",
            original_save_artifact,
        )
        raise RuntimeError("simulated crash before artifact commit")

    monkeypatch.setattr(flow_main, "_initiate_credential_layer_issuance", initiate)
    monkeypatch.setattr(
        InMemoryFlowRepository,
        "save_artifact",
        fail_first_artifact_save,
    )
    repo = InMemoryFlowRepository()
    await repo.save_definition(_flow())

    interrupted = await handle_application_approved(_event(), repo, _evidence())
    recovered = await handle_application_approved(_event(), repo, _evidence())

    assert interrupted["flows_triggered"] == 0
    assert recovered["flows_triggered"] == 1
    assert calls == 2
    assert len(await repo.list_instances("org-1")) == 1
    assert len(await repo.list_artifacts(recovered["instance_ids"][0])) == 1


@pytest.mark.asyncio
async def test_exact_replay_recovers_only_an_existing_durable_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def initiate(_instance, _flow_definition):
        return _issuance_response()

    monkeypatch.setattr(flow_main, "_initiate_credential_layer_issuance", initiate)
    repo = InMemoryFlowRepository()
    await repo.save_definition(_flow())

    recovered_after_early_crash = await handle_application_approved(
        _event(),
        repo,
        _evidence(),
        replay_recovery_only=True,
    )
    recovered = await handle_application_approved(
        _event(),
        repo,
        _evidence(),
        replay_recovery_only=True,
    )

    assert recovered_after_early_crash["flows_triggered"] == 1
    assert recovered["flows_triggered"] == 1
    assert recovered_after_early_crash["instance_ids"] == recovered["instance_ids"]
    assert recovered["offers"][0]["credential_offer_transaction_id"] == "transaction-1"


@pytest.mark.asyncio
async def test_same_application_flow_rejects_changed_issuance_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def initiate(_instance, _flow_definition):
        return _issuance_response()

    monkeypatch.setattr(flow_main, "_initiate_credential_layer_issuance", initiate)
    repo = InMemoryFlowRepository()
    await repo.save_definition(_flow())
    await handle_application_approved(_event(), repo, _evidence())
    changed = _event()
    changed.data["claims"]["profile"]["level"] = 3

    with pytest.raises(ApplicationOfferConflictError):
        await handle_application_approved(changed, repo, _evidence())

    assert len(await repo.list_instances("org-1")) == 1


@pytest.mark.asyncio
async def test_issuance_grpc_request_preserves_nested_claims_and_retry_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = None

    class Stub:
        def __init__(self, _channel):
            pass

        async def InitiateIssuance(self, request, *, timeout):
            nonlocal captured
            assert timeout == 10.0
            captured = request
            return SimpleNamespace(
                id="transaction-1",
                organization_id="org-1",
                credential_template_id="template-1",
                status="pending",
                credential_offer_uri="openid-credential-offer://offer",
                credential_offer_uris={},
                credential_offer_labels={},
                pre_auth_code="pre-authorized-1",
                expires_at="2026-08-10T12:00:00+00:00",
            )

    from marty_proto.v1 import issuance_service_pb2_grpc

    monkeypatch.setattr(issuance_service_pb2_grpc, "IssuanceServiceStub", Stub)

    async def template(_template_id):
        return SimpleNamespace(issuer_did="did:web:issuer.example")

    monkeypatch.setattr(flow_main, "_get_credential_template_reference", template)
    monkeypatch.setattr(flow_main.app.state, "issuance_grpc_channel", object(), raising=False)
    instance = SimpleNamespace(
        id="instance-1",
        organization_id="org-1",
        subject_id="applicant-1",
        application_flow_key_hash="f" * 64,
        context={
            "application_id": "application-1",
            "claims": {"profile": {"level": 2}, "roles": ["student", "member"]},
        },
    )
    flow = SimpleNamespace(credential_template_id="template-1")

    await flow_main._initiate_credential_layer_issuance(instance, flow)

    assert captured.application_id == "application-1"
    assert captured.issuer_did == "did:web:issuer.example"
    assert captured.delivery_mode == "wallet_only"
    assert captured.idempotency_key == f"application-flow-offer-v1:{'f' * 64}"
    assert json.loads(captured.claims_json) == instance.context["claims"]
    assert dict(captured.claims) == {}


@pytest.mark.asyncio
async def test_issuance_http_fallback_is_authenticated_and_semantically_identical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FailingStub:
        def __init__(self, _channel):
            pass

        async def InitiateIssuance(self, _request, *, timeout):
            assert timeout == 10.0
            raise RuntimeError("uncertain gRPC result")

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return _issuance_response()

    class Client:
        def __init__(self, *, timeout):
            assert timeout == 10.0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, *, headers, json):
            captured.update(url=url, headers=headers, json=json)
            return Response()

    from marty_proto.v1 import issuance_service_pb2_grpc

    monkeypatch.setattr(
        issuance_service_pb2_grpc,
        "IssuanceServiceStub",
        FailingStub,
    )
    monkeypatch.setattr(flow_main.httpx, "AsyncClient", Client)
    monkeypatch.setenv("ISSUANCE_API_KEY", "flow-to-issuance-test-key")

    async def template(_template_id):
        return SimpleNamespace(issuer_did="did:web:issuer.example")

    monkeypatch.setattr(flow_main, "_get_credential_template_reference", template)
    monkeypatch.setattr(flow_main.app.state, "issuance_grpc_channel", object(), raising=False)
    instance = SimpleNamespace(
        id="instance-1",
        organization_id="org-1",
        subject_id="applicant-1",
        application_flow_key_hash="f" * 64,
        context={
            "application_id": "application-1",
            "claims": {"profile": {"level": 2}, "roles": ["student", "member"]},
        },
    )

    result = await flow_main._initiate_credential_layer_issuance(
        instance,
        SimpleNamespace(credential_template_id="template-1"),
    )

    assert result["id"] == "transaction-1"
    assert captured["headers"] == {
        "X-API-Key": "flow-to-issuance-test-key",
        "Idempotency-Key": f"application-flow-offer-v1:{'f' * 64}",
    }
    assert captured["json"] == {
        "organization_id": "org-1",
        "credential_template_id": "template-1",
        "application_id": "application-1",
        "applicant_id": "applicant-1",
        "subject_did": None,
        "holder_did": None,
        "issuer_did": "did:web:issuer.example",
        "delivery_mode": "wallet_only",
        "claims": instance.context["claims"],
    }


def test_durable_flow_storage_contract_is_tenant_scoped() -> None:
    instance_constraints = {constraint.name for constraint in flow_instances.constraints}
    definition_constraints = {
        constraint.name for constraint in flow_definitions.constraints
    }
    assert "ck_flow_instances_application_flow_key_hash" in instance_constraints
    assert "ck_flow_instances_application_flow_key_hash" not in definition_constraints
    unique_indexes = {
        index.name: tuple(column.name for column in index.columns)
        for index in flow_instances.indexes
        if index.unique
    }
    assert unique_indexes["ux_flow_instances_org_application_flow_key"] == (
        "organization_id",
        "application_flow_key_hash",
    )
    unique_artifact_indexes = {
        index.name: tuple(column.name for column in index.columns)
        for index in flow_instance_artifacts.indexes
        if index.unique
    }
    assert unique_artifact_indexes[
        "ux_flow_instance_artifacts_issuance_transaction_id"
    ] == ("issuance_transaction_id",)
    assert flow_instance_artifacts.c.credential_offer_uris.nullable is False
