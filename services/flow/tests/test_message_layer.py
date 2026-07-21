from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from fastapi import HTTPException
from jwcrypto import jwt as jwcrypto_jwt
from starlette.requests import Request

import flow.main as flow_main
from marty_common.messages import MessageType
from flow.main import (
    ApplicationApprovedWebhook,
    _DC_API_PROTOCOL,
    CreateFlowDefinitionRequest,
    FlowDefinition,
    FlowStatus,
    FlowInstance,
    FlowInstanceStatus,
    FlowType,
    StartVerificationFlowRequest,
    DigitalCredentialSubmissionRequest,
    InMemoryFlowRepository,
    _base58_encode,
    _build_presentation_definition,
    _create_oid4vci_artifact,
    _dcql_claims_for_descriptor,
    _oid4vp_did_web_document,
    _select_vp_token_for_evaluation,
    _validate_credential_layer_references,
    _verify_vp_jwt_signature,
    handle_application_approved,
    get_verification_request_object,
    submit_digital_credential_response,
    start_verification_flow,
    submit_verification_response,
    update_flow_definition,
)


@pytest.fixture(autouse=True)
def clear_nonce_replay_cache(monkeypatch):
    flow_main._used_nonces.clear()
    flow_main._nonce_last_cleanup = 0.0
    monkeypatch.setattr(flow_main, "_nonce_redis", None)
    yield
    flow_main._used_nonces.clear()


def _jwt_segment(payload: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()


def _raw_segment(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def _decode_jwt_segment(segment: str) -> dict:
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode((segment + padding).encode()).decode())


def _form_request(values: dict[str, str]) -> Request:
    body = urlencode(values).encode()
    delivered = False

    async def receive():
        nonlocal delivered
        if delivered:
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/flows/instances/example/request",
            "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
        },
        receive,
    )


def _install_reference_validation_stubs(monkeypatch, *, templates, policies):
    class FakeCredentialTemplateStub:
        def __init__(self, _channel):
            pass

        async def GetTemplate(self, request):
            template = templates.get(request.template_id)
            if template is None:
                return SimpleNamespace(id="")
            template_payload = {
                "issuer_profile_id": "issuer-profile-1",
                "key_access_mode": "REMOTE_SIGNING",
            }
            template_payload.update(template)
            return SimpleNamespace(
                id=request.template_id,
                **template_payload,
            )

    class FakePresentationPolicyStub:
        def __init__(self, _channel):
            pass

        async def GetPolicy(self, request):
            policy = policies.get(request.policy_id)
            if policy is None:
                return SimpleNamespace(id="")
            return SimpleNamespace(id=request.policy_id, **policy)

    monkeypatch.setattr(
        "marty_proto.v1.credential_template_service_pb2_grpc.CredentialTemplateServiceStub",
        FakeCredentialTemplateStub,
    )
    monkeypatch.setattr(
        "marty_proto.v1.presentation_policy_service_pb2_grpc.PresentationPolicyServiceStub",
        FakePresentationPolicyStub,
    )
    monkeypatch.setattr("flow.main.app.state.ct_grpc_channel", object(), raising=False)
    monkeypatch.setattr("flow.main.app.state.pp_grpc_channel", object(), raising=False)


class _FakeMembership:
    def __init__(self, permissions: set[str] | None = None):
        self.permissions = permissions or set()
        self.status = "active"

    def is_active(self) -> bool:
        return True

    def has_permission(self, resource: str, action: str | None = None) -> bool:
        permission = resource if action is None else f"{resource}:{action}"
        return permission in self.permissions


class _FakeOrgClient:
    def __init__(self, membership: _FakeMembership):
        self.membership = membership
        self.calls: list[tuple[str, str]] = []

    async def get_membership(self, user_id: str, organization_id: str):
        self.calls.append((user_id, organization_id))
        return self.membership


def _install_org_client(monkeypatch, *, permissions: set[str]):
    org_client = _FakeOrgClient(_FakeMembership(permissions))

    async def _fake_get_organization_client(_request):
        return org_client

    monkeypatch.setattr(flow_main, "get_organization_client", _fake_get_organization_client)
    return org_client


def _ed25519_did_key(public_key) -> str:
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    multicodec = b"\xed\x01" + public_bytes
    return f"did:key:z{_base58_encode(multicodec)}"


def _signed_eddsa_jwt(payload: dict, private_key, did: str) -> str:
    header = _jwt_segment({"alg": "EdDSA", "kid": f"{did}#{did.removeprefix('did:key:')}"})
    body = _jwt_segment(payload)
    signing_input = f"{header}.{body}".encode()
    signature = private_key.sign(signing_input)
    return f"{header}.{body}.{_raw_segment(signature)}"


def _encrypted_dc_api_response(payload: dict) -> str:
    jwcrypto_jwe = pytest.importorskip("jwcrypto.jwe")
    jwcrypto_jwk = pytest.importorskip("jwcrypto.jwk")
    public_key = jwcrypto_jwk.JWK.from_json(json.dumps(flow_main._verifier_encryption_public_jwk()))
    token = jwcrypto_jwe.JWE(
        json.dumps(payload, separators=(",", ":")).encode(),
        protected={
            "alg": flow_main._HAIP_JWE_ALG,
            "enc": flow_main._HAIP_JWE_ENC,
            "kid": flow_main._HAIP_ENCRYPTION_KEY_ID,
        },
    )
    token.add_recipient(public_key)
    return token.serialize(compact=True)


def _encrypted_response_for_key(payload: dict, public_jwk: dict) -> str:
    jwcrypto_jwe = pytest.importorskip("jwcrypto.jwe")
    jwcrypto_jwk = pytest.importorskip("jwcrypto.jwk")
    key = jwcrypto_jwk.JWK.from_json(json.dumps(public_jwk))
    token = jwcrypto_jwe.JWE(
        json.dumps(payload, separators=(",", ":")).encode(),
        protected={
            "alg": flow_main._HAIP_JWE_ALG,
            "enc": flow_main._HAIP_JWE_ENC,
            "kid": public_jwk["kid"],
        },
    )
    token.add_recipient(key)
    return token.serialize(compact=True)


@pytest.mark.asyncio
async def test_validate_credential_layer_references_accepts_active_template_and_policy(monkeypatch):
    _install_reference_validation_stubs(
        monkeypatch,
        templates={
            "template-1": {"organization_id": "org-1", "status": "active"},
            "template-2": {"organization_id": "org-1", "status": "active"},
        },
        policies={
            "policy-1": {
                "organization_id": "org-1",
                "status": "active",
                "credential_requirements_json": json.dumps([
                    {"credential_template_id": "template-2"}
                ]),
            }
        },
    )

    await _validate_credential_layer_references(
        organization_id="org-1",
        credential_template_id="template-1",
        presentation_policy_id="policy-1",
        require_active=True,
    )


@pytest.mark.asyncio
async def test_validate_credential_layer_references_rejects_org_mismatch(monkeypatch):
    _install_reference_validation_stubs(
        monkeypatch,
        templates={"template-1": {"organization_id": "other-org", "status": "active"}},
        policies={},
    )

    with pytest.raises(HTTPException) as exc_info:
        await _validate_credential_layer_references(
            organization_id="org-1",
            credential_template_id="template-1",
        )

    assert exc_info.value.status_code == 400
    assert "other-org" in exc_info.value.detail


@pytest.mark.asyncio
async def test_validate_credential_layer_references_requires_active_for_activation(monkeypatch):
    _install_reference_validation_stubs(
        monkeypatch,
        templates={"template-1": {"organization_id": "org-1", "status": "draft"}},
        policies={},
    )

    with pytest.raises(HTTPException) as exc_info:
        await _validate_credential_layer_references(
            organization_id="org-1",
            credential_template_id="template-1",
            require_active=True,
        )

    assert exc_info.value.status_code == 400
    assert "must be active" in exc_info.value.detail


@pytest.mark.asyncio
async def test_validate_credential_layer_references_rejects_template_without_kms_issuer(monkeypatch):
    _install_reference_validation_stubs(
        monkeypatch,
        templates={
            "template-legacy": {
                "organization_id": "org-1",
                "status": "active",
                "issuer_profile_id": "",
                "key_access_mode": "LOCAL",
            }
        },
        policies={},
    )

    with pytest.raises(HTTPException) as exc_info:
        await _validate_credential_layer_references(
            organization_id="org-1",
            credential_template_id="template-legacy",
        )

    assert exc_info.value.status_code == 400
    assert "KMS-backed issuer profile" in exc_info.value.detail


@pytest.mark.asyncio
async def test_validate_credential_layer_references_validates_policy_requirement_templates(monkeypatch):
    _install_reference_validation_stubs(
        monkeypatch,
        templates={"template-1": {"organization_id": "other-org", "status": "active"}},
        policies={
            "policy-1": {
                "organization_id": "org-1",
                "status": "active",
                "credential_requirements_json": json.dumps([
                    {"credential_template_id": "template-1"}
                ]),
            }
        },
    )

    with pytest.raises(HTTPException) as exc_info:
        await _validate_credential_layer_references(
            organization_id="org-1",
            presentation_policy_id="policy-1",
            require_active=True,
        )

    assert exc_info.value.status_code == 400
    assert "Credential template template-1" in exc_info.value.detail


@pytest.mark.asyncio
async def test_update_flow_definition_replaces_existing_flow_and_checks_edit_permission(monkeypatch):
    _install_reference_validation_stubs(
        monkeypatch,
        templates={"template-new": {"organization_id": "org-1", "status": "active"}},
        policies={},
    )
    org_client = _install_org_client(monkeypatch, permissions={"flow-definition:edit"})

    repo = InMemoryFlowRepository()
    flow = FlowDefinition(
        organization_id="org-1",
        name="Old flow",
        flow_type=FlowType.OID4VCI_PRE_AUTHORIZED,
        credential_template_id="template-old",
    )
    flow.activate()
    await repo.save_definition(flow)

    response = await update_flow_definition(
        flow.id,
        CreateFlowDefinitionRequest(
            organization_id="org-1",
            name="Updated flow",
            description="Updated description",
            flow_type="oid4vci_pre_authorized",
            credential_template_id="template-new",
        ),
        SimpleNamespace(),
        user_id="user-1",
        repo=repo,
    )

    updated = await repo.get_definition(flow.id)
    assert response.id == flow.id
    assert response.name == "Updated flow"
    assert response.status == FlowStatus.DRAFT.value
    assert response.resolved_steps == [
        "create_offer",
        "token_exchange",
        "credential_request",
        "issue_credential",
    ]
    assert updated is not None
    assert updated.version == 2
    assert updated.credential_template_id == "template-new"
    assert updated.steps[0].config == {"protocol_step": "create_offer"}
    assert org_client.calls == [("user-1", "org-1")]


@pytest.mark.asyncio
async def test_update_flow_definition_rejects_organization_change(monkeypatch):
    _install_org_client(monkeypatch, permissions={"flow-definition:edit"})

    repo = InMemoryFlowRepository()
    flow = FlowDefinition(
        organization_id="org-1",
        name="Org-owned flow",
        flow_type=FlowType.OID4VCI_PRE_AUTHORIZED,
        credential_template_id="template-1",
    )
    await repo.save_definition(flow)

    with pytest.raises(HTTPException) as exc_info:
        await update_flow_definition(
            flow.id,
            CreateFlowDefinitionRequest(
                organization_id="org-2",
                name="Moved flow",
                flow_type="oid4vci_pre_authorized",
                credential_template_id="template-1",
            ),
            SimpleNamespace(),
            user_id="user-1",
            repo=repo,
        )

    assert exc_info.value.status_code == 400
    assert "organization_id cannot be changed" in exc_info.value.detail


@pytest.mark.asyncio
async def test_update_flow_definition_allows_inactive_references_while_draft(monkeypatch):
    _install_reference_validation_stubs(
        monkeypatch,
        templates={"template-draft": {"organization_id": "org-1", "status": "draft"}},
        policies={},
    )
    _install_org_client(monkeypatch, permissions={"flow-definition:edit"})

    repo = InMemoryFlowRepository()
    flow = FlowDefinition(
        organization_id="org-1",
        name="Draft flow",
        flow_type=FlowType.OID4VCI_PRE_AUTHORIZED,
        credential_template_id="template-old",
    )
    await repo.save_definition(flow)

    response = await update_flow_definition(
        flow.id,
        CreateFlowDefinitionRequest(
            organization_id="org-1",
            name="Draft dependency flow",
            flow_type="oid4vci_pre_authorized",
            credential_template_id="template-draft",
        ),
        SimpleNamespace(),
        user_id="user-1",
        repo=repo,
    )

    assert response.status == FlowStatus.DRAFT.value


@pytest.mark.asyncio
async def test_create_oid4vci_artifact_records_credential_offer_message(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://issuer.example")

    async def _fake_initiate_issuance(instance, flow_def):
        return {
            "id": "tx-123",
            "credential_offer_uri": "openid-credential-offer://?credential_offer=tx-123",
            "credential_offer_uris": {"default": "openid-credential-offer://?credential_offer=tx-123"},
            "credential_offer_labels": {"default": "Any OID4VCI Wallet"},
            "pre_auth_code": "pre-auth-123",
            "expires_at": "2026-05-05T12:00:00+00:00",
            "status": "offer_created",
        }

    monkeypatch.setattr(flow_main, "_initiate_credential_layer_issuance", _fake_initiate_issuance)

    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="flow-1",
        organization_id="org-1",
        status=FlowInstanceStatus.PENDING,
    )
    await repo.save_instance(instance)

    flow_def = FlowDefinition(
        organization_id="org-1",
        name="OID4VCI issuance",
        flow_type=FlowType.OID4VCI_PRE_AUTHORIZED,
        credential_template_id="template-123",
    )

    artifact = await _create_oid4vci_artifact(instance, flow_def, repo)

    assert artifact is not None
    assert artifact.credential_offer_uri == "openid-credential-offer://?credential_offer=tx-123"
    assert artifact.pre_authorized_code == "pre-auth-123"
    assert artifact.state == "tx-123"
    assert instance.context["credential_offer_transaction_id"] == "tx-123"
    assert instance.context["credential_offer_uris"] == {"default": "openid-credential-offer://?credential_offer=tx-123"}
    assert instance.context["credential_offer_labels"] == {"default": "Any OID4VCI Wallet"}
    assert instance.context["issuance_status"] == "offer_created"
    message = instance.context["mip_messages"]["credential_offer"]
    assert message["message_type"] == MessageType.CREDENTIAL_OFFER.value
    assert message["correlation_id"] == instance.id
    assert message["payload"]["credential_issuer"] == "https://issuer.example"
    assert message["payload"]["credential_configuration_ids"] == ["template-123"]
    assert message["payload"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"] == "pre-auth-123"
    assert message["payload"]["mip_flow_instance_id"] == instance.id


def _application_approved_custom_flow(*, name: str, credential_template_id: str) -> FlowDefinition:
    return FlowDefinition(
        organization_id="org-1",
        name=name,
        flow_type=FlowType.CUSTOM,
        credential_template_id=credential_template_id,
        trigger={"trigger_type": "WEBHOOK", "config": {"event_type": "APPLICATION_APPROVED"}},
        extension={
            "extension_uri": "urn:elevenid:test:application-approved",
            "extension_version": "1.0.0",
            "extends_flow_type": FlowType.OID4VCI_PRE_AUTHORIZED.value,
            "entry_step_id": "create_offer",
            "steps": [{"step_id": "create_offer", "action": "create_offer", "config": {}}],
            "transitions": [],
            "config": {},
        },
    )


@pytest.mark.asyncio
async def test_application_approved_webhook_filters_by_credential_template_id(monkeypatch):
    captured_claims = {}

    async def _fake_initiate_issuance(instance, flow_def):
        captured_claims.update(instance.context["claims"])
        return {
            "id": f"tx-{flow_def.credential_template_id}",
            "credential_offer_uri": f"openid-credential-offer://?credential_offer={flow_def.credential_template_id}",
            "credential_offer_uris": {"default": f"openid-credential-offer://?credential_offer={flow_def.credential_template_id}"},
            "credential_offer_labels": {"default": "Any OID4VCI Wallet"},
            "pre_auth_code": f"pre-{flow_def.credential_template_id}",
            "expires_at": "2026-05-05T12:00:00+00:00",
            "status": "offer_created",
        }

    monkeypatch.setattr(flow_main, "_initiate_credential_layer_issuance", _fake_initiate_issuance)

    repo = InMemoryFlowRepository()
    matching_flow = _application_approved_custom_flow(
        name="Issue Open Badge",
        credential_template_id="template-open-badge",
    )
    matching_flow.activate()
    await repo.save_definition(matching_flow)

    non_matching_flow = _application_approved_custom_flow(
        name="Issue Different Credential",
        credential_template_id="template-other",
    )
    non_matching_flow.activate()
    await repo.save_definition(non_matching_flow)

    result = await handle_application_approved(
        ApplicationApprovedWebhook(
            event_type="application.approved",
            aggregate_id="application-1",
            aggregate_type="application",
            organization_id="org-1",
            timestamp="2026-05-05T12:00:00+00:00",
            data={
                "applicant_id": "applicant-1",
                "credential_template_id": "template-open-badge",
                "email": "must-not-be-read-from-event-metadata@example.com",
                "application_status": "approved",
                "claims": {
                    "email": "holder@example.com",
                    "member_id": "user-1",
                    "organization_id": "org-1",
                    "issued_at": "2026-05-05T12:00:00+00:00",
                    "role": "applicant",
                },
            },
        ),
        repo=repo,
    )

    assert result["success"] is True
    assert result["flows_triggered"] == 1
    assert len(result["offers"]) == 1
    offer = result["offers"][0]
    assert offer["flow_definition_id"] == matching_flow.id
    assert offer["credential_offer_transaction_id"] == "tx-template-open-badge"
    assert offer["credential_offer_uri"].startswith("openid-credential-offer://")
    assert offer["issuance_status"] == "offer_created"
    assert captured_claims == {
        "email": "holder@example.com",
        "member_id": "user-1",
        "organization_id": "org-1",
        "issued_at": "2026-05-05T12:00:00+00:00",
        "role": "applicant",
    }


@pytest.mark.asyncio
async def test_application_approved_webhook_skips_malformed_trigger(monkeypatch):
    async def _fake_initiate_issuance(instance, flow_def):
        return {
            "id": f"tx-{flow_def.id}",
            "credential_offer_uri": f"openid-credential-offer://?credential_offer={flow_def.id}",
            "credential_offer_uris": {},
            "credential_offer_labels": {},
            "pre_auth_code": f"pre-{flow_def.id}",
            "expires_at": "2026-05-05T12:00:00+00:00",
            "status": "offer_created",
        }

    monkeypatch.setattr(flow_main, "_initiate_credential_layer_issuance", _fake_initiate_issuance)

    repo = InMemoryFlowRepository()
    malformed_flow = _application_approved_custom_flow(
        name="Malformed trigger",
        credential_template_id="template-open-badge",
    )
    malformed_flow.trigger = "application_approved"
    malformed_flow.activate()
    await repo.save_definition(malformed_flow)

    valid_flow = _application_approved_custom_flow(
        name="Canonical trigger",
        credential_template_id="template-open-badge",
    )
    valid_flow.activate()
    await repo.save_definition(valid_flow)

    result = await handle_application_approved(
        ApplicationApprovedWebhook(
            event_type="application.approved",
            aggregate_id="application-malformed-trigger",
            aggregate_type="application",
            organization_id="org-1",
            timestamp="2026-05-05T12:00:00+00:00",
            data={
                "applicant_id": "applicant-1",
                "credential_template_id": "template-open-badge",
            },
        ),
        repo=repo,
    )

    assert result["success"] is True
    assert result["flows_triggered"] == 1
    assert result["offers"][0]["flow_definition_id"] == valid_flow.id


@pytest.mark.asyncio
async def test_application_approved_webhook_returns_zero_when_template_not_found():
    repo = InMemoryFlowRepository()
    flow_def = _application_approved_custom_flow(
        name="Issue Open Badge",
        credential_template_id="template-open-badge",
    )
    flow_def.activate()
    await repo.save_definition(flow_def)

    result = await handle_application_approved(
        ApplicationApprovedWebhook(
            event_type="application.approved",
            aggregate_id="application-2",
            aggregate_type="application",
            organization_id="org-1",
            timestamp="2026-05-05T12:00:00+00:00",
            data={
                "applicant_id": "applicant-2",
                "credential_template_id": "template-missing",
            },
        ),
        repo=repo,
    )

    assert result["success"] is True
    assert result["flows_triggered"] == 0
    assert "No active custom OID4VCI extension" in result["reason"]
    assert "template-missing" in result["reason"]


@pytest.mark.asyncio
async def test_application_approved_webhook_requires_explicit_custom_trigger(monkeypatch):
    async def _fake_initiate_issuance(instance, flow_def):
        tx = f"tx-{flow_def.id}"
        instance.context["credential_offer_transaction_id"] = tx
        instance.context["credential_offer_uri"] = f"openid-credential-offer://?credential_offer_uri={tx}"
        instance.context["credential_offer_uris"] = {"wr-default": instance.context["credential_offer_uri"]}
        instance.context["credential_offer_labels"] = {"wr-default": "Any Wallet"}
        instance.context["issuance_status"] = "offer_created"
        return {
            "transaction_id": tx,
            "credential_offer_uri": instance.context["credential_offer_uri"],
            "credential_offer_uris": instance.context["credential_offer_uris"],
            "credential_offer_labels": instance.context["credential_offer_labels"],
            "status": "offer_created",
        }

    monkeypatch.setattr(flow_main, "_initiate_credential_layer_issuance", _fake_initiate_issuance)

    repo = InMemoryFlowRepository()
    flow_def = FlowDefinition(
        organization_id="org-1",
        name="Issue Open Badge (No Preconditions)",
        flow_type=FlowType.OID4VCI_PRE_AUTHORIZED,
        credential_template_id="template-open-badge",
        preconditions=[],
    )
    flow_def.activate()
    await repo.save_definition(flow_def)

    result = await handle_application_approved(
        ApplicationApprovedWebhook(
            event_type="application.approved",
            aggregate_id="application-3",
            aggregate_type="application",
            organization_id="org-1",
            timestamp="2026-05-05T12:00:00+00:00",
            data={
                "applicant_id": "applicant-3",
                "credential_template_id": "template-open-badge",
                "triggered_by_event": "application.manual_issue",
            },
        ),
        repo=repo,
    )

    assert result["success"] is False
    assert result["flows_triggered"] == 0
    assert "custom OID4VCI extension" in result["reason"]
    assert "offers" not in result


@pytest.mark.asyncio
async def test_application_approved_webhook_ignores_other_template_flows(monkeypatch):
    async def _fake_initiate_issuance(instance, flow_def):
        tx = f"tx-{flow_def.id}"
        instance.context["credential_offer_transaction_id"] = tx
        instance.context["credential_offer_uri"] = f"openid-credential-offer://?credential_offer_uri={tx}"
        instance.context["credential_offer_uris"] = {"wr-default": instance.context["credential_offer_uri"]}
        instance.context["credential_offer_labels"] = {"wr-default": "Any Wallet"}
        instance.context["issuance_status"] = "offer_created"
        return {
            "transaction_id": tx,
            "credential_offer_uri": instance.context["credential_offer_uri"],
            "credential_offer_uris": instance.context["credential_offer_uris"],
            "credential_offer_labels": instance.context["credential_offer_labels"],
            "status": "offer_created",
        }

    monkeypatch.setattr(flow_main, "_initiate_credential_layer_issuance", _fake_initiate_issuance)

    repo = InMemoryFlowRepository()
    flow_def = FlowDefinition(
        organization_id="org-1",
        name="Issue Other Template",
        flow_type=FlowType.OID4VCI_PRE_AUTHORIZED,
        credential_template_id="template-other",
        preconditions=[],
    )
    flow_def.activate()
    await repo.save_definition(flow_def)

    result = await handle_application_approved(
        ApplicationApprovedWebhook(
            event_type="application.approved",
            aggregate_id="application-4",
            aggregate_type="application",
            organization_id="org-1",
            timestamp="2026-05-05T12:00:00+00:00",
            data={
                "applicant_id": "applicant-4",
                "credential_template_id": "template-open-badge",
            },
        ),
        repo=repo,
    )

    assert result["success"] is True
    assert result["flows_triggered"] == 0
    assert "template-open-badge" in result["reason"]


@pytest.mark.asyncio
async def test_application_approved_webhook_manual_issue_does_not_bootstrap_default_flow(monkeypatch):
    async def _fake_initiate_issuance(instance, flow_def):
        tx = f"tx-{flow_def.id}"
        instance.context["credential_offer_transaction_id"] = tx
        instance.context["credential_offer_uri"] = f"openid-credential-offer://?credential_offer_uri={tx}"
        instance.context["credential_offer_uris"] = {"wr-default": instance.context["credential_offer_uri"]}
        instance.context["credential_offer_labels"] = {"wr-default": "Any Wallet"}
        instance.context["issuance_status"] = "offer_created"
        return {
            "transaction_id": tx,
            "credential_offer_uri": instance.context["credential_offer_uri"],
            "credential_offer_uris": instance.context["credential_offer_uris"],
            "credential_offer_labels": instance.context["credential_offer_labels"],
            "status": "offer_created",
        }

    monkeypatch.setattr(flow_main, "_initiate_credential_layer_issuance", _fake_initiate_issuance)

    repo = InMemoryFlowRepository()
    result = await handle_application_approved(
        ApplicationApprovedWebhook(
            event_type="application.approved",
            aggregate_id="application-5",
            aggregate_type="application",
            organization_id="org-1",
            timestamp="2026-05-05T12:00:00+00:00",
            data={
                "applicant_id": "applicant-5",
                "credential_template_id": "template-open-badge",
                "triggered_by_event": "application.manual_issue",
            },
        ),
        repo=repo,
    )

    assert result["success"] is False
    assert result["flows_triggered"] == 0
    assert "No active custom OID4VCI extension" in result["reason"]
    assert await repo.list_definitions("org-1") == []


@pytest.mark.asyncio
async def test_start_verification_uri_binds_encoded_client_id_to_signed_request(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")
    monkeypatch.setenv("OID4VP_CLIENT_ID_PREFIX", "decentralized_identifier")
    _install_reference_validation_stubs(
        monkeypatch,
        templates={},
        policies={
            "policy-1": {
                "organization_id": "org-1",
                "status": "active",
                "credential_requirements_json": "[]",
            },
        },
    )
    repo = InMemoryFlowRepository()

    started = await start_verification_flow(
        StartVerificationFlowRequest(presentation_policy_id="policy-1"),
        user_id="auth-service",
        repo=repo,
    )
    parsed = urlparse(started.request_uri)
    parameters = parse_qs(parsed.query)
    client_identifier = "decentralized_identifier:did:web:verifier.example:oid4vp"
    fetched_request_uri = (
        f"https://verifier.example/v1/flows/instances/{started.instance_id}/request"
    )

    assert parsed.scheme == "openid4vp"
    assert parameters == {
        "client_id": [client_identifier],
        "request_uri": [fetched_request_uri],
    }
    assert client_identifier not in parsed.query
    assert fetched_request_uri not in parsed.query

    async def _fake_presentation_definition(_policy_id: str) -> dict:
        return {
            "id": "pd-1",
            "input_descriptors": [
                {"id": "descriptor-1", "constraints": {"fields": []}},
            ],
        }

    monkeypatch.setattr(
        "flow.main._build_presentation_definition",
        _fake_presentation_definition,
    )
    signed_request = await get_verification_request_object(started.instance_id, repo)
    _header, payload, _signature = signed_request.body.decode().split(".", 2)

    assert _decode_jwt_segment(payload)["client_id"] == parameters["client_id"][0]


@pytest.mark.asyncio
async def test_started_post_request_uri_transports_wallet_nonce_into_signed_request(
    monkeypatch,
):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")
    monkeypatch.setenv("OID4VP_CLIENT_ID_PREFIX", "decentralized_identifier")
    _install_reference_validation_stubs(
        monkeypatch,
        templates={},
        policies={
            "policy-1": {
                "organization_id": "org-1",
                "status": "active",
                "credential_requirements_json": "[]",
            },
        },
    )
    repo = InMemoryFlowRepository()
    started = await start_verification_flow(
        StartVerificationFlowRequest(
            presentation_policy_id="policy-1",
            request_uri_method="post",
        ),
        user_id="auth-service",
        repo=repo,
    )
    parameters = parse_qs(urlparse(started.request_uri).query)

    assert parameters["request_uri_method"] == ["post"]
    assert len(parameters["request_uri"]) == 1

    async def _fake_presentation_definition(_policy_id: str) -> dict:
        return {
            "id": "pd-1",
            "input_descriptors": [
                {"id": "descriptor-1", "constraints": {"fields": []}},
            ],
        }

    monkeypatch.setattr(
        "flow.main._build_presentation_definition",
        _fake_presentation_definition,
    )
    signed_request = await get_verification_request_object(
        started.instance_id,
        repo,
        request=_form_request({"wallet_nonce": "wallet-nonce-from-post"}),
    )
    _header, payload, _signature = signed_request.body.decode().split(".", 2)
    decoded_payload = _decode_jwt_segment(payload)

    assert decoded_payload["client_id"] == parameters["client_id"][0]
    assert decoded_payload["wallet_nonce"] == "wallet-nonce-from-post"


@pytest.mark.asyncio
async def test_get_verification_request_object_records_presentation_request_message(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")

    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "flow_type": "verification",
            "nonce": "nonce-123",
            "presentation_policy_id": "policy-1",
            "oid4vp_client_id": "decentralized_identifier:did:web:verifier.example:oid4vp",
        },
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    async def _fake_presentation_definition(_policy_id: str) -> dict:
        return {
            "id": "pd-1",
            "input_descriptors": [{"id": "descriptor-1", "constraints": {"fields": []}}],
        }

    monkeypatch.setattr("flow.main._build_presentation_definition", _fake_presentation_definition)

    response = await get_verification_request_object(instance.id, repo)
    header, payload, _ = response.body.decode().split(".", 2)
    decoded_header = _decode_jwt_segment(header)
    decoded_payload = _decode_jwt_segment(payload)
    _, signing_key = flow_main.get_or_create_signing_key()
    verified_request = jwcrypto_jwt.JWT(key=signing_key, jwt=response.body.decode())

    assert response.media_type == "application/oauth-authz-req+jwt"
    assert json.loads(verified_request.claims) == decoded_payload
    assert decoded_header["kid"] == "did:web:verifier.example:oid4vp#oid4vp-verifier-key-1"
    assert decoded_payload["client_id"] == "decentralized_identifier:did:web:verifier.example:oid4vp"
    assert decoded_payload["iss"] == decoded_payload["client_id"]
    assert "client_id_scheme" not in decoded_payload
    assert "client_metadata" in decoded_payload
    assert "presentation_definition" not in decoded_payload
    assert decoded_payload["dcql_query"] == {"credentials": [{"id": "descriptor-1", "format": "jwt_vc_json"}]}
    assert instance.context["verification_audience"] == decoded_payload["client_id"]
    message = instance.context["mip_messages"]["presentation_request"]
    assert message["message_type"] == MessageType.PRESENTATION_REQUEST.value
    assert message["nonce"] == "nonce-123"
    assert message["payload"]["mip_flow_instance_id"] == instance.id
    assert message["payload"]["mip_policy_id"] == "policy-1"
    assert message["payload"]["presentation_definition"] is None
    assert message["payload"]["dcql_query"] == decoded_payload["dcql_query"]
    assert message["payload"]["client_id"] == decoded_payload["client_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outer_client_id",
    [
        None,
        "https://verifier.example/v1/flows/instances/flow/submit",
        "x509_hash:certificate-thumbprint",
    ],
)
async def test_lissi_compat_rejects_non_did_outer_client_identity(
    monkeypatch,
    outer_client_id: str | None,
):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "flow_type": "verification",
            "nonce": "nonce-123",
            "presentation_policy_id": "policy-1",
            "oid4vp_client_id": outer_client_id,
        },
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    with pytest.raises(HTTPException) as exc_info:
        await get_verification_request_object(instance.id, repo, compat="lissi")

    assert exc_info.value.status_code == 409
    assert "requires a DID verifier identity" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_verification_request_object_uses_dcql_vct_values(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")

    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "flow_type": "verification",
            "nonce": "nonce-123",
            "presentation_policy_id": "policy-1",
        },
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    async def _fake_presentation_definition(_policy_id: str) -> dict:
        return {
            "id": "pd-1",
            "input_descriptors": [
                {
                    "id": "req-marty-open-badge-login",
                    "format": {"spruce-vc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}},
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.vct"],
                                "filter": {
                                    "type": "string",
                                    "const": "https://beta.elevenidllc.com/credentials/marty-verified-member-badge",
                                },
                            },
                            {
                                "path": [
                                    "$.vc.credentialSubject.email",
                                    "$.credentialSubject.email",
                                    "$.email",
                                ],
                            },
                        ]
                    },
                }
            ],
        }

    monkeypatch.setattr("flow.main._build_presentation_definition", _fake_presentation_definition)

    response = await get_verification_request_object(instance.id, repo)
    _header, payload, _signature = response.body.decode().split(".", 2)
    decoded_payload = _decode_jwt_segment(payload)

    assert "presentation_definition" not in decoded_payload
    [credential_query] = decoded_payload["dcql_query"]["credentials"]
    assert credential_query["format"] == "dc+sd-jwt"
    assert credential_query["meta"] == {
        "vct_values": ["https://beta.elevenidllc.com/credentials/marty-verified-member-badge"]
    }
    assert credential_query["claims"] == [{"id": "claim_email", "path": ["email"]}]


@pytest.mark.asyncio
async def test_get_verification_request_object_supports_lissi_compat_profile(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")

    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "flow_type": "verification",
            "nonce": "nonce-123",
            "presentation_policy_id": "policy-1",
            "oid4vp_client_id": "decentralized_identifier:did:web:verifier.example:oid4vp",
        },
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    async def _fake_presentation_definition(_policy_id: str) -> dict:
        return {
            "id": "pd-1",
            "input_descriptors": [{"id": "descriptor-1", "constraints": {"fields": []}}],
        }

    monkeypatch.setattr("flow.main._build_presentation_definition", _fake_presentation_definition)

    response = await get_verification_request_object(instance.id, repo, compat="lissi")
    header, payload, _ = response.body.decode().split(".", 2)
    decoded_header = _decode_jwt_segment(header)
    decoded_payload = _decode_jwt_segment(payload)

    assert response.media_type == "application/oauth-authz-req+jwt"
    assert decoded_header["kid"] == "did:web:verifier.example:oid4vp#oid4vp-verifier-key-1"
    assert decoded_payload["client_id"] == "did:web:verifier.example:oid4vp"
    assert decoded_payload["iss"] == decoded_payload["client_id"]
    assert decoded_payload["client_id_scheme"] == "did"
    assert "client_metadata" not in decoded_payload
    assert "dcql_query" not in decoded_payload
    assert decoded_payload["presentation_definition"]["id"] == "pd-1"
    assert decoded_payload["response_mode"] == "direct_post"
    assert decoded_payload["response_uri"] == f"https://verifier.example/v1/flows/instances/{instance.id}/submit"
    assert instance.context["verification_audience"] == decoded_payload["client_id"]


@pytest.mark.asyncio
async def test_get_verification_request_object_supports_redirect_uri_client_id_prefix(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")
    monkeypatch.setenv("OID4VP_CLIENT_ID_PREFIX", "redirect_uri")
    monkeypatch.setenv("OID4VP_STRICT_CLIENT_METADATA", "1")

    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={"flow_type": "verification", "nonce": "nonce-123", "presentation_policy_id": "policy-1"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    async def _fake_presentation_definition(_policy_id: str) -> dict:
        return {"id": "pd-1", "input_descriptors": [{"id": "descriptor-1", "constraints": {"fields": []}}]}

    monkeypatch.setattr("flow.main._build_presentation_definition", _fake_presentation_definition)
    response = await get_verification_request_object(instance.id, repo)
    _header, payload, _signature = response.body.decode().split(".", 2)
    decoded_payload = _decode_jwt_segment(payload)
    expected = f"https://verifier.example/v1/flows/instances/{instance.id}/submit"

    assert decoded_payload["client_id"] == expected
    assert decoded_payload["response_uri"] == expected
    assert instance.context["oid4vp_expected_state"] == instance.id
    assert "client_id_scheme" not in decoded_payload
    assert set(decoded_payload["client_metadata"]) == {"vp_formats_supported"}
    assert instance.context["verification_audience"] == expected


@pytest.mark.asyncio
async def test_haip_request_uses_a_fresh_per_flow_response_encryption_key(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")
    repo = InMemoryFlowRepository()

    async def _fake_presentation_definition(_policy_id: str) -> dict:
        return {"id": "pd-1", "input_descriptors": [{"id": "descriptor-1", "constraints": {"fields": []}}]}

    monkeypatch.setattr("flow.main._build_presentation_definition", _fake_presentation_definition)
    instances = []
    for _ in range(2):
        instance = FlowInstance(
            flow_definition_id="__verification__",
            organization_id="org-1",
            status=FlowInstanceStatus.AWAITING_WALLET,
            context={"flow_type": "verification", "oid4vp_profile": "haip", "nonce": "nonce-123", "presentation_policy_id": "policy-1"},
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        await repo.save_instance(instance)
        instances.append(instance)

    payloads = []
    for instance in instances:
        response = await get_verification_request_object(instance.id, repo)
        _header, payload, _signature = response.body.decode().split(".", 2)
        payloads.append(_decode_jwt_segment(payload))

    keys = [payload["client_metadata"]["jwks"]["keys"][0] for payload in payloads]
    assert payloads[0]["response_mode"] == "direct_post.jwt"
    assert "authorization_encrypted_response_alg" not in payloads[0]["client_metadata"]
    assert "authorization_encrypted_response_enc" not in payloads[0]["client_metadata"]
    assert "authorization_encrypted_response_enc_values_supported" not in payloads[0]["client_metadata"]
    assert payloads[0]["client_metadata"]["encrypted_response_enc_values_supported"] == flow_main._HAIP_JWE_ENC_VALUES
    assert keys[0]["kid"] != keys[1]["kid"]
    assert "d" not in keys[0]
    assert instances[0].context["haip_response_encryption_private_jwk"]["kid"] == keys[0]["kid"]


@pytest.mark.asyncio
async def test_x509_hash_request_uses_certificate_client_id_and_x5c_header(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")
    monkeypatch.setenv("OID4VP_CLIENT_ID_PREFIX", "x509_hash")
    monkeypatch.setattr(
        flow_main,
        "_x509_hash_client_id_and_header",
        lambda: ("x509_hash:certificate-thumbprint", ["base64-der-leaf"]),
    )
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={"flow_type": "verification", "nonce": "nonce-123", "presentation_policy_id": "policy-1"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    async def _fake_presentation_definition(_policy_id: str) -> dict:
        return {"id": "pd-1", "input_descriptors": [{"id": "descriptor-1", "constraints": {"fields": []}}]}

    monkeypatch.setattr("flow.main._build_presentation_definition", _fake_presentation_definition)
    response = await get_verification_request_object(instance.id, repo)
    header, payload, _signature = response.body.decode().split(".", 2)
    decoded_header = _decode_jwt_segment(header)
    decoded_payload = _decode_jwt_segment(payload)

    assert decoded_payload["client_id"] == "x509_hash:certificate-thumbprint"
    assert decoded_header["x5c"] == ["base64-der-leaf"]
    assert "kid" not in decoded_header


@pytest.mark.asyncio
async def test_post_request_uri_binds_wallet_nonce_to_signed_request(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "flow_type": "verification", "nonce": "nonce-123",
            "presentation_policy_id": "policy-1", "request_uri_method": "post",
        },
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    async def _fake_presentation_definition(_policy_id: str) -> dict:
        return {"id": "pd-1", "input_descriptors": [{"id": "descriptor-1", "constraints": {"fields": []}}]}

    monkeypatch.setattr("flow.main._build_presentation_definition", _fake_presentation_definition)
    response = await get_verification_request_object(
        instance.id, repo, request=_form_request({"wallet_nonce": "wallet-nonce-1"})
    )
    _header, payload, _signature = response.body.decode().split(".", 2)
    assert _decode_jwt_segment(payload)["wallet_nonce"] == "wallet-nonce-1"


@pytest.mark.asyncio
async def test_submit_verification_response_decrypts_per_flow_direct_post_jwt():
    repo = InMemoryFlowRepository()
    public_jwk, private_jwk = flow_main._new_haip_response_encryption_key()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={"nonce": "nonce-haip", "haip_response_encryption_private_jwk": private_jwk},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)
    header = _jwt_segment({"alg": "none", "typ": "JWT"})
    payload = _jwt_segment({"nonce": "nonce-haip", "iss": "issuer.example", "given_name": "HAIP"})
    vp_token = f"{header}.{payload}."
    encrypted_response = _encrypted_response_for_key({"vp_token": vp_token}, public_jwk)

    response = await submit_verification_response(
        instance.id, None, None, None, repo=repo, response=encrypted_response
    )

    assert response.result == "passed"
    assert response.verified_claims["given_name"] == "HAIP"
    assert instance.context["vp_token"] == vp_token


@pytest.mark.asyncio
async def test_submit_verification_response_rejects_missing_or_mismatched_oid4vp_state():
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={"oid4vp_expected_state": "expected-state"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    with pytest.raises(flow_main.HTTPException) as missing:
        await submit_verification_response(instance.id, "vp-token", None, None, repo)
    assert missing.value.status_code == 400

    with pytest.raises(flow_main.HTTPException) as mismatched:
        await submit_verification_response(instance.id, "vp-token", None, "other-state", repo)
    assert mismatched.value.status_code == 400


@pytest.mark.asyncio
async def test_oid4vp_direct_post_callback_returns_only_the_standard_empty_object(monkeypatch):
    repo = InMemoryFlowRepository()
    called: dict[str, object] = {}

    async def _fake_submit(*args, **kwargs):
        called["args"] = args
        called["kwargs"] = kwargs
        return flow_main.VerificationResultResponse(
            instance_id="flow-1",
            status="completed",
            result="passed",
            decision="allow",
            decision_reason="internal result",
            verified_claims={"email": "member@example.test"},
            evaluation_timestamp="2026-01-01T00:00:00Z",
        )

    monkeypatch.setattr(flow_main, "submit_verification_response", _fake_submit)
    response = await flow_main.submit_oid4vp_direct_post_response(
        "flow-1", "vp-token", None, "state-1", repo, None
    )

    assert response.status_code == 200
    assert response.body == b"{}"
    assert called


@pytest.mark.asyncio
async def test_haip_direct_post_callback_returns_public_result_redirect(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        id="flow-haip",
        flow_definition_id="__verification__",
        organization_id="org-1",
        context={"oid4vp_profile": "haip"},
    )
    await repo.save_instance(instance)

    async def _fake_submit(*_args, **_kwargs):
        return flow_main.VerificationResultResponse(
            instance_id=instance.id,
            status="completed",
            result="passed",
            decision="allow",
            decision_reason="verified",
            verified_claims={},
            evaluation_timestamp="2026-01-01T00:00:00Z",
        )

    monkeypatch.setattr(flow_main, "submit_verification_response", _fake_submit)
    response = await flow_main.submit_oid4vp_direct_post_response(
        instance.id, "vp-token", None, instance.id, repo, None
    )

    assert response.status_code == 200
    assert response.body == b'{"redirect_uri":"https://verifier.example/v1/flows/instances/flow-haip"}'


@pytest.mark.asyncio
async def test_oid4vp_direct_post_callback_rejects_a_denied_presentation(monkeypatch):
    repo = InMemoryFlowRepository()

    async def _fake_submit(*_args, **_kwargs):
        return flow_main.VerificationResultResponse(
            instance_id="flow-1",
            status="completed",
            result="failed",
            decision="deny",
            decision_reason="signature invalid",
            verified_claims={},
            evaluation_timestamp="2026-01-01T00:00:00Z",
        )

    monkeypatch.setattr(flow_main, "submit_verification_response", _fake_submit)
    with pytest.raises(flow_main.HTTPException) as error:
        await flow_main.submit_oid4vp_direct_post_response("flow-1", "invalid-vp", None, None, repo, None)

    assert error.value.status_code == 400


@pytest.mark.asyncio
async def test_get_verification_request_object_supports_dc_api(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")

    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "flow_type": "verification",
            "nonce": "nonce-123",
            "presentation_policy_id": "policy-1",
        },
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    async def _fake_presentation_definition(_policy_id: str) -> dict:
        return {
            "id": "pd-1",
            "input_descriptors": [{"id": "descriptor-1", "constraints": {"fields": []}}],
        }

    monkeypatch.setattr("flow.main._build_presentation_definition", _fake_presentation_definition)

    response = await get_verification_request_object(instance.id, repo, transport="dc_api")
    header, payload, _ = response.body.decode().split(".", 2)
    decoded_header = _decode_jwt_segment(header)
    decoded_payload = _decode_jwt_segment(payload)

    assert response.media_type == "application/oauth-authz-req+jwt"
    assert decoded_header["kid"] == "did:web:verifier.example:oid4vp#oid4vp-verifier-key-1"
    assert decoded_payload["response_mode"] == flow_main._DC_API_JWT_RESPONSE_MODE
    assert decoded_payload["expected_origins"] == ["https://verifier.example"]
    assert "response_uri" not in decoded_payload
    assert "state" not in decoded_payload
    client_metadata = decoded_payload["client_metadata"]
    assert "authorization_encrypted_response_alg" not in client_metadata
    assert "authorization_encrypted_response_enc" not in client_metadata
    assert "authorization_encrypted_response_enc_values_supported" not in client_metadata
    assert client_metadata["encrypted_response_enc_values_supported"] == flow_main._HAIP_JWE_ENC_VALUES
    [encryption_key] = client_metadata["jwks"]["keys"]
    assert encryption_key["kid"] == flow_main._HAIP_ENCRYPTION_KEY_ID
    assert encryption_key["use"] == "enc"
    assert encryption_key["alg"] == flow_main._HAIP_JWE_ALG
    assert "d" not in encryption_key
    assert instance.context["dc_api_expected_origins"] == ["https://verifier.example"]
    assert instance.context["dc_api_protocol"] == _DC_API_PROTOCOL
    assert instance.context["dc_api_response_mode"] == flow_main._DC_API_JWT_RESPONSE_MODE
    message = instance.context["mip_messages"]["presentation_request"]
    assert "presentation_definition" not in decoded_payload
    assert message["payload"]["response_mode"] == flow_main._DC_API_JWT_RESPONSE_MODE
    assert message["payload"]["response_uri"] is None
    assert message["payload"]["presentation_definition"] is None
    assert message["payload"]["dcql_query"] == decoded_payload["dcql_query"]


def test_oid4vp_did_web_document_exposes_verifier_key(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://verifier.example")

    document = _oid4vp_did_web_document("https://verifier.example")

    assert document["id"] == "did:web:verifier.example:oid4vp"
    verification_method = document["verificationMethod"][0]
    assert verification_method["id"] == "did:web:verifier.example:oid4vp#oid4vp-verifier-key-1"
    assert verification_method["type"] == "JsonWebKey2020"
    assert verification_method["publicKeyJwk"]["kty"] == "EC"
    assert document["authentication"] == [verification_method["id"]]
    assert document["assertionMethod"] == [verification_method["id"]]


def test_vp_signature_check_uses_sd_jwt_key_binding_jwt():
    ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")

    holder_key = ed25519.Ed25519PrivateKey.generate()
    holder_did = _ed25519_did_key(holder_key.public_key())
    issuer_jwt_with_bad_signature = (
        f"{_jwt_segment({'alg': 'EdDSA', 'kid': f'{holder_did}#issuer'})}."
        f"{_jwt_segment({'iss': holder_did, 'vct': 'https://marty.example/credentials/MemberCredential'})}."
        "not-a-valid-signature"
    )
    disclosure = _raw_segment(json.dumps(["salt", "email", "holder@example.test"]).encode())
    key_binding_jwt = _signed_eddsa_jwt(
        {"nonce": "nonce-xyz", "aud": "https://beta.elevenidllc.com/v1/flows/instances/1/submit"},
        holder_key,
        holder_did,
    )

    assert _verify_vp_jwt_signature(
        f"{issuer_jwt_with_bad_signature}~{disclosure}~{key_binding_jwt}"
    ) is True


def test_vp_signature_check_rejects_invalid_key_binding_jwt_signature():
    ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")

    holder_key = ed25519.Ed25519PrivateKey.generate()
    holder_did = _ed25519_did_key(holder_key.public_key())
    issuer_jwt = (
        f"{_jwt_segment({'alg': 'none'})}."
        f"{_jwt_segment({'iss': 'did:web:beta.elevenidllc.com:orgs:marty'})}."
    )
    valid_kb_jwt = _signed_eddsa_jwt({"nonce": "nonce-xyz"}, holder_key, holder_did)
    invalid_kb_jwt = f"{valid_kb_jwt.rsplit('.', 1)[0]}.AAAA"

    assert _verify_vp_jwt_signature(f"{issuer_jwt}~{invalid_kb_jwt}") is False


def test_select_vp_token_unwraps_descriptor_map_payload():
    token = "header.payload.signature~disclosure~kb.header.signature"
    wrapped = json.dumps({"req-marty-member-sd-jwt": [token]})

    assert _select_vp_token_for_evaluation(wrapped) == token


def test_dcql_claims_include_required_direct_sd_jwt_paths():
    descriptor = {
        "constraints": {
            "fields": [
                {"path": ["$.vct"], "filter": {"const": "https://example.test/MemberCredential"}},
                {
                    "path": [
                        "$.vc.credentialSubject.email",
                        "$.credentialSubject.email",
                        "$.email",
                    ],
                    "optional": False,
                },
                {
                    "path": [
                        "$.vc.credentialSubject.given_name",
                        "$.credentialSubject.given_name",
                        "$.given_name",
                    ],
                    "optional": True,
                },
            ]
        }
    }

    assert _dcql_claims_for_descriptor(descriptor) == [
        {"id": "claim_email", "path": ["email"]}
    ]


@pytest.mark.asyncio
async def test_build_presentation_definition_requests_email_only_for_member_login(monkeypatch):
    requested_claims = [
        {
            "claim_name": "email",
            "display_name": "Email Address",
            "purpose": "Identify your account",
            "required": True,
            "intent_to_retain": False,
        }
    ]

    class FakePresentationPolicyStub:
        def __init__(self, _channel):
            pass

        async def GetPolicy(self, _request):
            return SimpleNamespace(
                id="policy-1",
                credential_requirements_json=json.dumps(
                    [
                        {
                            "id": "req-member-credential",
                            "credential_template_id": "template-1",
                            "display_name": "Member Credential",
                            "credential_payload_format": "ietf_sd_jwt",
                            "requested_claims": requested_claims,
                        }
                    ]
                ),
                organization_id="org-1",
            )

    class FakeCredentialTemplateStub:
        def __init__(self, _channel):
            pass

        async def GetTemplate(self, _request):
            return SimpleNamespace(
                id="template-1",
                credential_type="MemberCredential",
                vct="https://marty.example/credentials/MemberCredential",
                supported_formats=["sd_jwt_vc"],
            )

    monkeypatch.setattr(
        "marty_proto.v1.presentation_policy_service_pb2_grpc.PresentationPolicyServiceStub",
        FakePresentationPolicyStub,
    )
    monkeypatch.setattr(
        "marty_proto.v1.credential_template_service_pb2_grpc.CredentialTemplateServiceStub",
        FakeCredentialTemplateStub,
    )
    monkeypatch.setattr("flow.main.app.state.pp_grpc_channel", object(), raising=False)
    monkeypatch.setattr("flow.main.app.state.ct_grpc_channel", object(), raising=False)

    presentation_definition = await _build_presentation_definition("policy-1")
    descriptor = presentation_definition["input_descriptors"][0]
    fields = descriptor["constraints"]["fields"]
    type_fields = [field for field in fields if "filter" in field]
    named_fields = [field for field in descriptor["constraints"]["fields"] if "name" in field]

    assert type_fields[0] == {
        "path": ["$.vct"],
        "filter": {"type": "string", "const": "https://marty.example/credentials/MemberCredential"},
    }
    assert type_fields[1] == {
        "path": ["$.vc.type", "$.type"],
        "filter": {
            "anyOf": [
                {"type": "array", "contains": {"const": "MemberCredential"}},
                {"type": "string", "const": "MemberCredential"},
            ],
        },
        "optional": True,
    }
    assert descriptor["constraints"]["limit_disclosure"] == "required"
    assert named_fields == [
        {
            "name": "Email Address",
            "purpose": "Identify your account",
            "path": [
                "$.vc.credentialSubject.email",
                "$.credentialSubject.email",
                "$.email",
            ],
            "intent_to_retain": False,
            "optional": False,
        }
    ]
    assert _dcql_claims_for_descriptor(descriptor) == [{"id": "claim_email", "path": ["email"]}]


@pytest.mark.asyncio
async def test_build_presentation_definition_accepts_current_and_legacy_open_badge_vct(monkeypatch):
    class FakePresentationPolicyStub:
        def __init__(self, _channel):
            pass

        async def GetPolicy(self, _request):
            return SimpleNamespace(
                id="policy-1",
                credential_requirements_json=json.dumps(
                    [
                        {
                            "id": "req-marty-open-badge-login",
                            "credential_template_id": "template-open-badge",
                            "display_name": "Marty Verified Member Badge",
                            "credential_payload_format": "sd_jwt_vc",
                            "requested_claims": [
                                {
                                    "claim_name": "email",
                                    "display_name": "Email Address",
                                    "required": True,
                                }
                            ],
                        }
                    ]
                ),
                organization_id="org-1",
            )

    class FakeCredentialTemplateStub:
        def __init__(self, _channel):
            pass

        async def GetTemplate(self, _request):
            return SimpleNamespace(
                id="template-open-badge",
                credential_type="open_badge",
                vct="https://beta.elevenidllc.com/credentials/marty-verified-member-badge",
                supported_formats=["sd_jwt_vc"],
            )

    monkeypatch.setattr(
        "marty_proto.v1.presentation_policy_service_pb2_grpc.PresentationPolicyServiceStub",
        FakePresentationPolicyStub,
    )
    monkeypatch.setattr(
        "marty_proto.v1.credential_template_service_pb2_grpc.CredentialTemplateServiceStub",
        FakeCredentialTemplateStub,
    )
    monkeypatch.setattr("flow.main.app.state.pp_grpc_channel", object(), raising=False)
    monkeypatch.setattr("flow.main.app.state.ct_grpc_channel", object(), raising=False)

    presentation_definition = await _build_presentation_definition("policy-1")
    descriptor = presentation_definition["input_descriptors"][0]
    [vct_field] = [
        field
        for field in descriptor["constraints"]["fields"]
        if field.get("path") == ["$.vct"]
    ]

    assert vct_field["filter"] == {
        "type": "string",
        "enum": [
            "https://beta.elevenidllc.com/credentials/marty-verified-member-badge",
            "https://marty.example/credentials/open_badge",
        ],
    }


@pytest.mark.asyncio
async def test_submit_verification_response_records_verification_result_message():
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={"nonce": "nonce-xyz"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    header = _jwt_segment({"alg": "none", "typ": "JWT"})
    payload = _jwt_segment({"nonce": "nonce-xyz", "iss": "issuer.example", "given_name": "Marty"})
    vp_token = f"{header}.{payload}."

    response = await submit_verification_response(instance.id, vp_token, None, None, repo)

    assert response.result == "passed"
    message = instance.context["mip_messages"]["verification_result"]
    assert message["message_type"] == MessageType.VERIFICATION_RESULT.value
    assert message["correlation_id"] == instance.id
    assert message["payload"]["overall_result"] == "PASSED"
    assert message["payload"]["verifier_nonce"] == "nonce-xyz"
    assert message["payload"]["claim_results"][0]["claim_name"] == "given_name"


@pytest.mark.asyncio
async def test_submit_verification_response_forwards_flow_trust_profile_to_policy(monkeypatch):
    captured: dict[str, str] = {}

    class FakePresentationPolicyStub:
        def __init__(self, _channel):
            pass

        async def EvaluatePresentation(self, request):
            captured["policy_id"] = request.policy_id
            captured["trust_profile_id"] = request.trust_profile_id
            return SimpleNamespace(
                result="passed",
                decision="allow",
                decision_reason="Official signer is trusted",
                verified_claims_json='{"given_name":"Marty"}',
            )

    monkeypatch.setattr(
        "marty_proto.v1.presentation_policy_service_pb2_grpc.PresentationPolicyServiceStub",
        FakePresentationPolicyStub,
    )
    monkeypatch.setattr("flow.main.app.state.pp_grpc_channel", object(), raising=False)
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "nonce": "nonce-xyz",
            "presentation_policy_id": "policy-1",
            "trust_profile_id": "trust-1",
        },
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    header = _jwt_segment({"alg": "none", "typ": "JWT"})
    payload = _jwt_segment({"nonce": "nonce-xyz", "iss": "issuer.example", "given_name": "Marty"})
    response = await submit_verification_response(
        instance.id,
        f"{header}.{payload}.",
        None,
        None,
        repo,
    )

    assert response.result == "passed"
    assert captured == {
        "policy_id": "policy-1",
        "trust_profile_id": "trust-1",
    }


@pytest.mark.asyncio
async def test_internal_flow_fails_closed_when_policy_rejects_cross_org_trust(
    monkeypatch,
):
    class RejectingPresentationPolicyStub:
        def __init__(self, _channel):
            pass

        async def EvaluatePresentation(self, _request):
            raise RuntimeError(
                "Trust Profile and Presentation Policy must belong to the same organization"
            )

    monkeypatch.setattr(
        "marty_proto.v1.presentation_policy_service_pb2_grpc.PresentationPolicyServiceStub",
        RejectingPresentationPolicyStub,
    )
    monkeypatch.setattr("flow.main.app.state.pp_grpc_channel", object(), raising=False)
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "nonce": "nonce-xyz",
            "presentation_policy_id": "policy-1",
            "trust_profile_id": "trust-other-org",
        },
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)
    header = _jwt_segment({"alg": "none", "typ": "JWT"})
    payload = _jwt_segment({"nonce": "nonce-xyz", "iss": "issuer.example"})

    response = await submit_verification_response(
        instance.id,
        f"{header}.{payload}.",
        None,
        None,
        repo,
    )

    assert response.result == "failed"
    assert response.decision == "deny"
    assert "same organization" in response.decision_reason


@pytest.mark.asyncio
async def test_submit_verification_response_unwraps_descriptor_map_vp_token():
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    header = _jwt_segment({"alg": "none", "typ": "JWT"})
    payload = _jwt_segment({"iss": "issuer.example", "given_name": "Marty"})
    vp_token = f"{header}.{payload}."
    wrapped_vp_token = json.dumps({"req-marty-member-sd-jwt": [vp_token]})

    response = await submit_verification_response(instance.id, wrapped_vp_token, None, None, repo)

    assert response.result == "passed"
    assert response.verified_claims["given_name"] == "Marty"
    assert instance.context["vp_token"] == vp_token
    assert instance.context["vp_token_raw"] == wrapped_vp_token


@pytest.mark.asyncio
async def test_submit_digital_credential_response_uses_origin_audience():
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "nonce": "nonce-xyz",
            "dc_api_expected_origins": ["https://beta.elevenidllc.com"],
        },
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    header = _jwt_segment({"alg": "none", "typ": "JWT"})
    payload = _jwt_segment({"nonce": "nonce-xyz", "iss": "issuer.example", "given_name": "Marty"})
    vp_token = f"{header}.{payload}."

    response = await submit_digital_credential_response(
        instance.id,
        DigitalCredentialSubmissionRequest(
            protocol=_DC_API_PROTOCOL,
            origin="https://beta.elevenidllc.com",
            data={"vp_token": {"req-marty-member-sd-jwt": [vp_token]}},
        ),
        repo=repo,
    )

    assert response.result == "passed"
    assert response.verified_claims["given_name"] == "Marty"
    assert instance.context["verification_audience"] == "origin:https://beta.elevenidllc.com"
    assert instance.context["vp_token"] == vp_token


@pytest.mark.asyncio
async def test_submit_digital_credential_response_decrypts_dc_api_jwt_response():
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "nonce": "nonce-haip",
            "dc_api_expected_origins": ["https://beta.elevenidllc.com"],
        },
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    header = _jwt_segment({"alg": "none", "typ": "JWT"})
    payload = _jwt_segment({"nonce": "nonce-haip", "iss": "issuer.example", "given_name": "HAIP"})
    vp_token = f"{header}.{payload}."
    encrypted_response = _encrypted_dc_api_response(
        {"vp_token": {"req-marty-member-sd-jwt": [vp_token]}}
    )

    response = await submit_digital_credential_response(
        instance.id,
        DigitalCredentialSubmissionRequest(
            protocol=_DC_API_PROTOCOL,
            origin="https://beta.elevenidllc.com",
            data={"response": encrypted_response},
        ),
        repo=repo,
    )

    assert response.result == "passed"
    assert response.verified_claims["given_name"] == "HAIP"
    assert instance.context["dc_api_last_response_mode"] == flow_main._DC_API_JWT_RESPONSE_MODE
    assert instance.context["vp_token"] == vp_token


@pytest.mark.asyncio
async def test_submit_digital_credential_response_rejects_invalid_dc_api_jwt_response():
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={"dc_api_expected_origins": ["https://beta.elevenidllc.com"]},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)

    with pytest.raises(HTTPException) as exc_info:
        await submit_digital_credential_response(
            instance.id,
            DigitalCredentialSubmissionRequest(
                protocol=_DC_API_PROTOCOL,
                origin="https://beta.elevenidllc.com",
                data={"response": "not-a-jwe"},
            ),
            repo=repo,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["error"] == "invalid_request"
    assert "compact JWE" in exc_info.value.detail["error_description"]


@pytest.mark.asyncio
async def test_submit_digital_credential_response_rejects_unsupported_dc_api_jwt_alg():
    repo = InMemoryFlowRepository()
    instance = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={"dc_api_expected_origins": ["https://beta.elevenidllc.com"]},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)
    unsupported_response = f"{_jwt_segment({'alg': 'dir', 'enc': flow_main._HAIP_JWE_ENC})}...."

    with pytest.raises(HTTPException) as exc_info:
        await submit_digital_credential_response(
            instance.id,
            DigitalCredentialSubmissionRequest(
                protocol=_DC_API_PROTOCOL,
                origin="https://beta.elevenidllc.com",
                data={"response": unsupported_response},
            ),
            repo=repo,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["error"] == "invalid_request"
    assert "Unsupported dc_api.jwt JWE alg" in exc_info.value.detail["error_description"]
