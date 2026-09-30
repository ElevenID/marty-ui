"""Owned HTTPS Flow requests use the operator key and stay on the disposable edge."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import uuid

import pytest

from scripts import passport_supported_flow_gateway as gateway
from services.passport_disposable_identity import issuer_did


KEY = "mk_test_" + "a" * 43
OPERATOR_KEY = "mk_test_" + "b" * 43
IDENTIFIER = "d0000000-0000-4000-8000-000000000001"
TEMPLATE = "d0000000-0000-4000-8000-000000000003"
DESTINATION = "d0000000-0000-4000-8000-000000000004"
DEFINITION = "d0000000-0000-4000-8000-000000000005"
INSTANCE = "d0000000-0000-4000-8000-000000000006"
APPLICATION = "d0000000-0000-4000-8000-000000000007"
BUREAU = "d0000000-0000-4000-8000-000000000002"


class Response:
    status = 200

    def __init__(self, url):
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def geturl(self):
        return self.url

    def read(self, size):
        return b'{"id":"d0000000-0000-4000-8000-000000000001"}'


class Opener:
    def __init__(self):
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        return Response(request.full_url)


def fixture():
    project = "marty-passport-acceptance-selfhost-" + uuid.uuid4().hex[:12]
    root = Path(tempfile.gettempdir()) / project
    secrets = root / "secrets"
    secrets.mkdir(parents=True, mode=0o700)
    (secrets / "passport_acceptance_api_key").write_text(KEY + "\n")
    (secrets / "passport_acceptance_operator_api_key").write_text(OPERATOR_KEY + "\n")
    (secrets / "workload_identity_ca_cert").write_text("synthetic-ca")
    if os.name == "posix":
        (secrets / "passport_acceptance_api_key").chmod(0o600)
        (secrets / "passport_acceptance_operator_api_key").chmod(0o600)
        (secrets / "workload_identity_ca_cert").chmod(0o644)
    record = {
        "project": project, "disposable_root": str(root),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
        "containers": {"edge": "e" * 64},
    }
    return root, record


def cleanup(root):
    for path in (root / "secrets").iterdir():
        path.unlink()
    (root / "secrets").rmdir()
    root.rmdir()


def test_operator_and_native_requests_use_separate_keys_and_scoped_routes(monkeypatch):
    root, record = fixture()
    opener = Opener()
    inspected = []
    monkeypatch.setattr(gateway.ssl, "create_default_context", lambda **kwargs: object())
    edge = {"HostConfig": {"PortBindings": {"8443/tcp": [
        {"HostIp": "127.0.0.1", "HostPort": "29877"}]}},
        "NetworkSettings": {"Ports": {"8443/tcp": [
            {"HostIp": "127.0.0.1", "HostPort": "29877"}]}}}
    try:
        params = dict(
            inspector=lambda args: json.dumps([edge]),
            ownership=lambda *args: inspected.append(args) or
                {"live_ownership_verified": True},
            opener_factory=lambda *args: opener,
        )
        operator = gateway.owned_gateway_request(
            record, "selfhost", operator=True, expected_port=29877, **params)
        native = gateway.owned_gateway_request(
            record, "selfhost", operator=False, expected_port=29877, **params)
        assert operator("POST", "/v1/application-templates", {"name": "fixture"},
                        {"idempotency-key": "fixture-1"}) == (200, {"id": IDENTIFIER})
        assert native("GET", f"/v1/passport/applications/{IDENTIFIER}/production-status") \
            == (200, {"id": IDENTIFIER})
        assert operator("POST", f"/v1/flows/instances/{IDENTIFIER}/advance",
                        {"step_result": "success", "data": {}}) == (200, {"id": IDENTIFIER})
        assert opener.requests[0].headers["X-api-key"] == OPERATOR_KEY
        assert opener.requests[0].headers["Idempotency-key"] == "fixture-1"
        assert opener.requests[1].headers["X-api-key"] == KEY
        assert all(request.full_url.startswith("https://localhost:29877/")
                   for request in opener.requests)
        assert len(inspected) == 5
        with pytest.raises(gateway.FlowGatewayError):
            operator("GET", f"/v1/passport/applications/{IDENTIFIER}/production-status")
        with pytest.raises(gateway.FlowGatewayError):
            native("POST", "/v1/flows/definitions", {})
        with pytest.raises(gateway.FlowGatewayError):
            operator("GET", "/v1/flows/definitions/../instances")
        assert len(opener.requests) == 3
    finally:
        cleanup(root)


def test_operator_request_requires_owned_live_project(monkeypatch):
    root, record = fixture()
    monkeypatch.setattr(gateway.ssl, "create_default_context", lambda **kwargs: object())
    edge = {"HostConfig": {"PortBindings": {"8443/tcp": [
        {"HostIp": "127.0.0.1", "HostPort": "29877"}]}},
        "NetworkSettings": {"Ports": {"8443/tcp": [
            {"HostIp": "127.0.0.1", "HostPort": "29877"}]}}}
    reads = iter(({"live_ownership_verified": True},
                  {"live_ownership_verified": False}))
    opener = Opener()
    try:
        request = gateway.owned_gateway_request(
            record, "selfhost", operator=True, expected_port=29877,
            inspector=lambda args: json.dumps([edge]),
            ownership=lambda *args: next(reads),
            opener_factory=lambda *args: opener,
        )
        with pytest.raises(gateway.FlowGatewayError, match="ownership changed"):
            request("GET", "/v1/flows/definitions")
        assert opener.requests == []
    finally:
        cleanup(root)


def test_native_batch_companion_uses_public_owned_passport_routes(monkeypatch):
    root, record = fixture()
    opener = Opener()
    monkeypatch.setattr(gateway.ssl, "create_default_context", lambda **kwargs: object())
    edge = {"HostConfig": {"PortBindings": {"8443/tcp": [
        {"HostIp": "127.0.0.1", "HostPort": "29877"}]}},
        "NetworkSettings": {"Ports": {"8443/tcp": [
            {"HostIp": "127.0.0.1", "HostPort": "29877"}]}}}
    try:
        request = gateway.owned_gateway_request(
            record, "selfhost", operator=False, passport_write=True,
            expected_port=29877, inspector=lambda args: json.dumps([edge]),
            ownership=lambda *args: {"live_ownership_verified": True},
            opener_factory=lambda *args: opener)
        assert request("POST", "/v1/passport/applications", {"synthetic": True}) \
            == (200, {"id": IDENTIFIER})
        assert request("POST", f"/v1/passport/applications/{IDENTIFIER}/generate-sod") \
            == (200, {"id": IDENTIFIER})
        assert request("GET", f"/v1/passport/applications/{IDENTIFIER}/production-status") \
            == (200, {"id": IDENTIFIER})
        assert all(item.headers["X-api-key"] == KEY for item in opener.requests)
        with pytest.raises(gateway.FlowGatewayError, match="escaped scope"):
            request("POST", "/internal/passport/beta-batches/preflight")
        with pytest.raises(gateway.FlowGatewayError, match="escaped scope"):
            request("POST", f"/v1/passport/applications/{IDENTIFIER}/production-status")
        assert len(opener.requests) == 3
    finally:
        cleanup(root)


def test_flow_start_uses_operator_for_references_and_native_key_for_job(monkeypatch):
    events = []

    def local_inspector(args):
        return "local-docker-only"

    def factory(record, surface, *, operator, expected_port, inspector: object):
        assert (record["project"], surface, expected_port) == ("owned", "base", 29877)
        assert inspector is local_inspector

        def request(method, path, body=None, headers=None):
            events.append((operator, method, path))
            return 200, {}

        return request

    def references(request, organization, name, did, idempotency):
        assert organization == "00000000-0000-0000-0000-000000000001"
        assert did == issuer_did(29877)
        request("POST", "/v1/credential-templates", {}, {})
        return {"credential_template_id": IDENTIFIER,
                "application_template_id": TEMPLATE,
                "delivery_destination_profile_id": DESTINATION}

    def start(request, organization, name, refs, physical, native_request):
        assert refs["credential_template_id"] == IDENTIFIER
        assert physical["data_groups"] == {"DG1": "YQ==", "DG2": "Yg=="}
        assert physical["applicant"] and physical["mrz"]
        request("POST", "/v1/flows/instances", {})
        native_request("GET", f"/v1/passport/applications/{IDENTIFIER}/production-status", None)
        return {"native_job_id": IDENTIFIER, "flow_definition_id": DEFINITION,
                "flow_instance_id": INSTANCE, "application_id": APPLICATION}

    monkeypatch.setattr(gateway, "provision_physical_passport_references", references)
    monkeypatch.setattr(gateway, "start_physical_passport_flow", start)
    def advance(request, native_request, private_poll, history_read,
                organization, refs, started, did, *, restart, before_submit):
        assert restart() is True
        assert before_submit(started, "a" * 64) == BUREAU
        assert organization == "00000000-0000-0000-0000-000000000001"
        assert did == issuer_did(29877)
        assert started["native_job_id"] == IDENTIFIER
        return {"flow_step_count": 9, "native_effect_count": 6,
                "durable_history_verified": True,
                "restart_resume_verified": True,
                "restart_before_native_status": "SOD_SIGNED",
                "restart_after_native_status": "SUBMITTED",
                "signed_callback_receipt_sha256": "b" * 64,
                "callback_bureau_status": "QUALITY_CHECK",
                "bureau_job_id": BUREAU,
                "sod_sha256": "a" * 64}

    def batch_probe(record, surface, port, application, physical, *args, **kwargs):
        assert record["containers"]["issuance-native"] == "a" * 64
        assert application["application_template_id"] == TEMPLATE
        assert application["delivery_destination_profile_id"] == DESTINATION
        assert physical["data_groups"] == {"DG1": "YQ==", "DG2": "Yg=="}
        assert args[:4] == (INSTANCE, APPLICATION, IDENTIFIER, "a" * 64)
        return BUREAU, {"final_native_preflight": {
            "native_container_id": "a" * 64,
            "native_batch_preflight_verified": True},
            "batch": {"verified": True, "evidence": {
                "selected_flow_in_two_job_batch": True,
                "first_accepted_material_verified": True,
                "companion_native_completed": True}}}

    result = gateway.exercise_owned_flow(
        {"project": "owned", "containers": {"issuance-native": "a" * 64}},
        "base", 29877, "123456",
        dsc_der_sha256="2" * 64, dsc_pem_wire_sha256="3" * 64,
        batch_state_path=Path(tempfile.gettempdir()) / "pending.json",
        batch_deadline=datetime.now(timezone.utc) + timedelta(hours=1),
        inspector=local_inspector, request_factory=factory, advance=advance,
        restart=lambda: True, batch_probe=batch_probe)
    digest = hashlib.sha256(IDENTIFIER.encode()).hexdigest()
    assert result == {"references": {
                          "credential_template_id_sha256": digest,
                          "application_template_id_sha256": hashlib.sha256(TEMPLATE.encode()).hexdigest(),
                          "delivery_destination_profile_id_sha256": hashlib.sha256(DESTINATION.encode()).hexdigest()},
                      "flow": {"native_job_id_sha256": digest,
                               "flow_definition_id_sha256": hashlib.sha256(DEFINITION.encode()).hexdigest(),
                               "flow_instance_id_sha256": hashlib.sha256(INSTANCE.encode()).hexdigest(),
                               "application_id_sha256": hashlib.sha256(APPLICATION.encode()).hexdigest()},
                      "batch": {"final_native_preflight": {
                          "native_container_id": "a" * 64,
                          "native_batch_preflight_verified": True},
                          "batch": {"verified": True, "evidence": {
                              "selected_flow_in_two_job_batch": True,
                              "first_accepted_material_verified": True,
                              "companion_native_completed": True}},
                          "selected_source_job_sha256": digest,
                          "selected_bureau_job_sha256": hashlib.sha256(BUREAU.encode()).hexdigest(),
                          "dsc_der_sha256": "2" * 64},
                      "execution": {"nine_steps_verified": True,
                                    "six_native_effects_verified": True,
                                    "durable_history_verified": True,
                                    "restart_resume_verified": True,
                                    "restart_before_native_status": "SOD_SIGNED",
                                    "restart_after_native_status": "SUBMITTED",
                                    "signed_callback_receipt_sha256": "b" * 64,
                                    "callback_bureau_status": "QUALITY_CHECK",
                                    "bureau_job_id_sha256": hashlib.sha256(BUREAU.encode()).hexdigest(),
                                    "sod_sha256": "a" * 64}}
    assert events == [
        (True, "POST", "/v1/credential-templates"),
        (True, "POST", "/v1/flows/instances"),
        (False, "GET", f"/v1/passport/applications/{IDENTIFIER}/production-status"),
    ]
