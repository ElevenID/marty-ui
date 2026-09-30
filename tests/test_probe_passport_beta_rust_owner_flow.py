import json
import sys

import pytest

from scripts import probe_passport_beta_rust_owner_flow as proof


GATEWAY = "a" * 64
FLOW = "b" * 64
INSTANCE = "11111111-1111-4111-8111-111111111111"
JOB = "22222222-2222-4222-8222-222222222222"
APPLICATION = "33333333-3333-4333-8333-333333333333"
REFERENCE = "rust-owner-flow-" + "c" * 32
POST_ROUTE_ID = "44444444-4444-4444-8444-444444444444"
APP_DIGEST = "3" * 64
PLAN = {
    "source_commit": "d" * 40,
    "services_image": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "e" * 64,
    "postgres_container_id": "f" * 64,
    "old_container_ids_by_service": {"gateway": "1" * 64, "flow": "2" * 64},
}
FLOW_INPUT = {"organization_id": "org-1", "flow_definition_id": "flow-1",
              "issuer_did": "did:web:issuer.example"}
APPLICATION_INPUT = {"organization_id": "org-1",
                     "issuer_did": "did:web:issuer.example",
                     "credential_template_id": "credential-1",
                     "application_template_id": "application-1",
                     "delivery_destination_profile_id": "destination-1"}
OWNER = {"verified": True, "source_commit": PLAN["source_commit"],
         "transition_txid": "456"}


def runner_for(instance_exists):
    def runner(command):
        if command[:2] == ["docker", "ps"]:
            return GATEWAY if "label=com.docker.compose.service=gateway" in command else FLOW
        if command[:2] == ["docker", "inspect"]:
            container = command[2]
            service = "gateway" if container == GATEWAY else "flow"
            return json.dumps([{
                "Id": container,
                "Config": {"Image": PLAN["services_image"], "Labels": {
                    "com.docker.compose.project": "elevenid-beta",
                    "com.docker.compose.service": service}},
                "State": {"Running": True, "Status": "running"},
            }])
        if command[:2] == ["docker", "exec"]:
            sql = command[-1]
            if "SELECT id FROM flow_service.flow_instances" in sql:
                return INSTANCE if instance_exists() else ""
            if "SELECT status FROM flow_service.flow_instances" in sql:
                return "in_progress"
            if "SELECT application_id || '|' || status" in sql:
                return (APPLICATION + "|DRAFT|application-1|credential-1|"
                        "destination-1|did:web:issuer.example")
        raise AssertionError(command)
    return runner


def current_projection():
    return {"id": INSTANCE, "organization_id": "org-1", "flow_id": "flow-1",
            "flow_type": "physical_document_issuance", "status": "IN_PROGRESS",
            "current_step": "accept_application",
            "metadata": {"external_reference": REFERENCE},
            "context_data": {"application_id": APPLICATION,
                             "physical_document_job": {
                                 "id": JOB, "application_id": APPLICATION,
                                 "organization_id": "org-1",
                                 "issuer_did": FLOW_INPUT["issuer_did"],
                                 "flow_execution_id": INSTANCE}}}


def test_live_reference_validation_checks_active_flow_and_issuer():
    seen = []

    def request(_container, method, path, _session, _body):
        seen.append((method, path))
        if path.endswith("/validate"):
            return 200, {"valid": True, "errors": []}, "request-2"
        if path.startswith("/v1/credential-templates/"):
            return 200, {"id": "credential-1", "organization_id": "org-1",
                         "issuer_did": FLOW_INPUT["issuer_did"],
                         "status": "ACTIVE"}, "request-3"
        return 200, {"id": "flow-1", "organization_id": "org-1",
                     "flow_type": "physical_document_issuance", "status": "ACTIVE",
                     "credential_template_id": "credential-1",
                     "application_template_id": "application-1",
                     "delivery_destination_profile_id": "destination-1"}, "request-1"

    result = proof.validate_live_references(
        PLAN, FLOW_INPUT, APPLICATION_INPUT, "session=secret",
        runner=runner_for(lambda: False), request=request)
    assert result["verified"] is True
    assert result["gateway_container_id"] == GATEWAY
    assert seen == [
        ("GET", "/v1/flows/definitions/flow-1"),
        ("POST", "/v1/flows/definitions/flow-1/validate"),
        ("GET", "/v1/credential-templates/credential-1"),
    ]
    with pytest.raises(proof.HostProbeError, match="tenant or issuer differ"):
        proof.validate_live_references(
            PLAN, FLOW_INPUT, {**APPLICATION_INPUT, "issuer_did": "did:web:wrong"},
            "session=secret", runner=runner_for(lambda: False), request=request)


def test_private_flow_write_and_exact_receipt_retry():
    exists = False
    calls = []
    marker = None

    def mark(value):
        nonlocal marker
        marker = value

    def request(_container, method, path, _session, body):
        nonlocal exists
        calls.append((method, path))
        if method == "POST":
            assert body["external_reference"] == REFERENCE
            assert body["initial_context"]["physical_document"] == proof.SYNTHETIC_DOCUMENT
            exists = True
            return 200, {"id": INSTANCE}, POST_ROUTE_ID
        return 200, current_projection(), "get-route-" + str(len(calls))

    kwargs = {"runner": runner_for(lambda: exists), "request": request,
              "owner_verifier": lambda _plan, **_kwargs: OWNER}
    first = proof.probe(PLAN, FLOW_INPUT, "0" * 64,
                        APPLICATION_INPUT, APP_DIGEST, "session=secret",
                        REFERENCE, allow_post=True,
                        expected_transition_txid="456", before_post=mark, **kwargs)
    assert first["flow_and_job_rows_verified"] is True
    assert first["gateway_route_request_id"] == "get-route-2"
    assert first["gateway_write_route_request_id"] == POST_ROUTE_ID
    assert marker["gateway_container_id"] == GATEWAY
    retry = proof.probe(PLAN, FLOW_INPUT, "0" * 64,
                        APPLICATION_INPUT, APP_DIGEST, "session=secret",
                        REFERENCE, allow_post=False, existing=first,
                        expected_transition_txid="456", dispatch_marker=marker,
                        **kwargs)
    assert retry == first
    assert [method for method, _ in calls] == ["POST", "GET", "GET"]


def test_missing_retry_row_fails_without_second_post():
    marker = {"schema": "marty.passport-beta-rust-owner-flow-dispatch/v1",
              "source_commit": PLAN["source_commit"],
              "transition_txid": "456", "flow_file_sha256": "0" * 64,
              "application_file_sha256": APP_DIGEST,
              "external_reference": REFERENCE, "gateway_container_id": GATEWAY,
              "flow_container_id": FLOW}
    with pytest.raises(proof.HostProbeError, match="no resolved database row"):
        proof.probe(PLAN, FLOW_INPUT, "0" * 64,
                    APPLICATION_INPUT, APP_DIGEST, "session=secret",
                    REFERENCE, allow_post=False, expected_transition_txid="456",
                    dispatch_marker=marker,
                    runner=runner_for(lambda: False),
                    request=lambda *_args: pytest.fail("must not send POST"),
                    owner_verifier=lambda _plan, **_kwargs: OWNER)


def test_lost_creation_response_stays_closed_without_write_route_trace():
    exists = False
    marker = None

    def mark(value):
        nonlocal marker
        marker = value

    def uncertain(_container, method, _path, _session, _body):
        nonlocal exists
        assert method == "POST" and marker is not None
        exists = True
        raise proof.HostProbeError("response lost")

    kwargs = {"runner": runner_for(lambda: exists),
              "owner_verifier": lambda _plan, **_kwargs: OWNER}
    with pytest.raises(proof.HostProbeError, match="response lost"):
        proof.probe(PLAN, FLOW_INPUT, "0" * 64,
                    APPLICATION_INPUT, APP_DIGEST, "session=secret",
                    REFERENCE, allow_post=True, expected_transition_txid="456",
                    before_post=mark, request=uncertain, **kwargs)

    with pytest.raises(proof.HostProbeError, match="write route response is missing"):
        proof.probe(
            PLAN, FLOW_INPUT, "0" * 64,
            APPLICATION_INPUT, APP_DIGEST, "session=secret", REFERENCE,
            allow_post=False, expected_transition_txid="456", dispatch_marker=marker,
            request=lambda *_args: pytest.fail("must not dispatch a second POST"),
            **kwargs)


def test_native_job_must_match_validated_reference_tuple(monkeypatch):
    def database(sql, *_args):
        if sql.startswith("SELECT status"):
            return "in_progress"
        return (APPLICATION + "|DRAFT|application-1|credential-1|"
                "wrong-destination|did:web:issuer.example")

    monkeypatch.setattr(proof, "beta_psql", database)
    with pytest.raises(proof.HostProbeError, match="references differ"):
        proof.persisted_rows(PLAN, FLOW_INPUT, APPLICATION_INPUT,
                             INSTANCE, JOB, APPLICATION,
                             runner=lambda _args: "")


def test_unmarked_row_fails_closed():
    with pytest.raises(proof.HostProbeError, match="no dispatch marker"):
        proof.probe(PLAN, FLOW_INPUT, "0" * 64,
                    APPLICATION_INPUT, APP_DIGEST, "session=secret", REFERENCE,
                    allow_post=True, expected_transition_txid="456",
                    runner=runner_for(lambda: True),
                    request=lambda *_args: pytest.fail("must not request"),
                    owner_verifier=lambda _plan, **_kwargs: OWNER)


def test_cli_dispatch_selection_survives_intent_only_crash(tmp_path, monkeypatch, capsys):
    plan_path = tmp_path / "plan.json"
    flow_path = tmp_path / "flow.json"
    application_path = tmp_path / "application.json"
    session_path = tmp_path / "session.txt"
    intent_path = tmp_path / "intent.json"
    plan_path.write_text(json.dumps(PLAN), encoding="utf-8")
    flow_path.write_text(json.dumps(FLOW_INPUT), encoding="utf-8")
    application_path.write_text(json.dumps(APPLICATION_INPUT), encoding="utf-8")
    session_path.write_text("session=secret", encoding="utf-8")
    digest = proof.checked_flow(flow_path)[1]
    intent_path.write_text(json.dumps({
        "schema": "marty.passport-beta-rust-owner-flow-intent/v1",
        "source_commit": PLAN["source_commit"],
        "flow_file_sha256": digest,
        "application_file_sha256": proof.checked_application(application_path)[1],
        "transition_txid": "456",
        "external_reference": REFERENCE,
    }), encoding="utf-8")
    seen = []

    def fake_probe(_plan, _flow, _digest, _application, _application_digest,
                   _session, _reference, **kwargs):
        seen.append(kwargs["allow_post"])
        return {"transition_txid": "456"}

    monkeypatch.setattr(proof, "probe", fake_probe)
    monkeypatch.setattr(sys, "argv", [
        "probe", "--plan", str(plan_path), "--flow-file", str(flow_path),
        "--application-file", str(application_path),
        "--session-file", str(session_path), "--intent", str(intent_path),
    ])
    proof.main()
    capsys.readouterr()
    marker_path = tmp_path / "intent.json.dispatch.json"
    marker_path.write_text("{}", encoding="utf-8")
    proof.main()
    assert seen == [True, False]
