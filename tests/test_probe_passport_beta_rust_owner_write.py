"""Private beta write proof must come from the signed Rust process and database."""

from __future__ import annotations

import json

import pytest

from scripts import probe_passport_beta_rust_owner_write as probe


CONTAINER = "a" * 64
JOB = "11111111-1111-4111-8111-111111111111"
APPLICATION = "22222222-2222-4222-8222-222222222222"
FLOW = "rust-owner-" + "3" * 32


def inputs():
    plan = {
        "source_commit": "b" * 40,
        "postgres_container_id": "c" * 64,
        "services_image": "services@sha256:" + "d" * 64,
        "old_container_ids_by_service": {"issuance-native": "e" * 64},
    }
    application = {
        "organization_id": "org-1", "issuer_did": "did:example:issuer",
        "application_template_id": "template-1",
        "credential_template_id": "credential-1",
        "delivery_destination_profile_id": "destination-1",
    }
    owner = {"verified": True, "source_commit": plan["source_commit"],
             "postgres_container_id": plan["postgres_container_id"],
             "transition_txid": "9"}
    return plan, application, owner


def test_private_rust_application_write_matches_database(monkeypatch):
    plan, application, owner = inputs()
    monkeypatch.setattr(probe, "inspect", lambda *_: {
        "Id": CONTAINER,
        "Config": {"Image": plan["services_image"], "Labels": {
            "com.docker.compose.project": "elevenid-beta",
            "com.docker.compose.service": "issuance-native"}},
        "State": {"Running": True, "Status": "running"},
    })
    calls = []
    markers = []

    def request(command, body):
        calls.append((command, json.loads(body)))
        return (json.dumps({"id": JOB, "application_id": APPLICATION,
                            "organization_id": "org-1", "status": "DRAFT",
                            "flow_execution_id": json.loads(body)["flow_execution_id"]})
                + "\n201").encode()

    monkeypatch.setattr(probe, "beta_psql", lambda sql, *_: (
        "" if sql.startswith("SELECT id ||") else f"{APPLICATION}|DRAFT"))
    result = probe.probe(
        plan, application, "f" * 64,
        flow_execution_id=FLOW, allow_post=True,
        expected_transition_txid="9", before_post=markers.append,
        runner=lambda _: CONTAINER[:12], request=request,
        owner_verifier=lambda *_args, **_kwargs: owner,
    )
    assert result["database_row_verified"] is True
    assert result["job_id"] == JOB
    assert result["issuance_container_id"] == CONTAINER
    assert calls[0][0][:4] == ["docker", "exec", "-i", CONTAINER]
    assert "$GRPC_SERVICE_TOKEN" in calls[0][0][-1]
    assert calls[0][1]["flow_execution_id"] == FLOW
    assert markers[0]["issuance_container_id"] == CONTAINER
    resumed = probe.probe(
        plan, application, "f" * 64, flow_execution_id=FLOW,
        allow_post=False, expected_transition_txid="9",
        runner=lambda _: CONTAINER[:12],
        request=lambda *_: pytest.fail("resumed proof repeated write"),
        owner_verifier=lambda *_args, **_kwargs: owner, existing=result,
        dispatch_marker=markers[0],
    )
    assert resumed == result


def test_private_rust_write_rejects_missing_database_row(monkeypatch):
    plan, application, owner = inputs()
    monkeypatch.setattr(probe, "inspect", lambda *_: {
        "Id": CONTAINER,
        "Config": {"Image": plan["services_image"], "Labels": {
            "com.docker.compose.project": "elevenid-beta",
            "com.docker.compose.service": "issuance-native"}},
        "State": {"Running": True, "Status": "running"},
    })
    monkeypatch.setattr(probe, "beta_psql", lambda *_: "")

    def request(_, body):
        return (json.dumps({"id": JOB, "application_id": APPLICATION,
                            "organization_id": "org-1", "status": "DRAFT",
                            "flow_execution_id": json.loads(body)["flow_execution_id"]})
                + "\n201").encode()

    with pytest.raises(probe.HostProbeError, match="database row differs"):
        probe.probe(plan, application, "f" * 64,
                    flow_execution_id=FLOW, allow_post=True,
                    expected_transition_txid="9", before_post=lambda _: None,
                    runner=lambda _: CONTAINER[:12], request=request,
                    owner_verifier=lambda *_args, **_kwargs: owner)


def test_private_rust_write_recovers_committed_row_without_repeating_post(monkeypatch):
    plan, application, owner = inputs()
    monkeypatch.setattr(probe, "inspect", lambda *_: {
        "Id": CONTAINER,
        "Config": {"Image": plan["services_image"], "Labels": {
            "com.docker.compose.project": "elevenid-beta",
            "com.docker.compose.service": "issuance-native"}},
        "State": {"Running": True, "Status": "running"},
    })
    monkeypatch.setattr(probe, "beta_psql", lambda sql, *_: (
        f"{JOB}|{APPLICATION}|DRAFT" if sql.startswith("SELECT id ||")
        else f"{APPLICATION}|DRAFT"))
    result = probe.probe(
        plan, application, "f" * 64, flow_execution_id=FLOW,
        allow_post=False, expected_transition_txid="9",
        runner=lambda _: CONTAINER[:12],
        request=lambda *_: pytest.fail("recovery repeated write"),
        owner_verifier=lambda *_args, **_kwargs: owner,
    )
    assert result["job_id"] == JOB
    assert result["flow_execution_id"] == FLOW


def test_private_rust_write_refuses_uncertain_retry(monkeypatch):
    plan, application, owner = inputs()
    monkeypatch.setattr(probe, "inspect", lambda *_: {
        "Id": CONTAINER,
        "Config": {"Image": plan["services_image"], "Labels": {
            "com.docker.compose.project": "elevenid-beta",
            "com.docker.compose.service": "issuance-native"}},
        "State": {"Running": True, "Status": "running"},
    })
    monkeypatch.setattr(probe, "beta_psql", lambda *_: "")
    with pytest.raises(probe.HostProbeError, match="no resolved database row"):
        probe.probe(
            plan, application, "f" * 64, flow_execution_id=FLOW,
            allow_post=False, expected_transition_txid="9",
            runner=lambda _: CONTAINER[:12],
            request=lambda *_: pytest.fail("uncertain retry repeated write"),
            owner_verifier=lambda *_args, **_kwargs: owner,
        )
