"""The aggregate operator provisions references in the fenced phase and Flow afterward."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest

from scripts import probe_passport_beta_reference_provision as probe
from scripts.passport_supported_flow_start import STEPS


ORG = "00000000-0000-0000-0000-000000000019"
ISSUER = "did:web:beta.elevenidllc.com:orgs:pilot"
GATEWAY = "a" * 64
FLOW = "b" * 64


class Gateway:
    def __init__(self):
        self.rows = {path: [] for path in (
            "/v1/credential-templates", "/v1/application-templates",
            "/v1/delivery-destinations", "/v1/flows/definitions",
        )}
        self.posts = []

    def __call__(self, container, session, method, path, body, headers):
        assert container == GATEWAY and session == "pilot-session"
        route = urlsplit(path)
        base = route.path
        if method == "GET" and route.query:
            rows = deepcopy(self.rows[base])
            query = parse_qs(route.query)
            assert query["organization_id"] == [ORG]
            offset = int(query.get("offset", [0])[0])
            limit = int(query.get("limit", [len(rows)])[0])
            return 200, rows[offset:offset + limit]
        for collection, rows in self.rows.items():
            for row in rows:
                item = f"{collection}/{row['id']}"
                if method == "GET" and base == item:
                    return 200, deepcopy(row)
                if method == "POST" and base == item + "/activate":
                    self.posts.append(base)
                    row["status"] = "ACTIVE"
                    return 200, deepcopy(row)
                if method == "POST" and base == item + "/validate":
                    return 200, {"valid": True, "errors": []}
        assert method == "POST" and base in self.rows
        self.posts.append(base)
        identifier = body.get("id") or str(UUID(int=len(self.posts)))
        row = {**body, "id": identifier, "status": "DRAFT"}
        if base == "/v1/credential-templates":
            row["revocation_profile_id"] = None
        if base == "/v1/delivery-destinations":
            row["is_system"] = False
        if base == "/v1/flows/definitions":
            row["resolved_steps"] = list(STEPS)
        self.rows[base].append(row)
        return (201 if base == "/v1/delivery-destinations" else 200), deepcopy(row)


def test_reference_and_flow_phases_create_once_and_resume_without_writes(
    tmp_path, monkeypatch,
):
    gateway = Gateway()
    phase = "fully_fenced"
    profile_posts = []

    def beta_psql(sql, runner, container):
        assert "passport_cutover.state" in sql
        return phase

    def signed_service(plan, service, runner):
        return GATEWAY if service == "gateway" else FLOW

    def gateway_post(container, route, organization, cookie, body):
        profile_posts.append(body)
        assert cookie == "dsc-session" and organization == ORG
        return 200, {"identity": {**body, "status": "active"}}, "request-id"

    monkeypatch.setattr(probe, "beta_psql", beta_psql)
    monkeypatch.setattr(probe, "signed_service", signed_service)
    monkeypatch.setattr(probe, "staged_public_domain", lambda plan, runner: "beta.elevenidllc.com")
    monkeypatch.setattr(probe, "gateway_post", gateway_post)
    monkeypatch.setattr(probe, "private_gateway_json", gateway)
    plan = {"schema": "marty.passport-beta-aggregate-compose-plan/v1",
            "source_commit": "c" * 40, "postgres_container_id": "d" * 64}
    selection = {"organization_id": ORG, "dsc_issuer_did": ISSUER}
    intent = tmp_path / "intents"
    application = tmp_path / "application.json"
    flow = tmp_path / "flow.json"

    references = probe.provision(
        plan, selection, "pilot-session", "dsc-session", intent,
        application, None, phase="references",
    )
    assert references["verified"] is True and application.is_file()
    assert not gateway.rows["/v1/flows/definitions"]
    first_posts = list(gateway.posts)
    assert len(first_posts) == 5  # Three creates, two activations.
    phase = "rust_owner"
    resumed = probe.provision(
        plan, selection, "pilot-session", "dsc-session", intent,
        application, None, phase="references",
    )
    assert resumed["application_file_sha256"] == references["application_file_sha256"]
    assert gateway.posts == first_posts
    created_flow = probe.provision(
        plan, selection, "pilot-session", None, intent,
        application, flow, phase="flow",
    )
    assert created_flow["verified"] is True and flow.is_file()
    assert len(gateway.posts) == len(first_posts) + 2
    probe.provision(plan, selection, "pilot-session", None, intent,
                    application, flow, phase="flow")
    assert len(gateway.posts) == len(first_posts) + 2
    assert len(profile_posts) == 1  # Rust-owner resume does not write KMS.


def test_reference_creation_cannot_start_after_owner_transition(tmp_path, monkeypatch):
    monkeypatch.setattr(probe, "beta_psql", lambda *args: "rust_owner")
    monkeypatch.setattr(probe, "signed_service", lambda plan, service, runner:
                        GATEWAY if service == "gateway" else FLOW)
    monkeypatch.setattr(probe, "staged_public_domain", lambda *args: "beta.elevenidllc.com")
    monkeypatch.setattr(probe, "gateway_post", lambda *args:
                        (200, {"identity": {**args[4], "status": "active"}}, "request-id"))
    monkeypatch.setattr(probe, "private_gateway_json", Gateway())
    plan = {"schema": "marty.passport-beta-aggregate-compose-plan/v1",
            "source_commit": "c" * 40, "postgres_container_id": "d" * 64}
    with pytest.raises(ValueError, match="lacks sealed pretransition state"):
        probe.provision(plan, {"organization_id": ORG, "dsc_issuer_did": ISSUER},
                        "pilot-session", "dsc-session", tmp_path / "intents",
                        tmp_path / "application.json", None, phase="references")


def test_aggregate_operator_orders_real_reference_and_flow_writes_around_fence():
    operator = (Path(__file__).resolve().parents[1]
                / "scripts/run-passport-beta-aggregate-deploy.ps1").read_text()
    staged = operator.index("Wait-BetaHealthy -Services $applications")
    references = operator.index("'--phase', 'references'")
    ceremony = operator.index("$ceremonyProof = Invoke-Plan")
    transition = operator.index("$owner = Invoke-RustOwnerTransition")
    flow = operator.index("'--phase', 'flow'")
    flow_validation = operator.index("$flowReferences = Invoke-Plan")
    ingress = operator.index("Invoke-Compose -Services @($script:plan.recreate_ingress_last)")
    assert staged < references < ceremony < transition < flow < flow_validation < ingress


def test_private_gateway_transport_accepts_scoped_list_and_keeps_cookie_on_stdin(
    monkeypatch,
):
    calls = []

    def run(command, **options):
        calls.append((command, options))
        return SimpleNamespace(
            returncode=0,
            stdout=b"HTTP/1.1 200 OK\r\nx-request-id: trace-1\r\n\r\n[]",
        )

    monkeypatch.setattr(probe.subprocess, "run", run)
    status, result = probe.private_gateway_json(
        GATEWAY, "secret-cookie", "GET",
        f"/v1/flows/definitions?organization_id={ORG}&limit=10&offset=0",
        None, {},
    )
    assert status == 200 and result == []
    assert calls[0][1]["input"] == b"secret-cookie\n"
    assert "secret-cookie" not in " ".join(calls[0][0])
    assert "--url" in calls[0][0][6]
