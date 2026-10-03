"""The aggregate cutover must establish the selected chain through Gateway."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import probe_passport_beta_aggregate_ceremony as ceremony_gate
from scripts.probe_passport_beta_host import HostProbeError
from tests.test_probe_passport_beta_aggregate_kms import selected
from tests.test_probe_passport_beta_chain import certificates


GATEWAY = "a" * 64
SOURCE = "f" * 40


def ceremony_plan():
    choice = selected()
    return {
        "organization_id": choice["organization_id"],
        "csca": {
            "issuer_did": choice["csca_issuer_did"],
            "certificate_id": choice["csca_certificate_id"],
            "credential_format": "ICAO_EMRTD", "country": "US",
            "organization": "Marty", "common_name": "Marty Beta CSCA",
            "validity_days": 365,
        },
        "dsc": {
            "dsc_issuer_did": choice["dsc_issuer_did"],
            "csca_issuer_did": choice["csca_issuer_did"],
            "csca_certificate_id": choice["csca_certificate_id"],
            "credential_format": "ICAO_EMRTD", "country": "US",
            "organization": "Marty", "common_name": "Marty Beta DSC",
            "validity_days": 30, "idempotency_key": "beta-dsc-one",
        },
    }


def test_ceremony_file_matches_selected_profile_and_request(tmp_path: Path) -> None:
    path = tmp_path / "ceremony.json"
    path.write_text(json.dumps(ceremony_plan()), encoding="utf-8")
    plan, digest = ceremony_gate.checked_ceremony(path, selected())
    assert plan == ceremony_plan()
    assert len(digest) == 64
    changed = ceremony_plan()
    changed["dsc"]["csca_certificate_id"] = "another"
    path.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(HostProbeError, match="ceremony file is invalid"):
        ceremony_gate.checked_ceremony(path, selected())


def test_gateway_transport_uses_normal_authorized_route_and_keeps_cookie_private(
    monkeypatch,
) -> None:
    seen = []

    def docker(command, payload=b"", *, timeout=30):
        seen.append((command, payload, timeout))
        return (b"HTTP/1.1 200 OK\r\nx-request-id: trace-1\r\n"
                b"content-type: application/json\r\n\r\n"
                b'{"identity":{"status":"active"}}')

    monkeypatch.setattr(ceremony_gate, "docker_bytes", docker)
    status, response, request_id = ceremony_gate.gateway_post(
        GATEWAY, ceremony_gate.IDENTITY_ROUTE, "org-a", "secret-cookie",
        {"organization_id": "org-a"})
    assert (status, response["identity"]["status"], request_id) == (
        200, "active", "trace-1")
    command, payload, timeout = seen[0]
    assert command[-1] == (
        "http://127.0.0.1:8000/v1/signing-keys/issuer-identities?organization_id=org-a")
    assert b"secret-cookie\n" in payload and "secret-cookie" not in str(command)
    assert timeout == 120
    with pytest.raises(HostProbeError, match="request input is invalid"):
        ceremony_gate.gateway_post(GATEWAY, "/internal/compat/issuer-dids/sign",
                                   "org-a", "secret-cookie",
                                   {"organization_id": "org-a"})


def test_governed_gateway_provisions_then_issues_idempotent_chain(
    tmp_path: Path, monkeypatch,
) -> None:
    csca_pem, dsc_pem, _ = certificates()
    selection = selected()
    calls = []
    monkeypatch.setattr(ceremony_gate, "signed_service",
                        lambda plan, service, runner: GATEWAY)
    monkeypatch.setattr(ceremony_gate, "staged_public_domain",
                        lambda plan, runner: "beta.elevenidllc.com")

    def post(container, route, org, cookie, body):
        assert container == GATEWAY and org == "org-a"
        calls.append((route, cookie, body))
        if route == ceremony_gate.IDENTITY_ROUTE:
            return 200, {"identity": {key: value for key, value in body.items()
                                      if key != "organization_id"} | {"status": "active"},
                         "created": True}, "trace-id"
        if route == ceremony_gate.CSCA_ROUTE:
            return 200, {"status": "issued", "certificate_id": body["certificate_id"],
                         "issuer_did": body["issuer_did"],
                         "certificate_pem": csca_pem}, "trace-id"
        assert route == ceremony_gate.DSC_ROUTE
        return 200, {"status": "issued", "dsc_issuer_did": body["dsc_issuer_did"],
                     "csca_issuer_did": body["csca_issuer_did"],
                     "certificate_pem": dsc_pem, "chain_pem": csca_pem}, "trace-id"

    def issue():
        return ceremony_gate.issue(
            {"schema": "marty.passport-beta-aggregate-compose-plan/v1",
             "source_commit": SOURCE},
            {"organization_id": "org-a", "issuer_did": selection["dsc_issuer_did"]},
            selection, ceremony_plan(),
            {"application": "1" * 64, "selection": "2" * 64,
             "ceremony": "3" * 64},
            "csca-cookie", "dsc-cookie", tmp_path / "intent.json", post=post)

    first = issue()
    assert first["verified"] is True
    assert first["gateway_request_traces_verified"] is True
    assert first["certificate_chain_verified"] is True
    assert [route for route, _, _ in calls] == [
        ceremony_gate.IDENTITY_ROUTE, ceremony_gate.IDENTITY_ROUTE,
        ceremony_gate.CSCA_ROUTE, ceremony_gate.DSC_ROUTE]
    assert [cookie for _, cookie, _ in calls] == [
        "csca-cookie", "dsc-cookie", "csca-cookie", "dsc-cookie"]
    assert issue() == first
    assert "cookie" not in json.dumps(first)


def test_ceremony_refuses_changed_intent_or_same_authority(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(ceremony_gate, "signed_service",
                        lambda plan, service, runner: GATEWAY)
    monkeypatch.setattr(ceremony_gate, "staged_public_domain",
                        lambda plan, runner: "beta.elevenidllc.com")
    selection = selected()
    arguments = (
        {"schema": "marty.passport-beta-aggregate-compose-plan/v1",
         "source_commit": SOURCE},
        {"organization_id": "org-a", "issuer_did": selection["dsc_issuer_did"]},
        selection, ceremony_plan(),
        {"application": "1" * 64, "selection": "2" * 64,
         "ceremony": "3" * 64},
    )
    with pytest.raises(HostProbeError, match="authorities differ"):
        ceremony_gate.issue(*arguments, "one-cookie", "one-cookie",
                            tmp_path / "intent.json")
    intent = tmp_path / "intent.json"
    intent.write_text(json.dumps({"wrong": True}), encoding="utf-8")
    with pytest.raises(HostProbeError, match="intent differs"):
        ceremony_gate.issue(*arguments, "csca-cookie", "dsc-cookie", intent)


def test_staged_domain_and_local_dids_are_checked_before_intent(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(ceremony_gate, "signed_service",
                        lambda plan, service, runner: GATEWAY)
    monkeypatch.setattr(ceremony_gate, "inspect",
                        lambda container, runner: {"Config": {"Env": [
                            "PUBLIC_DOMAIN=beta.elevenidllc.com"]}})
    plan = {"schema": "marty.passport-beta-aggregate-compose-plan/v1",
            "source_commit": SOURCE, "beta_origin": "https://beta.elevenidllc.com"}
    assert ceremony_gate.staged_public_domain(plan, lambda *_: "") == (
        "beta.elevenidllc.com")
    selection = selected() | {"csca_issuer_did": "did:web:other.example:orgs:org-a:csca"}
    intent = tmp_path / "intent.json"
    with pytest.raises(HostProbeError, match="outside staged managed domain"):
        ceremony_gate.issue(
            plan, {"organization_id": "org-a", "issuer_did": selection["dsc_issuer_did"]},
            selection, ceremony_plan(),
            {"application": "1" * 64, "selection": "2" * 64,
             "ceremony": "3" * 64},
            "csca-cookie", "dsc-cookie", intent)
    assert not intent.exists()
    plan["beta_origin"] = "https://other.example"
    with pytest.raises(HostProbeError, match="public domain differs"):
        ceremony_gate.staged_public_domain(plan, lambda *_: "")


def test_ceremony_precedes_read_only_kms_and_owner_switch() -> None:
    script = (Path(__file__).resolve().parents[1] / "scripts"
              / "run-passport-beta-aggregate-deploy.ps1").read_text(encoding="utf-8")
    assert script.index("probe_passport_beta_aggregate_ceremony.py") < script.index(
        "probe_passport_beta_aggregate_kms.py") < script.index(
        "$owner = Invoke-RustOwnerTransition")
