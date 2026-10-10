"""The beta owner switch must follow live, selected managed issuer custody."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import ssl

import pytest

from scripts import probe_passport_beta_aggregate_kms as gate
from scripts.probe_passport_beta_host import HostProbeError
from tests.test_probe_passport_beta_chain import certificates
from tests.test_verify_passport_beta_issuer_profiles import resolution


CSCA_DID = "did:web:beta.elevenidllc.com:orgs:org-a:csca"
DSC_DID = "did:web:beta.elevenidllc.com:orgs:org-a:dsc"
SIGNING_KEYS = "a" * 64
OPENBAO = "b" * 64


def selected() -> dict[str, str]:
    return {
        "organization_id": "org-a",
        "csca_issuer_did": CSCA_DID,
        "csca_certificate_id": "beta-csca-1",
        "dsc_issuer_did": DSC_DID,
    }


def test_selected_docker_context_is_explicit_and_ignores_ambient_host(
    monkeypatch,
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "tcp://wrong-daemon:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "wrong-context")
    seen = []

    def run(command, **options):
        seen.append((command, options["env"]))
        return type("Result", (), {"returncode": 0, "stdout": b"ok"})()

    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate.docker_bytes(["docker", "exec", SIGNING_KEYS, "true"],
                             context="beta-selected") == b"ok"
    command, environment = seen[0]
    assert command[:4] == ["docker", "--context", "beta-selected", "exec"]
    assert "DOCKER_HOST" not in environment
    assert "DOCKER_CONTEXT" not in environment


def test_docker_identity_rejects_mismatched_daemon_before_requests(
    monkeypatch,
) -> None:
    calls = []

    def text(command, *, context=None):
        calls.append((command, context))
        return "beta-selected" if command[1] == "context" else "wrong-daemon"

    monkeypatch.setattr(gate, "docker_text", text)
    with pytest.raises(HostProbeError, match="context or daemon changed"):
        gate.checked_docker_context({
            "docker": {"context": "beta-selected", "daemon_id": "planned-daemon"}})
    assert calls == [
        (["docker", "context", "show"], None),
        (["docker", "info", "--format", "{{.ID}}"], "beta-selected"),
    ]


def test_chain_selection_requires_exact_tenant_and_distinct_dids(tmp_path: Path) -> None:
    path = tmp_path / "selection.json"
    path.write_text(json.dumps(selected()), encoding="utf-8")
    value, digest = gate.checked_selection(path)
    assert value == selected()
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    dotted = selected() | {"csca_certificate_id": "beta.csca:1"}
    path.write_text(json.dumps(dotted), encoding="utf-8")
    assert gate.checked_selection(path)[0] == dotted
    for mutation in (
        {"dsc_issuer_did": CSCA_DID},
        {"csca_certificate_id": "../foreign"},
        {"extra": "ignored"},
    ):
        bad = selected() | mutation
        path.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(HostProbeError):
            gate.checked_selection(path)


def test_transit_key_requires_nonexportable_live_ecdsa_version(monkeypatch) -> None:
    response = {"data": {"type": "ecdsa-p256", "exportable": False,
                         "latest_version": 3}}
    monkeypatch.setattr(gate, "docker_json", lambda command: response)
    assert gate.transit_key_version(OPENBAO, "managed-kms-dsc") == 3
    for field, value in (("exportable", True), ("type", "rsa-2048"),
                         ("latest_version", 0), ("latest_version", "3")):
        bad = copy.deepcopy(response)
        bad["data"][field] = value
        monkeypatch.setattr(gate, "docker_json", lambda command, result=bad: result)
        with pytest.raises(HostProbeError, match="nonexportable KMS custody"):
            gate.transit_key_version(OPENBAO, "managed-kms-dsc")
    with pytest.raises(HostProbeError, match="reference is invalid"):
        gate.transit_key_version(OPENBAO, "../foreign")


def fixture(monkeypatch):
    csca_pem, dsc_pem, _ = certificates()
    csca = resolution("csca")
    dsc = resolution("dsc")
    csca["issuer_did"] = csca["issuer_profile"]["issuer_did"] = CSCA_DID
    dsc["issuer_did"] = dsc["issuer_profile"]["issuer_did"] = DSC_DID
    dsc["issuer_x5c"] = [
        base64.b64encode(ssl.PEM_cert_to_DER_cert(dsc_pem)).decode("ascii")]
    responses = {"csca": csca, "x509_doc_signer": dsc}
    calls = {"sign": [], "proof": []}
    versions = {"managed-kms-csca": 1, "managed-kms-dsc": 2}
    record = {
        "status": "VALID", "certificate_id": "beta-csca-1",
        "metadata": {"issuer_did": CSCA_DID},
        "key_reference": "managed-kms-csca", "revoked_at": None,
        "cert_pem": csca_pem,
    }
    monkeypatch.setattr(gate, "signed_service",
                        lambda plan, service, runner: SIGNING_KEYS)
    monkeypatch.setattr(gate, "current_openbao",
                        lambda plan, runner: OPENBAO)

    def verify_live(*args, signer):
        calls["proof"].append(args)
        signer("org-a", CSCA_DID, "csca", b"c" * 48)
        signer("org-a", DSC_DID, "x509_doc_signer", b"d" * 48)
        return {"managed_kms_custody_verified": True, "chain_verified": True}

    monkeypatch.setattr(gate, "verify_live_signatures", verify_live)

    def sign(container, org, did, purpose, challenge):
        calls["sign"].append((container, org, did, purpose, challenge))
        return {"ok": True}

    def prove():
        return gate.prove(
            {"schema": "marty.passport-beta-aggregate-compose-plan/v1",
             "source_commit": "f" * 40},
            {"organization_id": "org-a", "issuer_did": DSC_DID},
            selected(), "1" * 64, "2" * 64,
            resolver=lambda container, org, did, purpose: responses[purpose],
            signer=sign,
            get_csca=lambda container, org, cert: record,
            key_version=lambda container, reference: versions[reference],
        )

    return prove, responses, record, versions, calls


def test_pretransition_binds_live_profiles_chain_keys_and_signatures(monkeypatch) -> None:
    prove, _, _, _, calls = fixture(monkeypatch)
    result = prove()
    assert result["verified"] is True
    assert result["managed_kms_custody_verified"] is True
    assert result["chain_verified"] is True
    assert result["private_key_exported"] is False
    assert result["key_versions"] == {"csca": 1, "dsc": 2}
    assert len(calls["proof"]) == 1
    assert [(call[0], call[3]) for call in calls["sign"]] == [
        (SIGNING_KEYS, "csca"), (SIGNING_KEYS, "x509_doc_signer")]
    assert "managed-kms-dsc" not in str(result)


def test_pretransition_rejects_stale_certificate_and_rotated_key(monkeypatch) -> None:
    prove, responses, record, versions, _ = fixture(monkeypatch)
    record["status"] = "REVOKED"
    with pytest.raises(HostProbeError, match="active CSCA"):
        prove()
    record["status"] = "VALID"
    record["key_reference"] = "old-csca-key"
    with pytest.raises(HostProbeError, match="managed profile"):
        prove()
    record["key_reference"] = "managed-kms-csca"
    original = responses["csca"]
    count = 0

    def rotate(container, org, did, purpose):
        nonlocal count
        count += 1
        if purpose == "csca" and count > 2:
            changed = copy.deepcopy(original)
            changed["issuer_profile"]["signing_key_reference"] = "rotated-key"
            return changed
        return responses[purpose]

    with pytest.raises(HostProbeError, match="changed during"):
        gate.prove(
            {"schema": "marty.passport-beta-aggregate-compose-plan/v1",
             "source_commit": "f" * 40},
            {"organization_id": "org-a", "issuer_did": DSC_DID},
            selected(), "1" * 64, "2" * 64,
            resolver=rotate,
            signer=lambda *args: {"ok": True},
            get_csca=lambda *args: record,
            key_version=lambda container, reference: versions[reference],
        )
