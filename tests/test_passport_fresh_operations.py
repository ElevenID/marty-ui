"""Orchestration controls only; fake ports do not qualify a passport demo."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import passport_fresh_operations as fresh


def plan() -> dict:
    issuer = "did:web:beta.example:issuers:org-a"
    return {
        "certificate_plan": {
            "organization_id": "org-a",
            "csca": {"issuer_did": issuer, "certificate_id": "test-csca",
                     "credential_format": "ICAO_EMRTD", "country": "US",
                     "organization": "Disposable Beta", "common_name": "Test CSCA",
                     "validity_days": 365},
            "dsc": {"dsc_issuer_did": issuer, "csca_issuer_did": issuer,
                    "csca_certificate_id": "test-csca", "credential_format": "ICAO_EMRTD",
                    "country": "US", "organization": "Disposable Beta",
                    "common_name": "Test DSC", "validity_days": 30,
                    "idempotency_key": "fresh-test-dsc"},
        },
        "application": {"organization_id": "org-a", "issuer_did": issuer},
        "selected_flow": {"flow_definition_id": "flow-definition-a",
                          "references": {"application_template_id": "app-template",
                                         "credential_template_id": "credential-template",
                                         "delivery_destination_profile_id": "delivery-profile"},
                          "physical_document": {"country_code": "US", "applicant": {"name": "Test"},
                                                "mrz": "test-mrz", "data_groups": {"DG1": "test"}}},
    }


@pytest.fixture
def ports(tmp_path: Path, monkeypatch):
    # Production custody code rejects paths under cwd; isolate the test process's
    # cwd rather than weakening that gate or replacing private-state writers.
    working = tmp_path / "working"
    working.mkdir()
    monkeypatch.chdir(working)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    state = private / "wire.json"
    handoff = private / "handoff.json"
    calls = []
    commitments = {"source_job_commitment": "a" * 64, "bureau_job_commitment": "b" * 64}
    bureau = "11111111-2222-4333-8444-555555555555"

    def chain_probe(*args, on_dsc_material, **kwargs):
        calls.append("chain")
        on_dsc_material("c" * 64, "d" * 64)
        return {"verified": True, "evidence": {"dsc_certificate_sha256": "c" * 64}}

    def batch_probe(*args):
        calls.append("batch")
        state.write_text("owned-wire-key", encoding="utf-8")
        assert args[7:11] == ("new-instance", "new-application", "new-job", "e" * 64)
        return bureau, {"verified": True, "evidence": {
            "selected_source_job_commitment": commitments["source_job_commitment"],
            "selected_bureau_job_commitment": commitments["bureau_job_commitment"]}}

    def material(*args):
        calls.append("material")
        assert args[:4] == ("org-a", "new-job", bureau, "e" * 64)
        return {"verified": True, "evidence": {
            "source_job_id_commitment": commitments["source_job_commitment"],
            "bureau_job_id_commitment": commitments["bureau_job_commitment"]}}

    def flow_probe(*args, on_signed_sod, on_submission, **kwargs):
        calls.append("flow")
        assert on_signed_sod("new-instance", "new-application", "new-job", "e" * 64) == bureau
        on_submission("org-a", "new-job", bureau, "e" * 64)
        return {"verified": True, "evidence": {
            "organization_id": "org-a", "flow_id": "flow-definition-a",
            "flow_instance_id": "new-instance", "application_id": "new-application",
            "job_id": "new-job", "bureau_job_id": bureau, "sod_sha256": "e" * 64,
            "terminal_native_status": "ACTIVE", "signed_simulator_callback_verified": True,
            "physical_claim": "not_claimed", **commitments}}

    def negative(private_handoff, *args, **kwargs):
        calls.append("negative")
        assert private_handoff == json.loads(handoff.read_text(encoding="utf-8"))
        assert private_handoff["source_job_id"] == "new-job"
        assert state.exists()
        return {"schema": "marty.passport-beta-negative-callbacks/v1", "verified": True,
                "physical_claim": "not_claimed", "unsigned": {"http_status": 422, **commitments},
                "foreign": {"http_status": 404, **commitments}}

    kwargs = dict(source_commit="1" * 40, stack_manifest_sha256="2" * 64,
                  csca_session="sessionId=governed-csca", dsc_session="sessionId=governed-dsc",
                  flow_session="sessionId=flow", api_key="secret-api-key-" * 4,
                  service_token="service-" * 8, operator_token="operator-" * 8,
                  native_container_id="3" * 64, simulator_container_id="4" * 64,
                  private_state_path=state, private_handoff_path=handoff,
                  verify_runtime=lambda: calls.append("runtime"), chain_probe=chain_probe,
                  flow_probe=flow_probe, batch_probe=batch_probe, material_receipt=material,
                  negative_probe=negative)
    return kwargs, calls, state, handoff


def test_fresh_returned_tuple_drives_denials_and_private_recovery(ports):
    kwargs, calls, state, handoff = ports
    result = fresh.exercise(plan(), **kwargs)
    assert calls == ["runtime", "chain", "flow", "batch", "material", "negative"]
    assert not state.exists() and handoff.exists()
    assert result["operations_verified"] is True and result["demo_qualified"] is False
    assert result["cleanup_scope"] == "native_batch_wire_state_only"
    serialized = json.dumps(result)
    assert all(value not in serialized for value in
               ("new-job", "new-application", "new-instance", "secret-api-key", "governed-csca"))


@pytest.mark.parametrize("field", ["job_id", "report", "video", "receipt"])
def test_prior_result_inputs_never_reach_producers(ports, field):
    kwargs, calls, _, _ = ports
    candidate = plan()
    candidate["selected_flow"][field] = "previous-run"
    with pytest.raises(fresh.FreshOperationError, match="adopt prior"):
        fresh.exercise(candidate, **kwargs)
    assert calls == []


def test_runtime_failure_prevents_all_mutations(ports):
    kwargs, calls, _, _ = ports
    kwargs["verify_runtime"] = Mock(side_effect=ValueError("protected passport roles missing"))
    with pytest.raises(ValueError, match="roles missing"):
        fresh.exercise(plan(), **kwargs)
    assert calls == []


def test_existing_recovery_state_cannot_be_adopted(ports):
    kwargs, calls, state, _ = ports
    state.write_text("prior-owned-state", encoding="utf-8")
    with pytest.raises(ValueError, match="Pending native batch"):
        fresh.exercise(plan(), **kwargs)
    assert calls == [] and state.read_text() == "prior-owned-state"


def test_negative_failure_preserves_wire_state_and_returned_handoff(ports):
    kwargs, calls, state, handoff = ports
    kwargs["negative_probe"] = Mock(side_effect=ValueError("fresh foreign callback changed job"))
    with pytest.raises(ValueError, match="changed job"):
        fresh.exercise(plan(), **kwargs)
    assert state.exists() and handoff.exists()
    assert "material" in calls


def test_mismatched_returned_flow_job_blocks_negative_operations(ports):
    kwargs, calls, state, handoff = ports
    original = kwargs["flow_probe"]

    def wrong(*args, **options):
        result = original(*args, **options)
        result["evidence"]["job_id"] = "other-job"
        return result

    kwargs["flow_probe"] = wrong
    with pytest.raises(fresh.FreshOperationError, match="returned active job"):
        fresh.exercise(plan(), **kwargs)
    assert state.exists() and not handoff.exists() and "negative" not in calls


def test_negative_success_for_another_job_does_not_clear_recovery(ports):
    kwargs, _, state, handoff = ports
    original = kwargs["negative_probe"]

    def wrong(*args, **options):
        result = original(*args, **options)
        result["foreign"]["source_job_commitment"] = "f" * 64
        return result

    kwargs["negative_probe"] = wrong
    with pytest.raises(fresh.FreshOperationError, match="negative operations"):
        fresh.exercise(plan(), **kwargs)
    assert state.exists() and handoff.exists()
