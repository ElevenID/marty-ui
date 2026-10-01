import copy
from datetime import datetime, timedelta, timezone

import pytest

from scripts.match_passport_beta_preliminary_soak import (
    LineageError, authenticate_preliminary_soak_lineage, match_preliminary_soak,
)


START = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
SOURCE = "a" * 40
STACK = "b" * 64
RECEIPT = "c" * 64
PLAN = "d" * 64
PRODUCTION = "e" * 64
ATTACHMENTS = "f" * 64
JOB = "1" * 64
BUREAU = "2" * 64


def live():
    return {
        "schema": "marty.passport-beta-acceptance/v1", "status": "blocked",
        "beta_origin": "https://beta.elevenidllc.com",
        "physical_claim": "not_claimed",
        "release": {"source_commit": SOURCE,
                    "stack_manifest_sha256": STACK,
                    "signed_manifest_verified": True},
        "deployment": {"provider_mode": "simulator",
                       "aggregate_deployment_receipt_sha256": RECEIPT,
                       "aggregate_plan_sha256": PLAN,
                       "production_snapshot_commitment": PRODUCTION,
                       "production_attachment_commitment": ATTACHMENTS},
    }


def preliminary():
    def verified(evidence):
        return {"verified": True, "evidence": evidence}

    selected = {"source_job_commitment": JOB, "bureau_job_commitment": BUREAU}
    return {
        "kind": "preliminary", "run_id": 111,
        "artifact_name": "passport-beta-preliminary-111",
        "artifact_sha256": "3" * 64,
        "workflow_commit": SOURCE,
        "run_completed_at_utc": START.isoformat(),
        "value": {
            "schema": "marty.passport-beta-preliminary/v1",
            "status": "qualified_for_recording",
            "beta_origin": "https://beta.elevenidllc.com",
            "physical_claim": "not_claimed",
            "synthetic_identities_only": True,
            "release": {"source_commit": SOURCE,
                        "stack_manifest_sha256": STACK,
                        "signed_manifest_verified": True},
            "deployment": {"provider_mode": "simulator",
                           "aggregate_deployment_receipt_sha256": RECEIPT,
                           "aggregate_plan_sha256": PLAN},
            "probes": {
                "managed_csca_dsc_chain": verified({}),
                "sod_signature": verified({}),
                "simulator_material_receipt": verified({}),
                "nine_route_gateway_flow": verified(selected),
                "physical_bureau_submission": verified({
                    "selected_source_job_commitment": JOB,
                    "selected_bureau_job_commitment": BUREAU}),
                "physical_bureau_batch": verified({
                    "selected_source_job_commitment": JOB,
                    "selected_bureau_job_commitment": BUREAU}),
                "signed_bureau_callback": verified(selected),
                "physical_claim_boundary": verified({
                    "physical_claim": "not_claimed", "booklet_verified": False}),
                "unsigned_or_foreign_callback_denied": verified(selected),
            },
        },
    }


def soak():
    return {
        "schema": "marty.passport-beta-soak-window/v1",
        "status": "protected_window_verified",
        "provenance_pending": False, "protected_runs_verified": True,
        "sample_count": 3, "minimum_hours": 24, "maximum_gap_hours": 13,
        "first_observed_at_utc": (START + timedelta(hours=1)).isoformat(),
        "last_observed_at_utc": (START + timedelta(hours=25)).isoformat(),
        "identity": {
            "release": {"source_commit": SOURCE,
                        "stack_manifest_sha256": STACK},
            "deployment": {
                "aggregate_deployment_receipt_sha256": RECEIPT,
                "aggregate_plan_sha256": PLAN,
                "production_snapshot_commitment": PRODUCTION,
                "production_attachment_commitment": ATTACHMENTS,
            },
            "selected_source_job_commitment": JOB,
            "selected_bureau_job_commitment": BUREAU,
        },
        "samples": [{"run_id": str(run)} for run in (222, 223, 224)],
    }


def test_matches_one_selected_job_after_preliminary_recording():
    result = match_preliminary_soak(live(), preliminary(), soak())
    assert result["release"] == {
        "source_commit": SOURCE, "stack_manifest_sha256": STACK}
    assert result["selected_source_job_commitment"] == JOB
    assert result["selected_bureau_job_commitment"] == BUREAU
    assert result["preliminary_run_id"] == 111
    assert len(result["soak_samples"]) == 3


def test_rejects_another_deployment_or_job():
    altered = copy.deepcopy(soak())
    altered["identity"]["deployment"][
        "aggregate_deployment_receipt_sha256"] = "4" * 64
    with pytest.raises(LineageError, match="selected beta job"):
        match_preliminary_soak(live(), preliminary(), altered)
    altered = copy.deepcopy(preliminary())
    altered["value"]["probes"]["signed_bureau_callback"]["evidence"][
        "bureau_job_commitment"] = "4" * 64
    with pytest.raises(LineageError, match="one selected job"):
        match_preliminary_soak(live(), altered, soak())


def test_rejects_preliminary_after_soak_or_unverified_probe():
    altered = copy.deepcopy(preliminary())
    altered["run_completed_at_utc"] = (START + timedelta(hours=2)).isoformat()
    with pytest.raises(LineageError, match="did not follow"):
        match_preliminary_soak(live(), altered, soak())
    altered = copy.deepcopy(preliminary())
    altered["value"]["probes"]["sod_signature"]["verified"] = False
    with pytest.raises(LineageError, match="unverified"):
        match_preliminary_soak(live(), altered, soak())


def test_rejects_preliminary_from_a_different_protected_source():
    altered = copy.deepcopy(preliminary())
    altered["workflow_commit"] = "9" * 40
    with pytest.raises(LineageError, match="artifact identity"):
        match_preliminary_soak(live(), altered, soak())


def test_authenticates_live_aggregate_and_protected_runs_before_join(tmp_path):
    (tmp_path / "aggregate-deployment.json").write_text("{}")
    calls = []

    def collect_live(path, *, api_key, attest):
        calls.append(("live", path, api_key, callable(attest)))
        return live()

    def read(kind, run_id):
        calls.append((kind, run_id))
        return preliminary()

    def verify_soak(run_ids, *, as_of, reader):
        calls.append(("soak", run_ids, as_of, reader is read))
        return soak()

    result = authenticate_preliminary_soak_lineage(
        tmp_path, "k" * 40, 111, [222, 223, 224],
        as_of=START + timedelta(hours=26),
        collector=collect_live, reader=read, soak_verifier=verify_soak,
    )
    assert result["preliminary_run_id"] == 111
    assert [item[0] for item in calls] == ["live", "preliminary", "soak"]
    assert calls[2][-1] is True
