import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from scripts.verify_passport_beta_soak_window import WindowError
from scripts.verify_protected_passport_soak import verify_protected


START = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


def reader(kind, run_id, *, late=False):
    assert kind == "soak"
    observed = START + timedelta(hours=(run_id - 1) * 12)
    source = "a" * 40
    report = {
        "schema": "marty.passport-beta-soak-sample/v1",
        "status": "observed", "observed_at_utc": observed.isoformat(),
        "beta_origin": "https://beta.elevenidllc.com",
        "physical_claim": "not_claimed",
        "protected_run": {"run_id": str(run_id), "workflow_commit": source},
        "release": {"source_commit": "b" * 40,
                    "stack_manifest_sha256": "c" * 64},
        "deployment": {
            "aggregate_deployment_receipt_sha256": "d" * 64,
            "aggregate_plan_sha256": "e" * 64,
            "production_snapshot_commitment": "f" * 64,
            "production_attachment_commitment": "0" * 64,
        },
        "checks": {
            "signed_live_runtime": True, "managed_issuer_capability": True,
            "native_gateway_flow_and_callback_route": True,
            "selected_passport_job_active": True,
            "beta_passport_drain": True,
            "production_containers_unchanged": True,
            "production_attachments_unchanged": True,
            "simulator_container_id": "1" * 64,
            "simulator_oci_digest": "sha256:" + "2" * 64,
            "selected_source_job_commitment": "3" * 64,
            "selected_bureau_job_commitment": "4" * 64,
        },
    }
    return {
        "kind": "soak", "run_id": run_id,
        "artifact_name": f"passport-beta-soak-{run_id}",
        "artifact_sha256": hashlib.sha256(json.dumps(report).encode()).hexdigest(),
        "value": report, "workflow_commit": source,
        "run_started_at_utc": (observed + timedelta(minutes=1) if late
                               else observed - timedelta(minutes=1)).isoformat(),
        "run_completed_at_utc": (observed + timedelta(minutes=2)).isoformat(),
    }


def test_authenticates_three_protected_runs_before_qualifying_window():
    result = verify_protected([3, 1, 2], as_of=START + timedelta(hours=25),
                              reader=reader)
    assert result["status"] == "protected_window_verified"
    assert result["provenance_pending"] is False
    assert [sample["run_id"] for sample in result["samples"]] == ["1", "2", "3"]


def test_rejects_forged_observation_time_or_reused_run():
    with pytest.raises(WindowError, match="outside its successful run"):
        verify_protected([1, 2, 3], as_of=START + timedelta(hours=25),
                         reader=lambda kind, run: reader(kind, run, late=run == 2))
    with pytest.raises(WindowError, match="repeated"):
        verify_protected([1, 2, 2], as_of=START + timedelta(hours=25),
                         reader=reader)
