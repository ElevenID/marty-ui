import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from scripts.verify_passport_beta_soak_window import WindowError, verify


START = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


def observation(when, run_id):
    return {
        "schema": "marty.passport-beta-soak-sample/v1",
        "status": "observed", "observed_at_utc": when.isoformat(),
        "beta_origin": "https://beta.elevenidllc.com",
        "physical_claim": "not_claimed",
        "protected_run": {"run_id": str(run_id), "workflow_commit": "a" * 40},
        "release": {"source_commit": "b" * 40,
                    "stack_manifest_sha256": "c" * 64},
        "deployment": {
            "aggregate_deployment_receipt_sha256": "d" * 64,
            "aggregate_plan_sha256": "e" * 64,
            "production_snapshot_commitment": "f" * 64,
            "production_attachment_commitment": "0" * 64,
        },
        "checks": {
            "signed_live_runtime": True,
            "managed_issuer_capability": True,
            "native_gateway_flow_and_callback_route": True,
            "selected_passport_job_active": True,
            "beta_passport_drain": True,
            "production_containers_unchanged": True,
            "production_attachments_unchanged": True,
            "production_public_site_reachable": True,
            "simulator_container_id": "1" * 64,
            "simulator_oci_digest": "sha256:" + "2" * 64,
            "selected_source_job_commitment": "3" * 64,
            "selected_bureau_job_commitment": "4" * 64,
        },
    }


def files(tmp_path, observations):
    paths = []
    for index, item in enumerate(observations):
        path = tmp_path / f"sample-{index}.json"
        path.write_text(json.dumps(item), encoding="utf-8")
        paths.append(path)
    return paths


def test_window_requires_same_release_job_and_production_over_24_hours(tmp_path):
    reports = [observation(START + timedelta(hours=hours), index + 1)
               for index, hours in enumerate((0, 12, 24))]
    result = verify(files(tmp_path, reports), as_of=START + timedelta(hours=25))
    assert result["status"] == "window_observed"
    assert result["provenance_pending"] is True
    assert result["sample_count"] == 3
    assert result["minimum_hours"] == 24


def test_window_rejects_drifted_selected_job_and_production(tmp_path):
    reports = [observation(START + timedelta(hours=hours), index + 1)
               for index, hours in enumerate((0, 12, 24))]
    changed_job = copy.deepcopy(reports)
    changed_job[1]["checks"]["selected_bureau_job_commitment"] = "5" * 64
    with pytest.raises(WindowError, match="selected job changed"):
        verify(files(tmp_path, changed_job), as_of=START + timedelta(hours=25))
    changed_production = copy.deepcopy(reports)
    changed_production[2]["deployment"]["production_attachment_commitment"] = "6" * 64
    with pytest.raises(WindowError, match="deployment"):
        verify(files(tmp_path, changed_production), as_of=START + timedelta(hours=25))


def test_window_rejects_missing_or_reused_observation(tmp_path):
    spaced = [observation(START + timedelta(hours=hours), index + 1)
              for index, hours in enumerate((0, 14, 28))]
    with pytest.raises(WindowError, match="missing observation"):
        verify(files(tmp_path, spaced), as_of=START + timedelta(hours=29))
    reused = [observation(START + timedelta(hours=hours), 1)
              for hours in (0, 12, 24)]
    with pytest.raises(WindowError, match="reuses"):
        verify(files(tmp_path, reused), as_of=START + timedelta(hours=25))


def test_window_rejects_short_or_stale_soak(tmp_path):
    short = [observation(START + timedelta(hours=hours), index + 1)
             for index, hours in enumerate((0, 6, 12))]
    with pytest.raises(WindowError, match="short or stale"):
        verify(files(tmp_path, short), as_of=START + timedelta(hours=13))
    complete = [observation(START + timedelta(hours=hours), index + 1)
                for index, hours in enumerate((0, 12, 24))]
    with pytest.raises(WindowError, match="short or stale"):
        verify(files(tmp_path, complete), as_of=START + timedelta(hours=38))
