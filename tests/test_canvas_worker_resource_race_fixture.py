"""Resource-race fixture integrity, separate from native process qualification."""

import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"


def test_resource_race_mutations_are_exact_resource_changes_not_job_edits():
    matrix = json.loads(
        (CONTRACTS / "canvas-worker-resource-race-scenarios.json").read_text()
    )
    assert matrix["schema"] == "marty.canvas-worker-resource-race-scenarios/v1"
    assert matrix["reference_scenario"] == "canvas-worker-rest-scenarios.json"
    assert matrix["retry_scenario"] == "canvas-worker-retry-scenarios.json"
    assert matrix["response"] == {
        "status": 503,
        "body": {"error": "synthetic-provider-unavailable"},
    }
    # Exact scoped edits guard against gaining parity by editing a job, lease,
    # clock, ciphertext, schema constraint, or a running worker implementation.
    assert matrix["cases"] == [
        {
            "name": "platform_reconfigured",
            "code": "canvas_platform_reconfigured",
            "retryable": True,
            "mutation": [
                "UPDATE issuance_service.canvas_platforms SET config_version=2,"
                "last_connection_error='synthetic-reconfigured' "
                "WHERE id='platform-review' AND organization_id='org-review'"
            ],
        },
        {
            "name": "application_removed",
            "code": "canvas_application_unavailable",
            "retryable": False,
            "mutation": [
                "UPDATE issuance_service.canvas_evidence_sync_targets "
                "SET application_id=NULL WHERE id='target-review' "
                "AND organization_id='org-review'",
                "DELETE FROM issuance_service.applications "
                "WHERE id='application-review' AND organization_id='org-review'",
            ],
        },
    ]


@pytest.mark.parametrize("case_name", ["platform_reconfigured", "application_removed"])
def test_resource_race_reference_preserves_resource_and_durable_outcome(case_name):
    references = json.loads(
        (CONTRACTS / "canvas-worker-resource-race-oracle.json").read_text()
    )
    assert set(references) == {"platform_reconfigured", "application_removed"}
    observed = references[case_name]
    assert observed["schema"] == "marty.canvas-worker-resource-race-oracle/v1"
    assert observed["case"] == case_name
    assert observed["same_job"] is True
    assert observed["unchanged_after_exit"] is True
    assert observed["exit_code_after_interrupt"] == -2
    baseline = json.loads((CONTRACTS / "canvas-worker-rest-oracle.json").read_text())
    assert observed["source_sha256"] == baseline["source_sha256"]
    assert len(observed["requests"]) == 1
    assert observed["requests"] == references["platform_reconfigured"]["requests"]
    before, after = observed["before"], observed["after"]
    assert before["heartbeat"]["metadata"]["phase"] == "processing"
    assert after["heartbeat"]["metadata"]["phase"] == "idle"
    assert len(before["jobs"]) == len(after["jobs"]) == 1
    original, job = before["jobs"][0], after["jobs"][0]
    assert original["status"] == "leased"
    assert original["lease_owner_present"] is True
    assert original["lease_expires_present"] is True
    assert original["attempt_count"] == job["attempt_count"] == 1
    assert original["result"] == job["result"] == {}
    assert job["lease_owner_present"] is False
    assert job["lease_expires_present"] is False
    for state in (before, after):
        assert state["facts"] == []
        assert state["snapshot"]["facts"] == 0
        assert state["snapshot"]["events"] == {}
        assert state["snapshot"]["credential"] == {"active": True, "count": 1}
    changed, final = observed["changed_resources"], observed["final_resources"]
    if case_name == "platform_reconfigured":
        assert job["status"] == "retry" and job["max_attempts"] == 8
        assert job["last_error_code"] == "canvas_platform_reconfigured"
        assert job["last_error_summary"] == (
            "Canvas platform configuration changed during synchronization"
        )
        assert job["retry_scheduled"] is True
        assert job["retry_delay_within_backoff_bounds"] is True
        assert job["completed"] is False
        assert changed == final
        assert final["platform"] == {
            "config_version": 2,
            "last_connection_error": "synthetic-reconfigured",
            "validated": False,
        }
        assert final["target"]["enabled"] is True
        assert final["application_present"] is True
        assert before["snapshot"] == after["snapshot"]
    else:
        assert job["status"] == "dead_letter" and job["max_attempts"] == 1
        assert job["last_error_code"] == "canvas_application_unavailable"
        assert job["last_error_summary"] == (
            "Canvas application became unavailable during synchronization"
        )
        assert job["retry_scheduled"] is None
        assert job["retry_delay_within_backoff_bounds"] is None
        assert job["completed"] is True
        assert changed["target"]["enabled"] is True
        assert final["target"]["enabled"] is False
        for resources in (changed, final):
            assert resources["application_present"] is False
            assert resources["target"]["application_id"] is None
        assert final["platform"] == {
            "config_version": 1,
            "last_connection_error": "canvas_authoritative_reads_failed",
            "validated": True,
        }
        assert after["snapshot"]["application"] is None


@pytest.mark.parametrize(
    "invalid", ["duplicate_case", "missing_case", "extra_case", "empty_matrix"]
)
def test_resource_race_parent_rejects_incomplete_or_ambiguous_matrix(
    monkeypatch, invalid
):
    monkeypatch.syspath_prepend(str(CONTRACTS.parent / "scripts"))
    native = importlib.import_module("test_canvas_worker_provider_signals_https")
    monkeypatch.setattr(native, "sys", SimpleNamespace(platform="linux"))
    cases = ["platform_reconfigured", "application_removed"]
    reference = {case: {"requests": []} for case in cases}
    if invalid == "duplicate_case":
        cases.append(cases[0])
    elif invalid == "missing_case":
        reference.pop(cases[0])
    elif invalid == "extra_case":
        reference["unconfigured_case"] = {"requests": []}
    else:
        cases.clear()
        reference.clear()
    inputs = iter(
        [
            json.dumps({"stages": [{}]}),
            json.dumps(reference),
            json.dumps({"cases": [{"name": case} for case in cases], "response": {}}),
        ]
    )
    monkeypatch.setattr(Path, "read_text", lambda *_: next(inputs))

    def unexpected_fixture():
        pytest.fail("Invalid matrix must be rejected before starting an HTTPS fixture")

    monkeypatch.setattr(native, "WorkerHttpsFixture", unexpected_fixture)
    with pytest.raises(AssertionError):
        native.run("synthetic-not-executed", "resource_race")
