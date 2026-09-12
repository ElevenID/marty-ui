"""Integrity of independently captured Python reports, not native body parity."""

from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "contracts/canvas-worker-body-timeout-oracle.json"
CAPTURE_SHA256 = "e97d7fee361a11d4245876b725c8ac417045254d766693f772da53409c9b50eb"
CASE_NAMES = [
    "application_body_prompt",
    "roster_body_prompt",
    "application_body_progress",
    "roster_body_progress",
    "application_body_stall",
    "roster_body_stall",
]


@pytest.fixture
def corpus():
    # No missing-artifact skip, capture fallback, or JSON numeric normalization.
    return json.loads(ORACLE.read_bytes())


@pytest.fixture
def matrix():
    return json.loads(
        (ROOT / "contracts/canvas-worker-body-timeout-scenarios.json").read_text()
    )


def observations(corpus):
    return [report["worker_body_timeout"] for report in corpus]


def test_exact_raw_capture_and_checkout_preserve_numeric_tokens():
    raw = ORACLE.read_bytes()
    assert len(raw) == 46_042
    assert hashlib.sha256(raw).hexdigest() == CAPTURE_SHA256
    assert b"\r" not in raw and raw.endswith(b"]\n")
    assert (
        "contracts/canvas-worker-body-timeout-oracle.json text eol=lf"
        in (ROOT / ".gitattributes").read_text().splitlines()
    )


def test_full_reports_close_six_cases_and_retain_published_identity(corpus, matrix):
    assert [case["name"] for case in matrix["cases"]] == CASE_NAMES
    assert [case["case"] for case in observations(corpus)] == CASE_NAMES
    assert len(set(CASE_NAMES)) == len(corpus) == 6
    assert matrix["reference_image"] == (
        "ghcr.io/elevenid/marty-credentials-issuance@sha256:"
        "9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176"
    )
    for report in corpus:
        assert set(report) == {
            "migration_revisions",
            "organization_dependency",
            "status",
            "worker_body_timeout",
            "worker_sha256",
        }
        assert report["migration_revisions"] == ["merge_issuance_heads"]
        assert report["organization_dependency"] == "synthetic-minimal"
        assert report["status"] == "passed"
        observed = report["worker_body_timeout"]
        assert observed["schema"] == "marty.canvas-worker-body-timeout-observation/v1"
        assert (
            report["worker_sha256"] == matrix["source_sha256"]["issuance.canvas_worker"]
        )
        for key in (
            "source_sha256",
            "http_source_sha256",
            "log_source_sha256",
            "runtime_versions",
        ):
            assert observed[key] == matrix[key]


def test_capture_inputs_bind_actual_unchanged_sources_without_json_rewriting(corpus):
    pins = observations(corpus)[0]["capture_source_sha256"]
    assert len(pins) == 16
    for observed in observations(corpus):
        assert observed["capture_source_sha256"] == pins
    for name, digest in pins.items():
        assert Path(name).name == name
        directory = "contracts" if name.endswith(".json") else "scripts"
        # Capture provenance deliberately normalizes checkout newlines only.
        source = (ROOT / directory / name).read_text(encoding="utf-8")
        assert hashlib.sha256(source.encode("utf-8")).hexdigest() == digest


def assert_number_types(corpus):
    for observed in observations(corpus):
        assert type(observed["exit_code_after_interrupt"]) is int
        for chunk in observed["chunks"]:
            assert type(chunk["scheduled_offset_seconds"]) is float
            for key in ("index", "byte_count", "flushed_byte_count"):
                assert type(chunk[key]) is int
        for state in (observed["before_release"], observed["outcome"]):
            for job in state["jobs"]:
                for key in ("attempt_count", "max_attempts"):
                    assert type(job[key]) is int
                for key, value in job["result"].items():
                    if key not in ("application_id", "policy_allowed"):
                        assert type(value) is int
            for key in ("candidate_count", "observation_count", "config_version"):
                assert type(state["target"][key]) is int
            for key in ("roster_cursor", "roster_size"):
                if key in state["target"]["metadata"]:
                    assert type(state["target"]["metadata"][key]) is int
            for fact in state["facts"]:
                for key in ("score", "score_maximum", "score_percent"):
                    assert type(fact["assertion"][key]) is float
            for score in state["snapshot"]["head_scores"] or []:
                assert type(score) is float


def test_published_float_scores_and_offsets_are_not_integer_counters(corpus):
    assert_number_types(corpus)


@pytest.mark.parametrize(
    "field",
    ["score", "score_maximum", "score_percent", "head", "offset", "counter", "cursor"],
)
def test_numeric_equality_cannot_hide_lossy_capture_rewriting(corpus, field):
    changed = deepcopy(corpus)
    first = changed[0]["worker_body_timeout"]
    if field == "head":
        first["outcome"]["snapshot"]["head_scores"][0] = 90
    elif field == "offset":
        first["chunks"][0]["scheduled_offset_seconds"] = 0
    elif field == "counter":
        first["outcome"]["jobs"][0]["result"]["facts_created"] = 1.0
    elif field == "cursor":
        changed[1]["worker_body_timeout"]["outcome"]["target"]["metadata"][
            "roster_cursor"
        ] = 0.0
    else:
        scores = first["outcome"]["facts"][0]["assertion"]
        scores[field] = int(scores[field])
    assert changed == corpus
    with pytest.raises(AssertionError):
        assert_number_types(changed)


@pytest.mark.parametrize("index", range(6), ids=CASE_NAMES)
def test_original_generation_and_target_specific_terminal_business_state(
    corpus, matrix, index
):
    case = matrix["cases"][index]
    observed = corpus[index]["worker_body_timeout"]
    before, after = observed["before_release"], observed["outcome"]
    assert before["facts"] == []
    assert len(before["jobs"]) == len(after["jobs"]) == 1
    for state, leased in ((before, True), (after, False)):
        job = state["jobs"][0]
        assert job["attempt_count"] == 1 and job["max_attempts"] == 8
        assert job["lease_owner_present"] is leased
        assert job["lease_expires_present"] is leased
        assert job["started"] is True
        assert state["heartbeat"]["metadata"]["phase"] == (
            "processing" if leased else "idle"
        )
        assert state["heartbeat"]["metadata"]["leased_jobs"] == int(leased)
        assert state["target"]["config_version"] == 1
        assert state["target"]["enabled"] is True
        assert state["target"]["target_type"] == case["target_type"]
    assert before["jobs"][0]["status"] == "leased"
    assert after["oauth"] == before["oauth"]
    assert after["snapshot"]["credential"] == before["snapshot"]["credential"]
    assert after["snapshot"]["reviews"] == before["snapshot"]["reviews"] == []
    job = after["jobs"][0]
    assert job["status"] == case["expected_status"]
    stalled = case["mode"] == "stall"
    roster = case["target_type"] == "background_roster"
    assert job["completed"] is (not stalled)
    if stalled:
        assert job["result"] == {}
        assert (
            job["retry_scheduled"] is job["retry_delay_within_backoff_bounds"] is True
        )
        assert after["facts"] == []
        expected_snapshot = deepcopy(before["snapshot"])
        if not roster:
            # The real application read failure evaluates policy false even
            # though it creates no fact; roster failure leaves policy unset.
            expected_snapshot["application"]["policy_allowed"] = False
        assert after["snapshot"] == expected_snapshot
        assert after["target"] == before["target"]
        assert (job["last_error_code"], job["last_error_summary"]) == (
            (
                "canvas_authoritative_read_failed",
                "Canvas background evidence could not be read",
            )
            if roster
            else (
                "canvas_authoritative_reads_failed",
                "No authoritative Canvas evidence requirement could be read",
            )
        )
    else:
        assert job["last_error_code"] is job["last_error_summary"] is None
        assert after["target"]["last_success_present"] is True
        if roster:
            assert job["result"] == dict.fromkeys(
                (
                    "candidates_seen",
                    "pending_claim",
                    "identity_link_required",
                    "observations_written",
                ),
                0,
            )
            assert after["facts"] == []
            assert after["snapshot"] == before["snapshot"]
            assert after["target"]["metadata"] == {
                "roster_cursor": 0,
                "roster_size": 0,
                "synthetic_marker": "preserve",
            }
            assert after["target"]["worker_heartbeat_present"] is False
            assert after["target"]["roster_cycle_completed_at_present"] is True
        else:
            assert (
                job["result"]["facts_created"]
                == job["result"]["requirements_checked"]
                == 1
            )
            assert job["result"]["policy_allowed"] is True
            assert len(after["facts"]) == 1
            assert after["facts"][0]["fact_type"] == "canvas.assignment_score"
            assert after["snapshot"]["events"] == {"evidence_fact_created": 1}
            assert after["target"]["metadata"] == {"worker_id": "worker-rest"}


def test_actual_flushes_and_late_stability_are_not_inferred_client_disconnects(
    corpus, matrix
):
    for observed, case in zip(observations(corpus), matrix["cases"], strict=True):
        assert observed["requests"] == [
            {
                "method": "GET",
                "accept": "application/json",
                "authorization": "Bearer synthetic-worker-rest-token",
                "path": matrix["request_paths"][case["target_type"]],
            }
        ]
        chunks = observed["chunks"]
        assert [chunk["index"] for chunk in chunks] == list(range(len(chunks)))
        assert [chunk["scheduled_offset_seconds"] for chunk in chunks] == matrix[
            "schedules"
        ][case["mode"]]
        for chunk in chunks:
            assert chunk["outcome"] == "flushed"
            assert chunk["disconnect_category"] is None
            assert chunk["byte_count"] == chunk["flushed_byte_count"] > 0
            assert chunk["write_within_declared_band"] is True
        timing = observed["timing"]
        assert set(timing) == {
            "all_attempts_within_declared_schedule",
            "first_terminal_interval_within_declared_window",
            "idle_outcome_within_declared_window",
            "initial_response_within_request_budget",
            "late_window_completed",
            "original_lease_current_through_join",
            "outcome_before_final_attempt",
        }
        for key, value in timing.items():
            assert value is (
                case["mode"] == "stall"
                if key == "outcome_before_final_attempt"
                else True
            )
        assert observed["stable_after_final_attempt_handler_join_and_interrupt"] is True
        assert observed["exit_code_after_interrupt"] == -2


def test_bounded_shutdown_profile_remains_source_pinned_and_payload_free(
    corpus, monkeypatch
):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    shutdown = importlib.import_module("canvas_worker_shutdown_output")
    for observed in observations(corpus):
        before = observed["logs_before_interrupt"]
        assert before == {
            "other_output_empty": True,
            "stdout_empty": True,
            "stderr_warning_categories": {
                "missing_credential_template_service_url": 1,
                "missing_revocation_profile_service_url": 1,
            },
        }
        after = observed["logs_after_interrupt"]
        assert after["pre_interrupt_profile"] == before
        assert after["python_version"] == shutdown.PYTHON_VERSION == "3.12.13"
        assert after["shutdown_source_sha256"] == shutdown.SOURCE_SHA256
        assert after["shutdown"] == {
            "caret_line_count": 4,
            "exception_chain": [
                "asyncio.exceptions.CancelledError",
                "KeyboardInterrupt",
            ],
            "frame_count": 11,
            "trace_line_count": 31,
            "traceback_count": 2,
            "unexpected_output_empty": True,
        }
