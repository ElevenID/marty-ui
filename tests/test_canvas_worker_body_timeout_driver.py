"""Synthetic reference-runner controls, not actual-worker body qualification."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
CASE_NAMES = [
    "application_body_prompt",
    "roster_body_prompt",
    "application_body_progress",
    "roster_body_progress",
    "application_body_stall",
    "roster_body_stall",
]


@pytest.fixture
def runner(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("run_canvas_worker_body_timeout_oracle")


class Clock:
    def __init__(self, now=100.0):
        self.now = now

    def monotonic(self):
        return self.now

    def sleep(self, duration):
        self.now += duration


def source_matrix():
    return json.loads(
        (ROOT / "contracts/canvas-worker-body-timeout-scenarios.json").read_text()
    )


def replace_matrix(monkeypatch, matrix):
    original = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *args, **kwargs: (
            json.dumps(matrix)
            if path.name == "canvas-worker-body-timeout-scenarios.json"
            else original(path, *args, **kwargs)
        ),
    )


@pytest.mark.parametrize("name", CASE_NAMES)
def test_all_six_cases_reuse_owned_seeds_and_exact_authenticated_get(runner, name):
    matrix, case, spec, shared, response, request, job_id = runner.load_case(
        ROOT / "contracts", name
    )
    assert [item["name"] for item in matrix["cases"]] == CASE_NAMES
    assert matrix["environment"] == {
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "120",
        "CANVAS_SYNC_WORKER_LEASE_SECONDS": "90",
        "CANVAS_SYNC_WORKER_POLL_SECONDS": "120",
        "LOG_LEVEL": "WARNING",
    }
    assert "source-derived" in matrix["expectation_status"].lower()
    assert shared["seed"]
    assert request == {
        "method": "GET",
        "path": matrix["request_paths"][case["target_type"]],
        "authorization": f"Bearer {spec['token']}",
        "accept": "application/json",
    }
    assert (
        sum(
            "INSERT INTO issuance_service.canvas_evidence_sync_jobs" in sql
            for sql in spec["post_oauth_seed"]
        )
        == 1
    )
    assert any(job_id in sql for sql in spec["post_oauth_seed"])
    if name.startswith("roster_"):
        assert response == {"status": 200, "body": []}
        assert request["path"].endswith("enrollment_type%5B%5D=student&per_page=100")
    else:
        assert response["status"] == 200 and isinstance(response["body"], dict)
        assert request["path"].endswith("submissions/7?include%5B%5D=assignment")


def test_unknown_case_is_rejected_without_echoing_selector(runner):
    with pytest.raises(AssertionError) as caught:
        runner.load_case(ROOT / "contracts", "private-case-sentinel")
    assert "private-case-sentinel" not in str(caught.value)


@pytest.mark.parametrize(
    "mutation",
    ["empty", "duplicate", "drop", "rename", "short_job", "short_lease", "short_poll"],
)
def test_case_inventory_and_lifecycle_configuration_cannot_drift(
    runner, monkeypatch, mutation
):
    matrix = source_matrix()
    if mutation == "empty":
        matrix["cases"] = []
    elif mutation == "duplicate":
        matrix["cases"][1] = deepcopy(matrix["cases"][0])
    elif mutation == "drop":
        matrix["cases"].pop()
    elif mutation == "rename":
        matrix["cases"][-1]["name"] = "private-case-sentinel"
    else:
        key = {
            "short_job": "JOB_TIMEOUT",
            "short_lease": "LEASE",
            "short_poll": "POLL",
        }[mutation]
        matrix["environment"][f"CANVAS_SYNC_WORKER_{key}_SECONDS"] = "10"
    replace_matrix(monkeypatch, matrix)
    with pytest.raises(AssertionError) as caught:
        runner.load_case(ROOT / "contracts", "application_body_prompt")
    assert "private-case-sentinel" not in str(caught.value)


@pytest.mark.parametrize(
    "mutation", [None, "duplicate", "unknown", "secret", "stdout", "oversized"]
)
def test_actual_log_profile_is_closed_and_payload_safe(runner, mutation):
    lines = (
        "WARNING:issuance.infrastructure.api.routes:REVOCATION_PROFILE_SERVICE_URL not set — revocation calls will fail\n"
        "WARNING:issuance.infrastructure.api.routes:CREDENTIAL_TEMPLATE_SERVICE_URL not set — template calls will fail\n"
    ).encode()
    stdout = b""
    if mutation == "duplicate":
        lines += lines
    elif mutation == "unknown":
        lines += b"WARNING:private-logger:private-payload\n"
    elif mutation == "secret":
        lines += b"synthetic-body-secret"
    elif mutation == "stdout":
        stdout = b"private-payload"
    elif mutation == "oversized":
        lines = b"x" * 65537
    if mutation is None:
        assert runner.observed_log_profile(
            io.BytesIO(stdout), io.BytesIO(lines), "synthetic-body-secret"
        ) == {
            "stdout_empty": True,
            "stderr_warning_categories": {
                "missing_revocation_profile_service_url": 1,
                "missing_credential_template_service_url": 1,
            },
            "other_output_empty": True,
        }
    else:
        with pytest.raises(AssertionError) as caught:
            runner.observed_log_profile(
                io.BytesIO(stdout), io.BytesIO(lines), "synthetic-body-secret"
            )
        assert all(
            value not in str(caught.value)
            for value in ("private-logger", "private-payload", "synthetic-body-secret")
        )


def case_inputs(runner, name):
    matrix, case, *_ = runner.load_case(ROOT / "contracts", name)
    return case, matrix["timing"]


@pytest.mark.parametrize(
    "name,seconds", [("application_body_stall", 15), ("roster_body_stall", 20)]
)
def test_stall_uses_entire_transition_minus_actual_flush_interval(
    runner, name, seconds
):
    case, timing = case_inputs(runner, name)
    flush = {"write_started_at": 108.0, "write_completed_at": 108.1}
    assert runner.assert_transition_timing(
        108 + seconds, 108.2 + seconds, flush, case, timing
    )
    # Delayed flush is actual transport evidence. Scheduled offset 8 must not
    # manufacture a 15/20-second interval when successful progress occurred later.
    with pytest.raises(AssertionError):
        runner.assert_transition_timing(
            108 + seconds,
            108.2 + seconds,
            {"write_started_at": 110.0, "write_completed_at": 110.1},
            case,
            timing,
        )
    # Wide SQL observations and write brackets cannot pass by midpoint/overlap.
    for lower, upper, write in [
        (105 + seconds, 108.2 + seconds, flush),
        (108 + seconds, 110 + seconds, flush),
        (
            108 + seconds,
            108.2 + seconds,
            {"write_started_at": 106.0, "write_completed_at": 110.0},
        ),
    ]:
        with pytest.raises(AssertionError):
            runner.assert_transition_timing(lower, upper, write, case, timing)


@pytest.mark.parametrize("seconds", [5, 10, 20])
def test_application_stall_rejects_wrong_timeout_even_if_observer_later_looks_valid(
    runner, seconds
):
    case, timing = case_inputs(runner, "application_body_stall")
    with pytest.raises(AssertionError):
        runner.assert_transition_timing(
            108 + seconds,
            108.1 + seconds,
            {"write_started_at": 108, "write_completed_at": 108.05},
            case,
            timing,
        )


def test_roster_stall_cannot_silently_inherit_fifteen_second_application_policy(runner):
    case, timing = case_inputs(runner, "roster_body_stall")
    with pytest.raises(AssertionError):
        runner.assert_transition_timing(
            123,
            123.1,
            {"write_started_at": 108, "write_completed_at": 108.05},
            case,
            timing,
        )


@pytest.mark.parametrize(
    "bad", [True, float("nan"), float("inf"), -float("inf"), 10**1000]
)
@pytest.mark.parametrize("field", ["lower", "upper", "write_start", "write_end"])
def test_invalid_timing_numbers_fail_statically(runner, bad, field):
    case, timing = case_inputs(runner, "application_body_stall")
    values = {"lower": 123, "upper": 123.1, "write_start": 108, "write_end": 108.05}
    values[field] = bad
    with pytest.raises(AssertionError):
        runner.assert_transition_timing(
            values["lower"],
            values["upper"],
            {
                "write_started_at": values["write_start"],
                "write_completed_at": values["write_end"],
            },
            case,
            timing,
        )


def retained_header_state(name):
    # Reuse observed business projections only, not their different network
    # timing or an invented body oracle. The new body cases remain uncaptured.
    reference = json.loads(
        (ROOT / "contracts/canvas-worker-timeout-oracle.json").read_text()
    )
    return deepcopy(
        next(
            item["outcome"]
            for item in reference["observations"]
            if item["case"] == name
        )
    )


def existing_effects():
    return {
        name: [{"id": "synthetic-existing"}]
        for name in (
            "facts",
            "heads",
            "reviews",
            "events",
            "candidates",
            "observations",
        )
    }


@pytest.mark.parametrize(
    "name", [name for name in CASE_NAMES if not name.endswith("stall")]
)
def test_success_controls_require_existing_target_specific_business_projection(
    runner, name
):
    case, _ = case_inputs(runner, name)
    state = retained_header_state(
        "roster_prompt" if name.startswith("roster") else "application_prompt"
    )
    runner.assert_outcome(state, case, {}, {})
    if name.startswith("roster"):
        state["jobs"][0]["result"].pop("observations_written")
    else:
        state["facts"] = []
    with pytest.raises(AssertionError):
        runner.assert_outcome(state, case, {}, {})


@pytest.mark.parametrize(
    "field", ["facts", "heads", "reviews", "events", "candidates", "observations"]
)
def test_application_stall_cannot_delete_existing_evidence(runner, field):
    case, _ = case_inputs(runner, "application_body_stall")
    state = retained_header_state("application_delayed_headers")
    before = existing_effects()
    runner.assert_outcome(state, case, before, deepcopy(before))
    after = deepcopy(before)
    after[field] = []
    with pytest.raises(AssertionError):
        runner.assert_outcome(state, case, before, after)


def roster_stall_state():
    # Source-derived synthetic boundary, not a recorded body-timeout result.
    state = retained_header_state("application_delayed_headers")
    state["jobs"][0].update(
        last_error_code="canvas_authoritative_read_failed",
        last_error_summary="Canvas background evidence could not be read",
    )
    state["target"].update(
        target_type="background_roster",
        metadata={
            "roster_cursor": 1,
            "synthetic_marker": "preserve",
            "worker_id": "worker-rest",
        },
        worker_heartbeat_present=True,
        roster_cycle_completed_at_present=False,
    )
    return state


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "application_code",
        "application_summary",
        "cursor_reset",
        "marker_lost",
        "heartbeat_lost",
        "worker_lost",
        "cycle_completed",
        "second_attempt",
        "success",
    ],
)
def test_roster_stall_requires_its_own_error_and_preserved_cursor_heartbeat(
    runner, mutation
):
    case, _ = case_inputs(runner, "roster_body_stall")
    state = roster_stall_state()
    if mutation == "application_code":
        state["jobs"][0]["last_error_code"] = "canvas_authoritative_reads_failed"
    elif mutation == "application_summary":
        state["jobs"][0]["last_error_summary"] = (
            "No authoritative Canvas evidence requirement could be read"
        )
    elif mutation == "cursor_reset":
        state["target"]["metadata"]["roster_cursor"] = 0
    elif mutation == "marker_lost":
        del state["target"]["metadata"]["synthetic_marker"]
    elif mutation == "heartbeat_lost":
        state["target"]["worker_heartbeat_present"] = False
    elif mutation == "worker_lost":
        del state["target"]["metadata"]["worker_id"]
    elif mutation == "cycle_completed":
        state["target"]["roster_cycle_completed_at_present"] = True
    elif mutation == "second_attempt":
        state["jobs"][0]["attempt_count"] = 2
    elif mutation == "success":
        state["target"]["last_success_present"] = True
    before = existing_effects()
    if mutation is None:
        runner.assert_outcome(state, case, before, deepcopy(before))
    else:
        with pytest.raises((AssertionError, KeyError)):
            runner.assert_outcome(state, case, before, deepcopy(before))


def leased_job():
    started = datetime(2026, 9, 8, tzinfo=timezone.utc)
    return {
        "id": "worker-validation-job",
        "organization_id": "org-review",
        "target_id": "target-review",
        "attempt_count": 1,
        "status": "leased",
        "lease_owner": "worker-rest",
        "lease_expires_at": started + timedelta(seconds=90),
        "started_at": started,
        "result": {},
    }


def terminal_job(initial):
    return {**initial, "status": "retry", "lease_owner": None, "lease_expires_at": None}


@pytest.mark.parametrize("leased", [True, False])
@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "another-job"),
        ("organization_id", "another-org"),
        ("target_id", "another-target"),
        ("attempt_count", 2),
        ("attempt_count", True),
        ("started_at", datetime(2026, 9, 9, tzinfo=timezone.utc)),
    ],
)
def test_original_job_generation_cannot_be_replaced(runner, leased, field, value):
    original = leased_job()
    current = deepcopy(original) if leased else terminal_job(original)
    runner.assert_same_generation(current, original, leased=leased)
    current[field] = value
    with pytest.raises(AssertionError):
        runner.assert_same_generation(current, original, leased=leased)


@pytest.mark.parametrize("mutation", ["renewed", "owner", "result", "not_leased"])
def test_active_lease_must_remain_the_original_lease(runner, mutation):
    original = leased_job()
    current = deepcopy(original)
    if mutation == "renewed":
        current["lease_expires_at"] += timedelta(seconds=1)
    elif mutation == "owner":
        current["lease_owner"] = "another-worker"
    elif mutation == "result":
        current["result"] = {"unexpected": True}
    else:
        current["status"] = "queued"
    with pytest.raises(AssertionError):
        runner.assert_same_generation(current, original, leased=True)


@pytest.mark.parametrize(
    "target",
    [
        {"config_version": 2, "enabled": True},
        {"config_version": True, "enabled": True},
        {"config_version": 1, "enabled": False},
        {"config_version": 1, "enabled": 1},
    ],
)
def test_target_generation_and_enabled_flag_are_exact(runner, target):
    runner.assert_target_generation({"config_version": 1, "enabled": True})
    with pytest.raises(AssertionError):
        runner.assert_target_generation(target)


def install_clock(monkeypatch, runner, now):
    clock = Clock(now)
    monkeypatch.setattr(runner, "time", clock)
    return clock


def test_first_terminal_query_freezes_interval_before_later_idle_observation(
    runner, monkeypatch
):
    original = leased_job()
    clock = install_clock(monkeypatch, runner, 114.9)
    reads = []

    def read():
        reads.append(clock.now)
        clock.now += 0.05
        return deepcopy(original) if len(reads) == 1 else terminal_job(original)

    result, lower, upper = runner.await_terminal(
        read, lambda: None, (original, 99, 99.1), 100, 30
    )
    assert result["status"] == "retry" and len(reads) == 2
    assert lower == 114.9 and upper == pytest.approx(115.025)
    # A delayed idle/full-state query cannot rewrite the already captured job
    # transition. The marker may look correct at 23 seconds while job time is 15.
    clock.now = 123
    case, timing = case_inputs(runner, "application_body_stall")
    with pytest.raises(AssertionError):
        runner.assert_transition_timing(
            lower,
            upper,
            {"write_started_at": 108, "write_completed_at": 108.05},
            case,
            timing,
        )


@pytest.mark.parametrize("duration", [0.5001, 1, 5])
def test_slow_job_query_cannot_manufacture_a_valid_terminal_observation(
    runner, monkeypatch, duration
):
    original = leased_job()
    clock = install_clock(monkeypatch, runner, 122)

    def read():
        clock.now += duration
        return terminal_job(original)

    with pytest.raises(AssertionError, match="query budget"):
        runner.await_terminal(read, lambda: None, (original, 99, 99.1), 100, 30)


def test_ready_terminal_after_overall_budget_is_rejected(runner, monkeypatch):
    original = leased_job()
    clock = install_clock(monkeypatch, runner, 129.9)

    def read():
        clock.now += 0.2
        return terminal_job(original)

    with pytest.raises(AssertionError, match="after its budget"):
        runner.await_terminal(read, lambda: None, (original, 99, 99.1), 100, 30)


def test_guard_failure_is_preserved_before_any_query(runner, monkeypatch):
    install_clock(monkeypatch, runner, 100)
    error = AssertionError("Synthetic owned worker exited")

    def guard():
        raise error

    def read():
        pytest.fail("Query must not occur after guard failure")

    with pytest.raises(AssertionError) as caught:
        runner.await_terminal(read, guard, (leased_job(), 99, 99.1), 100, 30)
    assert caught.value is error


@pytest.mark.parametrize("active_error", [False, True])
@pytest.mark.parametrize("failure", ["cancel", "initial", "finish", "close", "dispose"])
def test_all_owned_cleanup_runs_and_original_failure_is_preserved(
    runner, monkeypatch, active_error, failure
):
    calls = []

    def action(name):
        def invoke(*args):
            calls.append(name)
            if name == failure:
                raise RuntimeError("private-cleanup-sentinel")

        return invoke

    fixture = SimpleNamespace(
        cancel_schedule=SimpleNamespace(set=action("cancel")),
        initial_ready=SimpleNamespace(set=action("initial")),
        close=action("close"),
    )
    monkeypatch.setattr(runner, "finish_worker", action("finish"))
    engine = SimpleNamespace(dispose=action("dispose"))
    original = AssertionError("Original synthetic failure")
    if active_error:
        with pytest.raises(AssertionError) as caught:
            try:
                raise original
            finally:
                runner.cleanup(object(), fixture, engine)
        assert caught.value is original
        assert original.__notes__ == [
            "Owned body cleanup also failed; all owners were attempted"
        ]
    else:
        with pytest.raises(AssertionError, match="all owners were attempted") as caught:
            runner.cleanup(object(), fixture, engine)
    assert "private-cleanup-sentinel" not in str(caught.value)
    assert calls == ["cancel", "initial", "finish", "close", "dispose"]


@pytest.mark.parametrize(
    "mutation",
    [
        "schedule",
        "schedule_bool",
        "timing",
        "source",
        "http_source",
        "log_source",
        "httpx",
        "httpcore",
        "image",
    ],
)
def test_capture_inputs_cannot_change_without_explicit_contract_review(
    runner, monkeypatch, mutation
):
    matrix = source_matrix()
    if mutation == "schedule":
        matrix["schedules"]["progress"][-1] = 20
    elif mutation == "schedule_bool":
        matrix["schedules"]["progress"][0] = False
    elif mutation == "timing":
        matrix["timing"]["application_inactivity_min_seconds"] = 5
    elif mutation == "source":
        matrix["source_sha256"]["issuance.canvas_worker"] = "0" * 64
    elif mutation in ("http_source", "log_source"):
        matrix[mutation + "_sha256"] = "0" * 64
    elif mutation in ("httpx", "httpcore"):
        matrix["runtime_versions"][mutation] = "0.0.0"
    else:
        matrix["reference_image"] = "private-moving-image:latest"
    replace_matrix(monkeypatch, matrix)
    with pytest.raises(AssertionError) as caught:
        runner.load_case(ROOT / "contracts", "application_body_prompt")
    assert "private-moving-image" not in str(caught.value)


@pytest.mark.parametrize("mutation", [None, "worker", "log", "factory", "version"])
def test_installed_source_verification_and_capture_hashes_are_real(
    runner, monkeypatch, mutation
):
    matrix = source_matrix()
    factory_bytes = b"synthetic installed HTTP factory"
    monkeypatch.setattr(
        runner,
        "worker_source_sha256",
        lambda: {} if mutation == "worker" else runner.SOURCE_SHA256,
    )
    monkeypatch.setattr(
        runner,
        "published_log_source_sha256",
        lambda: "wrong" if mutation == "log" else runner.LOG_SOURCE_SHA256,
    )
    monkeypatch.setattr(
        runner, "HTTP_SOURCE_SHA256", hashlib.sha256(factory_bytes).hexdigest()
    )
    monkeypatch.setattr(
        runner,
        "version",
        lambda name: (
            "0.0.0" if mutation == "version" else runner.RUNTIME_VERSIONS[name]
        ),
    )
    original_read = Path.read_bytes
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda path: (
            (b"unexpected installed source" if mutation == "factory" else factory_bytes)
            if path.as_posix()
            == "/app/services/issuance/application/canvas_lti_services.py"
            else original_read(path)
        ),
    )
    if mutation is not None:
        with pytest.raises(AssertionError):
            runner.verify_sources(matrix, ROOT / "contracts")
    else:
        hashes = runner.verify_sources(matrix, ROOT / "contracts")
        assert set(hashes) >= {
            "run_canvas_worker_body_timeout_oracle.py",
            "canvas_worker_body_timeout_https_fixture.py",
            "canvas_worker_https_fixture.py",
            "canvas_worker_output_capture.py",
            "canvas-worker-body-timeout-scenarios.json",
        }
        for filename, actual in hashes.items():
            directory = "contracts" if filename.endswith(".json") else "scripts"
            assert (
                actual
                == hashlib.sha256(
                    (ROOT / directory / filename)
                    .read_text(encoding="utf-8")
                    .encode("utf-8")
                ).hexdigest()
            )


def completed_schedule(runner, name):
    matrix, case, _, _, response, request, _ = runner.load_case(
        ROOT / "contracts", name
    )
    offsets = matrix["schedules"][case["mode"]]
    fixture = runner.BodyTimeoutHttpsFixture(
        request,
        response,
        chunk_offsets=offsets,
        late_disconnect_from_index=len(offsets) - 1
        if case["mode"] == "stall"
        else None,
    )
    fixture.received_at = 99.9
    fixture.body_started_at = 100
    fixture.chunk_observations = [
        {
            "index": index,
            "scheduled_offset_seconds": offset,
            "write_started_seconds": offset + 0.01,
            "write_completed_seconds": offset + 0.02,
            "byte_count": len(chunk),
            "flushed_byte_count": len(chunk),
            "outcome": "flushed",
            "disconnect_category": None,
        }
        for index, (offset, chunk) in enumerate(
            zip(offsets, fixture.chunks, strict=True)
        )
    ]
    fixture.schedule_completed.set()
    fixture.handler_finished.set()
    return fixture, case, matrix["timing"]


@pytest.mark.parametrize("name", CASE_NAMES)
def test_complete_schedule_projects_counts_without_claiming_peer_receipt(runner, name):
    fixture, case, timing = completed_schedule(runner, name)
    result = runner.assert_schedule(fixture, case, timing)
    assert len(result) == len(fixture.chunks)
    assert all(item["write_within_declared_band"] is True for item in result)
    assert sum(item["flushed_byte_count"] for item in result) == len(fixture.body_bytes)
    assert all(
        "write_started_seconds" not in item and "write_completed_seconds" not in item
        for item in result
    )
    # No outcome/idle signal exists on this synthetic fixture: independently
    # completed writes are qualified from their actual handler observations.
    assert not hasattr(fixture, "outcome_observed")


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "duplicate",
        "unfinished",
        "unjoined",
        "early",
        "late",
        "slow_flush",
        "scheduled_drift",
        "bool_index",
        "bool_bytes",
        "short_flush",
        "early_close",
        "unknown_close",
        "extra_private_field",
    ],
)
def test_incomplete_or_unpunctual_schedule_cannot_become_capture_evidence(
    runner, mutation
):
    fixture, case, timing = completed_schedule(runner, "application_body_stall")
    rows = fixture.chunk_observations
    if mutation == "missing":
        rows.pop()
    elif mutation == "duplicate":
        rows.append(deepcopy(rows[-1]))
    elif mutation == "unfinished":
        fixture.schedule_completed.clear()
    elif mutation == "unjoined":
        fixture.handler_finished.clear()
    elif mutation == "early":
        rows[-1]["write_started_seconds"] = 30.9
    elif mutation == "late":
        rows[-1].update(write_started_seconds=31.6, write_completed_seconds=31.7)
    elif mutation == "slow_flush":
        rows[-1]["write_completed_seconds"] = 31.6
    elif mutation == "scheduled_drift":
        rows[-1]["scheduled_offset_seconds"] = 30
    elif mutation == "bool_index":
        rows[0]["index"] = False
    elif mutation == "bool_bytes":
        rows[0]["byte_count"] = True
    elif mutation == "short_flush":
        rows[-1]["flushed_byte_count"] -= 1
    elif mutation in ("early_close", "unknown_close"):
        row = rows[0] if mutation == "early_close" else rows[-1]
        row.update(
            outcome="peer_closed",
            flushed_byte_count=None,
            disconnect_category="broken_pipe"
            if mutation == "early_close"
            else "private-close-sentinel",
        )
    else:
        rows[-1]["private-payload"] = "private-sentinel"
    with pytest.raises(AssertionError) as caught:
        runner.assert_schedule(fixture, case, timing)
    assert "private" not in str(caught.value)


@pytest.mark.parametrize("name", CASE_NAMES)
def test_only_stall_final_attempt_may_report_expected_peer_close(runner, name):
    fixture, case, timing = completed_schedule(runner, name)
    fixture.chunk_observations[-1].update(
        outcome="peer_closed",
        flushed_byte_count=None,
        disconnect_category="broken_pipe",
    )
    if case["mode"] == "stall":
        projection = runner.assert_schedule(fixture, case, timing)
        assert projection[-1]["flushed_byte_count"] is None
    else:
        with pytest.raises(AssertionError):
            runner.assert_schedule(fixture, case, timing)


@pytest.mark.parametrize("name", ["application_body_stall", "roster_body_stall"])
def test_original_idle_observer_band_remains_mandatory_alongside_job_interval(
    runner, name
):
    case, timing = case_inputs(runner, name)
    seconds = 15 if name.startswith("application") else 20
    flush = {"write_started_at": 108, "write_completed_at": 108.05}
    assert runner.assert_transition_timing(
        108 + seconds, 108.2 + seconds, flush, case, timing
    )
    assert runner.assert_outcome_timing(99.9, 100, 108.3 + seconds, flush, case, timing)
    # A valid durable transition does not authorize slower idle/marker evidence.
    with pytest.raises(AssertionError):
        runner.assert_outcome_timing(99.9, 100, 110 + seconds, flush, case, timing)


def test_actual_flush_interval_does_not_substitute_scheduled_offset(runner):
    fixture, _, _ = completed_schedule(runner, "application_body_stall")
    fixture.chunk_observations[1].update(
        write_started_seconds=8.2, write_completed_seconds=8.4
    )
    assert runner.flush_interval(fixture, 1) == {
        "write_started_at": 108.2,
        "write_completed_at": 108.4,
    }
    fixture.chunk_observations[1]["outcome"] = "peer_closed"
    with pytest.raises(AssertionError):
        runner.flush_interval(fixture, 1)


@pytest.mark.parametrize("failure", ["engine", "seed", "start", "wait"])
def test_run_routes_startup_failures_through_all_acquired_owners(
    runner, monkeypatch, failure
):
    loaded = runner.load_case(ROOT / "contracts", "application_body_prompt")
    monkeypatch.setattr(runner, "load_case", lambda *_: loaded)
    monkeypatch.setattr(runner, "verify_sources", lambda *_: {})
    calls = []
    error = AssertionError("Original synthetic startup failure")

    def action(name, result=None):
        def invoke(*args, **kwargs):
            calls.append(name)
            if name == failure:
                raise error
            return result

        return invoke

    fixture = SimpleNamespace(
        origin="https://synthetic-loopback.invalid",
        cert=Path("unused-synthetic-cert"),
        cancel_schedule=SimpleNamespace(set=action("cancel")),
        initial_ready=SimpleNamespace(set=action("initial")),
        request_started=SimpleNamespace(is_set=lambda: False),
        close=action("close"),
        __enter__=action("enter"),
    )
    monkeypatch.setattr(
        runner, "BodyTimeoutHttpsFixture", lambda *args, **kwargs: fixture
    )
    engine = SimpleNamespace(dispose=action("dispose"))
    monkeypatch.setattr(runner, "create_engine", action("engine", engine))
    monkeypatch.setattr(runner, "seed_worker_database", action("seed", ([], "cipher")))
    monkeypatch.setattr(runner, "scalar", lambda *_: {})
    monkeypatch.setattr(runner, "worker_case", lambda *_: {})
    child = SimpleNamespace(poll=lambda: None)
    monkeypatch.setattr(runner, "start_worker", action("start", child))
    monkeypatch.setattr(runner, "wait_until", action("wait"))

    def finish(actual):
        assert actual is child
        calls.append("finish")
        raise RuntimeError("private-cleanup-sentinel")

    monkeypatch.setattr(runner, "finish_worker", finish)
    with pytest.raises(AssertionError) as caught:
        runner.run("application_body_prompt")
    assert caught.value is error
    cleanup_actions = [
        name
        for name in calls
        if name in {"cancel", "initial", "finish", "close", "dispose"}
    ]
    assert cleanup_actions == ["cancel", "initial"] + (
        ["finish"] if failure == "wait" else []
    ) + ["close"] + ([] if failure == "engine" else ["dispose"])
    assert "private-cleanup-sentinel" not in str(caught.value)
    if failure == "wait":
        assert caught.value.__notes__ == [
            "Owned body cleanup also failed; all owners were attempted"
        ]


@pytest.mark.parametrize(
    "name", [name for name in CASE_NAMES if not name.endswith("stall")]
)
def test_early_success_cannot_be_hidden_by_late_idle_response(runner, name):
    case, timing = case_inputs(runner, name)
    final = 124 if case["mode"] == "progress" else 100.05
    flush = {"write_started_at": final, "write_completed_at": final + 0.02}
    with pytest.raises(AssertionError):
        runner.assert_transition_timing(final - 1, final - 0.5, flush, case, timing)
    # The last leased query can legitimately start just before the final write;
    # do not invent an exact client read time from the server's flush bracket.
    assert runner.assert_transition_timing(
        final - 0.05, final + 0.05, flush, case, timing
    )


@pytest.mark.parametrize("name", ["application_body_prompt", "application_body_stall"])
@pytest.mark.parametrize("mutation", ["worker", "extra", "cycle"])
def test_application_metadata_cannot_be_dropped_or_replaced(runner, name, mutation):
    case, _ = case_inputs(runner, name)
    state = retained_header_state(
        "application_delayed_headers"
        if name.endswith("stall")
        else "application_prompt"
    )
    if mutation == "worker":
        state["target"]["metadata"].pop("worker_id")
    elif mutation == "extra":
        state["target"]["metadata"]["roster_cursor"] = 0
    else:
        state["target"]["roster_cycle_completed_at_present"] = True
    before = existing_effects()
    with pytest.raises(AssertionError):
        runner.assert_outcome(state, case, before, deepcopy(before))


@pytest.mark.parametrize(
    "name,final_closed",
    [(name, False) for name in CASE_NAMES]
    + [(name, True) for name in CASE_NAMES if name.endswith("stall")],
)
def test_late_window_outlives_actual_final_attempt_outcome_and_read_budget(
    runner, name, final_closed
):
    fixture, case, timing = completed_schedule(runner, name)
    if final_closed:
        fixture.chunk_observations[-1].update(
            outcome="peer_closed",
            flushed_byte_count=None,
            disconnect_category="broken_pipe",
        )
    final_completion = (
        fixture.body_started_at
        + fixture.chunk_observations[-1]["write_completed_seconds"]
    )
    successful = (
        fixture.chunk_observations[-2]
        if final_closed
        else fixture.chunk_observations[-1]
    )
    last_success = fixture.body_started_at + successful["write_completed_seconds"]
    read_budget = 15 if name.startswith("application") else 20
    outcome_at = (
        final_completion - 3 if case["mode"] == "stall" else final_completion + 0.1
    )
    expected = max(final_completion + 2, outcome_at + 2, last_success + read_budget + 2)
    assert runner.late_window_end(fixture, outcome_at, case, timing) == pytest.approx(
        expected
    )
    # Actual completion, not the nominal final offset, anchors the tail window.
    fixture.chunk_observations[-1]["write_completed_seconds"] += 0.2
    shifted = runner.late_window_end(fixture, outcome_at, case, timing)
    assert shifted == pytest.approx(expected + 0.2)
    assert runner.late_window_end(fixture, expected + 3, case, timing) == pytest.approx(
        expected + 5
    )


@pytest.mark.parametrize(
    "name", [name for name in CASE_NAMES if not name.endswith("stall")]
)
@pytest.mark.parametrize(
    "lower,upper,accepted",
    [
        (123.5, 126.02, True),
        (123.499, 124.1, False),
        (123.5, 126.021, False),
        (105, 124.1, False),
    ],
)
def test_success_requires_entire_conservative_interval_in_declared_final_flush_window(
    runner, name, lower, upper, accepted
):
    case, timing = case_inputs(runner, name)
    flush = {"write_started_at": 124, "write_completed_at": 124.02}
    if accepted:
        assert runner.assert_transition_timing(lower, upper, flush, case, timing)
    else:
        with pytest.raises(AssertionError):
            runner.assert_transition_timing(lower, upper, flush, case, timing)


@pytest.mark.parametrize(
    "mutation", [None, "secret", "stderr", "stdout", "oversize", "exit", "wait_timeout"]
)
def test_shutdown_reads_actual_output_after_wait_without_leaking_payloads(
    runner, mutation
):
    stdout = io.BytesIO()
    stderr = io.BytesIO(
        (
            "WARNING:issuance.infrastructure.api.routes:REVOCATION_PROFILE_SERVICE_URL not set — revocation calls will fail\n"
            "WARNING:issuance.infrastructure.api.routes:CREDENTIAL_TEMPLATE_SERVICE_URL not set — template calls will fail\n"
        ).encode()
    )
    initial = runner.observed_log_profile(stdout, stderr, "synthetic-shutdown-secret")
    calls = []

    def signal(value):
        assert value == runner.signal.SIGINT
        calls.append("signal")

    def wait(timeout):
        assert timeout == 10 and calls == ["signal"]
        calls.append("wait")
        stream = stdout if mutation == "stdout" else stderr
        stream.seek(0, 2)
        if mutation == "secret":
            stream.write(b"synthetic-shutdown-secret")
        elif mutation in ("stdout", "stderr"):
            stream.write(b"ERROR:private-logger:private-shutdown-payload\n")
        elif mutation == "oversize":
            stream.write(b"x" * 65537)
        elif mutation == "wait_timeout":
            raise TimeoutError("Synthetic owned wait deadline")
        return 0 if mutation == "exit" else -2

    child = SimpleNamespace(send_signal=signal, wait=wait)
    if mutation is None:
        exit_code, observed = runner.finish_and_verify_output(
            child, stdout, stderr, "synthetic-shutdown-secret"
        )
        assert exit_code == -2 and observed == initial
    else:
        with pytest.raises((AssertionError, TimeoutError)) as caught:
            runner.finish_and_verify_output(
                child, stdout, stderr, "synthetic-shutdown-secret"
            )
        assert all(
            value not in str(caught.value)
            for value in (
                "synthetic-shutdown-secret",
                "private-logger",
                "private-shutdown-payload",
            )
        )
    assert calls == ["signal", "wait"]
