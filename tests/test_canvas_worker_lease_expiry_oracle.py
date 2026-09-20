"""Adversarial synthetic controls; not actual published lease-expiry evidence."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
CASES = ("renewal_lock_early_release", "renewal_lock_crosses_expiry")
PRIVATE = "synthetic-private-lease-test-must-not-escape"


@pytest.fixture
def runner(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("run_canvas_worker_lease_expiry_oracle")


def original_job():
    started = datetime(2026, 9, 8, tzinfo=timezone.utc)
    return {
        "id": "worker-validation-job",
        "organization_id": "org-review",
        "target_id": "target-review",
        "attempt_count": 1,
        "status": "leased",
        "lease_owner": "worker-rest",
        "lease_expires_at": started + timedelta(seconds=30),
        "started_at": started,
        "result": {},
    }


@pytest.mark.parametrize("name", CASES)
def test_closed_case_selection_preserves_two_distinct_controls(runner, name):
    case = runner.validate_case(name)
    assert case["name"] == name


@pytest.mark.parametrize(
    "name", ["", "unknown", "renewal_lock_early_release ", None, True]
)
def test_unknown_cases_rejected_before_resource_setup(runner, name):
    with pytest.raises((AssertionError, ValueError, TypeError)):
        runner.validate_case(name)


@pytest.mark.parametrize("locked", [True, False])
@pytest.mark.parametrize(
    "field,value",
    [
        ("id", PRIVATE),
        ("organization_id", PRIVATE),
        ("target_id", PRIVATE),
        ("attempt_count", 2),
        ("attempt_count", True),
        ("started_at", datetime(2026, 9, 9, tzinfo=timezone.utc)),
    ],
)
def test_same_generation_is_required_before_and_after_unlock(
    runner, locked, field, value
):
    initial = original_job()
    current = deepcopy(initial)
    current[field] = value
    with pytest.raises(AssertionError) as caught:
        runner.validate_job(current, initial, locked=locked)
    assert PRIVATE not in str(caught.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "retry"),
        ("lease_owner", PRIVATE),
        ("result", {"target_config_version": 1}),
        ("lease_expires_at", datetime(2026, 9, 8, tzinfo=timezone.utc)),
    ],
)
def test_locked_lease_cannot_have_already_changed(runner, field, value):
    initial = original_job()
    current = deepcopy(initial)
    current[field] = value
    with pytest.raises(AssertionError) as caught:
        runner.validate_job(current, initial, locked=True)
    assert PRIVATE not in str(caught.value)


def test_locked_original_lease_is_accepted_without_clock_rewrite(runner):
    initial = original_job()
    before = deepcopy(initial)
    runner.validate_job(initial, before, locked=True)
    assert initial == before


@pytest.mark.parametrize("status", ["succeeded", "retry", "dead_letter"])
def test_postrelease_does_not_preselect_one_terminal_outcome(runner, status):
    initial = original_job()
    current = {
        **initial,
        "status": status,
        "lease_owner": None,
        "lease_expires_at": None,
        "result": {},
    }
    runner.validate_job(current, initial, locked=False)


def test_postrelease_renewal_is_observed_not_forced_to_failure(runner):
    initial = original_job()
    current = {
        **initial,
        "lease_expires_at": initial["lease_expires_at"] + timedelta(seconds=10),
    }
    runner.validate_job(current, initial, locked=False)


@pytest.mark.parametrize(
    "field,value", [("status", "queued"), ("lease_owner", PRIVATE)]
)
def test_postrelease_observation_still_rejects_a_different_owner_or_generation(
    runner, field, value
):
    initial = original_job()
    current = {**initial, field: value}
    with pytest.raises(AssertionError) as caught:
        runner.validate_job(current, initial, locked=False)
    assert PRIVATE not in str(caught.value)


def test_postrelease_lease_cannot_move_backwards(runner):
    initial = original_job()
    current = {
        **initial,
        "lease_expires_at": initial["lease_expires_at"] - timedelta(seconds=1),
    }
    with pytest.raises(AssertionError):
        runner.validate_job(current, initial, locked=False)


@pytest.mark.parametrize("status", ["succeeded", "retry", "dead_letter"])
def test_terminal_row_must_release_both_lease_fields(runner, status):
    initial = original_job()
    for changed in (
        {"status": status, "lease_owner": None},
        {"status": status, "lease_expires_at": None},
    ):
        with pytest.raises(AssertionError):
            runner.validate_job({**initial, **changed}, initial, locked=False)


@pytest.mark.parametrize("side", ["current", "initial"])
@pytest.mark.parametrize("mutation", ["missing", "extra", "not_mapping"])
def test_job_shape_is_closed_and_never_discloses_payload(runner, side, mutation):
    pair = {"current": original_job(), "initial": original_job()}
    if mutation == "missing":
        del pair[side]["started_at"]
    elif mutation == "extra":
        pair[side]["private"] = PRIVATE
    else:
        pair[side] = PRIVATE
    with pytest.raises(AssertionError) as caught:
        runner.validate_job(pair["current"], pair["initial"], locked=True)
    assert PRIVATE not in str(caught.value)


def cleanup_owners(monkeypatch, runner, fail_at=None):
    events = []

    def action(name):
        def invoke(*_args, **_kwargs):
            events.append(name)
            if name == fail_at:
                raise RuntimeError(PRIVATE)

        return invoke

    blocker = SimpleNamespace(
        rollback=action("rollback"), close=action("blocker_close")
    )
    fixture = SimpleNamespace(
        cancel_schedule=SimpleNamespace(set=action("cancel")),
        initial_ready=SimpleNamespace(set=action("unblock")),
        close=action("join"),
    )
    engine = SimpleNamespace(dispose=action("dispose"))
    child = object()
    monkeypatch.setattr(runner, "finish_worker", action("finish"))
    return events, blocker, child, fixture, engine


def test_cleanup_releases_owned_row_lock_before_worker_or_fixture_shutdown(
    runner, monkeypatch
):
    events, blocker, child, fixture, engine = cleanup_owners(monkeypatch, runner)
    runner.cleanup(blocker, child, fixture, engine)
    assert events.index("rollback") < events.index("cancel")
    assert events.index("cancel") < events.index("unblock")
    assert events.index("unblock") < events.index("finish")
    assert events.index("finish") < events.index("join") < events.index("dispose")


@pytest.mark.parametrize(
    "fail_at", ["rollback", "cancel", "unblock", "finish", "join", "dispose"]
)
def test_cleanup_attempts_all_owners_and_never_reports_private_exception(
    runner, monkeypatch, fail_at
):
    events, blocker, child, fixture, engine = cleanup_owners(
        monkeypatch, runner, fail_at
    )
    with pytest.raises(AssertionError) as caught:
        runner.cleanup(blocker, child, fixture, engine)
    assert events[0] == "rollback"
    assert {"cancel", "unblock", "finish", "join", "dispose"}.issubset(events)
    assert PRIVATE not in str(caught.value)


def test_cleanup_failure_preserves_original_static_failure(runner, monkeypatch):
    events, blocker, child, fixture, engine = cleanup_owners(
        monkeypatch, runner, "rollback"
    )
    original = AssertionError("Original lease observation failed")
    try:
        raise original
    except AssertionError as caught:
        runner.cleanup(blocker, child, fixture, engine)
        assert caught is original
    assert events[-1] == "dispose"
    assert original.__notes__
    assert PRIVATE not in " ".join(original.__notes__)


def test_interrupted_rollback_does_not_abandon_remaining_owned_resources(
    runner, monkeypatch
):
    events, blocker, child, fixture, engine = cleanup_owners(monkeypatch, runner)

    def interrupted():
        events.append("rollback")
        raise KeyboardInterrupt(PRIVATE)

    blocker.rollback = interrupted
    original = AssertionError("Original observation failed")
    try:
        raise original
    except AssertionError as caught:
        runner.cleanup(blocker, child, fixture, engine)
        assert caught is original
    assert events[-1] == "dispose"
    assert {"blocker_close", "cancel", "unblock", "finish", "join"}.issubset(events)
    assert PRIVATE not in " ".join(original.__notes__)


def clock_sample(seconds=0.0, width=0.05):
    return {
        "database_now": datetime(2026, 9, 8, tzinfo=timezone.utc)
        + timedelta(seconds=seconds),
        "monotonic_before": 100.0 + seconds,
        "monotonic_after": 100.0 + seconds + width,
    }


def blocker_observation():
    return {
        "waiting_count": 1,
        "matching_count": 1,
        "worker_pid": 300,
        "blocker_pid": 200,
    }


def test_one_distinct_owned_blocker_is_accepted(runner):
    runner.assert_blocker(blocker_observation(), 200)


@pytest.mark.parametrize(
    "field,value",
    [
        ("waiting_count", 0),
        ("waiting_count", 2),
        ("waiting_count", True),
        ("matching_count", 0),
        ("matching_count", 2),
        ("matching_count", True),
        ("worker_pid", 200),
        ("worker_pid", 0),
        ("worker_pid", True),
        ("blocker_pid", 201),
        ("blocker_pid", 0),
        ("blocker_pid", True),
    ],
)
def test_absent_ambiguous_self_or_unowned_blockers_fail(runner, field, value):
    row = blocker_observation()
    row[field] = value
    with pytest.raises(AssertionError):
        runner.assert_blocker(row, 200)


@pytest.mark.parametrize("shape", ["missing", "extra", "not_mapping"])
def test_blocker_report_is_closed_and_payload_safe(runner, shape):
    row = blocker_observation()
    if shape == "missing":
        del row["matching_count"]
    elif shape == "extra":
        row["query"] = PRIVATE
    else:
        row = PRIVATE
    with pytest.raises(AssertionError) as caught:
        runner.assert_blocker(row, 200)
    assert PRIVATE not in str(caught.value)


def test_clock_uses_bounded_brackets_and_database_elapsed_agreement(runner):
    initial = clock_sample()
    current = clock_sample(31)
    runner.validate_clock(initial)
    runner.validate_clock(current, initial)


@pytest.mark.parametrize(
    "mutation",
    [
        "slow",
        "backwards",
        "bool",
        "nan",
        "inf",
        "huge",
        "naive",
        "extra",
        "missing",
    ],
)
def test_invalid_clock_samples_fail_closed(runner, mutation):
    sample = clock_sample()
    if mutation == "slow":
        sample["monotonic_after"] = 100.5001
    elif mutation == "backwards":
        sample["monotonic_after"] = 99
    elif mutation == "bool":
        sample["monotonic_before"] = True
    elif mutation == "nan":
        sample["monotonic_before"] = float("nan")
    elif mutation == "inf":
        sample["monotonic_after"] = float("inf")
    elif mutation == "huge":
        sample["monotonic_after"] = 10**1000
    elif mutation == "naive":
        sample["database_now"] = sample["database_now"].replace(tzinfo=None)
    elif mutation == "extra":
        sample["payload"] = PRIVATE
    else:
        del sample["database_now"]
    with pytest.raises(AssertionError) as caught:
        runner.validate_clock(sample)
    assert PRIVATE not in str(caught.value)


@pytest.mark.parametrize("offset", [-2, 2])
def test_database_clock_jump_cannot_masquerade_as_monotonic_expiry(runner, offset):
    initial = clock_sample()
    current = clock_sample(31)
    current["database_now"] += timedelta(seconds=offset)
    with pytest.raises(AssertionError):
        runner.validate_clock(current, initial)


@pytest.mark.parametrize("elapsed,valid", [(0.1, True), (0.5, True), (0.5001, False)])
def test_actual_clock_reader_checks_query_latency_before_return(
    runner, monkeypatch, elapsed, valid
):
    times = iter((100.0, 100.0 + elapsed))
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(
        runner,
        "scalar",
        lambda engine, query: original_job()["started_at"],
    )
    if valid:
        assert runner.read_clock(object())["monotonic_after"] == 100.0 + elapsed
    else:
        with pytest.raises(AssertionError):
            runner.read_clock(object())


@pytest.mark.parametrize("elapsed,valid", [(0.1, True), (0.5, True), (0.5001, False)])
def test_actual_blocker_reader_checks_entire_connection_and_query_budget(
    runner, monkeypatch, elapsed, valid
):
    times = iter((100.0, 100.0 + elapsed))
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(times))
    events = []

    class Connection:
        def __enter__(self):
            events.append("entered")
            return self

        def __exit__(self, *_):
            events.append("closed")

        def execute(self, statement, parameters):
            assert parameters == {"blocker": 200}
            return SimpleNamespace(
                mappings=lambda: SimpleNamespace(one=blocker_observation)
            )

    engine = SimpleNamespace(connect=Connection)
    if valid:
        assert runner.read_blocker(engine, 200) == blocker_observation()
    else:
        with pytest.raises(AssertionError):
            runner.read_blocker(engine, 200)
    assert events == ["entered", "closed"]


@pytest.mark.parametrize("name,elapsed", [(CASES[0], 12), (CASES[1], 31.1)])
def test_release_control_has_predeclared_valid_clock_brackets(runner, name, elapsed):
    before = clock_sample(elapsed, width=0.02)
    after = clock_sample(elapsed + 0.04, width=0.02)
    expiry = original_job()["lease_expires_at"]
    runner.assert_release_timing(
        runner.validate_case(name), 100.0, before, after, expiry
    )


@pytest.mark.parametrize(
    "name,elapsed",
    [
        (CASES[0], 5),
        (CASES[0], 11.49),
        (CASES[0], 12.49),
        (CASES[0], 31),
        (CASES[1], 12),
        (CASES[1], 30.99),
        (CASES[1], 32),
    ],
)
def test_early_late_or_crossed_rollback_brackets_do_not_pass(runner, name, elapsed):
    before = clock_sample(elapsed, width=0.02)
    after = clock_sample(elapsed + 0.04, width=0.02)
    with pytest.raises(AssertionError):
        runner.assert_release_timing(
            runner.validate_case(name),
            100.0,
            before,
            after,
            original_job()["lease_expires_at"],
        )


def test_early_release_requires_original_lease_still_current(runner):
    expiry = original_job()["started_at"] + timedelta(seconds=12)
    with pytest.raises(AssertionError):
        runner.assert_release_timing(
            runner.validate_case(CASES[0]),
            100.0,
            clock_sample(12, 0.02),
            clock_sample(12.04, 0.02),
            expiry,
        )


@pytest.mark.parametrize("name,elapsed", [(CASES[0], 11.5), (CASES[1], 31)])
def test_slow_rollback_rejects_otherwise_valid_release_time(runner, name, elapsed):
    with pytest.raises(AssertionError):
        runner.assert_release_timing(
            runner.validate_case(name),
            100.0,
            clock_sample(elapsed, 0.02),
            clock_sample(elapsed + 0.51, 0.02),
            original_job()["lease_expires_at"],
        )


def body_fixture(final_outcome="flushed", final_completed=34.2):
    observations = [
        {"outcome": "flushed", "write_completed_seconds": offset}
        for offset in (0.1, 8.1, 16.1, 24.1)
    ] + [{"outcome": final_outcome, "write_completed_seconds": final_completed}]
    return SimpleNamespace(body_started_at=100.0, observations=lambda: observations)


@pytest.mark.parametrize(
    "final_outcome,completed,outcome,expected",
    [
        ("flushed", 34.2, 134.3, 151.2),
        ("peer_closed", 34.2, 134.3, 141.1),
        ("peer_closed", 35.0, 150.0, 152.0),
        ("flushed", 35.0, 134.3, 152.0),
    ],
)
def test_late_window_uses_actual_attempt_and_successful_read_progress(
    runner, final_outcome, completed, outcome, expected
):
    fixture = body_fixture(final_outcome, completed)
    stop = runner.late_window_end(
        fixture,
        outcome,
        {"target_type": "learner_application"},
        {
            "after_final_attempt_seconds": 2,
            "after_outcome_seconds": 2,
            "after_read_budget_seconds": 2,
        },
    )
    assert stop == pytest.approx(expected)
    assert stop >= 100 + completed + 2
    assert stop >= outcome + 2


def test_scenario_is_closed_new_input_not_a_changed_body_corpus():
    scenario = json.loads(
        (ROOT / "contracts/canvas-worker-lease-expiry-scenarios.json").read_text(
            encoding="utf-8"
        )
    )
    assert scenario["schema"] == "marty.canvas-worker-lease-expiry-scenarios/v1"
    assert scenario["cases"] == [
        {"name": CASES[0], "release_policy": "request_plus_12"},
        {"name": CASES[1], "release_policy": "original_expiry_plus_1"},
    ]
    assert scenario["environment"] == {
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "120",
        "CANVAS_SYNC_WORKER_LEASE_SECONDS": "30",
        "CANVAS_SYNC_WORKER_POLL_SECONDS": "120",
        "LOG_LEVEL": "WARNING",
    }
    assert scenario["schedule"] == [0, 8, 16, 24, 34]
    assert all(type(value) is int for value in scenario["schedule"])
    assert scenario["source_sha256"] == {
        "issuance.canvas_worker": "c5a7a692af7a808486b0a42d379699222bdf01f3995181c16da9d3466666e90a",
        "issuance.infrastructure.api.canvas_routes": "f3ea0cd0f94da4b08d071f03cad47afddf1ff2a587210c6a442b0b2f2a331943",
        "issuance.infrastructure.adapters.postgres_repository": "34ba42bd10227e0040c99378254c3652c388bab3131aadfdba2e0fe92cf89ccb",
        "issuance.application.canvas_sync_jobs": "e3cc45ef4b40cf9f80ad46699768e7d584bde53e75d29f36ab783780fa03e5f9",
    }


def schedule_fixture():
    chunks = (b"  {", b'"ke', b'y":', b"1", b"}")
    ledger = [
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
        for index, (offset, chunk) in enumerate(zip((0, 8, 16, 24, 34), chunks))
    ]
    return SimpleNamespace(
        chunks=chunks,
        observations=lambda: ledger,
        schedule_completed=SimpleNamespace(is_set=lambda: True),
        handler_finished=SimpleNamespace(is_set=lambda: True),
    )


@pytest.mark.parametrize("crosses_expiry", [False, True])
def test_all_five_real_flushes_are_valid_without_selecting_a_terminal_result(
    runner, crosses_expiry
):
    fixture = schedule_fixture()
    observed = runner.assert_schedule(fixture, crosses_expiry=crosses_expiry)
    assert len(observed) == 5
    assert all(row["write_within_declared_band"] for row in observed)


@pytest.mark.parametrize(
    "category", ["broken_pipe", "connection_reset", "tls_eof", "tls_closed"]
)
def test_only_cross_expiry_final_slot_can_report_a_closed_peer(runner, category):
    fixture = schedule_fixture()
    fixture.observations()[-1].update(
        outcome="peer_closed", flushed_byte_count=None, disconnect_category=category
    )
    runner.assert_schedule(fixture, crosses_expiry=True)
    with pytest.raises(AssertionError):
        runner.assert_schedule(fixture, crosses_expiry=False)


@pytest.mark.parametrize(
    "mutation",
    [
        "early_peer_close",
        "unknown_peer_close",
        "attempt_is_not_flush",
        "zero_bytes",
        "wrong_bytes",
        "late_write",
        "early_write",
        "reversed_write",
        "bool_index",
        "bool_time",
        "bool_bytes",
        "extra_payload",
        "wrong_offset",
        "missing_slot",
        "not_completed",
        "not_joined_writer",
    ],
)
def test_schedule_rejects_ambiguous_late_or_failed_body_progress(runner, mutation):
    fixture = schedule_fixture()
    row = fixture.observations()[1]
    if mutation == "early_peer_close":
        row.update(
            outcome="peer_closed",
            flushed_byte_count=None,
            disconnect_category="broken_pipe",
        )
    elif mutation == "unknown_peer_close":
        fixture.observations()[-1].update(
            outcome="peer_closed", flushed_byte_count=None, disconnect_category=PRIVATE
        )
    elif mutation == "attempt_is_not_flush":
        row["flushed_byte_count"] = None
    elif mutation == "zero_bytes":
        row["byte_count"] = 0
    elif mutation == "wrong_bytes":
        row["flushed_byte_count"] = 99
    elif mutation == "late_write":
        row["write_completed_seconds"] = 8.5001
    elif mutation == "early_write":
        row["write_started_seconds"] = 7.99
    elif mutation == "reversed_write":
        row["write_completed_seconds"] = 8
    elif mutation == "bool_index":
        row["index"] = True
    elif mutation == "bool_time":
        fixture.observations()[0]["scheduled_offset_seconds"] = False
    elif mutation == "bool_bytes":
        fixture.observations()[-1]["byte_count"] = True
    elif mutation == "extra_payload":
        row["payload"] = PRIVATE
    elif mutation == "wrong_offset":
        row["scheduled_offset_seconds"] = 7
    elif mutation == "missing_slot":
        fixture.observations().pop()
    elif mutation == "not_completed":
        fixture.schedule_completed.is_set = lambda: False
    else:
        fixture.handler_finished.is_set = lambda: False
    with pytest.raises(AssertionError) as caught:
        runner.assert_schedule(fixture, crosses_expiry=True)
    assert PRIVATE not in str(caught.value)


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "case",
        "order",
        "policy",
        "environment",
        "schedule",
        "bool_schedule",
        "source_pin",
    ],
)
def test_reviewed_inputs_fail_before_any_source_or_database_owner(
    runner, monkeypatch, mutation
):
    scenario = json.loads(
        (ROOT / "contracts" / runner.SCENARIO).read_text(encoding="utf-8")
    )
    if mutation == "schema":
        scenario["schema"] += "-unknown"
    elif mutation == "case":
        scenario["cases"][-1]["name"] = PRIVATE
    elif mutation == "order":
        scenario["cases"].reverse()
    elif mutation == "policy":
        scenario["cases"][0]["release_policy"] = "outcome_selected"
    elif mutation == "environment":
        scenario["environment"]["CANVAS_SYNC_WORKER_LEASE_SECONDS"] = "90"
    elif mutation == "schedule":
        scenario["schedule"][-1] = 30
    elif mutation == "bool_schedule":
        scenario["schedule"][0] = False
    else:
        scenario["source_sha256"]["issuance.canvas_worker"] = "0" * 64
    original = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *args, **kwargs: (
            json.dumps(scenario)
            if path.name == runner.SCENARIO
            else original(path, *args, **kwargs)
        ),
    )

    def unexpected(*_):
        pytest.fail("Malformed scenario reached source or database owner")

    monkeypatch.setattr(runner.body, "verify_sources", unexpected)
    monkeypatch.setattr(runner, "create_engine", unexpected)
    with pytest.raises(AssertionError) as caught:
        runner.verify_inputs(ROOT / "contracts", {})
    assert PRIVATE not in str(caught.value)


@pytest.mark.parametrize("fails", [False, True])
def test_prepare_dispatches_only_new_family_and_preserves_quiet_owned_cleanup(
    monkeypatch, capsys, fails
):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    probe = importlib.import_module("prepare_canvas_published_schema")
    for key in tuple(probe.os.environ):
        if key.startswith("MARTY_CANVAS_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("MARTY_CANVAS_WORKER_LEASE_EXPIRY_CASE", CASES[1])
    source = "synthetic pinned worker source"
    source_hash = hashlib.sha256(source.encode()).hexdigest()
    fixture = {
        "observed_source_sha256": source_hash,
        "migration_revisions": ["synthetic-revision"],
    }

    def read(path, *args, **kwargs):
        if path.name == "canvas-worker-consumer-range-oracle.json":
            return json.dumps(fixture)
        assert path == Path("/synthetic-worker.py")
        return source

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(
        probe.importlib.util,
        "find_spec",
        lambda name: SimpleNamespace(origin="/synthetic-worker.py"),
    )
    calls = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def execute(self, statement):
            calls.append(str(statement))
            return SimpleNamespace(scalars=lambda: ["synthetic-revision"])

    engine = SimpleNamespace(
        begin=Connection,
        connect=Connection,
        dispose=lambda: calls.append("dispose"),
    )
    monkeypatch.setattr(probe, "create_engine", lambda *args, **kwargs: engine)
    migration = ModuleType("services.issuance.manage_migrations")
    migration.upgrade = lambda: calls.append("upgrade")
    monkeypatch.setitem(sys.modules, migration.__name__, migration)
    expiry = ModuleType("run_canvas_worker_lease_expiry_oracle")
    body = ModuleType("run_canvas_worker_body_timeout_oracle")
    failure = AssertionError("Synthetic expiry capture failed")
    observation = {"schema": "synthetic-expiry", "sample": 1.0}

    def run(case):
        assert case == CASES[1]
        calls.append("expiry")
        print(PRIVATE)
        print(PRIVATE, file=sys.stderr)
        if fails:
            raise failure
        return observation

    def unexpected_body(*_):
        pytest.fail("Old BODY run must not be invoked by expiry dispatch")

    expiry.run = run
    body.run = unexpected_body
    monkeypatch.setitem(sys.modules, expiry.__name__, expiry)
    monkeypatch.setitem(sys.modules, body.__name__, body)
    if fails:
        with pytest.raises(AssertionError) as caught:
            probe.prepare()
        assert caught.value is failure
    else:
        report = probe.prepare()
        assert report["worker_lease_expiry"] is observation
        assert report["status"] == "passed"
        assert report["worker_sha256"] == source_hash
        assert not any(
            name in report
            for name in ("worker_body_timeout", "worker_timeout", "worker_deadline")
        )
    assert calls[-1] == "dispose"
    assert (
        calls.count("expiry") == calls.count("upgrade") == calls.count("dispose") == 1
    )
    assert capsys.readouterr() == ("", "")
