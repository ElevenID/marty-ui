"""Synthetic fixture integrity, not published/native timeout qualification."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from http.client import HTTPSConnection, RemoteDisconnected
import importlib
import hashlib
import io
import json
from pathlib import Path
import ssl
import time
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_frozen_timeout_capture_preserves_all_four_observed_controls():
    raw = (ROOT / "contracts/canvas-worker-timeout-oracle.json").read_bytes()
    assert hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest() == (
        "d5c9bbfb30e841a1b695159a2e6ded4e5d13f428f7ca99bded6729d13c262f49"
    )
    reference = json.loads(raw)
    assert reference["schema"] == "marty.canvas-worker-timeout-oracle/v1"
    cases = reference["observations"]
    assert [case["case"] for case in cases] == [
        "application_prompt",
        "application_delayed_headers",
        "roster_prompt",
        "roster_delayed_headers",
    ]
    for index, case in enumerate(cases):
        assert case["schema"] == "marty.canvas-worker-timeout-observation/v1"
        assert case["outcome"]["jobs"][0]["status"] == (
            "retry" if index == 1 else "succeeded"
        )
        assert len(case["requests"]) == 1 and case["requests"][0]["method"] == "GET"
        for key, value in case["timing"].items():
            assert value is (index == 1 if key == "outcome_before_release" else True)
        assert case["stable_after_release_handler_join_and_interrupt"] is True
        assert case["exit_code_after_interrupt"] == -2
        if index >= 2:
            assert set(case["outcome"]["jobs"][0]["result"]) == {
                "candidates_seen",
                "pending_claim",
                "identity_link_required",
                "observations_written",
            }


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return (
        importlib.import_module("canvas_worker_timeout_https_fixture"),
        importlib.import_module("run_canvas_worker_timeout_oracle"),
    )


def expected_request():
    return {
        "method": "GET",
        "path": "/owned",
        "authorization": "Bearer synthetic-token",
        "accept": "application/json",
    }


def request(fixture, *, method="GET", path="/owned", token="synthetic-token"):
    client = HTTPSConnection(
        "127.0.0.1",
        fixture.server.server_port,
        context=ssl.create_default_context(cafile=str(fixture.cert)),
        timeout=3,
    )
    try:
        client.request(
            method,
            path,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        response = client.getresponse()
        return response.status, response.read()
    finally:
        client.close()


@pytest.mark.parametrize(
    "name",
    [
        "application_prompt",
        "application_delayed_headers",
        "roster_prompt",
        "roster_delayed_headers",
    ],
)
def test_case_reuses_seed_owners_and_has_one_initial_job(modules, name):
    _, oracle = modules
    matrix, case, spec, shared, response, expected, job_id = oracle.load_case(
        ROOT / "contracts", name
    )
    assert "Source-derived" in matrix["expectation_status"]
    assert shared["seed"] and matrix["environment"] == oracle.ENVIRONMENT
    assert all(
        query.startswith("SELECT ")
        for key, query in matrix.items()
        if key.endswith("_sql")
    )
    assert (
        sum(
            "INSERT INTO issuance_service.canvas_evidence_sync_jobs" in sql
            for sql in spec["post_oauth_seed"]
        )
        == 1
    )
    assert any(job_id in sql for sql in spec["post_oauth_seed"])
    states = json.loads((ROOT / "contracts" / matrix["state_scenario"]).read_text())
    assert matrix["effect_rows_sql"] == states["effect_rows_sql"]
    assert matrix["operational_rows_sql"] == states["operational_rows_sql"]
    assert expected["authorization"] == f"Bearer {spec['token']}"
    assert expected["accept"] == "application/json" and expected["method"] == "GET"
    if case["target_type"] == "background_roster":
        roster = json.loads(
            (ROOT / "contracts" / matrix["roster_scenario"]).read_text()
        )
        assert spec["post_oauth_seed"] == roster["seed"]
        assert response == {"status": 200, "body": []}
        assert expected["path"].endswith("enrollment_type%5B%5D=student&per_page=100")
    else:
        assert response == spec["stages"][0]
        assert spec["post_oauth_seed"][0] == matrix["application_seed"]
        assert expected["path"].endswith("submissions/7?include%5B%5D=assignment")


@pytest.mark.parametrize(
    "mutation",
    [
        "empty",
        "duplicate",
        "omit_prompt",
        "wrong_delay",
        "wrong_target",
        "short_job",
        "early_release",
    ],
)
def test_matrix_cannot_drop_controls_or_change_timeout_isolation(
    modules, monkeypatch, mutation
):
    _, oracle = modules
    original = Path.read_text
    matrix = json.loads(
        (ROOT / "contracts/canvas-worker-timeout-scenarios.json").read_text()
    )
    if mutation == "empty":
        matrix["cases"] = []
    elif mutation == "duplicate":
        matrix["cases"][1] = deepcopy(matrix["cases"][0])
    elif mutation == "omit_prompt":
        matrix["cases"].pop(0)
    elif mutation == "wrong_delay":
        matrix["cases"][0]["delayed"] = 0
    elif mutation == "wrong_target":
        matrix["cases"][0]["target_type"] = "issued_drift"
    elif mutation == "short_job":
        matrix["environment"]["CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS"] = "15"
    else:
        matrix["timing"]["delay_seconds"] = 14
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *a, **kw: (
            json.dumps(matrix)
            if path.name == "canvas-worker-timeout-scenarios.json"
            else original(path, *a, **kw)
        ),
    )
    with pytest.raises(AssertionError):
        oracle.load_case(ROOT / "contracts", "application_prompt")


def test_unknown_case_fails_before_fixture_or_process(modules):
    with pytest.raises(AssertionError, match="Unknown timeout case"):
        modules[1].load_case(ROOT / "contracts", "not-an-approved-case")


@pytest.mark.parametrize("delayed", [False, True])
def test_actual_https_release_is_independent_of_worker_outcome(modules, delayed):
    fixture_module, _ = modules
    with ThreadPoolExecutor(max_workers=1) as clients:
        with fixture_module.TimeoutHttpsFixture(
            expected_request(),
            {"status": 200, "body": []},
            delay_seconds=0.15 if delayed else 0,
        ) as fixture:
            root = Path(fixture.certificates.name)
            future = clients.submit(request, fixture)
            assert fixture.request_started.wait(2)
            assert fixture.received_at is not None and not future.done()
            assert fixture.requests == [expected_request()]
            # Delayed mode must release even though no worker outcome or prompt
            # readiness event ever arrives. Prompt mode waits for the snapshot.
            if not delayed:
                assert not fixture.release.is_set()
                fixture.prompt_ready.set()
            assert future.result(timeout=2) == (200, b"[]")
            assert fixture.released_at >= fixture.received_at
            if delayed:
                assert fixture.released_at - fixture.received_at >= 0.15
                assert not fixture.prompt_ready.is_set()
            assert fixture.response_unblocked.is_set()
            fixture.assert_requests()
        assert not fixture.controller.is_alive() and not fixture.thread.is_alive()
        assert not root.exists()


def test_close_releases_and_joins_a_pending_response_without_claiming_timed_release(
    modules,
):
    fixture_module, _ = modules
    with ThreadPoolExecutor(max_workers=1) as clients:
        with fixture_module.TimeoutHttpsFixture(
            expected_request(), {"status": 200, "body": []}, delay_seconds=17
        ) as fixture:
            future = clients.submit(request, fixture)
            assert fixture.request_started.wait(2)
            assert not fixture.release.is_set()
        assert future.result(timeout=2) == (200, b"[]")
        assert fixture.released_at is None
        assert not fixture.controller.is_alive()


@pytest.mark.parametrize("mutation", ["path", "auth", "extra"])
def test_wrong_or_extra_https_requests_fail_without_echoing_values(modules, mutation):
    fixture_module, _ = modules
    fixture = fixture_module.TimeoutHttpsFixture(
        expected_request(), {"status": 200, "body": []}, delay_seconds=0
    )
    fixture.prompt_ready.set()
    with pytest.raises(AssertionError):
        with fixture:
            if mutation == "extra":
                assert request(fixture)[0] == 200
            with pytest.raises(RemoteDisconnected):
                request(
                    fixture,
                    path="/private-sentinel" if mutation == "path" else "/owned",
                    token="private-sentinel"
                    if mutation == "auth"
                    else "synthetic-token",
                )
            with pytest.raises(AssertionError) as caught:
                fixture.assert_requests()
            assert "private-sentinel" not in str(caught.value)
    assert not fixture.controller.is_alive() and not fixture.thread.is_alive()


def test_unsupported_post_is_observed_and_rejected_not_silently_ignored(modules):
    fixture_module, _ = modules
    with fixture_module.TimeoutHttpsFixture(
        expected_request(), {"status": 200, "body": []}, delay_seconds=0
    ) as fixture:
        assert request(fixture, method="POST")[0] == 501
        assert fixture.requests[0]["method"] == "POST"
        assert not fixture.request_started.is_set()
        with pytest.raises(AssertionError, match="requests differ"):
            fixture.assert_requests()


def test_controller_failure_releases_waiter_but_fails_transport(modules, monkeypatch):
    fixture_module, _ = modules
    fixture = fixture_module.TimeoutHttpsFixture(
        expected_request(), {"status": 200, "body": []}, delay_seconds=0
    )

    def expired(*_):
        raise AssertionError("not retained")

    monkeypatch.setattr(fixture, "_wait", expired)
    fixture._control()
    assert fixture.release.is_set() and fixture.released_at is None
    assert fixture.failures == ["Owned timeout release controller failed"]
    with pytest.raises(AssertionError):
        fixture.assert_requests()


def test_no_release_fails_actual_barrier_contract(modules):
    fixture_module, _ = modules
    fixture = fixture_module.TimeoutHttpsFixture(
        expected_request(), {"status": 200, "body": []}, delay_seconds=0
    )
    fixture.requests = [expected_request()]
    calls = []
    fixture.release = SimpleNamespace(
        wait=lambda timeout: calls.append(timeout) or False
    )
    with pytest.raises(AssertionError, match="never released"):
        fixture.wait_for_response(0, "/owned", fixture.stage)
    assert calls == [30] and not fixture.response_unblocked.is_set()


def test_controller_construction_failure_closes_existing_https_owner(
    modules, monkeypatch
):
    fixture_module, _ = modules
    calls = []
    monkeypatch.setattr(
        fixture_module.WorkerHttpsFixture,
        "__enter__",
        lambda self: calls.append("start"),
    )
    monkeypatch.setattr(
        fixture_module.WorkerHttpsFixture, "close", lambda self: calls.append("close")
    )

    def fail_construction(**_):
        raise RuntimeError("synthetic controller construction failure")

    monkeypatch.setattr(fixture_module, "Thread", fail_construction)
    fixture = fixture_module.TimeoutHttpsFixture(
        expected_request(), {"status": 200, "body": []}, delay_seconds=0
    )
    with pytest.raises(RuntimeError, match="synthetic controller construction"):
        fixture.__enter__()
    assert calls == ["start", "close"]
    assert fixture.cancel_controller.is_set() and fixture.release.is_set()


def test_controller_join_failure_still_closes_https_owner(modules, monkeypatch):
    fixture_module, _ = modules
    calls = []
    monkeypatch.setattr(
        fixture_module.WorkerHttpsFixture, "close", lambda self: calls.append("close")
    )

    def fail_join(*, timeout):
        assert timeout == 5
        raise RuntimeError("synthetic controller join failure")

    fixture = fixture_module.TimeoutHttpsFixture(
        expected_request(), {"status": 200, "body": []}, delay_seconds=0
    )
    fixture.controller = SimpleNamespace(ident=1, join=fail_join)
    with pytest.raises(RuntimeError, match="synthetic controller join"):
        fixture.close()
    assert calls == ["close"]
    assert fixture.cancel_controller.is_set() and fixture.release.is_set()


@pytest.mark.parametrize(
    "delayed,elapsed,valid",
    [
        (False, 0.1, True),
        (False, 2, False),
        (True, 17, True),
        (True, 15, False),
        (True, 19, False),
        (True, None, False),
    ],
)
def test_timing_predicate_cannot_accept_wrong_or_cleanup_release(
    modules, delayed, elapsed, valid
):
    _, oracle = modules
    fixture = SimpleNamespace(
        received_at=10, released_at=None if elapsed is None else 10 + elapsed
    )
    if valid:
        assert oracle.assert_release_timing(
            fixture, {"delayed": delayed}, oracle.TIMING
        )
    else:
        with pytest.raises(AssertionError):
            oracle.assert_release_timing(fixture, {"delayed": delayed}, oracle.TIMING)


@pytest.mark.parametrize("failure", ["timeout", "child_exit", "extra_job"])
def test_outcome_wait_fails_closed_on_timeout_exit_and_extra_job(modules, failure):
    _, oracle = modules
    state = {
        "jobs": [{"status": "leased"}],
        "heartbeat": {"metadata": {"phase": "busy"}},
    }
    if failure == "extra_job":
        state["jobs"].append({"status": "queued"})

    def guard():
        if failure == "child_exit":
            raise AssertionError("Owned child exited")

    with pytest.raises(AssertionError):
        oracle.await_outcome(lambda: state, guard, time.monotonic(), 0.02)


@pytest.mark.parametrize(
    "elapsed,accepted",
    [
        (5, False),
        (10, False),
        (14.49, False),
        (14.5, True),
        (15, True),
        (16.5, True),
        (16.51, False),
        (25, False),
        (35, False),
    ],
)
def test_application_timeout_cannot_pass_only_by_preceding_release(
    modules, elapsed, accepted
):
    _, oracle = modules
    case = {"name": "application_delayed_headers"}
    if accepted:
        assert oracle.assert_outcome_timing(100, 100 + elapsed, case, oracle.TIMING)
    else:
        with pytest.raises(AssertionError):
            oracle.assert_outcome_timing(100, 100 + elapsed, case, oracle.TIMING)


@pytest.mark.parametrize("elapsed", [float("nan"), float("inf"), -1, 25.001])
def test_every_case_rejects_invalid_or_overbudget_observed_outcomes(modules, elapsed):
    _, oracle = modules
    with pytest.raises(AssertionError):
        oracle.assert_outcome_timing(
            100, 100 + elapsed, {"name": "roster_delayed_headers"}, oracle.TIMING
        )


@pytest.mark.parametrize("elapsed", [0, 17, 25])
def test_roster_does_not_inherit_application_timeout_window(modules, elapsed):
    _, oracle = modules
    assert oracle.assert_outcome_timing(
        100, 100 + elapsed, {"name": "roster_delayed_headers"}, oracle.TIMING
    )


def test_outcome_requires_idle_not_just_completed_job(modules):
    _, oracle = modules
    states = iter(
        [
            {
                "jobs": [{"status": "succeeded"}],
                "heartbeat": {"metadata": {"phase": "busy"}},
            },
            {
                "jobs": [{"status": "succeeded"}],
                "heartbeat": {"metadata": {"phase": "idle"}},
            },
        ]
    )
    calls = []
    state, observed_at = oracle.await_outcome(
        lambda: next(states), lambda: calls.append(1), time.monotonic(), 1
    )
    assert len(calls) == 2 and state["heartbeat"]["metadata"]["phase"] == "idle"
    assert isinstance(observed_at, float)


@pytest.mark.parametrize(
    "mutation", [None, "unknown", "duplicate", "token", "oversized"]
)
def test_source_derived_log_profile_requires_actual_exact_lines(modules, mutation):
    _, oracle = modules
    lines = (
        "WARNING:issuance.infrastructure.api.routes:REVOCATION_PROFILE_SERVICE_URL not set — revocation calls will fail\n"
        "WARNING:issuance.infrastructure.api.routes:CREDENTIAL_TEMPLATE_SERVICE_URL not set — template calls will fail\n"
    ).encode()
    if mutation == "unknown":
        lines += b"WARNING:private-sentinel:private-sentinel\n"
    elif mutation == "duplicate":
        lines += lines
    elif mutation == "token":
        lines += b"synthetic-token"
    elif mutation == "oversized":
        lines = b"x" * 65537
    if mutation is None:
        assert oracle.observed_log_profile(
            io.BytesIO(), io.BytesIO(lines), "synthetic-token"
        )["stdout_empty"]
    else:
        with pytest.raises(AssertionError) as caught:
            oracle.observed_log_profile(
                io.BytesIO(), io.BytesIO(lines), "synthetic-token"
            )
        assert "private-sentinel" not in str(caught.value)
        assert "synthetic-token" not in str(caught.value)


def test_runner_failure_reaps_child_disposes_engine_and_closes_fixture(
    modules, monkeypatch
):
    fixture_module, oracle = modules
    loaded = list(oracle.load_case(ROOT / "contracts", "application_prompt"))
    source_bytes = b"synthetic-source"
    for key in ("http_source_sha256", "log_source_sha256"):
        loaded[0][key] = oracle.hashlib.sha256(source_bytes).hexdigest()
    monkeypatch.setattr(oracle, "load_case", lambda *_: loaded)
    monkeypatch.setattr(
        oracle, "worker_source_sha256", lambda: loaded[0]["source_sha256"]
    )
    original_read = Path.read_bytes
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda path: (
            source_bytes
            if str(path).replace("\\", "/").startswith("/app/")
            else original_read(path)
        ),
    )
    events = []
    engine = SimpleNamespace(dispose=lambda: events.append("dispose"))
    monkeypatch.setattr(oracle, "create_engine", lambda *a, **kw: engine)
    monkeypatch.setattr(oracle, "seed_worker_database", lambda *a: (None, "cipher"))
    monkeypatch.setattr(oracle, "scalar", lambda *a: {})
    child = SimpleNamespace(
        poll=lambda: None,
        kill=lambda: events.append("kill"),
        wait=lambda timeout: events.append(("wait", timeout)),
    )
    monkeypatch.setattr(oracle, "start_worker", lambda *a, **kw: child)

    def failed_wait(*a, **kw):
        raise AssertionError("Synthetic startup failure")

    monkeypatch.setattr(oracle, "wait_for", failed_wait)
    fixtures = []

    def owned_fixture(*a, **kw):
        fixture = fixture_module.TimeoutHttpsFixture(*a, **kw)
        fixtures.append(fixture)
        return fixture

    monkeypatch.setattr(oracle, "TimeoutHttpsFixture", owned_fixture)
    with pytest.raises(AssertionError, match="Synthetic startup failure"):
        oracle.run("application_prompt")
    assert events == ["kill", ("wait", 10), "dispose"]
    assert len(fixtures) == 1
    assert not fixtures[0].controller.is_alive() and not fixtures[0].thread.is_alive()
    assert not Path(fixtures[0].certificates.name).exists()


@pytest.mark.parametrize(
    "status,outcome_at,released_at,valid",
    [
        ("retry", 15, 17, True),
        ("retry", 18, 17, False),
        ("succeeded", 18, 17, True),
        ("succeeded", 15, 17, False),
        ("retry", 17, None, False),
    ],
)
def test_outcome_order_rejects_late_retry_and_early_success(
    modules, status, outcome_at, released_at, valid
):
    _, oracle = modules
    if valid:
        assert oracle.assert_outcome_order(
            outcome_at, released_at, {"expected_status": status}
        ) is (status == "retry")
    else:
        with pytest.raises(AssertionError):
            oracle.assert_outcome_order(
                outcome_at, released_at, {"expected_status": status}
            )


def retry_state():
    return {
        "jobs": [
            {
                "status": "retry",
                "attempt_count": 1,
                "max_attempts": 8,
                "lease_owner_present": False,
                "lease_expires_present": False,
                "started": True,
                "completed": False,
                "result": {},
                "last_error_code": "canvas_authoritative_reads_failed",
                "last_error_summary": "No authoritative Canvas evidence requirement could be read",
                "retry_scheduled": True,
                "retry_delay_within_backoff_bounds": True,
            }
        ],
        "heartbeat": {"metadata": {"phase": "idle", "leased_jobs": 0}},
        "oauth": {
            "status": "connected",
            "reauthorization_required": False,
            "refresh_lease_owner_present": False,
            "secret_enabled": True,
            "secret_used": True,
        },
        "target": {
            "target_type": "learner_application",
            "enabled": True,
            "config_version": 1,
            "worker_heartbeat_present": True,
            "last_success_present": False,
            "candidate_count": 0,
            "observation_count": 0,
        },
        "facts": [],
    }


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "deadline",
        "unrelated_error",
        "summary",
        "second_attempt",
        "facts",
        "heads",
        "reviews",
        "events",
        "candidates",
        "observations",
    ],
)
def test_timeout_outcome_requires_specific_error_and_unchanged_evidence(
    modules, mutation
):
    _, oracle = modules
    state = retry_state()
    # Seed real synthetic prior values in this unit boundary: replacing them by
    # an empty list is also a regression, not an acceptable 'no new rows' result.
    baseline = {
        key: [{"id": "synthetic-prior"}]
        for key in ("facts", "heads", "reviews", "events", "candidates", "observations")
    }
    completed = deepcopy(baseline)
    if mutation == "deadline":
        state["jobs"][0]["last_error_code"] = "canvas_sync_deadline_exceeded"
    elif mutation == "unrelated_error":
        state["jobs"][0]["last_error_code"] = "canvas_sync_unexpected_error"
    elif mutation == "summary":
        state["jobs"][0]["last_error_summary"] = "private-sentinel"
    elif mutation == "second_attempt":
        state["jobs"][0]["attempt_count"] = 2
    elif mutation is not None:
        completed[mutation] = []
    case = {"expected_status": "retry", "target_type": "learner_application"}
    if mutation is None:
        oracle.assert_outcome(state, case, baseline, completed)
    else:
        with pytest.raises(AssertionError):
            oracle.assert_outcome(state, case, baseline, completed)


@pytest.mark.parametrize(
    "target,mutation",
    [
        ("learner_application", None),
        ("learner_application", "missing_fact"),
        ("learner_application", "missing_check"),
        ("background_roster", None),
        ("background_roster", "missing_counter"),
        ("background_roster", "missing_wrap"),
        ("background_roster", "nonallowlisted_counter"),
        ("background_roster", "retained_heartbeat"),
    ],
)
def test_positive_controls_require_completed_business_projection(
    modules, target, mutation
):
    _, oracle = modules
    state = retry_state()
    state["jobs"][0].update(
        status="succeeded",
        completed=True,
        last_error_code=None,
        last_error_summary=None,
    )
    state["target"].update(target_type=target, last_success_present=True)
    if target == "learner_application":
        state["facts"] = [{"fact_type": "canvas.assignment_score"}]
        state["jobs"][0]["result"] = {
            "facts_created": 1,
            "requirements_checked": 1,
            "policy_allowed": True,
        }
        if mutation == "missing_fact":
            state["facts"] = []
        elif mutation == "missing_check":
            state["jobs"][0]["result"]["requirements_checked"] = 0
    else:
        state["target"].update(
            metadata={
                "roster_cursor": 0,
                "roster_size": 0,
                "synthetic_marker": "preserve",
            },
            roster_cycle_completed_at_present=True,
            worker_heartbeat_present=False,
        )
        state["jobs"][0]["result"] = {
            "candidates_seen": 0,
            "pending_claim": 0,
            "identity_link_required": 0,
            "observations_written": 0,
        }
        # Bind the synthetic positive's field inventory to every actual frozen
        # worker cycle, not the broader direct processor return value.
        reference = json.loads(
            (ROOT / "contracts/canvas-worker-mixed-roster-oracle.json").read_text()
        )
        assert reference["observations"]
        for observation in reference["observations"]:
            assert set(state["jobs"][0]["result"]) == set(
                observation["state"]["jobs"][-1]["result"]
            )
            assert observation["target"]["worker_id"] is None
        if mutation == "missing_counter":
            state["jobs"][0]["result"].pop("observations_written")
        elif mutation == "missing_wrap":
            state["target"]["metadata"]["roster_cursor"] = 1
        elif mutation == "nonallowlisted_counter":
            state["jobs"][0]["result"]["roster_remaining"] = 0
        elif mutation == "retained_heartbeat":
            state["target"]["worker_heartbeat_present"] = True
    case = {"expected_status": "succeeded", "target_type": target}
    if mutation is None:
        oracle.assert_outcome(state, case, {}, {})
    else:
        with pytest.raises(AssertionError):
            oracle.assert_outcome(state, case, {}, {})
