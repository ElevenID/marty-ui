"""Revocation harness integrity controls, not application parity evidence."""

import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from threading import Event
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest


def test_revocation_matrix_retains_transport_and_cleanup_inputs():
    root = Path(__file__).resolve().parents[1]
    matrix = json.loads(
        (root / "contracts/canvas-worker-oauth-revocation-scenarios.json").read_text()
    )
    cases = matrix["cases"]
    assert len(cases) == len({case["name"] for case in cases}) == 7
    assert [case["status"] for case in cases] == [200, 204, 404, 429, 503, 302, 200]
    assert cases[-1]["hold_response"] is True
    assert cases[3]["delay_bounds"] == [37, 37]
    assert all(case["delay_bounds"] == [30, 37] for case in cases[4:])
    assert len(matrix["additional_secrets"]) == 2
    assert {secret[1] for secret in matrix["additional_secrets"]} == {
        "org-review",
        "org-other",
    }


def test_nested_lease_matrix_inherits_queue_and_original_seed(monkeypatch):
    root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root / "scripts"))
    oracle = importlib.import_module("run_canvas_worker_oauth_revocation_oracle")
    matrix = oracle.load_matrix(
        root / "contracts", "canvas-worker-oauth-revocation-lease-scenarios.json"
    )
    assert len(matrix["seed"]) == 4 and len(matrix["before_start_sql"]) == 5
    assert len(matrix["case_before_start_sql"]) == 2
    assert [case["lease_seconds"] for case in matrix["cases"]] == [30, 120, 300, 300]
    reference = json.loads(
        (
            root / "contracts/canvas-worker-oauth-revocation-lease-oracle.json"
        ).read_text()
    )
    assert {case["name"] for case in matrix["cases"]} == set(reference)
    for case in matrix["cases"]:
        observed = reference[case["name"]]
        assert observed["queue"]["acquired_leases"] == {
            "seconds": case["lease_seconds"],
            "count": 3,
            "all_within_tolerance": True,
        }
        assert observed["heartbeat"]["metadata"]["phase"] == case.get(
            "completion_phase", "idle"
        )
        assert observed["queue"]["unselected_rows_unchanged"] is True
        assert len(observed["requests"]) == len(observed["retained_secret_ids"]) == 3
    assert "completion_sql" in matrix["cases"][-1]


def test_nonempty_selection_reference_preserves_exact_cap_and_order(monkeypatch):
    root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root / "scripts"))
    oracle = importlib.import_module("run_canvas_worker_oauth_revocation_oracle")
    matrix = oracle.load_matrix(
        root / "contracts", "canvas-worker-oauth-revocation-selection-scenarios.json"
    )
    assert matrix["cases"][0]["limits"] == [0, 499, 500, 501, 2147483648]
    reference = json.loads(
        (
            root / "contracts/canvas-worker-oauth-revocation-selection-oracle.json"
        ).read_text()
    )["selection_limits"]
    assert reference["connection_count"] == 509
    assert [item["count"] for item in reference["selections"]] == [
        1,
        499,
        500,
        500,
        500,
    ]
    for item in reference["selections"]:
        ids = [f"cap-{n:04d}" for n in range(1, item["count"] + 1)]
        assert item["ordered_ids_sha256"] == oracle.ordered_selection_digest(ids)
        assert item["ordered_ids_sha256"] != oracle.ordered_selection_digest(
            ids + [ids[-1]]
        )
        if len(ids) > 1:
            assert item["ordered_ids_sha256"] != oracle.ordered_selection_digest(
                list(reversed(ids))
            )
    assert reference["lease_acquisition_count"] == reference["http_request_count"] == 0
    assert (
        reference["connection_rows_unchanged"]
        and reference["ciphertexts_unchanged"]
        and reference["issued_rows_unchanged"]
    )


def test_repository_only_corpus_cannot_claim_native_https_replay(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    native = importlib.import_module("test_canvas_worker_oauth_revocation_https")
    monkeypatch.setattr(
        native,
        "WorkerHttpsFixture",
        lambda: pytest.fail("repository-only corpus must not create HTTPS replay"),
    )
    with pytest.raises(AssertionError):
        native.run("synthetic-not-executed", "oauth-revocation-selection")


@pytest.mark.parametrize("filename", ["a.json", "../outside.json"])
def test_reference_matrix_rejects_cycles_and_external_paths(
    monkeypatch, tmp_path, filename
):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    oracle = importlib.import_module("run_canvas_worker_oauth_revocation_oracle")
    (tmp_path / "a.json").write_text(json.dumps({"base_scenario": "b.json"}))
    (tmp_path / "b.json").write_text(json.dumps({"base_scenario": "a.json"}))
    with pytest.raises(AssertionError):
        oracle.load_matrix(tmp_path, filename)


@pytest.mark.parametrize(
    "durations",
    [
        [30, 30],
        [30, 30, None],
        [30, 30, 29.8],
        [30, 30, 30.2],
        [30, 30, float("nan")],
        [30, 30, float("inf")],
        [30, 30, "30"],
        [30, 30, True],
    ],
)
def test_acquired_lease_observation_rejects_incomplete_or_wrong_evidence(
    monkeypatch, durations
):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    oracle = importlib.import_module("run_canvas_worker_oauth_revocation_oracle")
    with pytest.raises(AssertionError):
        oracle.observe_acquired_leases(durations, 30, 3)
    assert oracle.observe_acquired_leases([29.95, 30, 30.05], 30, 3) == {
        "seconds": 30,
        "count": 3,
        "all_within_tolerance": True,
    }


@pytest.mark.parametrize("names,reference", [(["a", "a"], {"a": {}}), (["a"], {})])
@pytest.mark.parametrize(
    "kind",
    [
        "oauth-revocation",
        "oauth-revocation-fence",
        "oauth-revocation-patch",
        "oauth-revocation-retry-after",
        "oauth-revocation-backoff",
        "oauth-revocation-queue",
        "oauth-revocation-lease",
        "oauth-revocation-counters",
    ],
)
def test_native_owner_rejects_duplicate_or_missing_reference_cases(
    monkeypatch, names, reference, kind
):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    native = importlib.import_module("test_canvas_worker_oauth_revocation_https")
    inputs = iter(
        [
            json.dumps({"cases": [{"name": name} for name in names]}),
            json.dumps(reference),
        ]
    )
    monkeypatch.setattr(Path, "read_text", lambda *_: next(inputs))
    monkeypatch.setattr(
        native,
        "WorkerHttpsFixture",
        lambda: pytest.fail("invalid matrix must fail before fixture creation"),
    )
    with pytest.raises(AssertionError):
        native.run("synthetic-not-executed", kind)


@pytest.mark.parametrize("failure", ["child_exit", "timeout", "wrong_requests"])
@pytest.mark.parametrize(
    "kind",
    [
        "oauth-revocation",
        "oauth-revocation-patch",
        "oauth-revocation-retry-after",
        "oauth-revocation-backoff",
        "oauth-revocation-queue",
        "oauth-revocation-lease",
        "oauth-revocation-counters",
    ],
)
def test_native_owner_fails_closed_and_closes_https(
    monkeypatch, tmp_path, failure, kind
):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    native = importlib.import_module("test_canvas_worker_oauth_revocation_https")
    inputs = iter(
        [
            json.dumps({"cases": [{"name": "synthetic"}]}),
            json.dumps({"synthetic": {"requests": [{"method": "DELETE"}]}}),
        ]
    )
    monkeypatch.setattr(Path, "read_text", lambda *_: next(inputs))
    closed = []

    class Fixture:
        def __enter__(self):
            return SimpleNamespace(
                certificates=SimpleNamespace(name=str(tmp_path)),
                cert=tmp_path / "synthetic-cert",
                origin="https://127.0.0.1:1",
                requests=[],
            )

        def __exit__(self, *_):
            closed.append(True)

    def child(*_, **kwargs):
        assert kwargs["timeout"] == 240
        if failure == "timeout":
            raise native.subprocess.TimeoutExpired("synthetic-owned-child", 240)
        return SimpleNamespace(
            returncode=1 if failure == "child_exit" else 0, stdout="", stderr=""
        )

    monkeypatch.setattr(native, "WorkerHttpsFixture", Fixture)
    monkeypatch.setattr(native.subprocess, "run", child)
    with pytest.raises((AssertionError, native.subprocess.TimeoutExpired)):
        native.run("synthetic-not-executed", kind)
    assert closed == [True]


def test_cycle_reference_counts_return_values_not_durable_retry_count(monkeypatch):
    contracts = Path(__file__).resolve().parents[1] / "contracts"
    monkeypatch.syspath_prepend(str(contracts.parent / "scripts"))
    oracle = importlib.import_module("run_canvas_worker_oauth_revocation_oracle")
    matrix = oracle.load_matrix(
        contracts, "canvas-worker-oauth-revocation-counters-scenarios.json"
    )
    reference = json.loads(
        (contracts / "canvas-worker-oauth-revocation-counters-oracle.json").read_text()
    )
    assert len(matrix["cases"]) == len(reference) == 4
    assert {case["name"] for case in matrix["cases"]} == set(reference)
    assert "takeover_sql" in matrix and len(matrix["additional_secrets"]) == 2
    for case in matrix["cases"]:
        observed = reference[case["name"]]
        expected = dict.fromkeys(
            [
                "scheduled",
                "leased",
                "succeeded",
                "retried",
                "dead_lettered",
                "oauth_revocations_succeeded",
                "oauth_revocations_retried",
            ],
            0,
        )
        if case.get("replace_owner"):
            assert case["hold_response"] is True
            assert observed["fence"]["replacement_row_unchanged"] is True
            assert observed["connection"]["retry_count"] == 7
        else:
            expected[
                "oauth_revocations_succeeded"
                if case["status"] == 200
                else "oauth_revocations_retried"
            ] = 1
        assert observed["cycle_result"] == expected
        assert observed["retained_ciphertexts_unchanged"] is True
        assert observed["issued_rows_unchanged"] is True
        assert observed["job_count"] == 0 and len(observed["requests"]) == 1


@pytest.mark.parametrize("observe", [None, False, True, "true", 1])
def test_only_explicit_cycle_observer_changes_owned_child_command(monkeypatch, observe):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    startup = importlib.import_module("run_canvas_worker_startup_oracle")
    seen = []
    child = object()

    def spawn(command, **kwargs):
        seen.append(command)
        assert kwargs["env"]["CANVAS_SYNC_WORKER_ID"] == "synthetic-observer"
        assert kwargs["stdout"] == kwargs["stderr"] == startup.subprocess.DEVNULL
        assert kwargs["env"]["DATABASE_URL"].endswith("/canvas_published_schema_test")
        return child

    monkeypatch.setattr(startup.subprocess, "Popen", spawn)
    assert (
        startup.start_worker(
            {
                "database_scheme": "postgresql+asyncpg",
                "environment": {},
                "observe_cycle_result": observe,
            },
            "synthetic-observer",
        )
        is child
    )
    assert seen == [
        [
            startup.sys.executable,
            "/verification/scripts/run_canvas_worker_single_cycle.py",
        ]
        if observe is True
        else [startup.sys.executable, "-m", "issuance.canvas_worker"]
    ]


@pytest.mark.parametrize("released", [False, True])
def test_counter_owner_loss_uses_fenced_child_and_requires_release(
    monkeypatch, tmp_path, released
):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    native = importlib.import_module("test_canvas_worker_oauth_revocation_https")
    case = {"name": "synthetic", "replace_owner": True, "hold_response": True}
    requests = [{"method": "DELETE"}]
    inputs = iter(
        [
            json.dumps({"cases": [case]}),
            json.dumps({"synthetic": {"requests": requests}}),
        ]
    )
    monkeypatch.setattr(Path, "read_text", lambda *_: next(inputs))
    closed, calls = [], []
    received, release = Event(), Event()
    received.set()
    if released:
        release.set()

    class Fixture:
        def __enter__(self):
            return SimpleNamespace(
                certificates=SimpleNamespace(name=str(tmp_path)),
                cert=tmp_path / "synthetic-cert",
                origin="https://127.0.0.1:1",
                requests=requests,
                received=received,
                release=release,
            )

        def __exit__(self, *_):
            closed.append(True)

    def fenced(command, environment, https):
        calls.append(environment["MARTY_CANVAS_WORKER_OAUTH_REVOCATION_KIND"])
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(native, "WorkerHttpsFixture", Fixture)
    monkeypatch.setattr(native, "run_fenced_child", fenced)
    monkeypatch.setattr(
        native.subprocess, "run", lambda *_, **__: pytest.fail("fence bypassed")
    )
    if released:
        native.run("synthetic-not-executed", "oauth-revocation-counters")
    else:
        with pytest.raises(AssertionError):
            native.run("synthetic-not-executed", "oauth-revocation-counters")
    assert calls == ["oauth-revocation-counters"] and closed == [True]


def test_revocation_retry_matrix_retains_all_eight_rate_limit_shapes():
    contracts = Path(__file__).resolve().parents[1] / "contracts"
    matrix = json.loads(
        (
            contracts / "canvas-worker-oauth-revocation-retry-after-scenarios.json"
        ).read_text()
    )
    reference = json.loads(
        (
            contracts / "canvas-worker-oauth-revocation-retry-after-oracle.json"
        ).read_text()
    )
    assert matrix["base_scenario"] == "canvas-worker-oauth-revocation-scenarios.json"
    assert len(matrix["cases"]) == len(reference) == 8
    assert {case["name"] for case in matrix["cases"]} == set(reference)
    for case in matrix["cases"]:
        assert case["status"] == 429
        observed = reference[case["name"]]
        assert (
            observed["connection"]["error_code"] == "canvas_oauth_revoke_rate_limited"
        )
        assert observed["connection"]["retry_count"] == 1
        assert observed["connection"]["lease_owner_present"] is False
        assert len(observed["retained_secret_ids"]) == 3
        assert observed["retry_timing"] == {"kind": case["timing"], "matches": True}


def test_queue_reference_retains_order_eligibility_and_limited_batch():
    contracts = Path(__file__).resolve().parents[1] / "contracts"
    matrix = json.loads(
        (contracts / "canvas-worker-oauth-revocation-queue-scenarios.json").read_text()
    )
    reference = json.loads(
        (contracts / "canvas-worker-oauth-revocation-queue-oracle.json").read_text()
    )
    assert matrix["base_scenario"] == "canvas-worker-oauth-revocation-scenarios.json"
    assert {case["name"] for case in matrix["cases"]} == set(reference)
    order = [
        "queue-expired",
        "queue-unleased",
        "queue-oldest",
        "queue-later",
        "worker-rest-connection",
    ]
    for case in matrix["cases"]:
        observed = reference[case["name"]]
        selected = order[: case["request_count"]]
        assert observed["queue"]["lease_order"] == selected
        assert len(observed["requests"]) == len(selected)
        assert observed["queue"]["unselected_rows_unchanged"] is True
        assert observed["retry_timing"] == {"kind": "selected_bounds", "matches": True}
        rows = {row["id"]: row for row in observed["queue"]["connections"]}
        assert len(rows) == 8
        assert rows["queue-connected"]["status"] == "connected"
        assert rows["queue-leased"]["lease_owner"] == "synthetic-prior-worker"
        assert rows["queue-leased"]["lease_expires_present"] is True
        assert all(
            row["retry_count"] == int(name in selected) for name, row in rows.items()
        )
        assert all(rows[name]["lease_owner"] is None for name in selected)
        assert observed["retained_ciphertexts_unchanged"] is True
        assert len(observed["retained_secret_ids"]) == 3
    assert reference["limited_three"]["connection"]["retry_at_present"] is False
    assert reference["all_eligible"]["connection"]["retry_at_present"] is True


def test_backoff_extension_preserves_historical_counts_and_capped_boundaries():
    contracts = Path(__file__).resolve().parents[1] / "contracts"
    matrix = json.loads(
        (
            contracts / "canvas-worker-oauth-revocation-backoff-scenarios.json"
        ).read_text()
    )
    reference = json.loads(
        (contracts / "canvas-worker-oauth-revocation-backoff-oracle.json").read_text()
    )
    assert [case["retry_count"] for case in matrix["cases"]] == [1, 9, 10, 11, 999]
    assert len(matrix["cases"]) == len(reference) == 5
    assert {case["name"] for case in matrix["cases"]} == set(reference)
    assert matrix["cases"][0]["delay_bounds"] == [60, 75]
    assert matrix["cases"][1]["delay_bounds"] == [15360, 19200]
    assert all(case["delay_bounds"] == [21600, 27000] for case in matrix["cases"][2:])
    for case in matrix["cases"]:
        assert case["status"] == 503 and len(case["seed"]) == 1
        observed = reference[case["name"]]
        assert observed["connection"]["retry_count"] == case["retry_count"] + 1
        assert observed["connection"]["error_code"] == "canvas_oauth_revoke_rejected"
        assert len(observed["retained_secret_ids"]) == 3
        assert observed["retry_timing"] == {"kind": "bounds", "matches": True}


@pytest.mark.parametrize(
    "case_name",
    [
        "bounds",
        "date",
        "missing",
        "duplicate",
        "wrong_bound",
        "wrong_date",
        "missing_date",
        "naive",
    ],
)
def test_retry_parent_checks_real_deadline_record_and_closes_fixture(
    monkeypatch, tmp_path, case_name
):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    native = importlib.import_module("test_canvas_worker_oauth_revocation_https")
    is_date = "date" in case_name
    timing = "http_date" if is_date else "bounds"
    case = {"name": "synthetic", "timing": timing, "delay_bounds": [30, 37]}
    requests = [{"method": "DELETE"}]
    inputs = iter(
        [
            json.dumps({"cases": [case]}),
            json.dumps(
                {
                    "synthetic": {
                        "requests": requests,
                        "retry_timing": {"kind": timing, "matches": True},
                    }
                }
            ),
        ]
    )
    monkeypatch.setattr(Path, "read_text", lambda *_: next(inputs))
    updated = datetime(2026, 9, 6, tzinfo=timezone.utc)
    delay = (
        65
        if case_name == "wrong_date"
        else 20
        if case_name == "wrong_bound"
        else 60
        if is_date
        else 35
    )
    record = "CANVAS_WORKER_RETRY_TIMING=" + json.dumps(
        {
            "available_at": (updated + timedelta(seconds=delay)).isoformat(),
            "updated_at": updated.isoformat(),
        }
    )
    if case_name == "missing":
        record = ""
    elif case_name == "duplicate":
        record += "\n" + record
    elif case_name == "naive":
        record = record.replace("+00:00", "")
    dates = (
        [format_datetime(updated + timedelta(seconds=60), usegmt=True)]
        if is_date and case_name != "missing_date"
        else []
    )
    closed = []

    class Fixture:
        def __enter__(self):
            return SimpleNamespace(
                certificates=SimpleNamespace(name=str(tmp_path)),
                cert=tmp_path / "synthetic-cert",
                origin="https://127.0.0.1:1",
                requests=requests,
                retry_after_dates=dates,
            )

        def __exit__(self, *_):
            closed.append(True)

    monkeypatch.setattr(native, "WorkerHttpsFixture", Fixture)
    monkeypatch.setattr(
        native.subprocess,
        "run",
        lambda *_, **__: SimpleNamespace(returncode=0, stdout=record, stderr=""),
    )
    if case_name in {"bounds", "date"}:
        native.run("synthetic-not-executed", "oauth-revocation-retry-after")
    else:
        with pytest.raises(AssertionError):
            native.run("synthetic-not-executed", "oauth-revocation-retry-after")
    assert closed == [True]


def test_owner_fence_extension_retains_closed_cases_and_base_reference():
    contracts = Path(__file__).resolve().parents[1] / "contracts"
    matrix = json.loads(
        (contracts / "canvas-worker-oauth-revocation-fence-scenarios.json").read_text()
    )
    reference = json.loads(
        (contracts / "canvas-worker-oauth-revocation-fence-oracle.json").read_text()
    )
    assert matrix["base_scenario"] == "canvas-worker-oauth-revocation-scenarios.json"
    assert len(matrix["cases"]) == len(reference) == 2
    assert {case["status"] for case in matrix["cases"]} == {200, 429}
    assert all(case["hold_response"] for case in matrix["cases"])
    assert {case["name"] for case in matrix["cases"]} == set(reference)
    for observation in reference.values():
        assert observation["fence"]["before"]["owner"] == "worker-revocation"
        assert (
            observation["fence"]["replacement"]["owner"]
            == "synthetic-replacement-worker"
        )
        assert observation["fence"]["replacement_row_unchanged"] is True
        assert observation["connection"]["retry_count"] == 7
        assert len(observation["retained_secret_ids"]) == 3


def test_patch_failure_extension_observes_update_without_retaining_revoked_tokens():
    contracts = Path(__file__).resolve().parents[1] / "contracts"
    matrix = json.loads(
        (contracts / "canvas-worker-oauth-revocation-patch-scenarios.json").read_text()
    )
    reference = json.loads(
        (contracts / "canvas-worker-oauth-revocation-patch-oracle.json").read_text()
    )
    assert matrix["base_scenario"] == "canvas-worker-oauth-revocation-scenarios.json"
    assert len(matrix["cases"]) == len(reference) == 1
    case = matrix["cases"][0]
    assert case["name"] in reference and case["status"] == 200
    assert len(matrix["before_start_sql"]) == 2
    assert "OLD.id='platform-review'" in matrix["before_start_sql"][1]
    assert (
        "NEW.connection_config->>'oauth_status'='disconnected'"
        in matrix["before_start_sql"][1]
    )
    assert "IN SHARE MODE" in matrix["barrier_sql"]
    assert "wait_event_type='Lock'" in matrix["blocked_sql"]
    observed = reference[case["name"]]
    assert observed["disconnect_marker_update_observed"] is True
    assert observed["connection"] is None and observed["retry_timing"] is None
    assert observed["retained_secret_ids"] == ["worker-unrelated-token"]
    assert observed["platform"]["oauth_status"] == "connected"
    assert observed["heartbeat"]["metadata"]["phase"] == "idle"


@pytest.mark.parametrize(
    "failure",
    [None, "request", "transfer", "slow_transfer", "child_wait", "cleanup_timeout"],
)
def test_fenced_child_requires_handshake_and_releases_owned_response(
    monkeypatch, tmp_path, failure
):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    native = importlib.import_module("test_canvas_worker_oauth_revocation_https")
    https = SimpleNamespace(
        certificates=SimpleNamespace(name=str(tmp_path)),
        received=Event(),
        release=Event(),
    )
    control = tmp_path / "native-control"
    events = []

    class Child:
        returncode = None

        def poll(self):
            return self.returncode

        def communicate(self, timeout):
            assert https.release.is_set()
            events.append(timeout)
            if failure == "child_wait" and timeout == 90:
                raise native.subprocess.TimeoutExpired("synthetic-child", timeout)
            if failure == "cleanup_timeout" and timeout == 30:
                raise native.subprocess.TimeoutExpired("synthetic-child", timeout)
            self.returncode = 0
            return "synthetic output", ""

        def kill(self):
            events.append("kill")
            self.returncode = -9

    child = Child()

    def wait(_child, predicate, description, timeout=30):
        assert _child is child and not https.release.is_set()
        if description == "actual revocation DELETE":
            assert not (control / "request-received").exists()
            if failure in {"request", "cleanup_timeout"}:
                raise AssertionError("No actual request")
            https.received.set()
        else:
            assert (control / "request-received").is_file() and timeout == 5
            if failure == "transfer":
                raise AssertionError("No committed transfer")
            (control / "release-response").touch(exist_ok=False)
        assert predicate()

    times = iter([0, 6 if failure == "slow_transfer" else 1])
    monkeypatch.setattr(native.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(native, "wait_for", wait)
    monkeypatch.setattr(native.subprocess, "Popen", lambda *_, **__: child)
    if failure is None:
        result = native.run_fenced_child(["synthetic-not-executed"], {}, https)
        assert result.returncode == 0 and events == [90]
    else:
        with pytest.raises((AssertionError, native.subprocess.TimeoutExpired)):
            native.run_fenced_child(["synthetic-not-executed"], {}, https)
        assert child.poll() is not None
        if failure == "cleanup_timeout":
            assert events == [30, "kill", 10]
    assert https.release.is_set()
