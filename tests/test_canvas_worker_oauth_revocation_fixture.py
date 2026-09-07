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


@pytest.mark.parametrize("names,reference", [(["a", "a"], {"a": {}}), (["a"], {})])
@pytest.mark.parametrize(
    "kind",
    [
        "oauth-revocation",
        "oauth-revocation-fence",
        "oauth-revocation-patch",
        "oauth-revocation-retry-after",
        "oauth-revocation-backoff",
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
