"""Deadline fixture integrity; these tests are not published/native worker parity."""

import ast
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from copy import deepcopy
from http.client import HTTPSConnection
import importlib
import hashlib
import io
import json
from pathlib import Path
import ssl
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_frozen_deadline_capture_retains_both_controls_and_verified_predicates():
    raw = (ROOT / "contracts/canvas-worker-deadline-oracle.json").read_bytes()
    assert hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest() == (
        "7031a301007f175119566db866b9c418d8f0d04be86212849d0babdd55efe60e"
    )
    reference = json.loads(raw)
    assert reference["schema"] == "marty.canvas-worker-deadline-oracle/v1"
    cases = reference["observations"]
    assert [case["case"] for case in cases] == ["early_release", "deadline_cancel"]
    for index, case in enumerate(cases):
        assert case["schema"] == "marty.canvas-worker-deadline-observation/v1"
        assert [len(state["facts"]) for state in case["completed_read_states"]] == [
            1,
            2,
        ]
        assert len(case["outcome"]["facts"]) == (3 if index == 0 else 2)
        assert case["outcome"]["jobs"][0]["status"] == (
            "succeeded" if index == 0 else "retry"
        )
        for key in (
            "database_and_monotonic_elapsed_agree",
            "first_request_setup_within_age_budget",
            "timing_query_latency_within_budget",
            "last_renewed_lease_still_current_at_outcome",
            "stable_after_interrupt",
            "stable_after_release_and_handler_join",
            "worker_live_and_idle_after_late_response_window",
        ):
            assert case[key] is True
        assert case["deadline_outcome_within_declared_age_bounds"] is (
            None if index == 0 else True
        )
        assert case["committed_prefix_preserved_on_deadline"] is (
            None if index == 0 else True
        )
        assert len(case["requests"]) == 3
        assert case["renewals_observed_while_reads_pending"] == 2
        assert case["completed_reads_released_before_published_http_timeout"] == 2
        assert case["logs_before_interrupt"]["stderr_warning_categories"] == {
            "missing_revocation_profile_service_url": 1,
            "missing_credential_template_service_url": 1,
        }
        assert case["logs_before_interrupt"]["other_output_empty"] is True
        assert case["exit_code_after_interrupt"] == -2


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return (
        importlib.import_module("canvas_worker_deadline_https_fixture"),
        importlib.import_module("run_canvas_worker_deadline_oracle"),
    )


def get(fixture, path):
    client = HTTPSConnection(
        "127.0.0.1",
        fixture.server.server_port,
        context=ssl.create_default_context(cafile=str(fixture.cert)),
        timeout=5,
    )
    try:
        client.request("GET", path)
        response = client.getresponse()
        return response.status, json.loads(response.read())
    finally:
        client.close()


def test_shared_hook_retains_exact_default_thirty_second_wait(modules):
    fixture_module, _ = modules
    calls = []
    fixture = fixture_module.WorkerHttpsFixture()
    fixture.release = SimpleNamespace(
        wait=lambda seconds: calls.append(seconds) or True
    )
    assert fixture.wait_for_response(0, "/unused", {}) is False
    assert calls == []
    assert fixture.wait_for_response(0, "/unused", {"hold_response": True}) is True
    assert calls == [30]


def test_existing_single_response_hold_still_controls_actual_https(modules):
    fixture_module, _ = modules
    with ThreadPoolExecutor(max_workers=1) as clients:
        with fixture_module.WorkerHttpsFixture() as fixture:
            fixture.stage = {
                "hold_response": True,
                "status": 200,
                "body": {"legacy": True},
            }
            pending = clients.submit(get, fixture, "/legacy")
            assert fixture.received.wait(3)
            assert not pending.done()
            fixture.release.set()
            assert pending.result(timeout=3) == (200, {"legacy": True})


@pytest.mark.parametrize("count", [2, 3])
def test_indexed_releases_do_not_open_later_response_and_close_joins_handlers(
    modules, count
):
    fixture_module, _ = modules
    paths = ["/first", "/second", "/third"][:count]
    responses = {path: {"status": 200, "body": {"path": path}} for path in paths}
    with ThreadPoolExecutor(max_workers=3) as clients:
        with fixture_module.DeadlineHttpsFixture(paths, responses) as fixture:
            certificate_root = Path(fixture.certificates.name)
            first = clients.submit(get, fixture, paths[0])
            assert fixture.request_received[0].wait(3)
            second = clients.submit(get, fixture, paths[1])
            assert fixture.request_received[1].wait(3)
            third = clients.submit(get, fixture, paths[2]) if count == 3 else None
            if third is not None:
                assert fixture.request_received[2].wait(3)
                assert not third.done()
            assert not first.done() and not second.done()
            fixture.response_release[0].set()
            assert first.result(timeout=3) == (200, {"path": paths[0]})
            assert not second.done()
            assert fixture.response_unblocked[0].is_set()
            assert not fixture.response_unblocked[1].is_set()
            if third is not None:
                assert not third.done() and not fixture.response_unblocked[2].is_set()
        assert second.result(timeout=3) == (200, {"path": paths[1]})
        if third is not None:
            assert third.result(timeout=3) == (200, {"path": paths[2]})
        assert all(event.is_set() for event in fixture.response_unblocked)
        assert not fixture.thread.is_alive()
        assert not certificate_root.exists()
        assert [item["path"] for item in fixture.requests] == paths
        assert not fixture.failures


@pytest.mark.parametrize("index,path", [(2, "/third"), (0, "/wrong")])
def test_indexed_barrier_rejects_unknown_extra_or_reordered_requests(
    modules, index, path
):
    fixture_module, _ = modules
    fixture = fixture_module.DeadlineHttpsFixture(
        ["/first", "/second"],
        {path: {"status": 200, "body": {}} for path in ("/first", "/second")},
    )
    with pytest.raises(AssertionError):
        fixture.wait_for_response(index, path, fixture.stage)
    assert not any(event.is_set() for event in fixture.request_received)
    fixture.close()


@pytest.mark.parametrize("name", ["early_release", "deadline_cancel"])
def test_two_case_matrix_reuses_real_ordered_fact_requirements_and_fixed_bounds(
    modules, name
):
    _, oracle = modules
    matrix, case, spec, _, queued, responses = oracle.load_case(
        ROOT / "contracts", name
    )
    assert case["name"] == name
    assert [requirement["requirement_id"] for requirement in spec["requirements"]] == [
        "assignment",
        "quiz",
        "module",
    ]
    assert list(responses) == matrix["request_paths"]
    assert "worker-validation-job" in queued["initial_job_seed"]
    assert all(
        value.startswith("SELECT ")
        for key, value in matrix.items()
        if key.endswith("_sql")
    )
    assert "ORDER BY application_id,logical_key" in matrix["effect_rows_sql"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("completed_response_delay_seconds", 1),
        ("completed_response_latest_seconds", 15),
        ("published_http_timeout_seconds", 20),
        ("native_http_timeout_seconds", 15),
        ("post_response_observation_margin_seconds", 0),
        ("timing_bounds", {}),
        ("requirement_ids", ["assignment"]),
        ("environment", {"CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "1"}),
        ("cases", []),
    ],
)
def test_matrix_cannot_shorten_deadline_or_skip_real_read_control(
    modules, monkeypatch, field, value
):
    _, oracle = modules
    original = Path.read_text
    matrix = json.loads(
        (ROOT / "contracts/canvas-worker-deadline-scenarios.json").read_text()
    )
    matrix[field] = value

    def read(path, *args, **kwargs):
        return (
            json.dumps(matrix)
            if path.name == "canvas-worker-deadline-scenarios.json"
            else original(path, *args, **kwargs)
        )

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(AssertionError):
        oracle.load_case(ROOT / "contracts", "deadline_cancel")


@pytest.mark.parametrize(
    "contents",
    [b"synthetic-private-token", b"arbitrary-private-log", b"x" * 65537],
    ids=["token", "unknown-log", "oversized"],
)
def test_actual_log_guard_rejects_payloads_without_echoing_them(modules, contents):
    _, oracle = modules
    with pytest.raises(AssertionError) as caught:
        oracle.output_capture.observed_log_profile(
            io.BytesIO(), io.BytesIO(contents), "synthetic-private-token"
        )
    assert "arbitrary-private-log" not in str(caught.value)
    assert "synthetic-private-token" not in str(caught.value)


@pytest.mark.parametrize("mutation", [None, "empty", "duplicate", "stdout", "extra"])
def test_known_log_profile_is_observed_not_synthesized(modules, mutation):
    _, oracle = modules
    contents = (
        "WARNING:issuance.infrastructure.api.routes:REVOCATION_PROFILE_SERVICE_URL not set — revocation calls will fail\n"
        "WARNING:issuance.infrastructure.api.routes:CREDENTIAL_TEMPLATE_SERVICE_URL not set — template calls will fail\n"
    ).encode()
    stdout = b""
    if mutation == "empty":
        contents = b""
    elif mutation == "duplicate":
        contents += contents
    elif mutation == "stdout":
        stdout = contents
    elif mutation == "extra":
        contents += b"WARNING:other:unexpected\n"
    if mutation is not None:
        with pytest.raises(AssertionError):
            oracle.output_capture.observed_log_profile(
                io.BytesIO(stdout), io.BytesIO(contents), "synthetic-token"
            )
        return
    assert oracle.output_capture.observed_log_profile(
        io.BytesIO(stdout), io.BytesIO(contents), "synthetic-token"
    ) == {
        "stdout_empty": True,
        "stderr_warning_categories": {
            "missing_revocation_profile_service_url": 1,
            "missing_credential_template_service_url": 1,
        },
        "other_output_empty": True,
    }


@pytest.mark.parametrize(
    "material",
    [
        b"synthetic-startup-api-key",
        b"synthetic-startup-hmac-key",
        b"synthetic-local-only",
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ],
    ids=["api-key", "hmac-key", "database-password", "master-key"],
)
def test_log_diagnostics_never_bypass_other_synthetic_secrets(modules, material):
    _, oracle = modules
    with pytest.raises(AssertionError) as caught:
        oracle.output_capture.observed_log_profile(
            io.BytesIO(), io.BytesIO(material), "synthetic-token"
        )
    assert type(caught.value) is AssertionError
    assert material.decode() not in str(caught.value)


def test_log_diagnostic_is_fixed_categories_and_counts_only(modules):
    _, oracle = modules
    contents = (
        b"INFO:__main__:private worker message\n"
        b"INFO:httpx:private URL and payload\n"
        b"WARNING:private-logger:private warning\n"
        b"ERROR:private-logger:private error\n"
        b"Traceback (most recent call last):\n"
        b"private unformatted output\n"
    )
    with pytest.raises(AssertionError) as caught:
        oracle.output_capture.observed_log_profile(
            io.BytesIO(), io.BytesIO(contents), "synthetic-token"
        )
    assert type(caught.value).__name__ == (
        "DeadlineLogCountsStdoutLines0Info0Warning0Error0Other0Worker0Http0Traceback0"
        "MissingRevocationUrl0MissingTemplateUrl0"
        "StderrLines6Info2Warning1Error1Other2Worker1Http1Traceback1"
        "MissingRevocationUrl0MissingTemplateUrl0"
    )
    assert str(caught.value) == ""


@pytest.mark.parametrize("mutation", [None, "logger", "level", "suffix"])
def test_source_warning_classification_requires_exact_whole_line(modules, mutation):
    _, oracle = modules
    line = (
        "WARNING:issuance.infrastructure.api.routes:"
        "REVOCATION_PROFILE_SERVICE_URL not set — revocation calls will fail"
    )
    if mutation == "logger":
        line = line.replace("issuance.infrastructure.api.routes", "other")
    elif mutation == "level":
        line = line.replace("WARNING:", "INFO:")
    elif mutation == "suffix":
        line += " private payload"
    counts = oracle.output_capture.log_counts(line.encode())
    assert counts["MissingRevocationUrl"] == int(mutation is None)
    assert counts["MissingTemplateUrl"] == 0
    with pytest.raises(AssertionError):
        oracle.output_capture.observed_log_profile(
            io.BytesIO(), io.BytesIO(line.encode()), "synthetic-token"
        )


def timing_sample(age, before=None, after=None):
    return {
        "row": {
            "id": "worker-validation-job",
            "attempt_count": 1,
            "started_at": "synthetic-start",
            "age_seconds": age,
        },
        "before": 99 + age if before is None else before,
        "after": 99.1 + age if after is None else after,
    }


@pytest.mark.parametrize("age,accepted", [(0, True), (2, True), (2.001, False)])
def test_initial_job_age_setup_budget_exact_boundaries(modules, age, accepted):
    _, oracle = modules
    matrix, *_ = oracle.load_case(ROOT / "contracts", "deadline_cancel")
    if accepted:
        oracle.assert_job_timing(timing_sample(age), matrix["timing_bounds"])
    else:
        with pytest.raises(AssertionError):
            oracle.assert_job_timing(timing_sample(age), matrix["timing_bounds"])


@pytest.mark.parametrize("age", [25, 29.499, 29.5, 30, 33, 33.001, 35])
def test_deadline_age_rejects_premature_and_late_timer_with_fixed_tolerance(
    modules, age
):
    _, oracle = modules
    matrix, *_ = oracle.load_case(ROOT / "contracts", "deadline_cancel")
    args = (timing_sample(age), matrix["timing_bounds"], timing_sample(1))
    if 29.5 <= age <= 33:
        oracle.assert_job_timing(*args, deadline=True)
    else:
        with pytest.raises(AssertionError):
            oracle.assert_job_timing(*args, deadline=True)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "nan",
        "infinite",
        "negative",
        "boolean",
        "missing-start",
        "identity",
        "attempt",
        "changed-start",
        "slow-query",
        "reverse-query",
        "clock-jump",
    ],
)
def test_timing_evidence_rejects_invalid_or_inconsistent_samples(modules, mutation):
    _, oracle = modules
    matrix, *_ = oracle.load_case(ROOT / "contracts", "deadline_cancel")
    sample = timing_sample(30)
    if mutation == "missing":
        sample["row"].pop("age_seconds")
    elif mutation in ("nan", "infinite", "negative", "boolean"):
        sample["row"]["age_seconds"] = {
            "nan": float("nan"),
            "infinite": float("inf"),
            "negative": -1,
            "boolean": True,
        }[mutation]
    elif mutation == "missing-start":
        sample["row"]["started_at"] = None
    elif mutation == "identity":
        sample["row"]["id"] = "wrong-job"
    elif mutation == "attempt":
        sample["row"]["attempt_count"] = 2
    elif mutation == "changed-start":
        sample["row"]["started_at"] = "different-start"
    elif mutation == "slow-query":
        sample["after"] = sample["before"] + 1.001
    elif mutation == "reverse-query":
        sample["after"] = sample["before"] - 0.001
    elif mutation == "clock-jump":
        sample["before"] += 2
        sample["after"] += 2
    with pytest.raises(AssertionError):
        oracle.assert_job_timing(
            sample, matrix["timing_bounds"], timing_sample(1), deadline=True
        )


@pytest.mark.parametrize("latency,accepted", [(1, True), (1.001, False)])
def test_timing_query_latency_exact_boundary(modules, latency, accepted):
    _, oracle = modules
    matrix, *_ = oracle.load_case(ROOT / "contracts", "deadline_cancel")
    sample = timing_sample(1, before=100, after=100 + latency)
    if accepted:
        oracle.assert_job_timing(sample, matrix["timing_bounds"])
    else:
        with pytest.raises(AssertionError):
            oracle.assert_job_timing(sample, matrix["timing_bounds"])


@pytest.mark.parametrize(
    "drift,accepted", [(-0.5, True), (0.5, True), (-0.501, False), (0.501, False)]
)
def test_timing_clock_agreement_exact_boundary(modules, drift, accepted):
    _, oracle = modules
    matrix, *_ = oracle.load_case(ROOT / "contracts", "deadline_cancel")
    initial = timing_sample(1, before=100, after=100)
    terminal = timing_sample(30, before=129 + drift, after=129 + drift)
    if accepted:
        oracle.assert_job_timing(
            terminal, matrix["timing_bounds"], initial, deadline=True
        )
    else:
        with pytest.raises(AssertionError):
            oracle.assert_job_timing(
                terminal, matrix["timing_bounds"], initial, deadline=True
            )


def test_live_child_log_writes_cannot_be_overwritten_by_observer_seek(
    modules, tmp_path
):
    _, oracle = modules
    with ExitStack() as owner:
        writer, reader = oracle.output_capture.owned_log_streams(owner, tmp_path)
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys; print('first', flush=True); "
                "sys.stdin.readline(); print('second', flush=True)",
            ],
            stdin=subprocess.PIPE,
            stdout=writer,
            stderr=subprocess.DEVNULL,
        )
        try:
            # The read may be translated differently by the child on Windows;
            # normalize line endings only in this harmless synthetic regression.
            def first_visible():
                reader.seek(0)
                return reader.read().splitlines() == [b"first"]

            oracle.wait_for(first_visible, 5, "harmless child first write", child)
            reader.seek(0)  # precisely the offset that formerly risked overwrite
            child.stdin.write(b"continue\n")
            child.stdin.flush()
            assert child.wait(timeout=5) == 0
            reader.seek(0)
            assert reader.read().splitlines() == [b"first", b"second"]
        finally:
            child.stdin.close()
            oracle.finish_worker(child)


def test_log_read_is_bounded_even_if_child_grows_file_after_size_check(modules):
    _, oracle = modules

    class GrowingOutput(io.BytesIO):
        def seek(self, offset, whence=0):
            position = super().seek(offset, whence)
            # Simulate a writer appending immediately after the observed size.
            return 0 if whence == 2 else position

        def read(self, size=-1):
            assert size == 65537, "Observer must not perform an unbounded read"
            return super().read(size)

    with pytest.raises(AssertionError, match="Unexpectedly large owned worker output"):
        oracle.output_capture.observed_log_profile(
            GrowingOutput(b"x" * 65537), io.BytesIO(), "synthetic-unprinted-token"
        )


def test_handler_cleanup_does_not_remove_live_output_files(modules, tmp_path):
    fixture_module, oracle = modules
    with ExitStack() as owner:
        fixture = owner.enter_context(fixture_module.WorkerHttpsFixture())
        writer, reader = oracle.output_capture.owned_log_streams(owner, tmp_path)
        writer.write(b"synthetic-owned-output")
        writer.flush()
        fixture.close()
        reader.seek(0)
        assert reader.read(64) == b"synthetic-owned-output"
        assert Path(writer.name).is_file()
    assert writer.closed and reader.closed


def test_failed_fact_assertion_exposes_counts_not_payloads(modules):
    _, oracle = modules
    oracle.assert_fact_count({"facts": ["synthetic-private"]}, 1)
    with pytest.raises(AssertionError) as caught:
        oracle.assert_fact_count({"facts": ["synthetic-private"]}, 2)
    assert type(caught.value).__name__ == "DeadlineObservedFacts1Expected2"
    assert str(caught.value) == ""


@pytest.mark.parametrize(
    "mutation", [None, "extra", "order", "authorization", "method", "failure"]
)
def test_transport_comparison_is_exact_and_rejects_extra_work(modules, mutation):
    _, oracle = modules
    matrix, _, spec, *_ = oracle.load_case(ROOT / "contracts", "deadline_cancel")
    requests = [
        {
            "method": "GET",
            "path": path,
            "authorization": f"Bearer {spec['token']}",
            "accept": "application/json",
        }
        for path in matrix["request_paths"]
    ]
    fixture = SimpleNamespace(requests=deepcopy(requests), failures=[])
    if mutation == "extra":
        fixture.requests.append(deepcopy(requests[0]))
    elif mutation == "order":
        fixture.requests.reverse()
    elif mutation in {"authorization", "method"}:
        fixture.requests[0][mutation] = "synthetic-invalid"
    elif mutation == "failure":
        fixture.failures.append("synthetic-handler-failure")
    if mutation is None:
        oracle.assert_requests(fixture, matrix, spec["token"])
    else:
        with pytest.raises(AssertionError):
            oracle.assert_requests(fixture, matrix, spec["token"])


def test_runner_seeds_one_job_before_start_and_never_rewrites_live_rows():
    source = (ROOT / "scripts/run_canvas_worker_deadline_oracle.py").read_text()
    tree = ast.parse(source)
    starts = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "start_worker"
    ]
    writes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "exec_driver_sql"
    ]
    assert len(starts) == len(writes) == 1
    assert writes[0].lineno < starts[0].lineno
    assert ast.unparse(writes[0].args[0]) == "queued['initial_job_seed']"
    assert "subprocess.PIPE" not in source
    assert "committed_effect_rows" in source
    assert "while time.monotonic() < late_window_end" in source
