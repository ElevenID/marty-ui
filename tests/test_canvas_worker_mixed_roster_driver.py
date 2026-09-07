"""Synthetic parent orchestration integrity, not native-worker qualification."""

from copy import deepcopy
from contextlib import contextmanager
import importlib
import json
from pathlib import Path
import tempfile
from threading import Lock
import sys
import time
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
TRACES = ("requests", "token_scopes", "signer_requests", "signer_operations")


@pytest.fixture
def native(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    module = importlib.import_module("test_canvas_worker_mixed_roster_https")
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="linux"))
    return module


@pytest.fixture
def corpus():
    return tuple(
        json.loads(
            (ROOT / "contracts" / f"canvas-worker-mixed-roster-{name}.json").read_text()
        )
        for name in ("scenarios", "oracle")
    )


def test_run_routes_only_the_exact_frozen_case(native, corpus, monkeypatch):
    matrix, reference = corpus
    calls = []
    monkeypatch.setattr(native, "run_case", lambda *args: calls.append(args))
    native.run("synthetic-worker")
    assert calls == [("synthetic-worker", matrix, matrix["cases"][0], reference)]


@pytest.mark.parametrize(
    "mutation",
    [
        "empty-cases",
        "duplicate-cases",
        "wrong-case",
        "renamed-case",
        "empty-stages",
        "duplicate-stages",
        "matching-truncation",
        "missing-observation",
        "extra-observation",
        "reordered-observation",
    ],
)
def test_invalid_matrix_fails_before_fixture_or_process(
    native, corpus, monkeypatch, mutation
):
    matrix, reference = corpus
    if mutation == "empty-cases":
        matrix["cases"] = []
    elif mutation == "duplicate-cases":
        matrix["cases"].append(deepcopy(matrix["cases"][0]))
    elif mutation == "wrong-case":
        reference["case"] = "not-the-frozen-case"
    elif mutation == "renamed-case":
        matrix["cases"][0]["name"] = reference["case"] = "not-the-frozen-case"
    elif mutation == "empty-stages":
        matrix["cases"][0]["stages"] = []
    elif mutation == "duplicate-stages":
        matrix["cases"][0]["stages"][1] = deepcopy(matrix["cases"][0]["stages"][0])
    elif mutation == "matching-truncation":
        matrix["cases"][0]["stages"].pop()
        reference["observations"].pop()
    elif mutation == "missing-observation":
        reference["observations"].pop()
    elif mutation == "extra-observation":
        reference["observations"].append(deepcopy(reference["observations"][-1]))
    elif mutation == "reordered-observation":
        reference["observations"][0], reference["observations"][1] = (
            reference["observations"][1],
            reference["observations"][0],
        )
    inputs = iter(map(json.dumps, (matrix, reference)))
    monkeypatch.setattr(Path, "read_text", lambda *_: next(inputs))
    monkeypatch.setattr(
        native,
        "run_case",
        lambda *_: pytest.fail("Invalid corpus must not start a fixture or child"),
    )
    with pytest.raises(AssertionError):
        native.run("must-not-launch")


@pytest.mark.parametrize("field", [None, *TRACES, "failures"])
def test_transport_comparison_requires_all_four_exact_frozen_traces(
    native, corpus, field
):
    _, reference = corpus
    observation = reference["observations"][0]
    fixture = SimpleNamespace(
        **{key: deepcopy(observation[key]) for key in TRACES}, failures=[]
    )
    if field is not None:
        getattr(fixture, field).append("unexpected-synthetic-observation")
        with pytest.raises(AssertionError):
            native.assert_transport(fixture, observation)
    else:
        snapshot = native.assert_transport(fixture, observation)
        assert snapshot == {key: observation[key] for key in TRACES}
        fixture.requests.clear()
        assert snapshot["requests"] == observation["requests"]


@pytest.mark.parametrize(
    "failure",
    [
        None,
        "wrong-trace",
        "late-between-stages",
        "child-exit",
        "marker-timeout",
        "final-exit",
        "final-timeout",
        "cleanup-timeout",
        "late-exit-request",
        "late-shutdown-request",
    ],
)
def test_parent_orders_markers_compares_before_advancing_and_cleans_owned_resources(
    native, corpus, monkeypatch, tmp_path, failure
):
    matrix, reference = corpus
    events, fixtures, children, captures = [], [], [], []
    actual_touch = Path.touch
    actual_compare = native.assert_transport

    class Fixture:
        def __init__(self, actual_matrix):
            assert actual_matrix == matrix
            self.failures = []
            self.stage_index = -1
            self.closed = False
            self.server = SimpleNamespace(
                RequestHandlerClass=SimpleNamespace(request_observation_lock=Lock())
            )
            self.signer_server = SimpleNamespace(
                RequestHandlerClass=SimpleNamespace(request_observation_lock=Lock())
            )
            for field in TRACES:
                setattr(self, field, [])

        def __enter__(self):
            self.certificates = tempfile.TemporaryDirectory(
                dir=tmp_path, prefix="owned-driver-"
            )
            self.cert = Path(self.certificates.name) / "synthetic-cert"
            self.origin = "https://127.0.0.1:1"
            self.signer_origin = "http://127.0.0.1:2/internal/signing-keys"
            fixtures.append(self)
            return self

        def set_stage(self, stage):
            index = self.stage_index + 1
            assert stage == matrix["cases"][0]["stages"][index]
            # These are real observation locks: neither recorder may append
            # between the previous comparison, ledger clear and ready marker.
            assert self.server.RequestHandlerClass.request_observation_lock.locked()
            assert (
                self.signer_server.RequestHandlerClass.request_observation_lock.locked()
            )
            if index:
                assert events[-1] == ("compare", index - 1)
            events.append(("stage", index))
            self.stage_index = index
            for field in TRACES:
                setattr(self, field, [])

        def __exit__(self, *_):
            events.append(("close", self.stage_index))
            if failure == "late-shutdown-request":
                self.requests.append("unexpected-late-shutdown")
            self.closed = True
            self.certificates.cleanup()

    class Child:
        returncode = None

        def __init__(self):
            self.communications = []
            self.killed = False

        def poll(self):
            return self.returncode

        def communicate(self, timeout):
            self.communications.append(timeout)
            if not self.killed and (
                failure == "cleanup-timeout"
                or (failure == "final-timeout" and len(self.communications) == 1)
            ):
                raise native.subprocess.TimeoutExpired("synthetic-child", timeout)
            if failure == "late-exit-request" and len(self.communications) == 1:
                fixtures[0].requests.append("unexpected-late-exit")
            if not self.killed:
                self.returncode = 1 if failure == "final-exit" else 0
            return "synthetic-stdout", "synthetic-stderr"

        def kill(self):
            self.killed = True
            self.returncode = -9

    def launch(command, **options):
        fixture = fixtures[0]
        assert command == [
            "synthetic-worker",
            "worker_mixed_roster_native_child",
            "--exact",
            "--nocapture",
        ]
        environment = options["env"]
        assert environment["MARTY_CANVAS_WORKER_MIXED_ROSTER_CASE"] == reference["case"]
        assert (
            environment["MARTY_CANVAS_WORKER_MIXED_ROSTER_NATIVE_ORIGIN"]
            == fixture.origin
        )
        assert (
            environment["MARTY_CANVAS_WORKER_MIXED_ROSTER_SIGNER_ORIGIN"]
            == fixture.signer_origin
        )
        assert environment["SSL_CERT_FILE"] == str(fixture.cert)
        assert Path(environment["SSL_CERT_DIR"]).is_dir()
        assert list(Path(environment["SSL_CERT_DIR"]).iterdir()) == []
        assert environment["MARTY_CANVAS_WORKER_MIXED_ROSTER_CONTROL"] == str(
            Path(fixture.certificates.name) / "native-control"
        )
        assert options["stdin"] == native.subprocess.DEVNULL
        for field in ("stdout", "stderr"):
            capture = options[field]
            assert capture != native.subprocess.PIPE
            assert capture.seekable() and capture.writable() and not capture.closed
            captures.append(capture)
        assert options["text"] is True
        child = Child()
        children.append(child)
        return child

    def touch(path, *args, **kwargs):
        assert kwargs == {"exist_ok": False}
        kind, number = path.name.rsplit("-", 1)
        index = int(number)
        assert kind in {"stage-ready", "stage-ack"}
        expected_previous = "stage" if kind == "stage-ready" else "compare"
        assert events[-1] == (expected_previous, index)
        if kind == "stage-ready":
            assert fixtures[
                0
            ].server.RequestHandlerClass.request_observation_lock.locked()
            assert fixtures[
                0
            ].signer_server.RequestHandlerClass.request_observation_lock.locked()
        actual_touch(path, *args, **kwargs)
        events.append((kind, index))
        if failure == "late-between-stages" and kind == "stage-ack" and index == 0:
            fixtures[0].requests.append("unexpected-between-stages")

    def wait(child, path, timeout):
        assert child is children[0]
        index = fixtures[0].stage_index
        assert 0 < timeout <= native.STAGE_TIMEOUT_SECONDS
        assert path.name == f"stage-done-{index}"
        assert (path.parent / f"stage-ready-{index}").is_file()
        assert not (path.parent / f"stage-ack-{index}").exists()
        if index == 1 and failure in {
            "child-exit",
            "marker-timeout",
            "cleanup-timeout",
        }:
            if failure == "child-exit":
                child.returncode = 1
            raise AssertionError("synthetic stage did not complete")
        for field in TRACES:
            setattr(
                fixtures[0], field, deepcopy(reference["observations"][index][field])
            )
        if failure == "wrong-trace" and index == 1:
            fixtures[0].token_scopes.append("unexpected-scope")
        actual_touch(path, exist_ok=False)
        events.append(("done", index))

    def compare(fixture, observation):
        if events[-1][0] == "stage-ack" and events[-1][1] < 6:
            assert fixture.server.RequestHandlerClass.request_observation_lock.locked()
            assert fixture.signer_server.RequestHandlerClass.request_observation_lock.locked()
        value = actual_compare(fixture, observation)
        index = reference["observations"].index(observation)
        events.append(("compare", index))
        return value

    monkeypatch.setattr(native, "MixedRosterHttpsFixture", Fixture)
    monkeypatch.setattr(native.subprocess, "Popen", launch)
    monkeypatch.setattr(native, "wait_marker", wait)
    monkeypatch.setattr(native, "assert_transport", compare)
    monkeypatch.setattr(Path, "touch", touch)
    args = ("synthetic-worker", matrix, matrix["cases"][0], reference)
    if failure is None:
        snapshots = native.run_case(*args)
        assert snapshots == [
            {field: observation[field] for field in TRACES}
            for observation in reference["observations"]
        ]
        assert events[-2:] == [("close", 6), ("compare", 6)]
        assert [index for kind, index in events if kind == "stage-ack"] == list(
            range(7)
        )
    else:
        with pytest.raises((AssertionError, native.subprocess.TimeoutExpired)):
            native.run_case(*args)
    assert fixtures[0].closed
    assert len(captures) == 2 and all(capture.closed for capture in captures)
    assert not Path(fixtures[0].certificates.name).exists()
    assert children[0].poll() is not None
    assert children[0].killed is (failure == "cleanup-timeout")
    if failure == "cleanup-timeout":
        assert children[0].communications == [60, 10]
    if failure == "final-timeout":
        assert (
            len(children[0].communications) == 2
            and children[0].communications[-1] == 60
        )
    if failure == "late-between-stages":
        assert fixtures[0].stage_index == 0
    if failure in {"wrong-trace", "child-exit", "marker-timeout", "cleanup-timeout"}:
        assert fixtures[0].stage_index == 1
        assert ("stage-ack", 1) not in events


@pytest.mark.parametrize("status", [0, 1])
def test_wait_marker_rejects_child_exit_before_done(native, tmp_path, status):
    child = SimpleNamespace(poll=lambda: status, communicate=lambda **_: ("", ""))
    with pytest.raises(AssertionError, match="exited before"):
        native.wait_marker(child, tmp_path / "stage-done-0", 1)


def test_wait_marker_requires_marker_before_deadline(native, monkeypatch, tmp_path):
    child = SimpleNamespace(poll=lambda: None)
    ticks = iter([0, 2])
    monkeypatch.setattr(native.time, "monotonic", lambda: next(ticks))
    with pytest.raises(AssertionError, match="Timed out"):
        native.wait_marker(child, tmp_path / "stage-done-0", 1)


def test_remaining_timeout_never_exceeds_case_budget(native, monkeypatch):
    monkeypatch.setattr(native.time, "monotonic", lambda: 100)
    assert native.remaining_timeout(110, 120) == 10
    assert native.remaining_timeout(300, 120) == 120
    with pytest.raises(AssertionError, match="total bound"):
        native.remaining_timeout(100, 120)


def test_real_chatty_child_fails_promptly_with_bounded_tails_and_cleanup(
    native, corpus, monkeypatch, tmp_path
):
    # A real harmless local Python process replaces only the Rust executable.
    # No provider/signer server, database, credentials or network is involved.
    matrix, reference = corpus
    children, captures, roots, stages = [], [], [], []
    actual_popen = native.subprocess.Popen
    code = (
        "import sys; "
        "sys.stdout.write('synthetic-stdout-prefix\\n' + 'O' * (256 * 1024) + '\\nSYNTHETIC_STDOUT_TAIL\\n'); "
        "sys.stdout.flush(); "
        "sys.stderr.write('synthetic-stderr-prefix\\n' + 'E' * (256 * 1024) + '\\nSYNTHETIC_STDERR_TAIL\\n'); "
        "sys.stderr.flush(); sys.exit(1)"
    )

    @contextmanager
    def fixture(actual_matrix):
        assert actual_matrix == matrix
        with tempfile.TemporaryDirectory(
            dir=tmp_path, prefix="owned-output-regression-"
        ) as directory:
            root = Path(directory)
            roots.append(root)
            yield SimpleNamespace(
                certificates=SimpleNamespace(name=directory),
                cert=root / "synthetic-unused-cert",
                origin="https://127.0.0.1:1",
                signer_origin="http://127.0.0.1:2/internal/signing-keys",
                failures=[],
                **{field: [] for field in TRACES},
                server=SimpleNamespace(
                    RequestHandlerClass=SimpleNamespace(request_observation_lock=Lock())
                ),
                signer_server=SimpleNamespace(
                    RequestHandlerClass=SimpleNamespace(request_observation_lock=Lock())
                ),
                set_stage=lambda stage: stages.append(stage["name"]),
            )

    def launch(command, **options):
        assert command == [
            "synthetic-worker",
            "worker_mixed_roster_native_child",
            "--exact",
            "--nocapture",
        ]
        captures.extend([options["stdout"], options["stderr"]])
        child = actual_popen([sys.executable, "-c", code], **options)
        children.append(child)
        return child

    monkeypatch.setattr(native, "MixedRosterHttpsFixture", fixture)
    monkeypatch.setattr(native.subprocess, "Popen", launch)
    monkeypatch.setattr(native, "STAGE_TIMEOUT_SECONDS", 10)
    monkeypatch.setattr(native, "CASE_TIMEOUT_SECONDS", 15)
    started = time.monotonic()
    try:
        with pytest.raises(AssertionError) as caught:
            native.run_case("synthetic-worker", matrix, matrix["cases"][0], reference)
        elapsed = time.monotonic() - started
        assert elapsed < 5, (
            "Undrained output must not delay failure until the stage timeout"
        )
        assert len(children) == 1 and children[0].poll() == 1
        assert stages == [matrix["cases"][0]["stages"][0]["name"]]
        diagnostics = "\n".join(getattr(caught.value, "__notes__", []))
        assert "SYNTHETIC_STDOUT_TAIL" in diagnostics
        assert "SYNTHETIC_STDERR_TAIL" in diagnostics
        assert "synthetic-stdout-prefix" not in diagnostics
        assert "synthetic-stderr-prefix" not in diagnostics
        assert len(diagnostics.encode()) <= 2 * native.OUTPUT_TAIL_BYTES + 1024
        assert "Timed out" not in str(caught.value)
        assert len(captures) == 2 and all(capture.closed for capture in captures)
        assert all(not root.exists() for root in roots)
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
