"""Synthetic parent protocol tests; not actual native-worker qualification."""

from copy import deepcopy
import importlib
import json
from pathlib import Path
import sys
import tempfile
from threading import Event
import time
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def native(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("test_canvas_worker_deadline_https")


@pytest.fixture
def corpus():
    return tuple(
        json.loads(
            (ROOT / "contracts" / f"canvas-worker-deadline-{name}.json").read_text()
        )
        for name in ("scenarios", "oracle")
    )


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "empty",
        "duplicate",
        "renamed",
        "missing-reference",
        "reordered-reference",
        "missing-request",
        "extra-request",
    ],
)
def test_exact_two_case_three_read_matrix_is_mandatory(native, corpus, mutation):
    matrix, reference = corpus
    if mutation == "empty":
        matrix["cases"] = []
        reference["observations"] = []
    elif mutation == "duplicate":
        matrix["cases"][1] = deepcopy(matrix["cases"][0])
    elif mutation == "renamed":
        matrix["cases"][0]["name"] = reference["observations"][0]["case"] = (
            "unqualified"
        )
    elif mutation == "missing-reference":
        reference["observations"].pop()
    elif mutation == "reordered-reference":
        reference["observations"].reverse()
    elif mutation == "missing-request":
        reference["observations"][0]["requests"].pop()
    elif mutation == "extra-request":
        reference["observations"][0]["requests"].append(
            deepcopy(reference["observations"][0]["requests"][0])
        )
    if mutation is None:
        native.validate_matrix(matrix, reference)
    else:
        with pytest.raises(AssertionError):
            native.validate_matrix(matrix, reference)


@pytest.mark.parametrize("status", [0, 1])
def test_marker_wait_rejects_early_child_exit_without_output(native, tmp_path, status):
    child = SimpleNamespace(poll=lambda: status)
    with pytest.raises(AssertionError):
        native.wait_for(
            child, (tmp_path / "committed-prefix").is_file, 1, "committed-prefix"
        )


@pytest.mark.parametrize("allow_exited,status", [(False, None), (True, 0)])
def test_late_ready_marker_cannot_bypass_wait_budget(
    native, monkeypatch, allow_exited, status
):
    ticks = iter([0.0, 2.0])
    monkeypatch.setattr(
        native,
        "time",
        SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda *_: None),
    )
    with pytest.raises(AssertionError):
        native.wait_for(
            SimpleNamespace(poll=lambda: status),
            lambda: True,
            1,
            "child-done",
            allow_exited=allow_exited,
        )


def test_marker_wait_requires_expected_file_before_bound(native, monkeypatch, tmp_path):
    ticks = iter([0.0, 2.0, 2.0])
    monkeypatch.setattr(
        native,
        "time",
        SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda *_: None),
    )
    with pytest.raises(AssertionError):
        native.wait_for(
            SimpleNamespace(poll=lambda: None),
            (tmp_path / "committed-prefix").is_file,
            1,
            "committed-prefix",
        )


@pytest.mark.parametrize(
    "mutation",
    [None, "missing-known", "future-renewal", "premature-done", "directory", "unknown"],
)
def test_control_inventory_rejects_missing_and_premature_markers(
    native, tmp_path, mutation
):
    known = {"request-received-0"}
    (tmp_path / "request-received-0").touch()
    if mutation == "missing-known":
        (tmp_path / "request-received-0").unlink()
    elif mutation == "future-renewal":
        (tmp_path / "renewal-observed-1").touch()
    elif mutation == "premature-done":
        (tmp_path / "child-done").touch()
    elif mutation == "directory":
        (tmp_path / "renewal-observed-0").mkdir()
    elif mutation == "unknown":
        (tmp_path / "private-sentinel").touch()
    else:
        (tmp_path / "renewal-observed-0").touch()
    if mutation is None:
        native.assert_control(tmp_path, known, pending="renewal-observed-0")
    else:
        with pytest.raises(AssertionError) as caught:
            native.assert_control(tmp_path, known, pending="renewal-observed-0")
        assert "private-sentinel" not in str(caught.value)


def test_parent_and_child_markers_cannot_be_consumed_twice(native, tmp_path):
    known = set()
    native.write_marker(tmp_path, known, "request-received-0")
    with pytest.raises(AssertionError, match="Duplicate"):
        native.write_marker(tmp_path, known, "request-received-0")
    (tmp_path / "renewal-observed-0").touch()
    child = SimpleNamespace(poll=lambda: None)
    native.receive_marker(child, tmp_path, known, "renewal-observed-0", 1)
    with pytest.raises(AssertionError, match="Duplicate"):
        native.receive_marker(child, tmp_path, known, "renewal-observed-0", 1)


@pytest.mark.parametrize("case_name", ["early_release", "deadline_cancel"])
def test_run_routes_only_the_requested_exact_frozen_control(
    native, corpus, monkeypatch, case_name
):
    matrix, reference = corpus
    _, _, responses = native.load_inputs(ROOT)
    calls = []
    monkeypatch.setattr(native, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(native, "run_case", lambda *args: calls.append(args))
    native.run("synthetic", case_name)
    assert calls == [
        ("synthetic", matrix, case, observation, responses)
        for case, observation in zip(
            matrix["cases"], reference["observations"], strict=True
        )
        if case["name"] == case_name
    ]


@pytest.mark.parametrize("case_name", ["", "unknown", "early_release deadline_cancel"])
def test_run_rejects_unknown_case_before_launch(native, monkeypatch, case_name):
    monkeypatch.setattr(native, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        native, "run_case", lambda *_: pytest.fail("Invalid case launched child")
    )
    with pytest.raises(AssertionError):
        native.run("synthetic", case_name)


@pytest.mark.parametrize(
    "status,value,allowed,valid",
    [
        (0, True, False, False),
        (1, True, True, False),
        (0, False, True, False),
        (0, True, True, True),
        (None, True, False, True),
    ],
)
def test_only_final_success_marker_can_allow_an_already_exited_child(
    native, status, value, allowed, valid
):
    args = (SimpleNamespace(poll=lambda: status), lambda: value, 1, "child-done")
    if valid:
        assert native.wait_for(*args, allow_exited=allowed) is True
    else:
        with pytest.raises(AssertionError):
            native.wait_for(*args, allow_exited=allowed)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_wait_budget_never_polls_child_or_predicate(native, timeout):
    child = SimpleNamespace(poll=lambda: pytest.fail("Invalid wait polled child"))
    with pytest.raises(AssertionError, match="budget"):
        native.wait_for(
            child, lambda: pytest.fail("Invalid wait ran predicate"), timeout, "owned"
        )


@pytest.mark.parametrize(
    "field", [None, "method", "path", "authorization", "accept", "extra", "failure"]
)
def test_transcript_comparison_is_exact_and_never_echoes_values(native, corpus, field):
    _, reference = corpus
    observation = reference["observations"][0]
    fixture = SimpleNamespace(requests=deepcopy(observation["requests"]), failures=[])
    if field is None:
        native.assert_requests(fixture, observation)
        return
    if field == "extra":
        fixture.requests.append({"private-sentinel": True})
    elif field == "failure":
        fixture.failures.append("private-sentinel")
    else:
        fixture.requests[0][field] = "private-sentinel"
    with pytest.raises(AssertionError) as caught:
        native.assert_requests(fixture, observation)
    assert "private-sentinel" not in str(caught.value)


@pytest.mark.parametrize("case_name", ["early_release", "deadline_cancel"])
@pytest.mark.parametrize(
    "failure",
    [
        None,
        "wrong-request",
        "missing-renewal",
        "premature-marker",
        "early-child-exit",
        "late-request",
        "handler-not-unblocked",
        "late-shutdown-request",
        "cleanup-timeout",
        "cleanup-error",
    ],
)
def test_ordered_three_read_protocol_and_cleanup(
    native, corpus, monkeypatch, tmp_path, case_name, failure
):
    matrix, reference = corpus
    case = next(case for case in matrix["cases"] if case["name"] == case_name)
    observation = next(
        item for item in reference["observations"] if item["case"] == case_name
    )
    _, _, responses = native.load_inputs(ROOT)
    clock = SimpleNamespace(now=100.0)
    events, fixtures, children, captures, roots = [], [], [], [], []
    real_wait = native.wait_for

    class Release(Event):
        def __init__(self, fixture, index):
            super().__init__()
            self.fixture, self.index = fixture, index

        def set(self):
            if self.is_set():
                return
            super().set()
            fixture, index = self.fixture, self.index
            if fixture.closing:
                fixture.response_unblocked[index].set()
                return
            events.append(("release", index))
            if not (failure == "handler-not-unblocked" and index == 2):
                fixture.response_unblocked[index].set()
            if index < 2:
                assert (roots[0] / f"renewal-observed-{index}").is_file()
                assert 11 <= clock.now - fixture.received_at[index] < 14
                fixture.receive(index + 1)
            else:
                required = (
                    "committed-prefix"
                    if case_name == "early_release"
                    else "outcome-observed"
                )
                assert (roots[0] / required).is_file()

    class Fixture:
        def __init__(self, paths, actual_responses):
            assert paths == matrix["request_paths"] and actual_responses == responses
            self.requests, self.failures = [], []
            self.received_at = [None] * 3
            self.request_received = [Event() for _ in range(3)]
            self.response_release = [Release(self, i) for i in range(3)]
            self.response_unblocked = [Event() for _ in range(3)]
            self.closing = self.closed = False

        def receive(self, index):
            self.requests.append(deepcopy(observation["requests"][index]))
            if failure == "wrong-request" and index == 0:
                self.requests[0]["authorization"] = "private-sentinel"
            self.received_at[index] = clock.now
            self.request_received[index].set()

        def __enter__(self):
            self.certificates = tempfile.TemporaryDirectory(dir=tmp_path)
            self.cert = Path(self.certificates.name) / "unused-cert"
            self.cert.touch()
            self.origin = "https://127.0.0.1:1"
            fixtures.append(self)
            return self

        def close(self):
            if self.closed:
                return
            self.closing = True
            for release in self.response_release:
                release.set()
            self.certificates.cleanup()
            self.closed = True
            events.append(("close", 3))
            if failure == "late-shutdown-request":
                self.requests.append({"private-sentinel": True})

        def __exit__(self, *_):
            self.close()

    class Child:
        returncode = None

        def __init__(self):
            self.waits, self.killed, self.cleaned = [], False, False

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            self.waits.append(timeout)
            if failure == "cleanup-timeout" and not self.killed:
                raise native.subprocess.TimeoutExpired("synthetic", timeout)
            self.returncode = self.returncode if self.returncode is not None else 0
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9

        def cleanup(self, timeout=10):
            assert timeout == 10
            assert self.returncode is not None
            self.cleaned = True
            if failure == "cleanup-error":
                raise RuntimeError("private-sentinel")

    def launch(command, **options):
        assert command == [
            "synthetic",
            "worker_deadline_native_child",
            "--exact",
            "--nocapture",
        ]
        environment = options["env"]
        assert environment["MARTY_CANVAS_WORKER_DEADLINE_CASE"] == case_name
        assert (
            environment["MARTY_CANVAS_WORKER_DEADLINE_NATIVE_ORIGIN"]
            == fixtures[0].origin
        )
        assert environment["SSL_CERT_FILE"] == str(fixtures[0].cert)
        assert Path(environment["SSL_CERT_DIR"]).is_dir()
        control = Path(environment["MARTY_CANVAS_WORKER_DEADLINE_CONTROL"])
        assert control.name == "native-control"
        assert not control.is_relative_to(Path(fixtures[0].certificates.name))
        roots.append(control)
        assert options["stdin"] == native.subprocess.DEVNULL
        for field in ("stdout", "stderr"):
            assert options[field] != native.subprocess.PIPE
            captures.append(options[field])
        child = Child()
        children.append(child)
        fixtures[0].receive(0)
        if failure == "early-child-exit":
            child.returncode = 1
        return child

    def wait(child, predicate, timeout, phase, *, allow_exited=False):
        events.append((phase, None))
        control, fixture = roots[0], fixtures[0]
        if phase.startswith("renewal-observed-"):
            index = int(phase[-1])
            assert (control / f"request-received-{index}").is_file()
            assert not fixture.response_release[index].is_set()
            if failure in {"missing-renewal", "cleanup-timeout", "cleanup-error"}:
                raise AssertionError("Synthetic missing renewal")
            if failure == "premature-marker":
                (control / "child-done").touch()
            clock.now = fixture.received_at[index] + 10
            (control / phase).touch(exist_ok=False)
        elif phase.startswith("release-delay-"):
            clock.now = fixture.received_at[int(phase[-1])] + 11
        elif phase in {
            "committed-prefix",
            "outcome-observed",
            "late-window-verified",
            "child-done",
        }:
            if phase == "committed-prefix":
                assert not fixture.response_release[2].is_set()
                assert (control / "request-received-2").is_file()
            elif phase == "outcome-observed":
                assert fixture.response_release[2].is_set() is (
                    case_name == "early_release"
                )
                clock.now = 123 if case_name == "early_release" else 130
            elif phase == "late-window-verified":
                assert (control / "late-window-complete").is_file()
            else:
                assert fixture.closed and not Path(fixture.certificates.name).exists()
                assert control.is_dir() and (control / "handlers-joined").is_file()
                assert all(not capture.closed for capture in captures)
                child.returncode = 0
            (control / phase).touch(exist_ok=False)
        elif phase == "late-response-window":
            clock.now = fixture.received_at[2] + 22
            if failure == "late-request":
                fixture.requests.append({"private-sentinel": True})
        return real_wait(child, predicate, timeout, phase, allow_exited=allow_exited)

    monkeypatch.setattr(native, "DeadlineHttpsFixture", Fixture)
    monkeypatch.setattr(native, "OwnedProcess", launch)
    monkeypatch.setattr(native, "wait_for", wait)
    monkeypatch.setattr(
        native,
        "time",
        SimpleNamespace(
            monotonic=lambda: clock.now,
            sleep=lambda seconds: setattr(clock, "now", clock.now + seconds),
        ),
    )
    args = ("synthetic", matrix, case, observation, responses)
    if failure is None:
        native.run_case(*args)
        assert [index for phase, index in events if phase == "release"] == [0, 1, 2]
        assert [
            phase for phase, _ in events if phase.startswith("request-received-")
        ] == ["request-received-0", "request-received-1", "request-received-2"]
    else:
        with pytest.raises(AssertionError) as caught:
            native.run_case(*args)
        diagnostics = str(caught.value) + "\n".join(
            getattr(caught.value, "__notes__", [])
        )
        assert "private-sentinel" not in diagnostics
        assert "Native deadline phase:" in diagnostics
        assert "Owned deadline child output bytes:" in diagnostics
        if failure == "cleanup-error":
            assert str(caught.value) == "Synthetic missing renewal"
            assert "Owned deadline process cleanup failed" in diagnostics
    assert fixtures[0].closed and all(capture.closed for capture in captures)
    assert not roots[0].parent.exists()
    assert children[0].poll() is not None
    assert children[0].cleaned
    assert children[0].killed is (failure == "cleanup-timeout")
    if failure == "cleanup-timeout":
        assert children[0].waits == [35, 10]


@pytest.mark.parametrize("count_error", [None, OSError, ValueError])
def test_real_chatty_child_exits_without_pipe_blocking_or_payload_disclosure(
    native, corpus, monkeypatch, tmp_path, count_error
):
    matrix, reference = corpus
    _, _, responses = native.load_inputs(ROOT)
    children, captures, fixtures, control_roots = [], [], [], []
    real_popen = native.subprocess.Popen
    private = "private-output-token-sentinel"
    code = (
        "import sys; "
        f"sys.stdout.write('O' * (256 * 1024) + '{private}'); sys.stdout.flush(); "
        f"sys.stderr.write('E' * (256 * 1024) + '{private}'); sys.stderr.flush(); "
        "sys.exit(1)"
    )

    class Fixture:
        def __init__(self, *_):
            self.requests, self.failures = [], []
            self.request_received = [Event() for _ in range(3)]
            self.response_release = [Event() for _ in range(3)]
            self.response_unblocked = [Event() for _ in range(3)]
            self.received_at = [None] * 3
            self.closed = False

        def __enter__(self):
            self.certificates = tempfile.TemporaryDirectory(dir=tmp_path)
            self.cert = Path(self.certificates.name) / "unused-cert"
            self.origin = "https://127.0.0.1:1"
            fixtures.append(self)
            return self

        def close(self):
            self.closed = True
            for release in self.response_release:
                release.set()
            self.certificates.cleanup()

        def __exit__(self, *_):
            self.close()

    def launch(command, **options):
        assert command[1] == "worker_deadline_native_child"
        for field in ("stdout", "stderr"):
            assert options[field] != native.subprocess.PIPE
            captures.append(options[field])
        control_roots.append(
            Path(options["env"]["MARTY_CANVAS_WORKER_DEADLINE_CONTROL"]).parent
        )
        child = real_popen([sys.executable, "-c", code], **options)
        # This cross-platform test owns a single output-only child. Actual
        # process-group cleanup is exercised separately on Linux.
        child.cleanup = lambda timeout=10: child.wait(timeout=timeout)
        children.append(child)
        return child

    monkeypatch.setattr(native, "DeadlineHttpsFixture", Fixture)
    monkeypatch.setattr(native, "OwnedProcess", launch)
    if count_error is not None:

        def unreadable_output(*_):
            raise count_error(private)

        monkeypatch.setattr(native, "output_counts", unreadable_output)
    started = time.monotonic()
    with pytest.raises(AssertionError) as caught:
        native.run_case(
            "synthetic",
            matrix,
            matrix["cases"][0],
            reference["observations"][0],
            responses,
        )
    assert time.monotonic() - started < 10
    diagnostics = str(caught.value) + "\n".join(caught.value.__notes__)
    assert (
        private not in diagnostics
        and "O" * 50 not in diagnostics
        and "E" * 50 not in diagnostics
    )
    assert str(caught.value).startswith(
        "Native deadline child exited during request-received-0 (status 1)"
    )
    if count_error is None:
        assert "stdout=262" in diagnostics and "stderr=262" in diagnostics
    else:
        assert "Owned deadline child output counts unavailable" in diagnostics
    assert len(diagnostics) < 512
    assert children[0].wait(timeout=1) == 1
    assert fixtures[0].closed and all(
        event.is_set() for event in fixtures[0].response_release
    )
    assert all(capture.closed for capture in captures)
    assert not control_roots[0].exists()
