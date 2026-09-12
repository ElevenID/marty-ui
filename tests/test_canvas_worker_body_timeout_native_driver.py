"""Synthetic native BODY orchestration controls; no worker qualification."""

from copy import deepcopy
import importlib
import json
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def native(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("test_canvas_worker_body_timeout_https")


@pytest.fixture
def inputs(native):
    return native.load_inputs(ROOT)


@pytest.mark.parametrize(
    "mutation",
    [
        "empty",
        "duplicate",
        "missing",
        "reorder",
        "name",
        "schema",
        "bool-timing",
        "bool-offset",
        "request",
        "status",
        "timing-predicate",
    ],
)
def test_matrix_cannot_drop_or_change_a_frozen_control(native, inputs, mutation):
    matrix, reports, _ = deepcopy(inputs)
    observed = reports[0]["worker_body_timeout"]
    if mutation == "empty":
        reports.clear()
    elif mutation == "duplicate":
        reports[1] = deepcopy(reports[0])
    elif mutation == "missing":
        matrix["cases"].pop()
    elif mutation == "reorder":
        reports.reverse()
    elif mutation == "name":
        matrix["cases"][0]["name"] = "private-sentinel"
    elif mutation == "schema":
        observed["schema"] = "private-sentinel"
    elif mutation == "bool-timing":
        matrix["timing"]["initial_response_max_seconds"] = True
    elif mutation == "bool-offset":
        matrix["schedules"]["prompt"][0] = False
    elif mutation == "request":
        observed["requests"] *= 2
    elif mutation == "status":
        observed["outcome"]["jobs"][0]["status"] = "retry"
    else:
        observed["timing"]["late_window_completed"] = 1
    with pytest.raises(AssertionError) as caught:
        native.validate_matrix(matrix, reports)
    assert "private-sentinel" not in str(caught.value)


@pytest.mark.parametrize("index", range(6))
def test_each_cli_selection_uses_complete_raw_corpus_and_never_published_execution(
    native, monkeypatch, inputs, index
):
    matrix, reports, responses = inputs
    calls = []
    monkeypatch.setattr(native, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(native, "run_case", lambda *args: calls.append(args))

    def forbidden(*args):
        pytest.fail("Published execution/source inspection is not native replay")

    monkeypatch.setattr(native.body, "run", forbidden)
    monkeypatch.setattr(native.body, "verify_sources", forbidden)
    name = native.CASE_NAMES[index]
    native.run("synthetic-executable", name)
    assert calls == [
        (
            "synthetic-executable",
            matrix,
            matrix["cases"][index],
            reports[index]["worker_body_timeout"],
            responses[name],
        )
    ]


@pytest.mark.parametrize(
    "name", ["", "private-sentinel", "application_body_prompt\n", "application_prompt"]
)
def test_unknown_selector_fails_before_inputs_or_process(native, monkeypatch, name):
    monkeypatch.setattr(native, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(native, "load_inputs", lambda *_: pytest.fail("input access"))
    with pytest.raises(AssertionError, match="Unknown native body case"):
        native.run("unused", name)


def test_raw_numeric_cast_is_rejected_before_any_fixture_or_process(
    native, monkeypatch
):
    original = Path.read_bytes

    def changed(path):
        raw = original(path)
        if path.name == "canvas-worker-body-timeout-oracle.json":
            return raw.replace(b"90.0", b"90")
        return raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(AssertionError, match="raw corpus differs"):
        native.load_inputs(ROOT)


@pytest.fixture
def rig(native, inputs, monkeypatch, tmp_path):
    matrix, reports, responses = inputs
    clock = SimpleNamespace(now=100.0)
    events = []
    state = SimpleNamespace(
        control=None,
        fixture=None,
        child=None,
        fail=None,
        cleanup_fail=False,
        close_fail=False,
        control_mutation=None,
    )
    monkeypatch.setattr(native.time, "monotonic", lambda: clock.now)

    class Fixture:
        def __init__(
            self, expected, response, *, chunk_offsets, late_disconnect_from_index
        ):
            state.fixture = self
            self.requests = [expected]
            self.failures = []
            self.origin = "https://owned.invalid"
            self.cert = tmp_path / "owned-cert"
            self.received_at = 100.0
            self.body_started_at = 100.1
            self.chunk_offsets = chunk_offsets
            self.request_started = Event()
            self.request_started.set()
            self.initial_ready = Event()
            self.body_started = Event()
            self.schedule_completed = Event()
            self.handler_finished = Event()
            self.chunks = []
            self.ledger = []
            self.closed = False

        def __enter__(self):
            return self

        def close(self):
            if self.closed:
                return
            events.append("close")
            assert state.control.is_dir()
            assert "handlers-joined" not in {p.name for p in state.control.iterdir()}
            if state.fail == "join":
                self.requests *= 2
            self.closed = True
            if state.close_fail:
                raise OSError("private-close-payload")

        def __exit__(self, *_):
            self.close()

        def observations(self):
            return deepcopy(self.ledger)

    class Child:
        returncode = None

        def __init__(self, command, **kwargs):
            state.child = self
            state.control = Path(
                kwargs["env"]["MARTY_CANVAS_WORKER_BODY_TIMEOUT_CONTROL"]
            )
            assert command[1:] == [
                "worker_body_timeout_native_child",
                "--exact",
                "--nocapture",
            ]
            assert kwargs["stdout"] is not native.subprocess.PIPE
            assert kwargs["stderr"] is not native.subprocess.PIPE
            assert Path(kwargs["env"]["SSL_CERT_DIR"]).is_dir()

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            events.append("wait")
            assert (state.control / "child-done").is_file()
            self.returncode = 0
            return 0

        def cleanup(self, timeout):
            events.append("cleanup")
            assert timeout == 10 and state.control.is_dir()
            if state.cleanup_fail:
                raise RuntimeError("private-cleanup-payload")

    def wait(child, predicate, timeout, phase, *, allow_exited=False):
        events.append(phase)
        assert timeout > 0
        fixture = state.fixture
        if state.fail == phase:
            raise AssertionError("Synthetic bounded phase failure")
        if phase == "before-release-verified":
            assert not fixture.initial_ready.is_set()
            clock.now = 100.05
            (state.control / phase).touch()
        elif phase == "outcome-observed":
            assert fixture.initial_ready.is_set()
            if state.control_mutation == "removed":
                (state.control / "request-received").unlink()
            elif state.control_mutation == "future":
                (state.control / "handlers-joined").touch()
            elif state.control_mutation == "directory":
                (state.control / "private-control").mkdir()
            fixture.body_started.set()
            case = next(c for c in matrix["cases"] if c["name"] == state.name)
            reference = reports[native.CASE_NAMES.index(state.name)][
                "worker_body_timeout"
            ]
            for item in reference["chunks"]:
                fixture.chunks.append(b"x" * item["byte_count"])
                fixture.ledger.append(
                    {k: v for k, v in item.items() if k != "write_within_declared_band"}
                    | {
                        "write_started_seconds": item["scheduled_offset_seconds"],
                        "write_completed_seconds": item["scheduled_offset_seconds"]
                        + 0.01,
                    }
                )
            # The autonomous final write is not yet complete for stalls.
            end = {
                "prompt": 0.2,
                "progress": 24.2,
                "stall": 23.2 if case["target_type"] == "learner_application" else 28.2,
            }[case["mode"]]
            clock.now = 100 + end
            (state.control / phase).write_text(
                json.dumps(
                    {
                        "schema": "marty.canvas-worker-timeout-transition/v1",
                        "last_leased_start_seconds": end - 0.05,
                        "first_terminal_end_seconds": end,
                    }
                )
            )
        elif phase == "independent-final-attempt":
            clock.now = max(
                clock.now, fixture.body_started_at + fixture.chunk_offsets[-1] + 0.01
            )
            fixture.schedule_completed.set()
            assert not predicate(), "Handler completion must also be observed"
            fixture.handler_finished.set()
        elif phase == "late-response-window":
            # Must not publish completion on a shortened final+2 window.
            assert not predicate()
            clock.now = (
                fixture.body_started_at
                + fixture.chunk_offsets[-1]
                + 0.01
                + (15 if state.name.startswith("application") else 20)
                + 2
            )
        elif phase in ("late-window-verified", "child-done"):
            if phase == "child-done":
                assert fixture.closed and (state.control / "handlers-joined").exists()
            (state.control / phase).touch()
        assert predicate()

    monkeypatch.setattr(native, "BodyTimeoutHttpsFixture", Fixture)
    monkeypatch.setattr(native, "OwnedProcess", Child)
    monkeypatch.setattr(native, "wait_for", wait)

    def run(index=0):
        state.name = native.CASE_NAMES[index]
        native.run_case(
            "synthetic",
            matrix,
            matrix["cases"][index],
            reports[index]["worker_body_timeout"],
            responses[state.name],
        )

    return state, events, run


@pytest.mark.parametrize("index", range(6))
def test_ordered_autonomous_writes_full_late_window_join_then_cleanup(rig, index):
    state, events, run = rig
    run(index)
    assert events == [
        "request-received",
        "before-release-verified",
        "outcome-observed",
        "independent-final-attempt",
        "late-response-window",
        "late-window-verified",
        "close",
        "child-done",
        "wait",
        "cleanup",
    ]
    assert state.fixture.closed and not state.control.exists()


@pytest.mark.parametrize(
    "phase",
    [
        "request-received",
        "before-release-verified",
        "outcome-observed",
        "independent-final-attempt",
        "late-response-window",
        "late-window-verified",
        "child-done",
    ],
)
def test_every_phase_failure_contains_child_and_removes_owned_control(rig, phase):
    state, events, run = rig
    state.fail = phase
    with pytest.raises(AssertionError, match="Synthetic bounded phase failure"):
        run()
    assert "cleanup" in events and state.fixture.closed
    assert not state.control.exists()


def test_cleanup_failure_preserves_original_static_failure(rig):
    state, events, run = rig
    state.fail = "outcome-observed"
    state.cleanup_fail = True
    with pytest.raises(
        AssertionError, match="Synthetic bounded phase failure"
    ) as caught:
        run()
    assert "private-cleanup-payload" not in str(caught.value)
    assert all("private-cleanup-payload" not in note for note in caught.value.__notes__)
    assert "cleanup" in events and not state.control.exists()


def test_extra_request_during_join_cannot_reach_child_done(rig):
    state, events, run = rig
    state.fail = "join"
    with pytest.raises(AssertionError, match="request transcript differs"):
        run()
    assert "child-done" not in events and "cleanup" in events


@pytest.mark.parametrize("original_failure", [False, True])
def test_fixture_close_failure_is_static_and_cannot_mask_original(
    rig, original_failure
):
    state, events, run = rig
    state.close_fail = True
    if original_failure:
        state.fail = "outcome-observed"
    expected = (
        "Synthetic bounded phase failure"
        if original_failure
        else "HTTPS cleanup failed"
    )
    with pytest.raises(AssertionError, match=expected) as caught:
        run()
    assert "private-close-payload" not in str(caught.value)
    assert all("private-close-payload" not in note for note in caught.value.__notes__)
    assert "cleanup" in events and not state.control.exists()


@pytest.mark.parametrize("mutation", ["removed", "future", "directory"])
def test_missing_out_of_order_or_nonfile_controls_abort_and_cleanup(rig, mutation):
    state, events, run = rig
    state.control_mutation = mutation
    with pytest.raises(AssertionError, match="control"):
        run()
    assert "late-response-window" not in events and "cleanup" in events
    assert not state.control.exists()


@pytest.mark.parametrize("status", [0, 1, -9])
def test_shared_wait_rejects_early_exit_even_when_predicate_ready(native, status):
    child = SimpleNamespace(poll=lambda: status)
    with pytest.raises(AssertionError, match="child exited"):
        native.wait_for(child, lambda: True, 1, "outcome-observed")


def test_duplicate_parent_marker_cannot_be_acknowledged(native, tmp_path):
    known = set()
    native.write_marker(tmp_path, known, "request-received")
    with pytest.raises(AssertionError, match="Duplicate"):
        native.write_marker(tmp_path, known, "request-received")
