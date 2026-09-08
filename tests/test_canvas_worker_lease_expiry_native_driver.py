"""Synthetic controller controls; these do not execute native workers or SQL."""

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
    return importlib.import_module("test_canvas_worker_lease_expiry_https")


def observation(native, **changes):
    return {
        "schema": native.SCHEMA,
        "status": "succeeded",
        "lease_advanced_after_release": True,
        "original_lease_expired_at_release": False,
        "first_terminal_status": "succeeded",
        "release_start_seconds": 11.98,
        "release_end_seconds": 12.0,
    } | changes


@pytest.mark.parametrize("status", ["leased", "succeeded", "retry", "dead_letter"])
def test_closed_status_supports_idle_leased_without_inventing_terminal(native, status):
    value = observation(
        native,
        status=status,
        first_terminal_status=None if status == "leased" else status,
    )
    assert native.validate_outcome(value) == value
    _, reports, _ = native.load_inputs(ROOT)
    assert native.matches_reference(value, reports[0]["worker_lease_expiry"]) is (
        status == "succeeded"
    )


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema", "private-sentinel"),
        ("status", "private-sentinel"),
        ("status", True),
        ("first_terminal_status", "leased"),
        ("first_terminal_status", None),
        ("lease_advanced_after_release", 1),
        ("original_lease_expired_at_release", 0),
        ("release_start_seconds", -0.001),
        ("release_start_seconds", float("nan")),
        ("release_start_seconds", True),
        ("release_end_seconds", float("inf")),
        ("release_end_seconds", 60.001),
        ("release_end_seconds", 0),
        ("release_end_seconds", 10**1000),
    ],
)
def test_invalid_observation_is_payload_free(native, key, value):
    with pytest.raises(AssertionError) as caught:
        native.validate_outcome(observation(native, **{key: value}))
    assert "private-sentinel" not in str(caught.value)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"x" * 513,
        b"\xff",
        b"{bad",
        b"null",
        b'{"status":"leased","status":"private-sentinel"}',
    ],
)
def test_bounded_payload_rejects_malformed_duplicate_or_oversize(native, tmp_path, raw):
    path = tmp_path / "outcome-observed"
    path.write_bytes(raw)
    with pytest.raises(AssertionError) as caught:
        native.load_outcome(path)
    assert "private-sentinel" not in str(caught.value)


def test_payload_roundtrip_and_closed_fields(native, tmp_path):
    path = tmp_path / "outcome-observed"
    value = observation(native)
    path.write_text(json.dumps(value), encoding="utf-8")
    assert native.load_outcome(path) == value
    for malformed in (
        value | {"private-sentinel": 1},
        {k: v for k, v in value.items() if k != "status"},
    ):
        with pytest.raises(AssertionError):
            native.validate_outcome(malformed)


@pytest.mark.parametrize(
    "lo,hi,valid", [(11.5, 12.5, True), (11.499, 12.5, False), (11.5, 12.501, False)]
)
def test_release_whole_interval_must_fit_real_request_window(native, lo, hi, valid):
    value = observation(native, release_start_seconds=lo, release_end_seconds=hi)
    args = (
        value,
        native.reference.validate_case(native.CASE_NAMES[0]),
        100,
        100,
        SimpleNamespace(received_at=100),
        140,
    )
    if valid:
        assert native.validate_release(*args) == (111.5, 112.5)
    else:
        with pytest.raises(AssertionError):
            native.validate_release(*args)


def test_delayed_marker_cannot_masquerade_as_actual_request(native):
    with pytest.raises(AssertionError, match="actual request window"):
        native.validate_release(
            observation(native),
            native.reference.validate_case(native.CASE_NAMES[0]),
            101,
            101.1,
            SimpleNamespace(received_at=100),
            140,
        )


def test_load_inputs_never_executes_reference_or_installed_source_checks(
    native, monkeypatch
):
    def forbidden(*_):
        pytest.fail("published execution is forbidden in native controller")

    monkeypatch.setattr(native.reference, "run", forbidden)
    monkeypatch.setattr(native.reference, "verify_inputs", forbidden)
    monkeypatch.setattr(native.body, "verify_sources", forbidden)
    matrix, reports, response = native.load_inputs(ROOT)
    assert len(matrix["cases"]) == len(reports) == 2 and response["status"] == 200


@pytest.fixture
def rig(native, monkeypatch, tmp_path):
    matrix, reports, response = native.load_inputs(ROOT)
    clock = SimpleNamespace(now=100.0)
    state = SimpleNamespace(
        name=native.CASE_NAMES[0],
        fail=None,
        mismatch=False,
        chunk_mismatch=False,
        cleanup_fail=False,
        close_extra=False,
        child=None,
        fixture=None,
        control=None,
        exit_code=0,
        control_mutation=None,
    )
    events = []
    monkeypatch.setattr(native.time, "monotonic", lambda: clock.now)

    class Fixture:
        def __init__(
            self, request, _response, *, chunk_offsets, late_disconnect_from_index
        ):
            state.fixture = self
            self.requests = [request]
            self.failures = []
            self.cert = tmp_path / "owned-cert"
            self.origin = "https://owned.invalid"
            self.received_at = 100.0
            self.body_started_at = 100.1
            self.body_started = Event()
            self.initial_ready = Event()
            self.request_started = Event()
            self.request_started.set()
            self.schedule_completed = Event()
            self.handler_finished = Event()
            self.chunks = []
            self.closed = False
            assert chunk_offsets == [0, 8, 16, 24, 34]
            assert late_disconnect_from_index == (
                4 if state.name == native.CASE_NAMES[1] else None
            )

        def __enter__(self):
            return self

        def observations(self):
            return [
                {
                    "index": index,
                    "write_started_seconds": offset,
                    "write_completed_seconds": offset + 0.01,
                    "outcome": "flushed",
                }
                for index, offset in enumerate(native.reference.SCHEDULE)
            ]

        def close(self):
            if self.closed:
                return
            events.append("close")
            assert state.control.is_dir()
            self.closed = True
            if state.close_extra:
                self.requests *= 2

    class Child:
        returncode = None

        def __init__(self, command, **kwargs):
            state.child = self
            state.control = Path(
                kwargs["env"]["MARTY_CANVAS_WORKER_LEASE_EXPIRY_CONTROL"]
            )
            assert command[1:] == [
                "worker_lease_expiry_native_child",
                "--exact",
                "--nocapture",
            ]
            assert kwargs["env"]["MARTY_CANVAS_WORKER_LEASE_EXPIRY_CASE"] == state.name
            assert kwargs["stdout"] is not native.subprocess.PIPE
            assert kwargs["stderr"] is not native.subprocess.PIPE
            assert Path(kwargs["env"]["SSL_CERT_DIR"]).is_dir()

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            events.append("wait")
            assert state.fixture.closed and (state.control / "child-done").is_file()
            self.returncode = state.exit_code
            return self.returncode

        def cleanup(self, timeout):
            events.append("cleanup")
            assert timeout == 10
            if state.cleanup_fail:
                raise RuntimeError("private-cleanup-sentinel")

    def wait(child, predicate, timeout, phase, **_kwargs):
        events.append(phase)
        assert timeout > 0
        fixture = state.fixture
        if state.fail == phase:
            raise AssertionError("Synthetic phase failure")
        if phase == "before-release-verified":
            assert not fixture.initial_ready.is_set()
            clock.now = 100.05
            (state.control / phase).touch()
        elif phase == "outcome-observed":
            assert fixture.initial_ready.is_set()
            if state.control_mutation == "missing":
                (state.control / "request-received").unlink()
            elif state.control_mutation == "future":
                (state.control / "handlers-joined").touch()
            elif state.control_mutation == "directory":
                (state.control / "unexpected-control").mkdir()
            fixture.body_started.set()
            clock.now = 134.2
            value = observation(
                native,
                original_lease_expired_at_release=state.name == native.CASE_NAMES[1],
                release_start_seconds=31.1
                if state.name == native.CASE_NAMES[1]
                else 11.98,
                release_end_seconds=31.2
                if state.name == native.CASE_NAMES[1]
                else 12.0,
            )
            if state.mismatch:
                value.update(
                    status="leased",
                    first_terminal_status=None,
                    lease_advanced_after_release=False,
                )
            (state.control / phase).write_text(json.dumps(value), encoding="utf-8")
        elif phase == "independent-final-attempt":
            fixture.schedule_completed.set()
            assert not predicate(), "handler finish is independently required"
            fixture.handler_finished.set()
        elif phase == "late-response-window":
            clock.now = 136.2
            assert not predicate(), "final+2 is too short"
            clock.now = 151.12
        elif phase in ("late-window-verified", "child-done"):
            if phase == "child-done":
                assert fixture.closed and (state.control / "handlers-joined").is_file()
            (state.control / phase).touch()
        assert predicate()

    monkeypatch.setattr(native, "BodyTimeoutHttpsFixture", Fixture)
    monkeypatch.setattr(native, "OwnedProcess", Child)
    monkeypatch.setattr(native, "wait_for", wait)

    def schedule(*_args, **_kwargs):
        chunks = deepcopy(reports[0]["worker_lease_expiry"]["chunks"])
        if state.chunk_mismatch:
            # A stable, otherwise valid transport projection that differs only
            # from the frozen byte ledger; no status/renewal mismatch is injected.
            chunks[-1]["byte_count"] += 1
            chunks[-1]["flushed_byte_count"] += 1
        return chunks

    monkeypatch.setattr(native.reference, "assert_schedule", schedule)

    def run(index=0):
        state.name = native.CASE_NAMES[index]
        native.run_case(
            "synthetic",
            matrix["cases"][index],
            reports[index]["worker_lease_expiry"],
            response,
        )

    return state, events, run


@pytest.mark.parametrize("index", [0, 1])
def test_complete_protocol_checks_latewindow_join_and_containment(rig, index):
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
    assert not state.control.exists()


def test_idle_leased_mismatch_finishes_observation_then_fails(rig):
    state, events, run = rig
    state.mismatch = True
    with pytest.raises(AssertionError, match="differs from frozen") as caught:
        run(1)
    assert events[-4:] == ["close", "child-done", "wait", "cleanup"]
    assert not state.control.exists()
    assert any(
        "status=leased; terminal=None; renewed=False; original_expired=True" in note
        for note in caught.value.__notes__
    )


@pytest.mark.parametrize("index", [0, 1])
def test_chunk_only_mismatch_finishes_late_observation_join_and_cleanup(rig, index):
    state, events, run = rig
    state.chunk_mismatch = True
    with pytest.raises(AssertionError, match="differs from frozen") as caught:
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
    assert state.child.returncode == 0
    assert any(
        "status=succeeded; terminal=succeeded; renewed=True; "
        f"original_expired={bool(index)}" in note
        for note in caught.value.__notes__
    )


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
def test_each_phase_failure_cleans_owned_children_and_fixture(rig, phase):
    state, events, run = rig
    state.fail = phase
    with pytest.raises(AssertionError, match="Synthetic phase failure"):
        run()
    assert "cleanup" in events and state.fixture.closed and not state.control.exists()


def test_cleanup_failure_cannot_disclose_or_replace_original(rig):
    state, _, run = rig
    state.fail, state.cleanup_fail = "outcome-observed", True
    with pytest.raises(AssertionError, match="Synthetic phase failure") as caught:
        run()
    assert "private-cleanup-sentinel" not in str(caught.value)
    assert all(
        "private-cleanup-sentinel" not in note for note in caught.value.__notes__
    )


def test_extra_join_request_rejects_before_child_done(rig):
    state, events, run = rig
    state.close_extra = True
    with pytest.raises(AssertionError, match="transcript differs"):
        run()
    assert "child-done" not in events and "cleanup" in events


@pytest.mark.parametrize("status", [1, -9])
def test_nonzero_final_exit_never_passes(rig, status):
    state, events, run = rig
    state.exit_code = status
    with pytest.raises(AssertionError, match="failed final verification"):
        run()
    assert "cleanup" in events


@pytest.mark.parametrize("mutation", ["missing", "future", "directory"])
def test_marker_inventory_is_fail_closed(rig, mutation):
    state, events, run = rig
    state.control_mutation = mutation
    with pytest.raises(AssertionError, match="control"):
        run()
    assert "cleanup" in events and not state.control.exists()


def test_cleanup_failure_after_success_still_fails(rig):
    state, events, run = rig
    state.cleanup_fail = True
    with pytest.raises(AssertionError, match="process cleanup failed") as caught:
        run()
    assert "private-cleanup-sentinel" not in str(caught.value)
    assert "wait" in events and not state.control.exists()


@pytest.mark.parametrize("status", [0, 1, -9])
def test_real_shared_wait_rejects_early_exit_before_ready_acceptance(native, status):
    with pytest.raises(AssertionError, match="child exited"):
        native.wait_for(
            SimpleNamespace(poll=lambda: status), lambda: True, 1, "outcome-observed"
        )


@pytest.mark.parametrize("anchor", [float("nan"), float("inf"), True, 10**1000])
def test_release_anchor_rejects_nonfinite_and_non_numeric(native, anchor):
    with pytest.raises(AssertionError):
        native.release_interval(observation(native), anchor, 100.1, 100, 140)


@pytest.mark.parametrize("name", ["", "private-sentinel", None, True])
def test_unknown_selection_never_loads_inputs_or_launches(native, monkeypatch, name):
    monkeypatch.setattr(native.sys, "platform", "linux")
    monkeypatch.setattr(
        native, "load_inputs", lambda *_: pytest.fail("unexpected input read")
    )
    with pytest.raises(AssertionError, match="Unknown native expiry case"):
        native.run("synthetic", name)
