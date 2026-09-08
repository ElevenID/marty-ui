"""Synthetic timeout parent controls; not actual native-worker qualification."""

from copy import deepcopy
import importlib
import json
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
CASE_NAMES = (
    "application_prompt",
    "application_delayed_headers",
    "roster_prompt",
    "roster_delayed_headers",
)


def transition(lower=14.9, upper=15.1):
    return {
        "schema": "marty.canvas-worker-timeout-transition/v1",
        "last_leased_start_seconds": lower,
        "first_terminal_end_seconds": upper,
    }


@pytest.fixture
def native(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("test_canvas_worker_timeout_https")


@pytest.fixture
def corpus():
    return tuple(
        json.loads(
            (ROOT / "contracts" / f"canvas-worker-timeout-{name}.json").read_text()
        )
        for name in ("scenarios", "oracle")
    )


@pytest.mark.parametrize(
    "mutation",
    [None, "empty", "duplicate", "renamed", "missing", "reordered", "extra-request"],
)
def test_all_four_exact_frozen_controls_remain_mandatory(native, corpus, mutation):
    matrix, reference = corpus
    if mutation == "empty":
        matrix["cases"] = reference["observations"] = []
    elif mutation == "duplicate":
        matrix["cases"][1] = deepcopy(matrix["cases"][0])
    elif mutation == "renamed":
        matrix["cases"][0]["name"] = reference["observations"][0]["case"] = (
            "unqualified"
        )
    elif mutation == "missing":
        reference["observations"].pop()
    elif mutation == "reordered":
        reference["observations"].reverse()
    elif mutation == "extra-request":
        reference["observations"][0]["requests"] *= 2
    if mutation is None:
        native.validate_matrix(matrix, reference)
    else:
        with pytest.raises(AssertionError):
            native.validate_matrix(matrix, reference)


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_run_selects_one_case_without_dropping_full_matrix_validation(
    native, corpus, monkeypatch, case_name
):
    matrix, reference = corpus
    calls = []
    monkeypatch.setattr(native, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(native, "run_case", lambda *args: calls.append(args))
    native.run("synthetic", case_name)
    assert len(calls) == 1
    assert calls[0][0] == "synthetic" and calls[0][1] == matrix
    assert calls[0][2] == next(
        case for case in matrix["cases"] if case["name"] == case_name
    )
    assert calls[0][3] == next(
        item for item in reference["observations"] if item["case"] == case_name
    )


@pytest.mark.parametrize(
    "case_name", ["", "unqualified", "application_prompt roster_prompt"]
)
def test_unknown_case_never_launches_a_child(native, monkeypatch, case_name):
    monkeypatch.setattr(native, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        native, "run_case", lambda *_: pytest.fail("Invalid case launched")
    )
    with pytest.raises(AssertionError):
        native.run("synthetic", case_name)


@pytest.mark.parametrize(
    "field", [None, "method", "path", "authorization", "accept", "extra", "failure"]
)
def test_single_authenticated_get_is_exact_and_errors_do_not_echo_payload(
    native, corpus, field
):
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


@pytest.mark.parametrize(
    "elapsed,accepted",
    [
        (5, False),
        (10, False),
        (14.499, False),
        (14.5, True),
        (15, True),
        (16.5, True),
        (16.501, False),
        (20, False),
    ],
)
def test_application_marker_receipt_retains_frozen_observation_window(
    native, corpus, elapsed, accepted
):
    matrix, _ = corpus
    case = matrix["cases"][1]
    if accepted:
        native.assert_outcome_timing(100, 100 + elapsed, case, matrix["timing"])
    else:
        with pytest.raises(AssertionError):
            native.assert_outcome_timing(100, 100 + elapsed, case, matrix["timing"])


@pytest.mark.parametrize("lower,upper", [(0, 0), (14.9, 15.1), (90, 90)])
@pytest.mark.parametrize("size", [None, 512])
def test_transition_marker_accepts_only_bounded_closed_numeric_payload(
    native, tmp_path, lower, upper, size
):
    marker = tmp_path / "outcome-observed"
    expected = transition(lower, upper)
    raw = json.dumps(expected).encode()
    if size is not None:
        raw += b" " * (size - len(raw))
    marker.write_bytes(raw)
    assert native.load_transition(marker) == expected


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "invalid-json",
        "invalid-utf8",
        "array",
        "null",
        "wrong-schema",
        "missing-key",
        "extra-key",
        "duplicate-schema",
        "duplicate-number",
        "oversize",
        "bool-lower",
        "bool-upper",
        "string",
        "nan",
        "infinity",
        "negative",
        "reversed",
        "too-large",
    ],
)
def test_transition_marker_rejects_malformed_payload_without_echoing_it(
    native, tmp_path, mutation
):
    marker = tmp_path / "outcome-observed"
    value = transition()
    if mutation == "wrong-schema":
        value["schema"] = "private-sentinel"
    elif mutation == "missing-key":
        value.pop("first_terminal_end_seconds")
    elif mutation == "extra-key":
        value["private-sentinel"] = True
    elif mutation in {"bool-lower", "string", "nan", "infinity", "negative"}:
        value["last_leased_start_seconds"] = {
            "bool-lower": True,
            "string": "private-sentinel",
            "nan": float("nan"),
            "infinity": float("inf"),
            "negative": -0.001,
        }[mutation]
    elif mutation == "bool-upper":
        value["first_terminal_end_seconds"] = True
    elif mutation == "reversed":
        value = transition(16, 15)
    elif mutation == "too-large":
        value = transition(89, 90.001)
    raw = json.dumps(value).encode()
    if mutation == "invalid-json":
        raw = b'{"private-sentinel":'
    elif mutation == "invalid-utf8":
        raw = b"\xffprivate-sentinel"
    elif mutation == "array":
        raw = b'["private-sentinel"]'
    elif mutation == "null":
        raw = b"null"
    elif mutation.startswith("duplicate-"):
        duplicate = (
            b'"schema":"private-sentinel"'
            if mutation == "duplicate-schema"
            else b'"last_leased_start_seconds":15'
        )
        raw = raw[:-1] + b"," + duplicate + b"}"
    elif mutation == "oversize":
        raw += b" " * (513 - len(raw))
    if mutation != "missing":
        marker.write_bytes(raw)
    with pytest.raises(AssertionError) as caught:
        native.load_transition(marker)
    assert "private-sentinel" not in str(caught.value)


@pytest.mark.parametrize(
    "lower,upper,anchor_upper,accepted",
    [
        (14.5, 16.5, 100, True),
        (14.499, 15, 100, False),
        (15, 16.501, 100, False),
        (14, 17, 100, False),
        (14.9, 15.1, 100.1, True),
        (15, 15, 102, False),
        (4.9, 5.1, 100.1, False),
        (9.9, 10.1, 100.1, False),
        (19.9, 20.1, 100.1, False),
        (4.9, 15, 100.1, False),
    ],
)
def test_application_requires_whole_conservative_transition_interval(
    native, corpus, lower, upper, anchor_upper, accepted
):
    matrix, _ = corpus
    args = (
        transition(lower, upper),
        100,
        anchor_upper,
        100,
        matrix["cases"][1],
        matrix["timing"],
    )
    if accepted:
        actual = native.assert_transition_timing(*args)
        assert actual == pytest.approx((lower, anchor_upper + upper - 100))
    else:
        with pytest.raises(AssertionError):
            native.assert_transition_timing(*args)


@pytest.mark.parametrize(
    "lower,upper,anchor_lower,anchor_upper,request_at,accepted",
    [
        (17, 20, 100, 100.1, 100, True),
        (24, 25, 100, 100.01, 100, False),
        (0, 1, 99, 100, 100, False),
        (1, 2, 101, 100, 100, False),
        (1, 2, True, 100, 100, False),
        (1, 2, 100, float("nan"), 100, False),
    ],
)
def test_general_transition_budget_retains_roster_window_and_valid_anchor_order(
    native, corpus, lower, upper, anchor_lower, anchor_upper, request_at, accepted
):
    matrix, _ = corpus
    args = (
        transition(lower, upper),
        anchor_lower,
        anchor_upper,
        request_at,
        matrix["cases"][3],
        matrix["timing"],
    )
    if accepted:
        native.assert_transition_timing(*args)
    else:
        with pytest.raises(AssertionError):
            native.assert_transition_timing(*args)


@pytest.mark.parametrize(
    "case_index,upper,released,accepted",
    [
        (1, 16.5, 117, True),
        (1, 16.5, 116.5, False),
        (1, 16.5, 116, False),
        (0, 0.2, 100.1, True),
        (3, 17.2, 117, True),
    ],
)
def test_only_application_timeout_requires_entire_transition_before_release(
    native, corpus, case_index, upper, released, accepted
):
    matrix, _ = corpus
    args = (upper, 100, released, matrix["cases"][case_index])
    if accepted:
        native.assert_transition_before_release(*args)
    else:
        with pytest.raises(AssertionError):
            native.assert_transition_before_release(*args)


@pytest.mark.parametrize("elapsed", [17.1, 19.9, 20.1])
def test_roster_outcome_budget_is_not_narrowed_to_application_fifteen_seconds(
    native, corpus, elapsed
):
    matrix, _ = corpus
    native.assert_outcome_timing(
        100, 100 + elapsed, matrix["cases"][3], matrix["timing"]
    )


@pytest.mark.parametrize(
    "case_index,outcome,released,accepted",
    [
        (0, 101, 100.1, True),
        (0, 100.1, 101, False),
        (1, 115, 117, True),
        (1, 118, 117, False),
        (3, 117.1, 117, True),
        (3, 115, 117, False),
    ],
)
def test_outcome_order_does_not_allow_roster_failure_to_mimic_application_timeout(
    native, corpus, case_index, outcome, released, accepted
):
    matrix, _ = corpus
    if accepted:
        native.assert_outcome_order(outcome, released, matrix["cases"][case_index])
    else:
        with pytest.raises(AssertionError):
            native.assert_outcome_order(outcome, released, matrix["cases"][case_index])


@pytest.mark.parametrize(
    "case_index,delay,accepted",
    [
        (0, 0.1, True),
        (0, 2.001, False),
        (1, 15, False),
        (1, 17, True),
        (1, 18.001, False),
        (3, 15, False),
        (3, 17, True),
        (3, 20, False),
    ],
)
def test_release_band_remains_independent_of_worker_outcome(
    native, corpus, case_index, delay, accepted
):
    matrix, _ = corpus
    fixture = SimpleNamespace(received_at=100, released_at=100 + delay)
    if accepted:
        native.assert_release_timing(
            fixture, matrix["cases"][case_index], matrix["timing"]
        )
    else:
        with pytest.raises(AssertionError):
            native.assert_release_timing(
                fixture, matrix["cases"][case_index], matrix["timing"]
            )


@pytest.mark.parametrize("status", [0, 1])
def test_early_exit_cannot_supply_a_missing_timeout_receipt(native, status):
    with pytest.raises(AssertionError):
        native.wait_for(
            SimpleNamespace(poll=lambda: status), lambda: False, 1, "outcome-observed"
        )


def test_ready_predicate_after_timeout_does_not_pass(native, monkeypatch):
    times = iter([0.0, 2.0])
    monkeypatch.setattr(native, "time", SimpleNamespace(monotonic=lambda: next(times)))
    with pytest.raises(AssertionError):
        native.wait_for(
            SimpleNamespace(poll=lambda: None), lambda: True, 1, "outcome-observed"
        )


def test_child_acknowledgment_cannot_be_consumed_twice(native, tmp_path):
    known = {"request-received"}
    (tmp_path / "request-received").touch()
    (tmp_path / "before-release-verified").touch()
    child = SimpleNamespace(poll=lambda: None)
    native.receive_marker(child, tmp_path, known, "before-release-verified", 1)
    with pytest.raises(AssertionError, match="Duplicate"):
        native.receive_marker(child, tmp_path, known, "before-release-verified", 1)


@pytest.mark.parametrize(
    "case_name,failure,outcome_override",
    [(name, None, None) for name in CASE_NAMES]
    + [("roster_delayed_headers", None, 124)]
    + [("application_delayed_headers", None, 116.2)]
    + [("application_delayed_headers", "late-marker", 116.8)]
    + [
        ("application_delayed_headers", failure, None)
        for failure in (
            "early-exit",
            "premature-marker",
            "missing-prefix",
            "missing-request",
            "missing-release",
            "handler-blocked",
            "missing-done",
            "wrong-request",
            "late-request",
            "late-child-failure",
            "shutdown-request",
            "cleanup-timeout",
            "cleanup-error",
            "early-terminal-late-marker",
            "early-terminal-late-idle",
            "broad-transition",
            "lower-straddle",
            "upper-straddle",
        )
    ],
)
def test_controller_protocol_keeps_independent_release_full_late_window_and_cleanup(
    native, corpus, monkeypatch, tmp_path, case_name, failure, outcome_override
):
    matrix, reference = corpus
    _, _, responses = native.load_inputs(ROOT)
    case = next(item for item in matrix["cases"] if item["name"] == case_name)
    observation = next(
        item for item in reference["observations"] if item["case"] == case_name
    )
    model = SimpleNamespace(
        now=100.0, fixture=None, child=None, control=None, anchor=None
    )
    handles, actions = [], []
    terminal_at = (
        115
        if case_name == "application_delayed_headers"
        else (117.1 if case["delayed"] else 100.2)
    )
    idle_at = terminal_at
    marker_at = outcome_override if outcome_override is not None else terminal_at
    last_leased_at, first_terminal_at = terminal_at - 0.025, terminal_at
    if failure in {"early-terminal-late-marker", "early-terminal-late-idle"}:
        terminal_at = 105
        idle_at = 115 if failure == "early-terminal-late-idle" else terminal_at
        marker_at = 115
        last_leased_at, first_terminal_at = 104.975, 105
    elif failure == "broad-transition":
        terminal_at, idle_at, marker_at = 105, 115, 115
        last_leased_at, first_terminal_at = 104.9, 115
    elif failure == "lower-straddle":
        last_leased_at, first_terminal_at = 114.499, 115
    elif failure == "upper-straddle":
        terminal_at, idle_at, marker_at = 116.5, 116.5, 116.8
        last_leased_at, first_terminal_at = 116.4, 116.501

    class ControllerRelease(Event):
        def set(self):
            pytest.fail(
                "Parent wrote release; only the independent fixture controller may do so"
            )

    def advance(seconds):
        model.now += seconds
        fixture = model.fixture
        if (
            case["delayed"]
            and fixture.request_started.is_set()
            and model.now >= 117
            and fixture.released_at is None
        ):
            if failure != "missing-release":
                fixture.released_at = 117.0
                Event.set(fixture.release)
                if failure != "handler-blocked":
                    fixture.response_unblocked.set()
                actions.append("controller-release")

    class PromptReady(Event):
        def set(self):
            assert (model.control / "before-release-verified").is_file()
            super().set()
            if not case["delayed"]:
                model.fixture.released_at = model.now
                Event.set(model.fixture.release)
                model.fixture.response_unblocked.set()

    class Fixture:
        def __init__(self, expected_request, response, *, delay_seconds):
            assert expected_request == observation["requests"][0]
            assert response == responses[case_name]
            assert delay_seconds == (17 if case["delayed"] else 0)
            self.requests, self.failures = [], []
            self.received_at, self.released_at = 100.0, None
            self.request_started, self.response_unblocked = Event(), Event()
            self.prompt_ready, self.release = PromptReady(), ControllerRelease()
            self.closed = False
            model.fixture = self

        def __enter__(self):
            directory = tmp_path / "tls"
            directory.mkdir()
            self.cert = directory / "cert.pem"
            self.cert.touch()
            self.origin = "https://127.0.0.1:1"
            return self

        def close(self):
            if self.closed:
                return
            assert model.control.is_dir()
            Event.set(self.release)
            self.response_unblocked.set()
            self.cert.unlink()
            self.cert.parent.rmdir()
            self.closed = True
            actions.append("close")
            if failure == "shutdown-request":
                self.requests.append({"private-sentinel": True})

        def __exit__(self, *_):
            self.close()

    class Child:
        def __init__(self, command, **options):
            assert command == [
                "synthetic",
                "worker_timeout_native_child",
                "--exact",
                "--nocapture",
            ]
            env = options["env"]
            assert env["MARTY_CANVAS_WORKER_TIMEOUT_CASE"] == case_name
            assert (
                env["MARTY_CANVAS_WORKER_TIMEOUT_NATIVE_ORIGIN"] == model.fixture.origin
            )
            model.control = Path(env["MARTY_CANVAS_WORKER_TIMEOUT_CONTROL"])
            assert model.control.name == "native-control"
            assert not model.control.is_relative_to(model.fixture.cert.parent)
            handles.extend([options["stdout"], options["stderr"]])
            assert all(not handle.closed for handle in handles)
            self.returncode, self.cleaned, self.killed, self.waits = (
                None,
                False,
                False,
                [],
            )
            model.child = self
            model.fixture.requests = deepcopy(observation["requests"])
            if failure != "missing-request":
                model.fixture.request_started.set()
            if failure == "wrong-request":
                model.fixture.requests[0]["authorization"] = "private-sentinel"
            if failure == "premature-marker":
                (model.control / "child-done").touch()
            if failure == "early-exit":
                self.returncode = 1

        def poll(self):
            if self.returncode is not None:
                return self.returncode
            control = model.control
            if (control / "request-received").exists():
                if model.anchor is None:
                    model.anchor = model.now
                if failure not in {
                    "missing-prefix",
                    "cleanup-timeout",
                    "cleanup-error",
                }:
                    (control / "before-release-verified").touch(exist_ok=True)
            if (
                (control / "before-release-verified").exists()
                and model.now >= max(terminal_at, idle_at, marker_at)
                and not (control / "outcome-observed").exists()
            ):
                payload = transition(
                    last_leased_at - model.anchor, first_terminal_at - model.anchor
                )
                pending = control.parent / "transition-pending"
                pending.write_text(json.dumps(payload), encoding="utf-8")
                pending.replace(control / "outcome-observed")
            if (
                failure == "late-request"
                and model.now >= 120
                and len(model.fixture.requests) == 1
            ):
                model.fixture.requests.append({"private-sentinel": True})
            if (control / "late-window-complete").exists():
                assert model.now >= 122
                assert model.fixture.released_at is not None
                assert model.now >= marker_at + 2
                if failure == "late-child-failure":
                    self.returncode = 1
                else:
                    (control / "late-window-verified").touch(exist_ok=True)
            if (control / "handlers-joined").exists() and failure != "missing-done":
                assert model.fixture.closed and not model.fixture.cert.parent.exists()
                assert all(not handle.closed for handle in handles)
                already_done = (control / "child-done").exists()
                (control / "child-done").touch(exist_ok=True)
                if already_done:
                    self.returncode = 0
            return self.returncode

        def wait(self, timeout):
            self.waits.append(timeout)
            if failure == "cleanup-timeout" and not self.killed:
                raise native.subprocess.TimeoutExpired("synthetic", timeout)
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9

        def cleanup(self, timeout=10):
            assert timeout == 10
            self.cleaned = True
            if failure == "cleanup-error":
                raise RuntimeError("private-sentinel")

    monkeypatch.setattr(native, "TimeoutHttpsFixture", Fixture)
    monkeypatch.setattr(native, "OwnedProcess", Child)
    monkeypatch.setattr(
        native, "time", SimpleNamespace(monotonic=lambda: model.now, sleep=advance)
    )
    if failure is None:
        native.run_case("synthetic", matrix, case, observation, responses[case_name])
        assert model.now >= 122
        if case["delayed"]:
            assert actions.index("controller-release") < actions.index("close")
    else:
        with pytest.raises(AssertionError) as caught:
            native.run_case(
                "synthetic", matrix, case, observation, responses[case_name]
            )
        diagnostic = str(caught.value) + "\n".join(
            getattr(caught.value, "__notes__", [])
        )
        assert "private-sentinel" not in diagnostic
    assert model.fixture.closed and model.child.cleaned
    assert all(handle.closed for handle in handles)
    assert not model.control.parent.exists()
    if failure == "cleanup-timeout":
        assert model.child.killed and model.child.waits == [35, 10]
