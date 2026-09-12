"""Independent synthetic timing-envelope controls, not native worker qualification."""

import importlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return (
        importlib.import_module("test_canvas_worker_body_timeout_https"),
        importlib.import_module("run_canvas_worker_body_timeout_oracle"),
    )


@pytest.fixture
def timing():
    return json.loads(
        (ROOT / "contracts/canvas-worker-body-timeout-scenarios.json").read_text(
            encoding="utf-8"
        )
    )["timing"]


def transition(lower, upper):
    return {
        "schema": "marty.canvas-worker-timeout-transition/v1",
        "last_leased_start_seconds": lower,
        "first_terminal_end_seconds": upper,
    }


def case(mode, roster=False):
    return {
        "mode": mode,
        "target_type": "background_roster" if roster else "learner_application",
    }


def flush(start, end):
    return {"write_started_at": start, "write_completed_at": end}


def test_conservative_upper_can_exceed_receipt_without_clipping(modules, timing):
    native, source = modules
    bounds = native.project_transition(transition(23.9, 24.1), 100, 100.2, 100, 124.2)
    assert bounds == pytest.approx((123.9, 124.3))
    assert bounds[1] > 124.2
    assert source.assert_transition_timing(
        *bounds, flush(124, 124.02), case("progress"), timing
    )
    assert source.assert_outcome_timing(
        100, 100.1, 124.2, flush(124, 124.02), case("progress"), timing
    )


@pytest.mark.parametrize("roster", [False, True])
def test_early_terminal_cannot_hide_behind_late_idle_receipt(modules, timing, roster):
    native, source = modules
    observed = 128 if roster else 123
    bounds = native.project_transition(transition(4.9, 5.1), 100, 100.1, 100, observed)
    progress = flush(108, 108.01)
    # Scalar idle evidence alone looks like the expected 15s/20s read timeout.
    assert source.assert_outcome_timing(
        100, 100.1, observed, progress, case("stall", roster), timing
    )
    with pytest.raises(AssertionError):
        source.assert_transition_timing(
            *bounds, progress, case("stall", roster), timing
        )


@pytest.mark.parametrize("roster", [False, True])
def test_stale_wide_success_interval_rejected_despite_valid_final_idle(
    modules, timing, roster
):
    native, source = modules
    bounds = native.project_transition(transition(5, 24.1), 100, 100.1, 100, 124.3)
    progress = flush(124, 124.05)
    assert source.assert_outcome_timing(
        100, 100.1, 124.3, progress, case("progress", roster), timing
    )
    with pytest.raises(AssertionError):
        source.assert_transition_timing(
            *bounds, progress, case("progress", roster), timing
        )


@pytest.mark.parametrize("roster", [False, True])
def test_actual_progress_flush_not_scheduled_offset_owns_inactivity(
    modules, timing, roster
):
    native, source = modules
    # This would fit exactly against scheduled t=108, but is premature against
    # the real successful write's allowed 0.4s scheduling delay.
    lower = 27.6 if roster else 22.6
    upper = lower + 0.1
    bounds = native.project_transition(
        transition(lower, upper), 100, 100.05, 100, 100 + upper + 0.1
    )
    assert source.assert_transition_timing(
        *bounds, flush(108, 108), case("stall", roster), timing
    )
    with pytest.raises(AssertionError):
        source.assert_transition_timing(
            *bounds, flush(108.4, 108.45), case("stall", roster), timing
        )


@pytest.mark.parametrize("roster", [False, True])
@pytest.mark.parametrize("side", ["early", "late"])
def test_entire_stall_interval_must_fit_not_overlap(modules, timing, roster, side):
    native, source = modules
    minimum = 19.5 if roster else 14.5
    maximum = minimum + 2
    lower, upper = (
        (8 + minimum - 0.1, 8 + minimum + 0.1)
        if side == "early"
        else (8 + maximum - 0.1, 8 + maximum + 0.1)
    )
    bounds = native.project_transition(
        transition(lower, upper), 100, 100, 100, 100 + upper + 0.1
    )
    with pytest.raises(AssertionError):
        source.assert_transition_timing(
            *bounds, flush(108, 108), case("stall", roster), timing
        )


@pytest.mark.parametrize(
    "anchors", [(99, 100, 100, 124), (101, 100, 100, 124), (100, 125, 100, 124)]
)
def test_invalid_anchor_order_is_rejected(modules, anchors):
    native, _ = modules
    with pytest.raises(AssertionError):
        native.project_transition(transition(23.9, 24.1), *anchors)


@pytest.mark.parametrize(
    "value",
    [
        False,
        True,
        float("nan"),
        float("inf"),
        -float("inf"),
        10**1000,
        "private-review-sentinel",
    ],
)
@pytest.mark.parametrize("position", range(4))
def test_nonfinite_or_non_numeric_anchor_errors_are_payload_safe(
    modules, value, position
):
    native, _ = modules
    anchors = [100, 100.1, 100, 124.2]
    anchors[position] = value
    with pytest.raises(AssertionError) as failure:
        native.project_transition(transition(23.9, 24.1), *anchors)
    assert "private-review-sentinel" not in str(failure.value)


@pytest.mark.parametrize(
    "lower,upper",
    [
        (-0.1, 1),
        (2, 1),
        (0, 90.1),
        (False, 1),
        (0, True),
        (0, float("nan")),
        (0, 10**1000),
    ],
)
def test_invalid_transition_offsets_fail_closed(modules, lower, upper):
    native, _ = modules
    with pytest.raises(AssertionError):
        native.project_transition(transition(lower, upper), 100, 100.1, 100, 124.2)
