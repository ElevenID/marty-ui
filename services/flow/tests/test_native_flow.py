from __future__ import annotations

import json
from pathlib import Path

import pytest

from common.native_backend import NativeBackendUnavailable
from flow import native


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "flow_state.json"


def test_shared_transition_and_graph_vectors_use_the_native_kernel():
    diagnostics = native.initialize_native_flow_backend()
    assert diagnostics["available"] is True
    assert "flow_state_machine" in diagnostics["capabilities"]

    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    for case in fixture["transition_cases"]:
        request = case["request"]
        assert native.evaluate_transition(
            request["current"],
            request["target"],
            actor=request.get("actor"),
            event=request.get("event"),
        ) == case["expected"]

    for request in fixture["invalid_transitions"]:
        with pytest.raises(
            native.NativeFlowOperationError, match="FLOW.TRANSITION_NOT_ALLOWED"
        ):
            native.evaluate_transition(request["current"], request["target"])

    graph = fixture["graph"]
    assert native.validate_graph(graph) == {
        "valid": True,
        "step_count": 3,
        "transition_count": 2,
    }
    assert native.select_next_step(graph, "approve", "approval_granted") == "end"
    assert native.select_next_step(graph, "approve", "failure") is None


def test_missing_native_backend_fails_closed(monkeypatch: pytest.MonkeyPatch):
    def unavailable(*, required_capability: str | None = None):
        raise NativeBackendUnavailable(
            f"missing required native capability: {required_capability}"
        )

    monkeypatch.setattr(native, "_backend", None)
    monkeypatch.setattr(native, "_diagnostics", None)
    monkeypatch.setattr(native, "load_marty_rs", unavailable)
    with pytest.raises(NativeBackendUnavailable, match="flow_state_machine"):
        native.initialize_native_flow_backend()


def test_malformed_native_decision_fails_closed(monkeypatch: pytest.MonkeyPatch):
    class MalformedBackend:
        @staticmethod
        def flow_evaluate_transition(request_json: str) -> str:
            return "{}"

    monkeypatch.setattr(native, "_backend", MalformedBackend())
    monkeypatch.setattr(native, "_diagnostics", {"available": True})
    with pytest.raises(native.NativeFlowOperationError, match="decision shape"):
        native.evaluate_transition("created", "pending")
