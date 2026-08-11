"""Thin fail-closed adapter for canonical Rust flow decisions."""

from __future__ import annotations

import json
from types import ModuleType
from typing import Any

from common.native_backend import get_marty_rs_diagnostics, load_marty_rs


class NativeFlowOperationError(ValueError):
    """The canonical native flow kernel rejected or malformed an operation."""


_backend: ModuleType | Any | None = None
_diagnostics: dict[str, Any] | None = None


def initialize_native_flow_backend(
    backend: ModuleType | Any | None = None,
) -> dict[str, Any]:
    """Require the canonical backend and return startup diagnostics."""
    global _backend, _diagnostics
    if backend is None:
        backend = load_marty_rs(required_capability="flow_state_machine")
        diagnostics = get_marty_rs_diagnostics(
            backend, required_capability="flow_state_machine"
        )
    else:
        diagnostics = {
            "available": True,
            "backend": "injected-test-backend",
            "version": "test",
            "build_revision": "test",
            "capabilities": ["flow_state_machine"],
        }
    _backend = backend
    _diagnostics = diagnostics
    return dict(diagnostics)


def native_flow_diagnostics() -> dict[str, Any]:
    if _diagnostics is None:
        return initialize_native_flow_backend()
    return dict(_diagnostics)


def _native() -> ModuleType | Any:
    if _backend is None:
        initialize_native_flow_backend()
    if _backend is None:  # Defensive: initialization either succeeds or raises.
        raise NativeFlowOperationError("FLOW.NATIVE_BACKEND_UNAVAILABLE")
    return _backend


def _json_object(raw: Any, operation: str) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise NativeFlowOperationError(
            f"FLOW.INVALID_NATIVE_RESULT: {operation} did not return JSON"
        )
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as error:
        raise NativeFlowOperationError(
            f"FLOW.INVALID_NATIVE_RESULT: {operation} returned malformed JSON"
        ) from error
    if not isinstance(result, dict):
        raise NativeFlowOperationError(
            f"FLOW.INVALID_NATIVE_RESULT: {operation} did not return an object"
        )
    return result


def evaluate_transition(
    current: str,
    target: str,
    *,
    actor: str | None = None,
    event: str | None = None,
) -> dict[str, Any]:
    request: dict[str, Any] = {"current": current, "target": target}
    if actor is not None:
        request["actor"] = actor
    if event is not None:
        request["event"] = event
    try:
        result = _json_object(
            _native().flow_evaluate_transition(
                json.dumps(request, separators=(",", ":"), sort_keys=True)
            ),
            "flow_evaluate_transition",
        )
    except NativeFlowOperationError:
        raise
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    expected = {
        "prior_state",
        "new_state",
        "terminal",
        "no_op",
        "actor",
        "event",
    }
    if set(result) != expected or not isinstance(result["event"], str):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: transition decision shape is invalid"
        )
    if result["prior_state"] != current or result["new_state"] != target:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: transition decision changed requested states"
        )
    if not isinstance(result["terminal"], bool) or not isinstance(result["no_op"], bool):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: transition flags are invalid"
        )
    return result


def is_terminal_status(status: str) -> bool:
    """Return terminality from the canonical same-state decision."""
    return bool(evaluate_transition(status, status)["terminal"])


def validate_graph(graph: dict[str, Any]) -> dict[str, Any]:
    try:
        result = _json_object(
            _native().flow_validate_graph(
                json.dumps(graph, separators=(",", ":"), sort_keys=True)
            ),
            "flow_validate_graph",
        )
    except NativeFlowOperationError:
        raise
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    if set(result) != {"valid", "step_count", "transition_count"}:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: graph decision shape is invalid"
        )
    if result["valid"] is not True:
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: native graph validation did not succeed"
        )
    return result


def select_next_step(
    graph: dict[str, Any], current_step_id: str, outcome: str
) -> str | None:
    try:
        result = _native().flow_select_next_step(
            json.dumps(graph, separators=(",", ":"), sort_keys=True),
            current_step_id,
            outcome,
        )
    except Exception as error:
        raise NativeFlowOperationError(str(error)) from error
    if result is not None and not isinstance(result, str):
        raise NativeFlowOperationError(
            "FLOW.INVALID_NATIVE_RESULT: next-step decision is invalid"
        )
    return result
