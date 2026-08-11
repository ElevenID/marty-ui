"""Required Marty Rust backend loading and diagnostics."""

from __future__ import annotations

import json
from types import ModuleType
from typing import Any


class NativeBackendUnavailable(RuntimeError):
    """The required Marty Rust extension or capability is unavailable."""


class NativeOperationError(RuntimeError):
    """The Marty Rust extension returned an invalid diagnostic result."""


def _import_marty_rs() -> ModuleType:
    try:
        from marty_rs import _marty_rs
    except Exception as error:
        raise NativeBackendUnavailable(
            "The required marty_rs._marty_rs backend is unavailable"
        ) from error
    return _marty_rs


def get_marty_rs_diagnostics(
    backend: ModuleType,
    *,
    required_capability: str | None = None,
) -> dict[str, Any]:
    """Validate and return the backend's startup/health diagnostic snapshot."""

    diagnostics_fn = getattr(backend, "native_backend_diagnostics", None)
    if not callable(diagnostics_fn):
        raise NativeBackendUnavailable(
            "The Marty Rust backend does not expose native_backend_diagnostics"
        )
    try:
        diagnostics: Any = json.loads(diagnostics_fn())
    except Exception as error:
        raise NativeOperationError("Invalid Marty Rust backend diagnostics") from error
    if not isinstance(diagnostics, dict) or diagnostics.get("available") is not True:
        raise NativeBackendUnavailable("The Marty Rust backend is not ready")
    if not diagnostics.get("version") or diagnostics.get("backend") != "_marty_rs":
        raise NativeOperationError("Incomplete Marty Rust backend diagnostics")
    capabilities = diagnostics.get("capabilities")
    if not isinstance(capabilities, list):
        raise NativeOperationError("Marty Rust capabilities are malformed")
    if required_capability and required_capability not in capabilities:
        raise NativeBackendUnavailable(
            f"The Marty Rust backend lacks required capability: {required_capability}"
        )
    return diagnostics


def load_marty_rs(*, required_capability: str | None = None) -> ModuleType:
    """Load the sole supported native binding surface and verify diagnostics."""
    backend = _import_marty_rs()
    get_marty_rs_diagnostics(
        backend,
        required_capability=required_capability,
    )
    return backend
