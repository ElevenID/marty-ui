"""Closed worker launch classification shared by deployment preflights.

This recognizes reviewed argument vectors, not shell syntax or image contents.
Callers remain responsible for immutable artifact and release provenance.
"""

from __future__ import annotations

from typing import Any


NATIVE_WORKER = "/usr/local/bin/marty-canvas-sync-worker"
DISPATCHER = "/app/services/entrypoint.sh"
NATIVE_LOADER = f". /app/load-secrets-env.sh\nexec {NATIVE_WORKER}\n"
PYTHON_LOADER = ". /app/load-secrets-env.sh\nexec python -m issuance.canvas_worker\n"


def classify_worker_launch(
    entrypoint: Any, command: Any, environment: Any,
) -> str | None:
    if not isinstance(environment, dict):
        return None
    if any(not isinstance(key, str) or (value is not None and not isinstance(value, str))
           for key, value in environment.items()):
        return None
    for vector in (entrypoint, command):
        if vector is not None and (
            not isinstance(vector, list)
            or any(not isinstance(argument, str) for argument in vector)
        ):
            return None
    direct = command if not entrypoint else entrypoint if not command else None
    loader = entrypoint == ["/bin/sh", "-c"]
    if direct in (["python", "-m", "issuance.canvas_worker"],
                  ["python3", "-m", "issuance.canvas_worker"]) or (
        loader and command == [PYTHON_LOADER]
    ):
        return "python"
    if environment.get("CANVAS_SYNC_PROCESSOR") not in (None, ""):
        return None
    selector = environment.get("SERVICE_NAME")
    if selector not in (None, "", "canvas-sync-worker", "canvas_sync_worker"):
        return None
    if loader and command == [NATIVE_LOADER]:
        return "native"
    if direct == [DISPATCHER] and selector in ("canvas-sync-worker", "canvas_sync_worker"):
        return "native"
    if direct == [NATIVE_WORKER]:
        # URL templates are shell-expanded, but native secret-file readers and
        # library-owned file settings must not be forbidden by a launch check.
        # This classifier does not establish the validity of secret contents.
        if environment.get("DATABASE_URL_TEMPLATE"):
            return None
        return "native"
    return None
