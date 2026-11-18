"""Thin, read-only adapter to the source-matched Rust Passport model policy."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

if __package__:
    from .selfhost_native_operator import operator_bytes
else:
    from selfhost_native_operator import operator_bytes

ROOT = Path(__file__).resolve().parents[1]


def evaluate(operation: str, *, error_type=ValueError, **context):
    try:
        result = json.loads(operator_bytes(ROOT, "operator", "passport-model", operation,
                                          input=json.dumps(context).encode("utf-8")))
        if (not isinstance(result, dict) or type(result.get("ok")) is not bool
                or (result["ok"] and set(result) != {"ok", "value"})
                or (not result["ok"] and (set(result) != {"ok", "error"}
                                         or not isinstance(result["error"], str)))):
            raise ValueError("Invalid native policy response")
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        raise error_type("Rust Passport model policy could not be verified") from exc
    if not result["ok"]:
        raise error_type(result["error"])
    return result["value"]
