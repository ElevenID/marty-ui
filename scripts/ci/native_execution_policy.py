"""Source-matched CI-only Rust libtest policy adapter."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
from source_matched_native import verified_native_binary


def _evaluate(operation: str, **context):
    if operation in {"verify", "positive-summary"}:
        # Child stdout may be arbitrarily large; only candidate summary rows
        # belong to result policy. Case outcomes use the separate libtest log.
        context["lines"] = [line for line in context["lines"] if line.startswith("test result: ")]
    binary = verified_native_binary(ROOT, "MARTY_CI_EXECUTION")
    command = [str(binary)] if binary is not None else [
        "cargo", "+1.95.0", "run", "--quiet", "--locked",
        "--manifest-path", str(ROOT / "rust/Cargo.toml"),
        "-p", "marty-ci-execution", "--",
    ]
    result = subprocess.run([*command, operation], input=json.dumps(context).encode(),
                            check=True, capture_output=True, timeout=300)
    try:
        response = json.loads(result.stdout)
        if not isinstance(response, dict) or type(response.get("ok")) is not bool:
            raise ValueError("invalid_native_execution_policy_response")
        if response["ok"] and set(response) == {"ok", "value"}:
            return response["value"]
        if (not response["ok"] and set(response) == {"ok", "error"}
                and isinstance(response["error"], str)):
            raise ValueError(response["error"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid_native_execution_policy_response") from exc
    raise ValueError("invalid_native_execution_policy_response")


def evaluate(operation: str, **context):
    try:
        return _evaluate(operation, **context)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        # Do not include a command, child output, or caller context in evidence.
        raise ValueError("native_execution_policy_unavailable") from exc


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "positive-summary":
        raise SystemExit("Expected positive-summary LOGFILE")
    lines = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace").splitlines()
    try:
        accepted = evaluate("positive-summary", lines=lines)
    except ValueError:
        accepted = False
    raise SystemExit(0 if accepted else 1)
