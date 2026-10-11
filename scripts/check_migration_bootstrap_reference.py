#!/usr/bin/env python3
"""Compare a candidate bootstrap with the frozen Python effect/state corpus.

The candidate reads one JSON object from stdin with ``name`` and ``input``.
It writes one JSON object with ``exit_codes``, ``effects``, ``state``, and
``error_tags``. All effects are simulated; the harness supplies no live URLs.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

try:
    from .capture_migration_bootstrap_reference import OUTPUT, capture
except ImportError:
    from capture_migration_bootstrap_reference import OUTPUT, capture


def check(candidate: list[str], contract_path: Path = OUTPUT) -> list[str]:
    reference = json.loads(contract_path.read_text(encoding="utf-8"))
    if reference != capture():
        raise ValueError("Python reference differs from committed corpus")
    failures: list[str] = []
    # A candidate must receive only simulated case inputs. In particular,
    # never inherit ambient database, Redis, or OpenBao credentials/URLs.
    safe_env = {key: os.environ[key] for key in
                ("PATH", "SystemRoot", "WINDIR", "PATHEXT", "TMP", "TEMP")
                if key in os.environ}
    safe_env["PYTHONNOUSERSITE"] = "1"
    for case in reference["cases"]:
        invocation = {"name": case["name"], "input": case["input"]}
        result = subprocess.run(
            candidate, input=json.dumps(invocation), text=True,
            capture_output=True, timeout=30, check=False, env=safe_env,
        )
        if result.returncode:
            failures.append(f"{case['name']}: candidate exited {result.returncode}")
            continue
        try:
            actual = json.loads(result.stdout)
        except ValueError:
            failures.append(f"{case['name']}: candidate output is not JSON")
            continue
        expected = {key: case[key] for key in
                    ("exit_codes", "effects", "state", "error_tags")}
        if actual != expected:
            differences = [key for key in expected if actual.get(key) != expected[key]]
            failures.append(f"{case['name']}: differs in {', '.join(differences)}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", nargs=argparse.REMAINDER,
                        help="candidate command after --")
    args = parser.parse_args()
    candidate = args.candidate[1:] if args.candidate[:1] == ["--"] else args.candidate
    if not candidate:
        parser.error("provide a candidate command after --")
    failures = check(candidate)
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"{len(capture()['cases']) - len(failures)} cases matched")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
