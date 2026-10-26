"""Private stdin adapter for the source-matched Rust beta rehearsal."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys
from selfhost_native_operator import operator_bytes, OperatorCleanupError


def main():
    payload = sys.stdin.buffer.read(64 * 1024 + 1)
    if len(payload) > 64 * 1024:
        raise SystemExit("Beta rehearsal input exceeds its fixed bound")
    try:
        value = json.loads(operator_bytes(Path(__file__).resolve().parents[1],
                                         "operator", "beta-rehearsal", input=payload))
        if not isinstance(value, dict) or set(value) != {"completed"} or value["completed"] is not True:
            raise ValueError("Invalid native rehearsal response")
    except OperatorCleanupError:
        raise SystemExit("Beta rehearsal cleanup requires inspection; preserve run-owned resources and logs")
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        raise SystemExit("Beta migration rehearsal failed; live maintenance was not entered")
    sys.stdout.write(json.dumps(value, ensure_ascii=True))


if __name__ == "__main__":
    main()
