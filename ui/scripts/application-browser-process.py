"""Bridge the application browser worker to the existing Linux process owner.

This diagnostic tool is not copied into the nginx runtime context. The fixed
Node caller supplies the browser command; no shell or inherited Python startup
configuration is used. The shared owner returns success only after its kernel
child set is empty, including detached Chromium descendants.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
GUARDIAN = ROOT / "scripts/installer_startup_process.py"
GUARDIAN_BYTES = GUARDIAN.read_bytes()
owner = types.ModuleType("application_browser_owner")
owner.__file__ = str(GUARDIAN)
# Bind execution to these exact source bytes rather than a timestamp-valid pyc.
exec(compile(GUARDIAN_BYTES, str(GUARDIAN), "exec"), owner.__dict__)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", required=True, type=int)
    parser.add_argument("--timeout", required=True, type=float)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    command = options.command
    if command[:1] == ["--"]:
        command = command[1:]
    result = {"schema": "marty.application-browser-process/v1", "status": "failed",
              "descendants_reaped": False,
              "guardian": {"path": "scripts/installer_startup_process.py",
                           "sha256": "sha256:" + hashlib.sha256(GUARDIAN_BYTES).hexdigest()}}
    status = 1
    try:
        # Caller death cancels this controller. Its separate subreaper observes
        # controller death and remains responsible for cleanup independently.
        owner._prctl(1, signal.SIGTERM)
        if options.parent <= 1 or os.getppid() != options.parent:
            raise owner.ProcessError("application browser caller is absent")
        output = owner.command(command, env=dict(os.environ), timeout=options.timeout, limit=1024 * 1024)
        result.update(status="passed", descendants_reaped=True, stdout_bytes=len(output),
                      stdout_sha256="sha256:" + hashlib.sha256(output).hexdigest())
        status = 0
    except owner.CleanupPending:
        # The isolated subreaper continues cleaning. The caller must preserve
        # the still-owned temporary profile and may not report success.
        result["status"] = "cleanup-pending"
        status = 75
    except owner.ProcessError as error:
        # This is the owner's explicit terminal failure after ECHILD. Other
        # ownership errors, including unexpected owner death, prove no cleanup.
        result["descendants_reaped"] = str(error) == "startup browser command failed after descendant cleanup"
    except (OSError, ValueError, TypeError):
        pass
    print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
