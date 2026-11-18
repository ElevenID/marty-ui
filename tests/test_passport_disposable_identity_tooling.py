"""Direct demo entrypoints must load the moved test-only identity helper."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_producer_entrypoints_import_without_pythonpath() -> None:
    environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    for name in ("passport_supported_provisioning_producer.py",
                 "passport_supported_protected_producer.py"):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / name), "--help"],
            cwd=ROOT, env=environment, capture_output=True, text=True,
            timeout=20, check=False,
        )
        assert result.returncode == 0, (name, result.stderr)
