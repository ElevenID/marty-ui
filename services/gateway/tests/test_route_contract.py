"""Guard the implementation-independent gateway route and middleware contract."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[3]


def test_gateway_route_contract_is_current() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/gateway_route_contract.py", "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr or result.stdout
