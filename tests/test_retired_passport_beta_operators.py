"""The retired beta cutover entrypoints must never reach host mutations."""

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
OPERATORS = (
    "start-passport-beta-db-maintenance.ps1",
    "run-passport-beta-native-db-gates.ps1",
    "run-passport-beta-aggregate-deploy.ps1",
)


@pytest.mark.parametrize("name", OPERATORS)
def test_retired_operator_has_only_a_terminal_diagnostic(name: str) -> None:
    source = (ROOT / "scripts" / name).read_text(encoding="utf-8")
    _, body = source.split("\n)\n", 1)
    statements = [line.strip() for line in body.splitlines() if line.strip()]
    assert len(statements) == 1
    assert statements[0].startswith("throw 'Historical passport beta ")
    assert statements[0].endswith("fresh Rust-owned deployment path'")
