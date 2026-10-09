"""The retired beta cutover entrypoints must never reach host mutations."""

from pathlib import Path

import pytest

from scripts import prepare_passport_beta_native_migrations as legacy_sql


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


def test_retired_sql_handoff_cannot_construct_or_stage_migrations() -> None:
    for obsolete in ("build_sql", "checked_migrations", "stage_sql"):
        assert not hasattr(legacy_sql, obsolete)
    with pytest.raises(legacy_sql.NativeMigrationError, match="retired"):
        legacy_sql.prepare(Path("unused-manifest"), Path("unused-receipt"))
