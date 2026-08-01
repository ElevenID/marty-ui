from pathlib import Path

import pytest

from scripts.check_public_protocol_contract import (
    _assert_generated_bindings_current,
)


def _write_generator(protocol_root: Path, source: str) -> None:
    scripts = protocol_root / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "codegen.py").write_text(source, encoding="utf-8")


def test_generated_binding_check_runs_all_targets_in_read_only_mode(tmp_path: Path) -> None:
    _write_generator(
        tmp_path,
        """\
import sys

if sys.argv[1:] != [\"--check\"]:
    raise SystemExit(2)
print(\"Generated bindings are current.\")
""",
    )

    _assert_generated_bindings_current(tmp_path)


def test_generated_binding_check_rejects_stale_clients(tmp_path: Path) -> None:
    _write_generator(
        tmp_path,
        """\
print(\"Generated bindings are stale: reference/typescript/src/models.ts\")
raise SystemExit(1)
""",
    )

    with pytest.raises(AssertionError, match="generated bindings are stale"):
        _assert_generated_bindings_current(tmp_path)


def test_generated_binding_check_rejects_missing_generator(tmp_path: Path) -> None:
    with pytest.raises(AssertionError, match="missing scripts/codegen.py"):
        _assert_generated_bindings_current(tmp_path)
