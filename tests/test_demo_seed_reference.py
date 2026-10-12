"""The live demo seed commands must work without the retired Python package."""

from __future__ import annotations

import json
import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = json.loads(
    (ROOT / "contracts/demo-seed-reference-v1.json").read_text(encoding="utf-8")
)


def test_demo_seed_reference_keeps_released_identifiers_and_catalog() -> None:
    assert REFERENCE["schema"] == "marty.demo-seed-reference/v1"
    assert REFERENCE["source"]["commit"] == "36bb2aac65759edc2ccdce120e16a61391a7ce32"
    ids = REFERENCE["canvas_system_ids"]
    assert ids == {
        "MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_APPLICATION_TEMPLATE_ID":
            "0ab66d45-0d84-5fbd-837f-25788d3227a1",
        "MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_TEMPLATE_ID":
            "50000000-0000-0000-0000-000000000041",
        "MARTY_DEFAULT_ORG_ID": "00000000-0000-0000-0000-000000000001",
        "MARTY_VERIFIED_MEMBER_BADGE_APPLICATION_TEMPLATE_ID":
            "0ab66d45-0d84-5fbd-837f-25788d32279e",
        "MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID":
            "50000000-0000-0000-0000-000000000040",
    }
    bundle = REFERENCE["vendor_bundle"]
    assert bundle["organization"]["id"] == "22222222-2222-2222-2222-222222222222"
    assert len(bundle["credential_types"]) == 7
    assert len(bundle["credential_templates"]) == 8


def test_provenance_uses_canonical_git_blob_bytes() -> None:
    source = REFERENCE["source"]
    source_paths = {
        "system_ids_sha256": (
            "packages/marty-common/marty_common/system_ids.py",
            "5dcac6ed7719d0bdc32e8948a2ce803112c660a7b0ecd04164fed0ff562f5717",
        ),
        "demo_seed_data_sha256": (
            "packages/marty-common/marty_common/demo_seed_data.py",
            "2c4b71cdc775e167e10e9b47e5b629dcf53b3e771dd6769f135dbb8a12d1bc83",
        ),
    }
    marty_checkout = ROOT.parent.parent / "Marty"
    for field, (path, expected) in source_paths.items():
        assert source[field] == expected
        if (marty_checkout / ".git").exists():
            blob = subprocess.run(
                ["git", "-C", str(marty_checkout), "show", f"{source['commit']}:{path}"],
                capture_output=True,
                check=True,
            ).stdout
            assert hashlib.sha256(blob).hexdigest() == expected


def test_live_seed_commands_start_without_marty_common() -> None:
    for script in ("seed_canvas_real.py", "seed_demo_vendor_fixtures.py"):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / script), "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, (script, result.stderr)
        assert "--env-file" in result.stdout


def test_demo_vendor_seed_rejects_persistent_alias_without_database(monkeypatch, capsys) -> None:
    from scripts import seed_demo_vendor_fixtures as seed

    monkeypatch.setenv("MARTY_MIGRATION_PROFILE", "selfhost_prod")
    monkeypatch.setattr(sys, "argv", ["seed_demo_vendor_fixtures.py", "--env-file", "missing.env"])
    assert seed.main() == 2
    assert "selfhost-production" in capsys.readouterr().err
