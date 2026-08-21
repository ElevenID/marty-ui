from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).parents[3]


def test_every_python_migration_has_exactly_one_rust_owner() -> None:
    contract = json.loads(
        (ROOT / "contracts" / "credential-template-migration-history.json").read_text(
            encoding="utf-8"
        )
    )
    actual = {
        path.name
        for path in (
            ROOT / "services" / "credential_template" / "infrastructure" / "migrations" / "versions"
        ).glob("*.py")
    }
    owned = [
        revision
        for revisions in contract["rust_owners"].values()
        for revision in revisions
    ]
    assert len(owned) == contract["legacy_revision_count"] == 45
    assert len(set(owned)) == len(owned)
    assert set(owned) == actual
