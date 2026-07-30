from __future__ import annotations

import runpy
from pathlib import Path


def test_custody_metadata_migration_removes_deprecated_fields_recursively() -> None:
    migration = runpy.run_path(
        str(
            Path(__file__).parents[1]
            / "infrastructure"
            / "migrations"
            / "versions"
            / "20260730_0001_remove_deprecated_trust_profile_key_metadata.py"
        )
    )

    assert migration["_sanitize"](
        {
            "owner": "trust-team",
            "key_management": {"kms_arn": "arn:aws:kms:private"},
            "nested": {
                "purpose": "verification",
                "key_binding": {"managed_key_id": "private"},
                "items": [
                    {"name": "safe"},
                    {"signing_agent_url": "https://private.invalid"},
                ],
            },
        }
    ) == {
        "owner": "trust-team",
        "nested": {
            "purpose": "verification",
            "items": [{"name": "safe"}, {}],
        },
    }
