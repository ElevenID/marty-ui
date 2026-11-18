import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_credential_template_history_is_consolidated_into_native_migrations() -> None:
    contract = json.loads(
        (ROOT / "contracts/credential-template-migration-history.json").read_text(
            encoding="utf-8"
        )
    )
    assigned_revisions = [
        revision
        for revisions in contract["rust_owners"].values()
        for revision in revisions
    ]
    reconciliation = (
        ROOT
        / "rust/services/credential-template/migrations/0002_legacy_data_reconciliation.sql"
    ).read_text(encoding="utf-8")

    assert contract["legacy_revision_count"] == 45
    assert len(assigned_revisions) == 45
    assert len(set(assigned_revisions)) == 45
    assert "rust_credential_template_0002" in reconciliation
    assert not (ROOT / "services/credential_template").exists()


def test_presentation_policy_history_is_consolidated_into_native_owners() -> None:
    contract = json.loads(
        (ROOT / "contracts/presentation-policy-migration-history.json").read_text(
            encoding="utf-8"
        )
    )
    assigned_revisions = [
        revision
        for revisions in contract["rust_owners"].values()
        for revision in revisions
    ]

    assert contract["legacy_revision_count"] == 9
    assert len(assigned_revisions) == 9
    assert len(set(assigned_revisions)) == 9
    assert (
        ROOT / "rust/services/presentation-policy/migrations/0001_presentation_policy.sql"
    ).is_file()
    assert (ROOT / "rust/services/presentation-policy/src/catalog.rs").is_file()
    assert not list((ROOT / "services/presentation_policy").rglob("*.*"))
