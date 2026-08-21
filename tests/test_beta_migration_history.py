import json
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


ROOT = Path(__file__).resolve().parents[1]


def _history(relative_path: str) -> ScriptDirectory:
    config = Config()
    config.set_main_option("script_location", str(ROOT / relative_path))
    return ScriptDirectory.from_config(config)


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


def test_presentation_policy_history_contains_beta_revision_and_one_head() -> None:
    history = _history("services/presentation_policy/infrastructure/migrations")

    assert history.get_heads() == ["20260718_pp_0001"]
    assert history.get_revision("20260717_pp_0001") is not None
