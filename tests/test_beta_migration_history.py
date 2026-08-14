from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


ROOT = Path(__file__).resolve().parents[1]


def _history(relative_path: str) -> ScriptDirectory:
    config = Config()
    config.set_main_option("script_location", str(ROOT / relative_path))
    return ScriptDirectory.from_config(config)


def test_credential_template_history_contains_beta_revision_and_one_head() -> None:
    history = _history("services/credential_template/infrastructure/migrations")

    assert history.get_heads() == ["20260814_ct_0001"]
    assert history.get_revision("20260717_0001") is not None
    assert history.get_revision("20260801_0003") is not None
    assert history.get_revision("20260806_0002") is not None
    assert history.get_revision("20260811_ct_0001") is not None


def test_presentation_policy_history_contains_beta_revision_and_one_head() -> None:
    history = _history("services/presentation_policy/infrastructure/migrations")

    assert history.get_heads() == ["20260718_pp_0001"]
    assert history.get_revision("20260717_pp_0001") is not None
