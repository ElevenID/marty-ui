from pathlib import Path


def test_flow_migrations_do_not_mutate_presentation_policy_schema():
    versions = Path(__file__).parent / "infrastructure" / "migrations" / "versions"

    for migration in versions.glob("*.py"):
        source = migration.read_text(encoding="utf-8")
        assert "presentation_policy_service" not in source, (
            f"{migration.name} crosses the Flow service ownership boundary"
        )
