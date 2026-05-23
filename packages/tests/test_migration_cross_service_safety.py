from pathlib import Path


def test_trust_profile_initial_migration_does_not_touch_credential_template_schema() -> None:
    migration_file = Path(
        "services/trust_profile/infrastructure/migrations/versions/"
        "20260203_0204_33f047612e9b_initial_trust_profile_schema.py"
    )
    content = migration_file.read_text(encoding="utf-8")

    forbidden_tokens = [
        "credential_template_service",
        "credential_templates",
        "ix_credential_template_service_credential_templates",
    ]

    for token in forbidden_tokens:
        assert token not in content, (
            "Trust-profile initial migration must not create/drop credential-template schema objects; "
            f"found forbidden token: {token}"
        )
