from __future__ import annotations

from credential_template.infrastructure.adapters.postgres_adapter import PostgresCredentialTemplateRepository


def test_legacy_seed_claims_without_ids_get_stable_ids() -> None:
    claim = {"name": "email", "claim_type": "string"}

    first = PostgresCredentialTemplateRepository._legacy_claim_id("template-1", 0, claim)
    second = PostgresCredentialTemplateRepository._legacy_claim_id("template-1", 0, claim)

    assert first == second
    assert first


def test_legacy_number_claim_type_maps_to_supported_type() -> None:
    assert PostgresCredentialTemplateRepository._claim_type_value("number") == "integer"
    assert PostgresCredentialTemplateRepository._claim_type_value("text") == "string"
