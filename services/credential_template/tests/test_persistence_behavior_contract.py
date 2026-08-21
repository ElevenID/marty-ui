import json
from pathlib import Path

from credential_template.infrastructure.adapters.postgres_adapter import (
    PostgresCredentialTemplateRepository,
)


FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "contracts"
    / "credential-template-persistence-behavior.json"
)


def _contract() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_legacy_claim_ids_match_the_language_neutral_contract() -> None:
    for case in _contract()["legacy_claims"]:
        actual = PostgresCredentialTemplateRepository._legacy_claim_id(
            case["template_id"],
            case["index"],
            {"name": case["name"]},
        )
        assert actual == case["expected_id"]


def test_legacy_claim_type_aliases_match_the_language_neutral_contract() -> None:
    for legacy, canonical in _contract()["legacy_claim_type_aliases"].items():
        assert PostgresCredentialTemplateRepository._claim_type_value(legacy) == canonical
