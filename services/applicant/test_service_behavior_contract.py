from __future__ import annotations

import json
from pathlib import Path

from services.applicant.main import (
    ApplicantStatus,
    ApplicationStatus,
    ClaimState,
    EvidenceStatus,
    MAX_EVIDENCE_BYTES,
    InMemoryApplicantRepository,
    create_app,
)


ROOT = Path(__file__).resolve().parents[2]


def test_python_baseline_matches_language_neutral_applicant_contract() -> None:
    contract = json.loads(
        (ROOT / "contracts/applicant-service-behavior.json").read_text(
            encoding="utf-8"
        )
    )
    actual_operations = {
        (method, route.path)
        for route in create_app().routes
        for method in getattr(route, "methods", set())
        if route.path.startswith("/v1/")
    }
    expected_operations = {
        (operation["method"], operation["path"])
        for operation in contract["http_operations"]
    }

    assert actual_operations == expected_operations
    assert {status.value for status in ApplicantStatus} == set(
        contract["lifecycle_statuses"]
    )
    assert {status.value for status in ApplicationStatus} == set(
        contract["lifecycle_statuses"]
    )
    assert {status.value for status in ClaimState} == set(contract["claim_states"])
    assert {status.value for status in EvidenceStatus} == set(
        contract["evidence_statuses"]
    )
    assert MAX_EVIDENCE_BYTES == contract["maximum_evidence_bytes"]
    assert (
        InMemoryApplicantRepository.LOCK_TTL_SECONDS
        == contract["reviewer_lock_ttl_seconds"]
    )
