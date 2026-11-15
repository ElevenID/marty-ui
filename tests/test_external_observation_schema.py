"""Candidate envelope schema only; Gateway decoding and live admission are not enabled."""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "contracts/external-observation-v1.schema.json").read_bytes())
VALIDATOR = Draft202012Validator(SCHEMA)
BASE = {
    "binding_id": "synthetic-binding",
    "binding_revision": 7,
    "observation_id": "synthetic-observation",
    "sequence": 11,
    "observed_at_ms": 1_800_000_000_000,
    "effective_at_ms": 1_799_999_999_000,
    "claims": {"completed": True, "score": 95.0},
}


def test_candidate_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)
    VALIDATOR.validate(BASE)


@pytest.mark.parametrize("field", list(BASE))
def test_every_envelope_field_is_required(field):
    body = copy.deepcopy(BASE)
    del body[field]
    assert not VALIDATOR.is_valid(body)


@pytest.mark.parametrize("field", [
    "organization_id", "organizationId", "subject_id", "application_id", "provider",
    "source_id", "fact_type", "scope", "verified", "verification", "approved",
    "policy_allowed", "issuer_key", "signing_key", "api_key", "receipt_id",
])
def test_caller_cannot_add_authority_fields(field):
    body = copy.deepcopy(BASE)
    body[field] = "synthetic-forbidden"
    assert not VALIDATOR.is_valid(body)


@pytest.mark.parametrize("field", [
    "binding_revision", "sequence", "observed_at_ms", "effective_at_ms",
])
@pytest.mark.parametrize("value", [0, -1, 9_007_199_254_740_992, 1.5, True, "1", None])
def test_integer_authority_fields_use_safe_positive_json_integers(field, value):
    body = copy.deepcopy(BASE)
    body[field] = value
    assert not VALIDATOR.is_valid(body)


@pytest.mark.parametrize("field", ["binding_id", "observation_id"])
@pytest.mark.parametrize("value", ["", "x" * 129, "../foreign", "other/path", "x\ny", "learner@example.test", None])
def test_identifiers_cannot_be_empty_paths_or_oversized(field, value):
    body = copy.deepcopy(BASE)
    body[field] = value
    assert not VALIDATOR.is_valid(body)


@pytest.mark.parametrize("claims", [
    {}, [], None, {"": True}, {"x" * 129: True}, {"x/y": True},
    {"completed": {"verified": True}}, {"completed": [True]},
    {"name": ""}, {"name": "x" * 513}, {"name": "hidden\ncontrol"},
    {"name": "hidden\u0085control"}, {str(n): True for n in range(33)},
])
def test_claims_are_bounded_primitive_values_not_nested_documents(claims):
    body = copy.deepcopy(BASE)
    body["claims"] = claims
    assert not VALIDATOR.is_valid(body)


@pytest.mark.parametrize("claims", [
    {"completed": False}, {"score": None}, {"score": 0},
    {"name": "Synthetic learning activity"},
])
def test_unsigned_claim_types_are_supported_without_granting_trust(claims):
    body = copy.deepcopy(BASE)
    body["claims"] = claims
    VALIDATOR.validate(body)
    # Exact operator allowlists, finite numbers, timestamp ordering, UTF-8 byte
    # lengths and reserved claim names are additionally enforced by the Rust
    # admission owner. Schema validation alone is not admission or verification.
