"""Native owner fixtures and public/private trust readback schema boundaries."""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = json.loads((ROOT / "contracts/trust-profile-readback-schemas.json").read_bytes())
CASES = json.loads((ROOT / "contracts/trust-profile-readback-behavior.json").read_bytes())["cases"]
PRIVACY = json.loads((ROOT / "contracts/trust-profile-override-boundary.json").read_bytes())
VALIDATOR = Draft202012Validator({"$ref":"#/components/schemas/runtime__trust_profile_response", "components":{"schemas":SCHEMAS}}, format_checker=FormatChecker())


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_native_owner_public_response(case):
    VALIDATOR.validate(case["expected"])


@pytest.mark.parametrize("case", PRIVACY["rejected"], ids=lambda case: case["name"])
def test_private_override_is_not_a_public_readback(case):
    payload = copy.deepcopy(CASES[0]["expected"])
    payload["system_issuer_overrides"] = case["overrides"]
    assert not VALIDATOR.is_valid(payload)


@pytest.mark.parametrize("case", PRIVACY["supported"], ids=lambda case: case["name"])
def test_public_overrides_remain_supported(case):
    payload = copy.deepcopy(CASES[0]["expected"])
    payload["system_issuer_overrides"] = case["overrides"]
    VALIDATOR.validate(payload)


@pytest.mark.parametrize("field,value", [("status","ACTIVE"),("description",None),("organization_id",3),("created_at","not-a-date"),("provider","private"),("supported_formats",[]),("supported_formats",["MDOC","MDOC"]),("trust_sources",[{"source_type":"ROOT_CA","pinned_certificates":[],"registry_sync_token":"private"}])])
def test_native_types_and_public_projection_are_enforced(field,value):
    payload = copy.deepcopy(CASES[0]["expected"])
    payload[field] = value
    assert not VALIDATOR.is_valid(payload)


@pytest.mark.parametrize("index,field", [(0,"supported_formats"),(1,"trusted_assertion_formats")])
def test_credential_and_machine_require_their_own_format_contract(index,field):
    payload = copy.deepcopy(CASES[index]["expected"])
    del payload[field]
    assert not VALIDATOR.is_valid(payload)
