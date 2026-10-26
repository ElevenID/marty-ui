#!/usr/bin/env python3
"""Validate native trust readbacks against an actual gateway export."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = (
    ("get", "/v1/trust-profiles"), ("post", "/v1/trust-profiles"),
    ("get", "/v1/trust-profiles/{profile_id}"), ("patch", "/v1/trust-profiles/{profile_id}"),
    ("post", "/v1/trust-profiles/{profile_id}/activate"),
)


def validate(document, behavior, privacy):
    for name, component in document["components"]["schemas"].items():
        if name in {"runtime__trust_profile_response", "runtime__trust_source", "runtime__trust_did_resolution", "runtime__trust_public_value"}:
            Draft202012Validator.check_schema(component)
    cases = [case["expected"] for case in behavior["cases"]]
    rejected = []
    for case in privacy["rejected"]:
        bad = copy.deepcopy(cases[0])
        bad["system_issuer_overrides"] = case["overrides"]
        rejected.append(bad)
    for field, value in [("provider", "private"), ("status", "ACTIVE"),
                         ("description", None), ("organization_id", 3)]:
        bad = copy.deepcopy(cases[0])
        bad[field] = value
        rejected.append(bad)
    bad = copy.deepcopy(cases[1])
    del bad["trusted_assertion_formats"]
    rejected.append(bad)
    bad = copy.deepcopy(cases[0])
    del bad["supported_formats"]
    rejected.append(bad)
    for method, path in OPERATIONS:
        operation = document["paths"][path][method]
        if operation.get("x-marty-response-schema-documented") is not True:
            raise ValueError(f"Undocumented native trust readback: {method} {path}")
        schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
        expected = {"$ref": "#/components/schemas/runtime__trust_profile_response"}
        many = method == "get" and path == "/v1/trust-profiles"
        if schema != ({"type": "array", "items": expected} if many else expected):
            raise ValueError(f"Wrong native trust component: {method} {path}")
        schema = {**schema, "components": document["components"]}
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        for case in cases:
            validator.validate([case] if many else case)
        for bad in rejected:
            if validator.is_valid([bad] if many else bad):
                raise ValueError(f"Private/invalid trust readback admitted: {method} {path}")
        if many:
            validator.validate([])
        if many and validator.is_valid({"items": cases}):
            raise ValueError("Invented trust collection envelope admitted")
    deleted = document["paths"]["/v1/trust-profiles/{profile_id}"]["delete"]["responses"]["200"]["content"]["application/json"]["schema"]
    deletion = Draft202012Validator(deleted)
    deletion.validate({"success": True})
    if any(deletion.is_valid(value) for value in ({"success": False}, {}, {"success": True, "provider": "private"})):
        raise ValueError("Trust deletion contract is not the exact native success object")
    query = {p["name"]: p["schema"] for p in document["paths"]["/v1/trust-profiles"]["get"]["parameters"]}
    for name, default in [("limit", 100), ("offset", 0)]:
        if query[name] != {"type": "integer", "minimum": 0, "maximum": 18446744073709551615, "default": default}:
            raise ValueError(f"Wrong native trust pagination: {name}")
    return {"native_trust_operations": len(OPERATIONS), "owner_readbacks": len(cases), "rejected_readbacks": len(rejected), "delete_success_contract": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openapi", type=Path, required=True)
    args = parser.parse_args()
    document = json.loads(args.openapi.read_bytes())
    behavior = json.loads((ROOT / "contracts/trust-profile-readback-behavior.json").read_bytes())
    privacy = json.loads((ROOT / "contracts/trust-profile-override-boundary.json").read_bytes())
    print(json.dumps(validate(document, behavior, privacy), sort_keys=True))


if __name__ == "__main__":
    main()
