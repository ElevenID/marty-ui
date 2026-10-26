#!/usr/bin/env python3
"""Validate native organization readbacks against an actual gateway export."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
COLLECTIONS = (
    "/v1/organizations",
    "/v1/organizations/discover",
    "/v1/organizations/mine",
)


def validate(document, behavior):
    """Use the same readback cases exercised by the gateway's typed projector."""
    cases = [behavior["expected_response"]]
    cases.extend(case["expected"] for case in behavior["response_cases"])
    for path in COLLECTIONS:
        operation = document["paths"][path]["get"]
        if operation.get("x-marty-response-schema-documented") is not True:
            raise ValueError(f"Undocumented organization response: {path}")
        response = operation["responses"]["200"]["content"]["application/json"]["schema"]
        if response != {"type": "array", "items": {"$ref": "#/components/schemas/schemas__organization"}}:
            raise ValueError(f"Organization collection is not the native array: {path}")
        schema = {**response, "components": document["components"]}
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        for payload in ([], cases):
            validator.validate(payload)
        # An envelope or private fields must not silently become public output.
        private = copy.deepcopy(cases[0])
        private[behavior["private_response_field"]] = {"private": True}
        for invalid in ({"items": cases}, [private], [{"id": cases[0]["id"]}]):
            if validator.is_valid(invalid):
                raise ValueError(f"Organization schema admits an invalid/private response: {path}")
    return {"organization_collections": len(COLLECTIONS), "readback_cases": len(cases)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openapi", type=Path, required=True)
    args = parser.parse_args()
    document = json.loads(args.openapi.read_bytes())
    behavior = json.loads((ROOT / "contracts/gateway-organization-behavior.json").read_bytes())
    print(json.dumps(validate(document, behavior), sort_keys=True))


if __name__ == "__main__":
    main()
