#!/usr/bin/env python3
"""Check native template write fixtures against an actual gateway export."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


def validate(document, fixtures):
    validators = {}
    for method, path, component in (
        ("POST", "/v1/credential-templates", "create"),
        ("PATCH", "/v1/credential-templates/{template_id}", "update"),
    ):
        operation = document["paths"][path][method.lower()]
        expected = {
            "$ref": f"#/components/schemas/runtime__credential_template_{component}_request"
        }
        request = operation["requestBody"]["content"]["application/json"]["schema"]
        if (
            request != expected
            or operation.get("x-marty-request-schema-documented") is not True
        ):
            raise ValueError("Template request binding is missing or incomplete")
        schema = {**request, "components": document["components"]}
        Draft202012Validator.check_schema(schema)
        validators[method] = Draft202012Validator(
            schema, format_checker=FormatChecker()
        )
    for method, key in [("POST", "valid_create"), ("PATCH", "valid_update")]:
        for case in fixtures[key]:
            validators[method].validate(case["public"])
    for case in fixtures["invalid"]:
        if validators[case["method"]].is_valid(case["public"]):
            raise ValueError(f"Template schema admits rejected fixture: {case['name']}")
    return {
        "valid_template_writes": len(fixtures["valid_create"])
        + len(fixtures["valid_update"]),
        "rejected_template_writes": len(fixtures["invalid"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openapi", type=Path, required=True)
    args = parser.parse_args()
    document = json.loads(args.openapi.read_bytes())
    fixtures = json.loads(
        (ROOT / "contracts/credential-template-write-behavior.json").read_bytes()
    )
    print(json.dumps(validate(document, fixtures), sort_keys=True))


if __name__ == "__main__":
    main()
