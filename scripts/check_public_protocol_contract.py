#!/usr/bin/env python3
"""Fail when Marty public template responses drift from marty-protocol."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from fastapi import Response
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "services"))

from gateway.models import CredentialTemplateResponse  # noqa: E402
from gateway.routes.credentials import (  # noqa: E402
    _PUBLIC_TEMPLATE_RESPONSE_FIELDS,
    _sanitize_credential_template_response,
)


FORBIDDEN_PUBLIC_FIELDS = {
    "auto_generate_artifacts",
    "issuer_algorithm",
    "issuer_certificate_chain_pem",
    "issuer_key_id",
    "issuer_profile_id",
    "key_access_mode",
    "key_name",
    "key_reference",
    "key_version",
    "kms_provider",
    "provider",
    "remote_key_binding",
    "remote_signing_config",
    "service_id",
    "signing_key_reference",
    "signing_service_id",
    "transit_mount",
}


def _load_registry(protocol_root: Path) -> Registry:
    registry = Registry()
    for directory in ("schemas", "enums"):
        for path in sorted((protocol_root / directory).rglob("*.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                continue
            resource = Resource.from_contents(document)
            registry = registry.with_resource(path.resolve().as_uri(), resource)
            identifier = document.get("$id")
            if isinstance(identifier, str):
                registry = registry.with_resource(identifier, resource)
    return registry


def _property_names(value: object) -> set[str]:
    if isinstance(value, dict):
        result = set(value.get("properties", {}))
        for child in value.values():
            result.update(_property_names(child))
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for child in value:
            result.update(_property_names(child))
        return result
    return set()


def _public_response(
    *,
    credential_format: str,
    credential_type: str,
    vct: str | None = None,
    doctype: str | None = None,
    namespace: str | None = None,
) -> dict[str, Any]:
    claim = {
        "name": "given_name",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "display_name": "Given name",
        "mdoc_namespace": namespace,
        "mdoc_element_identifier": "given_name" if namespace else None,
        "pattern": "must-not-leak",
    }
    internal = {
        "id": "10000000-0000-4000-8000-000000000001",
        "organization_id": "20000000-0000-4000-8000-000000000001",
        "name": "Public contract fixture",
        "description": "Marty-owned response-contract fixture.",
        "status": "ACTIVE",
        "credential_type": credential_type,
        "compliance_profile_id": "30000000-0000-4000-8000-000000000001",
        "vct": vct,
        "doctype": doctype,
        "credential_payload_format": credential_format,
        "claims": [claim],
        "validity_rules": {"ttl_seconds": 3600, "renewable": False},
        "privacy_posture": {
            "default_disclose_all": False,
            "prefer_predicates": False,
            "sd_alg": "sha-256",
        },
        "issuer_did": "did:web:issuer.example.test",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "issuer_profile_id": "must-not-leak",
        "issuer_key_id": "must-not-leak",
        "issuer_algorithm": "must-not-leak",
        "signing_service_id": "must-not-leak",
        "key_access_mode": "must-not-leak",
        "remote_signing_config": {"provider": "must-not-leak"},
        "auto_generate_artifacts": True,
    }
    response = _sanitize_credential_template_response(
        Response(content=json.dumps(internal), media_type="application/json")
    )
    return json.loads(response.body)


def check_contract(protocol_root: Path) -> None:
    schema_path = protocol_root / "schemas" / "credential-template.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    registry = _load_registry(protocol_root)
    validator = Draft202012Validator(
        schema,
        registry=registry,
        format_checker=FormatChecker(),
    )

    schema_fields = set(schema["properties"])
    response_fields = set(CredentialTemplateResponse.model_fields)
    allowlist_fields = set(_PUBLIC_TEMPLATE_RESPONSE_FIELDS)
    if response_fields != schema_fields:
        raise AssertionError(
            "CredentialTemplateResponse fields drifted from marty-protocol: "
            f"schema_only={sorted(schema_fields - response_fields)}, "
            f"runtime_only={sorted(response_fields - schema_fields)}"
        )
    if allowlist_fields != schema_fields:
        raise AssertionError(
            "credential response allowlist drifted from marty-protocol: "
            f"schema_only={sorted(schema_fields - allowlist_fields)}, "
            f"runtime_only={sorted(allowlist_fields - schema_fields)}"
        )

    schema_required = set(schema["required"])
    runtime_required = {
        name
        for name, field in CredentialTemplateResponse.model_fields.items()
        if field.is_required()
    }
    if runtime_required != schema_required:
        raise AssertionError(
            "CredentialTemplateResponse required fields drifted from "
            f"marty-protocol: schema_only={sorted(schema_required - runtime_required)}, "
            f"runtime_only={sorted(runtime_required - schema_required)}"
        )

    leaked_schema_fields = FORBIDDEN_PUBLIC_FIELDS & _property_names(schema)
    if leaked_schema_fields:
        raise AssertionError(
            f"marty-protocol exposes custody selectors: {sorted(leaked_schema_fields)}"
        )

    responses = [
        _public_response(
            credential_format="SD_JWT_VC",
            credential_type="EmployeeCredential",
            vct="EmployeeCredential",
        ),
        _public_response(
            credential_format="MDOC",
            credential_type="org.iso.18013.5.1.mDL",
            doctype="org.iso.18013.5.1.mDL",
            namespace="org.iso.18013.5.1",
        ),
    ]
    for document in responses:
        validator.validate(document)
        leaked = FORBIDDEN_PUBLIC_FIELDS & _property_names(document)
        if leaked:
            raise AssertionError(
                f"runtime response exposes custody selectors: {sorted(leaked)}"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol-root", type=Path, required=True)
    args = parser.parse_args()
    check_contract(args.protocol_root.resolve())
    print("Public credential-template responses match the pinned marty-protocol schema.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
