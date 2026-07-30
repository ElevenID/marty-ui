#!/usr/bin/env python3
"""Fail when Marty public operations drift from the pinned marty-protocol."""

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

from gateway.models import (  # noqa: E402
    CredentialTemplateResponse,
    IssuanceCreate,
    OrganizationTrustProfileResponse,
    PUBLIC_ISSUANCE_RESERVED_CLAIMS,
    StartVerificationFlowRequest,
    VerificationRequestResponse,
)
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
    "key_binding",
    "key_access_mode",
    "key_management",
    "key_name",
    "key_reference",
    "key_version",
    "kms_arn",
    "kms_provider",
    "kms_region",
    "managed_key_id",
    "provider",
    "remote_key_binding",
    "remote_signing_config",
    "service_id",
    "signing_agent_auth",
    "signing_agent_url",
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


def _assert_model_shape(
    *,
    model: Any,
    schema: dict[str, Any],
    label: str,
) -> None:
    schema_fields = set(schema["properties"])
    runtime_fields = set(model.model_fields)
    if runtime_fields != schema_fields:
        raise AssertionError(
            f"{label} fields drifted from marty-protocol: "
            f"schema_only={sorted(schema_fields - runtime_fields)}, "
            f"runtime_only={sorted(runtime_fields - schema_fields)}"
        )

    schema_required = set(schema.get("required", []))
    runtime_required = {
        name for name, field in model.model_fields.items() if field.is_required()
    }
    if runtime_required != schema_required:
        raise AssertionError(
            f"{label} required fields drifted from marty-protocol: "
            f"schema_only={sorted(schema_required - runtime_required)}, "
            f"runtime_only={sorted(runtime_required - schema_required)}"
        )


def _validator(
    protocol_root: Path,
    registry: Registry,
    filename: str,
) -> tuple[dict[str, Any], Draft202012Validator]:
    schema = json.loads(
        (protocol_root / "schemas" / filename).read_text(encoding="utf-8")
    )
    return schema, Draft202012Validator(
        schema,
        registry=registry,
        format_checker=FormatChecker(),
    )


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

    trust_profile_schema_path = (
        protocol_root / "schemas" / "organization-trust-profile.json"
    )
    trust_profile_schema = json.loads(
        trust_profile_schema_path.read_text(encoding="utf-8")
    )
    trust_profile_validator = Draft202012Validator(
        trust_profile_schema,
        registry=registry,
        format_checker=FormatChecker(),
    )
    trust_profile_schema_fields = set(trust_profile_schema["properties"])
    trust_profile_runtime_fields = set(OrganizationTrustProfileResponse.model_fields)
    if trust_profile_runtime_fields != trust_profile_schema_fields:
        raise AssertionError(
            "OrganizationTrustProfileResponse fields drifted from marty-protocol: "
            f"schema_only={sorted(trust_profile_schema_fields - trust_profile_runtime_fields)}, "
            f"runtime_only={sorted(trust_profile_runtime_fields - trust_profile_schema_fields)}"
        )

    trust_profile_schema_required = set(trust_profile_schema["required"])
    trust_profile_runtime_required = {
        name
        for name, field in OrganizationTrustProfileResponse.model_fields.items()
        if field.is_required()
    }
    if trust_profile_runtime_required != trust_profile_schema_required:
        raise AssertionError(
            "OrganizationTrustProfileResponse required fields drifted from "
            "marty-protocol: "
            f"schema_only={sorted(trust_profile_schema_required - trust_profile_runtime_required)}, "
            f"runtime_only={sorted(trust_profile_runtime_required - trust_profile_schema_required)}"
        )

    leaked_schema_fields = FORBIDDEN_PUBLIC_FIELDS & _property_names(
        trust_profile_schema
    )
    if leaked_schema_fields:
        raise AssertionError(
            "marty-protocol Organization Trust Profile exposes custody selectors: "
            f"{sorted(leaked_schema_fields)}"
        )

    trust_profile_response = OrganizationTrustProfileResponse(
        id="40000000-0000-4000-8000-000000000001",
        organization_id="20000000-0000-4000-8000-000000000001",
        framework_id="50000000-0000-4000-8000-000000000001",
        name="eudi-verification",
        display_name="EUDI verification",
        compliance_status="COMPLIANT",
        allowed_algorithms=["ES256"],
        allowed_formats=["SD_JWT_VC", "MDOC"],
        metadata={"owner": "trust-team"},
        created_at="2026-01-01T00:00:00Z",
    ).model_dump(mode="json", exclude_none=True)
    trust_profile_validator.validate(trust_profile_response)
    leaked = FORBIDDEN_PUBLIC_FIELDS & _property_names(trust_profile_response)
    if leaked:
        raise AssertionError(
            "runtime Organization Trust Profile response exposes custody selectors: "
            f"{sorted(leaked)}"
        )

    issuance_schema, issuance_validator = _validator(
        protocol_root,
        registry,
        "issuance-request.json",
    )
    _assert_model_shape(
        model=IssuanceCreate,
        schema=issuance_schema,
        label="IssuanceCreate",
    )
    schema_reserved_claims = set(
        issuance_schema["properties"]["claims"]["propertyNames"]["not"]["enum"]
    )
    if schema_reserved_claims != set(PUBLIC_ISSUANCE_RESERVED_CLAIMS):
        raise AssertionError(
            "Issuance reserved-claim boundary drifted from marty-protocol: "
            f"schema_only={sorted(schema_reserved_claims - PUBLIC_ISSUANCE_RESERVED_CLAIMS)}, "
            f"runtime_only={sorted(PUBLIC_ISSUANCE_RESERVED_CLAIMS - schema_reserved_claims)}"
        )
    issuance = IssuanceCreate(
        organization_id="20000000-0000-4000-8000-000000000001",
        issuer_did="did:web:issuer.example.test",
        subject_did="did:example:holder",
        claims={"given_name": "Ada"},
    ).model_dump(mode="json", exclude_none=True)
    issuance_validator.validate(issuance)

    verification_request_schema, verification_request_validator = _validator(
        protocol_root,
        registry,
        "verification-flow-start-request.json",
    )
    _assert_model_shape(
        model=StartVerificationFlowRequest,
        schema=verification_request_schema,
        label="StartVerificationFlowRequest",
    )
    verification_request = StartVerificationFlowRequest(
        presentation_policy_id="30000000-0000-4000-8000-000000000001",
        organization_id="20000000-0000-4000-8000-000000000001",
        issuer_did="did:web:verifier.example.test",
        request_uri_method="post",
    ).model_dump(mode="json", exclude_none=True)
    verification_request_validator.validate(verification_request)

    verification_response_schema, verification_response_validator = _validator(
        protocol_root,
        registry,
        "verification-flow-start-response.json",
    )
    _assert_model_shape(
        model=VerificationRequestResponse,
        schema=verification_response_schema,
        label="VerificationRequestResponse",
    )
    verification_response = VerificationRequestResponse(
        instance_id="flow-instance",
        request_uri="openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test",
        qr_code_data="openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test",
        presentation_policy_id="30000000-0000-4000-8000-000000000001",
        nonce="a-high-entropy-nonce-value",
        expires_at="2026-07-30T20:00:00Z",
        status="AWAITING_WALLET",
    ).model_dump(mode="json")
    verification_response_validator.validate(verification_response)

    for model in (IssuanceCreate, StartVerificationFlowRequest):
        leaked_runtime_fields = FORBIDDEN_PUBLIC_FIELDS & set(model.model_fields)
        if leaked_runtime_fields:
            raise AssertionError(
                f"{model.__name__} exposes custody selectors: "
                f"{sorted(leaked_runtime_fields)}"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol-root", type=Path, required=True)
    args = parser.parse_args()
    check_contract(args.protocol_root.resolve())
    print("Public operations match the pinned marty-protocol schemas.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
