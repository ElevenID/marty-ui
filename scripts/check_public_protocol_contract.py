#!/usr/bin/env python3
"""Fail when Marty public operations drift from the pinned marty-protocol."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from check_generated_protocol_bindings import assert_generated_bindings_current
from fastapi import Response
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "services"))

from gateway.models import (  # noqa: E402
    PUBLIC_ISSUANCE_RESERVED_CLAIMS,
    CredentialRenewalOfferResponse,
    CredentialTemplateResponse,
    DidcommDeliverRequest,
    DidcommDeliveryResponse,
    FlowDefinitionCreate,
    FlowDefinitionResponse,
    FlowDefinitionUpdate,
    FlowInstanceCreate,
    FlowInstanceResponse,
    IssuanceCreate,
    IssuanceResponse,
    IssuanceTransactionResponse,
    IssuedCredentialLifecycleRequest,
    IssuedCredentialRecordResponse,
    IssuerEntityCreate,
    IssuerEntityResponse,
    IssuerEntityUpdate,
    IssuerIdentityCertificateRequest,
    IssuerIdentityCreateRequest,
    IssuerIdentityCreateResponse,
    IssuerIdentityDeleteResponse,
    IssuerIdentityListResponse,
    IssuerIdentityOperationRequest,
    IssuerIdentityResolutionResponse,
    IssuerIdentityResponse,
    OrganizationCreate,
    OrganizationResponse,
    OrganizationTrustProfileResponse,
    OrganizationUpdate,
    PresentationPolicyCreate,
    PresentationPolicyResponse,
    PresentationPolicyUpdate,
    StartVerificationFlowRequest,
    TrustProfileIssuerCreate,
    TrustProfileIssuerResponse,
    TrustProfileIssuerUpdate,
    VerificationRequestResponse,
    VerificationResultResponse,
)
from gateway.routes.credentials import (  # noqa: E402
    _PUBLIC_TEMPLATE_RESPONSE_FIELDS,
    _sanitize_credential_template_response,
)
from gateway.routes.organizations import (  # noqa: E402
    _sanitize_organization_response,
    _validated_organization_payload,
)
from gateway.routes.trust import (  # noqa: E402
    _sanitize_issuer_entity_response,
    _sanitize_trust_profile_issuer_response,
    _validated_issuer_entity_payload,
    _validated_trust_profile_issuer_payload,
)
from gateway.routes.verification import (  # noqa: E402
    _PUBLIC_PRESENTATION_POLICY_FIELDS,
    _sanitize_presentation_policy_response,
    _validated_policy_payload,
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
    "resolver_url",
    "service_id",
    "signing_agent_auth",
    "signing_agent_url",
    "signing_key_reference",
    "signing_service_id",
    "transit_mount",
    "universal_resolver_url",
    "verification_method_id",
}

FORBIDDEN_ORGANIZATION_FIELDS = FORBIDDEN_PUBLIC_FIELDS | {
    "settings",
    "plan",
    "plan_expires_at",
}

FORBIDDEN_FLOW_FIELDS = FORBIDDEN_PUBLIC_FIELDS | {
    "access_token",
    "api_key",
    "client_secret",
    "pre-auth_code",
    "pre-authorized_code",
    "pre_auth_code",
    "private_key",
    "private_key_jwk",
    "refresh_token",
    "session_token",
}

TRUST_CONFIGURATION_UI_PATHS = (
    "ui/src/components/console/trust/TrustProfileWizard.jsx",
    "ui/src/components/console/trust/steps/TrustSourcesStep.jsx",
)

FORBIDDEN_TRUST_CONFIGURATION_TOKENS = {
    "issuer_profile_id",
    "issuer_key_id",
    "kms_key_id",
    "kms_provider",
    "signing_key_reference",
    "signing_service_id",
    "verification_keys",
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
    assert_generated_bindings_current(protocol_root)

    for relative_path in TRUST_CONFIGURATION_UI_PATHS:
        source = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        leaked_tokens = {
            token for token in FORBIDDEN_TRUST_CONFIGURATION_TOKENS if token in source
        }
        if leaked_tokens:
            raise AssertionError(
                f"{relative_path} bypasses the DID-only trust boundary with: "
                f"{sorted(leaked_tokens)}"
            )

    schema_path = protocol_root / "schemas" / "credential-template.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    registry = _load_registry(protocol_root)

    organization_schema, organization_validator = _validator(
        protocol_root,
        registry,
        "organization.json",
    )
    _assert_model_shape(
        model=OrganizationResponse,
        schema=organization_schema,
        label="OrganizationResponse",
    )
    organization_internal = {
        "id": "20000000-0000-4000-8000-000000000001",
        "name": "example-issuer",
        "display_name": "Example Issuer",
        "description": "Example tenant",
        "join_code": None,
        "visibility": "PUBLIC",
        "owner_id": "owner-subject",
        "status": "active",
        "org_type": "enterprise",
        "join_mechanism": "open",
        "requires_approval": True,
        "is_discoverable": True,
        "contact_email": "operator@example.com",
        "contact_phone": None,
        "website": "https://example.com",
        "membership": None,
        "created_at": "2026-07-31T00:00:00Z",
        "updated_at": "2026-07-31T00:00:00Z",
    }
    organization_response = _sanitize_organization_response(
        Response(
            content=json.dumps(organization_internal),
            media_type="application/json",
        )
    )
    if organization_response.status_code != 200:
        raise AssertionError("valid Organization response failed runtime sanitization")
    organization_validator.validate(json.loads(organization_response.body))

    private_organization = {**organization_internal, "settings": {"private": True}}
    rejected_private_organization = _sanitize_organization_response(
        Response(
            content=json.dumps(private_organization),
            media_type="application/json",
        )
    )
    if rejected_private_organization.status_code != 502:
        raise AssertionError("private Organization state did not fail closed")

    organization_create_schema, organization_create_validator = _validator(
        protocol_root,
        registry,
        "organization-create-request.json",
    )
    _assert_model_shape(
        model=OrganizationCreate,
        schema=organization_create_schema,
        label="OrganizationCreate",
    )
    organization_create = OrganizationCreate(
        name="example-issuer",
        display_name="Example Issuer",
        org_type="healthcare",
        visibility="PUBLIC",
        join_mechanism="open",
        requires_approval=True,
    )
    organization_create_validator.validate(
        json.loads(_validated_organization_payload(organization_create))
    )

    organization_update_schema, organization_update_validator = _validator(
        protocol_root,
        registry,
        "organization-update-request.json",
    )
    _assert_model_shape(
        model=OrganizationUpdate,
        schema=organization_update_schema,
        label="OrganizationUpdate",
    )
    organization_update = OrganizationUpdate(
        organization_id="20000000-0000-4000-8000-000000000001",
        display_name="Updated Example Issuer",
    )
    organization_update_validator.validate(
        json.loads(_validated_organization_payload(organization_update))
    )

    for document in (
        organization_schema,
        organization_create_schema,
        organization_update_schema,
    ):
        leaked = FORBIDDEN_ORGANIZATION_FIELDS & _property_names(document)
        if leaked:
            raise AssertionError(
                f"marty-protocol Organization boundary exposes private fields: {sorted(leaked)}"
            )
    for model in (OrganizationCreate, OrganizationUpdate, OrganizationResponse):
        leaked = FORBIDDEN_ORGANIZATION_FIELDS & set(model.model_fields)
        if leaked:
            raise AssertionError(
                f"runtime Organization boundary exposes private fields: {sorted(leaked)}"
            )

    issuer_entity_schema, issuer_entity_validator = _validator(
        protocol_root,
        registry,
        "issuer-entity.json",
    )
    _assert_model_shape(
        model=IssuerEntityResponse,
        schema=issuer_entity_schema,
        label="IssuerEntityResponse",
    )
    issuer_entity_internal = {
        "id": "10000000-0000-4000-8000-000000000001",
        "organization_id": "20000000-0000-4000-8000-000000000001",
        "issuer_id": "did:web:issuer.example",
        "issuer_type": "ORGANIZATION",
        "display_name": "Example Issuer",
        "description": "Tenant trust-registry entry",
        "is_system_issuer": False,
        "compliance_status": "COMPLIANT",
        "accreditation_body": None,
        "accreditation_date": None,
        "valid_from": "2026-08-01T00:00:00Z",
        "valid_until": None,
        "trust_anchor_id": None,
        "revoked_at": None,
        "revocation_reason": None,
        "revoked_by": None,
        "metadata": {"jurisdiction": "US"},
        "created_at": "2026-08-01T00:00:00Z",
        "updated_at": "2026-08-01T00:00:00Z",
    }
    issuer_entity_response = _sanitize_issuer_entity_response(
        Response(
            content=json.dumps(issuer_entity_internal),
            media_type="application/json",
        )
    )
    if issuer_entity_response.status_code != 200:
        raise AssertionError("valid IssuerEntity failed runtime sanitization")
    issuer_entity_validator.validate(json.loads(issuer_entity_response.body))

    private_issuer_entity = {
        **issuer_entity_internal,
        "metadata": {"nested": {"signing_service_id": "must-not-leak"}},
    }
    rejected_private_issuer = _sanitize_issuer_entity_response(
        Response(
            content=json.dumps(private_issuer_entity),
            media_type="application/json",
        )
    )
    if rejected_private_issuer.status_code != 502:
        raise AssertionError("private IssuerEntity metadata did not fail closed")

    issuer_entity_create_schema, issuer_entity_create_validator = _validator(
        protocol_root,
        registry,
        "issuer-entity-create-request.json",
    )
    _assert_model_shape(
        model=IssuerEntityCreate,
        schema=issuer_entity_create_schema,
        label="IssuerEntityCreate",
    )
    issuer_entity_create = IssuerEntityCreate(
        organization_id="20000000-0000-4000-8000-000000000001",
        issuer_id="did:web:issuer.example",
        display_name="Example Issuer",
        metadata={"jurisdiction": "US"},
    )
    issuer_entity_create_validator.validate(
        json.loads(_validated_issuer_entity_payload(issuer_entity_create))
    )

    issuer_entity_update_schema, issuer_entity_update_validator = _validator(
        protocol_root,
        registry,
        "issuer-entity-update-request.json",
    )
    _assert_model_shape(
        model=IssuerEntityUpdate,
        schema=issuer_entity_update_schema,
        label="IssuerEntityUpdate",
    )
    issuer_entity_update = IssuerEntityUpdate(
        organization_id="20000000-0000-4000-8000-000000000001",
        display_name="Updated Example Issuer",
    )
    issuer_entity_update_validator.validate(
        json.loads(_validated_issuer_entity_payload(issuer_entity_update))
    )

    trust_profile_issuer_schema, trust_profile_issuer_validator = _validator(
        protocol_root,
        registry,
        "trust-profile-issuer.json",
    )
    _assert_model_shape(
        model=TrustProfileIssuerResponse,
        schema=trust_profile_issuer_schema,
        label="TrustProfileIssuerResponse",
    )
    trust_profile_issuer_internal = {
        "id": "30000000-0000-4000-8000-000000000001",
        "trust_profile_id": "40000000-0000-4000-8000-000000000001",
        "issuer_id": issuer_entity_internal["id"],
        "trust_level": 100,
        "relationship_status": "TRUSTED",
        "cascade_revocation_policy": "NOTIFY_ONLY",
        "metadata": {"credential_template_ids": ["template-1"]},
        "created_at": "2026-08-01T00:00:00Z",
        "updated_at": "2026-08-01T00:00:00Z",
    }
    trust_profile_issuer_response = _sanitize_trust_profile_issuer_response(
        Response(
            content=json.dumps(trust_profile_issuer_internal),
            media_type="application/json",
        )
    )
    if trust_profile_issuer_response.status_code != 200:
        raise AssertionError("valid TrustProfileIssuer failed runtime sanitization")
    trust_profile_issuer_validator.validate(
        json.loads(trust_profile_issuer_response.body)
    )

    trust_profile_issuer_create_schema, trust_profile_issuer_create_validator = (
        _validator(
            protocol_root,
            registry,
            "trust-profile-issuer-create-request.json",
        )
    )
    _assert_model_shape(
        model=TrustProfileIssuerCreate,
        schema=trust_profile_issuer_create_schema,
        label="TrustProfileIssuerCreate",
    )
    trust_profile_issuer_create = TrustProfileIssuerCreate(
        issuer_id=issuer_entity_internal["id"],
        metadata={"credential_template_ids": ["template-1"]},
    )
    trust_profile_issuer_create_validator.validate(
        json.loads(_validated_trust_profile_issuer_payload(trust_profile_issuer_create))
    )

    trust_profile_issuer_update_schema, trust_profile_issuer_update_validator = (
        _validator(
            protocol_root,
            registry,
            "trust-profile-issuer-update-request.json",
        )
    )
    _assert_model_shape(
        model=TrustProfileIssuerUpdate,
        schema=trust_profile_issuer_update_schema,
        label="TrustProfileIssuerUpdate",
    )
    trust_profile_issuer_update = TrustProfileIssuerUpdate(trust_level=80)
    trust_profile_issuer_update_validator.validate(
        json.loads(_validated_trust_profile_issuer_payload(trust_profile_issuer_update))
    )

    issuer_identity_schema, issuer_identity_validator = _validator(
        protocol_root,
        registry,
        "issuer-identity.json",
    )
    _assert_model_shape(
        model=IssuerIdentityResponse,
        schema=issuer_identity_schema,
        label="IssuerIdentityResponse",
    )
    issuer_identity_list_schema, issuer_identity_list_validator = _validator(
        protocol_root,
        registry,
        "issuer-identity-list-response.json",
    )
    _assert_model_shape(
        model=IssuerIdentityListResponse,
        schema=issuer_identity_list_schema,
        label="IssuerIdentityListResponse",
    )
    issuer_identity = IssuerIdentityResponse(
        issuer_did="did:web:issuer.example",
        key_purpose="vc_jwt_issuer",
        credential_format="SD_JWT_VC",
        algorithm="ES256",
        status="active",
    ).model_dump(mode="json")
    issuer_identity_validator.validate(issuer_identity)
    issuer_identity_list_validator.validate({"identities": [issuer_identity]})

    issuer_operation = {
        "organization_id": "org-conformance",
        "issuer_did": "did:web:issuer.example",
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "SD_JWT_VC",
        "algorithm": "ES256",
    }
    lifecycle_contracts = (
        (
            IssuerIdentityOperationRequest,
            "issuer-identity-operation-request.json",
            issuer_operation,
        ),
        (
            IssuerIdentityCreateRequest,
            "issuer-identity-create-request.json",
            issuer_operation,
        ),
        (
            IssuerIdentityCertificateRequest,
            "issuer-identity-certificate-request.json",
            {**issuer_operation, "cert_pem": "public certificate"},
        ),
        (
            IssuerIdentityCreateResponse,
            "issuer-identity-create-response.json",
            {"identity": issuer_identity, "created": True},
        ),
        (
            IssuerIdentityDeleteResponse,
            "issuer-identity-delete-response.json",
            {"deleted": issuer_identity},
        ),
        (
            IssuerIdentityResolutionResponse,
            "issuer-identity-resolution-response.json",
            {
                "identity": issuer_identity,
                "public_jwk": {"kty": "EC", "crv": "P-256"},
            },
        ),
    )
    lifecycle_schemas: list[dict[str, Any]] = []
    for model, schema_name, payload in lifecycle_contracts:
        lifecycle_schema, lifecycle_validator = _validator(
            protocol_root, registry, schema_name
        )
        _assert_model_shape(
            model=model, schema=lifecycle_schema, label=model.__name__
        )
        lifecycle_validator.validate(
            model.model_validate(payload).model_dump(mode="json", exclude_none=True)
        )
        lifecycle_schemas.append(lifecycle_schema)

    for document in (
        issuer_entity_schema,
        issuer_entity_create_schema,
        issuer_entity_update_schema,
        trust_profile_issuer_schema,
        trust_profile_issuer_create_schema,
        trust_profile_issuer_update_schema,
        issuer_identity_schema,
        issuer_identity_list_schema,
        *lifecycle_schemas,
    ):
        leaked = FORBIDDEN_PUBLIC_FIELDS & set(document.get("properties", {}))
        if leaked:
            raise AssertionError(
                f"marty-protocol issuer boundary exposes custody selectors: {sorted(leaked)}"
            )
    for model in (
        IssuerEntityCreate,
        IssuerEntityUpdate,
        IssuerEntityResponse,
        TrustProfileIssuerCreate,
        TrustProfileIssuerUpdate,
        TrustProfileIssuerResponse,
        IssuerIdentityResponse,
        IssuerIdentityListResponse,
        IssuerIdentityOperationRequest,
        IssuerIdentityCreateRequest,
        IssuerIdentityCertificateRequest,
        IssuerIdentityCreateResponse,
        IssuerIdentityDeleteResponse,
        IssuerIdentityResolutionResponse,
    ):
        leaked = FORBIDDEN_PUBLIC_FIELDS & set(model.model_fields)
        if leaked:
            raise AssertionError(
                f"runtime issuer boundary exposes custody selectors: {sorted(leaked)}"
            )

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

    # Flow and issuance-management operations are public product contracts,
    # not loose pass-throughs. Keep their required fields, tenant selectors,
    # and response projections exactly aligned with marty-protocol.
    operation_models = (
        ("flow-create-request.json", FlowDefinitionCreate),
        ("flow-update-request.json", FlowDefinitionUpdate),
        ("flow-execution-start-request.json", FlowInstanceCreate),
        ("flow.json", FlowDefinitionResponse),
        ("flow-execution.json", FlowInstanceResponse),
        ("verification-result-response.json", VerificationResultResponse),
        ("issuance-response.json", IssuanceResponse),
        ("issuance.json", IssuanceTransactionResponse),
        ("issued-credential.json", IssuedCredentialRecordResponse),
        ("issued-credential-lifecycle-request.json", IssuedCredentialLifecycleRequest),
        ("credential-renewal-offer-response.json", CredentialRenewalOfferResponse),
        ("didcomm-deliver-request.json", DidcommDeliverRequest),
        ("didcomm-delivery-response.json", DidcommDeliveryResponse),
    )
    operation_validators: dict[str, Draft202012Validator] = {}
    for filename, model in operation_models:
        operation_schema, operation_validator = _validator(
            protocol_root,
            registry,
            filename,
        )
        _assert_model_shape(
            model=model,
            schema=operation_schema,
            label=model.__name__,
        )
        leaked = FORBIDDEN_FLOW_FIELDS & _property_names(operation_schema)
        if leaked:
            raise AssertionError(
                f"marty-protocol {filename} exposes private service state: "
                f"{sorted(leaked)}"
            )
        leaked_runtime_fields = FORBIDDEN_FLOW_FIELDS & set(model.model_fields)
        if leaked_runtime_fields:
            raise AssertionError(
                f"{model.__name__} exposes private service state: "
                f"{sorted(leaked_runtime_fields)}"
            )
        operation_validators[filename] = operation_validator

    flow_create = FlowDefinitionCreate(
        organization_id="20000000-0000-4000-8000-000000000001",
        name="Employee issuance",
        flow_type="oid4vci_pre_authorized",
        credential_template_id="template-employee",
    ).model_dump(mode="json", exclude_none=True)
    operation_validators["flow-create-request.json"].validate(flow_create)
    flow_update = FlowDefinitionUpdate(
        organization_id="20000000-0000-4000-8000-000000000001",
        name="Updated employee issuance",
    ).model_dump(mode="json", exclude_unset=True)
    operation_validators["flow-update-request.json"].validate(flow_update)
    flow_start = FlowInstanceCreate(
        organization_id="20000000-0000-4000-8000-000000000001",
        flow_definition_id="flow-employee",
        initial_context={"purpose": "employee onboarding"},
    ).model_dump(mode="json")
    operation_validators["flow-execution-start-request.json"].validate(flow_start)

    try:
        FlowInstanceCreate(
            organization_id="20000000-0000-4000-8000-000000000001",
            flow_definition_id="flow-employee",
            initial_context={"nested": {"pre_auth_code": "must-not-enter"}},
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "private service state was accepted in Flow initial_context"
        )

    public_documents = {
        "flow.json": FlowDefinitionResponse(
            id="flow-employee",
            organization_id="20000000-0000-4000-8000-000000000001",
            name="Employee issuance",
            flow_type="oid4vci_pre_authorized",
            flow_category="ISSUANCE",
            resolved_steps=[
                "create_offer",
                "token_exchange",
                "credential_request",
                "issue_credential",
            ],
            credential_template_id="template-employee",
            approval_strategy="AUTO",
            status="ACTIVE",
            version=1,
            created_at="2026-07-31T00:00:00Z",
            updated_at="2026-07-31T00:00:00Z",
        ),
        "flow-execution.json": FlowInstanceResponse(
            id="execution-employee",
            flow_id="flow-employee",
            flow_type="oid4vci_pre_authorized",
            organization_id="20000000-0000-4000-8000-000000000001",
            status="IN_PROGRESS",
            context_data={"purpose": "employee onboarding"},
            step_results={},
            metadata={},
            state_history=[],
            created_at="2026-07-31T00:00:00Z",
            updated_at="2026-07-31T00:00:00Z",
        ),
        "verification-result-response.json": VerificationResultResponse(
            instance_id="execution-verification",
            status="COMPLETED",
            result="passed",
            decision="allow",
            verified_claims={"employee_id": "E-123"},
        ),
        "issuance-response.json": IssuanceResponse(
            id="issuance-employee",
            organization_id="20000000-0000-4000-8000-000000000001",
            credential_template_id="template-employee",
            status="pending",
            credential_offer_uri="openid-credential-offer://example",
            credential_offer_uris={},
            credential_offer_labels={},
            expires_at="2026-08-01T00:00:00Z",
        ),
        "issuance.json": IssuanceTransactionResponse(
            id="issuance-employee",
            organization_id="20000000-0000-4000-8000-000000000001",
            credential_template_id="template-employee",
            status="pending",
            created_at="2026-07-31T00:00:00Z",
        ),
        "issued-credential.json": IssuedCredentialRecordResponse(
            id="credential-employee",
            organization_id="20000000-0000-4000-8000-000000000001",
            credential_id="credential-employee",
            credential_type="EmployeeCredential",
            credential_format="SD_JWT_VC",
            flow_execution_id="issuance-employee",
            credential_template_id="template-employee",
            subject_id="did:example:holder",
            issued_at="2026-07-31T00:00:00Z",
            status="ACTIVE",
            status_list_entries=[],
            created_at="2026-07-31T00:00:00Z",
        ),
        "credential-renewal-offer-response.json": CredentialRenewalOfferResponse(
            source_credential_id="credential-employee",
            transaction_id="issuance-renewal",
            credential_offer_uri="openid-credential-offer://renewal",
            credential_offer_uris={},
            credential_offer_labels={},
            expires_at="2026-08-01T00:00:00Z",
        ),
    }
    for filename, runtime_document in public_documents.items():
        document = runtime_document.model_dump(mode="json", exclude_none=True)
        operation_validators[filename].validate(document)
        leaked = FORBIDDEN_FLOW_FIELDS & _property_names(document)
        if leaked:
            raise AssertionError(
                f"runtime {filename} exposes private service state: {sorted(leaked)}"
            )

    lifecycle_request = IssuedCredentialLifecycleRequest(
        reason="Credential superseded",
    ).model_dump(mode="json", exclude_none=True)
    operation_validators["issued-credential-lifecycle-request.json"].validate(
        lifecycle_request
    )

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

    presentation_schema, presentation_validator = _validator(
        protocol_root,
        registry,
        "presentation-policy.json",
    )
    _assert_model_shape(
        model=PresentationPolicyResponse,
        schema=presentation_schema,
        label="PresentationPolicyResponse",
    )
    if set(_PUBLIC_PRESENTATION_POLICY_FIELDS) != set(
        presentation_schema["properties"]
    ):
        raise AssertionError(
            "presentation-policy response allowlist drifted from marty-protocol"
        )
    presentation_internal = {
        "id": "60000000-0000-4000-8000-000000000001",
        "organization_id": "20000000-0000-4000-8000-000000000001",
        "name": "Employee verification",
        "status": "active",
        "description": "Verify an employee credential.",
        "purpose": "Workforce access",
        "required_claims": [
            {
                "claim_name": "employee_id",
                "credential_type": "EmployeeCredential",
            }
        ],
        "accepted_credential_types": ["EmployeeCredential"],
        "display_metadata": {
            "title": "Employee verification",
            "description": "Present an employee credential.",
            "purpose": "employment_verification",
            "purpose_description": "Workforce access",
            "verifier_name": "Example verifier",
            "verifier_logo_url": None,
            "privacy_policy_url": None,
            "terms_of_service_url": None,
        },
        "credential_requirements": [
            {
                "credential_template_id": "template-employee",
                "display_name": "Employee credential",
                "description": None,
                "required": True,
                "credential_payload_format": "SD_JWT_VC",
                "requested_claims": [
                    {
                        "claim_name": "employee_id",
                        "display_name": "Employee ID",
                        "description": None,
                        "required": True,
                        "selective_disclosure": True,
                        "accept_derived": True,
                        "predicate_spec": None,
                        "constraints": [],
                    }
                ],
                "trust_profile_id": None,
                "max_age_seconds": None,
                "require_fresh_issuance": False,
            }
        ],
        "alternative_requirements": [],
        "compliance_profile_id": None,
        "trust_profile_id": None,
        "holder_binding": {"required": False},
        "freshness": {"require_not_revoked": True},
        "prefer_predicates": False,
        "supported_circuits": [],
        "fallback_policy": "ACCEPT_RAW",
        "issuer_constraints": None,
        "credential_ranking_strategy": "FRESHEST_FIRST",
        "credential_ranking_weights": None,
        "version": 1,
        "created_at": "2026-07-30T00:00:00Z",
        "updated_at": "2026-07-30T00:00:00Z",
        "issuer_profile_id": "must-not-leak",
        "signing_service_id": "must-not-leak",
    }
    presentation_response = _sanitize_presentation_policy_response(
        Response(
            content=json.dumps(presentation_internal),
            media_type="application/json",
        )
    )
    presentation = json.loads(presentation_response.body)
    presentation_validator.validate(presentation)
    leaked = FORBIDDEN_PUBLIC_FIELDS & _property_names(presentation)
    if leaked:
        raise AssertionError(
            f"runtime Presentation Policy response exposes custody selectors: {sorted(leaked)}"
        )

    presentation_create_schema, presentation_create_validator = _validator(
        protocol_root,
        registry,
        "presentation-policy-create-request.json",
    )
    _assert_model_shape(
        model=PresentationPolicyCreate,
        schema=presentation_create_schema,
        label="PresentationPolicyCreate",
    )
    presentation_create_model = PresentationPolicyCreate(
        organization_id="20000000-0000-4000-8000-000000000001",
        name="Employee verification",
        purpose="Workforce access",
        required_claims=[
            {
                "claim_name": "employee_id",
                "credential_type": "EmployeeCredential",
            }
        ],
        accepted_credential_types=["EmployeeCredential"],
        holder_binding={"required": False},
    )
    presentation_create = _validated_policy_payload(presentation_create_model)
    presentation_create_validator.validate(presentation_create)

    presentation_update_schema, presentation_update_validator = _validator(
        protocol_root,
        registry,
        "presentation-policy-update-request.json",
    )
    _assert_model_shape(
        model=PresentationPolicyUpdate,
        schema=presentation_update_schema,
        label="PresentationPolicyUpdate",
    )
    presentation_update = PresentationPolicyUpdate(
        organization_id="20000000-0000-4000-8000-000000000001",
        name="Updated employee verification",
        freshness={"require_not_revoked": True},
    )
    presentation_update = _validated_policy_payload(presentation_update)
    presentation_update_validator.validate(presentation_update)

    for schema in (presentation_create_schema, presentation_update_schema):
        leaked_schema_fields = FORBIDDEN_PUBLIC_FIELDS & _property_names(schema)
        if leaked_schema_fields:
            raise AssertionError(
                "marty-protocol Presentation Policy operation exposes custody "
                f"selectors: {sorted(leaked_schema_fields)}"
            )

    for model in (
        IssuanceCreate,
        PresentationPolicyCreate,
        PresentationPolicyUpdate,
        StartVerificationFlowRequest,
    ):
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
