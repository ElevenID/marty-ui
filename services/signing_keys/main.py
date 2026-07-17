"""Signing Keys Service.

Initial extraction scaffold from gateway signing-key routes.
This service will become the owner of KMS adapter orchestration,
service registry persistence, publication workflows, and compliance logic.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from fastapi import FastAPI

from marty_common import create_service_app

SERVICE_NAME = "signing-keys-service"
SERVICE_PORT = int(os.environ.get("SIGNING_KEYS_SERVICE_PORT", "8017"))

# Key purposes and credential format routing (GAP-002 / GAP-007)
KEY_PURPOSES = (
    "vc_jwt_issuer",
    "mdoc_dsc",
    "x509_doc_signer",
    "holder_binding",
    "presentation_signing",
    "vdsnc_signing",
    "jwks_signing",
    "lti_tool_signing",
)

KEY_PURPOSE_ALGORITHM_CONSTRAINTS: dict[str, frozenset[str]] = {
    "vc_jwt_issuer": frozenset({"ES256", "ES384", "RS256", "EdDSA"}),
    "mdoc_dsc": frozenset({"ES256", "ES384", "EdDSA"}),
    "x509_doc_signer": frozenset({"ES256", "ES384", "RS256", "EdDSA"}),
    "holder_binding": frozenset({"ES256", "EdDSA"}),
    "presentation_signing": frozenset({"ES256", "EdDSA"}),
    "vdsnc_signing": frozenset({"ES256", "ES384", "EdDSA"}),
    "jwks_signing": frozenset({"ES256", "ES384", "RS256", "EdDSA"}),
    "lti_tool_signing": frozenset({"RS256"}),
}

KEY_PURPOSE_CREDENTIAL_FORMATS: dict[str, tuple[str, ...]] = {
    "vc_jwt_issuer": ("jwt_vc_json", "dc+sd-jwt"),
    "mdoc_dsc": ("mso_mdoc", "zk_mdoc"),
    "x509_doc_signer": ("mso_mdoc", "zk_mdoc"),
    "holder_binding": ("mso_mdoc", "zk_mdoc", "dc+sd-jwt"),
    "presentation_signing": ("jwt_vc_json", "dc+sd-jwt", "mso_mdoc", "zk_mdoc"),
    "vdsnc_signing": ("vds_nc",),
    "jwks_signing": ("jwt_vc_json", "dc+sd-jwt"),
    "lti_tool_signing": (),
}

KEY_MANAGEMENT_SERVICE_TYPES: tuple[dict[str, Any], ...] = (
    {
        "id": "openbao-transit",
        "label": "OpenBao Transit",
        "description": "Register an OpenBao transit service that exposes signing keys remotely.",
        "provider": "openbao",
        "protocol": "vault-transit",
        "category": "service-hsm",
        "auth_modes": ["service_token", "token", "approle", "mtls"],
        "connection_fields": ["endpoint", "mount", "namespace"],
        "key_reference_label": "Transit key name",
        "supports_inventory": True,
    },
    {
        "id": "hashicorp-vault-transit",
        "label": "HashiCorp Vault Transit",
        "description": "Use Vault Transit as the signing backend for issuance keys.",
        "provider": "hashicorp-vault",
        "protocol": "vault-transit",
        "category": "service-hsm",
        "auth_modes": ["token", "approle", "mtls"],
        "connection_fields": ["endpoint", "mount", "namespace"],
        "key_reference_label": "Transit key name",
        "supports_inventory": True,
    },
    {
        "id": "aws-kms",
        "label": "AWS KMS",
        "description": "Register a customer-managed AWS KMS key for remote signing.",
        "provider": "aws",
        "protocol": "aws-kms",
        "category": "cloud-kms",
        "auth_modes": ["iam_role", "access_key", "assume_role"],
        "connection_fields": ["region"],
        "key_reference_label": "Key ARN",
        "supports_inventory": False,
    },
    {
        "id": "azure-key-vault",
        "label": "Azure Key Vault",
        "description": "Register an Azure Key Vault key as a signing source.",
        "provider": "azure",
        "protocol": "azure-key-vault",
        "category": "cloud-kms",
        "auth_modes": ["managed_identity", "client_secret", "certificate"],
        "connection_fields": ["endpoint"],
        "key_reference_label": "Key identifier",
        "supports_inventory": False,
    },
    {
        "id": "gcp-cloud-kms",
        "label": "Google Cloud KMS",
        "description": "Register a Google Cloud KMS crypto key version.",
        "provider": "gcp",
        "protocol": "gcp-kms",
        "category": "cloud-kms",
        "auth_modes": ["workload_identity", "service_account"],
        "connection_fields": ["region"],
        "key_reference_label": "Crypto key resource",
        "supports_inventory": False,
    },
    {
        "id": "custom-transit-compatible",
        "label": "Custom Transit-Compatible Service",
        "description": "Any service that implements the transit-compatible signing protocol Marty supports.",
        "provider": "custom",
        "protocol": "vault-transit-compatible",
        "category": "custom",
        "auth_modes": ["token", "mtls", "api_key", "custom"],
        "connection_fields": ["endpoint", "mount", "namespace"],
        "key_reference_label": "Key reference",
        "supports_inventory": False,
    },
)

KEY_MANAGEMENT_SERVICE_CAPABILITIES: dict[str, dict[str, Any]] = {
    "openbao-transit": {
        "supported_algorithms": ["ES256", "ES384", "RS256", "EdDSA"],
        "signature_encoding": "raw_ieee_p1363",
        "public_key_export": True,
        "hardware_attestation": False,
        "key_import": False,
        "key_create": True,
        "key_delete": True,
        "key_list": True,
        "rotation": True,
    },
    "hashicorp-vault-transit": {
        "supported_algorithms": ["ES256", "ES384", "RS256", "EdDSA"],
        "signature_encoding": "raw_ieee_p1363",
        "public_key_export": True,
        "hardware_attestation": False,
        "key_import": False,
        "key_create": True,
        "key_delete": True,
        "key_list": True,
        "rotation": True,
    },
    "aws-kms": {
        "supported_algorithms": ["ES256", "ES384", "RS256"],
        "signature_encoding": "der",
        "public_key_export": True,
        "hardware_attestation": True,
        "key_import": True,
        "key_create": True,
        "key_delete": False,
        "key_list": False,
        "rotation": True,
    },
    "azure-key-vault": {
        "supported_algorithms": ["ES256", "ES384", "RS256", "EdDSA"],
        "signature_encoding": "der",
        "public_key_export": True,
        "hardware_attestation": True,
        "key_import": True,
        "key_create": True,
        "key_delete": True,
        "key_list": True,
        "rotation": True,
    },
    "gcp-cloud-kms": {
        "supported_algorithms": ["ES256", "ES384", "RS256", "EdDSA"],
        "signature_encoding": "der",
        "public_key_export": True,
        "hardware_attestation": True,
        "key_import": True,
        "key_create": True,
        "key_delete": False,
        "key_list": True,
        "rotation": True,
    },
    "custom-transit-compatible": {
        "supported_algorithms": ["ES256", "ES384", "RS256", "EdDSA"],
        "signature_encoding": "raw_ieee_p1363",
        "public_key_export": False,
        "hardware_attestation": False,
        "key_import": False,
        "key_create": False,
        "key_delete": False,
        "key_list": False,
        "rotation": False,
    },
}

router = APIRouter(prefix="/v1/signing-keys", tags=["Signing Keys"])


class ServiceExtractionStatus(BaseModel):
    """Status payload for service extraction visibility."""

    service_name: str = Field(default=SERVICE_NAME)
    phase: str = Field(default="bootstrap")
    migrated_capabilities: list[str] = Field(
        default_factory=lambda: [
            "service-bootstrap",
            "health-surface",
            "integration-test-target",
        ]
    )
    pending_capabilities: list[str] = Field(
        default_factory=lambda: [
            "registry-persistence",
            "kms-adapter-integration",
            "jwks-did-publication-persistence",
            "audit-event-storage",
            "compliance-summary-computation",
        ]
    )


@router.get("/service-status", response_model=ServiceExtractionStatus, summary="Signing Keys Service Extraction Status")
async def get_service_status() -> ServiceExtractionStatus:
    """Report extraction progress for the new signing-keys microservice."""
    return ServiceExtractionStatus()


@router.get("/config/purposes", summary="List Available Key Purposes")
async def list_key_purposes() -> dict[str, Any]:
    """Return the list of valid key purpose identifiers with their algorithm constraints and default format mappings."""
    purposes = []
    for purpose in KEY_PURPOSES:
        purposes.append({
            "id": purpose,
            "allowed_algorithms": sorted(KEY_PURPOSE_ALGORITHM_CONSTRAINTS.get(purpose, frozenset())),
            "credential_formats": list(KEY_PURPOSE_CREDENTIAL_FORMATS.get(purpose, ())),
        })
    return JSONResponse(content={"purposes": purposes})


@router.get("/config/service-capabilities", summary="List Provider Capability Metadata")
async def list_service_capabilities() -> dict[str, Any]:
    """Return the static capability metadata for each registered service type."""
    result = []
    for service_type in KEY_MANAGEMENT_SERVICE_TYPES:
        caps = KEY_MANAGEMENT_SERVICE_CAPABILITIES.get(
            service_type["id"],
            KEY_MANAGEMENT_SERVICE_CAPABILITIES["custom-transit-compatible"],
        )
        result.append({
            "service_type_id": service_type["id"],
            "label": service_type["label"],
            "capabilities": caps,
        })
    return JSONResponse(content={"service_capabilities": result})


def create_app() -> FastAPI:
    """Create and configure the signing-keys service app."""
    return create_service_app(
        title="Signing Keys Service",
        description="Signing key and KMS service orchestration (extraction bootstrap).",
        service_name=SERVICE_NAME,
        routers=[router],
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )


app = create_app()


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness endpoint."""
    return {"status": "healthy", "service": SERVICE_NAME}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
