#!/usr/bin/env python3
"""
Migration Runner for All Marty-UI Services

This script runs database migrations for all microservices in the correct order.
It ensures that the database schema is up-to-date before services start.

Usage:
    python run_all_migrations.py [--verify-only]

Options:
    --verify-only    Check if migrations are up-to-date without applying them

Environment Variables:
    DATABASE_URL     PostgreSQL connection string (required)
"""

import base64
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from sqlalchemy import create_engine, text

# Add services to path
services_root = Path(__file__).parent
sys.path.insert(0, str(services_root))

from marty_common.migration import (
    AlembicMigrationAdapter,
    MigrationError,
)
from marty_common.migration_profile import migration_profile, migration_profile_settings
from marty_common.system_ids import MARTY_DEFAULT_ORG_ID, MARTY_DEFAULT_ORG_SLUG


# Service configurations
SERVICES = [
    {
        "name": "organization",
        "module": "organization.infrastructure.models",
    },
    {
        "name": "auth",
        "module": "auth.infrastructure.models",
    },
    {
        "name": "revocation_profile",
        "module": "revocation_profile.infrastructure.models",
    },
    {
        "name": "credential_template",
        "module": "credential_template.infrastructure.models",
    },
    {
        "name": "trust_profile",
        "module": "trust_profile.infrastructure.models",
    },
    {
        "name": "issuance",
        "module": "issuance.infrastructure.models",
    },
    {
        "name": "presentation_policy",
        "module": "presentation_policy.infrastructure.models",
    },
    {
        "name": "deployment_profile",
        "module": "deployment_profile.infrastructure.models",
    },
    {
        "name": "flow",
        "module": "flow.infrastructure.models",
    },
]

MANAGED_OPENBAO_SERVICE_ID = "managed-openbao-transit"

MARTY_KMS_KEY_SPECS: list[dict[str, Any]] = [
    {
        "id": "cred-issuer-marty-es256",
        "name": "Marty ES256 issuer key",
        "type": "ecdsa-p256",
        "algorithm": "ES256",
        "key_purposes": ["vc_jwt_issuer", "jwks_signing"],
        "credential_formats": ["jwt_vc_json", "dc+sd-jwt"],
    },
    {
        "id": "cred-issuer-marty-es384",
        "name": "Marty ES384 issuer key",
        "type": "ecdsa-p384",
        "algorithm": "ES384",
        "key_purposes": ["vc_jwt_issuer"],
        "credential_formats": ["jwt_vc_json", "dc+sd-jwt"],
    },
    {
        "id": "cred-issuer-marty-rs256",
        "name": "Marty RS256 issuer key",
        "type": "rsa-2048",
        "algorithm": "RS256",
        "key_purposes": ["vc_jwt_issuer"],
        "credential_formats": ["jwt_vc_json"],
    },
    {
        "id": "lti-tool-marty-rs256",
        "name": "Marty LTI tool signing key",
        "type": "rsa-2048",
        "algorithm": "RS256",
        "key_purposes": ["lti_tool_signing"],
        "credential_formats": [],
    },
    {
        "id": "cred-issuer-marty-eddsa",
        "name": "Marty EdDSA issuer key",
        "type": "ed25519",
        "algorithm": "EdDSA",
        "key_purposes": ["vc_jwt_issuer", "jwks_signing"],
        "credential_formats": ["jwt_vc_json", "dc+sd-jwt"],
    },
    {
        "id": "cred-dsc-marty-primary",
        "name": "Marty document signer key",
        "type": "ecdsa-p256",
        "algorithm": "ES256",
        "key_purposes": ["mdoc_dsc", "vdsnc_signing"],
        "credential_formats": ["mso_mdoc", "vds_nc"],
    },
]

MARTY_ISSUER_PROFILE_SPECS: list[dict[str, str]] = [
    {
        "id": "ip-marty-vc-jwt-issuer",
        "name": "Marty VC issuer",
        "signing_key_reference": "cred-issuer-marty-es256",
        "key_purpose": "vc_jwt_issuer",
    },
    {
        "id": "ip-marty-mdoc-dsc",
        "name": "Marty mDoc document signer",
        "signing_key_reference": "cred-dsc-marty-primary",
        "key_purpose": "mdoc_dsc",
    },
    {
        "id": "ip-marty-vdsnc-issuer",
        "name": "Marty VDS-NC document signer",
        "signing_key_reference": "cred-dsc-marty-primary",
        "key_purpose": "vdsnc_signing",
    },
]


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_secret_value(name: str) -> str:
    value = os.environ.get(name)
    if value:
        return value.strip()

    file_path = os.environ.get(f"{name}_FILE")
    if not file_path:
        return ""

    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _bool_env(name: str, default: bool = True) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off", "disabled"}


def _public_domain() -> str:
    configured = os.environ.get("PUBLIC_DOMAIN", "").strip()
    if configured:
        if "://" in configured:
            configured = urlparse(configured).netloc
        return configured.strip().strip("/")

    for env_name in ("MARTY_ISSUER_BASE_URL", "ISSUER_BASE_URL", "PUBLIC_API_URL"):
        candidate = os.environ.get(env_name, "").strip()
        if candidate:
            parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
            if parsed.netloc:
                return parsed.netloc

    return "beta.elevenidllc.com"


def _issuer_base_url() -> str:
    configured = (
        os.environ.get("MARTY_ISSUER_BASE_URL")
        or os.environ.get("ISSUER_BASE_URL")
        or os.environ.get("PUBLIC_API_URL")
    )
    if configured:
        return configured.rstrip("/")
    return f"https://{_public_domain()}".rstrip("/")


def _issuer_did() -> str:
    configured = os.environ.get("MARTY_ISSUER_DID", "").strip()
    if configured:
        return configured
    return f"did:web:{_did_web_domain(_public_domain())}:orgs:{_marty_org_slug()}"


def _did_web_domain(public_domain: str) -> str:
    return public_domain.strip().strip("/").replace(":", "%3A").replace("/", ":")


def _marty_org_slug() -> str:
    configured = os.environ.get("MARTY_ORG_SLUG", MARTY_DEFAULT_ORG_SLUG).strip().lower()
    safe = "".join(ch for ch in configured if ch.isalnum() or ch in "._-")
    return safe or MARTY_DEFAULT_ORG_SLUG


def _redis_gateway_url() -> str:
    redis_url = os.environ.get("REDIS_URL", "").strip()
    if not redis_url:
        return ""

    parsed = urlparse(redis_url)
    if parsed.path and parsed.path.strip("/") and parsed.path.strip("/").isdigit():
        return redis_url

    db = os.environ.get("REDIS_DB_GATEWAY", "2").strip() or "2"
    path = f"/{db}"
    return urlunparse(parsed._replace(path=path))


def _storage_key(organization_id: str) -> str:
    return f"org:{organization_id}:signing-key-services"


def _jwks_storage_key(organization_id: str) -> str:
    return f"org:{organization_id}:signing-key-jwks"


def _did_doc_storage_key(organization_id: str) -> str:
    return f"org:{organization_id}:signing-key-did-document"


def _issuer_profiles_storage_key(organization_id: str) -> str:
    return f"org:{organization_id}:issuer-profiles"


def _did_web_slug_key(slug: str) -> str:
    return f"did-web-slug:{slug}"


def _did_fragment_for_key_reference(key_reference: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in key_reference)
    return safe.strip("-") or key_reference


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_uint(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return _b64url(value.to_bytes(length, "big"))


def _public_key_pem_to_jwk(public_key_pem: str, key_id: str, algorithm: str) -> dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

    public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    jwk: dict[str, Any]

    if isinstance(public_key, EllipticCurvePublicKey):
        numbers = public_key.public_numbers()
        crv = "P-384" if public_key.curve.key_size == 384 else "P-256"
        width = 48 if crv == "P-384" else 32
        jwk = {
            "kty": "EC",
            "crv": crv,
            "x": _b64url(numbers.x.to_bytes(width, "big")),
            "y": _b64url(numbers.y.to_bytes(width, "big")),
        }
    elif isinstance(public_key, RSAPublicKey):
        numbers = public_key.public_numbers()
        jwk = {
            "kty": "RSA",
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }
    elif isinstance(public_key, Ed25519PublicKey):
        raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}
    else:
        raise RuntimeError(f"Unsupported OpenBao public key type for {key_id}.")

    jwk["kid"] = key_id
    jwk["alg"] = algorithm
    jwk["use"] = "sig"
    return jwk


def _openbao_public_key_to_jwk(public_key: str, key_id: str, key_type: str, algorithm: str) -> dict[str, Any]:
    if "BEGIN PUBLIC KEY" in public_key:
        return _public_key_pem_to_jwk(public_key, key_id, algorithm)

    if key_type == "ed25519":
        raw = base64.b64decode(public_key)
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(raw),
            "kid": key_id,
            "alg": algorithm,
            "use": "sig",
        }

    raise RuntimeError(f"OpenBao key {key_id} does not expose a supported public key format.")


def _bao_request(
    method: str,
    path: str,
    *,
    bao_addr: str,
    bao_token: str,
    json_body: dict[str, Any] | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    import httpx

    url = f"{bao_addr.rstrip('/')}/v1/{path.lstrip('/')}"
    response = httpx.request(
        method,
        url,
        headers={"X-Vault-Token": bao_token},
        json=json_body,
        timeout=timeout,
    )
    if response.status_code == 204 or not response.content:
        return {}
    if response.status_code >= 400:
        response.raise_for_status()
    return response.json()


def _ensure_transit_mount(bao_addr: str, bao_token: str) -> None:
    import httpx

    try:
        mounts = _bao_request("GET", "sys/mounts", bao_addr=bao_addr, bao_token=bao_token)
        if "transit/" in (mounts.get("data") or {}):
            return
        _bao_request(
            "POST",
            "sys/mounts/transit",
            bao_addr=bao_addr,
            bao_token=bao_token,
            json_body={"type": "transit"},
        )
    except httpx.HTTPStatusError as exc:
        if exc.response is not None and exc.response.status_code in {400, 403}:
            print("  OpenBao transit mount could not be managed with this token; continuing with key read/create checks.")
            return
        raise


def _read_openbao_transit_key(bao_addr: str, bao_token: str, key_id: str) -> dict[str, Any] | None:
    import httpx

    try:
        return _bao_request("GET", f"transit/keys/{key_id}", bao_addr=bao_addr, bao_token=bao_token).get("data") or {}
    except httpx.HTTPStatusError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            return None
        raise


def _extract_openbao_public_key(key_id: str, data: dict[str, Any]) -> str:
    versions = data.get("keys")
    if not isinstance(versions, dict) or not versions:
        raise RuntimeError(f"OpenBao key {key_id} has no public key versions.")

    latest = str(data.get("latest_version") or max(int(v) for v in versions.keys() if str(v).isdigit()))
    version_data = versions.get(latest) or versions.get(str(latest)) or {}
    public_key = version_data.get("public_key")
    if not isinstance(public_key, str) or not public_key:
        raise RuntimeError(f"OpenBao key {key_id} does not expose public key material.")
    return public_key


def _ensure_openbao_key(bao_addr: str, bao_token: str, spec: dict[str, Any]) -> dict[str, Any]:
    import httpx

    key_id = str(spec["id"])
    data = _read_openbao_transit_key(bao_addr, bao_token, key_id)
    if data is None:
        try:
            _bao_request(
                "POST",
                f"transit/keys/{key_id}",
                bao_addr=bao_addr,
                bao_token=bao_token,
                json_body={"type": spec["type"]},
            )
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code if exc.response is not None else "unknown"
            raise RuntimeError(
                f"OpenBao key {key_id} is missing and could not be created (HTTP {status})."
            ) from exc
        data = _read_openbao_transit_key(bao_addr, bao_token, key_id)

    if data is None:
        raise RuntimeError(f"OpenBao key {key_id} is missing after create attempt.")

    public_key = _extract_openbao_public_key(key_id, data)
    public_jwk = _openbao_public_key_to_jwk(public_key, key_id, str(spec["type"]), str(spec["algorithm"]))
    return {
        **spec,
        "provider_key_name": key_id,
        "public_jwk": public_jwk,
        "latest_version": data.get("latest_version"),
    }


def _load_json_from_redis(redis_client: Any, key: str, default: dict[str, Any]) -> dict[str, Any]:
    payload = redis_client.get(key)
    if not payload:
        return dict(default)
    try:
        parsed = json.loads(payload if isinstance(payload, str) else payload.decode("utf-8"))
    except Exception:
        return dict(default)
    return parsed if isinstance(parsed, dict) else dict(default)


def _save_json_to_redis(redis_client: Any, key: str, document: dict[str, Any]) -> None:
    redis_client.set(key, json.dumps(document))


def _seed_signing_registry(redis_client: Any, organization_id: str, key_records: list[dict[str, Any]]) -> None:
    storage_key = _storage_key(organization_id)
    registry = _load_json_from_redis(
        redis_client,
        storage_key,
        {"services": [], "default_service_id": None, "format_defaults": {}, "type_defaults": {}},
    )

    now = _utcnow_iso()
    key_aliases = [record["id"] for record in key_records]
    algorithms = sorted({record["algorithm"] for record in key_records})
    key_purposes = sorted({purpose for record in key_records for purpose in record.get("key_purposes", [])})
    credential_formats = sorted({fmt for record in key_records for fmt in record.get("credential_formats", [])})

    managed_service = {
        "id": MANAGED_OPENBAO_SERVICE_ID,
        "name": "Marty managed OpenBao transit",
        "description": "Managed by the Marty service stack and seeded during clean-slate migrations.",
        "service_type": "openbao-transit",
        "provider": "openbao",
        "provider_label": "OpenBao Transit",
        "protocol": "vault-transit",
        "category": "service-hsm",
        "endpoint": "",
        "region": "",
        "mount": "transit",
        "namespace": "",
        "auth_mode": "service_token",
        "auth_reference": "Managed by Marty service stack",
        "key_reference": "cred-issuer-marty-es256",
        "key_aliases": key_aliases,
        "algorithms": algorithms,
        "status": "configured",
        "managed": True,
        "read_only": True,
        "managed_by": "Marty service stack",
        "organization_id": organization_id,
        "key_count": len(key_aliases),
        "capabilities": {
            "discover_keys": True,
            "sign": True,
            "rotate_keys": False,
            "upload_public_keys": False,
            "delete_keys": False,
            "multiple_key_references": True,
            "public_key_export": True,
            "supported_algorithms": algorithms,
        },
        "signature_encoding": "raw_ieee_p1363",
        "key_purposes": key_purposes,
        "credential_formats": credential_formats,
        "created_at": now,
        "updated_at": now,
    }

    existing_services = registry.get("services") if isinstance(registry.get("services"), list) else []
    services = [
        service
        for service in existing_services
        if isinstance(service, dict) and service.get("id") != MANAGED_OPENBAO_SERVICE_ID
    ]
    services.insert(0, managed_service)

    format_defaults = registry.get("format_defaults") if isinstance(registry.get("format_defaults"), dict) else {}
    for credential_format in ("jwt_vc_json", "dc+sd-jwt", "mso_mdoc", "vds_nc"):
        format_defaults.setdefault(credential_format, MANAGED_OPENBAO_SERVICE_ID)

    type_defaults = registry.get("type_defaults") if isinstance(registry.get("type_defaults"), dict) else {}
    for key_purpose in ("vc_jwt_issuer", "jwks_signing", "lti_tool_signing", "mdoc_dsc", "vdsnc_signing"):
        type_defaults.setdefault(key_purpose, MANAGED_OPENBAO_SERVICE_ID)

    registry["services"] = services
    registry["default_service_id"] = registry.get("default_service_id") or MANAGED_OPENBAO_SERVICE_ID
    registry["format_defaults"] = format_defaults
    registry["type_defaults"] = type_defaults
    key_reference_purposes = (
        registry.get("key_reference_purposes")
        if isinstance(registry.get("key_reference_purposes"), dict)
        else {}
    )
    managed_key_purposes = (
        dict(key_reference_purposes.get(MANAGED_OPENBAO_SERVICE_ID) or {})
        if isinstance(key_reference_purposes.get(MANAGED_OPENBAO_SERVICE_ID), dict)
        else {}
    )
    for record in key_records:
        key_reference = record["id"]
        seeded_purposes = list(record.get("key_purposes") or [])
        existing_purposes = managed_key_purposes.get(key_reference)
        if existing_purposes is not None and existing_purposes != seeded_purposes:
            raise RuntimeError(
                f"Managed signing key {key_reference!r} has conflicting purpose bindings: "
                f"{existing_purposes!r} != {seeded_purposes!r}"
            )
        managed_key_purposes[key_reference] = seeded_purposes
    key_reference_purposes[MANAGED_OPENBAO_SERVICE_ID] = managed_key_purposes
    registry["key_reference_purposes"] = key_reference_purposes
    _save_json_to_redis(redis_client, storage_key, registry)


def _seed_did_and_jwks(
    redis_client: Any,
    organization_id: str,
    issuer_did: str,
    key_records: list[dict[str, Any]],
) -> None:
    did_key = _did_doc_storage_key(organization_id)
    did_doc = _load_json_from_redis(
        redis_client,
        did_key,
        {
            "id": issuer_did,
            "controller": issuer_did,
            "verificationMethod": [],
            "assertionMethod": [],
        },
    )
    did_doc["id"] = issuer_did
    did_doc["controller"] = issuer_did

    key_ids = {record["id"] for record in key_records}
    methods = did_doc.get("verificationMethod") if isinstance(did_doc.get("verificationMethod"), list) else []
    methods_by_id = {
        method.get("id"): method
        for method in methods
        if isinstance(method, dict) and isinstance(method.get("id"), str)
        and not (
            isinstance(method.get("publicKeyJwk"), dict)
            and method["publicKeyJwk"].get("kid") in key_ids
        )
    }
    assertion = did_doc.get("assertionMethod") if isinstance(did_doc.get("assertionMethod"), list) else []
    assertion = [
        entry
        for entry in assertion
        if isinstance(entry, str)
        and not any(entry.endswith(f"#{_did_fragment_for_key_reference(key_id)}") for key_id in key_ids)
    ]

    # Protocol/client-assertion keys are published only through the Canvas LTI
    # JWKS. They must never become credential issuer assertion methods.
    issuer_key_records = [
        record
        for record in key_records
        if "lti_tool_signing" not in (record.get("key_purposes") or [])
    ]
    jwks = []
    for record in issuer_key_records:
        key_id = record["id"]
        fragment = _did_fragment_for_key_reference(key_id)
        vm_id = f"{issuer_did}#{fragment}"
        public_jwk = dict(record["public_jwk"])
        public_jwk["kid"] = key_id
        methods_by_id[vm_id] = {
            "id": vm_id,
            "type": "JsonWebKey",
            "controller": issuer_did,
            "publicKeyJwk": public_jwk,
        }
        if vm_id not in assertion:
            assertion.append(vm_id)
        jwks.append(public_jwk)

    did_doc["verificationMethod"] = list(methods_by_id.values())
    did_doc["assertionMethod"] = assertion
    did_doc["updated_at"] = _utcnow_iso()
    _save_json_to_redis(redis_client, did_key, did_doc)
    _save_json_to_redis(
        redis_client,
        _jwks_storage_key(organization_id),
        {"keys": jwks, "organization_id": organization_id, "updated_at": _utcnow_iso()},
    )
    if issuer_did.startswith("did:web:"):
        slug = _marty_org_slug()
        redis_client.set(_did_web_slug_key(slug), organization_id)


def _seed_issuer_profiles(
    redis_client: Any,
    organization_id: str,
    issuer_did: str,
    issuer_url: str,
) -> None:
    storage_key = _issuer_profiles_storage_key(organization_id)
    doc = _load_json_from_redis(redis_client, storage_key, {"profiles": []})
    profiles = doc.get("profiles") if isinstance(doc.get("profiles"), list) else []
    profiles_by_id = {
        profile.get("id"): profile
        for profile in profiles
        if isinstance(profile, dict) and isinstance(profile.get("id"), str)
    }
    now = _utcnow_iso()

    for spec in MARTY_ISSUER_PROFILE_SPECS:
        existing = profiles_by_id.get(spec["id"])
        verification_method_id = f"{issuer_did}#{_did_fragment_for_key_reference(spec['signing_key_reference'])}"
        profile = {
            "id": spec["id"],
            "organization_id": organization_id,
            "name": spec["name"],
            "issuer_did": issuer_did,
            "issuer_url": issuer_url,
            "signing_service_id": MANAGED_OPENBAO_SERVICE_ID,
            "signing_key_reference": spec["signing_key_reference"],
            "verification_method_id": verification_method_id,
            "key_purpose": spec["key_purpose"],
            "status": "active",
            "created_at": existing.get("created_at") if isinstance(existing, dict) else now,
            "updated_at": now,
        }
        profiles_by_id[spec["id"]] = profile

    doc["profiles"] = list(profiles_by_id.values())
    _save_json_to_redis(redis_client, storage_key, doc)


def bootstrap_marty_kms_identity() -> bool:
    """Seed the Marty KMS-backed DID identity used by clean-slate deployments."""
    print(f"\n{'='*60}")
    print("Marty KMS/DID bootstrap")
    print(f"{'='*60}")

    if not _bool_env("MARTY_KMS_BOOTSTRAP_ENABLED", default=True):
        print("  Skipped: MARTY_KMS_BOOTSTRAP_ENABLED is disabled.")
        return True

    redis_url = _redis_gateway_url()
    if not redis_url:
        print("  Skipped: REDIS_URL is not configured.")
        return True

    bao_addr = os.environ.get("BAO_ADDR", "").strip()
    if not bao_addr:
        print("  Skipped: BAO_ADDR is not configured.")
        return True

    bao_token = _read_secret_value("BAO_TOKEN") or _read_secret_value("OPENBAO_SERVICE_TOKEN")
    if not bao_token:
        print("  Failed: BAO_TOKEN/OPENBAO_SERVICE_TOKEN is not configured.", file=sys.stderr)
        return False

    try:
        import redis

        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        for attempt in range(1, 6):
            try:
                redis_client.ping()
                break
            except Exception:
                if attempt == 5:
                    raise
                time.sleep(1)

        organization_id = os.environ.get("MARTY_ORG_ID", MARTY_DEFAULT_ORG_ID).strip() or MARTY_DEFAULT_ORG_ID
        issuer_did = _issuer_did()
        issuer_url = _issuer_base_url()

        _ensure_transit_mount(bao_addr, bao_token)
        key_records = [_ensure_openbao_key(bao_addr, bao_token, spec) for spec in MARTY_KMS_KEY_SPECS]

        _seed_signing_registry(redis_client, organization_id, key_records)
        _seed_did_and_jwks(redis_client, organization_id, issuer_did, key_records)
        _seed_issuer_profiles(redis_client, organization_id, issuer_did, issuer_url)

        print(f"  Seeded {len(key_records)} OpenBao keys for org {organization_id}.")
        print(f"  Published issuer DID: {issuer_did}")
        print(f"  Published did:web slug: {_marty_org_slug()} -> {organization_id}")
        print("  Seeded signing registry, DID document, JWKS, and issuer profiles.")
        return True
    except Exception as exc:
        print(f"  Failed Marty KMS/DID bootstrap: {exc}", file=sys.stderr)
        return False


def get_database_url() -> str:
    """Get database URL from environment."""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("✗ Error: DATABASE_URL environment variable not set", file=sys.stderr)
        sys.exit(1)
    
    # Convert asyncpg URL to sync for Alembic
    return database_url.replace("+asyncpg", "")


def ensure_schemas(database_url: str) -> None:
    """Ensure all service schemas exist."""
    print("\n" + "="*60)
    print("Creating database schemas...")
    print("="*60)
    
    schemas = [
        "organization_service",
        "auth_service",
        "credential_template_service",
        "trust_profile_service",
        "issuance_service",
        "presentation_policy_service",
        "deployment_profile_service",
        "flow_service",
        "revocation_profile_service",
    ]
    
    engine = create_engine(database_url)
    try:
        with engine.connect() as conn:
            for schema in schemas:
                conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema}"))
                print(f"  ✓ {schema}")
            conn.commit()
        print("✓ All schemas ready")
    except Exception as e:
        print(f"✗ Error creating schemas: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        engine.dispose()


def run_service_migration(service_config: dict, database_url: str, verify_only: bool = False) -> bool:
    """Run migrations for a single service.
    
    Args:
        service_config: Service configuration dict with name and module
        database_url: Database connection URL
        verify_only: If True, only verify schema without applying migrations
        
    Returns:
        True if migrations successful/verified, False otherwise
    """
    service_name = service_config["name"]
    module_name = service_config["module"]
    
    print(f"\n{'='*60}")
    print(f"Service: {service_name}")
    print(f"{'='*60}")
    
    try:
        # Import service models
        module = __import__(module_name, fromlist=["mapper_registry"])
        mapper_registry = module.mapper_registry
        
        # Create migration adapter
        adapter = AlembicMigrationAdapter(
            database_url=database_url,
            metadata=mapper_registry.metadata,
        )
        
        # Initialize migrations directory (creates alembic.ini, env.py, etc. if they don't exist)
        migrations_dir = services_root / service_name / "infrastructure" / "migrations"
        
        # Only initialize if migrations directory doesn't have required files
        if not (migrations_dir / "alembic.ini").exists() or not (migrations_dir / "env.py").exists():
            adapter.initialize(service_name=service_name, migrations_dir=migrations_dir)
        else:
            # Manually configure the adapter to use existing migration infrastructure
            adapter._service_name = service_name
            adapter._migrations_dir = migrations_dir
            alembic_ini_path = migrations_dir / "alembic.ini"
            
            from alembic.config import Config
            adapter.alembic_cfg = Config(str(alembic_ini_path))
            adapter.alembic_cfg.set_main_option("script_location", str(migrations_dir))
            adapter.alembic_cfg.set_main_option("sqlalchemy.url", database_url)
            adapter.alembic_cfg.attributes["target_metadata"] = mapper_registry.metadata
        
        if verify_only:
            # Verify schema is up-to-date
            is_valid = adapter.verify_schema(raise_on_mismatch=False)
            if is_valid:
                print(f"✓ {service_name}: Schema is up-to-date")
                return True
            else:
                print(f"✗ {service_name}: Schema is outdated")
                return False
        else:
            # Apply migrations
            current = adapter.current()
            print(f"  Current revision: {current or 'None'}")
            
            # Check if there are any migrations to apply
            from alembic.script import ScriptDirectory
            script_dir = ScriptDirectory.from_config(adapter.alembic_cfg)
            head = script_dir.get_current_head()
            print(f"  Head revision: {head or 'None'}")
            
            if not head:
                print(f"⚠ {service_name}: No migration files found in versions directory")
                print(f"  Versions directory: {migrations_dir / 'versions'}")
            elif current != head:
                # Run migrations when current doesn't match head
                # This includes the case when current is None (first run)
                adapter.upgrade(revision="head")
                new_current = adapter.current()
                print(f"  New revision: {new_current or 'None'}")
                print(f"✓ {service_name}: Migrations applied successfully")
            else:
                print("  Already up-to-date")
                print(f"✓ {service_name}: No migrations needed")
            
            return True
            
    except ImportError as e:
        print(f"⚠ {service_name}: No models module found ({e}), skipping...")
        return True  # Not an error if service doesn't have migrations yet
        
    except MigrationError as e:
        print(f"✗ {service_name}: Migration error: {e}", file=sys.stderr)
        return False
        
    except Exception as e:
        print(f"✗ {service_name}: Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Run migrations for all Marty-UI services"
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify migrations are up-to-date without applying",
    )
    
    args = parser.parse_args()
    
    # Get database URL
    database_url = get_database_url()
    
    print("="*60)
    print("MARTY-UI DATABASE MIGRATION RUNNER")
    print("="*60)
    print(f"Database: {database_url.split('@')[1] if '@' in database_url else database_url}")
    print(f"Mode: {'Verify Only' if args.verify_only else 'Apply Migrations'}")
    profile = migration_profile()
    settings = migration_profile_settings()
    print(
        "Profile: "
        f"{profile} "
        f"(demo={settings.include_demo_seed_data}, "
        f"beta={settings.include_beta_seed_data}, "
        f"experiments={settings.include_experimental_seed_data}, "
        f"test={settings.include_test_seed_data}, "
        f"experimental_fixes={settings.allow_experimental_data_fixes}, "
        f"persistent={settings.persistent})"
    )
    
    # Ensure schemas exist first
    if not args.verify_only:
        ensure_schemas(database_url)
    
    # Run migrations for each service
    success_count = 0
    failure_count = 0
    
    for service_config in SERVICES:
        success = run_service_migration(service_config, database_url, args.verify_only)
        if success:
            success_count += 1
        else:
            failure_count += 1

    kms_bootstrap_success = True
    if not args.verify_only:
        kms_bootstrap_success = bootstrap_marty_kms_identity()
    
    # Print summary
    print(f"\n{'='*60}")
    print("MIGRATION SUMMARY")
    print(f"{'='*60}")
    print(f"Total services: {len(SERVICES)}")
    print(f"Marty KMS identity: {'ready' if kms_bootstrap_success else 'failed'}")
    print(f"✓ Successful: {success_count}")
    print(f"✗ Failed: {failure_count}")
    
    if failure_count > 0 or not kms_bootstrap_success:
        if not kms_bootstrap_success:
            print("\nMarty KMS/DID bootstrap failed")
            if failure_count == 0:
                sys.exit(1)
        print(f"\n✗ {failure_count} service(s) failed migration")
        sys.exit(1)
    else:
        print("\n✓ All migrations completed successfully")
        sys.exit(0)


if __name__ == "__main__":
    main()
