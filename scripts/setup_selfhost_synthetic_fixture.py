#!/usr/bin/env python3
"""Provision disposable Keycloak and managed DID profiles for the public journey.

Run only after the exact self-host ZIP starts. The selected issuer and verifier
use Marty's public profile API; custody is independently checked against a
disposable external OpenBao transit instance. No CSCA or DSC is involved.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def required_environment(values: dict[str, str]) -> dict[str, str]:
    names = (
        "SELFHOST_GATEWAY_URL", "SELFHOST_KEYCLOAK_URL", "SELFHOST_PUBLIC_DOMAIN",
        "SELFHOST_TEST_USERNAME", "SELFHOST_TEST_PASSWORD", "SELFHOST_ORG_ID",
        "SELFHOST_ISSUER_DID", "SELFHOST_VERIFIER_DID",
        "SELFHOST_SECRET_ROOT", "SELFHOST_COMPOSE_MODEL_PATH",
        "SELFHOST_BAO_AUDIT_URL", "SELFHOST_BAO_AUDIT_TOKEN_FILE",
        "SELFHOST_CUSTODY_SIGNING_KEY_FILE", "SELFHOST_SOURCE_SHA",
        "SELFHOST_ARCHIVE_SHA256", "SELFHOST_IMAGE_LOCK_SHA256",
        "SELFHOST_KMS_CUSTODY_EVIDENCE_PATH",
        "SELFHOST_KMS_CUSTODY_SIGNATURE_PATH",
    )
    missing = [name for name in names if not values.get(name)]
    if missing:
        raise ValueError("synthetic fixture inputs absent: " + ", ".join(missing))
    if values["SELFHOST_ISSUER_DID"] != values["SELFHOST_VERIFIER_DID"]:
        raise ValueError("synthetic issuer and verifier must share the local organization DID")
    did = "did:web:" + values["SELFHOST_PUBLIC_DOMAIN"].replace(":", "%3A")
    did += ":orgs:" + values["SELFHOST_ORG_ID"]
    if values["SELFHOST_ISSUER_DID"] != did:
        raise ValueError("synthetic DID differs from installed public domain and organization")
    if not values["SELFHOST_TEST_USERNAME"].lower().endswith("@selfhost.marty.invalid"):
        raise ValueError("synthetic operator email must use the reserved test domain")
    for name in ("SELFHOST_GATEWAY_URL", "SELFHOST_KEYCLOAK_URL",
                 "SELFHOST_BAO_AUDIT_URL"):
        url = urlsplit(values[name])
        if (url.scheme != "http" or url.hostname not in {"127.0.0.1", "localhost"}
                or url.username or url.password or url.path not in {"", "/"}
                or url.query or url.fragment):
            raise ValueError(f"{name} must use disposable loopback HTTP")
    return {name: values[name] for name in names}


def managed_reference(org: str, did: str, purpose: str) -> str:
    if purpose not in {"vc_jwt_issuer", "oid4vp_request_signing"}:
        raise ValueError("unsupported synthetic profile purpose")
    tuple_value = f"{org}|{did}|{purpose}|SD_JWT_VC|ES256"
    token = uuid.uuid5(uuid.NAMESPACE_URL, tuple_value).hex[:20]
    prefix = "cred-issuer-" if purpose == "vc_jwt_issuer" else "oid4vp-verifier-"
    return f"{prefix}{token}-es256"


def checked_file(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} file is absent or linked")
    if path.stat().st_size == 0:
        raise ValueError(f"{label} file is empty")
    return path


def validate_installed_model(model: dict, fixture: dict[str, str]) -> None:
    services = model.get("services", {})
    if not isinstance(services, dict):
        raise ValueError("installed Compose model has no service map")
    migration = services.get("db-migrate", {}).get("environment", {})
    configurator = services.get("keycloak-configurator", {}).get("environment", {})
    signing = services.get("signing-keys", {}).get("environment", {})
    bao = urlsplit(str(signing.get("BAO_ADDR", "")))
    audit = urlsplit(fixture["SELFHOST_BAO_AUDIT_URL"])
    for service, target, url_name in (("edge", 80, "SELFHOST_GATEWAY_URL"),
                                      ("keycloak", 8080, "SELFHOST_KEYCLOAK_URL")):
        ports = services.get(service, {}).get("ports")
        url_port = urlsplit(fixture[url_name]).port
        if (url_port is None or not isinstance(ports, list) or len(ports) != 1
                or not isinstance(ports[0], dict)
                or ports[0].get("host_ip") != "127.0.0.1"
                or str(ports[0].get("published")) != str(url_port)
                or ports[0].get("target") != target
                or ports[0].get("protocol", "tcp") != "tcp"):
            raise ValueError(f"{url_name} differs from installed {service} published port")
    if (migration.get("MARTY_ORG_ID") != fixture["SELFHOST_ORG_ID"]
            or migration.get("MARTY_ORG_ADMIN_EMAIL") != fixture["SELFHOST_TEST_USERNAME"]
            or migration.get("PUBLIC_DOMAIN") != fixture["SELFHOST_PUBLIC_DOMAIN"]
            or configurator.get("MARTY_ORG_ADMIN_EMAIL") != fixture["SELFHOST_TEST_USERNAME"]
            or configurator.get("KEYCLOAK_REALM") != "11id"
            or configurator.get("PUBLIC_DOMAIN") != fixture["SELFHOST_PUBLIC_DOMAIN"]
            or bao.scheme != "http" or bao.hostname != "host.docker.internal"
            or bao.port is None or bao.port != audit.port):
        raise ValueError("synthetic operator differs from migration-seeded organization")


def validate_public_p256_jwk(public_jwk: dict) -> ec.EllipticCurvePublicKey:
    if public_jwk.get("kty") != "EC" or public_jwk.get("crv") != "P-256":
        raise ValueError("resolved public issuer key is not P-256")
    coordinates = []
    for coordinate in ("x", "y"):
        value = public_jwk.get(coordinate)
        if not isinstance(value, str) or "=" in value:
            raise ValueError("resolved public issuer key is not canonical P-256")
        try:
            decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
        except (ValueError, TypeError) as error:
            raise ValueError("resolved public issuer key is not canonical P-256") from error
        canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
        if len(decoded) != 32 or canonical != value:
            raise ValueError("resolved public issuer key is not canonical P-256")
        coordinates.append(int.from_bytes(decoded, "big"))
    try:
        return ec.EllipticCurvePublicNumbers(*coordinates, ec.SECP256R1()).public_key()
    except ValueError as error:
        raise ValueError("resolved public issuer key is not valid P-256") from error


def validate_transit_binding(metadata: dict, public_jwk: dict) -> int:
    if (metadata.get("type") != "ecdsa-p256" or metadata.get("exportable") is not False
            or type(metadata.get("latest_version")) is not int
            or metadata["latest_version"] <= 0):
        raise ValueError("managed transit key lacks non-exportable P-256 custody")
    version = metadata["latest_version"]
    entry = metadata.get("keys", {}).get(str(version), {})
    pem = entry.get("public_key") if isinstance(entry, dict) else None
    if (not isinstance(pem, str)
            or not pem.startswith("-----BEGIN PUBLIC KEY-----\n")
            or not pem.rstrip().endswith("-----END PUBLIC KEY-----")):
        raise ValueError("managed transit key has no public key")
    # Compare parsed public keys, not just their shapes: the audit endpoint
    # could otherwise describe a different non-exportable key than the
    # installed service resolved through its canonical KMS adapter.
    resolved = validate_public_p256_jwk(public_jwk)
    try:
        audited = serialization.load_pem_public_key(pem.encode("ascii"))
    except (UnicodeError, ValueError) as error:
        raise ValueError("managed transit public key is invalid") from error
    if (not isinstance(audited, ec.EllipticCurvePublicKey)
            or not isinstance(audited.curve, ec.SECP256R1)
            or audited.public_numbers() != resolved.public_numbers()):
        raise ValueError("managed transit public key differs from resolved profile")
    return version


def validate_audit_token(metadata: dict) -> None:
    # Policy names and TTL are observable here; ACL contents are an operator
    # prerequisite and are not represented as verified custody evidence.
    policies = metadata.get("policies")
    ttl = metadata.get("ttl")
    if (not isinstance(policies, list)
            or "selfhost-qualification-audit" not in policies
            or "root" in policies
            or any(policy not in {"default", "selfhost-qualification-audit"}
                   for policy in policies)
            or type(ttl) is not int or not 0 < ttl <= 3600):
        raise ValueError("OpenBao audit token lacks expected policy name or short TTL")


def validate_profile_projection(profile: dict, *, did: str, purpose: str) -> dict:
    selector = {"issuer_did": did, "key_purpose": purpose,
                "credential_format": "SD_JWT_VC", "algorithm": "ES256"}
    if (not isinstance(profile, dict) or profile.get("status") != "active"
            or any(profile.get(name) != value for name, value in selector.items())):
        raise ValueError("public issuer profile differs from expected selector")
    return selector


def profile_proof(selector: dict, reference: str, version: int) -> dict:
    if not selector or not reference or type(version) is not int or version <= 0:
        raise ValueError("managed profile proof is incomplete")
    return {"profile_selector": selector, "key_reference": reference,
            "key_version": version}


def managed_key_binding(organization_id: str, reference: str) -> str:
    values = ("marty-managed-key-binding-v1", organization_id,
              "managed-openbao-transit", reference)
    digest = hashlib.sha256()
    for value in values:
        digest.update(value.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


async def keycloak_user(client: httpx.AsyncClient, fixture: dict[str, str],
                        admin_password: str) -> None:
    token_result = await client.post("/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli", "username": "admin",
        "password": admin_password,
    })
    token_result.raise_for_status()
    token = token_result.json().get("access_token")
    if not isinstance(token, str) or not token:
        raise ValueError("disposable Keycloak admin token is absent")
    headers = {"Authorization": f"Bearer {token}"}
    realm = "11id"
    email = fixture["SELFHOST_TEST_USERNAME"]
    lookup = await client.get(f"/admin/realms/{realm}/users", headers=headers,
                              params={"username": email, "exact": "true"})
    lookup.raise_for_status()
    users = lookup.json()
    if not isinstance(users, list) or len(users) > 1:
        raise ValueError("synthetic Keycloak user lookup is ambiguous")
    if not users:
        created = await client.post(f"/admin/realms/{realm}/users", headers=headers,
                                    json={"username": email, "email": email,
                                          "enabled": True, "emailVerified": True,
                                          "attributes": {"user_type": ["administrator"],
                                                         "onboarding_completed": ["true"]}})
        created.raise_for_status()
        lookup = await client.get(f"/admin/realms/{realm}/users", headers=headers,
                                  params={"username": email, "exact": "true"})
        lookup.raise_for_status()
        users = lookup.json()
    if not isinstance(users, list) or len(users) != 1 or not users[0].get("id"):
        raise ValueError("synthetic Keycloak user was not created")
    user_id = str(users[0]["id"])
    password = await client.put(
        f"/admin/realms/{realm}/users/{user_id}/reset-password", headers=headers,
        json={"type": "password", "value": fixture["SELFHOST_TEST_PASSWORD"],
              "temporary": False})
    password.raise_for_status()
    role = await client.get(f"/admin/realms/{realm}/roles/administrator", headers=headers)
    role.raise_for_status()
    mapped = await client.post(
        f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
        headers=headers, json=[role.json()])
    mapped.raise_for_status()


async def provision(fixture: dict[str, str]) -> dict:
    # The runner sets cwd to the exact reviewed integration checkout. Reuse its
    # public API client and PKCE helper instead of copying wallet protocol code.
    sys.path.insert(0, str(Path.cwd()))
    from tests.integration.gateway.helpers.auth_helper import AuthHelper
    from tests.integration.gateway.helpers.gateway_client import GatewayClient

    secret_root = Path(fixture["SELFHOST_SECRET_ROOT"])
    admin_file = checked_file(str(secret_root / "keycloak_admin_password"),
                              "Keycloak admin password")
    audit_file = checked_file(fixture["SELFHOST_BAO_AUDIT_TOKEN_FILE"], "OpenBao audit token")
    audit_token = audit_file.read_text(encoding="utf-8").strip()
    if not audit_token:
        raise ValueError("OpenBao audit token is empty")
    async with httpx.AsyncClient(base_url=fixture["SELFHOST_KEYCLOAK_URL"],
                                 timeout=20.0, trust_env=False) as keycloak:
        await keycloak_user(keycloak, fixture, admin_file.read_text(encoding="utf-8").strip())
    helper = AuthHelper(auth_service_url=fixture["SELFHOST_GATEWAY_URL"],
                        keycloak_local_url=fixture["SELFHOST_KEYCLOAK_URL"],
                        gateway_external_host=fixture["SELFHOST_PUBLIC_DOMAIN"])
    session = await helper.get_session_id(fixture["SELFHOST_TEST_USERNAME"],
                                          fixture["SELFHOST_TEST_PASSWORD"])
    if not session:
        raise ValueError("synthetic operator public PKCE login failed")
    org = fixture["SELFHOST_ORG_ID"]
    did = fixture["SELFHOST_ISSUER_DID"]
    async with GatewayClient(base_url=fixture["SELFHOST_GATEWAY_URL"]) as gateway:
        gateway.set_session(session)
        organizations = await gateway.list_organizations()
        if not any(item.get("id") == org for item in organizations):
            raise ValueError("synthetic operator cannot access migration-seeded organization")
        proofs = []
        async with httpx.AsyncClient(base_url=fixture["SELFHOST_BAO_AUDIT_URL"],
                                     timeout=20.0, trust_env=False) as bao:
            lookup = await bao.get("/v1/auth/token/lookup-self", headers={
                "X-Vault-Token": audit_token})
            lookup.raise_for_status()
            validate_audit_token(lookup.json().get("data", {}))
            for purpose in ("vc_jwt_issuer", "oid4vp_request_signing"):
                profile = await gateway.create_issuer_identity(
                    organization_id=org, issuer_did=did, key_purpose=purpose,
                    credential_format="SD_JWT_VC", algorithm="ES256")
                selector = validate_profile_projection(profile, did=did, purpose=purpose)
                resolved = await gateway.resolve_issuer_identity_public_key(
                    organization_id=org, issuer_did=did, key_purpose=purpose,
                    credential_format="SD_JWT_VC", algorithm="ES256")
                if not isinstance(resolved, dict) or resolved.get("identity") != profile:
                    raise ValueError("resolved public identity differs from created profile")
                reference = managed_reference(org, did, purpose)
                if resolved.get("managed_key_binding_sha256") != managed_key_binding(org,
                                                                                     reference):
                    raise ValueError("resolved public identity uses an unexpected managed key")
                response = await bao.get(f"/v1/transit/keys/{quote(reference)}", headers={
                    "X-Vault-Token": audit_token})
                response.raise_for_status()
                version = validate_transit_binding(response.json().get("data", {}),
                                                   resolved.get("public_jwk", {}))
                proofs.append(profile_proof(selector, reference, version))
    return {"schema": "marty.selfhost-kms-custody/v1",
            "source_sha": fixture["SELFHOST_SOURCE_SHA"],
            "archive_sha256": fixture["SELFHOST_ARCHIVE_SHA256"],
            "image_lock_sha256": fixture["SELFHOST_IMAGE_LOCK_SHA256"],
            "organization_id": org, "issuer_did": did, "verifier_did": did,
            "issuer_key_non_exportable": True, "verifier_key_non_exportable": True,
            "profile_proofs": proofs}


def write_signed_evidence(fixture: dict[str, str], document: dict) -> None:
    evidence = Path(fixture["SELFHOST_KMS_CUSTODY_EVIDENCE_PATH"])
    signature = Path(fixture["SELFHOST_KMS_CUSTODY_SIGNATURE_PATH"])
    private_key = checked_file(fixture["SELFHOST_CUSTODY_SIGNING_KEY_FILE"],
                               "custody signing key")
    if (not evidence.is_absolute() or not signature.is_absolute()
            or evidence.exists() or signature.exists()):
        raise ValueError("synthetic custody outputs are not fresh absolute paths")
    evidence.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key),
         "-in", str(evidence), "-out", str(signature)],
        capture_output=True, check=False, timeout=30)
    if result.returncode != 0 or not signature.is_file() or signature.stat().st_size == 0:
        raise ValueError("synthetic custody evidence signing failed")


def main() -> int:
    try:
        fixture = required_environment(dict(os.environ))
        model_path = checked_file(fixture["SELFHOST_COMPOSE_MODEL_PATH"], "Compose model")
        validate_installed_model(json.loads(model_path.read_text(encoding="utf-8")), fixture)
        document = asyncio.run(provision(fixture))
        write_signed_evidence(fixture, document)
    except (OSError, RuntimeError, TypeError, ValueError, httpx.HTTPError) as error:
        # Never include HTTP bodies or secret-bearing tracebacks in a release report.
        print(f"synthetic self-host fixture failed: {type(error).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
