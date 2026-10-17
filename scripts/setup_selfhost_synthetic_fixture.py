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
import re
import ssl
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx

from selfhost_openbao_client import (
    CUSTODY_SIGNER, CUSTODY_SIGNER_POLICY, custody_signer_public,
)


def required_environment(values: dict[str, str]) -> dict[str, str]:
    names = (
        "SELFHOST_GATEWAY_URL", "SELFHOST_KEYCLOAK_URL", "SELFHOST_PUBLIC_DOMAIN",
        "SELFHOST_TEST_USERNAME", "SELFHOST_TEST_PASSWORD", "SELFHOST_ORG_ID",
        "SELFHOST_ISSUER_DID", "SELFHOST_VERIFIER_DID",
        "SELFHOST_SECRET_ROOT", "SELFHOST_COMPOSE_MODEL_PATH",
        "SELFHOST_BAO_AUDIT_URL", "SELFHOST_BAO_AUDIT_TOKEN_FILE",
        "SELFHOST_KMS_JWK_TOOL",
        "SELFHOST_CUSTODY_SIGNING_TOKEN_FILE", "SELFHOST_SOURCE_SHA",
        "SELFHOST_ARCHIVE_SHA256", "SELFHOST_IMAGE_LOCK_SHA256",
        "SELFHOST_RUN_ID", "SELFHOST_FIXTURE_SHA256", "SELFHOST_CUSTODY_CHALLENGE",
        "SELFHOST_KMS_CUSTODY_EVIDENCE_PATH",
        "SELFHOST_KMS_CUSTODY_SIGNATURE_PATH",
        "SELFHOST_KMS_CUSTODY_PUBLIC_KEY_PATH",
    )
    missing = [name for name in names if not values.get(name)]
    if missing:
        raise ValueError("synthetic fixture inputs absent: " + ", ".join(missing))
    if (re.fullmatch(r"[0-9a-f]{64}", values["SELFHOST_CUSTODY_CHALLENGE"]) is None
            or re.fullmatch(r"[0-9a-f]{64}", values["SELFHOST_FIXTURE_SHA256"]) is None):
        raise ValueError("synthetic custody challenge or fixture digest is invalid")
    if values["SELFHOST_ISSUER_DID"] != values["SELFHOST_VERIFIER_DID"]:
        raise ValueError("synthetic issuer and verifier must share the local organization DID")
    did = "did:web:" + values["SELFHOST_PUBLIC_DOMAIN"].replace(":", "%3A")
    did += ":orgs:" + values["SELFHOST_ORG_ID"]
    if values["SELFHOST_ISSUER_DID"] != did:
        raise ValueError("synthetic DID differs from installed public domain and organization")
    if not values["SELFHOST_TEST_USERNAME"].lower().endswith("@selfhost.marty.invalid"):
        raise ValueError("synthetic operator email must use the reserved test domain")
    for name in ("SELFHOST_GATEWAY_URL", "SELFHOST_KEYCLOAK_URL"):
        url = urlsplit(values[name])
        if (url.scheme != "http" or url.hostname not in {"127.0.0.1", "localhost"}
                or url.username or url.password or url.path not in {"", "/"}
                or url.query or url.fragment):
            raise ValueError(f"{name} must use disposable loopback HTTP")
    audit = urlsplit(values["SELFHOST_BAO_AUDIT_URL"])
    if (audit.scheme != "https" or audit.hostname not in {"127.0.0.1", "localhost"}
            or audit.port is None or audit.username or audit.password
            or audit.path not in {"", "/"} or audit.query or audit.fragment):
        raise ValueError("SELFHOST_BAO_AUDIT_URL must use disposable loopback HTTPS")
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
            or bao.scheme != "https" or bao.hostname != "host.docker.internal"
            or bao.port is None or bao.port != audit.port):
        raise ValueError("synthetic operator differs from migration-seeded organization")


def trusted_audit_context(secret_root: Path) -> ssl.SSLContext:
    ca = checked_file(str(secret_root / "openbao_tls_ca_cert"), "OpenBao TLS CA")
    if b"PRIVATE KEY" in ca.read_bytes():
        raise ValueError("OpenBao TLS CA contains private key material")
    return ssl.create_default_context(cafile=str(ca))


def audit_client(url: str, secret_root: Path) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=url, timeout=20.0, trust_env=False,
                             verify=trusted_audit_context(secret_root))


def validate_public_p256_jwk(public_jwk: dict) -> None:
    if (not isinstance(public_jwk, dict) or public_jwk.get("kty") != "EC"
            or public_jwk.get("crv") != "P-256"):
        raise ValueError("resolved public issuer key is not P-256")
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


def validate_transit_binding(metadata: dict, public_jwk: dict, jwk_tool: Path) -> int:
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
    # Reuse the Rust public-key converter already used by release qualification.
    # Python only compares canonical public coordinates; it does not parse EC.
    validate_public_p256_jwk(public_jwk)
    try:
        result = subprocess.run([str(jwk_tool)], input=pem, capture_output=True,
                                text=True, timeout=10, check=False)
        if result.returncode != 0 or len(result.stdout) > 16 * 1024:
            raise ValueError("managed transit public key is invalid")
        audited = json.loads(result.stdout)
        validate_public_p256_jwk(audited)
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as error:
        raise ValueError("managed transit public key is invalid") from error
    if any(audited[name] != public_jwk[name] for name in ("kty", "crv", "x", "y")):
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


def validate_custody_signer_token(metadata: dict) -> None:
    policies = metadata.get("policies")
    ttl = metadata.get("ttl")
    if (not isinstance(policies, list) or set(policies) != {CUSTODY_SIGNER_POLICY}
            or metadata.get("orphan") is not True
            or type(ttl) is not int or not 0 < ttl <= 3600):
        raise ValueError("OpenBao custody signer token is not scoped or short-lived")


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
    jwk_tool = checked_file(fixture["SELFHOST_KMS_JWK_TOOL"], "Rust public-key converter")
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
        async with audit_client(fixture["SELFHOST_BAO_AUDIT_URL"], secret_root) as bao:
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
                                                   resolved.get("public_jwk", {}), jwk_tool)
                proofs.append(profile_proof(selector, reference, version))
    return {"schema": "marty.selfhost-kms-custody/v1",
            "source_sha": fixture["SELFHOST_SOURCE_SHA"],
            "archive_sha256": fixture["SELFHOST_ARCHIVE_SHA256"],
            "image_lock_sha256": fixture["SELFHOST_IMAGE_LOCK_SHA256"],
            "run_id": fixture["SELFHOST_RUN_ID"],
            "fixture_sha256": fixture["SELFHOST_FIXTURE_SHA256"],
            "challenge": fixture["SELFHOST_CUSTODY_CHALLENGE"],
            "organization_id": org, "issuer_did": did, "verifier_did": did,
            "issuer_key_non_exportable": True, "verifier_key_non_exportable": True,
            "profile_proofs": proofs}


async def write_signed_evidence(fixture: dict[str, str], document: dict) -> None:
    evidence = Path(fixture["SELFHOST_KMS_CUSTODY_EVIDENCE_PATH"])
    signature = Path(fixture["SELFHOST_KMS_CUSTODY_SIGNATURE_PATH"])
    public_key = Path(fixture["SELFHOST_KMS_CUSTODY_PUBLIC_KEY_PATH"])
    token_file = checked_file(fixture["SELFHOST_CUSTODY_SIGNING_TOKEN_FILE"],
                              "OpenBao custody signer token")
    token = token_file.read_text(encoding="ascii").strip()
    if not token:
        raise ValueError("OpenBao custody signer token is empty")
    if (not evidence.is_absolute() or not signature.is_absolute()
            or not public_key.is_absolute()
            or any(path.exists() or path.is_symlink()
                   for path in (evidence, signature, public_key))):
        raise ValueError("synthetic custody outputs are not fresh absolute paths")
    headers = {"X-Vault-Token": token}
    async with audit_client(fixture["SELFHOST_BAO_AUDIT_URL"],
                            Path(fixture["SELFHOST_SECRET_ROOT"])) as bao:
        lookup = await bao.get("/v1/auth/token/lookup-self", headers=headers)
        lookup.raise_for_status()
        validate_custody_signer_token(lookup.json().get("data", {}))
        metadata = await bao.get(f"/v1/transit/keys/{CUSTODY_SIGNER}", headers=headers)
        metadata.raise_for_status()
        version, pem = custody_signer_public(metadata.json().get("data", {}))
        denied_export = await bao.get(
            f"/v1/transit/export/signing-key/{CUSTODY_SIGNER}", headers=headers)
        denied_other_sign = await bao.post(
            "/v1/transit/sign/cred-issuer-qualification-denied", headers=headers,
            json={"input": "YQ=="})
        if denied_export.status_code != 403 or denied_other_sign.status_code != 403:
            raise ValueError("OpenBao custody signer token has excess capabilities")
        document = {**document,
                    "attestation_key_reference": CUSTODY_SIGNER,
                    "attestation_key_version": version,
                    "attestation_key_non_exportable": True}
        raw = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
        result = await bao.post(f"/v1/transit/sign/{CUSTODY_SIGNER}", headers=headers,
                                json={"input": base64.b64encode(raw).decode("ascii")})
        result.raise_for_status()
        encoded = result.json().get("data", {}).get("signature")
        prefix = f"vault:v{version}:"
        if not isinstance(encoded, str) or not encoded.startswith(prefix):
            raise ValueError("OpenBao custody signature version differs from public key")
        try:
            signed = base64.b64decode(encoded[len(prefix):], validate=True)
        except ValueError as error:
            raise ValueError("OpenBao custody signature is invalid") from error
        if (len(signed) != 64
                or base64.b64encode(signed).decode("ascii") != encoded[len(prefix):]):
            raise ValueError("OpenBao custody signature is invalid")
    evidence.write_bytes(raw)
    signature.write_bytes(signed)
    public_key.write_text(pem, encoding="ascii")


def main() -> int:
    try:
        fixture = required_environment(dict(os.environ))
        model_path = checked_file(fixture["SELFHOST_COMPOSE_MODEL_PATH"], "Compose model")
        validate_installed_model(json.loads(model_path.read_text(encoding="utf-8")), fixture)
        async def setup() -> None:
            document = await provision(fixture)
            await write_signed_evidence(fixture, document)

        asyncio.run(setup())
    except (OSError, RuntimeError, TypeError, ValueError, httpx.HTTPError) as error:
        # Never include HTTP bodies or secret-bearing tracebacks in a release report.
        print(f"synthetic self-host fixture failed: {type(error).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
