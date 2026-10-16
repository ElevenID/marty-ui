#!/usr/bin/env python3
"""Run the public business journey against one exact extracted self-host ZIP.

This opt-in component starts and tears down one fresh, uniquely named Docker
project from a prepared ZIP. It does not provision external OpenBao, KMS keys,
operator identities, or release signatures, so it cannot qualify a bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import nullcontext
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from check_prepared_selfhost_consumer import check, verify_descriptor
from check_selfhost_installed_runtime_plan import (
    BETA_SERVICES, EXPECTED_ROLE_SECRETS, EXPECTED_SERVICES, plan,
)
from qualify_selfhost_migrations import PRIVATE_KEY_CONTENT_QUERY, PRIVATE_KEY_SCHEMA_QUERY
from provision_selfhost_disposable_tls import exact_images, openbao_network
from selfhost_handoff_contract import PINNED_INTEGRATION_SHA
from selfhost_journey_diagnostics import RunDiagnostics
from selfhost_openbao_client import Bao, CUSTODY_SIGNER, custody_signer_public


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PROJECT = re.compile(r"marty-selfhost-qual-[0-9a-f]{16}\Z")
FIXTURE_PATH = "scripts/setup_selfhost_synthetic_fixture.py"
KEYCLOAK_SQL_PATH = "scripts/sql/keycloak-kms-only-verify.sql"
JOURNEY = "tests/oss_stack/selfhost_customer_journey.py"
JOURNEY_INPUTS = ("SELFHOST_GATEWAY_URL", "SELFHOST_KEYCLOAK_URL",
                  "SELFHOST_PUBLIC_DOMAIN", "SELFHOST_TEST_USERNAME",
                  "SELFHOST_TEST_PASSWORD", "SELFHOST_ORG_ID",
                  "SELFHOST_ISSUER_DID", "SELFHOST_VERIFIER_DID")
COMPLETED = frozenset({"db-migrate", "issuance-migrations", "revocation-profile-migrate",
                       "keycloak-configurator"})
NOT_LOCAL = BETA_SERVICES | {"cloudflared"}
LOCAL_SERVICES = EXPECTED_SERVICES - NOT_LOCAL
LOCAL_SECRET_NAMES = frozenset(
    secret for service in LOCAL_SERVICES
    for secret in EXPECTED_ROLE_SECRETS.get(service, ())
)
SECRET_CATALOG = Path(__file__).resolve().parents[1] / "deploy-config/catalog/secrets.json"


def optional_local_secrets(catalog_path: Path = SECRET_CATALOG) -> frozenset[str]:
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    if catalog.get("schema_version") != 1 or not isinstance(catalog.get("secrets"), dict):
        raise ValueError("self-host secret catalog is invalid")
    optional = set()
    for entry in catalog["secrets"].values():
        if not isinstance(entry, dict):
            raise ValueError("self-host secret catalog entry is invalid")
        name = entry.get("compose_secret")
        if entry.get("allow_empty") is True and name in LOCAL_SECRET_NAMES:
            optional.add(name)
    return frozenset(optional)


OPTIONAL_LOCAL_SECRET_NAMES = optional_local_secrets()
FALSE_VALUES = frozenset({"false", "0", "no", "n", "off"})
CANVAS_DISABLED_FLAGS = frozenset({
    "CANVAS_PORTABLE_INTEGRATION_ENABLED", "CANVAS_LEGACY_EVENT_INGEST_ENABLED",
    "CANVAS_MIRROR_WORKER_ENABLED",
})
CANVAS_UNUSED_SETTINGS = frozenset({
    "CANVAS_CREDENTIALS_PUBLISH_URL", "CANVAS_CREDENTIALS_STATUS_SYNC_URL",
    "CANVAS_CREDENTIALS_ISSUER_ID", "CANVAS_CREDENTIALS_BADGECLASS_ID",
})


def measured(diagnostics: RunDiagnostics | None, name: str):
    return diagnostics.measure(name) if diagnostics is not None else nullcontext()


def command(args: list[str], *, cwd: Path | None = None,
            env: dict[str, str] | None = None, timeout: int = 60,
            input_text: str | None = None) -> str:
    try:
        result = subprocess.run(args, cwd=cwd, env=env, timeout=timeout,
                                input=input_text, capture_output=True,
                                text=True, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("installed journey command failed") from error
    if result.returncode:
        # Responses can contain credentials and claims. Never put raw output in
        # an artifact or exception; the private runner log is operator-owned.
        raise ValueError("installed journey command returned failure")
    return result.stdout


def verify_keycloak_database_custody(compose: list[str], install_root: Path,
                                     source_checkout: Path,
                                     source_sha: str,
                                     environment: dict[str, str]) -> None:
    """Run the reviewed read-only custody gate inside the owned PostgreSQL service."""
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise ValueError("reviewed Keycloak database custody source is invalid")
    sql = command(["git", "show", f"{source_sha}:{KEYCLOAK_SQL_PATH}"],
                  cwd=source_checkout)
    if not sql.startswith("-- Read-only release check") or "BEGIN READ ONLY;" not in sql:
        raise ValueError("reviewed Keycloak database custody SQL is invalid")
    command([*compose, "exec", "-T", "postgres", "psql", "-X", "-q",
             "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "keycloak"],
            cwd=install_root, env=environment, input_text=sql)


def exercise_installed_keycloak_keys(environment: dict[str, str],
                                    secret_root: Path) -> None:
    """Require issuance and refresh in both installed realms before the SQL scan."""
    base = environment.get("SELFHOST_KEYCLOAK_URL", "")
    parsed = urlsplit(base)
    if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.username or parsed.password or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment):
        raise ValueError("installed Keycloak URL must use disposable loopback HTTP")
    password_file = secret_root / "keycloak_admin_password"
    if password_file.is_symlink() or not password_file.is_file():
        raise ValueError("installed Keycloak admin password is absent or linked")
    admin_password = password_file.read_text(encoding="utf-8").strip()
    test_username = environment.get("SELFHOST_TEST_USERNAME", "")
    test_password = environment.get("SELFHOST_TEST_PASSWORD", "")
    if not admin_password or not test_username or not test_password:
        raise ValueError("installed Keycloak probe credentials are absent")
    opener = build_opener(ProxyHandler({}))

    def token(realm: str, fields: dict[str, str]) -> dict:
        request = Request(
            f"{base.rstrip('/')}/realms/{realm}/protocol/openid-connect/token",
            data=urlencode({"client_id": "admin-cli", **fields}).encode("ascii"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with opener.open(request, timeout=20) as response:
                result = json.load(response)
        except Exception:
            # Never propagate an HTTP body, credential, or token to diagnostics.
            raise ValueError("installed Keycloak token use failed") from None
        if (not isinstance(result, dict) or result.get("token_type") != "Bearer"
                or not isinstance(result.get("access_token"), str)
                or not result["access_token"]
                or not isinstance(result.get("refresh_token"), str)
                or not result["refresh_token"]):
            raise ValueError("installed Keycloak token response is incomplete")
        return result

    for realm, username, password in (
        ("master", "admin", admin_password),
        ("11id", test_username, test_password),
    ):
        issued = token(realm, {"grant_type": "password", "username": username,
                               "password": password})
        token(realm, {"grant_type": "refresh_token",
                      "refresh_token": issued["refresh_token"]})


def verify_marty_database_custody(compose: list[str], install_root: Path,
                                  environment: dict[str, str]) -> None:
    """Reject private-key schema and content after representative installed writes."""
    psql = [*compose, "exec", "-T", "postgres", "psql", "-X",
            "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "marty"]
    schema = command([*psql, "-At"], cwd=install_root, env=environment,
                     input_text=PRIVATE_KEY_SCHEMA_QUERY)
    if schema.strip():
        raise ValueError("installed Marty database retains private-key schema")
    command([*psql, "-q"], cwd=install_root, env=environment,
            input_text=PRIVATE_KEY_CONTENT_QUERY)


def build_public_kms_jwk_tool(source_checkout: Path, target_root: Path) -> Path:
    if (target_root.is_symlink() or not target_root.is_dir()
            or any(target_root.iterdir())):
        raise ValueError("Rust public-key build target is not fresh")
    if command(["git", "status", "--porcelain", "--untracked-files=all"],
               cwd=source_checkout).strip():
        raise ValueError("release source checkout has local changes")
    # The qualification binary must come from this source, not ambient Cargo
    # configuration, compiler wrappers, flags, or a shared build cache.
    inherited = {"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR",
                 "TEMP", "TMP", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY",
                 "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    build_env = {name: value for name, value in os.environ.items()
                 if name.upper() in inherited}
    cargo_home = target_root / "cargo-home"
    cargo_target = target_root / "target"
    cargo_home.mkdir()
    build_env["CARGO_HOME"] = str(cargo_home)
    build_env["CARGO_TARGET_DIR"] = str(cargo_target)
    command(["cargo", "build", "--locked", "--manifest-path",
             str(source_checkout / "rust" / "Cargo.toml"), "-p", "marty-release-evidence",
             "--bin", "public-kms-jwk"], cwd=source_checkout / "rust",
            env=build_env, timeout=1200)
    tool = cargo_target / "debug" / "public-kms-jwk"
    if tool.is_symlink() or not tool.is_file():
        raise ValueError("source-built Rust public-key converter is absent")
    return tool


def pinned_integration_checkout(root: Path, revision: str) -> None:
    if (revision != PINNED_INTEGRATION_SHA or root.is_symlink()
            or not root.is_dir()):
        raise ValueError("integration checkout or exact revision is invalid")
    if command(["git", "rev-parse", "HEAD^{commit}"], cwd=root).strip() != revision:
        raise ValueError("integration checkout differs from pinned revision")
    if command(["git", "remote", "get-url", "origin"], cwd=root).strip() not in {
        "https://github.com/ElevenID/marty-integration-tests.git",
        "https://github.com/ElevenID/marty-integration-tests",
    }:
        raise ValueError("integration checkout is not the reviewed public repository")
    if command(["git", "status", "--porcelain"], cwd=root).strip():
        raise ValueError("integration checkout has uncommitted changes")
    command(["git", "merge-base", "--is-ancestor", revision,
             "refs/remotes/origin/main"], cwd=root)
    if not (root / JOURNEY).is_file():
        raise ValueError("pinned integration checkout lacks the public journey")


def live_services(raw: str, model: dict) -> dict[str, str]:
    parsed = parse_status(raw)
    services = model.get("services")
    if not isinstance(services, dict) or set(services) != EXPECTED_SERVICES:
        raise ValueError("installed Compose model differs from reviewed service closure")
    actual = {}
    for item in parsed:
        name = item.get("Service")
        if not isinstance(name, str) or name in actual:
            raise ValueError("installed Compose status contains duplicate or unnamed roles")
        actual[name] = item
    expected = LOCAL_SERVICES
    if set(actual) != expected:
        raise ValueError("installed Compose status lacks the exact local service closure")
    states: dict[str, str] = {}
    for name, item in actual.items():
        state, health, exit_code = item.get("State"), item.get("Health"), item.get("ExitCode")
        if name in COMPLETED:
            if state != "exited" or exit_code != 0:
                raise ValueError(f"installed one-shot service did not complete: {name}")
        elif state != "running":
            raise ValueError(f"installed runtime service is not running: {name}")
        elif "healthcheck" in services[name] and health != "healthy":
            raise ValueError(f"installed runtime service is not healthy: {name}")
        states[name] = state
    return states


def parse_status(raw: str) -> list[dict]:
    if not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except ValueError:
        try:
            parsed = [json.loads(line) for line in raw.splitlines() if line.strip()]
        except ValueError as nested:
            raise ValueError("installed Compose status is invalid") from nested
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list) or any(not isinstance(item, dict) for item in parsed):
        raise ValueError("installed Compose status is invalid")
    return parsed


def fresh_project(state_root: Path, compose: list[str], install_root: Path,
                  environment: dict[str, str]) -> None:
    if (state_root.is_symlink() or not state_root.is_dir()
            or any(state_root.iterdir())):
        raise ValueError("qualification state root is not a fresh empty directory")
    empty_project(compose, install_root, environment)


def disabled_optional_secrets(model: dict | None) -> frozenset[str]:
    if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
        return frozenset()
    services = model["services"]

    def environment(service: str) -> dict | None:
        entry = services.get(service)
        if not isinstance(entry, dict) or not isinstance(entry.get("environment"), dict):
            return None
        return entry["environment"]

    allowed = {"google_analytics_measurement_id", "google_site_verification"}
    keycloak = environment("keycloak-configurator")
    notification = environment("notification")
    if keycloak is not None:
        social = keycloak.get("KEYCLOAK_SOCIAL_LOGIN_ENABLED")
        if isinstance(social, str) and social.lower() in FALSE_VALUES:
            allowed.update(("google_client_id", "google_client_secret"))
        if (notification is not None
                and keycloak.get("KEYCLOAK_SMTP_USERNAME") == ""
                and notification.get("SMTP_USERNAME") == ""):
            allowed.add("smtp_password")
    observed_canvas: set[str] = set()
    canvas_disabled = True
    for service in sorted(LOCAL_SERVICES):
        env = environment(service)
        if env is None:
            continue
        for name in CANVAS_DISABLED_FLAGS:
            if name in env:
                observed_canvas.add(name)
                value = env[name]
                if not isinstance(value, str) or value.lower() not in FALSE_VALUES:
                    canvas_disabled = False
        for name in CANVAS_UNUSED_SETTINGS:
            if name in env:
                observed_canvas.add(name)
                if env[name] != "":
                    canvas_disabled = False
    if (canvas_disabled and observed_canvas ==
            CANVAS_DISABLED_FLAGS | CANVAS_UNUSED_SETTINGS):
        allowed.add("canvas_credentials_shared_secret")
    return frozenset(allowed & OPTIONAL_LOCAL_SECRET_NAMES)


def required_secrets(secret_root: Path, model: dict | None = None) -> None:
    if secret_root.is_symlink() or not secret_root.is_dir():
        raise ValueError("qualification secret root is absent or linked")
    empty_allowed = disabled_optional_secrets(model)
    for name in sorted(LOCAL_SECRET_NAMES):
        path = secret_root / name
        if (path.is_symlink() or not path.is_file()
                or (path.stat().st_size == 0 and name not in empty_allowed)):
            raise ValueError(f"qualification secret material is missing: {name}")
        if path.stat().st_size == 0:
            continue
        # Bundled examples use these literal sentinels. Never read secret
        # contents into a report or command line.
        with path.open("rb") as stream:
            prefix = stream.read(32).strip().lower()
        if prefix.startswith((b"change-me", b"change_me", b"changeme",
                              b"replace-me", b"replace_me", b"placeholder")):
            raise ValueError(f"qualification secret is a placeholder: {name}")


def fixture_setup(script: Path, digest: str, integration_checkout: Path) -> None:
    if (not script.is_absolute() or script.is_symlink() or not script.is_file()
            or SHA256.fullmatch(digest) is None
            or script.resolve().is_relative_to(integration_checkout.resolve())):
        raise ValueError("operator fixture setup script or SHA256 is invalid")
    if hashlib.sha256(script.read_bytes()).hexdigest() != digest:
        raise ValueError("operator fixture setup script changed")


def source_bound_fixture(script: Path, digest: str, source_checkout: Path,
                         source_sha: str) -> None:
    if script.resolve() != (source_checkout / FIXTURE_PATH).resolve():
        raise ValueError("fixture setup is not the reviewed source hook")
    if command(["git", "status", "--porcelain", "--", FIXTURE_PATH],
               cwd=source_checkout).strip():
        raise ValueError("source fixture hook has local changes")
    reviewed = command(["git", "show", f"{source_sha}:{FIXTURE_PATH}"],
                       cwd=source_checkout)
    if hashlib.sha256(reviewed.encode("utf-8")).hexdigest() != digest:
        raise ValueError("fixture hook differs from the prepared source commit")


def live_custody_signer(install_root: Path, openbao_state_root: Path,
                        secret_root: Path, openbao_project: str, model: dict,
                        environment: dict[str, str]) -> tuple[int, str]:
    """Enroll the signer from the owned, image-locked local OpenBao instance."""
    endpoint = environment.get("SELFHOST_BAO_AUDIT_URL", "")
    match = re.fullmatch(r"https://127\.0\.0\.1:([0-9]{2,5})", endpoint)
    if match is None or not 1 <= int(match.group(1)) <= 65535:
        raise ValueError("custody audit endpoint is not the installed loopback OpenBao")
    signing = model.get("services", {}).get("signing-keys", {}).get("environment", {})
    service_url = urlsplit(str(signing.get("BAO_ADDR", "")))
    if (service_url.scheme != "https" or service_url.hostname != "host.docker.internal"
            or service_url.port != int(match.group(1))):
        raise ValueError("installed signing-keys uses a different OpenBao port")
    if (not openbao_state_root.is_absolute() or openbao_state_root.is_symlink()
            or not openbao_state_root.is_dir()):
        raise ValueError("custody OpenBao state root is invalid")
    state_root = openbao_state_root.resolve()
    ca = state_root / "tls" / "ca.crt"
    staged_ca = secret_root / "openbao_tls_ca_cert"
    if (ca.is_symlink() or staged_ca.is_symlink() or not ca.is_file()
            or not staged_ca.is_file() or ca.stat().st_size > 65536
            or ca.read_bytes() != staged_ca.read_bytes()):
        raise ValueError("custody OpenBao CA differs from the installed CA")
    _, image = exact_images(install_root)
    openbao_network(openbao_project, state_root, image,
                    expected_host_port=int(match.group(1)))
    token_file = Path(environment.get("SELFHOST_BAO_AUDIT_TOKEN_FILE", ""))
    if (not token_file.is_absolute() or token_file.is_symlink()
            or not token_file.is_file() or token_file.stat().st_size > 2048):
        raise ValueError("custody audit token file is invalid")
    token = token_file.read_text(encoding="ascii").strip()
    if not token:
        raise ValueError("custody audit token is absent")
    bao = Bao(endpoint, ca, token)
    lookup = bao.request("GET", "auth/token/lookup-self").get("data", {})
    policies = lookup.get("policies")
    if (not isinstance(policies, list) or "selfhost-qualification-audit" not in policies
            or set(policies) - {"selfhost-qualification-audit", "default"}
            or type(lookup.get("ttl")) is not int or not 0 < lookup["ttl"] <= 3600):
        raise ValueError("custody audit token has excess authority or expired")
    metadata_path = f"transit/keys/{CUSTODY_SIGNER}"
    forbidden_paths = (
        f"{metadata_path}/config", f"{metadata_path}/rotate",
        f"{metadata_path}/import", f"transit/sign/{CUSTODY_SIGNER}",
        f"transit/export/signing-key/{CUSTODY_SIGNER}",
        "auth/token/create", "sys/policies/acl/selfhost-qualification-audit",
    )
    capabilities = bao.request("POST", "sys/capabilities-self", {
        "paths": [metadata_path, *forbidden_paths],
    })
    if (capabilities.get(metadata_path) != ["read"]
            or any(capabilities.get(path) not in (["deny"], [])
                   for path in forbidden_paths)):
        raise ValueError("custody audit token has excess effective capabilities")
    metadata = bao.request("GET", f"transit/keys/{CUSTODY_SIGNER}").get("data", {})
    version, pem = custody_signer_public(metadata)
    for method, path, body in (
        ("GET", f"transit/export/signing-key/{CUSTODY_SIGNER}", None),
        ("POST", f"transit/sign/{CUSTODY_SIGNER}", {"input": "YQ=="}),
    ):
        try:
            bao.request(method, path, body)
        except HTTPError as error:
            if error.code != 403:
                raise ValueError("custody audit token denial is invalid") from None
        else:
            raise ValueError("custody audit token can export or sign")
    return version, pem


def verify_kms_custody(evidence: Path, signature: Path, public_key: Path,
                       preflight: dict, environment: dict[str, str],
                       live_signer: tuple[int, str]) -> str:
    for label, path in (("custody evidence", evidence), ("custody signature", signature),
                        ("custody public key", public_key)):
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise ValueError(f"signed {label} is absent")
    if public_key.read_text(encoding="ascii") != live_signer[1]:
        raise ValueError("KMS custody signer differs from owned OpenBao metadata")
    document = json.loads(evidence.read_text(encoding="utf-8"))
    expected = {
        "schema": "marty.selfhost-kms-custody/v1",
        "source_sha": preflight["source_sha"],
        "archive_sha256": preflight["archive_sha256"],
        "image_lock_sha256": preflight["image_lock_sha256"],
        "run_id": preflight["run_id"],
        "fixture_sha256": environment["SELFHOST_FIXTURE_SHA256"],
        "challenge": environment["SELFHOST_CUSTODY_CHALLENGE"],
        "organization_id": environment["SELFHOST_ORG_ID"],
        "issuer_did": environment["SELFHOST_ISSUER_DID"],
        "verifier_did": environment["SELFHOST_VERIFIER_DID"],
        "issuer_key_non_exportable": True,
        "verifier_key_non_exportable": True,
        "attestation_key_reference": CUSTODY_SIGNER,
        "attestation_key_non_exportable": True,
    }
    if not isinstance(document, dict) or any(document.get(k) != v for k, v in expected.items()):
        raise ValueError("signed KMS custody evidence does not bind installed fixture")
    if document.get("attestation_key_version") != live_signer[0]:
        raise ValueError("signed KMS custody signer version is invalid")
    proofs = document.get("profile_proofs")
    if not isinstance(proofs, list) or len(proofs) != 2:
        raise ValueError("signed KMS custody profile proofs are incomplete")
    for proof, did, purpose, prefix in zip(
        proofs,
        (environment["SELFHOST_ISSUER_DID"], environment["SELFHOST_VERIFIER_DID"]),
        ("vc_jwt_issuer", "oid4vp_request_signing"),
        ("cred-issuer-", "oid4vp-verifier-"),
    ):
        selector = {"issuer_did": did, "key_purpose": purpose,
                    "credential_format": "SD_JWT_VC", "algorithm": "ES256"}
        tuple_value = f'{environment["SELFHOST_ORG_ID"]}|{did}|{purpose}|SD_JWT_VC|ES256'
        reference = f"{prefix}{uuid.uuid5(uuid.NAMESPACE_URL, tuple_value).hex[:20]}-es256"
        if (not isinstance(proof, dict)
                or set(proof) != {"profile_selector", "key_reference", "key_version"}
                or proof["profile_selector"] != selector
                or proof["key_reference"] != reference
                or type(proof["key_version"]) is not int
                or proof["key_version"] <= 0):
            raise ValueError("signed KMS custody profile proof does not bind managed key")
    command(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
             "-inkey", str(public_key), "-sigfile", str(signature),
             "-in", str(evidence)], timeout=120)
    return hashlib.sha256(evidence.read_bytes()).hexdigest()


def empty_project(compose: list[str], install_root: Path,
                  environment: dict[str, str]) -> None:
    if parse_status(command([*compose, "ps", "--all", "--format", "json"],
                            cwd=install_root, env=environment)):
        raise ValueError("qualification Docker project still contains containers")


def installed_journey(compose: list[str], install_root: Path, state_root: Path,
                      compose_model_path: Path, secret_root: Path,
                      model: dict, integration_checkout: Path,
                      environment: dict[str, str], setup_script: Path,
                      setup_sha256: str,
                      evidence: Path, signature: Path, public_key: Path,
                      preflight: dict,
                      diagnostics: RunDiagnostics | None = None,
                      source_checkout: Path | None = None,
                      openbao_state_root: Path | None = None,
                      openbao_project: str | None = None,
                      ) -> tuple[dict[str, str], str]:
    """Own only a preflighted, empty disposable project; always tear it down."""
    with measured(diagnostics, "fresh_project"):
        fresh_project(state_root, compose, install_root, environment)
    selected = sorted(LOCAL_SERVICES)
    started = False
    failure: Exception | None = None
    states: dict[str, str] = {}
    custody_sha256 = ""
    try:
        # A temporary empty Docker config prevents borrowing operator registry
        # credentials. Every pulled image has already been matched to the lock.
        with measured(diagnostics, "image_pull"):
            command([*compose, "pull", *selected], cwd=install_root,
                    env=environment, timeout=1200)
        started = True
        with measured(diagnostics, "startup"):
            command([*compose, "up", "-d", "--no-build", *selected],
                    cwd=install_root, env=environment, timeout=900)
        with measured(diagnostics, "readiness"):
            deadline = time.monotonic() + 300
            while True:
                status = command([*compose, "ps", "--all", "--format", "json"],
                                 cwd=install_root, env=environment)
                try:
                    states = live_services(status, model)
                    break
                except ValueError:
                    if time.monotonic() >= deadline:
                        raise ValueError("installed service closure did not become healthy") from None
                    time.sleep(5)
        journey_env = {**environment, "PYTHONDONTWRITEBYTECODE": "1",
                       "SELFHOST_KMS_CUSTODY_EVIDENCE_PATH": str(evidence),
                       "SELFHOST_KMS_CUSTODY_SIGNATURE_PATH": str(signature),
                       "SELFHOST_KMS_CUSTODY_PUBLIC_KEY_PATH": str(public_key),
                       "SELFHOST_COMPOSE_MODEL_PATH": str(compose_model_path),
                       "SELFHOST_SECRET_ROOT": str(secret_root),
                       "SELFHOST_SOURCE_SHA": preflight["source_sha"],
                       "SELFHOST_ARCHIVE_SHA256": preflight["archive_sha256"],
                       "SELFHOST_IMAGE_LOCK_SHA256": preflight["image_lock_sha256"],
                       "SELFHOST_RUN_ID": preflight["run_id"],
                       "SELFHOST_FIXTURE_SHA256": setup_sha256,
                       "SELFHOST_CUSTODY_CHALLENGE": secrets.token_hex(32)}
        with measured(diagnostics, "fixture_setup"):
            if evidence.exists() or signature.exists():
                raise ValueError("KMS custody output exists before fresh fixture setup")
            fixture_setup(setup_script, setup_sha256, integration_checkout)
            command([sys.executable, str(setup_script)], cwd=integration_checkout,
                    env=journey_env, timeout=600)
        with measured(diagnostics, "custody_verification"):
            if openbao_state_root is None or openbao_project is None:
                raise ValueError("owned OpenBao custody inputs are absent")
            live_signer = live_custody_signer(
                install_root, openbao_state_root, secret_root, openbao_project, model,
                journey_env)
            custody_sha256 = verify_kms_custody(evidence, signature, public_key,
                                                preflight, journey_env, live_signer)
        with measured(diagnostics, "public_journey"):
            command([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                     JOURNEY], cwd=integration_checkout, env=journey_env, timeout=900)
        with measured(diagnostics, "keycloak_issuance_refresh"):
            exercise_installed_keycloak_keys(journey_env, secret_root)
        with measured(diagnostics, "keycloak_database_custody"):
            if source_checkout is None:
                raise ValueError("release source is required for Keycloak custody")
            verify_keycloak_database_custody(compose, install_root,
                                              source_checkout, preflight["source_sha"],
                                              environment)
        with measured(diagnostics, "marty_database_custody"):
            verify_marty_database_custody(compose, install_root, environment)
    except Exception as error:
        failure = error
    finally:
        if started:
            try:
                with measured(diagnostics, "cleanup"):
                    command([*compose, "down", "--volumes", "--remove-orphans",
                             "--timeout", "30"], cwd=install_root, env=environment,
                            timeout=120)
                    empty_project(compose, install_root, environment)
            except Exception as error:
                raise ValueError("owned qualification project teardown failed") from error
    if failure is not None:
        raise failure
    return states, custody_sha256


def validate_inputs(args: argparse.Namespace) -> None:
    if sys.platform != "linux":
        raise ValueError("installed business journey requires Linux Docker")
    if PROJECT.fullmatch(args.project_name) is None:
        raise ValueError("qualification project name is not disposable and owned")
    for name in ("archive", "image_lock", "transaction", "receipt", "descriptor",
                 "install_root", "state_root", "secret_root", "env_file", "source_checkout",
                 "integration_checkout", "openbao_state_root"):
        path = getattr(args, name)
        if not path.is_absolute():
            raise ValueError(f"{name} must be an absolute path")
    if (args.env_file.is_symlink() or not args.env_file.is_file()
            or args.env_file.resolve().is_relative_to(args.source_checkout.resolve())):
        raise ValueError("operator env file is absent or inside source checkout")
    fixture_setup(args.fixture_setup, args.fixture_setup_sha256,
                  args.integration_checkout)
    source_bound_fixture(args.fixture_setup, args.fixture_setup_sha256,
                         args.source_checkout, args.source_sha)
    for name in ("kms_custody_evidence", "kms_custody_signature",
                 "kms_custody_public_key"):
        path = getattr(args, name)
        if (not path.is_absolute() or path.is_symlink()
                or path.resolve().is_relative_to(args.source_checkout.resolve())
                or path.resolve().is_relative_to(args.install_root.resolve())
                or path.resolve().is_relative_to(args.integration_checkout.resolve())):
            raise ValueError(f"{name} path is not isolated from installation and source")
    missing = [name for name in JOURNEY_INPUTS if not os.environ.get(name)]
    if missing:
        raise ValueError("public journey fixture inputs are absent: " + ", ".join(missing))
    pinned_integration_checkout(args.integration_checkout, args.integration_sha)
    if command(["git", "rev-parse", "HEAD^{commit}"], cwd=args.source_checkout).strip() != args.source_sha:
        raise ValueError("source checkout differs from prepared ZIP source")
    verify_descriptor(args.archive, args.image_lock, args.transaction,
                      args.receipt, args.descriptor)


def run(args: argparse.Namespace, diagnostics: RunDiagnostics | None = None) -> dict:
    with measured(diagnostics, "input_validation"):
        validate_inputs(args)
    environment = os.environ.copy()
    compose = ["docker", "compose", "--project-name", args.project_name,
               "--env-file", str(args.env_file),
               "-f", str(args.install_root / "docker-compose.yml")]
    with measured(diagnostics, "compose_render"):
        raw_model = command([*compose, "--profile", "*", "config", "--format", "json"],
                            cwd=args.install_root, env=environment)
        model = json.loads(raw_model)
    with measured(diagnostics, "artifact_preflight"):
        preflight = check(args.archive, args.image_lock, args.transaction, args.receipt,
                          Path(args.compose_model), args.source_checkout,
                          args.source_sha, args.run_id, args.install_root,
                          args.state_root, args.secret_root)
        if json.loads(args.compose_model.read_text(encoding="utf-8")) != model:
            raise ValueError("rendered installed Compose model differs from live source")
        runtime_plan = plan(model, preflight, args.secret_root)
        if runtime_plan.get("qualification") != "unqualified":
            raise ValueError("installed runtime plan unexpectedly claims qualification")
        required_secrets(args.secret_root, model)
    with (tempfile.TemporaryDirectory(prefix="marty-selfhost-jwk-build-") as build_root,
          tempfile.TemporaryDirectory(prefix="marty-selfhost-anonymous-docker-") as config):
        with measured(diagnostics, "public_key_tool_build"):
            jwk_tool = build_public_kms_jwk_tool(args.source_checkout, Path(build_root))
        environment["SELFHOST_KMS_JWK_TOOL"] = str(jwk_tool)
        environment["DOCKER_CONFIG"] = config
        states, custody_sha256 = installed_journey(
            compose, args.install_root, args.state_root, args.compose_model,
            args.secret_root, model,
            args.integration_checkout, environment, args.fixture_setup,
            args.fixture_setup_sha256,
            args.kms_custody_evidence, args.kms_custody_signature,
            args.kms_custody_public_key, preflight, diagnostics,
            source_checkout=args.source_checkout,
            openbao_state_root=args.openbao_state_root,
            openbao_project=args.openbao_project)
    return {"schema": "marty.selfhost-installed-business-journey/v1",
            "qualification": "unqualified", "source_sha": args.source_sha,
            "archive_sha256": preflight["archive_sha256"],
            "image_lock_sha256": preflight["image_lock_sha256"],
            "transaction_sha256": preflight["transaction_sha256"],
            "integration_revision": args.integration_sha,
            "fixture_setup_sha256": args.fixture_setup_sha256,
            "kms_custody_evidence_sha256": custody_sha256,
            "public_journey": "passed", "clean_start": "observed",
            "keycloak_issuance_refresh": "passed",
            "keycloak_database_custody": "passed",
            "marty_database_custody": "passed",
            "owned_teardown": "observed", "observed_services": sorted(states)}


def diagnostic_target(args: argparse.Namespace) -> Path | None:
    target = args.diagnostic_output
    if target is None:
        return None
    resolved = target.resolve()
    if (not target.is_absolute() or target.is_symlink() or target.exists()
            or not target.parent.is_dir()
            or resolved.is_relative_to(args.source_checkout.resolve())
            or resolved.is_relative_to(args.install_root.resolve())
            or resolved.is_relative_to(args.integration_checkout.resolve())
            or resolved.is_relative_to(args.secret_root.resolve())
            or resolved == args.output.resolve()):
        raise ValueError("diagnostic output path is not fresh and isolated")
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "image-lock", "transaction", "receipt", "descriptor",
                 "install-root", "state-root", "secret-root", "env-file",
                 "openbao-state-root",
                 "source-checkout", "integration-checkout", "compose-model", "output",
                 "fixture-setup", "kms-custody-evidence", "kms-custody-signature",
                 "kms-custody-public-key"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    for name in ("source-sha", "run-id", "integration-sha", "project-name",
                 "fixture-setup-sha256", "openbao-project"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--diagnostic-output", type=Path,
                        help="optional redacted timing and host-resource report")
    args = parser.parse_args()
    try:
        target = diagnostic_target(args)
        if (not args.output.is_absolute() or not args.output.parent.is_dir()
                or args.output.exists() or args.output.is_symlink()):
            raise ValueError("installed journey output is not fresh and absolute")
    except (OSError, ValueError) as error:
        print(f"installed journey output preflight failed: {error}", file=sys.stderr)
        return 2
    diagnostics = RunDiagnostics(args.state_root)
    diagnostics.start()
    status = 0
    result: dict | None = None
    try:
        result = run(args, diagnostics)
    except (OSError, KeyError, TypeError, ValueError) as error:
        print(f"installed journey failed: {error}", file=sys.stderr)
        status = 2
    finally:
        diagnostics.stop()
    if target is not None:
        try:
            with target.open("x", encoding="utf-8") as stream:
                json.dump(diagnostics.report(
                    checks_result="passed" if status == 0 else "failed"),
                          stream, indent=2, sort_keys=True)
                stream.write("\n")
        except (OSError, ValueError) as error:
            print(f"installed journey diagnostic failed: {error}", file=sys.stderr)
            status = 2
    if status == 0 and result is not None:
        try:
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2, sort_keys=True)
                stream.write("\n")
        except (OSError, ValueError) as error:
            print(f"installed journey output failed: {error}", file=sys.stderr)
            status = 2
    return status


if __name__ == "__main__":
    raise SystemExit(main())
