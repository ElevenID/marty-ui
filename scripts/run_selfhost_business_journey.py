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
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import nullcontext
from pathlib import Path

from check_prepared_selfhost_consumer import check, verify_descriptor
from check_selfhost_installed_runtime_plan import (
    BETA_SERVICES, EXPECTED_ROLE_SECRETS, EXPECTED_SERVICES, plan,
)
from selfhost_handoff_contract import PINNED_INTEGRATION_SHA
from selfhost_journey_diagnostics import RunDiagnostics


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PROJECT = re.compile(r"marty-selfhost-qual-[0-9a-f]{16}\Z")
TRUST_ROOTS_PATH = "deploy-config/selfhost-kms-custody-trust-roots.json"
FIXTURE_PATH = "scripts/setup_selfhost_synthetic_fixture.py"
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
            env: dict[str, str] | None = None, timeout: int = 60) -> str:
    try:
        result = subprocess.run(args, cwd=cwd, env=env, timeout=timeout,
                                capture_output=True, text=True, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("installed journey command failed") from error
    if result.returncode:
        # Responses can contain credentials and claims. Never put raw output in
        # an artifact or exception; the private runner log is operator-owned.
        raise ValueError("installed journey command returned failure")
    return result.stdout


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


def trusted_custody_keys(source_checkout: Path, source_sha: str) -> frozenset[str]:
    raw = command(["git", "show", f"{source_sha}:{TRUST_ROOTS_PATH}"],
                  cwd=source_checkout)
    policy = json.loads(raw)
    if (not isinstance(policy, dict)
            or set(policy) != {"schema", "approved_public_key_sha256"}
            or policy["schema"] != "marty.selfhost-kms-custody-trust-roots/v1"
            or not isinstance(policy["approved_public_key_sha256"], list)
            or any(SHA256.fullmatch(str(value)) is None
                   for value in policy["approved_public_key_sha256"])):
        raise ValueError("source-bound KMS custody trust roots are invalid")
    keys = frozenset(policy["approved_public_key_sha256"])
    if not keys or len(keys) != len(policy["approved_public_key_sha256"]):
        raise ValueError("source-bound KMS custody signer is not approved")
    return keys


def verify_kms_custody(evidence: Path, signature: Path, public_key: Path,
                       preflight: dict, environment: dict[str, str],
                       trusted_keys: frozenset[str]) -> str:
    for label, path in (("custody evidence", evidence), ("custody signature", signature),
                        ("custody public key", public_key)):
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise ValueError(f"signed {label} is absent")
    if hashlib.sha256(public_key.read_bytes()).hexdigest() not in trusted_keys:
        raise ValueError("KMS custody signer is not approved by release source")
    document = json.loads(evidence.read_text(encoding="utf-8"))
    expected = {
        "schema": "marty.selfhost-kms-custody/v1",
        "source_sha": preflight["source_sha"],
        "archive_sha256": preflight["archive_sha256"],
        "image_lock_sha256": preflight["image_lock_sha256"],
        "organization_id": environment["SELFHOST_ORG_ID"],
        "issuer_did": environment["SELFHOST_ISSUER_DID"],
        "verifier_did": environment["SELFHOST_VERIFIER_DID"],
        "issuer_key_non_exportable": True,
        "verifier_key_non_exportable": True,
    }
    if not isinstance(document, dict) or any(document.get(k) != v for k, v in expected.items()):
        raise ValueError("signed KMS custody evidence does not bind installed fixture")
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
                      preflight: dict, trusted_keys: frozenset[str],
                      diagnostics: RunDiagnostics | None = None,
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
                       "SELFHOST_COMPOSE_MODEL_PATH": str(compose_model_path),
                       "SELFHOST_SECRET_ROOT": str(secret_root),
                       "SELFHOST_SOURCE_SHA": preflight["source_sha"],
                       "SELFHOST_ARCHIVE_SHA256": preflight["archive_sha256"],
                       "SELFHOST_IMAGE_LOCK_SHA256": preflight["image_lock_sha256"]}
        if evidence.exists() or signature.exists():
            raise ValueError("KMS custody output exists before fresh fixture setup")
        with measured(diagnostics, "fixture_setup"):
            fixture_setup(setup_script, setup_sha256, integration_checkout)
            command([sys.executable, str(setup_script)], cwd=integration_checkout,
                    env=journey_env, timeout=600)
        with measured(diagnostics, "custody_verification"):
            custody_sha256 = verify_kms_custody(evidence, signature, public_key,
                                                preflight, journey_env, trusted_keys)
        with measured(diagnostics, "public_journey"):
            command([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                     JOURNEY], cwd=integration_checkout, env=journey_env, timeout=900)
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


def validate_inputs(args: argparse.Namespace) -> frozenset[str]:
    if sys.platform != "linux":
        raise ValueError("installed business journey requires Linux Docker")
    if PROJECT.fullmatch(args.project_name) is None:
        raise ValueError("qualification project name is not disposable and owned")
    for name in ("archive", "image_lock", "transaction", "receipt", "descriptor",
                 "install_root", "state_root", "secret_root", "env_file", "source_checkout",
                 "integration_checkout"):
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
    trusted_keys = trusted_custody_keys(args.source_checkout, args.source_sha)
    verify_descriptor(args.archive, args.image_lock, args.transaction,
                      args.receipt, args.descriptor)
    return trusted_keys


def run(args: argparse.Namespace, diagnostics: RunDiagnostics | None = None) -> dict:
    with measured(diagnostics, "input_validation"):
        trusted_keys = validate_inputs(args)
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
            args.kms_custody_public_key, preflight, trusted_keys, diagnostics)
    return {"schema": "marty.selfhost-installed-business-journey/v1",
            "qualification": "unqualified", "source_sha": args.source_sha,
            "archive_sha256": preflight["archive_sha256"],
            "image_lock_sha256": preflight["image_lock_sha256"],
            "transaction_sha256": preflight["transaction_sha256"],
            "integration_revision": args.integration_sha,
            "fixture_setup_sha256": args.fixture_setup_sha256,
            "kms_custody_evidence_sha256": custody_sha256,
            "public_journey": "passed", "clean_start": "observed",
            "owned_teardown": "observed", "observed_services": sorted(states)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "image-lock", "transaction", "receipt", "descriptor",
                 "install-root", "state-root", "secret-root", "env-file",
                 "source-checkout", "integration-checkout", "compose-model", "output",
                 "fixture-setup", "kms-custody-evidence", "kms-custody-signature",
                 "kms-custody-public-key"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    for name in ("source-sha", "run-id", "integration-sha", "project-name",
                 "fixture-setup-sha256"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--diagnostic-output", type=Path,
                        help="optional redacted timing and host-resource report")
    args = parser.parse_args()
    diagnostics = RunDiagnostics(args.state_root)
    diagnostics.start()
    status = 0
    try:
        result = run(args, diagnostics)
        if args.output.exists():
            raise ValueError("installed journey output already exists")
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (OSError, KeyError, TypeError, ValueError) as error:
        print(f"installed journey failed: {error}", file=sys.stderr)
        status = 2
    finally:
        diagnostics.stop()
    if args.diagnostic_output is not None:
        try:
            target = args.diagnostic_output
            if (not target.is_absolute() or target.is_symlink()
                    or target.resolve().is_relative_to(args.source_checkout.resolve())
                    or target.resolve().is_relative_to(args.install_root.resolve())
                    or target.resolve().is_relative_to(args.integration_checkout.resolve())
                    or target.resolve().is_relative_to(args.secret_root.resolve())
                    or target.resolve() == args.output.resolve()):
                raise ValueError("diagnostic output path is not isolated")
            with target.open("x", encoding="utf-8") as stream:
                json.dump(diagnostics.report(result="passed" if status == 0 else "failed"),
                          stream, indent=2, sort_keys=True)
                stream.write("\n")
        except (OSError, ValueError) as error:
            print(f"installed journey diagnostic failed: {error}", file=sys.stderr)
            status = 2
    return status


if __name__ == "__main__":
    raise SystemExit(main())
