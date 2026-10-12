#!/usr/bin/env python3
"""Local-only exact-bundle signing-key runtime continuation; never qualification."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path

import probe_selfhost_installed_migrations as migrations
from check_selfhost_locked_image_platform import accepted_repo_digests

COMPOSE = migrations.ROOT / "docker-compose.selfhost-signing-scoped-disposable.yml"
SERVICES = re.compile(r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\Z")
ORG_ID = "00000000-0000-0000-0000-000000000001"
OTHER_ORG = "00000000-0000-0000-0000-000000000002"
PRIVATE_JWK_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth"}
EXPECTED_KIDS = {"cred-issuer-marty-es256", "cred-issuer-marty-eddsa"}


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise migrations.QualificationError(reason)


def locked_services_image(lock_path: Path, receipt: dict) -> str:
    """Use only the lock already bound to the ZIP, receipt and descriptor."""
    lock = json.loads(lock_path.read_bytes())
    require(lock.get("services") == receipt.get("images"),
            "Signing service image differs from the verified receipt")
    image = lock["services"].get("signing-keys")
    require(isinstance(image, str) and SERVICES.fullmatch(image) is not None,
            "Signing service requires the exact reviewed services repository")
    return image


def verify_local_image(
    image: str,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    require(SERVICES.fullmatch(image) is not None, "Signing service image is not exact")
    try:
        run(["docker", "pull", "--platform", "linux/amd64", image],
            check=True, capture_output=True, text=True)
        inspected = run(["docker", "image", "inspect", image,
                         "--format", "{{json .}}"],
                        check=True, capture_output=True, text=True)
        details = json.loads(inspected.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise migrations.QualificationError(
            "Exact signing service image cannot be pulled or inspected"
        ) from exc
    require(isinstance(details, dict)
            and details.get("Os") == "linux"
            and details.get("Architecture") == "amd64",
            "Selected signing service image is not linux/amd64")
    digests = details.get("RepoDigests")
    require(isinstance(digests, list) and any(
        isinstance(item, str) and item in accepted_repo_digests(image)
        for item in digests), "Selected signing service image differs from exact digest")


def validate_model(model: dict, images: dict[str, str], image: str,
                   secret_dir: Path, install_root: Path, project: str) -> None:
    """Permit exactly the existing migration topology plus one private service."""
    require(isinstance(model, dict) and isinstance(model.get("services"), dict)
            and isinstance(model.get("secrets"), dict),
            "Signing runtime Compose model is invalid")
    baseline = deepcopy(model)
    service = baseline["services"].pop("signing-keys", None)
    signing_secrets = {
        name: baseline["secrets"].pop(name, None)
        for name in ("issuance_api_key", "signing_service_key", "signing_issuer_key",
                     "sign_grant_verify_token", "signing_keys_openbao_token")
    }
    require(isinstance(service, dict) and all(isinstance(item, dict) for item in signing_secrets.values()),
            "Signing runtime service or secret is missing")
    migrations.validate_scoped_model(baseline, images, secret_dir, install_root,
                                     project)
    for name, secret in signing_secrets.items():
        require(set(secret) == {"name", "file"}
                and secret["name"] == f"{project}_{name}"
                and isinstance(secret["file"], str)
                and Path(secret["file"]).resolve() == (secret_dir / name).resolve(),
                "Signing runtime credential is not disposable")
    require(service == {
        "image": image,
        "platform": "linux/amd64",
        "command": None,
        "entrypoint": None,
        "environment": {
            "SERVICE_NAME": "signing_keys",
            "ENVIRONMENT": "production",
            "MARTY_RELEASE_VERSION": "scoped-probe",
            "SIGNING_KEYS_SERVICE_PORT": "8017",
            "SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/issuance_api_key",
            "SIGNING_KEYS_SERVICE_SIGN_GATEWAY_KEY_FILE": "/run/secrets/signing_service_key",
            "SIGNING_KEYS_ISSUER_SIGN_KEY_FILE": "/run/secrets/signing_issuer_key",
            "SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE": "/run/secrets/sign_grant_verify_token",
            "SIGNING_KEYS_REDIS_URL": "redis://redis:6379/2",
            "BAO_ADDR": "http://openbao:8200",
            "BAO_TOKEN_FILE": "/run/secrets/signing_keys_openbao_token",
            "PUBLIC_DOMAIN": "migration.invalid",
        },
        "secrets": [
            {"source": "issuance_api_key", "target": "/run/secrets/issuance_api_key"},
            {"source": "signing_service_key", "target": "/run/secrets/signing_service_key"},
            {"source": "signing_issuer_key", "target": "/run/secrets/signing_issuer_key"},
            {"source": "sign_grant_verify_token", "target": "/run/secrets/sign_grant_verify_token"},
            {"source": "signing_keys_openbao_token", "target": "/run/secrets/signing_keys_openbao_token"},
        ],
        "depends_on": {
            "redis": {"condition": "service_healthy", "required": True},
            "openbao": {"condition": "service_healthy", "required": True},
        },
        "healthcheck": {
            "test": ["CMD", "curl", "--fail", "http://localhost:8017/health"],
            "interval": "2s", "retries": 30,
        },
        "networks": {"private": None},
        "restart": "no",
    }, "Signing runtime topology or no-host-port boundary changed")


def validate_jwks(raw: str, *, organization_id: str, present: bool) -> int:
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise migrations.QualificationError("Signing JWKS response is invalid") from exc
    require(isinstance(document, dict)
            and document.get("organization_id") == organization_id
            and isinstance(document.get("keys"), list),
            "Signing JWKS does not match the requested organization")
    keys = document["keys"]
    require(bool(keys) == present,
            "Signing JWKS key presence differs from migration seed")
    require(all(isinstance(key, dict) and not PRIVATE_JWK_FIELDS.intersection(key)
                and isinstance(key.get("kid"), str) and key["kid"]
                and isinstance(key.get("kty"), str) and key["kty"]
                for key in keys), "Signing JWKS contains malformed or private keys")
    if present:
        require(EXPECTED_KIDS.issubset({key["kid"] for key in keys}),
                "Signing JWKS lacks the migration-owned issuer keys")
    return len(keys)


def run_signing_runtime(
    compose: list[str], environment: dict[str, str], secret_dir: Path,
    run: Callable[..., subprocess.CompletedProcess[str]], *,
    images: dict[str, str], image: str, install_root: Path,
) -> dict:
    values = [(secret_dir / name).read_text(encoding="ascii")
              for name in ("bao_service_token", "signing_keys_openbao_token",
                           "sign_grant_verify_token")]
    for name in ("issuance_api_key", "signing_service_key", "signing_issuer_key"):
        path = secret_dir / name
        path.write_text(secrets.token_hex(32), encoding="ascii")
        if os.name == "posix":
            path.chmod(0o600)
        values.append(path.read_text(encoding="ascii"))
    require(len(set(values)) == len(values), "Signing credentials must be distinct")
    runtime_env = {**environment, "PROBE_SERVICES_IMAGE": image}
    runtime_compose = [*compose, "-f", str(COMPOSE)]
    rendered = migrations._checked(
        run([*runtime_compose, "config", "--format", "json"], runtime_env),
        "Signing runtime Compose model is invalid")
    try:
        validate_model(json.loads(rendered), images, image, secret_dir,
                       install_root, compose[3])
    except (TypeError, ValueError, KeyError) as exc:
        raise migrations.QualificationError("Signing runtime Compose model is invalid") from exc
    verify_local_image(image)
    started = False
    try:
        started = True
        migrations._checked(
            run([*runtime_compose, "up", "-d", "--no-deps", "--pull", "never",
                 "--wait", "--wait-timeout", "120", "signing-keys"], runtime_env, 240),
            "Exact signing runtime did not become healthy")

        def read_jwks(organization_id: str) -> str:
            return migrations._checked(run(
                [*runtime_compose, "exec", "-T", "signing-keys", "curl", "--fail",
                 "--silent", "--show-error",
                 f"http://127.0.0.1:8017/v1/signing-keys/jwks?organization_id={organization_id}"],
                runtime_env), "Signing JWKS read failed")

        count = validate_jwks(read_jwks(ORG_ID), organization_id=ORG_ID, present=True)
        validate_jwks(read_jwks(OTHER_ORG), organization_id=OTHER_ORG, present=False)
        return {"schema": "marty.selfhost-signing-runtime-probe/v1",
                "qualification": "unqualified", "services_image": image,
                "service": "signing-keys", "public_jwk_count": count,
                "unknown_organization_keys": 0}
    finally:
        if started:
            migrations._checked(run([*runtime_compose, "down", "--volumes"],
                                    runtime_env, 120),
                                "Disposable signing runtime teardown failed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "image-lock", "transaction", "receipt", "descriptor",
                 "install-root", "source-sha", "run-id"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    lock = Path(args.image_lock)
    install_root = Path(args.install_root)
    images, receipt = migrations.bundle_images(
        Path(args.archive), lock, Path(args.transaction), Path(args.receipt),
        Path(args.descriptor), install_root, args.source_sha, args.run_id)
    image = locked_services_image(lock, receipt)
    images["openbao"] = migrations.reviewed_openbao()
    report = migrations.probe(
        images, receipt, install_root,
        after_migrations=lambda compose, env, secret_dir, run: run_signing_runtime(
            compose, env, secret_dir, run, images=images, image=image,
            install_root=install_root))
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
