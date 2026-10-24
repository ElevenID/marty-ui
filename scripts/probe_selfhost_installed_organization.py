#!/usr/bin/env python3
"""Opt-in exact-bundle Organization runtime witness; never qualification."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path

import probe_selfhost_installed_migrations as migrations
import probe_selfhost_installed_signing_keys as signing

COMPOSE = migrations.ROOT / "docker-compose.selfhost-organization-scoped-disposable.yml"
ORG_ID = signing.ORG_ID


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise migrations.QualificationError(reason)


def locked_services_image(lock_path: Path, receipt: dict) -> str:
    """Select Organization only from the already verified exact bundle lock."""
    lock = json.loads(lock_path.read_bytes())
    require(
        lock.get("services") == receipt.get("images"),
        "Organization service image differs from the verified receipt",
    )
    image = lock["services"].get("organization")
    require(
        isinstance(image, str) and signing.SERVICES.fullmatch(image) is not None,
        "Organization requires the exact reviewed services repository",
    )
    return image


def validate_model(
    model: dict,
    images: dict[str, str],
    image: str,
    secret_dir: Path,
    install_root: Path,
    project: str,
) -> None:
    """Admit the migration topology plus exactly one private installed service."""
    require(
        isinstance(model, dict)
        and isinstance(model.get("services"), dict)
        and isinstance(model.get("secrets"), dict),
        "Organization runtime Compose model is invalid",
    )
    baseline = deepcopy(model)
    service = baseline["services"].pop("organization", None)
    secret = baseline["secrets"].pop("grpc_service_token", None)
    require(
        isinstance(service, dict) and isinstance(secret, dict),
        "Organization runtime service or secret is missing",
    )
    migrations.validate_scoped_model(
        baseline, images, secret_dir, install_root, project
    )
    require(
        set(secret) == {"name", "file"}
        and secret["name"] == f"{project}_grpc_service_token"
        and isinstance(secret["file"], str)
        and Path(secret["file"]).resolve()
        == (secret_dir / "grpc_service_token").resolve(),
        "Organization service token is not disposable",
    )
    require(
        service
        == {
            "image": image,
            "platform": "linux/amd64",
            "command": None,
            "entrypoint": None,
            "environment": {
                "SERVICE_NAME": "organization",
                "ENVIRONMENT": "production",
                "MARTY_RELEASE_VERSION": "scoped-probe",
                "ORGANIZATION_SERVICE_PORT": "8002",
                "ORG_GRPC_PORT": "9002",
                "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
                "DATABASE_URL_TEMPLATE": "postgresql://marty:$${MARTY_DB_PASSWORD}@postgres:5432/marty",
                "REDIS_URL": "redis://redis:6379",
                "REDIS_DB_GATEWAY": "2",
                "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
                "MARTY_ORG_ID": ORG_ID,
                "MARTY_ORG_ADMIN_EMAIL": "probe@migration.invalid",
                "ORGANIZATION_CREATION_ENABLED": "false",
                "ES_GRPC_TARGET": "event-stream:9015",
                "ES_GRPC_TIMEOUT_SECONDS": "1",
            },
            "secrets": [
                {
                    "source": "marty_db_password",
                    "target": "/run/secrets/marty_db_password",
                },
                {
                    "source": "grpc_service_token",
                    "target": "/run/secrets/grpc_service_token",
                },
            ],
            "depends_on": {
                "postgres": {"condition": "service_healthy", "required": True},
                "redis": {"condition": "service_healthy", "required": True},
            },
            "healthcheck": {
                "test": ["CMD", "curl", "--fail", "http://localhost:8002/health"],
                "interval": "2s",
                "retries": 30,
            },
            "networks": {"private": None},
            "restart": "no",
        },
        "Organization runtime topology or no-host-port boundary changed",
    )


def validate_read(raw: str, expected_status: int) -> int:
    try:
        body, marker, status = raw.rpartition("\n")
        require(
            bool(marker) and status == str(expected_status),
            "Organization read status differs",
        )
        if expected_status != 200:
            return 0
        organizations = json.loads(body)
        require(isinstance(organizations, list), "Organization read is not a list")
        seeded = [
            org
            for org in organizations
            if isinstance(org, dict)
            and org.get("id") == ORG_ID
            and org.get("name") == "Marty"
            and org.get("status") == "active"
        ]
        require(len(seeded) == 1, "Migrated Organization seed is not readable")
        return len(organizations)
    except (ValueError, TypeError) as exc:
        raise migrations.QualificationError("Organization read is invalid") from exc


def run_organization_runtime(
    compose: list[str],
    environment: dict[str, str],
    secret_dir: Path,
    run: Callable[..., subprocess.CompletedProcess[str]],
    *,
    images: dict[str, str],
    image: str,
    install_root: Path,
) -> dict:
    token_path = secret_dir / "grpc_service_token"
    token = secrets.token_hex(32)
    token_path.write_text(token, encoding="ascii")
    if os.name == "posix":
        token_path.chmod(0o444)
    require(
        token
        not in {
            secret_dir.joinpath(name).read_text(encoding="ascii")
            for name in (
                "marty_db_password",
                "bao_root_token",
                "bao_service_token",
                "notification_openbao_token",
            )
        },
        "Organization service token must be distinct",
    )
    runtime_env = {**environment, "PROBE_SERVICES_IMAGE": image}
    runtime_compose = [*compose, "-f", str(COMPOSE)]
    rendered = migrations._checked(
        run([*runtime_compose, "config", "--format", "json"], runtime_env),
        "Organization runtime Compose model is invalid",
    )
    try:
        validate_model(
            json.loads(rendered), images, image, secret_dir, install_root, compose[3]
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise migrations.QualificationError(
            "Organization runtime Compose model is invalid"
        ) from exc
    signing.verify_local_image(image)
    started = False
    try:
        started = True
        migrations._checked(
            run(
                [
                    *runtime_compose,
                    "up",
                    "-d",
                    "--no-deps",
                    "--pull",
                    "never",
                    "--wait",
                    "--wait-timeout",
                    "120",
                    "organization",
                ],
                runtime_env,
                240,
            ),
            "Exact Organization runtime did not become healthy",
        )

        def read(header: str | None) -> str:
            command = [*runtime_compose, "exec", "-T", "organization", "sh", "-ec"]
            script = 'curl --silent --show-error --write-out "\\n%{http_code}" '
            if header == "valid":
                script += (
                    '--header "x-service-token: '
                    '$(cat /run/secrets/grpc_service_token)" '
                )
            elif header == "wrong":
                script += '--header "x-service-token: wrong-token" '
            script += "http://127.0.0.1:8002/v1/organizations"
            return migrations._checked(
                run([*command, script], runtime_env),
                "Organization business read failed",
            )

        count = validate_read(read("valid"), 200)
        validate_read(read(None), 401)
        validate_read(read("wrong"), 401)
        return {
            "schema": "marty.selfhost-organization-runtime-probe/v1",
            "qualification": "unqualified",
            "services_image": image,
            "service": "organization",
            "seeded_organization_id": ORG_ID,
            "organization_count": count,
            "missing_token_status": 401,
            "wrong_token_status": 401,
        }
    finally:
        if started:
            migrations._checked(
                run([*runtime_compose, "down", "--volumes"], runtime_env, 120),
                "Disposable Organization runtime teardown failed",
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "archive",
        "image-lock",
        "transaction",
        "receipt",
        "descriptor",
        "install-root",
        "source-sha",
        "run-id",
    ):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    lock = Path(args.image_lock)
    install_root = Path(args.install_root)
    images, receipt = migrations.bundle_images(
        Path(args.archive),
        lock,
        Path(args.transaction),
        Path(args.receipt),
        Path(args.descriptor),
        install_root,
        args.source_sha,
        args.run_id,
    )
    image = locked_services_image(lock, receipt)
    images["openbao"] = migrations.reviewed_openbao()
    report = migrations.probe(
        images,
        receipt,
        install_root,
        after_migrations=lambda compose, env, secret_dir, run: run_organization_runtime(
            compose,
            env,
            secret_dir,
            run,
            images=images,
            image=image,
            install_root=install_root,
        ),
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
