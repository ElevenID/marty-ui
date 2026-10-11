#!/usr/bin/env python3
"""Local-only, exact-bundle migration probe with disposable scoped OpenBao.

This is migration evidence only, not a release gate or installed-stack claim.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
from typing import Callable

if __package__:
    from .check_prepared_selfhost_consumer import (
        verify_descriptor, verify_extracted_bundle, verify_receipt,
    )
    from .passport_supported_infra_images import registry_index
    from .check_selfhost_locked_image_platform import accepted_repo_digests
    from .qualify_selfhost_migrations import (
        PRIVATE_KEY_CONTENT_QUERY, PRIVATE_KEY_SCHEMA_QUERY,
        QualificationError, _assert_run, _checked, _empty_project, command,
        native_command, validate_images, validate_model,
    )
else:
    from check_prepared_selfhost_consumer import (
        verify_descriptor, verify_extracted_bundle, verify_receipt,
    )
    from passport_supported_infra_images import registry_index
    from check_selfhost_locked_image_platform import accepted_repo_digests
    from qualify_selfhost_migrations import (
        PRIVATE_KEY_CONTENT_QUERY, PRIVATE_KEY_SCHEMA_QUERY,
        QualificationError, _assert_run, _checked, _empty_project, command,
        native_command, validate_images, validate_model,
    )


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.selfhost-migrations-scoped-disposable.yml"
PIN = ROOT / "deploy-config/selfhost-migration-disposable-openbao.json"
START = ROOT / "scripts/passport_supported_openbao_start.sh"
BOOTSTRAP = ROOT / "scripts/selfhost_migration_openbao_bootstrap.sh"
EXPECTED_PIN = "quay.io/openbao/openbao@sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878"
PROJECT = re.compile(r"marty-selfhost-scoped-migrate-[0-9a-f]{16}\Z")
HEAD = "SELECT version_num FROM notification_service.alembic_version LIMIT 1"
REGISTRY = "org:00000000-0000-0000-0000-000000000001:signing-key-services"


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise QualificationError(reason)


def reviewed_openbao(path: Path = PIN,
                     inspect: Callable[[str], dict] = registry_index) -> str:
    policy = json.loads(path.read_text(encoding="utf-8"))
    require(policy == {
        "schema": "marty.selfhost-migration-disposable-openbao/v1",
        "scope": "disposable-selfhost-migration-probe-only",
        "platform": "linux/amd64",
        "reference": EXPECTED_PIN,
        "version": "2.5.2",
        "source_revision": "932fcf892eba8d646a9bfc58a59ea3b2475b17fa",
    }, "Disposable OpenBao pin differs from reviewed fixture scope")
    index = inspect(EXPECTED_PIN)
    manifests = index.get("manifests") if isinstance(index, dict) else None
    matches = [entry for entry in manifests if
               isinstance(entry, dict)
               and isinstance(entry.get("platform"), dict)
               and entry["platform"].get("os") == "linux"
               and entry["platform"].get("architecture") == "amd64"
               and isinstance(entry.get("digest"), str)
               and re.fullmatch(r"sha256:[0-9a-f]{64}", entry["digest"]) is not None]
    require(len(matches) == 1, "Disposable OpenBao lacks one linux/amd64 manifest")
    annotations = matches[0].get("annotations", {})
    require(isinstance(annotations, dict)
            and annotations.get("org.opencontainers.image.revision") in
            (None, policy["source_revision"])
            and annotations.get("org.opencontainers.image.version") in
            (None, policy["version"]), "Disposable OpenBao provenance differs")
    return EXPECTED_PIN


def bundle_images(archive: Path, lock_path: Path, transaction: Path,
                  receipt_path: Path, descriptor: Path, install_root: Path,
                  source_sha: str, run_id: str) -> tuple[dict[str, str], dict]:
    verify_descriptor(archive, lock_path, transaction, receipt_path, descriptor)
    receipt = verify_receipt(archive, lock_path, transaction, receipt_path,
                             source_sha, run_id)
    verify_extracted_bundle(archive, install_root)
    lock_bytes = lock_path.read_bytes()
    require((install_root / ".marty-selfhost-images.json").read_bytes() == lock_bytes,
            "Installed bundle image lock differs")
    lock = json.loads(lock_bytes)
    require(lock.get("services") == receipt["images"],
            "Installed bundle image closure differs")
    require((install_root / "docker/openbao-init.sh").is_file(),
            "Installed bundle lacks OpenBao initializer")
    images = {"migrations": lock["services"].get("db-migrate"),
              "services": lock["services"].get("issuance"),
              "postgres": lock["services"].get("postgres"),
              "redis": lock["services"].get("redis")}
    require(lock["services"].get("issuance-migrations") == images["services"],
            "Installed Issuance runtime and migration images differ")
    # Existing image-role validator rejects mutable or wrong-repository inputs.
    validate_images({**images, "openbao": EXPECTED_PIN})
    return images, receipt


def verify_local_platforms(
    images: dict[str, str],
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Bind each selected local linux/amd64 image to its exact repository digest."""
    validate_images(images)
    for reference in sorted(set(images.values())):
        try:
            run(["docker", "pull", "--platform", "linux/amd64", reference],
                check=True, capture_output=True, text=True)
            inspected = run(["docker", "image", "inspect", reference,
                             "--format", "{{json .}}"],
                            check=True, capture_output=True, text=True)
            image = json.loads(inspected.stdout)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            raise QualificationError("Exact probe image cannot be pulled or inspected") from exc
        require(isinstance(image, dict) and image.get("Os") == "linux"
                and image.get("Architecture") == "amd64",
                "Selected probe image is not linux/amd64")
        digests = image.get("RepoDigests")
        require(isinstance(digests, list) and any(
            isinstance(item, str) and item in accepted_repo_digests(reference)
            for item in digests), "Selected probe image differs from exact digest")


def validate_scoped_model(model: dict, images: dict[str, str],
                          secret_dir: Path, install_root: Path, project: str) -> None:
    """Validate exact disposable topology, then reuse the mature base contract."""
    require(isinstance(model, dict) and set(model) ==
            {"name", "services", "networks", "secrets", "configs"},
            "Disposable Compose model has unexpected top-level inputs")
    services = model.get("services")
    require(isinstance(services, dict) and set(services) ==
            {"postgres", "redis", "openbao", "openbao-bootstrap", "db-migrate",
             "native-schema-migrate"},
            "Disposable service set changed")
    require(all(isinstance(service, dict)
                and service.get("platform") == "linux/amd64"
                for service in services.values()),
            "Disposable service platform changed")
    bootstrap = services["openbao-bootstrap"]
    require(isinstance(bootstrap, dict) and set(bootstrap) ==
            {"image", "platform", "networks", "command", "entrypoint", "environment", "configs", "secrets",
             "volumes", "depends_on", "restart"}
            and bootstrap["command"] is None
            and bootstrap["image"] == images["openbao"]
            and bootstrap["networks"] == {"private": None}
            and bootstrap["entrypoint"] ==
            ["/bin/sh", "/usr/local/bin/selfhost-migration-openbao-bootstrap"]
            and bootstrap["environment"] == {"BAO_ADDR": "http://openbao:8200"}
            and bootstrap["secrets"] == [{"source": "bao_root_token",
                                          "target": "/run/secrets/bao_root_token"}]
            and bootstrap["configs"] == [
                {"source": "openbao_bootstrap",
                 "target": "/usr/local/bin/selfhost-migration-openbao-bootstrap"},
                {"source": "openbao_init", "target": "/usr/local/bin/openbao-init"}]
            and bootstrap["volumes"] == [{"type": "bind", "source": str(secret_dir),
                                           "target": "/work/secrets"}]
            and bootstrap["depends_on"] ==
            {"openbao": {"condition": "service_healthy", "required": True}}
            and bootstrap["restart"] == "no", "Disposable bootstrap topology changed")
    migration = services["db-migrate"]
    require(migration["environment"].get("BAO_TOKEN_FILE") ==
            "/run/secrets/bao_service_token"
            and migration["environment"].get("NOTIFICATION_OPENBAO_TOKEN_FILE") ==
            "/run/secrets/notification_openbao_token"
            and migration.get("secrets") == [
                {"source": name, "target": f"/run/secrets/{name}"}
                for name in ("marty_db_password", "bao_service_token",
                             "notification_openbao_token")],
            "Migration does not use distinct scoped tokens")
    secret_paths = {name: secret_dir / name for name in
                    ("marty_db_password", "bao_root_token", "bao_service_token",
                     "notification_openbao_token")}
    require(isinstance(model.get("secrets"), dict)
            and set(model["secrets"]) == set(secret_paths)
            and all(isinstance(model["secrets"][name], dict)
                    and set(model["secrets"][name]) == {"name", "file"}
                    and model["secrets"][name]["name"] == f"{project}_{name}"
                    and Path(model["secrets"][name]["file"]).resolve() == path.resolve()
                    for name, path in secret_paths.items()),
            "Disposable secret sources changed")
    config_paths = {"openbao_start": START,
                    "openbao_bootstrap": BOOTSTRAP,
                    "openbao_init": install_root / "docker/openbao-init.sh"}
    require(isinstance(model.get("configs"), dict)
            and set(model["configs"]) == set(config_paths)
            and all(isinstance(model["configs"][name], dict)
                    and set(model["configs"][name]) == {"name", "file"}
                    and model["configs"][name]["name"] == f"{project}_{name}"
                    and Path(model["configs"][name]["file"]).resolve() == path.resolve()
                    for name, path in config_paths.items()),
            "Disposable OpenBao fixture files changed")
    baseline = deepcopy(model)
    for service in baseline["services"].values():
        del service["platform"]
    del baseline["services"]["openbao-bootstrap"]
    baseline["services"]["db-migrate"]["environment"]["BAO_TOKEN_FILE"] = "/run/secrets/bao_root_token"
    baseline["services"]["db-migrate"]["secrets"][1] = {
        "source": "bao_root_token", "target": "/run/secrets/bao_root_token"}
    del baseline["secrets"]["bao_service_token"]
    for name, path in secret_paths.items():
        if name != "bao_service_token":
            baseline["secrets"][name]["file"] = str(path)
    del baseline["configs"]["openbao_bootstrap"]
    del baseline["configs"]["openbao_init"]
    baseline["configs"]["openbao_start"]["file"] = str(START.resolve())
    validate_model(baseline, images, secret_dir, project)


def probe(images: dict[str, str], receipt: dict, install_root: Path, *,
          run: Callable[..., subprocess.CompletedProcess[str]] = command,
          project: str | None = None) -> dict:
    project = project or "marty-selfhost-scoped-migrate-" + secrets.token_hex(8)
    require(PROJECT.fullmatch(project) is not None, "Disposable project name is invalid")
    with tempfile.TemporaryDirectory(prefix="marty-selfhost-scoped-migrate-") as temporary:
        secret_dir = Path(temporary)
        if os.name == "posix":
            secret_dir.chmod(0o700)
        for name in ("marty_db_password", "bao_root_token"):
            path = secret_dir / name
            path.write_text(secrets.token_hex(32), encoding="ascii")
            if os.name == "posix":
                path.chmod(0o600)
        environment = os.environ.copy()
        environment.update({
            "PROBE_MIGRATIONS_IMAGE": images["migrations"],
            "PROBE_SERVICES_IMAGE": images["services"],
            "PROBE_POSTGRES_IMAGE": images["postgres"],
            "PROBE_REDIS_IMAGE": images["redis"],
            "PROBE_OPENBAO_IMAGE": images["openbao"],
            "PROBE_SECRET_DIR": str(secret_dir),
            "PROBE_OPENBAO_START": str(START.resolve()),
            "PROBE_OPENBAO_BOOTSTRAP": str(BOOTSTRAP.resolve()),
            "PROBE_OPENBAO_INIT": str((install_root / "docker/openbao-init.sh").resolve()),
            "COMPOSE_PROFILES": "",
        })
        compose = ["docker", "compose", "--project-name", project, "-f", str(COMPOSE)]
        rendered = _checked(run([*compose, "config", "--format", "json"], environment),
                            "Disposable Compose model is invalid")
        try:
            validate_scoped_model(json.loads(rendered), images, secret_dir,
                                  install_root, project)
        except (TypeError, ValueError, KeyError) as exc:
            raise QualificationError("Disposable Compose model is invalid") from exc
        _empty_project(project, environment, run)
        verify_local_platforms(images)
        started = False
        try:
            started = True
            _checked(run([*compose, "up", "-d", "--wait", "--wait-timeout", "120",
                          "postgres", "redis", "openbao"], environment, 240),
                     "Disposable dependencies did not become ready")
            _checked(run([*compose, "run", "--no-deps", "--rm", "openbao-bootstrap"],
                         environment, 180), "Disposable scoped OpenBao bootstrap failed")
            for name in ("bao_service_token", "notification_openbao_token"):
                path = secret_dir / name
                require(path.is_file() and not path.is_symlink()
                        and path.stat().st_size > 0, "Disposable scoped token is missing")
            token_values = [(secret_dir / name).read_bytes().strip()
                            for name in ("bao_root_token", "bao_service_token",
                                         "notification_openbao_token")]
            require(all(token_values) and len(set(token_values)) == len(token_values),
                    "Disposable OpenBao tokens must be distinct")
            ledger = None
            for _ in range(2):
                migration = run([*compose, "run", "--no-deps", "--rm", "db-migrate"],
                                environment, 900)
                _checked(migration, "Exact-bundle self-host migrations failed")
                _assert_run(migration.stdout + migration.stderr)
                _checked(run([*compose, "run", "--no-deps", "--rm",
                              "native-schema-migrate"], environment, 900),
                         "Exact-bundle Rust native schema migrations failed")
                _checked(run([*compose, "run", "--no-deps", "--rm",
                              "--entrypoint", "/bin/sh", "native-schema-migrate",
                              "-ec", native_command("verify-owned-schema")],
                             environment, 900),
                         "Exact-bundle Rust native schema verification failed")
                head = _checked(run([*compose, "exec", "-T", "postgres", "psql", "-U",
                                     "marty", "-d", "marty", "-Atqc", HEAD], environment),
                                "Notification migration ledger is unavailable").strip()
                require(re.fullmatch(r"[0-9]{8}_[0-9]{4}", head) is not None
                        and (ledger is None or ledger == head),
                        "Notification migration ledger changed or is missing")
                ledger = head
                redis = _checked(run([*compose, "exec", "-T", "redis", "redis-cli",
                                      "-n", "2", "EXISTS", REGISTRY], environment),
                                 "KMS registry verification failed").strip()
                require(redis == "1", "KMS registry was not seeded")
                private_schema = _checked(run([*compose, "exec", "-T", "postgres",
                                               "psql", "-U", "marty", "-d", "marty",
                                               "-Atqc", PRIVATE_KEY_SCHEMA_QUERY],
                                              environment),
                                          "Private-key schema inventory failed").strip()
                require(not private_schema,
                        "Exact-bundle schema created private-key storage")
                _checked(run([*compose, "exec", "-T", "postgres", "psql", "-U",
                              "marty", "-d", "marty", "-v", "ON_ERROR_STOP=1",
                              "-qAtc", PRIVATE_KEY_CONTENT_QUERY], environment),
                         "Private-key content storage scan failed")
            return {"schema": "marty.selfhost-installed-migrations-probe/v1",
                    "qualification": "unqualified", "archive_sha256": receipt["archive_sha256"],
                    "image_lock_sha256": receipt["image_lock_sha256"],
                    "migrations_image": images["migrations"],
                    "services_image": images["services"], "openbao_image": images["openbao"],
                    "native_schemas": "verified", "private_key_storage": "absent",
                    "notification_head": ledger, "runs": 2}
        finally:
            if started:
                _checked(run([*compose, "down", "--volumes"], environment, 120),
                         "Disposable teardown failed")
                _empty_project(project, environment, run)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "image-lock", "transaction", "receipt", "descriptor",
                 "install-root", "source-sha", "run-id"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    images, receipt = bundle_images(
        Path(args.archive), Path(args.image_lock), Path(args.transaction),
        Path(args.receipt), Path(args.descriptor), Path(args.install_root),
        args.source_sha, args.run_id)
    images["openbao"] = reviewed_openbao()
    print(json.dumps(probe(images, receipt, Path(args.install_root)), sort_keys=True))


if __name__ == "__main__":
    main()
