#!/usr/bin/env python3
"""Run native profile services against fresh disposable PostgreSQL and audit custody."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from qualify_selfhost_migrations import (
    PRIVATE_KEY_CONTENT_QUERY,
    PRIVATE_KEY_SCHEMA_QUERY,
)


ROOT = Path(__file__).resolve().parents[1]
DATABASE = "marty_kms_profiles"
IMAGE = "docker.io/library/postgres@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229"


def run(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        raise RuntimeError(f"disposable command failed: {args[0]} {args[1]}")
    return result.stdout.strip()


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def psql(container: str, query: str) -> str:
    return run(
        "docker", "exec", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
        "-U", "postgres", "-d", DATABASE, "-At", "-c", query,
    )


def start_service(name: str, environment: dict[str, str]) -> None:
    executable = ROOT / "rust" / "target" / "debug" / (
        name + (".exe" if os.name == "nt" else "")
    )
    if not executable.is_file():
        raise RuntimeError(f"build the native service binary first: {name}")
    port = free_port()
    prefix = "DEPLOYMENT_PROFILE" if name == "marty-deployment-profile" else "COMPLIANCE_PROFILE"
    backend = name + "-rust"
    child_environment = dict(environment, **{f"{prefix}_HTTP_ADDR": f"127.0.0.1:{port}"})
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(
            [str(executable)], cwd=ROOT, env=child_environment,
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(120):
                if process.poll() is not None:
                    raise RuntimeError(f"native service exited before health: {name}")
                try:
                    with urllib.request.urlopen(  # noqa: S310 - owned loopback process
                        f"http://127.0.0.1:{port}/health/native-backend", timeout=1,
                    ) as response:
                        health = json.load(response)
                    if health.get("status") != "ready" or health.get("backend") != backend:
                        raise RuntimeError(f"native service health is invalid: {name}")
                    return
                except (OSError, urllib.error.URLError):
                    time.sleep(0.25)
            raise RuntimeError(f"native service did not become healthy: {name}")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def main() -> None:
    container = f"marty-kms-profiles-{uuid.uuid4().hex[:12]}"
    password = f"disposable-{uuid.uuid4().hex}"
    started = False
    try:
        container_id = run(
            "docker", "run", "--rm", "-d", "--name", container,
            "--label", "marty.disposable=kms-profile-runtime",
            "-e", f"POSTGRES_PASSWORD={password}", "-e", f"POSTGRES_DB={DATABASE}",
            "-p", "127.0.0.1::5432", IMAGE,
        )
        started = True
        if len(container_id) != 64:
            raise RuntimeError("disposable PostgreSQL container ID is invalid")
        port = int(run("docker", "port", container, "5432/tcp").splitlines()[0].rsplit(":", 1)[1])
        for _ in range(120):
            ready = subprocess.run(
                ["docker", "exec", container, "pg_isready", "-U", "postgres", "-d", DATABASE],
                capture_output=True, timeout=10, check=False,
            )
            if ready.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("disposable PostgreSQL did not become ready")
        for _ in range(40):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                time.sleep(0.25)
        else:
            raise RuntimeError("disposable PostgreSQL host port did not become ready")
        environment = dict(
            os.environ,
            DATABASE_URL=f"postgresql://postgres:{password}@127.0.0.1:{port}/{DATABASE}",
            ENVIRONMENT="test",
            GRPC_INSECURE_ALLOWED="true",
        )
        services = ("marty-deployment-profile", "marty-compliance-profile")
        for _ in range(2):
            for service in services:
                start_service(service, environment)
        counts = psql(container, "SELECT "
            "(SELECT count(*) FROM deployment_profile_service.deployment_profiles),"
            "(SELECT count(*) FROM compliance_profile_service.profiles),"
            "(SELECT count(*) FROM deployment_profile_service.native_migrations),"
            "(SELECT count(*) FROM compliance_profile_service.native_migrations)")
        deployment, compliance, deployment_migration, compliance_migration = map(int, counts.split("|"))
        if deployment < 1 or compliance < 1 or deployment_migration != 1 or compliance_migration != 1:
            raise RuntimeError("native migration or system seed is incomplete")
        if psql(container, PRIVATE_KEY_SCHEMA_QUERY):
            raise RuntimeError("native profile schema contains private-key storage")
        psql(container, PRIVATE_KEY_CONTENT_QUERY)
        catalog = psql(container, "SELECT table_schema || '.' || table_name || '.' || column_name "
            "|| ':' || data_type FROM information_schema.columns "
            "WHERE table_schema IN ('deployment_profile_service','compliance_profile_service') "
            "ORDER BY 1")
        receipt = {
            "schema": "marty.kms-profile-runtime-schema-audit/v1",
            "qualification": "local-disposable-runtime-only",
            "database": "fresh loopback PostgreSQL 16; source-built native service binaries",
            "postgres_image": IMAGE,
            "services": list(services),
            "startups_per_service": 2,
            "deployment_seed_rows": deployment,
            "compliance_seed_rows": compliance,
            "migration_rows_per_service": 1,
            "column_count": len(catalog.splitlines()),
            "catalog_inventory_sha256": hashlib.sha256(catalog.encode()).hexdigest(),
            "private_key_catalog_entries": 0,
            "json_text_content_scan": "passed after Rust migration and seed",
            "limits": ["local source-built executables, not signed release artifacts", "runtime writes beyond migration seeds not exercised"],
        }
        output = ROOT / "artifacts" / "kms-profile-runtime-schema-audit.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(receipt, sort_keys=True))
    finally:
        if started:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=30, check=False)


if __name__ == "__main__":
    main()
