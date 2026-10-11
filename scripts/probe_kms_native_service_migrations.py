#!/usr/bin/env python3
"""Exercise native migration/repository contracts on fresh, isolated databases.

The receipt is source-built evidence, not qualification of released images.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid

from qualify_selfhost_migrations import PRIVATE_KEY_CONTENT_QUERY, PRIVATE_KEY_SCHEMA_QUERY


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "docker.io/library/postgres@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229"
CASES = (
    ("auth", "marty-auth", "persistence_contract", "postgres_audit_behavior_matches_contract_when_configured", "AUTH_POSTGRES_TEST_URL", "auth_service"),
    ("organization", "marty-organization", "postgres_integration", "complete_repository_round_trip_is_tenant_bound_when_configured", "ORGANIZATION_POSTGRES_TEST_URL", "organization_service"),
    ("credential_template", "marty-credential-template", "postgres_integration", "complete_repository_round_trip_is_tenant_bound_when_configured", "CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL", "credential_template_service"),
    ("presentation_policy", "marty-presentation-policy", "postgres_integration", "migration_and_complete_repository_round_trip_when_configured", "PRESENTATION_POLICY_POSTGRES_TEST_URL", "presentation_policy_service"),
    ("verification", "marty-verification-service", "binary:marty-verification-service", "migrate", "DATABASE_URL", "verification_service"),
)


def run(*args: str, timeout: int = 120, env: dict[str, str] | None = None, cwd: Path | None = None) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd, check=False)
    if result.returncode:
        tail = "\n".join((result.stdout + result.stderr).splitlines()[-35:])
        raise RuntimeError(f"{args[0]} {args[1]} failed (exit {result.returncode}):\n{tail}")
    return result.stdout.strip()


def psql(container: str, database: str, query: str) -> str:
    return run("docker", "exec", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
               "-U", "postgres", "-d", database, "-At", "-c", query)


def main() -> None:
    container = f"marty-kms-native-migrations-{uuid.uuid4().hex[:12]}"
    password = f"disposable-{uuid.uuid4().hex}"
    started = False
    results = []
    try:
        container_id = run("docker", "run", "--rm", "-d", "--name", container,
                           "--label", "marty.disposable=kms-native-migrations",
                           "-e", f"POSTGRES_PASSWORD={password}",
                           "-p", "127.0.0.1::5432", IMAGE)
        started = True
        if len(container_id) != 64:
            raise RuntimeError("disposable PostgreSQL container ID is invalid")
        port = int(run("docker", "port", container, "5432/tcp").splitlines()[0].rsplit(":", 1)[1])
        for _ in range(120):
            ready = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres"],
                                   capture_output=True, timeout=10, check=False)
            if ready.returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("disposable PostgreSQL did not become ready")
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass

        for name, package, target, test, variable, schema in CASES:
            database = f"marty_kms_{name}"
            for _ in range(120):
                try:
                    psql(container, "postgres", f'CREATE DATABASE "{database}"')
                    break
                except RuntimeError:
                    time.sleep(0.25)
            else:
                raise RuntimeError(f"disposable PostgreSQL could not create {database}")
            environment = dict(os.environ)
            environment["CARGO_INCREMENTAL"] = "0"
            environment[variable] = f"postgresql://postgres:{password}@127.0.0.1:{port}/{database}"
            if target.startswith("binary:"):
                binary = target.removeprefix("binary:")
                run("cargo", "+1.95", "build", "--locked", "--offline", "-j2", "-p", package,
                    "--bin", binary, timeout=600, env=environment, cwd=ROOT / "rust")
                executable = ROOT / "rust" / "target" / "debug" / (binary + (".exe" if os.name == "nt" else ""))
                run(str(executable), test, timeout=120, env=environment, cwd=ROOT)
                run(str(executable), test, timeout=120, env=environment, cwd=ROOT)
            else:
                run("cargo", "+1.95", "test", "--locked", "--offline", "-j2", "-p", package,
                    "--test", target, test, "--", "--exact", timeout=600,
                    env=environment, cwd=ROOT / "rust")
            entries = psql(container, database, PRIVATE_KEY_SCHEMA_QUERY)
            if entries:
                raise RuntimeError(f"private-key schema entries in {name}: {entries}")
            psql(container, database, PRIVATE_KEY_CONTENT_QUERY)
            table_count, column_count = map(int, psql(container, database, f"""
                SELECT COUNT(DISTINCT c.oid), COUNT(a.attnum)
                FROM pg_catalog.pg_class c
                JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
                WHERE n.nspname='{schema}' AND c.relkind IN ('r','p')
                  AND a.attnum>0 AND NOT a.attisdropped
            """).split("|"))
            if table_count == 0 or column_count == 0:
                raise RuntimeError(f"native migration did not create {schema}")
            result = {"service": name, "schema": schema, "tables": table_count,
                      "columns": column_count, "contract": f"{package}/{target}/{test}",
                      "private_key_catalog_entries": 0, "private_key_content_scan": "passed"}
            if name == "verification":
                session_columns = int(psql(container, database, """
                    SELECT COUNT(*) FROM pg_catalog.pg_attribute
                    WHERE attrelid='public.verification_sessions'::regclass
                      AND attnum>0 AND NOT attisdropped
                """))
                if session_columns == 0:
                    raise RuntimeError("native Verification session table is absent")
                result["public_verification_session_columns"] = session_columns
            results.append(result)
            print(f"{name}: {table_count} tables, {column_count} columns; custody scan passed", flush=True)
        receipt = {
            "schema": "marty.kms-native-service-migration-audit/v1",
            "qualification": "local-disposable-runtime-only",
            "source_sha": run("git", "rev-parse", "HEAD", cwd=ROOT),
            "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "postgres_image": IMAGE,
            "services": results,
            "limits": ["source-built Rust contracts, not signed release artifacts",
                       "does not audit Python metadata or installed-stack cutover"],
        }
        output = ROOT / "artifacts" / "kms-native-service-migration-audit-20261011.json"
        output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {output.relative_to(ROOT)}; sha256={hashlib.sha256(output.read_bytes()).hexdigest()}")
    finally:
        if started:
            run("docker", "rm", "-f", container)


if __name__ == "__main__":
    main()
