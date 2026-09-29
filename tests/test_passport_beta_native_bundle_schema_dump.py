"""Optional disposable replay against the frozen schema-only beta snapshot."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import time
import uuid

import pytest

from scripts.prepare_passport_beta_native_migrations import (
    MIGRATIONS, build_sql, migration_set_sha256, normalized_sql,
)


ROOT = Path(__file__).resolve().parents[1]
POSTGRES_IMAGE = "postgres:15-alpine@sha256:fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c"
SCHEMA_SHA256 = "b701125d79712d83b27f0816b85808a59aa645d6ed747affd56f17b43b306741"
INSTALL = ROOT / "scripts/sql/passport-beta-fence-install.sql"
DRAIN = ROOT / "scripts/sql/passport-beta-fence-drain.sql"
START = ROOT / "scripts/sql/passport-beta-db-maintenance-start.sql"
FINALIZE = ROOT / "scripts/sql/passport-beta-batch-acl-finalize.sql"
ENABLE = ROOT / "scripts/sql/passport-beta-db-enable-app-login.sql"
VERIFY = ROOT / "scripts/sql/passport-beta-fence-verify.sql"


def docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          check=False, timeout=90)


def psql(container: str, query: str) -> str:
    result = docker("exec", container, "psql", "-X", "-U", "postgres", "-d", "marty",
                    "-v", "ON_ERROR_STOP=1", "-At", "-c", query)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def run_file(container: str, path: Path, settings: list[str] | None = None) -> None:
    copied = docker("cp", str(path), f"{container}:/tmp/{path.name}")
    assert copied.returncode == 0, copied.stderr
    result = docker("exec", container, "psql", "-X", "-U", "postgres", "-d", "marty",
                    "-v", "ON_ERROR_STOP=1", "-qAt", *(settings or []),
                    "-f", f"/tmp/{path.name}")
    assert result.returncode == 0, result.stderr


def test_real_native_bundle_commits_receipt_on_frozen_beta_schema(tmp_path: Path):
    if os.getenv("BETA_FENCE_DISPOSABLE_DOCKER") != "1":
        pytest.skip("disposable PostgreSQL must be explicitly enabled")
    raw_path = os.getenv("BETA_FENCE_SCHEMA_ONLY_DUMP")
    if not raw_path:
        pytest.skip("set BETA_FENCE_SCHEMA_ONLY_DUMP to the frozen schema-only snapshot")
    dump = Path(raw_path)
    assert dump.is_file() and hashlib.sha256(dump.read_bytes()).hexdigest() == SCHEMA_SHA256
    name = f"marty-native-bundle-test-{uuid.uuid4().hex[:12]}"
    started = docker("run", "--rm", "-d", "--name", name, "--network", "none",
                     "-e", "POSTGRES_PASSWORD=disposable-only", POSTGRES_IMAGE)
    assert started.returncode == 0, started.stderr
    try:
        for _ in range(60):
            ready = docker("exec", name, "psql", "-U", "postgres", "-d", "postgres",
                           "-At", "-c", "SELECT 1")
            if ready.returncode == 0 and ready.stdout.strip() == "1":
                break
            time.sleep(0.25)
        else:
            pytest.fail("disposable PostgreSQL did not become ready")
        for _ in range(60):
            role = docker("exec", name, "psql", "-U", "postgres", "-d", "postgres",
                          "-v", "ON_ERROR_STOP=1", "-c", "CREATE ROLE marty LOGIN")
            if role.returncode == 0:
                break
            time.sleep(0.25)
        else:
            pytest.fail("disposable PostgreSQL role could not be created")
        created = docker("exec", name, "createdb", "-U", "postgres", "-O", "marty", "marty")
        assert created.returncode == 0, created.stderr
        run_file(name, dump)
        psql(name, "ALTER SCHEMA issuance_service OWNER TO marty")
        psql(name, "ALTER SCHEMA flow_service OWNER TO marty")
        psql(name, """
            DO $owners$
            DECLARE relation record;
            BEGIN
                FOR relation IN
                    SELECT n.nspname, c.relname FROM pg_class AS c
                    JOIN pg_namespace AS n ON n.oid=c.relnamespace
                    WHERE n.nspname IN ('issuance_service','flow_service')
                      AND c.relkind IN ('r','p')
                LOOP
                    EXECUTE format('ALTER TABLE %I.%I OWNER TO marty',
                                   relation.nspname, relation.relname);
                END LOOP;
            END
            $owners$;
        """)
        # INSTALL includes DRAIN under the same guarded transaction.
        copied = docker("cp", str(DRAIN), f"{name}:/tmp/{DRAIN.name}")
        assert copied.returncode == 0, copied.stderr
        system_id = psql(name, "SELECT system_identifier FROM pg_control_system()")
        database_oid = psql(name, "SELECT oid FROM pg_database WHERE datname='marty'")
        target = [
            "-c", "SET marty.passport_beta_verified_project = 'elevenid-beta'",
            "-c", f"SET marty.passport_beta_expected_system_identifier = '{system_id}'",
            "-c", f"SET marty.passport_beta_expected_database_oid = '{database_oid}'",
        ]
        run_file(name, INSTALL, target)
        epoch = psql(name, "SELECT epoch FROM passport_cutover.state")
        target += ["-c", f"SET marty.passport_beta_expected_fence_epoch = '{epoch}'"]
        run_file(name, START, target)
        migrations = tuple((relative, normalized_sql((ROOT / relative).read_bytes(), relative))
                           for relative in MIGRATIONS)
        payload = tmp_path / "native-bundle.sql"
        payload.write_bytes(build_sql({"system_id": system_id, "database_oid": database_oid,
                                       "fence_epoch": epoch}, migrations, "a" * 40))
        run_file(name, payload)
        run_file(name, FINALIZE, target)
        digest = migration_set_sha256(migrations)
        assert psql(name, "SELECT source_commit || '|' || migration_set_sha256 "
                          "FROM passport_cutover.native_migration_receipt") == "a" * 40 + "|" + digest
        assert psql(name, "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE "
                          "oid='passport_cutover.native_migration_receipt'::regclass") == (
            "marty_passport_fence_owner"
        )
        target += [
            "-c", "SET marty.passport_beta_expected_source_commit = '" + "a" * 40 + "'",
            "-c", f"SET marty.passport_beta_expected_native_migration_sha256 = '{digest}'",
        ]
        run_file(name, ENABLE, target)
        assert psql(name, "SELECT rolcanlogin FROM pg_roles WHERE rolname='marty'") == "t"
        run_file(name, VERIFY, target)
    finally:
        docker("stop", name)
