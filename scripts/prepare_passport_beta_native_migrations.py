#!/usr/bin/env python3
"""Bind the beta Rust SQL payload to protected source and the signed image.

This emits SQL or a read-only plan. A separate protected operator must hold the
beta host lock, stop writers, verify the live target, and execute the payload.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Callable

try:
    from .check_passport_beta_fence_authority import (
        manifest_source, protected_file, protected_source, run,
    )
except ImportError:
    from check_passport_beta_fence_authority import (
        manifest_source, protected_file, protected_source, run,
    )


ROOT = Path(__file__).resolve().parents[1]
IMAGE_REPOSITORY = "ghcr.io/elevenid/marty-ui-oss/migrations"
MIGRATIONS = (
    "rust/services/issuance/migrations/0001_oid4vci_public_protocol.sql",
    "rust/services/issuance/migrations/0002_physical_document_jobs.sql",
    "rust/services/issuance/migrations/0003_passport_bureau_provider_binding.sql",
    "rust/services/issuance/migrations/0004_passport_submission_intent.sql",
    "rust/services/issuance/migrations/0005_passport_submission_provenance.sql",
    "rust/services/issuance/migrations/0006_passport_beta_batch_identity.sql",
    "rust/services/issuance/migrations/0007_passport_beta_batch_provenance.sql",
    "rust/services/issuance/migrations/0008_passport_beta_batch_wire_evidence.sql",
    "rust/services/flow/migrations/0001_flow_schema.sql",
    "rust/services/flow/migrations/0002_builtin_flows.sql",
)
PROTECTED = (
    ".gitattributes",
    "services/Dockerfile.migrations",
    "scripts/prepare_passport_beta_native_migrations.py",
    "scripts/sql/passport-beta-batch-acl-finalize.sql",
    "scripts/sql/passport-beta-db-enable-app-login.sql",
    "scripts/run-passport-beta-native-db-gates.ps1",
    *MIGRATIONS,
)
NUMBER = re.compile(r"[1-9][0-9]*\Z")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")


class NativeMigrationError(RuntimeError):
    """The signed Rust SQL cannot be bound to this fenced beta target."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeMigrationError(message)


def normalized_sql(data: bytes, path: str) -> bytes:
    try:
        text = data.decode("utf-8", errors="strict").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise NativeMigrationError(f"Native migration is not UTF-8: {path}") from exc
    require("\r" not in text and bool(text.strip()),
            f"Native migration has unsupported line endings or is empty: {path}")
    require(not any(line.lstrip().startswith("\\") for line in text.splitlines()),
            f"Native migration contains a psql command: {path}")
    return text.encode("utf-8")


def image_path(relative: str) -> str:
    parts = relative.split("/")
    return f"/app/passport-native-migrations/{parts[2]}/{parts[-1]}"


def read_image_sql(image: str, relative: str) -> bytes:
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--pull", "never",
         "--entrypoint", "cat", image, image_path(relative)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=90,
    )
    if result.returncode != 0:
        raise NativeMigrationError(f"Signed migration image lacks {relative}")
    return result.stdout


def checked_migrations(
    root: Path, image: str, image_reader: Callable[[str, str], bytes] = read_image_sql,
) -> tuple[tuple[str, bytes], ...]:
    require(re.fullmatch(re.escape(IMAGE_REPOSITORY) + r"@sha256:[0-9a-f]{64}",
                         image) is not None,
            "Migration image must use the signed immutable repository and digest")
    for directory in ("rust/services/issuance/migrations",
                      "rust/services/flow/migrations"):
        found = {path.relative_to(root).as_posix()
                 for path in (root / directory).glob("*.sql")}
        expected = {path for path in MIGRATIONS if path.startswith(directory + "/")}
        if directory.endswith("/issuance/migrations"):
            expected.add("rust/services/issuance/migrations/0000_issuance_service_baseline.sql")
        require(found == expected,
                f"Native migration inventory changed: {directory}")
    result = []
    for relative in MIGRATIONS:
        local = normalized_sql((root / relative).read_bytes(), relative)
        packaged = image_reader(image, relative)
        require(packaged == local,
                f"Signed migration image SQL differs from protected source: {relative}")
        result.append((relative, local))
    return tuple(result)


def checked_receipt(path: Path, source_commit: str) -> dict[str, str]:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise NativeMigrationError("Fence installation receipt is unreadable") from exc
    require(isinstance(receipt, dict)
            and receipt.get("schema") == "marty.passport-beta-fence-installation/v1"
            and receipt.get("source_commit") == source_commit,
            "Fence receipt is not bound to protected source")
    fence = receipt.get("fence")
    require(isinstance(fence, dict)
            and fence.get("schema") == "marty.passport-beta-fence-verification/v1"
            and fence.get("phase") == "fully_fenced",
            "Fence receipt lacks a full fence")
    system_id = str(receipt.get("postgres_system_identifier", ""))
    database_oid = str(receipt.get("database_oid", ""))
    epoch = str(fence.get("epoch", ""))
    container_id = str(receipt.get("postgres_container_id", ""))
    require(all(NUMBER.fullmatch(value) is not None
                for value in (system_id, database_oid, epoch))
            and CONTAINER_ID.fullmatch(container_id) is not None,
            "Fence receipt has invalid PostgreSQL or container identity")
    return {"system_id": system_id, "database_oid": database_oid,
            "fence_epoch": epoch, "container_id": container_id}


def migration_set_sha256(migrations: tuple[tuple[str, bytes], ...]) -> str:
    hasher = hashlib.sha256()
    for relative, data in migrations:
        hasher.update(relative.encode("utf-8") + b"\0")
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(data)
    return hasher.hexdigest()


def build_sql(
    receipt: dict[str, str], migrations: tuple[tuple[str, bytes], ...],
    source_commit: str,
) -> bytes:
    for key in ("system_id", "database_oid", "fence_epoch"):
        require(NUMBER.fullmatch(receipt[key]) is not None,
                f"Invalid migration target {key}")
    require(re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None,
            "Invalid protected migration source commit")
    migration_digest = migration_set_sha256(migrations)
    prefix = (
        "SET marty.passport_beta_verified_project = 'elevenid-beta';\n"
        f"SET marty.passport_beta_expected_system_identifier = '{receipt['system_id']}';\n"
        f"SET marty.passport_beta_expected_database_oid = '{receipt['database_oid']}';\n"
        f"SET marty.passport_beta_expected_fence_epoch = '{receipt['fence_epoch']}';\n"
        "BEGIN;\nSET LOCAL lock_timeout = '10s';\n"
        "SET LOCAL statement_timeout = '300s';\n"
        "DO $target$\nBEGIN\n"
        "    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)\n"
        "        OR current_database() <> 'marty'\n"
        "        OR current_setting('marty.passport_beta_verified_project', true)\n"
        "            IS DISTINCT FROM 'elevenid-beta'\n"
        "        OR current_setting('marty.passport_beta_expected_system_identifier', true)\n"
        "            IS DISTINCT FROM (SELECT system_identifier::text FROM pg_control_system())\n"
        "        OR current_setting('marty.passport_beta_expected_database_oid', true)\n"
        "            IS DISTINCT FROM (SELECT oid::text FROM pg_database\n"
        "                              WHERE datname=current_database())\n"
        "        OR current_setting('marty.passport_beta_expected_fence_epoch', true)\n"
        "            IS DISTINCT FROM (SELECT epoch::text FROM passport_cutover.state\n"
        "                              WHERE singleton=true AND phase='fully_fenced')\n"
        "        OR (SELECT count(*) FROM passport_cutover.state\n"
        "            WHERE singleton=true AND phase='fully_fenced' AND epoch>0) <> 1\n"
        "        OR EXISTS (SELECT 1 FROM pg_roles\n"
        "                   WHERE rolname IN ('marty','marty_beta_migrator') AND rolcanlogin)\n"
        "        OR (SELECT count(*) FROM pg_roles\n"
        "            WHERE rolname IN ('marty','marty_beta_migrator')) <> 2\n"
        "        OR EXISTS (SELECT 1 FROM pg_stat_activity\n"
        "                   WHERE usename IN ('marty','marty_beta_migrator')\n"
        "                     AND pid<>pg_backend_pid()) THEN\n"
        "        RAISE EXCEPTION 'native migrations lack exact fenced beta target';\n"
        "    END IF;\nEND\n$target$;\n"
        "LOCK TABLE issuance_service.physical_document_jobs,\n"
        "    flow_service.flow_definitions, flow_service.flow_instances\n"
        "    IN ACCESS EXCLUSIVE MODE;\n"
    ).encode("utf-8")
    payload = bytearray(prefix)
    for relative, data in migrations:
        payload.extend(f"\n-- protected native migration: {relative}\n".encode("ascii"))
        payload.extend(data)
        payload.extend(b"\n")
    issuance_versions = [
        Path(relative).stem for relative, _ in migrations
        if relative.startswith("rust/services/issuance/migrations/")
    ]
    ledger_rows = ["    ('issuance_service_baseline_v1')"]
    ledger_rows.extend(f"    ('{version}')" for version in issuance_versions)
    payload.extend((
        "\n-- Privileged, atomic handoff to the read-only Rust schema verifier.\n"
        "CREATE TABLE issuance_service.rust_schema_migrations (\n"
        "    version text PRIMARY KEY,\n"
        "    applied_at timestamptz NOT NULL DEFAULT now()\n"
        ");\n"
        "ALTER TABLE issuance_service.rust_schema_migrations\n"
        "    OWNER TO marty_passport_fence_owner;\n"
        "REVOKE ALL ON issuance_service.rust_schema_migrations FROM PUBLIC, marty;\n"
        "GRANT SELECT ON issuance_service.rust_schema_migrations TO marty;\n"
        "INSERT INTO issuance_service.rust_schema_migrations (version) VALUES\n"
        + ",\n".join(ledger_rows) + ";\n"
        "\n-- Commit evidence in the same transaction as every native migration.\n"
        "CREATE TABLE passport_cutover.native_migration_receipt (\n"
        "    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),\n"
        "    fence_epoch bigint NOT NULL,\n"
        "    source_commit text NOT NULL,\n"
        "    migration_set_sha256 text NOT NULL,\n"
        "    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()\n"
        ");\n"
        "ALTER TABLE passport_cutover.native_migration_receipt\n"
        "    OWNER TO marty_passport_fence_owner;\n"
        "REVOKE ALL ON passport_cutover.native_migration_receipt FROM PUBLIC, marty;\n"
        "INSERT INTO passport_cutover.native_migration_receipt\n"
        "    (singleton, fence_epoch, source_commit, migration_set_sha256)\n"
        f"VALUES (true, {receipt['fence_epoch']}, '{source_commit}',"
        f" '{migration_digest}');\n"
    ).encode("ascii"))
    payload.extend(b"COMMIT;\n")
    return bytes(payload)


def prepare(manifest: Path, fence_receipt: Path) -> tuple[dict[str, object], bytes]:
    head = protected_source()
    for relative in PROTECTED:
        protected_file(relative, run)
    signed = manifest_source(manifest, head, rust_only=True)
    receipt = checked_receipt(fence_receipt, head)
    digest = signed["oci_digests"][IMAGE_REPOSITORY]
    image = f"{IMAGE_REPOSITORY}@{digest}"
    migrations = checked_migrations(ROOT, image)
    payload = build_sql(receipt, migrations, head)
    plan = {
        "schema": "marty.passport-beta-native-migration-plan/v1",
        "source_commit": head,
        "migration_image": image,
        "postgres_container_id": receipt["container_id"],
        "postgres_system_identifier": receipt["system_id"],
        "database_oid": receipt["database_oid"],
        "fence_epoch": receipt["fence_epoch"],
        "migration_set_sha256": migration_set_sha256(migrations),
        "migrations": [
            {"path": relative, "sha256": hashlib.sha256(data).hexdigest()}
            for relative, data in migrations
        ],
        "sql_sha256": hashlib.sha256(payload).hexdigest(),
        "batch_acl_sql_sha256": hashlib.sha256(
            (ROOT / "scripts/sql/passport-beta-batch-acl-finalize.sql").read_bytes()
        ).hexdigest(),
        "enable_login_sql_sha256": hashlib.sha256(
            (ROOT / "scripts/sql/passport-beta-db-enable-app-login.sql").read_bytes()
        ).hexdigest(),
    }
    return plan, payload


def stage_sql(path: Path, payload: bytes) -> None:
    """Create or verify a durable byte-exact payload outside protected source."""
    require(path.is_absolute() and not path.resolve().is_relative_to(ROOT.resolve()),
            "Native SQL stage path must be absolute and outside protected source")
    if path.exists():
        require(path.is_file() and not path.is_symlink()
                and path.read_bytes() == payload,
                "Existing native SQL stage differs from signed source")
        return
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=path.name + ".stage-", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        try:
            # A hard link publishes complete bytes without replacing a prior
            # stage, on the same filesystem as the target path.
            os.link(temporary, path)
        except FileExistsError:
            require(path.is_file() and not path.is_symlink()
                    and path.read_bytes() == payload,
                    "Existing native SQL stage differs from signed source")
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-manifest", type=Path, required=True)
    parser.add_argument("--fence-receipt", type=Path, required=True)
    parser.add_argument("--emit-sql", action="store_true")
    parser.add_argument("--output-sql", type=Path)
    args = parser.parse_args()
    try:
        require(not (args.emit_sql and args.output_sql),
                "Choose one native SQL output mode")
        plan, payload = prepare(args.stack_manifest, args.fence_receipt)
        if args.output_sql:
            stage_sql(args.output_sql, payload)
    except (NativeMigrationError, OSError, KeyError, ValueError) as exc:
        raise SystemExit(f"Protected beta native migration is unavailable: {exc}") from exc
    if args.emit_sql:
        sys.stdout.buffer.write(payload)
    else:
        print(json.dumps(plan, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
