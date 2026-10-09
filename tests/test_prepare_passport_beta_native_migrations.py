"""Source/image equality and target binding for the beta Rust SQL payload."""

from __future__ import annotations

import json

import pytest

from scripts import prepare_passport_beta_native_migrations as native
from scripts.prepare_passport_beta_native_migrations import (
    MIGRATIONS, NativeMigrationError, build_sql, checked_migrations,
    checked_receipt, image_path, normalized_sql,
)


IMAGE = "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "a" * 64


def source_tree(root):
    baseline = root / "rust/services/issuance/migrations/0000_issuance_service_baseline.sql"
    baseline.parent.mkdir(parents=True, exist_ok=True)
    baseline.write_bytes(b"SELECT 0;\n")
    for index, relative in enumerate(MIGRATIONS):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"SELECT {index};\r\n".encode())


def test_image_must_match_every_normalized_protected_migration(tmp_path):
    source_tree(tmp_path)
    source = checked_migrations(
        tmp_path, IMAGE,
        lambda _image, relative: (tmp_path / relative).read_bytes().replace(b"\r\n", b"\n"),
    )
    assert tuple(relative for relative, _ in source) == MIGRATIONS
    assert image_path(MIGRATIONS[0]) == (
        "/app/passport-native-migrations/issuance/0001_oid4vci_public_protocol.sql"
    )
    with pytest.raises(NativeMigrationError, match="differs from protected source"):
        checked_migrations(tmp_path, IMAGE, lambda _image, _relative: b"SELECT 0;\n")
    extra = tmp_path / "rust/services/flow/migrations/0003_unreviewed.sql"
    extra.write_text("SELECT 1;\n", encoding="utf-8")
    with pytest.raises(NativeMigrationError, match="inventory changed"):
        checked_migrations(tmp_path, IMAGE, lambda _image, _relative: b"SELECT 0;\n")


def test_checked_in_inventory_and_protected_ledger_cover_same_issuance_sql():
    migrations = checked_migrations(
        native.ROOT, IMAGE,
        lambda _image, relative: normalized_sql(
            (native.ROOT / relative).read_bytes(), relative,
        ),
    )
    assert tuple(path for path, _ in migrations) == MIGRATIONS
    target = {"system_id": "123", "database_oid": "456",
              "fence_epoch": "7", "container_id": "c" * 64}
    payload = build_sql(target, migrations, "b" * 40).decode("utf-8")
    issuance_versions = [
        path.rsplit("/", 1)[-1].removesuffix(".sql")
        for path in MIGRATIONS if "/issuance/migrations/" in path
    ]
    for version in issuance_versions:
        assert payload.count(f"('{version}')") == 1
    assert "('0001_flow_schema')" not in payload


def test_disposable_marker_without_issuance_sql_has_valid_baseline_ledger():
    target = {"system_id": "123", "database_oid": "456",
              "fence_epoch": "7", "container_id": "c" * 64}
    payload = build_sql(target, (("disposable.sql", b"SELECT 1;\n"),), "b" * 40)
    assert (b"INSERT INTO issuance_service.rust_schema_migrations (version) VALUES\n"
            b"    ('issuance_service_baseline_v1');\n") in payload


def test_sql_normalization_rejects_meta_commands_and_bad_line_endings():
    assert normalized_sql(b"SELECT 1;\r\n", "reviewed.sql") == b"SELECT 1;\n"
    with pytest.raises(NativeMigrationError, match="psql command"):
        normalized_sql(b"  \\! echo unreviewed\n", "reviewed.sql")
    with pytest.raises(NativeMigrationError, match="line endings"):
        normalized_sql(b"SELECT 1;\r", "reviewed.sql")
    with pytest.raises(NativeMigrationError, match="UTF-8"):
        normalized_sql(b"\xff", "reviewed.sql")


def test_receipt_binds_protected_source_and_sql_attests_database(tmp_path):
    receipt = {
        "schema": "marty.passport-beta-fence-installation/v1",
        "source_commit": "b" * 40,
        "postgres_system_identifier": "123456",
        "database_oid": "9876",
        "postgres_container_id": "c" * 64,
        "fence": {
            "schema": "marty.passport-beta-fence-verification/v1",
            "phase": "fully_fenced", "epoch": 345,
        },
    }
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    target = checked_receipt(path, "b" * 40)
    payload = build_sql(target, ((MIGRATIONS[0], b"SELECT 1;\n"),), "b" * 40)
    assert payload.count(b"BEGIN;") == 1
    assert b"DO $target$\nBEGIN\n" in payload
    assert b"SELECT 1;\n" in payload
    assert payload.endswith(b"COMMIT;\n")
    assert b"CREATE TABLE passport_cutover.native_migration_receipt" in payload
    assert b"source_commit, migration_set_sha256" in payload
    assert b"CREATE TABLE issuance_service.rust_schema_migrations" in payload
    assert b"GRANT SELECT ON issuance_service.rust_schema_migrations TO marty" in payload
    assert b"('0001_oid4vci_public_protocol')" in payload
    assert b"expected_system_identifier = '123456'" in payload
    assert b"expected_fence_epoch = '345'" in payload
    assert b"pg_stat_activity" in payload
    assert b"rolcanlogin" in payload
    with pytest.raises(NativeMigrationError, match="protected source"):
        checked_receipt(path, "d" * 40)
    receipt["fence"]["epoch"] = "0'\nDROP SCHEMA issuance_service CASCADE;--"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(NativeMigrationError, match="invalid PostgreSQL"):
        checked_receipt(path, "b" * 40)


def test_retired_preparer_rejects_before_touching_protected_source(monkeypatch, tmp_path):
    monkeypatch.setattr(native, "protected_source", lambda: pytest.fail("legacy source read"))
    with pytest.raises(NativeMigrationError, match="retired"):
        native.prepare(tmp_path / "stack-manifest.json",
                       tmp_path / "fence-receipt.json")


def test_staged_native_sql_is_byte_exact_and_retry_safe(tmp_path):
    path = tmp_path / "native.sql"
    (tmp_path / "native.sql.stage-interrupted").write_bytes(b"truncated")
    native.stage_sql(path, b"SELECT 1;\n")
    native.stage_sql(path, b"SELECT 1;\n")
    assert path.read_bytes() == b"SELECT 1;\n"
    with pytest.raises(NativeMigrationError, match="differs from signed source"):
        native.stage_sql(path, b"SELECT 2;\n")
    with pytest.raises(NativeMigrationError, match="outside protected source"):
        native.stage_sql(native.ROOT / "native.sql", b"SELECT 1;\n")
