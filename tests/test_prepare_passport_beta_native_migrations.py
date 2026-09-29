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
    payload = build_sql(target, ((MIGRATIONS[0], b"SELECT 1;\n"),))
    assert payload.count(b"BEGIN;") == 1
    assert b"DO $target$\nBEGIN\n" in payload
    assert payload.endswith(b"SELECT 1;\n\nCOMMIT;\n")
    assert b"expected_system_identifier = '123456'" in payload
    assert b"expected_fence_epoch = '345'" in payload
    assert b"pg_stat_activity" in payload
    with pytest.raises(NativeMigrationError, match="protected source"):
        checked_receipt(path, "d" * 40)
    receipt["fence"]["epoch"] = "0'\nDROP SCHEMA issuance_service CASCADE;--"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(NativeMigrationError, match="invalid PostgreSQL"):
        checked_receipt(path, "b" * 40)


def test_prepare_binds_protected_main_receipt_and_signed_image(monkeypatch, tmp_path):
    checked = []
    monkeypatch.setattr(native, "protected_source", lambda: "b" * 40)
    monkeypatch.setattr(native, "protected_file", lambda relative, runner: checked.append(
        (relative, runner)
    ))
    monkeypatch.setattr(native, "manifest_source", lambda _manifest, head: {
        "oci_digests": {native.IMAGE_REPOSITORY: "sha256:" + "a" * 64},
        "source_commit": head,
    })
    monkeypatch.setattr(native, "checked_receipt", lambda _path, _head: {
        "system_id": "123456", "database_oid": "9876",
        "fence_epoch": "345", "container_id": "c" * 64,
    })
    monkeypatch.setattr(native, "checked_migrations", lambda _root, image: (
        (MIGRATIONS[0], b"SELECT 1;\n"),
    ) if image == IMAGE else ())
    plan, payload = native.prepare(tmp_path / "stack-manifest.json",
                                   tmp_path / "fence-receipt.json")
    assert tuple(relative for relative, _ in checked) == native.PROTECTED
    assert all(runner is native.run for _, runner in checked)
    assert plan["source_commit"] == "b" * 40
    assert plan["migration_image"] == IMAGE
    assert plan["migrations"][0]["path"] == MIGRATIONS[0]
    assert payload.endswith(b"SELECT 1;\n\nCOMMIT;\n")
