"""Prepared preview staging keeps lineage and secrets outside the bundle."""

import hashlib
import json
import os
import shutil
import stat
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import stage_selfhost_disposable_preview as stage  # noqa: E402
from generate_selfhost_disposable_credentials import (  # noqa: E402
    GENERATED, OPERATOR_PASSWORD_POLICY, validate_operator_password,
)
from record_selfhost_bundle_preparation import record  # noqa: E402


SOURCE_SHA = "b" * 40


def preview_assets(tmp_path: Path) -> Path:
    assets = tmp_path / "assets"
    assets.mkdir()
    image = "example.org/app@sha256:" + "a" * 64
    plugin = "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "b" * 64
    lock = {"schema": "marty.selfhost-image-lock/v1", "release": "marty-ui@1.2.3",
            "openbao_didcomm_image": plugin, "services": {"app": image}}
    (assets / "prepared-selfhost-images.json").write_text(json.dumps(lock), encoding="utf-8")
    (assets / "selfhost-preparation-transaction.json").write_text("{}", encoding="utf-8")
    source_compose = (Path(__file__).resolve().parents[1] /
                      "docker-compose.selfhost.openbao.yml").read_text(encoding="utf-8")
    placeholder = "${MARTY_OPENBAO_DIDCOMM_IMAGE:?set MARTY_OPENBAO_DIDCOMM_IMAGE to the reviewed plugin image digest}"
    files = {
        ".marty-selfhost-images.json": (assets / "prepared-selfhost-images.json").read_bytes(),
        "docker-compose.selfhost.openbao.yml": source_compose.replace(
            placeholder, plugin).encode(),
        "docker-compose.yml": f"services:\n  app:\n    image: {image}\n".encode(),
        "README.md": b"experimental, unqualified\n",
        "scripts/launch.sh": b"#!/bin/sh\nexit 0\n",
    }
    marker = {"schema": "marty.selfhost-bundle-files/v1",
              "files": {name: hashlib.sha256(value).hexdigest()
                        for name, value in files.items()}, "directories": ["", "scripts"]}
    archive = assets / "prepared-selfhost-bundle.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("selfhost-prepared/", b"")
        bundle.writestr("selfhost-prepared/scripts/", b"")
        for name, content in files.items():
            if name == "scripts/launch.sh":
                executable = zipfile.ZipInfo(f"selfhost-prepared/{name}")
                executable.create_system = 3
                executable.external_attr = (stat.S_IFREG | 0o755) << 16
                bundle.writestr(executable, content)
            else:
                bundle.writestr(f"selfhost-prepared/{name}", content)
        bundle.writestr("selfhost-prepared/.marty-selfhost-bundle.json",
                        json.dumps(marker))
    receipt = record(archive, assets / "prepared-selfhost-images.json",
                     assets / "selfhost-preparation-transaction.json", SOURCE_SHA, "123")
    (assets / "prepared-selfhost-bundle.json").write_text(
        json.dumps(receipt), encoding="utf-8")
    (assets / "prepared-selfhost-product-descriptor.json").write_text(
        "{}", encoding="utf-8")
    (assets / "SELFHOST-PREVIEW-README.md").write_text(
        "unqualified test", encoding="utf-8")
    (assets / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256((assets / name).read_bytes()).hexdigest()}  {name}\n"
        for name in sorted(stage.ASSETS)), encoding="ascii")
    return assets


@pytest.mark.parametrize("with_operator_password", [False, True])
def test_stages_exact_archive_and_private_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
    with_operator_password: bool,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX private-file behavior")
    assets = preview_assets(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    realm = source / "config/keycloak/11id-realm.json"
    realm.parent.mkdir(parents=True)
    realm.write_text(json.dumps({"passwordPolicy": OPERATOR_PASSWORD_POLICY}))
    private = tmp_path / "private"
    monkeypatch.setattr(stage.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(stage, "clean_source_sha", lambda _source: SOURCE_SHA)
    monkeypatch.setattr(stage, "verify_descriptor", lambda *_args: None)
    calls = []
    original_write = stage.write_operator_password

    def record_write(path: Path, *, realm_file: Path) -> None:
        calls.append((path, realm_file))
        original_write(path, realm_file=realm_file)

    monkeypatch.setattr(stage, "write_operator_password", record_write)
    result = stage.stage(assets, source, private,
                         with_operator_password=with_operator_password)
    assert result["qualification"] == "unqualified"
    assert result["source_sha"] == SOURCE_SHA
    assert result["install_root"] == str(private / "install" / "selfhost-prepared")
    assert stat.S_IMODE(private.stat().st_mode) == 0o700
    assert {path.name for path in (private / "secrets").iterdir()} == GENERATED
    assert stat.S_IMODE((private / "install" / "selfhost-prepared" /
                         "scripts" / "launch.sh").stat().st_mode) == 0o755
    assert not (private / "install" / "selfhost-prepared" / "secrets").exists()
    assert json.loads((private / "stage.json").read_text(encoding="utf-8")) == result
    password_file = private / "operator-password"
    assert password_file.exists() is with_operator_password
    assert calls == ([(password_file, realm)] if with_operator_password else [])
    if with_operator_password:
        password = password_file.read_text(encoding="ascii").strip()
        validate_operator_password(password, realm)
        assert stat.S_IMODE(password_file.stat().st_mode) == 0o600
        assert password not in json.dumps(result)
        assert password not in str(capsys.readouterr())
    with pytest.raises(ValueError, match="fresh private root"):
        stage.stage(assets, source, private, with_operator_password=with_operator_password)


def test_checksum_failure_precedes_private_root_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX private-file behavior")
    assets = preview_assets(tmp_path)
    (assets / "SELFHOST-PREVIEW-README.md").write_text("changed", encoding="utf-8")
    source = tmp_path / "source"
    source.mkdir()
    private = tmp_path / "private"
    monkeypatch.setattr(stage.os, "geteuid", lambda: 1000)
    with pytest.raises(ValueError, match="checksum"):
        stage.stage(assets, source, private)
    assert not private.exists()


@pytest.mark.parametrize("with_operator_password", [False, True])
def test_late_failure_removes_owned_partial_credentials_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_operator_password: bool,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX private-file behavior")
    assets = preview_assets(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    realm = source / "config/keycloak/11id-realm.json"
    realm.parent.mkdir(parents=True)
    realm.write_text(json.dumps({"passwordPolicy": OPERATOR_PASSWORD_POLICY}))
    private = tmp_path / "private"
    monkeypatch.setattr(stage.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(stage, "clean_source_sha", lambda _source: SOURCE_SHA)
    monkeypatch.setattr(stage, "verify_descriptor", lambda *_args: None)
    original_generate = stage.generate

    def fail_after_secret_creation(root: Path) -> None:
        assert (private / "operator-password").exists() is with_operator_password
        (root / "sensitive").write_text("do-not-retain", encoding="ascii")
        raise RuntimeError("injected staging failure")

    monkeypatch.setattr(stage, "generate", fail_after_secret_creation)
    with pytest.raises(RuntimeError, match="injected staging failure"):
        stage.stage(assets, source, private, with_operator_password=with_operator_password)
    assert not private.exists()
    monkeypatch.setattr(stage, "generate", original_generate)
    assert stage.stage(assets, source, private)["qualification"] == "unqualified"


@pytest.mark.parametrize("policy", [None, "length(8)"])
def test_opt_in_uses_selected_source_policy_before_generating_service_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX private-file behavior")
    assets = preview_assets(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    if policy is not None:
        realm = source / "config/keycloak/11id-realm.json"
        realm.parent.mkdir(parents=True)
        realm.write_text(json.dumps({"passwordPolicy": policy}))
    private = tmp_path / "private"
    monkeypatch.setattr(stage.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(stage, "clean_source_sha", lambda _source: SOURCE_SHA)
    monkeypatch.setattr(stage, "verify_descriptor", lambda *_args: None)
    monkeypatch.setattr(stage, "generate", lambda _: pytest.fail("service generation called"))
    with pytest.raises(ValueError, match="shipped operator password policy"):
        stage.stage(assets, source, private, with_operator_password=True)
    assert not private.exists()


@pytest.mark.parametrize("enabled", [False, True])
def test_cli_forwards_only_opt_in_and_sanitizes_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, enabled: bool,
) -> None:
    paths = [tmp_path / name for name in ("assets", "source", "private")]
    argv = ["stage", "--assets-dir", str(paths[0]), "--source-checkout", str(paths[1]),
            "--private-root", str(paths[2])]
    if enabled:
        argv.append("--with-operator-password")
    monkeypatch.setattr(sys, "argv", argv)
    calls = []

    def fail(*args, **kwargs):
        calls.append((args, kwargs))
        raise ValueError("sensitive-failure-detail")

    monkeypatch.setattr(stage, "stage", fail)
    assert stage.main() == 2
    assert calls == [(tuple(paths), {"with_operator_password": enabled})]
    captured = capsys.readouterr()
    assert not captured.out
    assert captured.err == "disposable preview staging failed: ValueError\n"


def test_unsafe_parent_is_rejected_before_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX private-file behavior")
    assets = preview_assets(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o700)
    parent.chmod(0o777)
    private = parent / "private"
    monkeypatch.setattr(stage.os, "geteuid", lambda: 1000)
    with pytest.raises(ValueError, match="operator-owned and private"):
        stage.stage(assets, source, private)
    assert not private.exists()


def test_replaced_root_is_not_deleted_on_late_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX private-file behavior")
    assets = preview_assets(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    private = tmp_path / "private"
    moved = tmp_path / "moved-owned-root"
    monkeypatch.setattr(stage.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(stage, "clean_source_sha", lambda _source: SOURCE_SHA)
    monkeypatch.setattr(stage, "verify_descriptor", lambda *_args: None)

    def replace_root(_secrets: Path) -> None:
        private.rename(moved)
        private.mkdir(mode=0o700)
        (private / "unrelated").write_text("keep", encoding="ascii")
        raise RuntimeError("injected staging failure")

    monkeypatch.setattr(stage, "generate", replace_root)
    with pytest.raises(RuntimeError, match="manual recovery"):
        stage.stage(assets, source, private)
    assert (private / "unrelated").read_text(encoding="ascii") == "keep"
    assert moved.is_dir()
    shutil.rmtree(private)
    shutil.rmtree(moved)
