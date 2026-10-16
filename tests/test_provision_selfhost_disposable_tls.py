"""Disposable installed TLS staging uses reviewed digests and keyless outputs."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import provision_selfhost_disposable_tls as stage  # noqa: E402
from passport_remote_tls import PUBLIC_TLS_FILES, accept_remote_tls  # noqa: E402

SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
OPENBAO = "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "b" * 64


def bundle(tmp_path: Path) -> Path:
    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    (bundle_root / ".marty-selfhost-images.json").write_text(json.dumps({
        "schema": "marty.selfhost-image-lock/v1",
        "services": {"gateway": SERVICES, "signing-keys": SERVICES},
        "openbao_didcomm_image": OPENBAO,
    }), encoding="utf-8")
    return bundle_root


def test_locked_images_and_bundle_assets(tmp_path: Path) -> None:
    root = bundle(tmp_path)
    assert stage.exact_images(root) == (SERVICES, OPENBAO)
    assets = json.loads((ROOT / "deploy-config/bundles/selfhost.json").read_text(
        encoding="utf-8"))["assets"]
    assert {"scripts/provision_selfhost_disposable_tls.py",
            "scripts/passport_remote_tls.py"} <= set(assets)
    lock = root / ".marty-selfhost-images.json"
    data = json.loads(lock.read_text(encoding="utf-8"))
    data["services"]["signing-keys"] = SERVICES.replace("a" * 64, "c" * 64)
    lock.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="reviewed installer image"):
        stage.exact_images(root)


def test_openbao_network_requires_exact_running_project_and_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    details = [{
        "State": {"Running": True}, "Config": {"Image": OPENBAO, "Labels": {
            "com.docker.compose.project": "marty-selfhost-openbao",
            "com.docker.compose.service": "openbao",
        }},
        "Mounts": [{"Destination": "/bao/data", "Type": "bind", "Source": str(state)}],
        "NetworkSettings": {"Networks": {"private": {"Aliases": ["openbao"]}}},
    }]
    monkeypatch.setattr(stage.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 0, "123456789abc\n", ""))
    monkeypatch.setattr(stage, "docker_json", lambda args: details)
    assert stage.openbao_network("marty-selfhost-openbao", state, OPENBAO) == "private"
    details[0]["Config"]["Image"] = SERVICES
    with pytest.raises(RuntimeError, match="locked bundle image"):
        stage.openbao_network("marty-selfhost-openbao", state, OPENBAO)
    details[0]["Config"]["Image"] = OPENBAO
    details[0]["Config"]["Labels"]["com.docker.compose.project"] = "other"
    with pytest.raises(RuntimeError, match="locked bundle image"):
        stage.openbao_network("marty-selfhost-openbao", state, OPENBAO)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0,
                    reason="Linux root-only disposable staging")
def test_stages_only_public_tls_outputs_into_existing_private_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir(mode=0o700)
    existing = secret_root / "existing-credential"
    existing.write_text("leave-alone", encoding="ascii")
    state = tmp_path / "state"
    (state / "tls").mkdir(parents=True)
    (state / "tls" / "ca.crt").write_text("public-ca", encoding="ascii")
    (state / "root.token").write_text("root-token-only-in-state-123456", encoding="ascii")
    root = bundle(tmp_path)
    monkeypatch.setattr(stage, "openbao_network", lambda *_: "private")
    certificate = (ROOT / "rust/services/signing-keys/tests/fixtures"
                   / "public_certificates/root-ca.pem").read_text(encoding="ascii")

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        assert command[0:3] == ["docker", "run", "--rm"]
        assert "--network" in command and command[command.index("--network") + 1] == "private"
        assert command[-1] == SERVICES
        mount = next(part for part in command if part.startswith("type=bind,")
                     and part.endswith(",dst=/output"))
        output = Path(mount.split(",src=", 1)[1].split(",dst=", 1)[0])
        for name in PUBLIC_TLS_FILES:
            value = certificate if name.endswith("_cert") else f"hvs.synthetic-{name}-distinct"
            (output / name).write_text(value, encoding="ascii")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(stage.subprocess, "run", fake_run)
    stage.provision(root, secret_root, state, "marty-selfhost-openbao")
    assert {path.name for path in secret_root.iterdir()} == PUBLIC_TLS_FILES | {existing.name}
    assert existing.read_text(encoding="ascii") == "leave-alone"
    assert not (secret_root / "root.token").exists()
    assert all(stat.S_IMODE((secret_root / name).stat().st_mode) == 0o644
               for name in PUBLIC_TLS_FILES)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file-mode rollback")
def test_public_tls_move_rolls_back_after_chmod_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "tls-output"
    output.mkdir(mode=0o700)
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(mode=0o700)
    certificate = (ROOT / "rust/services/signing-keys/tests/fixtures"
                   / "public_certificates/root-ca.pem").read_text(encoding="ascii")
    for name in PUBLIC_TLS_FILES:
        (output / name).write_text(
            certificate if name.endswith("_cert") else f"hvs.synthetic-{name}-distinct-token",
            encoding="ascii",
        )
    original_chmod = os.chmod
    called = 0

    def fail_third_chmod(path: Path, mode: int) -> None:
        nonlocal called
        called += 1
        if called == 3:
            raise OSError("injected chmod failure")
        original_chmod(path, mode)

    monkeypatch.setattr(os, "chmod", fail_third_chmod)
    with pytest.raises(OSError, match="injected chmod failure"):
        accept_remote_tls(output, secrets_dir, "root-token-must-not-be-reused")
    assert {path.name for path in output.iterdir()} == PUBLIC_TLS_FILES
    assert list(secrets_dir.iterdir()) == []


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0,
                    reason="Linux root-only disposable staging")
def test_ownership_failure_removes_all_staged_tls_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir(mode=0o700)
    state = tmp_path / "state"
    (state / "tls").mkdir(parents=True)
    (state / "tls" / "ca.crt").write_text("public-ca", encoding="ascii")
    (state / "root.token").write_text("root-token-only-in-state-123456", encoding="ascii")
    root = bundle(tmp_path)
    monkeypatch.setattr(stage, "openbao_network", lambda *_: "private")
    certificate = (ROOT / "rust/services/signing-keys/tests/fixtures"
                   / "public_certificates/root-ca.pem").read_text(encoding="ascii")

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        mount = next(part for part in command if part.startswith("type=bind,")
                     and part.endswith(",dst=/output"))
        output = Path(mount.split(",src=", 1)[1].split(",dst=", 1)[0])
        for name in PUBLIC_TLS_FILES:
            (output / name).write_text(
                certificate if name.endswith("_cert") else f"hvs.synthetic-{name}-distinct",
                encoding="ascii",
            )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(stage.subprocess, "run", fake_run)
    called = 0

    def fail_third_chown(_path: Path, _uid: int, _gid: int) -> None:
        nonlocal called
        called += 1
        if called == 3:
            raise OSError("injected chown failure")

    monkeypatch.setattr(stage.os, "chown", fail_third_chown)
    with pytest.raises(OSError, match="injected chown failure"):
        stage.provision(root, secret_root, state, "marty-selfhost-openbao")
    assert list(secret_root.iterdir()) == []


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0,
                    reason="Linux root-only disposable staging")
def test_timeout_failed_cleanup_retains_container_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_root = tmp_path / "secrets"
    secret_root.mkdir(mode=0o700)
    state = tmp_path / "state"
    (state / "tls").mkdir(parents=True)
    (state / "tls" / "ca.crt").write_text("public-ca", encoding="ascii")
    (state / "root.token").write_text("root-token-only-in-state-123456", encoding="ascii")
    root = bundle(tmp_path)
    monkeypatch.setattr(stage, "openbao_network", lambda *_: "private")
    container_id = "d" * 64

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        if command[0:2] == ["docker", "run"]:
            Path(command[command.index("--cidfile") + 1]).write_text(
                container_id, encoding="ascii",
            )
            raise subprocess.TimeoutExpired(command, 180)
        assert command == ["docker", "rm", "--force", container_id]
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(stage.subprocess, "run", fake_run)
    with pytest.raises(stage.BootstrapCleanupError, match="manual cleanup required"):
        stage.provision(root, secret_root, state, "marty-selfhost-openbao")
    cidfiles = list(tmp_path.glob("marty-selfhost-tls-*.cid"))
    assert len(cidfiles) == 1
    assert cidfiles[0].read_text(encoding="ascii") == container_id
    assert list(secret_root.iterdir()) == []
