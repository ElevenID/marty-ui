"""Only rendered-disabled integrations may receive empty Compose files."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import stage_selfhost_disabled_optional_secrets as optional  # noqa: E402
import run_selfhost_business_journey as journey  # noqa: E402

PROJECT = "marty-selfhost-qual-1234567890abcdef"


def disabled_model() -> dict:
    return {"services": {
        "keycloak-configurator": {"environment": {
            "KEYCLOAK_SOCIAL_LOGIN_ENABLED": "false", "KEYCLOAK_SMTP_USERNAME": "",
        }},
        "notification": {"environment": {"SMTP_USERNAME": ""}},
        "issuance": {"environment": {
            **{name: "false" for name in journey.CANVAS_DISABLED_FLAGS},
            **{name: "" for name in journey.CANVAS_UNUSED_SETTINGS},
        }},
    }}


def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    if os.name != "posix" or os.geteuid() != 0:
        pytest.skip("POSIX ownership fixture requires root in disposable test container")
    secret_root = tmp_path / "secrets"
    secret_root.mkdir(mode=0o700)
    os.chown(secret_root, 1000, 1000)
    install_root = tmp_path / "install"
    install_root.mkdir()
    (install_root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    env_file = tmp_path / "install.env"
    env_file.write_text("PREVIEW=1\n", encoding="utf-8")
    monkeypatch.setattr(optional, "render_model", lambda *_: disabled_model())
    monkeypatch.setattr(optional.os, "getuid", lambda: 1000)
    monkeypatch.setattr(optional.os, "geteuid", lambda: 1000)
    return secret_root, install_root, env_file


def test_creates_exact_six_empty_private_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_root, install_root, env_file = setup(tmp_path, monkeypatch)
    assert optional.stage(secret_root, install_root, env_file, PROJECT) == 6
    assert {path.name for path in secret_root.iterdir()} == journey.OPTIONAL_LOCAL_SECRET_NAMES
    for path in secret_root.iterdir():
        assert path.stat().st_size == 0
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
    with pytest.raises(ValueError, match="overwrite"):
        optional.stage(secret_root, install_root, env_file, PROJECT)


def test_enabled_integration_cannot_receive_empty_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_root, install_root, env_file = setup(tmp_path, monkeypatch)
    data = disabled_model()
    data["services"]["keycloak-configurator"]["environment"][
        "KEYCLOAK_SOCIAL_LOGIN_ENABLED"] = "true"
    monkeypatch.setattr(optional, "render_model", lambda *_: data)
    with pytest.raises(ValueError, match="not all optional integrations"):
        optional.stage(secret_root, install_root, env_file, PROJECT)
    assert not list(secret_root.iterdir())


def test_late_mode_failure_rolls_back_owned_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_root, install_root, env_file = setup(tmp_path, monkeypatch)
    real_fchmod = optional.os.fchmod
    calls = 0

    def fail_second(fd: int, mode: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected chmod failure")
        real_fchmod(fd, mode)

    monkeypatch.setattr(optional.os, "fchmod", fail_second)
    with pytest.raises(OSError, match="injected chmod failure"):
        optional.stage(secret_root, install_root, env_file, PROJECT)
    assert not list(secret_root.iterdir())


def test_renders_exact_installed_compose_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_root = tmp_path / "install"
    install_root.mkdir()
    compose = install_root / "docker-compose.yml"
    compose.write_text("services: {}\n", encoding="utf-8")
    env_file = tmp_path / "install.env"
    env_file.write_text("PREVIEW=1\n", encoding="utf-8")

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert argv == [
            "docker", "compose", "--project-name", PROJECT,
            "--env-file", str(env_file), "-f", str(compose),
            "--profile", "*", "config", "--format", "json",
        ]
        assert kwargs["cwd"] == install_root
        return subprocess.CompletedProcess(argv, 0, json.dumps({"name": PROJECT}), "")

    monkeypatch.setattr(optional.subprocess, "run", fake_run)
    assert optional.render_model(install_root, env_file, PROJECT)["name"] == PROJECT


def test_rejects_rendered_project_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_root = tmp_path / "install"
    install_root.mkdir()
    (install_root / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    env_file = tmp_path / "install.env"
    env_file.write_text("PREVIEW=1\n", encoding="utf-8")
    monkeypatch.setattr(
        optional.subprocess, "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 0, json.dumps({"name": "wrong-project"}), "",
        ),
    )
    with pytest.raises(ValueError, match="project differs"):
        optional.render_model(install_root, env_file, PROJECT)
