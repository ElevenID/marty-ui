"""Render real Compose defaults and overrides without contacting a daemon."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
GRAPHS = (
    ("docker-compose.base.yml",),
    ("docker-compose.base.yml", "docker-compose.beta.yml"),
    ("docker-compose.selfhost.prod.yml", "docker-compose.selfhost.bundle.override.yml"),
    ("docker-compose.selfhost.openbao.yml",),
    ("docker-compose.ui-prod.yml",),
    ("docker-compose.ui-release.yml",),
)


def render(files, tmp_path, overrides=None):
    docker = shutil.which("docker")
    if not docker or subprocess.run(
        [docker, "compose", "version"], capture_output=True, timeout=10
    ).returncode:
        pytest.skip("Docker Compose is unavailable")
    # Do not inherit local deployment secrets, .env files or memory overrides.
    env = {key: value for key, value in os.environ.items()
           if key in {"PATH", "HOME", "USERPROFILE", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP"}}
    for source in ROOT.glob("docker-compose*.yml"):
        for key in re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", source.read_text()):
            env[key] = "synthetic-required-value"
    env.update({
        "KEYCLOAK_KMS_IMAGE_DIGEST": "sha256:" + "a" * 64,
        "MARTY_KEYCLOAK_KMS_IMAGE": "example.invalid/keycloak-kms@sha256:" + "a" * 64,
        "KEYCLOAK_KMS_ADDR": "https://openbao:8200",
        "KEYCLOAK_KMS_KEY_VERSION": "1",
        "MARTY_OPENBAO_DIDCOMM_IMAGE": "example.invalid/openbao@sha256:" + "b" * 64,
        "SELFHOST_STATE_DIR": str(tmp_path / "state"),
        "UI_BASE_URL": "https://example.invalid",
    })
    env.update(overrides or {})
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")
    command = [docker, "compose", "--env-file", str(empty_env)]
    for name in files:
        command.extend(["-f", str(ROOT / name)])
    command.extend(["config", "--format", "json", "--no-env-resolution"])
    result = subprocess.run(command, cwd=tmp_path, env=env, capture_output=True,
                            text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["services"]


@pytest.mark.parametrize("files", GRAPHS)
def test_defaults_bound_every_service_and_keycloak_heap(files, tmp_path):
    services = render(files, tmp_path)
    assert services
    for name, service in services.items():
        assert int(service.get("mem_limit", 0)) > 0, name
        deploy_limit = service.get("deploy", {}).get("resources", {}).get("limits", {}).get("memory")
        if deploy_limit is not None:
            assert int(deploy_limit) == int(service["mem_limit"]), name
    if "keycloak" in services:
        keycloak = services["keycloak"]
        assert int(keycloak["mem_limit"]) == 2 * 1024**3
        assert keycloak["environment"]["JAVA_OPTS_KC_HEAP"] == (
            "-XX:InitialRAMPercentage=20 -XX:MaxRAMPercentage=65"
        )


@pytest.mark.parametrize("files", GRAPHS[:3])
def test_keycloak_tuning_keeps_compose_and_deploy_limits_consistent(files, tmp_path):
    services = render(files, tmp_path, {"MARTY_KEYCLOAK_MEMORY_LIMIT": "3g"})
    keycloak = services["keycloak"]
    assert int(keycloak["mem_limit"]) == 3 * 1024**3
    if "deploy" in keycloak:
        assert int(keycloak["deploy"]["resources"]["limits"]["memory"]) == int(keycloak["mem_limit"])
