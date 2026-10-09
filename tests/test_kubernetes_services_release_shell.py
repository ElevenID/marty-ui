"""The Kubernetes signed-release preflight binds the selected manifest directory."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = (
    "00-namespace.yaml", "01-configmap.yaml", "03-postgres.yaml",
    "04-redis-rabbitmq.yaml", "05-keycloak.yaml",
    "05b-revocation-profile-migrations.yaml", "06-db-migrate.yaml",
    "06a-issuance-migrations.yaml", "07-microservices.yaml",
    "07a-issuance-native.yaml", "07b-signing-keys.yaml",
    "08-ui.yaml", "09-cloudflared.yaml",
)


def git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def bash_binary() -> str:
    if os.name == "nt":
        binary = Path("C:/Program Files/Git/bin/bash.exe")
        if binary.is_file():
            return str(binary)
    value = shutil.which("bash")
    if value is None:
        pytest.skip("Bash is unavailable")
    return value


def run_preflight(repo: Path, manifest_dir: Path) -> subprocess.CompletedProcess:
    source = (ROOT / "scripts/deploy-kubernetes.sh").read_text(encoding="utf-8")
    prefix = "require_kubernetes_services_release() {\n"
    assert source.count(prefix) == 1
    body = source.split(prefix, 1)[1].split("\n}", 1)[0]
    script = (
        "set -euo pipefail\n"
        + prefix + body + "\n}\n"
        + "error() { printf '%s\\n' \"$*\" >&2; return 1; }\n"
        + 'REPO_ROOT="$(cd "$1" && pwd -P)"\n'
        + 'K8S_DIR="$2"\n'
        + 'MARTY_STACK_MANIFEST=stack-manifest.json\n'
        + 'MARTY_SERVICES_IMAGE=ghcr.io/elevenid/marty-ui-oss/services@sha256:'
        + "a" * 64 + '\n'
        + 'PYTHON_BIN=true\n'
        + "require_kubernetes_services_release\n"
    )
    return subprocess.run(
        [bash_binary(), "--noprofile", "--norc", "-c", script,
         "preflight", repo.as_posix(), manifest_dir.as_posix()],
        capture_output=True, text=True, check=False,
    )


def test_signed_kubernetes_preflight_requires_clean_tracked_manifests(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    manifests = repo / "k8s/oracle"
    manifests.mkdir(parents=True)
    for name in MANIFESTS:
        (manifests / name).write_text("kind: List\n", encoding="utf-8")
    tracked = manifests / "07-microservices.yaml"
    git("init", "-q", cwd=repo)
    git("-c", "user.name=Test", "-c", "user.email=test@example.test",
        "add", ".", cwd=repo)
    git("-c", "user.name=Test", "-c", "user.email=test@example.test",
        "commit", "-qm", "fixture", cwd=repo)

    assert run_preflight(repo, manifests).returncode == 0
    tracked.write_text("kind: Deployment\n", encoding="utf-8")
    assert run_preflight(repo, manifests).returncode != 0
    tracked.write_text("kind: List\n", encoding="utf-8")
    outside = tmp_path / "other"
    outside.mkdir()
    assert run_preflight(repo, outside).returncode != 0

    custom = repo / "k8s/custom"
    custom.mkdir()
    for name in MANIFESTS:
        (custom / name).write_text("kind: List\n", encoding="utf-8")
    (repo / ".gitignore").write_text("k8s/custom/01-configmap.yaml\n", encoding="utf-8")
    git("add", ".", cwd=repo)
    git("-c", "user.name=Test", "-c", "user.email=test@example.test",
        "commit", "-qm", "custom fixture", cwd=repo)
    assert run_preflight(repo, custom).returncode != 0
