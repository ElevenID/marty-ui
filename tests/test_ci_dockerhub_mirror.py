"""Keep CI's Docker Hub cache route digest-pinned and fail-closed."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tomllib

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
JOBS = WORKFLOW["jobs"]
MIRROR_SCRIPT = "bash scripts/ci/configure-dockerhub-mirror.sh"
BUILDKIT_CONFIG = ".github/buildkit-ci-mirror.toml"


def test_buildkit_uses_only_the_documented_docker_hub_cache() -> None:
    config = tomllib.loads((ROOT / BUILDKIT_CONFIG).read_text(encoding="utf-8"))
    assert config == {"registry": {"docker.io": {"mirrors": ["mirror.gcr.io"]}}}
    for owner in (
        "test-rust-passport-image",
        "test-rust-services",
        "test-rust-service-images",
        "test-release-contracts",
    ):
        buildx = [
            step for step in JOBS[owner]["steps"]
            if step.get("uses", "").startswith("docker/setup-buildx-action@")
        ]
        assert len(buildx) == 1, owner
        assert buildx[0]["with"]["buildkitd-config"] == BUILDKIT_CONFIG


def test_host_mirror_is_installed_before_docker_use_without_killing_services() -> None:
    script = (ROOT / "scripts/ci/configure-dockerhub-mirror.sh").read_text(encoding="utf-8")
    assert "https://mirror.gcr.io" in script
    assert "sudo kill -HUP" in script
    assert "docker info --format" in script
    assert "systemctl restart" not in script
    for owner in (
        "test-ui-crawler-nginx",
        "test-passport-fence-postgres",
        "test-rust-passport-image",
        "test-rust-services",
        "test-rust-service-images",
        "rust-supply-chain",
    ):
        steps = JOBS[owner]["steps"]
        assert steps[0]["uses"].startswith("actions/checkout@"), owner
        assert steps[1]["run"] == MIRROR_SCRIPT, owner
        assert not steps[1].get("continue-on-error", False), owner


def test_pre_step_service_images_retain_their_exact_pinned_digests() -> None:
    services = JOBS["test-rust-services"]["services"]
    assert services["postgres"]["image"] == (
        "postgres:15-alpine@"
        "sha256:fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c"
    )
    assert services["redis"]["image"] == (
        "redis:7.4-alpine@"
        "sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
    )
    assert services["openbao"]["image"].startswith("quay.io/openbao/openbao@sha256:")


def test_release_oci_backend_keeps_containerd_and_adds_only_mirror() -> None:
    steps = JOBS["test-release-contracts"]["steps"]
    docker = next(step for step in steps if step.get("name") == "Configure the pinned containerd image store")
    config = json.loads(docker["with"]["daemon-config"])
    assert config == {
        "features": {"containerd-snapshotter": True},
        "registry-mirrors": ["https://mirror.gcr.io"],
    }
    assert not docker.get("continue-on-error", False)


def test_disposable_postgres_prefers_exact_cache_digest_with_canonical_fallback() -> None:
    script = (ROOT / "scripts/ci/pull-pinned-dockerhub-image.sh").read_text(
        encoding="utf-8"
    )
    assert 'docker pull "$mirror"' in script
    assert 'docker pull "$canonical"' in script
    assert script.index('docker pull "$mirror"') < script.index(
        'docker pull "$canonical"'
    )
    job = JOBS["test-passport-fence-postgres"]
    pull = next(
        step for step in job["steps"]
        if step.get("name") == "Pull the exact disposable PostgreSQL image with a safe registry fallback"
    )
    assert not pull.get("continue-on-error", False)
    assert (
        "postgres:15-alpine@sha256:"
        "fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c"
    ) in pull["run"]
    assert 'echo "BETA_FENCE_POSTGRES_IMAGE=$image" >> "$GITHUB_ENV"' in pull["run"]
    test_source = (ROOT / "tests/test_passport_beta_scoped_fence_postgres.py").read_text(
        encoding="utf-8"
    )
    assert "if POSTGRES_IMAGE not in {CANONICAL_POSTGRES_IMAGE, MIRRORED_POSTGRES_IMAGE}:" in test_source


@pytest.mark.skipif(os.name != "posix", reason="stub Docker requires POSIX executable PATH")
@pytest.mark.parametrize(
    ("mode", "expected_status", "expected_prefix"),
    [
        ("mirror", 0, "mirror.gcr.io/library/"),
        ("fallback", 0, ""),
        ("fail", 1, ""),
    ],
)
def test_pinned_pull_executes_safe_fallback(
    mode: str, expected_status: int, expected_prefix: str, tmp_path: Path
) -> None:
    canonical = (
        "postgres:15-alpine@sha256:"
        "fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c"
    )
    docker_stub = tmp_path / "docker"
    docker_stub.write_text("""#!/usr/bin/env bash
mock_docker() {
  if [[ "$DOCKER_TEST_MODE" == mirror ]]; then
    [[ "$2" == mirror.gcr.io/library/* ]]
  elif [[ "$DOCKER_TEST_MODE" == fallback ]]; then
    [[ "$2" != mirror.gcr.io/library/* ]]
  else
    return 1
  fi
}
mock_docker "$@"
""", encoding="utf-8")
    docker_stub.chmod(0o755)
    result = subprocess.run(
        ["bash", "scripts/ci/pull-pinned-dockerhub-image.sh", canonical],
        cwd=ROOT,
        env={
            **os.environ,
            "DOCKER_TEST_MODE": mode,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected_status, result.stderr
    assert result.stdout.strip() == (
        expected_prefix + canonical if expected_status == 0 else ""
    )


def test_pinned_pull_rejects_unpinned_input_before_docker() -> None:
    result = subprocess.run(
        ["bash", "scripts/ci/pull-pinned-dockerhub-image.sh", "postgres:latest"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "Expected one digest-pinned" in result.stderr
