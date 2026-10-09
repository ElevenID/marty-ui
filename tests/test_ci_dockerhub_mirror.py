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
BUILDKIT_PIN = (
    "moby/buildkit:buildx-stable-1@sha256:"
    "cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea"
)


def test_buildkit_uses_only_the_documented_docker_hub_cache() -> None:
    config = tomllib.loads((ROOT / BUILDKIT_CONFIG).read_text(encoding="utf-8"))
    assert config == {"registry": {"docker.io": {"mirrors": ["mirror.gcr.io"]}}}
    assert WORKFLOW["env"]["MARTY_CI_BUILDKIT_PIN"] == BUILDKIT_PIN
    for owner in (
        "test-openbao-didcomm-plugin",
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
        if owner != "test-release-contracts":
            assert buildx[0]["with"]["driver-opts"] == (
                "image=${{ env.MARTY_CI_BUILDKIT_IMAGE }}"
            )
            steps = JOBS[owner]["steps"]
            select = [
                (index, step) for index, step in enumerate(steps)
                if step.get("name") == "Select the exact BuildKit image with registry fallback"
            ]
            assert len(select) == 1, owner
            assert select[0][0] < steps.index(buildx[0])
            assert 'pull-pinned-dockerhub-image.sh "$MARTY_CI_BUILDKIT_PIN"' in select[0][1]["run"]
            assert 'echo "MARTY_CI_BUILDKIT_IMAGE=$image" >> "$GITHUB_ENV"' in select[0][1]["run"]


def test_host_mirror_is_installed_before_docker_use_without_killing_services() -> None:
    script = (ROOT / "scripts/ci/configure-dockerhub-mirror.sh").read_text(encoding="utf-8")
    assert "https://mirror.gcr.io" in script
    assert "sudo kill -HUP" in script
    assert "docker info --format" in script
    assert "systemctl restart" not in script
    for owner in (
        "test-ui-crawler-nginx",
        "test-openbao-didcomm-plugin",
        "test-rust-services",
        "test-rust-service-images",
    ):
        steps = JOBS[owner]["steps"]
        assert steps[0]["uses"].startswith("actions/checkout@"), owner
        assert steps[1]["run"] == MIRROR_SCRIPT, owner
        assert not steps[1].get("continue-on-error", False), owner


def test_rust_service_images_start_after_registry_setup_with_exact_digests() -> None:
    job = JOBS["test-rust-services"]
    assert "services" not in job
    assert "job.services." not in str(job)
    steps = job["steps"]
    mirror_index = next(i for i, step in enumerate(steps) if step.get("run") == MIRROR_SCRIPT)
    start_index = next(
        i for i, step in enumerate(steps)
        if step.get("name") == "Start digest-pinned Rust test services after registry setup"
    )
    assert mirror_index < start_index
    start = steps[start_index]["run"]
    assert "bash scripts/ci/pull-pinned-dockerhub-image.sh" in start
    assert "postgres:15-alpine@sha256:fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c" in start
    assert "redis:7.4-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99" in start
    assert "quay.io/openbao/openbao@sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878" in start
    assert 'echo "MARTY_RUST_CI_POSTGRES_ID=$postgres_id" >> "$GITHUB_ENV"' in start
    assert 'echo "MARTY_RUST_CI_REDIS_ID=$redis_id" >> "$GITHUB_ENV"' in start
    assert "test -n \"$postgres_id\"" in start
    assert "test -n \"$redis_id\"" in start


def test_release_oci_backend_keeps_containerd_and_adds_only_mirror() -> None:
    steps = JOBS["test-release-contracts"]["steps"]
    docker = next(step for step in steps if step.get("name") == "Configure the pinned containerd image store")
    config = json.loads(docker["with"]["daemon-config"])
    assert config == {
        "features": {"containerd-snapshotter": True},
        "registry-mirrors": ["https://mirror.gcr.io"],
    }
    assert not docker.get("continue-on-error", False)


def test_rust_fixtures_prefer_exact_cache_digest_with_canonical_fallback() -> None:
    script = (ROOT / "scripts/ci/pull-pinned-dockerhub-image.sh").read_text(
        encoding="utf-8"
    )
    assert 'docker pull "$mirror"' in script
    assert 'docker pull "$canonical"' in script
    assert script.index('docker pull "$mirror"') < script.index(
        'docker pull "$canonical"'
    )
    job = JOBS["test-rust-services"]
    pull = next(
        step for step in job["steps"]
        if step.get("name") == "Start digest-pinned Rust test services after registry setup"
    )
    assert not pull.get("continue-on-error", False)
    assert (
        "postgres:15-alpine@sha256:"
        "fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c"
    ) in pull["run"]
    assert "MARTY_RUST_CI_POSTGRES_IMAGE=$(bash scripts/ci/pull-pinned-dockerhub-image.sh" in pull["run"]
    assert "docker compose -p marty-rust-ci -f .github/compose/rust-ci-fixtures.yml" in pull["run"]
    fixtures = (ROOT / ".github/compose/rust-ci-fixtures.yml").read_text(
        encoding="utf-8"
    )
    assert "${MARTY_RUST_CI_POSTGRES_IMAGE:?exact PostgreSQL digest required}" in fixtures


@pytest.mark.skipif(os.name != "posix", reason="stub Docker requires POSIX executable PATH")
@pytest.mark.parametrize(
    ("canonical", "mirror_prefix"),
    [
        (
            "postgres:15-alpine@sha256:"
            "fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c",
            "mirror.gcr.io/library/",
        ),
        (
            "postgres@sha256:"
            "fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c",
            "mirror.gcr.io/library/",
        ),
        (BUILDKIT_PIN, "mirror.gcr.io/"),
    ],
)
@pytest.mark.parametrize(
    ("mode", "expected_status", "expect_mirror"),
    [
        ("local_canonical", 0, False),
        ("local_mirror", 0, True),
        ("mirror", 0, True),
        ("fallback", 0, False),
        ("fail", 1, False),
    ],
)
def test_pinned_pull_executes_safe_fallback(
    canonical: str, mirror_prefix: str, mode: str,
    expected_status: int, expect_mirror: bool, tmp_path: Path,
) -> None:
    docker_stub = tmp_path / "docker"
    docker_stub.write_text("""#!/usr/bin/env bash
mock_docker() {
  if [[ "$1" == image && "$2" == inspect ]]; then
    if [[ "$DOCKER_TEST_MODE" == local_canonical ]]; then
      [[ "$3" != mirror.gcr.io/library/* ]]
      return
    fi
    if [[ "$DOCKER_TEST_MODE" == local_mirror ]]; then
      [[ "$3" == mirror.gcr.io/* ]]
      return
    fi
    return 1
  fi
  if [[ "$DOCKER_TEST_MODE" == local_* ]]; then
    return 99
  fi
  if [[ "$DOCKER_TEST_MODE" == mirror ]]; then
    [[ "$2" == mirror.gcr.io/* ]]
  elif [[ "$DOCKER_TEST_MODE" == fallback ]]; then
    [[ "$2" != mirror.gcr.io/* ]]
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
        (mirror_prefix if expect_mirror else "") + canonical
        if expected_status == 0 else ""
    )


@pytest.mark.skipif(os.name != "posix", reason="Bash subprocess requires POSIX runner")
@pytest.mark.parametrize(
    "reference",
    ["postgres:latest", "moby/buildkit:buildx-stable-1@sha256:" + "0" * 64],
)
def test_pinned_pull_rejects_unpinned_input_before_docker(reference: str) -> None:
    result = subprocess.run(
        ["bash", "scripts/ci/pull-pinned-dockerhub-image.sh", reference],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "Expected one approved digest-pinned" in result.stderr


def test_image_smokes_use_the_same_pinned_cache_fallback() -> None:
    expected = {
        "scripts/smoke-issuance-image.sh": (
            "postgres:15-alpine@sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f",
        ),
        "scripts/smoke-verification-image.sh": (
            "postgres:15-alpine@sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f",
            "redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2",
        ),
    }
    for path, images in expected.items():
        source = (ROOT / path).read_text(encoding="utf-8")
        assert source.count("scripts/ci/pull-pinned-dockerhub-image.sh") == len(images)
        for image in images:
            assert image in source
        assert '"$postgres_image"' in source
        if len(images) == 2:
            assert '"$redis_image"' in source


def test_packaged_worker_startup_uses_the_exact_oracle_postgres_digest() -> None:
    source = (ROOT / "scripts/test_canvas_worker_image_startup.py").read_text(
        encoding="utf-8"
    )
    assert 'pins["observed_postgres_image"]' in source
    assert '"scripts/ci/pull-pinned-dockerhub-image.sh"' in source
    assert "selected_postgres" in source


def test_published_canvas_and_flow_acceptance_keep_frozen_digest_with_mirror() -> None:
    for path in (
        "scripts/ci/run-published-canvas-contracts.sh",
        "scripts/ci/run-flow-acceptance-contracts.sh",
    ):
        source = (ROOT / path).read_text(encoding="utf-8")
        assert "pull-pinned-dockerhub-image.sh" in source
        assert "MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE" in source
        assert "observed_postgres_image" in source
    flow = (ROOT / "scripts/ci/run-flow-acceptance-contracts.sh").read_text(
        encoding="utf-8"
    )
    assert "redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2" in flow
    assert 'docker tag "$redis_image" redis:7-alpine' in flow


def test_both_supply_chain_workflows_run_the_same_pinned_native_audit() -> None:
    script = (ROOT / "scripts/ci/run-cargo-deny.sh").read_text(encoding="utf-8")
    assert "version=0.20.2" in script
    assert "digest=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f" in script
    assert "sha256sum --check --status" in script
    assert "--manifest-path rust/Cargo.toml --all-features" in script
    assert "check advisories bans licenses sources" in script
    scheduled = yaml.safe_load(
        (ROOT / ".github/workflows/rust-security.yml").read_text(encoding="utf-8")
    )
    for job in (JOBS["rust-supply-chain"], scheduled["jobs"]["rust-supply-chain"]):
        assert not any(
            "cargo-deny-action" in step.get("uses", "") for step in job["steps"]
        )
        toolchain = next(
            step for step in job["steps"]
            if step.get("uses", "").startswith("dtolnay/rust-toolchain@")
        )
        assert toolchain["with"]["toolchain"] == "1.95.0"
        assert any(
            step.get("run") == "bash scripts/ci/run-cargo-deny.sh"
            for step in job["steps"]
        )


def test_organization_quality_uses_reviewed_cache_fallback_policy() -> None:
    quality = yaml.safe_load(
        (ROOT / ".github/workflows/organization-quality.yml").read_text(
            encoding="utf-8"
        )
    )["jobs"]["workflow-quality"]
    policy = "c6dd7de55112abb53284dd0254f3a5914301a3ed"
    assert quality["uses"] == (
        f"ElevenID/.github/.github/workflows/quality-workflows.yml@{policy}"
    )
    assert quality["with"] == {"policy-ref": policy}
