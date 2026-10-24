from __future__ import annotations

import re
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from packages.catalog_test_support import CatalogView


REPO_ROOT = Path(__file__).resolve().parents[1]
K8S_DIR = REPO_ROOT / "k8s" / "oracle"
MUTABLE_IMAGE_PATTERN = re.compile(
    r"image:\s+.*(?::latest|:-latest|:prod|:-prod|:main|:-main|:dev|:-dev)(?:\s|$|[}@])"
)
MUTABLE_TAG_ASSIGNMENT_PATTERN = re.compile(
    r"^(?:SELFHOST_IMAGE_TAG|IMAGE_TAG)=(?:latest|prod|main|dev)$",
    re.MULTILINE,
)
K8S_DEPLOYMENT_PATTERN = re.compile(
    r"^kind: Deployment\nmetadata:\n  name: (?P<name>[\w-]+)\n(?P<body>.*?)(?=^---|\Z)",
    re.MULTILINE | re.DOTALL,
)


def k8s_deployment_blocks(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    return {
        match.group("name"): match.group(0)
        for match in K8S_DEPLOYMENT_PATTERN.finditer(text)
    }


def test_kubernetes_manifests_do_not_use_mutable_image_tags():
    violations: list[str] = []
    for path in sorted(K8S_DIR.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        for pattern in (MUTABLE_IMAGE_PATTERN, MUTABLE_TAG_ASSIGNMENT_PATTERN):
            for match in pattern.finditer(text):
                line_no = text[: match.start()].count("\n") + 1
                violations.append(
                    f"{path.relative_to(REPO_ROOT)}:{line_no}: {match.group(0)}"
                )

    assert violations == []


def test_kubernetes_ui_uses_selfhost_image_variant():
    text = (K8S_DIR / "08-ui.yaml").read_text(encoding="utf-8")

    assert "${OCIR_REGISTRY}/marty-ui/ui-selfhost:${IMAGE_TAG}" in text
    assert "${OCIR_REGISTRY}/marty-ui/ui:${IMAGE_TAG}" not in text


def test_kubernetes_cloudflared_uses_release_wrapper_image():
    text = (K8S_DIR / "09-cloudflared.yaml").read_text(encoding="utf-8")

    assert "cloudflare/cloudflared:latest" not in text
    assert "${OCIR_REGISTRY}/marty-ui/cloudflared-wrapper:${IMAGE_TAG}" in text
    assert "imagePullSecrets:" in text


def test_kubernetes_app_deployments_have_no_commerce_license_gate():
    blocks = k8s_deployment_blocks(K8S_DIR / "07-microservices.yaml")

    assert blocks
    for name, block in blocks.items():
        assert "LICENSE_PUBLIC_KEY" not in block
        assert "LICENSE_KEY" not in block
        assert "envFrom:" in block, name
        assert "name: marty-config" in block, name


def test_kubernetes_update_script_updates_selfhost_image_variants():
    text = (REPO_ROOT / "scripts" / "deploy-kubernetes.sh").read_text(encoding="utf-8")

    assert "ui=${IMAGE_REGISTRY}/marty-ui/ui-selfhost:${IMAGE_TAG}" in text
    assert (
        "cloudflared=${IMAGE_REGISTRY}/marty-ui/cloudflared-wrapper:${IMAGE_TAG}"
        in text
    )
    assert 'services --group "$1" --field k8s_deployment' in text
    assert 'app_services="$(catalog_services app)"' in text
    assert 'done <<< "$app_services"' in text
    assert (
        'deployment/"${svc}" "${svc}=${IMAGE_REGISTRY}/marty-ui/${svc}:${IMAGE_TAG}"'
        in text
    )
    assert '[[ -z "$svc" || "$svc" == "issuance" ]] && continue' in text
    assert (
        "canvas-sync-worker=${IMAGE_REGISTRY}/marty-ui/issuance:${IMAGE_TAG}"
        not in text
    )
    assert "IMAGE_TAG=v1.1" not in text


@pytest.mark.parametrize("failure", ["exit", "empty"])
def test_registry_builder_rejects_catalog_failure_before_docker(tmp_path, failure):
    if os.name == "nt":
        git = shutil.which("git")
        assert git
        bash = str(Path(git).resolve().parents[1] / "bin/bash.exe")
    else:
        bash = shutil.which("bash")
    assert bash
    source_sha = subprocess.check_output(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], text=True,
    ).strip()
    binary = tmp_path / "marty-deploy"
    service_result = "exit 97" if failure == "exit" else "exit 0"
    binary.write_bytes(
        ("#!/bin/sh\n"
         "if [ \"$1\" = --build-identity ]; then\n"
         f"  printf '%s\\n' '{source_sha}:v1.1.246'\n"
         "elif [ \"$3\" = validate ]; then\n"
         "  printf 'catalog valid\\n'\n"
         "elif [ \"$3\" = services ]; then\n"
         f"  {service_result}\n"
         "else\n"
         "  exit 98\n"
         "fi\n").encode()
    )
    binary.chmod(0o755)
    release_version_double = tmp_path / "release-version-double"
    release_version_double.write_bytes(b"#!/bin/sh\nprintf 'v1.1.246\\n'\n")
    release_version_double.chmod(0o755)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_bytes(b'#!/bin/sh\nprintf "DOCKER:%s\\n" "$1" >> "$DOCKER_CALLS"\nexit 99\n')
    docker.chmod(0o755)
    calls = tmp_path / "docker-calls.log"
    env = {
        **os.environ,
        "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
        "PYTHON_BIN": str(release_version_double),
        "IMAGE_REGISTRY": "synthetic.invalid/owned",
        "MARTY_DEPLOY_BIN": str(binary),
        "MARTY_DEPLOY_BIN_SHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "MARTY_DEPLOY_SOURCE_SHA": source_sha,
        "MARTY_DEPLOY_RELEASE_TAG": "v1.1.246",
        "MARTY_API_CORE_VERSION": "0.1.0",
        "MARTY_API_CORE_URI": "synthetic-api-core.tgz",
        "MARTY_API_CORE_DIGEST": "sha256:" + "a" * 64,
        "MARTY_BLOG_VERSION": "0.1.0",
        "MARTY_BLOG_URI": "synthetic-blog.tgz",
        "MARTY_BLOG_DIGEST": "sha256:" + "b" * 64,
        "DOCKER_CALLS": str(calls),
    }
    env.pop("MARTY_UI_SHA", None)
    result = subprocess.run(
        [bash, str(REPO_ROOT / "scripts/build-push-registry.sh")],
        env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "Deployment catalog" in result.stdout + result.stderr
    assert not calls.exists()


def test_kubernetes_worker_uses_catalog_native_per_service_image():
    catalog = CatalogView.load(REPO_ROOT)
    worker = "canvas-sync-worker"
    assert worker in catalog.services_for_group("app")
    assert catalog.service_field(worker, "k8s_deployment") == worker
    assert catalog.service_field(worker, "image_name") == worker
    assert catalog.service_field(worker, "dockerfile") == "services/Dockerfile"
    assert catalog.service_field(worker, "service_name_env") == "canvas_sync_worker"
    block = k8s_deployment_blocks(K8S_DIR / "07-microservices.yaml")[worker]
    assert f"image: ${{OCIR_REGISTRY}}/marty-ui/{worker}:${{IMAGE_TAG}}" in block
    assert 'command: ["/usr/local/bin/marty-canvas-sync-worker"]' in block
    assert "image: ${MARTY_ISSUANCE_IMAGE}" not in block
    assert "/marty-ui/issuance:${IMAGE_TAG}" not in block


def test_kubernetes_rust_issuance_and_migration_keep_the_same_pin():
    api = k8s_deployment_blocks(K8S_DIR / "07-microservices.yaml")["issuance"]
    migration = (K8S_DIR / "06a-issuance-migrations.yaml").read_text(encoding="utf-8")
    for block in (api, migration):
        assert "image: ${MARTY_ISSUANCE_IMAGE}" in block
        assert "/marty-ui/issuance:${IMAGE_TAG}" not in block
        assert "/marty-ui/canvas-sync-worker:${IMAGE_TAG}" not in block
    catalog = CatalogView.load(REPO_ROOT)
    assert (
        catalog.service_field("issuance", "artifact_role")
        == "marty-ui-services"
    )
    assert (
        catalog.service_field("issuance-migrations", "artifact_role")
        == "marty-ui-services"
    )


def test_registry_build_script_publishes_selfhost_image_variants():
    text = (REPO_ROOT / "scripts" / "build-push-registry.sh").read_text(
        encoding="utf-8"
    )

    assert '"ui-selfhost"' in text
    assert "--build-arg UI_VARIANT=selfhost" in text
    assert '"cloudflared-wrapper"' in text


def test_ui_docker_builds_use_only_verified_public_release_dependencies():
    dockerfile = (REPO_ROOT / "docker" / "ui.Dockerfile").read_text(encoding="utf-8")
    registry_build_script = (
        REPO_ROOT / "scripts" / "build-push-registry.sh"
    ).read_text(encoding="utf-8")

    assert (
        "dependencies.@elevenid/marty-api-core=file:/tmp/marty-api-core.tgz"
        in dockerfile
    )
    assert "dependencies.@elevenid/marty-blog=file:/tmp/marty-blog.tgz" in dockerfile
    assert "MARTY_API_CORE_DIGEST#sha256:" in dockerfile
    assert "MARTY_BLOG_DIGEST#sha256:" in dockerfile
    assert "marty-subscriptions" not in dockerfile
    assert "COPY ../" not in dockerfile
    assert "--build-context" not in registry_build_script
    assert "MARTY_API_CORE_URI" in registry_build_script
    assert "MARTY_API_CORE_DIGEST" in registry_build_script
    assert "MARTY_BLOG_URI" in registry_build_script
    assert "MARTY_BLOG_DIGEST" in registry_build_script
    assert "marty-subscriptions" not in registry_build_script
