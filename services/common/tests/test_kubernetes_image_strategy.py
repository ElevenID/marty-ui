from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
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
                violations.append(f"{path.relative_to(REPO_ROOT)}:{line_no}: {match.group(0)}")

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
    assert "cloudflared=${IMAGE_REGISTRY}/marty-ui/cloudflared-wrapper:${IMAGE_TAG}" in text
    assert "canvas-sync-worker=${IMAGE_REGISTRY}/marty-ui/issuance:${IMAGE_TAG}" in text
    assert "IMAGE_TAG=v1.1" not in text


def test_registry_build_script_publishes_selfhost_image_variants():
    text = (REPO_ROOT / "scripts" / "build-push-registry.sh").read_text(encoding="utf-8")

    assert '"ui-selfhost"' in text
    assert "--build-arg UI_VARIANT=selfhost" in text
    assert '"cloudflared-wrapper"' in text


def test_ui_docker_builds_include_only_public_source_dependency_contexts():
    dockerfile = (REPO_ROOT / "docker" / "ui.Dockerfile").read_text(encoding="utf-8")
    registry_build_script = (REPO_ROOT / "scripts" / "build-push-registry.sh").read_text(encoding="utf-8")

    assert 'dependencies.@elevenid/marty-api-core=$MARTY_API_CORE_VERSION' in dockerfile
    assert 'dependencies.@elevenid/marty-blog=$MARTY_BLOG_VERSION' in dockerfile
    assert "marty-subscriptions" not in dockerfile
    assert "COPY ../" not in dockerfile
    assert "--build-context" not in registry_build_script
    assert "marty-subscriptions" not in registry_build_script
