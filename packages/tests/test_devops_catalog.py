import re
from pathlib import Path

import yaml

from marty_devops import DeploymentCatalog


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_public_deployment_catalog_loads_without_commerce_metadata():
    catalog = DeploymentCatalog.load(REPO_ROOT)
    assert "oss-release" in catalog.artifacts
    assert "selfhost-production" in catalog.stacks
    assert "license_key" not in catalog.secrets
    assert catalog.redacted_stack_plan("selfhost-production")["artifact_profile"] == "oss-release"


def test_catalog_uses_repository_local_or_released_artifacts():
    catalog = DeploymentCatalog.load(REPO_ROOT)
    for service in catalog.services.values():
        context = str(service.get("context", ""))
        assert not context.startswith("..")
        assert not str(service.get("dockerfile", "")).startswith("marty-")


def test_selfhost_bundle_assets_exist():
    catalog = DeploymentCatalog.load(REPO_ROOT)
    assert all(asset.exists() for asset in catalog.bundle_assets("selfhost"))


def test_selfhost_secret_templates_cover_compose_references():
    compose = (REPO_ROOT / "docker-compose.selfhost.prod.yml").read_text(
        encoding="utf-8"
    )
    names = set(
        re.findall(
            r"(?m)^\s+file: \$\{SELFHOST_SECRET_DIR:\?[^}]+\}/([a-z0-9_]+)\s*$",
            compose,
        )
    )
    assert names
    template_dir = REPO_ROOT / "docker/secrets/selfhost.example"
    assert not names - {path.name for path in template_dir.iterdir() if path.is_file()}

    catalog = DeploymentCatalog.load(REPO_ROOT)
    required = set(catalog.stacks["selfhost-production"]["required_secrets"])
    assert required <= names
    for name in required:
        placeholder = (template_dir / name).read_text(encoding="utf-8").strip()
        assert placeholder.lower().replace("_", "-").startswith("change-me")


def test_dedicated_service_signing_credential_is_mounted_only_on_gateway_and_signing_keys():
    key = "SIGNING_KEYS_SERVICE_SIGN_GATEWAY_KEY"
    manifests = [
        REPO_ROOT / "k8s/oracle/07-microservices.yaml",
        REPO_ROOT / "k8s/oracle/07b-signing-keys.yaml",
    ]
    holders = set()
    for manifest in manifests:
        for resource in yaml.safe_load_all(manifest.read_text(encoding="utf-8")):
            if not isinstance(resource, dict) or resource.get("kind") != "Deployment":
                continue
            for container in resource["spec"]["template"]["spec"]["containers"]:
                if any(item.get("name") == key for item in container.get("env", [])):
                    holders.add(resource["metadata"]["name"])
    assert holders == {"gateway", "signing-keys"}


def test_issuer_signing_credential_is_only_on_signing_workloads():
    key = "SIGNING_KEYS_ISSUER_SIGN_KEY"
    holders = set()
    for name in ("07-microservices.yaml", "07a-issuance-native.yaml", "07b-signing-keys.yaml"):
        manifest = REPO_ROOT / "k8s/oracle" / name
        for resource in yaml.safe_load_all(manifest.read_text(encoding="utf-8")):
            if not isinstance(resource, dict) or resource.get("kind") != "Deployment":
                continue
            for container in resource["spec"]["template"]["spec"]["containers"]:
                if any(item.get("name") == key for item in container.get("env", [])):
                    holders.add(resource["metadata"]["name"])
    assert holders == {"gateway", "signing-keys", "issuance", "issuance-native", "canvas-sync-worker", "flow"}


def test_selfhost_example_declares_required_compose_settings():
    compose = (REPO_ROOT / "docker-compose.selfhost.prod.yml").read_text(
        encoding="utf-8"
    )
    required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", compose))
    assert required
    example = (REPO_ROOT / ".env.selfhost.production.example").read_text(
        encoding="utf-8"
    )
    declared = set(re.findall(r"(?m)^([A-Z0-9_]+)=", example))
    assert required <= declared

    org = re.search(r"(?m)^MARTY_ORG_ID=([^\s]+)$", example)
    callback = re.search(r"(?m)^FLOW_CALLBACK_DESTINATIONS=([^\s]+)$", example)
    auth_url = re.search(r"(?m)^\s+AUTH_SERVICE_INTERNAL_URL: (\S+)$", compose)
    assert org and callback and auth_url
    assert callback.group(1) == (
        f"{org.group(1)}|{auth_url.group(1)}"
        "/internal/v1/auth/credential-verified?nonce=__MARTY_TOKEN__"
    )
