import json
import re
import subprocess
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]


def _catalog() -> tuple[dict, dict, dict, dict]:
    config = REPO_ROOT / "deploy-config"
    services = json.loads((config / "catalog/services.json").read_text(encoding="utf-8"))["services"]
    secrets = json.loads((config / "catalog/secrets.json").read_text(encoding="utf-8"))["secrets"]
    artifacts = json.loads((config / "catalog/artifacts.json").read_text(encoding="utf-8"))["artifacts"]
    stacks = {payload["name"]: payload for path in (config / "stacks").glob("*.json") if (payload := json.loads(path.read_text(encoding="utf-8")))}
    return services, secrets, artifacts, stacks


def _rust_catalog(*args: str) -> str:
    return subprocess.run(
        ["cargo", "+1.95.0", "run", "--quiet", "--locked", "--manifest-path", str(REPO_ROOT / "rust/Cargo.toml"),
         "-p", "marty-deployment-catalog", "--bin", "marty-deploy", "--", "--repo-root", str(REPO_ROOT), *args],
        check=True, capture_output=True, text=True, cwd=REPO_ROOT,
    ).stdout


def test_public_deployment_catalog_loads_without_commerce_metadata():
    _services, secrets, artifacts, stacks = _catalog()
    assert "Deployment catalog validation passed." in _rust_catalog("validate")
    assert "oss-release" in artifacts
    assert "selfhost-production" in stacks
    assert "license_key" not in secrets
    assert json.loads(_rust_catalog("plan", "selfhost-production", "--json"))["artifact_profile"] == "oss-release"


def test_catalog_uses_repository_local_or_released_artifacts():
    services, _secrets, _artifacts, _stacks = _catalog()
    for service in services.values():
        context = str(service.get("context", ""))
        assert not context.startswith("..")
        assert not str(service.get("dockerfile", "")).startswith("marty-")


def test_selfhost_bundle_assets_exist():
    assert all(Path(asset).exists() for asset in _rust_catalog("bundle-assets", "selfhost").splitlines())


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

    _services, _secrets, _artifacts, stacks = _catalog()
    required = set(stacks["selfhost-production"]["required_secrets"])
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
