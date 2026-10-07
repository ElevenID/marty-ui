import re
from pathlib import Path

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
        assert (template_dir / name).read_text(encoding="utf-8").strip().startswith(
            "change-me"
        )


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
