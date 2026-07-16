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
