"""Production deployment must use a fully governed runtime definition."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_unsafe_layered_production_profile_remains_retired() -> None:
    assert not (ROOT / "docker-compose.profile.prod.yml").exists()


def test_catalog_names_only_governed_production_entrypoints() -> None:
    deployment_guide = (ROOT / "deploy-config" / "README.md").read_text(
        encoding="utf-8"
    )

    assert (
        "Selfhost production compose: docker-compose.selfhost.prod.yml"
        in deployment_guide
    )
    assert (
        "Kubernetes deployment script: scripts/deploy-kubernetes.sh" in deployment_guide
    )
    assert (
        "Do not layer the development-oriented `docker-compose.base.yml`"
        in deployment_guide
    )


def test_production_environment_template_requires_internal_service_auth() -> None:
    environment_template = (ROOT / ".env.production.example").read_text(
        encoding="utf-8"
    )

    assert "GRPC_SERVICE_TOKEN=" in environment_template
    assert "at least 32 random characters" in environment_template
