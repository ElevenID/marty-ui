from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def text(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_python_revocation_service_is_removed() -> None:
    assert not (REPO_ROOT / "services" / "revocation_profile").exists()
    assert not (
        REPO_ROOT
        / "deploy-config"
        / "compose"
        / "tunnel-beta"
        / "revocation-profile-rust.yml"
    ).exists()
    assert '"name": "revocation_profile"' not in text("services/run_all_migrations.py")


def test_shared_service_image_dispatches_revocation_to_rust() -> None:
    dockerfile = text("services/Dockerfile")
    entrypoint = text("services/entrypoint.sh")

    assert "cargo build --locked --release -p marty-revocation-profile" in dockerfile
    assert "target/release/marty-revocation-profile" in dockerfile
    assert 'if [ "$MODULE_NAME" = "revocation_profile" ]; then' in entrypoint
    assert "exec /usr/local/bin/marty-revocation-profile" in entrypoint


def test_compose_runs_rust_migration_before_shared_migrations() -> None:
    for compose_path in (
        "docker-compose.base.yml",
        "docker-compose.selfhost.prod.yml",
    ):
        compose = text(compose_path)
        assert "revocation-profile-migrate:" in compose
        assert 'RP_MIGRATE_ONLY: "true"' in compose
        assert "revocation-profile-migrate:\n        condition: service_completed_successfully" in compose

    assert "revocation-profile-migrate:" in text("docker-compose.profile.ghcr.yml")
    assert "revocation-profile-migrate:" in text(
        "docker-compose.selfhost.bundle.override.yml"
    )


def test_kubernetes_runs_rust_migration_before_shared_job() -> None:
    migration = next(
        yaml.safe_load_all(
            text("k8s/oracle/05b-revocation-profile-migrations.yaml")
        )
    )
    container = migration["spec"]["template"]["spec"]["containers"][0]
    environment = {item["name"]: item for item in container["env"]}

    assert migration["kind"] == "Job"
    assert migration["metadata"]["name"] == "revocation-profile-migrations"
    assert container["image"].endswith("/marty-ui/revocation-profile:${IMAGE_TAG}")
    assert environment["RP_MIGRATE_ONLY"]["value"] == "true"
    assert environment["DATABASE_URL"]["valueFrom"]["secretKeyRef"]["key"] == (
        "DATABASE_SYNC_URL"
    )

    deploy = text("scripts/deploy-kubernetes.sh")
    rust_position = deploy.index("05b-revocation-profile-migrations.yaml")
    shared_position = deploy.index("06-db-migrate.yaml")
    assert rust_position < shared_position
    assert "kubectl wait --for=condition=complete job/revocation-profile-migrations" in deploy
