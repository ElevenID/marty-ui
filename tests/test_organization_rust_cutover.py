from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def contract() -> dict[str, object]:
    return json.loads(text("contracts/organization-rust-cutover.json"))


def test_shared_service_image_builds_and_runs_native_organization() -> None:
    behavior = contract()
    binary = str(behavior["required_binary"])
    target = str(behavior["required_ci_target"])
    dockerfile = text("services/Dockerfile")
    entrypoint = text("services/entrypoint.sh")
    dedicated = text("rust/services/Dockerfile.ci")
    workflow = text(".github/workflows/ci.yml")
    assert (
        f"cargo build --locked --release -p marty-organization --bin {binary}"
        in dockerfile
    )
    assert f"/build/rust/target/release/{binary} /usr/local/bin/{binary}" in dockerfile
    assert 'if [ "$MODULE_NAME" = "organization" ]; then' in entrypoint
    assert f"exec /usr/local/bin/{binary}" in entrypoint
    assert f"FROM runtime AS {target}" in dedicated
    assert f"target: {target}" in workflow
    assert "tags: marty-organization:ci" in workflow
    assert "Smoke-test organization image with PostgreSQL and Redis" in workflow


def test_native_database_contracts_run_against_postgresql_in_ci() -> None:
    workflow = text(".github/workflows/ci.yml")
    for executable in (
        "organization-migration-contract",
        "organization-application-postgres-contract",
        "organization-repository-postgres-contract",
    ):
        assert f"target/debug/{executable}" in workflow
    assert "ORGANIZATION_POSTGRES_TEST_URL:" in workflow


def test_beta_enables_fail_closed_native_service_authentication() -> None:
    beta = yaml.safe_load(text("docker-compose.beta.yml"))
    environment = beta["services"]["organization"]["environment"]
    assert environment["ENVIRONMENT"] == "beta"
    assert environment["GRPC_SERVICE_TOKEN"].startswith("${GRPC_SERVICE_TOKEN:?")


def test_native_runtime_owns_operational_and_delivery_composition() -> None:
    main = text("rust/services/organization/src/main.rs")
    assert "OrganizationServiceConfig::from_env()" in main
    assert "OrganizationRuntime::new(&config)" in main
    assert "organization_core_router(http_state)" in main
    assert "OrganizationServiceServer::new(grpc_service)" in main
    assert "run_outbox_dispatcher(" in main
    assert "reconcile_organization_startup(" in main


def test_only_the_native_organization_runtime_remains() -> None:
    behavior = contract()
    assert (ROOT / str(behavior["runtime_owner"])).is_dir()
    assert (ROOT / str(behavior["migration_owner"])).is_file()
    assert (ROOT / str(behavior["surface_contract"])).is_file()
    assert not (ROOT / str(behavior["python_runtime_removed"])).exists()
    assert behavior["python_runtime_fallback"] is False


def test_python_migration_runner_does_not_import_deleted_organization() -> None:
    migration_runner = text("services/run_all_migrations.py")
    assert '"name": "organization"' not in migration_runner
    assert '"module": "organization.infrastructure.models"' not in migration_runner


def test_deleted_python_organization_cannot_reenter_ownership_inventory() -> None:
    ownership = json.loads(text("docs/rust-migration-ownership.json"))
    capability = next(
        item for item in ownership["capabilities"] if item["id"] == "organization-service"
    )

    assert capability["status"] == "native-active"
    assert capability["canonical"]["paths"] == ["rust/services/organization"]
    assert capability["legacy"] == []
