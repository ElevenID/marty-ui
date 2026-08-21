from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_shared_service_image_builds_and_runs_native_organization() -> None:
    dockerfile = text("services/Dockerfile")
    entrypoint = text("services/entrypoint.sh")
    assert (
        "cargo build --locked --release -p marty-organization --bin marty-organization"
        in dockerfile
    )
    assert (
        "/build/rust/target/release/marty-organization "
        "/usr/local/bin/marty-organization"
    ) in dockerfile
    assert 'if [ "$MODULE_NAME" = "organization" ]; then' in entrypoint
    assert "exec /usr/local/bin/marty-organization" in entrypoint


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


def test_python_service_is_retained_until_packaging_and_live_acceptance_pass() -> None:
    # This assertion is deliberately inverted in the deletion commit. It keeps
    # the cutover atomic: packaging and executable acceptance must pass before
    # the superseded tree is removed.
    assert (ROOT / "services/organization/main.py").is_file()
