from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def contract() -> dict[str, object]:
    return json.loads(text("contracts/credential-template-rust-cutover.json"))


def test_shared_service_image_dispatches_credential_template_to_rust() -> None:
    behavior = contract()
    binary = str(behavior["required_binary"])
    dockerfile = text("services/Dockerfile")
    entrypoint = text("services/entrypoint.sh")
    assert (
        f"-p marty-credential-template --bin {binary}"
        in dockerfile
    )
    assert f"/build/rust/target/release/{binary} /usr/local/bin/{binary}" in dockerfile
    assert 'if [ "$MODULE_NAME" = "credential_template" ]' in entrypoint
    assert f"exec /usr/local/bin/{binary}" in entrypoint


def test_native_image_and_ci_target_preserve_both_service_ports() -> None:
    behavior = contract()
    target = str(behavior["required_ci_target"])
    dockerfile = text("rust/services/Dockerfile.ci")
    workflow = text(".github/workflows/ci.yml")
    assert f"FROM runtime AS {target}" in dockerfile
    assert "EXPOSE 8003 9003" in dockerfile
    assert f"target: {target}" in workflow
    assert "tags: marty-credential-template:ci" in workflow
    assert "Smoke-test credential-template image with PostgreSQL" in workflow


def test_native_migration_and_repository_contracts_run_against_postgresql_in_ci() -> None:
    workflow = text(".github/workflows/ci.yml")
    runtime = text("scripts/ci/run-rust-db-contracts.sh")
    assert "python3 ../scripts/ci/run-db-contract-groups.py" in workflow
    assert "export CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL=" in runtime
    assert "target/debug/credential-template-migration-contract --test-threads=1" in runtime
    assert 'contains("marty-credential-template")' in workflow


def test_compose_supplies_every_fail_closed_native_dependency() -> None:
    base = text("docker-compose.base.yml")
    beta = text("docker-compose.beta.yml")
    for setting in (
        "ORG_GRPC_TARGET: organization:9002",
        "RP_GRPC_TARGET: revocation-profile:9013",
        "TRUST_PROFILE_SERVICE_URL: http://trust-profile:8004",
        "SIGNING_KEYS_INTERNAL_URL: http://gateway:8000/internal/signing-keys",
        "PUBLIC_API_URL:",
        "MARTY_ORG_ID:",
    ):
        assert setting in base
    assert "credential-template:" in beta
    assert "ENVIRONMENT: beta" in beta
    assert "MARTY_MIGRATION_PROFILE: beta" in beta


def test_kubernetes_supplies_native_secrets_and_checks_readiness() -> None:
    deployment = text("k8s/oracle/07-microservices.yaml")
    credential_start = deployment.index("  name: credential-template")
    credential_end = deployment.index("# 5. Trust Profile", credential_start)
    credential = deployment[credential_start:credential_end]
    assert "key: GRPC_SERVICE_TOKEN" in credential
    assert "name: SIGNING_KEYS_INTERNAL_API_KEY" in credential
    assert "key: SIGNING_KEYS_INTERNAL_API_KEY" in credential
    assert "path: /health" in credential
    assert "path: /ready" in credential


def test_only_the_native_credential_template_runtime_remains() -> None:
    behavior = contract()
    assert (ROOT / str(behavior["runtime_owner"])).is_dir()
    assert (ROOT / str(behavior["migration_owner"])).is_file()
    assert (ROOT / str(behavior["surface_contract"])).is_file()
    assert (ROOT / str(behavior["migration_history_contract"])).is_file()
    assert not (ROOT / str(behavior["python_runtime_removed"])).exists()
    assert behavior["python_runtime_fallback"] is False


def test_python_migration_runner_does_not_import_deleted_credential_template() -> None:
    migration_runner = text("services/run_all_migrations.py")
    assert '"name": "credential_template"' not in migration_runner
    assert '"module": "credential_template.infrastructure.models"' not in migration_runner


def test_deleted_python_credential_template_cannot_reenter_ownership_inventory() -> None:
    ownership = json.loads(text("docs/rust-migration-ownership.json"))
    capability = next(
        item
        for item in ownership["capabilities"]
        if item["id"] == "credential-template-service"
    )

    assert capability["status"] == "native-active"
    assert capability["canonical"]["paths"] == ["rust/services/credential-template"]
    assert capability["legacy"] == []
