from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_only_the_native_flow_runtime_remains() -> None:
    contract = json.loads(text("contracts/flow-rust-cutover-behavior.json"))
    entrypoint = text("services/entrypoint.sh")

    assert contract["schema_version"] == 1
    assert contract["runtime_owner"] == "rust/services/flow"
    assert not list((ROOT / contract["python_runtime_removed"]).rglob("*.py"))
    assert not list((ROOT / contract["removed_python_contract_image"]).rglob("*"))
    assert not (ROOT / "docker-compose.flow-idempotency-contract.yml").exists()
    assert 'if [ "$MODULE_NAME" = "flow" ]; then' in entrypoint
    assert "exec /usr/local/bin/marty-flow" in entrypoint


def test_rust_owns_flow_schema_and_postgresql_behavior() -> None:
    contract = json.loads(text("contracts/flow-rust-cutover-behavior.json"))
    migration_runner = text("services/run_all_migrations.py")
    workflow = text(".github/workflows/ci.yml")

    assert (ROOT / contract["migration_owner"]).is_dir()
    assert '"name": "flow"' not in migration_runner
    assert '"flow_service"' not in migration_runner
    assert "flow-idempotency-contract:" not in workflow
    assert "docker-compose.flow-idempotency-contract.yml" not in workflow
    assert "target/debug/flow-postgres-contract --test-threads=1" in workflow


def test_compose_preserves_development_and_beta_features() -> None:
    contract = json.loads(text("contracts/flow-rust-cutover-behavior.json"))
    base = text("docker-compose.base.yml")
    beta = text("docker-compose.beta.yml")
    flow_base = base.split("\n  flow:\n", maxsplit=1)[1].split(
        "\n  issuance:\n", maxsplit=1
    )[0]
    flow_beta = beta.split("\n  flow:\n", maxsplit=1)[1].split(
        "\n  revocation-profile:\n", maxsplit=1
    )[0]

    assert f'ENVIRONMENT: {contract["development_environment"]}' in flow_base
    assert f'ENVIRONMENT: {contract["deployed_environment"]}' in flow_beta
    assert 'GRPC_INSECURE_ALLOWED: "true"' in flow_beta
    assert "FLOW_WEBHOOK_SECRET must be set for beta" in flow_beta
    assert "FLOW_APPLICATION_EVENT_HMAC_KEY must be set for beta" in flow_beta
    assert "flow_workload_client_cert" in flow_beta
    assert "flow_workload_server_cert" in flow_beta
    assert "auth_workload_client_cert" in beta
    assert "applicant_workload_client_cert" in beta
    assert "pp_workload_server_cert" in beta
    assert "SIGNING_KEYS_INTERNAL_URL: http://signing-keys:8017/internal" in flow_base

    selfhost = text("docker-compose.selfhost.prod.yml")
    flow_selfhost = selfhost.split("\n  flow:\n", maxsplit=1)[1].split(
        "\n  verification:\n", maxsplit=1
    )[0]
    assert "SIGNING_KEYS_INTERNAL_URL: http://signing-keys:8017/internal" in flow_selfhost


def test_deleted_python_flow_cannot_reenter_ownership_inventory() -> None:
    ownership = text("docs/rust-migration-ownership.json")
    assert "services/flow" not in ownership
