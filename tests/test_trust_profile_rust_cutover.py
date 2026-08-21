from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def contract() -> dict[str, object]:
    return json.loads(text("contracts/trust-profile-service-behavior.json"))


def test_only_the_native_trust_profile_runtime_remains() -> None:
    behavior = contract()
    runtime_owner = ROOT / str(behavior["runtime_owner"])
    python_runtime = ROOT / str(behavior["python_runtime_removed"])
    entrypoint = text("services/entrypoint.sh")

    assert runtime_owner.is_dir()
    assert not python_runtime.exists()
    assert 'if [ "$MODULE_NAME" = "trust_profile" ]; then' in entrypoint
    assert "exec /usr/local/bin/marty-trust-profile" in entrypoint


def test_rust_owns_schema_history_and_postgresql_acceptance() -> None:
    behavior = contract()
    migration_runner = text("services/run_all_migrations.py")
    workflow = text(".github/workflows/ci.yml")

    assert (ROOT / str(behavior["migration_owner"])).is_file()
    assert '"name": "trust_profile"' not in migration_runner
    assert '"trust_profile_service"' not in migration_runner
    assert "TEST_POSTGRES_URL:" in workflow
    assert "trust_profile_contracts" in workflow


def test_native_service_has_shared_and_dedicated_image_paths() -> None:
    shared = text("services/Dockerfile")
    native = text("rust/services/Dockerfile.ci")
    workflow = text(".github/workflows/ci.yml")

    assert (
        "cargo build --locked --release -p marty-trust-profile "
        "--bin marty-trust-profile"
    ) in shared
    assert (
        "/build/rust/target/release/marty-trust-profile "
        "/usr/local/bin/marty-trust-profile"
    ) in shared
    assert "FROM runtime AS trust_profile" in native
    assert "target: trust_profile" in workflow
    assert "tags: marty-trust-profile:ci" in workflow


def test_deployed_manifests_supply_fail_closed_native_configuration() -> None:
    base = text("docker-compose.base.yml")
    beta = text("docker-compose.beta.yml")
    selfhost = text("docker-compose.selfhost.prod.yml")
    kubernetes = text("k8s/oracle/07-microservices.yaml")

    base_service = base.split("\n  trust-profile:\n", 1)[1].split(
        "\n  applicant:\n", 1
    )[0]
    beta_service = beta.split("\n  trust-profile:\n", 1)[1].split(
        "\n  applicant:\n", 1
    )[0]
    selfhost_service = selfhost.split("\n  trust-profile:\n", 1)[1].split(
        "\n  issuance:\n", 1
    )[0]
    kubernetes_service = kubernetes.split("# 5. Trust Profile", 1)[1].split(
        "# 6. Issuance", 1
    )[0]

    for setting in (
        "ORG_GRPC_TARGET: organization:9002",
        "SIGNING_KEYS_INTERNAL_API_KEY:",
        "MARTY_ORG_ID:",
        "MARTY_ISSUER_DID:",
        "PUBLIC_API_URL:",
    ):
        assert setting in base_service
    assert "ENVIRONMENT: beta" in beta_service
    assert "*beta-grpc-service-auth" in beta_service
    assert "must be set for beta" in beta_service
    assert "SIGNING_KEYS_INTERNAL_API_KEY_FILE" in selfhost_service
    assert "BAO_TOKEN" not in selfhost_service
    assert "name: SIGNING_KEYS_INTERNAL_API_KEY" in kubernetes_service
    assert "key: SIGNING_KEYS_INTERNAL_API_KEY" in kubernetes_service


def test_deleted_python_service_cannot_reenter_ownership_inventory() -> None:
    ownership = text("docs/rust-migration-ownership.json")

    assert "services/trust_profile" not in ownership
    assert '"id": "trust-profile-service"' in ownership
    assert '"paths": ["rust/services/trust-profile"]' in ownership
