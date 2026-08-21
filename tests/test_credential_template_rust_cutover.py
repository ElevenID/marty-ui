from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_shared_service_image_dispatches_credential_template_to_rust() -> None:
    dockerfile = text("services/Dockerfile")
    entrypoint = text("services/entrypoint.sh")
    assert (
        "cargo build --locked --release -p marty-credential-template --bin marty-credential-template"
        in dockerfile
    )
    assert (
        "/build/rust/target/release/marty-credential-template "
        "/usr/local/bin/marty-credential-template"
    ) in dockerfile
    assert 'if [ "$MODULE_NAME" = "credential_template" ]' in entrypoint
    assert "exec /usr/local/bin/marty-credential-template" in entrypoint


def test_native_image_and_ci_target_preserve_both_service_ports() -> None:
    dockerfile = text("rust/services/Dockerfile.ci")
    workflow = text(".github/workflows/ci.yml")
    assert "FROM runtime AS credential_template" in dockerfile
    assert "EXPOSE 8003 9003" in dockerfile
    assert "target: credential_template" in workflow
    assert "tags: marty-credential-template:ci" in workflow


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
