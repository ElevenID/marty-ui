from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_public_service_image_executes_only_the_native_verification_binary() -> None:
    dockerfile = text("services/Dockerfile")
    entrypoint = text("services/entrypoint.sh")
    assert "-p marty-verification-service --bin marty-verification-service" in dockerfile
    assert "/target/release/marty-verification-service /usr/local/bin/marty-verification-service" in dockerfile
    assert 'if [ "$MODULE_NAME" = "verification" ]; then' in entrypoint
    assert "exec /usr/local/bin/marty-verification-service" in entrypoint


def test_dedicated_native_image_compose_target_and_ci_gate_are_present() -> None:
    dockerfile = text("rust/services/Dockerfile.ci")
    compose = text("docker-compose.base.yml")
    workflow = text(".github/workflows/ci.yml")
    assert "FROM runtime AS verification" in dockerfile
    assert "target: verification" in compose
    assert "target: verification" in workflow
    assert "tags: marty-verification-service:ci" in workflow


def test_native_images_forward_the_same_migration_command_to_the_binary() -> None:
    entrypoint = text("services/entrypoint.sh")
    dedicated = text("rust/services/Dockerfile.ci")
    ghcr = text("docker-compose.profile.ghcr.yml")
    assert 'exec /usr/local/bin/marty-verification-service "$@"' in entrypoint
    assert '\\"$@\\"' in dedicated
    assert 'entrypoint: ["/app/services/entrypoint.sh"]' in ghcr


def test_beta_uses_the_same_native_image_for_schema_and_compatibility_runtime() -> None:
    base = text("docker-compose.base.yml")
    beta = text("docker-compose.beta.yml")
    workflow = text(".github/workflows/ci.yml")
    assert "verification-migrations:" in base
    assert 'command: ["migrate"]' in base
    assert "verification-migrations:\n        condition: service_completed_successfully" in base
    assert 'VERIFICATION_CREDENTIALS_COMPAT_ENABLED: "true"' in beta
    assert "VERIFICATION_GOVERNANCE_JSON must be set for beta" in beta
    assert "VERIFICATION_GOVERNANCE_JSON: '{\"ci_compose_render_only\":true}'" in workflow


def test_ci_smokes_migration_start_readiness_and_a_real_operation_from_one_image() -> None:
    workflow = text(".github/workflows/ci.yml")
    release = text(".github/workflows/cd.yml")
    smoke = text("scripts/smoke-verification-image.sh")
    assert "Smoke-test verification migration and compatibility runtime from one image" in workflow
    assert (
        "bash scripts/smoke-verification-image.sh marty-verification-service:ci dedicated"
        in workflow
    )
    assert "Smoke-test the published shared services verification artifact" in release
    assert '"${{ env.SERVICES_IMAGE }}@${{ steps.services.outputs.digest }}"' in release
    assert "scripts/smoke-verification-image.sh" in release
    assert "shared" in release
    assert "--entrypoint /app/services/entrypoint.sh" in smoke
    assert "--env SERVICE_NAME=verification" in smoke
    assert 'for _ in 1 2; do' in smoke
    assert '"$image" migrate' in smoke
    assert "202608091200" in smoke
    assert 'http://127.0.0.1:${port}/ready' in smoke
    assert 'http://127.0.0.1:${port}/health' in smoke
    assert 'http://127.0.0.1:${port}/v1/verification/health' in smoke
    assert 'http://127.0.0.1:${port}/v1/verification/sessions' in smoke
    assert "purpose-scoped-test-key" in smoke
    assert 'v1/verification/sessions/${session_id}/submit' in smoke
    assert '.canonical_result.verification_id == ("verification:" + $session_id)' in smoke
    assert '.canonical_result.context.transaction_id == ("transaction:" + $session_id)' in smoke
    assert '.status == "failed" and .nonce == ""' in smoke


def test_only_native_verification_runtime_sources_remain() -> None:
    service = ROOT / "services" / "verification"
    assert not list(service.rglob("*.py"))
    manifest = json.loads(text("docs/rust-migration-ownership.json"))
    capability = next(
        value for value in manifest["capabilities"] if value["id"] == "verification-service"
    )
    assert capability["status"] == "native-active"
    assert capability["legacy"] == []
    guard = next(
        value
        for value in manifest["guardrails"]["native_service_guards"]
        if value["capability_id"] == "verification-service"
    )
    assert guard["forbidden_globs"] == ["services/verification/**/*.py"]


def test_behavior_contract_and_native_crate_are_owned() -> None:
    contract = json.loads(text("contracts/verification-service-behavior.json"))
    assert contract["service"] == "verification"
    assert len(contract["routes"]) == 8
    manifest = text("rust/services/verification/Cargo.toml")
    assert 'name = "marty-verification-service"' in manifest
    workspace = text("rust/Cargo.toml")
    assert '"services/verification"' in workspace
