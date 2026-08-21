from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_public_service_image_executes_only_the_native_verification_binary() -> None:
    dockerfile = text("services/Dockerfile")
    entrypoint = text("services/entrypoint.sh")
    assert "cargo build --locked --release -p marty-verification-service" in dockerfile
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
