from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_public_service_image_executes_only_the_native_device_binary() -> None:
    dockerfile = text("services/Dockerfile")
    entrypoint = text("services/entrypoint.sh")
    assert "cargo build --locked --release -p marty-device-registration --bin marty-device-registration" in dockerfile
    assert "/build/rust/target/release/marty-device-registration /usr/local/bin/marty-device-registration" in dockerfile
    assert 'if [ "$MODULE_NAME" = "device_registration" ]; then' in entrypoint
    assert "exec /usr/local/bin/marty-device-registration" in entrypoint


def test_dedicated_native_image_compose_target_and_ci_gate_are_present() -> None:
    dockerfile = text("rust/services/Dockerfile.ci")
    compose = text("docker-compose.base.yml")
    workflow = text(".github/workflows/ci.yml")
    assert "FROM runtime AS device_registration" in dockerfile
    assert "target: device_registration" in compose
    assert "target: device_registration" in workflow
    assert "tags: marty-device-registration:ci" in workflow


def test_only_native_device_registration_runtime_sources_remain() -> None:
    service = ROOT / "services" / "device_registration"
    assert not list(service.rglob("*.py"))
    manifest = json.loads(text("docs/rust-migration-ownership.json"))
    capability = next(value for value in manifest["capabilities"] if value["id"] == "device-registration-service")
    assert capability["status"] == "native-active"
    assert capability["legacy"] == []
    guard = next(value for value in manifest["guardrails"]["native_service_guards"] if value["capability_id"] == "device-registration-service")
    assert guard["forbidden_globs"] == ["services/device_registration/**/*.py"]


def test_behavior_contract_and_native_crate_are_owned() -> None:
    contract = json.loads(text("contracts/device-registration-service-behavior.json"))
    assert contract["service"] == "device-registration"
    assert len(contract["routes"]) == 6
    manifest = text("rust/services/device-registration/Cargo.toml")
    assert 'name = "marty-device-registration"' in manifest
    workspace = text("rust/Cargo.toml")
    assert '"services/device-registration"' in workspace


def test_beta_runtime_uses_authenticated_dedicated_redis_database() -> None:
    compose = text("docker-compose.beta.yml")
    device = compose.split("  device-registration:\n", 1)[1].split("\n  event-stream:\n", 1)[0]
    assert "ENVIRONMENT: beta" in device
    assert (
        "REDIS_URL: redis://:${REDIS_PASSWORD:?REDIS_PASSWORD must be set for beta}@redis:6379/5"
        in device
    )
