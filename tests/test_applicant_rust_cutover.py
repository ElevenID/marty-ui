from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_public_service_image_executes_only_the_native_applicant_binary() -> None:
    dockerfile = text("services/Dockerfile")
    entrypoint = text("services/entrypoint.sh")
    assert "cargo build --locked --release -p marty-applicant --bin marty-applicant" in dockerfile
    assert "/build/rust/target/release/marty-applicant /usr/local/bin/marty-applicant" in dockerfile
    assert 'if [ "$MODULE_NAME" = "applicant" ]; then' in entrypoint
    assert "exec /usr/local/bin/marty-applicant" in entrypoint
    assert "applicant.migrate_store_v03" not in entrypoint


def test_dedicated_native_image_and_ci_gate_are_present() -> None:
    dockerfile = text("rust/services/Dockerfile.ci")
    workflow = text(".github/workflows/ci.yml")
    assert "FROM runtime AS applicant" in dockerfile
    assert "target: applicant" in workflow
    assert "tags: marty-applicant:ci" in workflow


def test_only_native_applicant_runtime_sources_remain() -> None:
    service = ROOT / "services" / "applicant"
    assert not list(service.rglob("*.py"))
    manifest = json.loads(text("docs/rust-migration-ownership.json"))
    capability = next(
        value for value in manifest["capabilities"] if value["id"] == "applicant-service"
    )
    assert capability["status"] == "native-active"
    assert capability["legacy"] == []
    guard = next(
        value
        for value in manifest["guardrails"]["native_service_guards"]
        if value["capability_id"] == "applicant-service"
    )
    assert guard["forbidden_globs"] == ["services/applicant/**/*.py"]
