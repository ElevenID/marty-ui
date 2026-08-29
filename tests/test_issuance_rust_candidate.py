from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_frozen_surface_provenance_and_coverage_are_complete() -> None:
    surface_bytes = (ROOT / "contracts/issuance-runtime-surface.json").read_bytes()
    surface = json.loads(surface_bytes)
    coverage = json.loads(text("contracts/issuance-native-coverage.json"))
    discovery_bytes = (ROOT / "contracts/issuance-static-discovery.json").read_bytes()
    discovery = json.loads(discovery_bytes)
    assert surface["schema"] == "marty.issuance-runtime-surface/v1"
    assert surface["http"]["route_count"] == len(surface["http"]["routes"]) == 131
    assert surface["grpc"]["method_count"] == len(surface["grpc"]["methods"]) == 12
    canonical_surface = surface_bytes.replace(b"\r\n", b"\n")
    assert (
        hashlib.sha256(canonical_surface).hexdigest()
        == coverage["upstream"]["sha256"]
    )
    assert coverage["upstream"]["commit"] == "578e86ef43166be79add2d812e92ef650535edaa"
    assert hashlib.sha256(discovery_bytes.replace(b"\r\n", b"\n")).hexdigest() == (
        coverage["behavior_contract"]["sha256"]
    )
    assert (
        coverage["behavior_contract"]["commit"]
        == "5b210bde2bee4360a9504e4c360250b54f48f5ba"
    )
    assert discovery["schema"] == "marty.issuance-static-discovery/v1"
    native = {operation["operation"]: operation for operation in coverage["native_http"]}
    assert native.pop("health_check") == {
        "method": "GET",
        "path": "/health",
        "operation": "health_check",
        "response": {
            "status_code": 200,
            "body": {"status": "healthy", "service": "issuance-service"},
        },
    }
    discovery_cases = {case["operation"]: case for case in discovery["cases"]}
    assert set(native) == set(discovery_cases)
    for operation, coverage_entry in native.items():
        assert coverage_entry["method"] == discovery_cases[operation]["method"] == "GET"
        assert coverage_entry["behavior_case"] == operation
        expected_case_path = coverage_entry["path"].replace(
            "{credential_type:path}", "access_badge"
        ).replace("{org_id}", "org-a")
        assert discovery_cases[operation]["path"] == expected_case_path
    assert coverage["remaining"] == {
        "http": 124,
        "grpc": 12,
        "runtime_modes": ["api", "canvas-sync-worker"],
        "literal_environment_variables": 85,
        "dynamic_configuration_lookups": 20,
        "migration_revisions": 44,
        "migration_heads": 1,
    }
    assert coverage["native_environment_variables"] == [
        "CORS_ALLOWED_ORIGINS",
        "ISSUANCE_SERVICE_PORT",
        "ISSUER_BASE_URL",
        "ISSUER_DISPLAY_NAME",
    ]


def test_candidate_is_owned_but_cannot_replace_the_python_runtime() -> None:
    ownership = json.loads(text("docs/rust-migration-ownership.json"))
    capability = next(
        value
        for value in ownership["capabilities"]
        if value["id"] == "issuance-service"
    )
    assert capability["status"] == "cutover-in-progress"
    assert capability["canonical"]["paths"] == ["rust/services/issuance"]
    assert capability["legacy"][0]["repository"] == "ElevenID/marty-credentials"

    workspace = text("rust/Cargo.toml")
    dockerfile = text("services/Dockerfile")
    entrypoint = text("services/entrypoint.sh")
    compose = text("docker-compose.base.yml")
    assert '"services/issuance"' in workspace
    assert "marty-issuance-service" not in dockerfile
    assert "marty-issuance-service" not in entrypoint
    assert "MARTY_ISSUANCE_IMAGE" in compose
