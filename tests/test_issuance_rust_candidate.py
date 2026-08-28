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
    assert surface["schema"] == "marty.issuance-runtime-surface/v1"
    assert surface["http"]["route_count"] == len(surface["http"]["routes"]) == 131
    assert surface["grpc"]["method_count"] == len(surface["grpc"]["methods"]) == 12
    canonical_surface = surface_bytes.replace(b"\r\n", b"\n")
    assert (
        hashlib.sha256(canonical_surface).hexdigest()
        == coverage["upstream"]["sha256"]
    )
    assert coverage["upstream"]["commit"] == "578e86ef43166be79add2d812e92ef650535edaa"
    assert coverage["native_http"] == [
        {
            "method": "GET",
            "path": "/health",
            "operation": "health_check",
            "response": {
                "status_code": 200,
                "body": {"status": "healthy", "service": "issuance-service"},
            },
        }
    ]
    assert coverage["remaining"] == {
        "http": 130,
        "grpc": 12,
        "runtime_modes": ["api", "canvas-sync-worker"],
        "literal_environment_variables": 88,
        "dynamic_configuration_lookups": 20,
        "migration_revisions": 44,
        "migration_heads": 1,
    }
    assert coverage["native_environment_variables"] == ["ISSUANCE_SERVICE_PORT"]


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
