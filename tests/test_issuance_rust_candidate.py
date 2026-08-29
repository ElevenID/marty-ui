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
    tenant_bytes = (ROOT / "contracts/issuance-tenant-discovery.json").read_bytes()
    tenant = json.loads(tenant_bytes)
    transaction_bytes = (
        ROOT / "contracts/issuance-offer-transaction-reads.json"
    ).read_bytes()
    transaction_reads = json.loads(transaction_bytes)
    token_exchange_bytes = (
        ROOT / "contracts/issuance-token-exchange.json"
    ).read_bytes()
    token_exchange = json.loads(token_exchange_bytes)
    proof_nonce_bytes = (ROOT / "contracts/issuance-proof-nonce.json").read_bytes()
    proof_nonce = json.loads(proof_nonce_bytes)
    assert surface["schema"] == "marty.issuance-runtime-surface/v1"
    assert surface["http"]["route_count"] == len(surface["http"]["routes"]) == 131
    assert surface["grpc"]["method_count"] == len(surface["grpc"]["methods"]) == 12
    canonical_surface = surface_bytes.replace(b"\r\n", b"\n")
    assert (
        hashlib.sha256(canonical_surface).hexdigest() == coverage["upstream"]["sha256"]
    )
    assert coverage["upstream"]["commit"] == "578e86ef43166be79add2d812e92ef650535edaa"
    assert (
        hashlib.sha256(discovery_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == (coverage["behavior_contract"]["sha256"])
    )
    assert (
        coverage["behavior_contract"]["commit"]
        == "5b210bde2bee4360a9504e4c360250b54f48f5ba"
    )
    assert discovery["schema"] == "marty.issuance-static-discovery/v1"
    assert (
        hashlib.sha256(tenant_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == (coverage["tenant_behavior_contract"]["sha256"])
    )
    assert (
        coverage["tenant_behavior_contract"]["commit"]
        == "d853a14efb5cce2894aea138e2e784735499a7fc"
    )
    assert tenant["schema"] == "marty.issuance-tenant-discovery/v1"
    assert (
        hashlib.sha256(transaction_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == coverage["transaction_read_behavior_contract"]["sha256"]
    )
    assert (
        coverage["transaction_read_behavior_contract"]["commit"]
        == "4d628a185cf82b84a400c6ea495865786c9f4588"
    )
    assert transaction_reads["schema"] == "marty.issuance-offer-transaction-reads/v1"
    assert len(transaction_reads["edge_cases"]) == 8
    assert len(transaction_reads["failures"]) == 7
    assert (
        hashlib.sha256(token_exchange_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == coverage["token_exchange_behavior_contract"]["sha256"]
    )
    assert (
        coverage["token_exchange_behavior_contract"]["commit"]
        == "5c470988b597b8e26b93395e169f78b0edd6787f"
    )
    assert token_exchange["schema"] == "marty.issuance-token-exchange/v1"
    assert len(token_exchange["cases"]) == 4
    assert len(token_exchange["failures"]) == 17
    assert token_exchange["rate_limit"] == {
        "requests": 2,
        "window_seconds": 17,
        "request": {
            "form": {
                "grant_type": "unsupported",
                "pre-authorized_code": "pre-auth-token",
            }
        },
        "allowed_status_code": 400,
        "status_code": 429,
        "headers": {"Retry-After": "17"},
        "body": {"detail": "Rate limit exceeded"},
    }
    assert token_exchange["dependency_failures"] == [
        {
            "name": "token_repository_unavailable",
            "setup": "repository_unavailable",
            "form": {
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": "pre-auth-token",
            },
            "status_code": 500,
            "content_type": "text/plain",
            "body": "Internal Server Error",
            "repository_calls": [
                {"method": "get_by_pre_auth_code", "value": "pre-auth-token"}
            ],
        }
    ]
    assert (
        hashlib.sha256(proof_nonce_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == coverage["proof_nonce_behavior_contract"]["sha256"]
    )
    assert (
        coverage["proof_nonce_behavior_contract"]["commit"]
        == "b1f8845dabc4e64d93dc0336acba032a5b1255ff"
    )
    assert proof_nonce["schema"] == "marty.issuance-proof-nonce/v1"
    assert proof_nonce["inputs"] == {
        "path": "/v1/issuance/nonce",
        "generated_nonce": "contract-proof-nonce",
        "ttl_seconds": 300,
    }
    assert proof_nonce["persistence"] == {
        "digest_algorithm": "sha-256",
        "digest_length": 64,
        "plaintext_retained": False,
        "single_use": True,
    }
    native = {
        operation["operation"]: operation for operation in coverage["native_http"]
    }
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
    tenant_cases = {case["operation"]: case for case in tenant["variants"]}
    transaction_cases = {case["operation"]: case for case in transaction_reads["cases"]}
    assert set(native) == (
        set(discovery_cases)
        | set(tenant_cases)
        | set(transaction_cases)
        | {"exchange_token", "nonce_endpoint", "issue_credential"}
    )
    for operation, coverage_entry in native.items():
        if operation == "exchange_token":
            assert coverage_entry == {
                "method": "POST",
                "path": token_exchange["inputs"]["path"],
                "operation": "exchange_token",
                "token_exchange_behavior_case": "exchange_token",
            }
            continue
        if operation == "nonce_endpoint":
            assert coverage_entry == {
                "method": "POST",
                "path": proof_nonce["inputs"]["path"],
                "operation": "nonce_endpoint",
                "proof_nonce_behavior_case": "nonce_endpoint",
            }
            continue
        if operation == "issue_credential":
            assert coverage_entry == {
                "method": "POST",
                "path": "/v1/issuance/credential",
                "operation": "issue_credential",
                "credential_behavior_contract": True,
            }
            continue
        if operation in tenant_cases:
            assert coverage_entry["tenant_behavior_case"] == operation
            assert coverage_entry["method"] == "GET"
            assert tenant_cases[operation]["path"] == coverage_entry["path"].replace(
                "{org_id}", "org-a"
            )
            continue
        if operation in transaction_cases:
            assert coverage_entry["transaction_read_behavior_case"] == operation
            assert (
                coverage_entry["method"]
                == transaction_cases[operation]["method"]
                == "GET"
            )
            expected_paths = {
                "get_credential_offer": "/v1/issuance/offers/tx-pending",
                "list_transactions": "/v1/issuance/transactions?organization_id=org-a",
                "get_transaction": "/v1/issuance/transactions/tx-revoked",
                "get_transaction_revocation_status": (
                    "/v1/issuance/transactions/tx-revoked/revocation-status"
                ),
                "get_issuance_transaction_owner": (
                    "/internal/v1/resource-owners/issuance-transactions/tx-pending"
                ),
            }
            assert transaction_cases[operation]["path"] == expected_paths[operation]
            continue
        assert coverage_entry["method"] == discovery_cases[operation]["method"] == "GET"
        assert coverage_entry["behavior_case"] == operation
        expected_case_path = (
            coverage_entry["path"]
            .replace("{credential_type:path}", "access_badge")
            .replace("{org_id}", "org-a")
        )
        assert discovery_cases[operation]["path"] == expected_case_path
    assert coverage["remaining"] == {
        "http": 113,
        "grpc": 12,
        "runtime_modes": ["api", "canvas-sync-worker"],
        "literal_environment_variables": 73,
        "dynamic_configuration_lookups": 20,
        "migration_revisions": 44,
        "migration_heads": 1,
    }
    assert coverage["native_environment_variables"] == [
        "CORS_ALLOWED_ORIGINS",
        "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS",
        "CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS",
        "CANVAS_PILOT_ORGANIZATION_IDS",
        "CANVAS_PORTABLE_INTEGRATION_ENABLED",
        "DATABASE_URL",
        "GRPC_SERVICE_TOKEN",
        "ISSUANCE_SERVICE_PORT",
        "ISSUANCE_API_KEY",
        "ISSUER_BASE_URL",
        "ISSUER_DISPLAY_NAME",
        "REVOCATION_PROFILE_SERVICE_URL",
        "SIGNING_KEYS_INTERNAL_API_KEY",
        "SIGNING_KEYS_INTERNAL_URL",
        "TOKEN_RATE_LIMIT",
        "TOKEN_RATE_WINDOW",
    ]


def test_candidate_is_path_split_without_replacing_the_python_runtime() -> None:
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
    beta = text("docker-compose.beta.yml")
    production = text("docker-compose.selfhost.prod.yml")
    assert '"services/issuance"' in workspace
    assert "marty-issuance-service" in dockerfile
    assert "marty-issuance-service" in entrypoint
    assert "issuance-native:" in beta
    assert "ISSUANCE_NATIVE_SERVICE_URL: http://issuance-native:8005" in beta
    assert "issuance-native:" not in production
    assert "MARTY_ISSUANCE_IMAGE" in compose
