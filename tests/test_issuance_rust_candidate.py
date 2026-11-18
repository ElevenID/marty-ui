from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_platform_postgres_contracts_remain_required_after_provider_retirement() -> (
    None
):
    contract_dir = ROOT / "rust" / "services" / "issuance" / "tests"
    assert not list(contract_dir.glob("canvas_*_postgres_contract.rs"))
    assert (contract_dir / "proof_nonce_postgres_contract.rs").is_file()
    assert (contract_dir / "internal_application_postgres_contract.rs").is_file()
    manifest = text("rust/services/issuance/Cargo.toml")
    assert 'name = "proof_nonce_postgres_contract"' in manifest
    assert 'name = "internal_application_postgres_contract"' in manifest
    assert 'name = "canvas_' not in manifest
    runner = text("scripts/ci/run-rust-db-contracts.sh")
    assert "resolve_contract_executable proof_nonce_postgres_contract" in runner
    assert (
        "resolve_contract_executable internal_application_postgres_contract" in runner
    )
    assert "Expected one proof nonce PostgreSQL contract executable" in runner
    assert "resolve_issuance_canvas_contracts" not in runner
    assert "python3 ../scripts/ci/run-db-contract-groups.py" in text(
        ".github/workflows/ci.yml"
    )


def test_internal_application_postgres_contract_is_required_in_ci() -> None:
    manifest = text("rust/services/issuance/Cargo.toml")
    runtime = text("scripts/ci/run-rust-db-contracts.sh")
    assert 'name = "internal_application_postgres_contract"' in manifest
    assert 'path = "tests/internal_application_postgres_contract.rs"' in manifest
    assert (
        "resolve_contract_executable internal_application_postgres_contract" in runtime
    )
    assert "Expected one internal Application PostgreSQL contract executable" in runtime


def test_signing_storage_contracts_use_guarded_disposable_redis_in_ci() -> None:
    workflow = text(".github/workflows/ci.yml")
    runtime = text("scripts/ci/run-rust-db-contracts.sh")
    contract = text("rust/services/signing-keys/tests/document_storage_contract.rs")
    issuer_contract = text(
        "rust/services/signing-keys/tests/issuer_profile_storage_contract.rs"
    )

    assert 'redis-cli -n 14 SET marty:tests:disposable-guard "$nonce"' in workflow
    assert 'export MARTY_TEST_REDIS_DISPOSABLE_NONCE="$nonce"' in workflow
    assert "signing_disposable_redis_url=redis://127.0.0.1:6379/14" in runtime
    for name in ("signing_document", "issuer_profile"):
        assert (
            'MARTY_TEST_REDIS_URL="$signing_disposable_redis_url" \\\n'
            f"  run_timed {name}"
        ) in runtime
    assert 'std::env::var("MARTY_TEST_REDIS_DISPOSABLE_NONCE")' in contract
    assert "disposable_backends::disposable_redis_url().await" in issuer_contract


def test_oid4vci_migration_postgres_contract_is_required_in_real_database_ci() -> None:
    manifest = text("rust/services/issuance/Cargo.toml")
    runtime = text("scripts/ci/run-rust-db-contracts.sh")
    workflow = text(".github/workflows/ci.yml")
    assert 'name = "oid4vci_migration_postgres_contract"' in manifest
    assert 'path = "tests/oid4vci_migration_postgres_contract.rs"' in manifest
    assert "resolve_contract_executable oid4vci_migration_postgres_contract" in runtime
    assert (
        "Expected one Issuance OID4VCI migration PostgreSQL contract executable"
        in runtime
    )
    assert (
        "resolve_recorded_contract_executable marty-issuance-service "
        "oid4vci_migration_postgres_contract"
    ) in workflow
    assert (
        "compiled Issuance OID4VCI migration PostgreSQL contract executable" in workflow
    )
    assert runtime.index(
        "resolve_contract_executable oid4vci_migration_postgres_contract"
    ) < runtime.index(
        "resolve_contract_executable issuance_transaction_postgres_contract"
    ), "the following transaction suite must recreate tables after the rollback fixture"


def test_issuance_image_smoke_uses_the_shared_migration_fixture() -> None:
    workflow = text(".github/workflows/ci.yml")
    smoke = text("scripts/smoke-issuance-image.sh")
    contract = text(
        "rust/services/issuance/tests/oid4vci_migration_postgres_contract.rs"
    )
    fixture = "rust/services/issuance/tests/fixtures/oid4vci_migration_base.sql"

    assert "bash scripts/smoke-issuance-image.sh marty-issuance:ci" in workflow
    assert fixture in smoke
    assert 'include_str!("fixtures/oid4vci_migration_base.sql")' in contract
    assert "issuance-postgres" in smoke
    assert "/unused" not in smoke
    assert smoke.count("--host 127.0.0.1") == 4
    assert 'POSTGRES_PASSWORD="$postgres_password"' in smoke
    assert smoke.count('PGPASSWORD="$postgres_password"') == 3
    assert (
        'DATABASE_URL="postgresql://marty:${postgres_password}@issuance-postgres/marty"'
        in smoke
    )
    assert (
        "SIGNING_KEYS_INTERNAL_URL=http://synthetic-secret-service:8017/internal/signing-keys"
        in smoke
    )
    assert "INTEGRATION_SECRET_MASTER_KEY" not in smoke
    assert "access_token_expires_at" in smoke
    assert "ux_issuance_events_oid4vci_notification_id" in smoke


def test_issuance_executable_smoke_uses_an_isolated_migrated_database() -> None:
    workflow = text(".github/workflows/ci.yml")
    executable = text("rust/services/issuance/tests/executable_smoke.rs")

    assert "marty_issuance_executable_smoke_test" in workflow
    assert '"rust/target/debug/$owner" migrate' in workflow
    assert '"rust/target/debug/$owner" verify-owned-schema' in workflow
    assert "CREATE TABLE organization_service.organizations" not in workflow
    assert (
        "CREATE TABLE credential_template_service.credential_templates" not in workflow
    )
    assert "rust/target/debug/marty-issuance-service migrate" in workflow
    assert (
        "ISSUANCE_EXECUTABLE_SMOKE_DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/"
        "marty_issuance_executable_smoke_test"
    ) in workflow
    assert executable.count('.env("DATABASE_URL", &database_url)') == 6
    assert "executable_serves_issuance_rpc_with_remote_key_mutual_tls" in executable
    assert "ISSUANCE_EXECUTABLE_SMOKE_DATABASE_URL" in executable
    assert "skipping executable smoke test" in executable


def test_passport_bureau_postgres_contract_runs_in_ci() -> None:
    workflow = text(".github/workflows/ci.yml")
    bureau = text("rust/services/issuance/src/bin/passport_beta_bureau.rs")

    assert "marty_passport_bureau_test" in workflow
    assert (
        "PASSPORT_BUREAU_TEST_DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/"
        "marty_passport_bureau_test"
    ) in workflow
    assert "cargo test --locked --workspace" in workflow
    assert "test = true" in text("rust/services/issuance/Cargo.toml")
    assert (
        "postgres_bureau_jobs_are_durable_idempotent_and_tenant_bound_when_configured"
        in bureau
    )


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
    credential_lifecycle_bytes = (
        ROOT / "contracts/issuance-credential-lifecycle.json"
    ).read_bytes()
    credential_lifecycle = json.loads(credential_lifecycle_bytes)
    application_template_bytes = (
        ROOT / "contracts/issuance-application-templates.json"
    ).read_bytes()
    application_templates = json.loads(application_template_bytes)
    internal_application_bytes = (
        ROOT / "contracts/issuance-internal-applications.json"
    ).read_bytes()
    internal_applications = json.loads(internal_application_bytes)
    retention_bytes = (
        ROOT / "contracts/issuance-retention-management.json"
    ).read_bytes()
    retention = json.loads(retention_bytes)
    resource_owner_bytes = (
        ROOT / "contracts/issuance-resource-owner-lookups.json"
    ).read_bytes()
    resource_owners = json.loads(resource_owner_bytes)
    issued_credential_adapter_bytes = (
        ROOT / "contracts/issuance-issued-credential-adapters.json"
    ).read_bytes()
    issued_credential_adapters = json.loads(issued_credential_adapter_bytes)
    oid4vci_authorization_bytes = (
        ROOT / "contracts/issuance-oid4vci-authorization.json"
    ).read_bytes()
    oid4vci_authorization = json.loads(oid4vci_authorization_bytes)
    assert surface["schema"] == "marty.issuance-runtime-surface/v1"
    assert surface["http"]["route_count"] == len(surface["http"]["routes"]) == 131
    assert surface["grpc"]["method_count"] == len(surface["grpc"]["methods"]) == 12
    canonical_surface = surface_bytes.replace(b"\r\n", b"\n")
    assert (
        hashlib.sha256(canonical_surface).hexdigest() == coverage["upstream"]["sha256"]
    )
    assert coverage["upstream"]["commit"] == "f127f55ecfb113ebcdfee55a79e6bae937114dfa"
    assert (
        hashlib.sha256(discovery_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == coverage["behavior_contract"]["sha256"]
    )
    assert (
        coverage["behavior_contract"]["commit"]
        == "367945d4e37b93c5e3a385e60a5c417c7862dc6d"
    )
    assert discovery["schema"] == "marty.issuance-static-discovery/v1"
    assert (
        hashlib.sha256(tenant_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == coverage["tenant_behavior_contract"]["sha256"]
    )
    assert (
        coverage["tenant_behavior_contract"]["commit"]
        == "8e3868bcf424838c7f47085bb7a24cca7006472c"
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
    assert (
        hashlib.sha256(credential_lifecycle_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == coverage["credential_lifecycle_behavior_contract"]["sha256"]
    )
    assert (
        coverage["credential_lifecycle_behavior_contract"]["commit"]
        == "335c8566af4c873a30f960635db2624723008ae3"
    )
    assert credential_lifecycle["schema"] == "marty.issuance-credential-lifecycle/v1"
    assert len(credential_lifecycle["scope"]["http"]) == 4
    assert len(credential_lifecycle["scope"]["grpc"]) == 4
    assert len(credential_lifecycle["transitions"]) == 3
    assert credential_lifecycle["mutation_order"] == [
        "load-credential",
        "enforce-resource-organization-when-http",
        "validate-transition",
        "publish-revocation-profile-status",
        "persist-local-status",
        "synchronize-canvas-delivery-records",
        "emit-grpc-stream-event",
        "return-response",
    ]
    assert (
        credential_lifecycle["publication"]["revocation_profile"]
        == "required-before-local-persistence"
    )
    assert len(credential_lifecycle["failures"]) == 7
    assert len(credential_lifecycle["security_invariants"]) == 4
    assert (
        hashlib.sha256(application_template_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == coverage["application_template_behavior_contract"]["sha256"]
    )
    assert (
        coverage["application_template_behavior_contract"]["commit"]
        == "f127f55ecfb113ebcdfee55a79e6bae937114dfa"
    )
    assert application_templates["schema"] == "marty.issuance-application-templates/v1"
    assert len(application_templates["surface"]["routes"]) == 8
    assert (
        hashlib.sha256(internal_application_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == coverage["internal_application_behavior_contract"]["platform_adaptation"]["sha256"]
    )
    assert (
        coverage["internal_application_behavior_contract"]["commit"]
        == "e40c1ce6e807714278ef362d3ed24909dd8686fa"
    )
    assert (
        hashlib.sha256(resource_owner_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == coverage["resource_owner_behavior_contract"]["sha256"]
    )
    assert coverage["resource_owner_behavior_contract"] == {
        "path": "contracts/issuance-resource-owner-lookups.json",
        "sha256": "59b3f21107824f85136768545bca8f4a6374d3a4708a0408b1a7769c61c00a06",
        "source_repository": "ElevenID/marty-credentials",
        "source_path": "services/issuance/infrastructure/api/routes.py",
        "source_commit": "15af5232df376bb9596b5aed3703110bf890fce5",
    }
    assert resource_owners["schema"] == "marty.issuance-resource-owner-lookups/v1"
    assert resource_owners["authentication"]["trusted_tenant_header"] == "ignored"
    assert resource_owners["persistence"] == {
        "read_only": True,
        "projection": ["organization_id"],
        "id_scope": "unscoped",
    }
    assert resource_owners["intentional_native_corrections"] == [
        {
            "id": "RESOURCE-OWNER-001:sanitized-repository-failure",
            "legacy": {
                "status_code": 500,
                "content_type": "text/plain",
                "body": "Internal Server Error",
            },
            "native": {
                "status_code": 500,
                "content_type": "application/json",
                "body": {
                    "detail": "Issuance transaction data is temporarily unavailable"
                },
            },
            "rationale": "Reuse the already-native issuance-transaction owner failure boundary so all three owner kinds expose one sanitized, DRY internal error without a repository cause.",
            "gateway_invariant": {
                "status_code": 500,
                "content_type": "application/json",
                "body": {"detail": "Authorization service unavailable"},
                "upstream_body_disclosed": False,
                "proxy_continues": False,
            },
        }
    ]
    assert (
        hashlib.sha256(
            issued_credential_adapter_bytes.replace(b"\r\n", b"\n")
        ).hexdigest()
        == coverage["issued_credential_adapter_behavior_contract"]["sha256"]
    )
    assert coverage["issued_credential_adapter_behavior_contract"] == {
        "path": "contracts/issuance-issued-credential-adapters.json",
        "sha256": "05941c84d1d1ab80ef99b5eefe856d522cccc6b6cce719d8b4cc81a7a3b757e2",
        "source_repository": "ElevenID/marty-credentials",
        "source_path": "services/issuance/infrastructure/api/routes.py",
        "source_commit": "15af5232df376bb9596b5aed3703110bf890fce5",
    }
    assert (
        issued_credential_adapters["schema"]
        == "marty.issuance-issued-credential-adapters/v1"
    )
    assert len(issued_credential_adapters["operations"]) == 5
    assert (
        hashlib.sha256(oid4vci_authorization_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == coverage["oid4vci_authorization_behavior_contract"]["sha256"]
    )
    assert coverage["oid4vci_authorization_behavior_contract"] == {
        "path": "contracts/issuance-oid4vci-authorization.json",
        "sha256": "5eda9ba42017691d1b9152b4e9c9cbdbf824eb805b054aa2725b8c919db89511",
        "source_repository": "ElevenID/marty-credentials",
        "source_commit": "aaa6a9b8e31e62cd0ab087eef5fc1f4835048e26",
        "source_tree": "819b7458a31c75d28043a4660643b029c5ec4567",
        "intentional_native_corrections": [
            "OID4VCI-AUTH-002:validate-and-bind-bearer",
            "OID4VCI-ERROR-001:structured-sanitized-internal-errors",
            "OID4VCI-MGMT-001:registered-client-tenant-binding",
            "OID4VCI-NOTIFY-001:validate-notification-request",
            "SECURITY-ACCESS-TOKEN-001:exact-1800-second-expiry",
            "OID4VCI-REDIRECT-002:http-or-https-only-localhost",
        ],
    }
    assert len(oid4vci_authorization["routes"]) == 7
    assert issued_credential_adapters["projection"]["credential_formats"] == [
        "MDOC",
        "VDS_NC",
        "SD_JWT_VC",
        "VC_JWT",
        "JSON_LD",
    ]
    assert internal_applications["schema"] == "marty.issuance-internal-applications/v1"
    assert len(internal_applications["surface"]["routes"]) == 14
    assert (
        hashlib.sha256(retention_bytes.replace(b"\r\n", b"\n")).hexdigest()
        == coverage["retention_behavior_contract"]["sha256"]
    )
    assert retention["schema"] == "marty.issuance-retention-management/v1"
    assert len(retention["routes"]) == 2
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
    credential_lifecycle_routes = {
        route["operation"]: route for route in credential_lifecycle["scope"]["http"]
    }
    application_template_operations = {
        route["operation"] for route in application_templates["surface"]["routes"]
    }
    internal_application_operations = {
        route["operation"] for route in internal_applications["surface"]["routes"]
    }
    retention_operations = {route["operation"]: route for route in retention["routes"]}
    resource_owner_operations = {
        route["operation"]: route for route in resource_owners["operations"]
    }
    issued_credential_adapter_operations = {
        route["operation"]: route for route in issued_credential_adapters["operations"]
    }
    oid4vci_public_operations = {
        route["operation"]: route for route in oid4vci_authorization["routes"]
    }
    renewal_bytes = text("contracts/credential-renewal-python-reference.json").encode()
    assert coverage["renewal_behavior_contract"] == {
        "path": "contracts/credential-renewal-python-reference.json",
        "sha256": "136b046f08c58d2a7fa70982404dabd7265164d91f49ee184cfbc63eb49b3f0f",
        "intentional_native_corrections": [
            "RENEWAL-001:links-before-delivery",
            "RENEWAL-002:pending-uri-on-unsent-delivery",
            "RENEWAL-003:atomic-canvas-successor-association",
        ],
    }
    assert (
        hashlib.sha256(renewal_bytes).hexdigest()
        == coverage["renewal_behavior_contract"]["sha256"]
    )
    retired = coverage["retired_legacy"]
    frozen_routes = {
        (route["method"], route["path"], route["operation"])
        for route in surface["http"]["routes"]
    }
    retired_routes = {
        (route["method"], route["path"], route["operation"])
        for route in retired["http_routes"]
    }
    native_routes = {
        (route["method"], route["path"], route["operation"])
        for route in coverage["native_http"]
    }
    assert len(retired_routes) == len(retired["http_routes"]) == 59
    assert retired_routes <= frozen_routes
    assert retired_routes.isdisjoint(native_routes)
    assert all(
        path.startswith("/v1/integrations/canvas/") or "/canvas-" in path
        for _, path, _ in retired_routes
    )
    remaining_routes = frozen_routes - native_routes - retired_routes
    assert len(remaining_routes) == coverage["remaining"]["http"]
    assert all(path.startswith("/v1/passport/") for _, path, _ in remaining_routes)
    assert (
        len(native_routes) + len(retired_routes) + len(remaining_routes)
        == surface["http"]["route_count"]
    )
    retired_environment = set(retired["environment_variables"])
    assert len(retired_environment) == len(retired["environment_variables"]) == 39
    assert retired_environment <= set(surface["configuration"]["environment_variables"])
    assert all(name.startswith("CANVAS_") for name in retired_environment)
    assert retired_environment.isdisjoint(coverage["native_environment_variables"])
    assert set(retired["runtime_modes"]) == {"canvas-sync-worker"}
    assert {mode["name"] for mode in surface["runtime"]["modes"]} == set(
        coverage["remaining"]["runtime_modes"]
    ) | set(retired["runtime_modes"])
    provenance = coverage["internal_application_behavior_contract"]
    adaptation = provenance["platform_adaptation"]
    assert adaptation["owner"] == "ElevenID/marty-ui"
    assert (
        adaptation["base_sha256"]
        == provenance["sha256"]
        == "650f22242055fbd4acbea523749a2d10aa8509a95fad9175d7b134c76433da12"
    )
    assert adaptation["reason"].strip()
    assert len(coverage["native_http"]) == 63
    assert set(native) == set(discovery_cases) | set(tenant_cases) | set(
        transaction_cases
    ) | set(
        credential_lifecycle_routes
    ) | application_template_operations | internal_application_operations | set(
        retention_operations
    ) | set(resource_owner_operations) | set(
        issued_credential_adapter_operations
    ) | set(oid4vci_public_operations) | {
        "didcomm_deliver",
        "initiate_issuance",
        "renew_issued_credential",
        "exchange_token",
        "nonce_endpoint",
        "issue_credential",
    }
    for operation, coverage_entry in native.items():
        if operation == "renew_issued_credential":
            assert coverage_entry == {
                "method": "POST",
                "path": "/v1/issued-credentials/{credential_id}/renew",
                "operation": "renew_issued_credential",
                "renewal_behavior_contract": True,
            }
            continue
        if operation == "initiate_issuance":
            assert coverage_entry == {
                "method": "POST",
                "path": "/v1/issuance/initiate",
                "operation": "initiate_issuance",
                "initiation_behavior_contract": True,
            }
            continue
        if operation == "didcomm_deliver":
            assert coverage_entry == {
                "method": "POST",
                "path": "/v1/issuance/didcomm/deliver",
                "operation": "didcomm_deliver",
                "didcomm_behavior_contract": True,
            }
            continue
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
        if operation in credential_lifecycle_routes:
            assert coverage_entry == {
                **credential_lifecycle_routes[operation],
                "credential_lifecycle_behavior_contract": True,
            }
            continue
        if operation in application_template_operations:
            assert coverage_entry["application_template_behavior_case"] == operation
            assert any(
                (
                    route["method"] == coverage_entry["method"]
                    and route["path"] == coverage_entry["path"]
                    and (route["operation"] == operation)
                    for route in application_templates["surface"]["routes"]
                )
            )
            continue
        if operation in internal_application_operations:
            assert coverage_entry["internal_application_behavior_case"] == operation
            assert any(
                (
                    route["method"] == coverage_entry["method"]
                    and route["path"] == coverage_entry["path"]
                    and (route["operation"] == operation)
                    for route in internal_applications["surface"]["routes"]
                )
            )
            continue
        if operation in retention_operations:
            assert coverage_entry == {
                **retention_operations[operation],
                "retention_behavior_contract": True,
            }
            continue
        if operation in resource_owner_operations:
            frozen = resource_owner_operations[operation]
            assert coverage_entry == {
                "method": frozen["method"],
                "path": frozen["path"],
                "operation": frozen["operation"],
                "resource_owner_behavior_contract": True,
            }
            continue
        if operation in issued_credential_adapter_operations:
            frozen = issued_credential_adapter_operations[operation]
            expected = {
                "method": frozen["method"],
                "path": frozen["path"],
                "operation": frozen["operation"],
                "issued_credential_adapter_behavior_contract": True,
            }
            assert coverage_entry == expected
            continue
        if operation in oid4vci_public_operations:
            frozen = oid4vci_public_operations[operation]
            assert coverage_entry == {
                "method": frozen["method"],
                "path": frozen["path"],
                "operation": frozen["operation"],
                "oid4vci_authorization_behavior_contract": True,
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
                "get_transaction_revocation_status": "/v1/issuance/transactions/tx-revoked/revocation-status",
                "get_issuance_transaction_owner": "/internal/v1/resource-owners/issuance-transactions/tx-pending",
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
        "http": 9,
        "grpc": 0,
        "runtime_modes": ["api"],
        "literal_environment_variables": 12,
        "dynamic_configuration_lookups": 20,
        "migration_revisions": 46,
        "migration_heads": 1,
    }
    assert coverage["native_environment_variables"] == [
        "CORS_ALLOWED_ORIGINS",
        "APP_ENV",
        "CREDENTIAL_TEMPLATE_SERVICE_URL",
        "CT_GRPC_TARGET",
        "DATABASE_URL",
        "DIDCOMM_ALLOW_PRIVATE_IPS",
        "DIDCOMM_DID_WEB_INTERNAL_BASE_URL",
        "DIDCOMM_ENCRYPTION_POLICY_FILE",
        "DIDCOMM_TLS_CA_FILE",
        "DIDCOMM_UNIVERSAL_RESOLVER_URL",
        "ENVIRONMENT",
        "GRPC_CA_CERT",
        "GRPC_SERVICE_TOKEN",
        "GRPC_SERVICE_TOKEN_FILE",
        "GRPC_TLS_CA_CERT",
        "INTEGRATION_SECRET_MASTER_KEY_ENV",
        "ISSUANCE_GRPC_ENABLED",
        "ISSUANCE_GRPC_PORT",
        "ISSUANCE_SERVICE_PORT",
        "ISSUANCE_API_KEY",
        "ISSUANCE_AUTH_SESSION_TTL_MINUTES",
        "ALLOWED_REDIRECT_URIS",
        "ISSUANCE_OFFER_TTL_MINUTES",
        "ISSUER_BASE_URL",
        "ISSUER_DISPLAY_NAME",
        "LOG_LEVEL",
        "ORG_GRPC_TARGET",
        "REVOCATION_PROFILE_SERVICE_URL",
        "RP_GRPC_TARGET",
        "SIGNING_KEYS_INTERNAL_API_KEY",
        "SIGNING_KEYS_INTERNAL_URL",
        "TOKEN_RATE_LIMIT",
        "TOKEN_RATE_WINDOW",
        "UI_BASE_URL",
        "UNIVERSAL_RESOLVER_URL",
        "VCDM_RELATED_RESOURCE_MAX_BYTES",
        "VCDM_RELATED_RESOURCE_TIMEOUT_SECONDS",
        "VCDM_RELATED_RESOURCE_URLS",
    ]
    assert coverage["platform_additive_environment_variables"] == [
        "GRPC_INSECURE_ALLOWED",
        "GRPC_TLS_CLIENT_CERT",
        "GRPC_TLS_CLIENT_KMS_ADDR",
        "GRPC_TLS_CLIENT_KMS_CA_CERT",
        "GRPC_TLS_CLIENT_KMS_KEY_NAME",
        "GRPC_TLS_CLIENT_KMS_KEY_VERSION",
        "GRPC_TLS_CLIENT_KMS_TOKEN_FILE",
    ]
    frozen_environment_variables = set(
        surface["configuration"]["environment_variables"]
    )
    native_environment_variables = set(coverage["native_environment_variables"])
    additive_environment_variables = set(
        coverage["platform_additive_environment_variables"]
    )
    assert native_environment_variables <= frozen_environment_variables
    assert additive_environment_variables.isdisjoint(frozen_environment_variables)
    assert coverage["remaining"]["literal_environment_variables"] == len(
        frozen_environment_variables
        - native_environment_variables
        - set(coverage["retired_legacy"]["environment_variables"])
    )


def test_oid4vci_coverage_mutations_break_the_enforced_provenance_or_route_floor() -> (
    None
):
    coverage = json.loads(text("contracts/issuance-native-coverage.json"))
    contract_bytes = (
        ROOT / "contracts/issuance-oid4vci-authorization.json"
    ).read_bytes()
    contract = json.loads(contract_bytes)
    expected_routes = {
        (route["method"], route["path"], route["operation"])
        for route in contract["routes"]
    }

    def valid(candidate: dict) -> bool:
        metadata = candidate.get("oid4vci_authorization_behavior_contract", {})
        selected = {
            (route["method"], route["path"], route["operation"])
            for route in candidate["native_http"]
            if route.get("oid4vci_authorization_behavior_contract") is True
        }
        return (
            metadata.get("path") == "contracts/issuance-oid4vci-authorization.json"
            and metadata.get("source_commit")
            == contract["source"]["protected_main_commit"]
            and metadata.get("source_tree") == contract["source"]["protected_main_tree"]
            and metadata.get("sha256")
            == hashlib.sha256(contract_bytes.replace(b"\r\n", b"\n")).hexdigest()
            and selected == expected_routes
        )

    assert valid(coverage)
    for mutate in [
        lambda value: value["oid4vci_authorization_behavior_contract"].__setitem__(
            "sha256", "0" * 64
        ),
        lambda value: value["oid4vci_authorization_behavior_contract"].__setitem__(
            "source_tree", "0" * 40
        ),
        lambda value: value["native_http"].__setitem__(
            0, {**value["native_http"][0], "path": "/v1/issuance/wrong"}
        ),
        lambda value: value["native_http"].pop(0),
    ]:
        changed = json.loads(json.dumps(coverage))
        mutate(changed)
        assert not valid(changed)


def test_candidate_uses_rust_runtime_across_compose_surfaces() -> None:
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
    assert "file: docker-compose.service.issuance-native.yml" in beta
    beta += text("docker-compose.service.issuance-native.yml")
    production = text("docker-compose.selfhost.prod.yml")
    assert '"services/issuance"' in workspace
    assert "marty-issuance-service" in dockerfile
    assert "marty-issuance-service" in entrypoint
    assert "issuance-native:" in beta
    assert "ISSUANCE_NATIVE_SERVICE_URL: http://issuance-native:8005" in beta
    assert "CANVAS_LTI_STATE_TTL_MINUTES:" not in beta
    assert "CANVAS_LTI_JWKS_TTL_MINUTES:" not in beta
    assert "CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES:" not in beta
    assert "CANVAS_OAUTH_COMPLETION_REDIRECT_URL:" not in beta
    assert "INTEGRATION_SECRET_MASTER_KEY:" not in beta
    assert "CANVAS_ALLOW_PRIVATE_BASE_URLS:" not in beta
    assert "CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS:" not in beta
    assert "CANVAS_PRIVATE_ORIGIN_ALLOWLIST:" not in beta
    assert "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST:" not in beta
    assert "CANVAS_LEGACY_EVENT_INGEST_ENABLED:" not in beta
    assert "CANVAS_CREDENTIALS_SHARED_SECRET:" not in beta
    assert "CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST:" not in beta
    assert "CANVAS_CREDENTIALS_STATUS_SYNC_TIMEOUT_SECONDS:" not in beta
    assert "ISSUANCE_NATIVE_SERVICE_URL: http://issuance-native:8005" in production
    assert "ISSUANCE_SERVICE_URL: http://issuance:8005" in production
    assert "file: docker-compose.service.issuance-native-runtime.yml" in production
    assert "MARTY_ISSUANCE_IMAGE" not in production
    assert "CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES:" not in production
    assert "MARTY_ISSUANCE_IMAGE" not in compose
    assert 'command: ["migrate"]' in compose


def test_public_issued_credential_adapters_cut_over_without_claiming_siblings() -> None:
    coverage = json.loads(text("contracts/issuance-native-coverage.json"))
    gateway = json.loads(text("contracts/gateway-routes.json"))
    native = {(route["method"], route["path"]) for route in coverage["native_http"]}
    public = {(route["method"], route["path"]) for route in gateway["routes"]}

    internal_lifecycle = {
        ("POST", "/v1/issuance/credentials/{credential_id}/revoke"),
        ("POST", "/v1/issuance/credentials/{credential_id}/suspend"),
        ("POST", "/v1/issuance/credentials/{credential_id}/reinstate"),
        ("GET", "/v1/issuance/credentials/{credential_id}/status"),
    }
    public_record_adapters = {
        ("GET", "/v1/issued-credentials"),
        ("GET", "/v1/issued-credentials/{credential_id}"),
        ("POST", "/v1/issued-credentials/{credential_id}/revoke"),
        ("POST", "/v1/issued-credentials/{credential_id}/suspend"),
        ("POST", "/v1/issued-credentials/{credential_id}/reinstate"),
    }
    independently_owned = {
        ("GET", "/v1/issued-credentials/mine"),
        ("POST", "/v1/credentials/issued/batch-revoke"),
        ("GET", "/v1/credentials/revocations"),
    }
    canvas_mirror_publish = (
        "POST",
        "/v1/issued-credentials/{credential_id}/deliveries/canvas-credentials/publish",
    )

    assert internal_lifecycle <= native
    assert internal_lifecycle.isdisjoint(public)
    assert public_record_adapters <= public
    assert public_record_adapters <= native
    assert canvas_mirror_publish not in native
    assert canvas_mirror_publish not in public
    assert independently_owned.isdisjoint(native)
    assert (
        "POST",
        "/v1/issued-credentials/{credential_id}/renew",
    ) in native, "the independently migrated renewal route must remain native"
    assert (
        "GET",
        "/v1/issued-credentials/{credential_id}/status",
    ) not in public


def test_beta_status_consumer_selects_native_without_changing_production() -> None:
    beta = yaml.safe_load(text("docker-compose.beta.yml"))
    presentation_policy = beta["services"]["presentation-policy"]
    assert presentation_policy["environment"]["MIP_CREDENTIAL_STATUS_URL_TEMPLATE"] == (
        "http://issuance-native:8005/v1/issuance/credentials/{credential_id}/status"
    )
    assert presentation_policy["depends_on"]["issuance-native"] == {
        "condition": "service_healthy"
    }

    production = yaml.safe_load(text("docker-compose.selfhost.prod.yml"))
    assert production["services"]["presentation-policy"]["environment"][
        "MIP_CREDENTIAL_STATUS_URL_TEMPLATE"
    ] == (
        "${MIP_CREDENTIAL_STATUS_URL_TEMPLATE:-http://issuance:8005/v1/issuance/"
        "credentials/{credential_id}/status}"
    )
