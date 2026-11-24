"""Fail-closed policy for the central Rust feature-regression probe inputs."""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / ".github" / "feature-regression" / "rust-probe"
MANIFEST = PROBE / "Cargo.toml"
LOCK = PROBE / "Cargo.lock"
SUBJECT = PROBE / "behavior_subject.rs"
ISSUANCE_MANIFEST = ROOT / "rust" / "services" / "issuance" / "Cargo.toml"
ISSUANCE_LIB = ROOT / "rust" / "services" / "issuance" / "src" / "lib.rs"
ISSUANCE_DIAGNOSTICS = (
    ROOT
    / "rust"
    / "services"
    / "issuance"
    / "src"
    / "internal_application_diagnostics.rs"
)
DIAGNOSTIC = (
    "event=internal_application_failure;stage=ordinary_issuer_context;"
    "category=dependency_unavailable;application_correlation_sha256="
    "b5ccfc2fc885903c0727f561fa4586490b661d9d53ec0fd19904ec6a85cfb192;"
    "check_correlation_sha256=;resource_correlation_sha256="
)
EXPECTED_OBSERVATIONS = {
    ("create-success", "public_status"): 200,
    ("create-success", "public_message"): "Ada_['Lovelace']",
    ("create-success", "safe_server_diagnostic"): "",
    ("auth-missing", "public_status"): 401,
    ("auth-missing", "public_message"): "X-API-Key header is missing",
    ("auth-missing", "safe_server_diagnostic"): "",
    ("template-missing", "public_status"): 404,
    ("template-missing", "public_message"): "Application template not found",
    ("template-missing", "safe_server_diagnostic"): "",
    ("repository-unavailable", "public_status"): 503,
    (
        "repository-unavailable",
        "public_message",
    ): "Application repository is unavailable",
    ("repository-unavailable", "safe_server_diagnostic"): "",
    ("issuer-context-unavailable", "public_status"): 503,
    (
        "issuer-context-unavailable",
        "public_message",
    ): "Issuer signing context is unavailable.",
    ("issuer-context-unavailable", "safe_server_diagnostic"): DIAGNOSTIC,
}
EXPECTED_OPERATIONS = {
    "create-success": "internal-application.create",
    "auth-missing": "internal-application.create",
    "template-missing": "internal-application.create",
    "repository-unavailable": "internal-application.create",
    "issuer-context-unavailable": "internal-application.approve",
}

# Expected values belong to this oracle, never to the executable subject.
# Configuration functions expose no HTTP response; their real return values
# provide the operator diagnostic projection instead.
CONFIGURATION_RESULTS = {
    "auth-missing-realm": ("auth.oidc-configuration", {
        "result": "rejected", "error": "AUTH.CONFIGURATION: KEYCLOAK_REALM is required",
    }),
    "auth-invalid-provider": ("auth.oidc-configuration", {
        "result": "rejected", "error": "AUTH.CONFIGURATION: OIDC_PROVIDER_MODE must be keycloak or external",
    }),
    "auth-pkce-s256": ("auth.pkce", {
        "challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    }),
    "flow-pool-two": ("flow.configuration", {
        "result": "accepted", "database_max_connections": 2, "redis_database": 3,
    }),
    "flow-pool-zero": ("flow.configuration", {
        "result": "rejected", "error": "FLOW.CONFIGURATION: FLOW_DATABASE_MAX_CONNECTIONS is invalid",
    }),
    "flow-missing-database": ("flow.configuration", {
        "result": "rejected", "error": "FLOW.CONFIGURATION: DATABASE_URL is required",
    }),
    "flow-missing-redis": ("flow.configuration", {
        "result": "rejected", "error": "FLOW.CONFIGURATION: REDIS_URL is required",
    }),
    "flow-invalid-redis-database": ("flow.configuration", {
        "result": "rejected", "error": "FLOW.CONFIGURATION: REDIS_DB_FLOW is invalid",
    }),
}
for case_id, (operation, result) in CONFIGURATION_RESULTS.items():
    EXPECTED_OPERATIONS[case_id] = operation
    EXPECTED_OBSERVATIONS.update({
        (case_id, "public_status"): "not_exposed",
        (case_id, "public_message"): "not_exposed",
        (case_id, "safe_server_diagnostic"): result,
    })

# HTTP expectations specify the intended production router/application contract,
# not an invocation capture. Native proof support deliberately adds no-store to
# both callback methods, including rejection redirects. Provider/cache ports are synthetic; response
# status, public errors, redirects, cookie attributes and logged stage codes
# are produced by the actual Auth owners.
HTTP_UI = "https://console.probe.invalid"
HTTP_FAILURE = HTTP_UI + "/?auth_error=Session+expired.+Please+try+again."
HTTP_NO_STORE = "no-store, max-age=0"


def http_expectation(case_id, status, *, body=None, location=None, cookies=(), cache=None, diagnostics=()):
    EXPECTED_OPERATIONS[case_id] = "auth.http-session"
    EXPECTED_OBSERVATIONS.update({
        (case_id, "public_status"): status,
        (case_id, "public_message"): {
            "body": body, "location": location, "cache_control": cache,
            "session_cookie_attributes": list(cookies),
        },
        (case_id, "safe_server_diagnostic"): list(diagnostics),
    })


http_expectation("auth-http-login", 302, location="https://identity.probe.invalid/authorize")
http_expectation("auth-http-invalid-locale", 400, body={"detail": "Supply ui_locales or the legacy kc_locale alias, not both"})
http_expectation("auth-http-registration-disabled", 409, cache=HTTP_NO_STORE, body={
    "code": "oidc_registration_unsupported", "detail": "Registration is managed by your identity provider",
})
for case_id in ("auth-http-state-save-failure", "auth-http-authorization-failure"):
    http_expectation(case_id, 503, body={"detail": "Authentication service unavailable"})
http_expectation("auth-http-missing-parameters", 302, cache=HTTP_NO_STORE, location=HTTP_UI + "/?auth_error=Missing+authentication+parameters")
for case_id, diagnostic in {
    "auth-http-unknown-state": "auth_oidc_state_invalid",
    "auth-http-expired-state": "auth_oidc_state_expired",
    "auth-http-missing-nonce": "auth_oidc_nonce_missing",
    "auth-http-state-consume-failure": "auth_oidc_state_consume_failed",
    "auth-http-exchange-failure": "auth_oidc_code_exchange_failed",
    "auth-http-missing-access": "auth_oidc_access_token_missing",
    "auth-http-missing-id": "auth_oidc_id_token_missing",
    "auth-http-token-validation-failure": "auth_oidc_token_validation_failed",
    "auth-http-provision-failure": "auth_user_provisioning_failed",
    "auth-http-session-save-failure": "auth_session_save_failed",
    "auth-http-login-event-failure": "auth_login_event_publish_failed",
    "auth-http-session-event-failure": "auth_session_event_publish_failed",
    "auth-http-callback-replay": "auth_oidc_state_invalid",
}.items():
    http_expectation(case_id, 302, cache=HTTP_NO_STORE, location=HTTP_FAILURE, diagnostics=(diagnostic,))
http_expectation("auth-http-callback-success", 302, cache=HTTP_NO_STORE, location=HTTP_UI + "/console/profile", cookies=(
    "HttpOnly;Max-Age=3600;Path=/;SameSite=Lax;Secure",
))
for case_id in ("auth-http-anonymous", "auth-http-after-logout"):
    http_expectation(case_id, 200, body={"authenticated": False, "user_fields": []}, cache=HTTP_NO_STORE)
http_expectation("auth-http-authenticated", 200, cache=HTTP_NO_STORE, body={
    "authenticated": True,
    "user_fields": ["email", "organization_context_unavailable", "organizations", "roles", "user_id", "user_type"],
})
http_expectation("auth-http-logout", 302, location="https://identity.probe.invalid/logout", cookies=(
    "Max-Age=0;Path=/;SameSite=Lax;Secure",
))
http_expectation("auth-http-invalid-picture", 400, body={"detail": "picture must be an image data URL or https URL"})
for case_id in ("auth-http-session-get-failure", "auth-http-profile-save-failure"):
    http_expectation(case_id, 503, body={"detail": "Session store unavailable"})


def assert_expected_probe_output(raw: bytes) -> None:
    document = json.loads(raw)
    canonical = json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    assert raw == canonical, "probe output must be canonical JSON without a trailing newline"
    assert document["schema"] == "elevenid.behavior-subject-output/v2"

    observations = document["observations"]
    assert len(observations) == len(EXPECTED_OBSERVATIONS)
    assert all(
        set(item) == {"id", "operation_id", "case_id", "dimension", "value"}
        and item["operation_id"] == EXPECTED_OPERATIONS[item["case_id"]]
        and item["id"] == f'{item["case_id"]}.{item["dimension"]}'
        for item in observations
    )
    actual = {
        (item["case_id"], item["dimension"]): item["value"] for item in observations
    }
    assert actual == EXPECTED_OBSERVATIONS

    diagnostic = actual[("issuer-context-unavailable", "safe_server_diagnostic")]
    for forbidden in (
        "application-probe-1",
        "probe-management-key",
        "ignored@example.test",
    ):
        assert forbidden not in diagnostic


def test_probe_uses_only_the_reserved_regular_files() -> None:
    assert {path.name for path in PROBE.iterdir() if path.name != "target"} == {
        "Cargo.lock",
        "Cargo.toml",
        "behavior_subject.rs",
    }
    for path in (MANIFEST, LOCK, SUBJECT):
        assert path.is_file()
        assert not path.is_symlink()


def test_probe_manifest_has_one_fixed_binary_and_real_candidate_dependency() -> None:
    manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["bin"] == [
        {
            "name": "elevenid-feature-regression-probe",
            "path": "behavior_subject.rs",
            "test": False,
        }
    ]
    build_budget = manifest["package"]["metadata"]["elevenid-feature-regression"]
    assert build_budget == {
        "build-storage-cap-bytes": 2_147_483_648,
        "reserved-non-target-bytes": 134_217_728,
        "target-budget-bytes": 2_013_265_920,
    }
    assert build_budget["target-budget-bytes"] == (
        build_budget["build-storage-cap-bytes"]
        - build_budget["reserved-non-target-bytes"]
    )
    assert manifest["dependencies"]["marty-issuance-service"] == {
        "path": "../../../rust/services/issuance",
        "features": ["feature-regression-observer"],
    }
    assert manifest["dependencies"]["marty-auth"] == {"path": "../../../rust/services/auth"}
    assert manifest["dependencies"]["marty-flow"] == {"path": "../../../rust/services/flow"}
    production = tomllib.loads((ROOT / "rust/Cargo.toml").read_text(encoding="utf-8"))
    assert manifest["patch"]["crates-io"] == production["patch"]["crates-io"]
    assert manifest["profile"]["dev"] == {
        "opt-level": "z",
        "debug": 0,
        "strip": "symbols",
        "incremental": False,
        "codegen-units": 1,
    }

    lock = tomllib.loads(LOCK.read_text(encoding="utf-8"))
    root_package = next(
        package
        for package in lock["package"]
        if package["name"] == "elevenid-feature-regression-probe"
    )
    assert {
        "async-trait",
        "axum",
        "chrono",
        "http-body-util",
        "marty-issuance-service",
        "serde_json",
        "tokio",
        "tower",
    }.issubset(root_package["dependencies"])
    subject = SUBJECT.read_text(encoding="utf-8")
    for production_call in (
        "internal_application_http::router",
        "InternalApplicationService::new",
        "OrdinaryInternalApplicationApprover::new",
        "observe_internal_application_diagnostics",
        "marty_auth::oidc_config_from_values",
        "marty_auth::pkce_s256_challenge",
        "marty_flow::FlowServiceConfig::from_values",
        "AuthApplication::new",
        "auth_core_router",
        "impl SessionRepository for Ports",
        "impl PkceStateRepository for Ports",
    ):
        assert production_call in subject
    assert "ordinary_issuer_context_dependency_unavailable_diagnostic" not in subject
    for forbidden_expected_output in (
        "X-API-Key header is missing",
        "Application template not found",
        "Application repository is unavailable",
        "Issuer signing context is unavailable.",
        "AUTH.CONFIGURATION:",
        "FLOW.CONFIGURATION:",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "Session+expired.+Please+try+again.",
        "Missing+authentication+parameters",
    ):
        assert forbidden_expected_output not in subject


def test_probe_framework_lock_sources_match_the_production_workspace() -> None:
    production = tomllib.loads((ROOT / "rust/Cargo.lock").read_text(encoding="utf-8"))
    probe = tomllib.loads(LOCK.read_text(encoding="utf-8"))

    def framework_packages(lock):
        return {
            (package["name"], package["version"]): package["source"]
            for package in lock["package"]
            if "github.com/ElevenID/marty-microservices-framework" in package.get("source", "")
        }

    expected = framework_packages(production)
    actual = framework_packages(probe)
    assert actual, "the probe must exercise the production framework"
    assert all(expected.get(package) == source for package, source in actual.items())


def test_ci_runs_the_frozen_offline_probe_twice_and_compares_exact_output() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    assert "Verify frozen Rust feature-regression probe" in workflow
    assert 'cargo fetch --locked --manifest-path "$manifest"' in workflow
    assert workflow.count("cargo run --frozen --offline --quiet \\") == 2
    assert "cmp --silent \"$first_output\" \"$second_output\"" in workflow
    assert (
        'python3 tests/test_feature_regression_rust_probe.py "$first_output"'
        in workflow
    )
    assert 'target_bytes=$(du -sb "$target" | cut -f1)' in workflow
    assert '["elevenid-feature-regression"]["target-budget-bytes"]' in workflow
    assert 'test "$target_bytes" -le "$target_budget_bytes"' in workflow


def test_ci_enforces_probe_clippy_and_observer_isolation() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    assert "Lint frozen Rust feature-regression probe" in workflow
    assert 'target="$RUNNER_TEMP/feature-regression-rust-probe-clippy-target"' in workflow
    assert "cargo clippy --frozen --offline" in workflow
    assert "--bin elevenid-feature-regression-probe -- -D warnings" in workflow
    assert "Verify feature-regression observer isolation" in workflow
    assert "cargo test --frozen --offline --manifest-path rust/Cargo.toml" in workflow
    assert "--package marty-issuance-service --lib" in workflow
    assert "--features feature-regression-observer" in workflow
    assert (
        "internal_application_diagnostics::tests::"
        "feature_observer_is_task_scoped_non_nested_and_cleans_up"
    ) in workflow
    assert "-- --exact" in workflow


def test_observer_is_narrow_feature_gated_and_absent_from_default_api() -> None:
    issuance_manifest = tomllib.loads(ISSUANCE_MANIFEST.read_text(encoding="utf-8"))
    assert issuance_manifest["features"] == {
        "default": [],
        "feature-regression-observer": [],
    }
    library = ISSUANCE_LIB.read_text(encoding="utf-8")
    assert "mod internal_application_diagnostics;" in library
    assert "pub mod internal_application_diagnostics;" not in library
    assert '#[cfg(feature = "feature-regression-observer")]' in library
    assert (
        "pub use internal_application_diagnostics::"
        "observe_internal_application_diagnostics;"
    ) in library
    diagnostics = ISSUANCE_DIAGNOSTICS.read_text(encoding="utf-8")
    assert "tokio::task_local!" in diagnostics
    assert "internal Application diagnostic observer scopes cannot be nested" in diagnostics
    assert "pub struct InternalApplicationDiagnosticProjection" not in diagnostics


def test_expected_values_cover_every_case_dimension_and_redacted_diagnostic() -> None:
    cases = {case_id for case_id, _ in EXPECTED_OBSERVATIONS}
    assert {
        dimension for _, dimension in EXPECTED_OBSERVATIONS
    } == {"public_status", "public_message", "safe_server_diagnostic"}
    assert len(EXPECTED_OBSERVATIONS) == len(cases) * 3
    assert "application-probe-1" not in DIAGNOSTIC
    assert "probe-management-key" not in DIAGNOSTIC


def test_oracle_rejects_a_missing_real_issuer_warning() -> None:
    observations = []
    for (case_id, dimension), value in EXPECTED_OBSERVATIONS.items():
        if (case_id, dimension) == (
            "issuer-context-unavailable",
            "safe_server_diagnostic",
        ):
            value = ""
        observations.append(
            {
                "id": f"{case_id}.{dimension}",
                "operation_id": EXPECTED_OPERATIONS[case_id],
                "case_id": case_id,
                "dimension": dimension,
                "value": value,
            }
        )
    raw = json.dumps(
        {
            "schema": "elevenid.behavior-subject-output/v2",
            "observations": observations,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    try:
        assert_expected_probe_output(raw)
    except AssertionError:
        return
    raise AssertionError("oracle accepted a missing real issuer warning")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_feature_regression_rust_probe.py OUTPUT.json")
    assert_expected_probe_output(Path(sys.argv[1]).read_bytes())
