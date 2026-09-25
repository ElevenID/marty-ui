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
    assert {path.name for path in PROBE.iterdir() if not path.name == "target"} == {
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
    assert manifest["patch"]["crates-io"] == {
        "isomdl": {
            "git": "https://github.com/ElevenID/isomdl-elevenid",
            "rev": "671044c9495aec101bf0cd381669d5ed6f64dd11",
        },
        "ssi-jwt": {"path": "../../../rust/third_party/ssi-jwt"},
    }
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
    ):
        assert production_call in subject
    assert "ordinary_issuer_context_dependency_unavailable_diagnostic" not in subject
    for forbidden_expected_output in (
        "X-API-Key header is missing",
        "Application template not found",
        "Application repository is unavailable",
        "Issuer signing context is unavailable.",
    ):
        assert forbidden_expected_output not in subject


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
        "passport-self-signed-test": ["marty-verification/authority-issuance"],
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
