"""Record effective libtest obligations for DB, Canvas, Flow, and self-host runners.

Discovery uses the same executable and selection arguments as execution. libtest
--list includes ignored tests by default, so a second ignored-only discovery is
required before claiming which bodies should actually run. This is evidence of
harness execution, not proof that every assertion inside a test was reached.
"""

import argparse
import ast
import codecs
import hashlib
import importlib.machinery
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_NAME = "db-contract-obligations.jsonl"
UNIT_EVIDENCE_NAME = "rust-unit-obligations.jsonl"
CANVAS_EVIDENCE_NAMES = {
    "canvas_composition_acceptance": "canvas-composition-obligations.jsonl",
    "canvas_worker_acceptance": "canvas-worker-obligations.jsonl",
}
PREFIX = "MARTY_DB_OBLIGATION_V1 "
UNIT_PREFIX = "MARTY_RUST_UNIT_OBLIGATION_V1 "
CANVAS_PREFIX = "MARTY_CANVAS_OBLIGATION_V1 "
RUN_IDENTITY = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_SHA")
FIXTURE_OWNER = ".github/compose/rust-ci-fixtures.yml"
RUNNER_OWNER = "scripts/ci/run-rust-db-contracts.sh"
FLOW_OWNERS = {
    "flow-pr": "scripts/ci/run-flow-acceptance-contracts.sh",
    "canvas": "scripts/ci/run-published-canvas-contracts.sh",
}
FLOW_FIXTURE_OWNER = "rust/services/issuance/tests/support/canvas_published_database.rs"
SELFHOST_OWNER = "scripts/ci/run-published-canvas-contracts.sh"
SELFHOST_FIXTURE_OWNER = (
    "rust/crates/selfhost-acceptance/tests/support/selfhost_packaged_runtime.rs"
)
RENEWAL_UNIT_PREFIX = "canvas_sync_worker::retry_handoff_tests::"
RENEWAL_UNIT_CASES = frozenset(
    RENEWAL_UNIT_PREFIX + name
    for name in (
        "retry_delay_owns_all_normalized_header_shapes_and_backoff_edges",
        "retry_hint_reaches_the_actual_worker_failure_port",
        "terminal_validation_errors_reach_actual_worker_dead_letter_port",
        "terminal_processor_errors_reach_actual_worker_dead_letter_port",
    )
) | frozenset(
    RENEWAL_UNIT_PREFIX + "renewal_tests::" + name
    for name in (
        "lease_error_then_success",
        "lease_error_then_retry",
        "lease_error_then_terminal",
        "lease_error_then_deadline",
        "lease_error_then_cancel",
        "target_error_then_success",
        "target_error_then_retry",
        "target_error_then_terminal",
        "target_error_then_deadline",
        "target_error_then_cancel",
        "process_error_then_success",
        "process_error_then_retry",
        "process_error_then_terminal",
        "process_error_then_deadline",
        "process_error_then_cancel",
        "lease_error_survives_failed_completion",
        "target_error_survives_failed_retry_persistence",
        "process_error_survives_failed_deadline_persistence",
        "actual_cycle_does_not_count_persisted_success_after_renewal_error",
    )
)
LIBRARY_UNIT_IGNORED_OWNERS = {
    **{
        "credential_builder::tests::"
        + name: "scripts/probe_integration_secret_coordinated_restore.py"
        for name in (
            "sd_jwt_signs_exact_native_input_with_public_holder_key",
            "jwt_vc_preserves_open_badge_profile_and_reserved_id",
            "mdoc_ignores_request_controlled_certificate_chain",
            "data_integrity_uses_native_canonicalization_and_verifies_completion",
        )
    },
    **{
        "canvas_readiness_runtime::tests::"
        + name: "scripts/probe_integration_secret_coordinated_restore.py"
        for name in (
            "live_challenges_prove_the_published_lti_and_kms_keys",
            "live_challenges_reject_ambiguous_or_private_key_material_before_kms_use",
            "kms_challenge_requires_the_active_method_in_both_did_relationships",
        )
    },
    **{
        "passport_http::reconciliation_tests::"
        + name: ".github/workflows/ci.yml:passport_reconciliation"
        for name in (
            "beta_reconciliation_replays_only_exact_material_and_binds_first_receipt",
            "beta_batch_http_binds_exact_flow_pair_and_replays_after_artifact_scrub",
            "beta_batch_http_completes_receipts_when_wire_kms_fails",
            "beta_batch_http_rejects_retained_response_with_wrong_receipt_mapping",
            "beta_batch_http_never_creates_a_missing_batch_row_through_single_submit",
        )
    },
    "canvas_operation_http::tests::native_socket_case": "scripts/run_canvas_timeout_consumer_oracle.py",
    "internal_application_diagnostics::tests::actual_tracing_event_child": (
        "internal_application_diagnostics::tests::actual_tracing_event_fields_are_stable_in_isolated_process"
    ),
}
CASE = r"[A-Za-z_][A-Za-z0-9_:]*"
# Stable libtest's separate result log is unaffected by stdout inherited by a
# tested process. --logfile is deprecated but supported by pinned Rust 1.95;
# the real-harness regression check must fail visibly if that interface changes.
CASE_RESULT = re.compile(rf"^(ok|failed|ignored) ({CASE})$")
IGNORED_RESULT = re.compile(rf"^ignored: .* ({CASE})$")
SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
    r"(\d+) ignored; (\d+) measured; (\d+) filtered out; finished in .+$"
)


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def compiler_target_source_inputs(executable: Path) -> dict[str, object]:
    """Observe one compiled test target's Rustc depfile, not Cargo dependencies."""
    depfile = executable.with_suffix(".d")
    try:
        if depfile.is_symlink() or not depfile.is_file():
            raise ValueError("missing compiler depfile")
        first = depfile.read_text(encoding="utf-8").splitlines()[0]
        target, separator, dependencies = first.partition(": ")
        declared_target = Path(target)
        if not declared_target.is_absolute():
            declared_target = ROOT / "rust" / declared_target
        if (
            not separator
            or declared_target.resolve(strict=True) != depfile.resolve(strict=True)
            or "\\ " in dependencies
            or not dependencies.strip()
        ):
            raise ValueError("unrecognized compiler depfile")
        root = ROOT.resolve(strict=True)
        paths = set()
        for token in dependencies.split():
            candidate = Path(token)
            if not candidate.is_absolute():
                candidate = ROOT / "rust" / candidate
            if candidate.is_symlink():
                raise ValueError("linked compiler source input")
            resolved = candidate.resolve(strict=True)
            if not resolved.is_file():
                raise ValueError("invalid compiler source input")
            paths.add(resolved.relative_to(root).as_posix())
        return {
            "compiler_depfile_sha256": digest(depfile),
            "compiler_target_source_scope": "single_rustc_test_target",
            "observed_compiler_target_source_inputs": [
                {"path": path, "sha256": digest(ROOT / path)}
                for path in sorted(paths)
            ],
        }
    except (OSError, UnicodeError, ValueError, IndexError) as error:
        raise ValueError("compiler_target_source_input_drift") from error


def canvas_published_image_inputs() -> dict[str, object]:
    """Record the two immutable published-image inputs without environment data."""
    path = "contracts/canvas-worker-consumer-range-oracle.json"
    pin_path = ROOT / path
    try:
        if pin_path.is_symlink() or not pin_path.is_file():
            raise ValueError("missing or linked pin source")
        pins = json.loads(pin_path.read_text(encoding="utf-8"))
        postgres = pins["observed_postgres_image"]
        probe = pins["observed_image"]
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
        raise ValueError("canvas_published_image_pin_drift") from error
    image = re.compile(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}\Z")
    if not all(isinstance(value, str) and image.fullmatch(value)
               for value in (postgres, probe)):
        raise ValueError("canvas_published_image_pin_drift")
    selected = os.environ.get("MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE")
    if selected == postgres:
        selection = "canonical"
    elif selected == f"mirror.gcr.io/library/{postgres}":
        selection = "digest_preserving_mirror"
    elif os.environ.get("GITHUB_ACTIONS") == "true":
        # The runner must have pulled one of the exact references before any
        # Canvas case executes. Never publish an arbitrary environment value.
        raise ValueError("canvas_published_postgres_selection_drift")
    else:
        selection = "unverified_local"
    return {
        "pin_source": path,
        "pin_source_sha256": digest(pin_path),
        "postgres_reference": postgres,
        "postgres_selection": selection,
        "probe_reference": probe,
        "source_closure": "incomplete",
    }


ACCEPTANCE_RUST_TEST_SOURCES = {
    "flow_acceptance": (
        "rust/crates/flow-acceptance/tests/flow_published_schema_contract.rs"
    ),
    "selfhost_acceptance": (
        "rust/crates/selfhost-acceptance/tests/selfhost_public_image_contract.rs"
    ),
    "canvas_composition_acceptance": (
        "rust/crates/canvas-acceptance/tests/canvas_published_schema_contract.rs"
    ),
    "canvas_worker_acceptance": (
        "rust/crates/canvas-worker-acceptance/tests/canvas_published_worker_contract.rs"
    ),
}


def acceptance_rust_first_hop_inputs(name: str) -> list[dict[str, str]]:
    """Observe direct Rust test imports and literals, not their transitive graph."""
    source_path = ACCEPTANCE_RUST_TEST_SOURCES[name]
    source = ROOT / source_path
    try:
        if source.is_symlink() or not source.is_file():
            raise ValueError("invalid Rust test source")
        content = source.read_text(encoding="utf-8")
        module_paths = re.findall(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]', content)
        included_source_paths = re.findall(r'\binclude!\s*\(\s*"([^"]+)"\s*\)', content)
        literal_paths = re.findall(
            r'\binclude_(?:str|bytes)!\s*\(\s*"([^"]+)"\s*\)', content
        )
        if (
            len(module_paths) != len(re.findall(r"#\s*\[\s*path\b", content))
            or len(included_source_paths) != len(re.findall(r"\binclude!\s*\(", content))
            or len(literal_paths) != len(re.findall(r"\binclude_(?:str|bytes)!\s*\(", content))
        ):
            raise ValueError("unrecognized Rust source input")
        package, target, _ = obligation(name)
        manifest_path = (
            ROOT / "rust/crates" / package.removeprefix("marty-") / "Cargo.toml"
        )
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        declared = [
            entry for entry in manifest.get("test", []) if entry.get("name") == target
        ]
        if (
            manifest["package"]["name"] != package
            or len(declared) != 1
            or declared[0].get("path")
            != source.relative_to(manifest_path.parent).as_posix()
        ):
            raise ValueError("unrecognized acceptance test target")
        paths = {source_path}
        for relative in (*module_paths, *included_source_paths, *literal_paths):
            candidate = source.parent / relative
            if candidate.is_symlink():
                raise ValueError("linked Rust source input")
            resolved = candidate.resolve(strict=True)
            path = resolved.relative_to(ROOT.resolve(strict=True))
            if not resolved.is_file():
                raise ValueError("invalid Rust source input")
            paths.add(path.as_posix())
        return [{"path": path, "sha256": digest(ROOT / path)} for path in sorted(paths)]
    except (OSError, UnicodeError, ValueError, KeyError) as error:
        raise ValueError("acceptance_rust_source_input_drift") from error


def obligation(name: str) -> tuple[str, str, list[dict[str, str]]]:
    """The dispatch owner's declared inputs; environment values never leave it."""
    postgres = "ISSUANCE_POSTGRES_TEST_URL"
    entries = {
        "general_contracts": (
            "marty-revocation-profile",
            "contracts",
            (
                "MARTY_TEST_POSTGRES_URL",
                "MARTY_TEST_REDIS_URL",
                "MARTY_TEST_REVOCATION_MIGRATION_DATABASE_URL",
                "MARTY_TEST_REVOCATION_MIGRATION_DATABASE_NAME",
            ),
        ),
        "signing_registry": (
            "marty-signing-keys",
            "registry_storage_contract",
            ("MARTY_TEST_REDIS_URL",),
        ),
        "signing_document": (
            "marty-signing-keys",
            "document_storage_contract",
            (
                "MARTY_TEST_REDIS_URL",
                "MARTY_TEST_REDIS_DISPOSABLE_NONCE",
            ),
        ),
        "issuer_profile": (
            "marty-signing-keys",
            "issuer_profile_storage_contract",
            ("MARTY_TEST_REDIS_URL", "MARTY_TEST_REDIS_DISPOSABLE_NONCE"),
        ),
        "credential_template": (
            "marty-credential-template",
            "postgres_integration",
            ("CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL",),
        ),
        "credential_template_migration": (
            "marty-credential-template",
            "migration_contract",
            ("CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL",),
        ),
        "presentation_policy": (
            "marty-presentation-policy",
            "postgres_integration",
            ("PRESENTATION_POLICY_POSTGRES_TEST_URL",),
        ),
        "trust_profile_migration": (
            "marty-trust-profile",
            "migration_contract",
            ("TEST_POSTGRES_URL",),
        ),
        "organization_migration": (
            "marty-organization",
            "migration_contract",
            ("ORGANIZATION_POSTGRES_TEST_URL",),
        ),
        "organization_application": (
            "marty-organization",
            "application_postgres_integration",
            ("ORGANIZATION_POSTGRES_TEST_URL",),
        ),
        "organization_repository": (
            "marty-organization",
            "postgres_integration",
            ("ORGANIZATION_POSTGRES_TEST_URL",),
        ),
    }
    for label, target, variable in (
        ("issuance_oid4vci_migration", "oid4vci_migration_postgres_contract", postgres),
        ("issuance_transaction", "issuance_transaction_postgres_contract", postgres),
        ("issuance_credential", "credential_postgres_contract", postgres),
        (
            "retention",
            "retention_postgres_contract",
            "MARTY_RETENTION_POSTGRES_TEST_URL",
        ),
        ("passport", "passport_postgres_contract", "MARTY_PASSPORT_POSTGRES_TEST_URL"),
        ("application_template", "application_template_postgres_contract", postgres),
        ("internal_application", "internal_application_postgres_contract", postgres),
    ):
        entries[label] = ("marty-issuance-service", target, (variable,))
    canvas = {
        "canvas_award_candidate",
        "canvas_event_status",
        "canvas_lti_deep_linking",
        "canvas_lti_evidence",
        "canvas_lti_login",
        "canvas_lti_sync_enqueue",
        "canvas_management",
        "canvas_mirror",
        "canvas_oauth",
        "canvas_sync_worker",
        "proof_nonce",
    }
    for prefix in canvas:
        target = f"{prefix}_postgres_contract"
        entries[target] = (
            "marty-issuance-service",
            target,
            ("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL",),
        )
    entries["flow_acceptance"] = (
        "marty-flow-acceptance",
        "flow_published_schema_contract",
        (
            "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST",
            "MARTY_ISSUANCE_TEST_BINARY",
            "MARTY_BASE_COMPOSE_BINARY",
            "MARTY_DIDCOMM_TEST_PYTHON",
            "MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE",
        ),
    )
    entries["selfhost_acceptance"] = (
        "marty-selfhost-acceptance",
        "selfhost_public_image_contract",
        (
            "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST",
            "MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE",
            "MARTY_SELFHOST_TEST_IMAGE",
            "MARTY_SELFHOST_TEST_REVISION",
            "MARTY_SELFHOST_TEST_PACKAGER_BINARY",
            "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE",
        ),
    )
    entries["canvas_composition_acceptance"] = (
        "marty-canvas-acceptance",
        "canvas_published_schema_contract",
        (
            "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST",
            "MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE",
            "MARTY_ISSUANCE_TEST_BINARY",
            "MARTY_CANVAS_OPENBAO_URL",
            "MARTY_CANVAS_OPENBAO_ROOT_TOKEN",
            "MARTY_CANVAS_OPENBAO_CA_CERT_FILE",
        ),
    )
    entries["canvas_worker_acceptance"] = (
        "marty-canvas-worker-acceptance",
        "canvas_published_worker_contract",
        (
            "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST",
            "MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE",
            "MARTY_CANVAS_WORKER_TEST_BINARY",
        ),
    )
    entries["renewal_unit"] = (
        "marty-issuance-service",
        "marty_issuance_service",
        (),
    )
    entries["issuance_library_unit"] = entries["renewal_unit"]
    if name not in entries:
        raise ValueError("unknown_dispatch")
    package, target, variables = entries[name]
    inputs = [
        {
            "name": variable,
            "consumer": package,
            "owner": RUNNER_OWNER,
            "provisioner": ".github/workflows/ci.yml"
            if variable.endswith("URL")
            or variable == "MARTY_TEST_REDIS_DISPOSABLE_NONCE"
            else RUNNER_OWNER,
            "requirement": "required",
        }
        for variable in variables
    ]
    if name == "flow_acceptance":
        for item in inputs:
            item["owner"] = "Flow acceptance runner (selected by call site)"
            item["provisioner"] = (
                ".github/workflows/ci.yml"
                if item["name"]
                in {"MARTY_BASE_COMPOSE_BINARY", "MARTY_DIDCOMM_TEST_PYTHON"}
                else "Flow acceptance runner (selected by call site)"
            )
    if name == "selfhost_acceptance":
        for item in inputs:
            item["owner"] = SELFHOST_OWNER
            item["provisioner"] = (
                ".github/workflows/ci.yml"
                if item["name"].startswith("MARTY_SELFHOST_TEST_")
                or item["name"] == "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE"
                else SELFHOST_OWNER
            )
    if name in CANVAS_EVIDENCE_NAMES:
        for item in inputs:
            item["owner"] = "scripts/ci/run-published-canvas-contracts.sh"
            item["provisioner"] = "scripts/ci/run-published-canvas-contracts.sh"
        inputs.append(
            {
                "name": "MARTY_CANVAS_FULL_QUALIFICATION",
                "consumer": package,
                "owner": "scripts/ci/run-published-canvas-contracts.sh",
                "provisioner": ".github/workflows/ci.yml",
                "requirement": "default_routine_or_explicit_full",
            }
        )
        if name == "canvas_worker_acceptance":
            inputs.extend(
                {
                    "name": variable,
                    "consumer": package,
                    "owner": "scripts/ci/run-published-canvas-contracts.sh",
                    "provisioner": "scripts/ci/run-published-canvas-contracts.sh",
                    "requirement": "parallel_target_only",
                }
                for variable in (
                    "MARTY_CANVAS_WORKER_RETRY_AFTER_TIER",
                    "MARTY_CANVAS_WORKER_VALIDATION_TIER",
                )
            )
    # These tests use a Rust-owned HTTPS Signing Keys fixture by default, or an
    # explicitly supplied live route. Record the conditional dependency names,
    # without treating absent optional route inputs as absent test execution.
    if target in {
        "canvas_oauth_postgres_contract",
        "canvas_sync_worker_postgres_contract",
    }:
        inputs.extend(
            {
                "name": variable,
                "consumer": package,
                "owner": "rust/services/issuance/tests/support/remote_integration_secret.rs",
                "provisioner": "Rust-owned fixture or caller-supplied live route",
                "requirement": "optional_live_route",
            }
            for variable in (
                "MARTY_TEST_SIGNING_KEYS_INTERNAL_URL",
                "MARTY_TEST_SIGNING_KEYS_INTEGRATION_SECRET_KEY",
                "MARTY_TEST_SIGNING_KEYS_INTERNAL_CA_FILE",
            )
        )
    return package, target, inputs


def artifact_identity(
    executable: Path,
    package: str,
    target: str,
    *,
    library_test: bool = False,
    record_compiler_inputs: bool = False,
) -> dict:
    executable_sha256 = digest(executable)
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            raise ValueError("missing_runner_temp")
        return {
            "provenance": "local_unrecorded",
            "executable_sha256": executable_sha256,
        }
    artifacts = Path(runner_temp) / "rust-test-artifacts.json"
    matches = []
    for line in artifacts.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if value.get("reason") != "compiler-artifact" or not value.get("executable"):
            continue
        if (
            value["package_id"].rsplit("#", 1)[-1].split("@", 1)[0] == package
            and value["target"]["name"] == target
            and ("lib" if library_test else "test") in value["target"]["kind"]
            and (not library_test or value.get("profile", {}).get("test") is True)
        ):
            matches.append(value)
    if library_test and len(matches) != 1:
        raise ValueError("missing_or_ambiguous_compiler_artifact")
    # Match the existing resolver's unique-path requirement. Workflow preparation
    # copies several binaries to readable aliases; prove byte identity to their
    # same-run Cargo executable instead of rejecting those deliberate copies.
    matches = list({row["executable"]: row for row in matches}.values())
    if len(matches) != 1:
        raise ValueError("missing_or_ambiguous_compiler_artifact")
    [artifact] = matches
    recorded_executable = Path(artifact["executable"])
    same_path = recorded_executable.resolve() == executable.resolve()
    if not recorded_executable.is_file():
        raise ValueError("missing_compiler_artifact_executable")
    if not same_path and digest(recorded_executable) != executable_sha256:
        raise ValueError("compiler_artifact_content_mismatch")
    identity = {
        "provenance": "same_run_compiler_artifact",
        "compiler_artifacts_sha256": digest(artifacts),
        "features": artifact.get("features", []),
        "binding": "same_path" if same_path else "byte_identical_copy",
        "executable_sha256": executable_sha256,
    }
    if record_compiler_inputs:
        identity.update(compiler_target_source_inputs(recorded_executable))
    return identity


def libtest_harness(package: str, target: str) -> dict:
    service = (
        "issuance"
        if package == "marty-issuance-service"
        else package.removeprefix("marty-")
    )
    if (package, target) == ("marty-flow-acceptance", "flow_published_schema_contract"):
        manifest_path = ROOT / "rust/crates/flow-acceptance/Cargo.toml"
    elif (package, target) == (
        "marty-selfhost-acceptance",
        "selfhost_public_image_contract",
    ):
        manifest_path = ROOT / "rust/crates/selfhost-acceptance/Cargo.toml"
    elif (package, target) in {
        ("marty-canvas-acceptance", "canvas_published_schema_contract"),
        ("marty-canvas-worker-acceptance", "canvas_published_worker_contract"),
    }:
        manifest_path = (
            ROOT / "rust/crates" / package.removeprefix("marty-") / "Cargo.toml"
        )
    else:
        manifest_path = ROOT / "rust/services" / service / "Cargo.toml"
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["package"]["name"] != package:
        raise ValueError("foreign_harness_manifest")
    if (package, target) == ("marty-issuance-service", "marty_issuance_service"):
        if (manifest_path.parent / "src/lib.rs").is_file() and not manifest.get("lib"):
            return {
                "manifest": manifest_path.relative_to(ROOT).as_posix(),
                "manifest_sha256": digest(manifest_path),
                "harness": "libtest",
            }
        raise ValueError("unsupported_library_harness")
    declared = [
        entry for entry in manifest.get("test", []) if entry.get("name") == target
    ]
    if declared:
        if (
            len(declared) != 1
            or not declared[0].get("harness", True)
            or not declared[0].get("test", True)
        ):
            raise ValueError("unsupported_test_harness")
    elif (
        not manifest["package"].get("autotests", True)
        or not (manifest_path.parent / "tests" / f"{target}.rs").is_file()
    ):
        raise ValueError("missing_libtest_target")
    return {
        "manifest": manifest_path.relative_to(ROOT).as_posix(),
        "manifest_sha256": digest(manifest_path),
        "harness": "libtest",
    }


def selection(
    arguments: list[str], *, allow_nocapture: bool = False, allow_skip: bool = False
) -> tuple[list[str], str]:
    mode = "default"
    selectors = []
    skip_value = False
    for argument in arguments:
        if skip_value:
            if not re.fullmatch(CASE, argument):
                raise ValueError("invalid_skip_selector")
            selectors.append(argument)
            skip_value = False
            continue
        if argument == "--skip":
            if not allow_skip:
                raise ValueError("unsupported_selection_argument")
            selectors.append(argument)
            skip_value = True
            continue
        if argument in {"--ignored", "--include-ignored"}:
            if mode != "default":
                raise ValueError("ambiguous_ignored_selection")
            mode = argument.removeprefix("--")
        elif (
            argument == "--exact"
            or (argument == "--nocapture" and allow_nocapture)
            or re.fullmatch(r"--test-threads=[1-9][0-9]*", argument)
        ):
            selectors.append(argument)
        elif re.fullmatch(CASE, argument):
            selectors.append(argument)
        else:
            raise ValueError("unsupported_selection_argument")
    if skip_value:
        raise ValueError("missing_skip_selector")
    return selectors, mode


def list_cases(command: list[str]) -> set[str]:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError("libtest_discovery_failed")
    return parse_case_listing(result.stdout)


def parse_case_listing(output: str) -> set[str]:
    cases = []
    for line in output.splitlines():
        if match := re.fullmatch(rf"({CASE}): test", line):
            cases.append(match[1])
        elif line and not re.fullmatch(r"\d+ tests?, \d+ benchmarks?", line):
            raise ValueError("unrecognized_libtest_discovery")
    if len(cases) != len(set(cases)):
        raise ValueError("duplicate_discovered_case")
    return set(cases)


def verify_flow_roster(executable: str, expected: set[str], ignored: set[str]) -> None:
    # One shared exact roster is owned by the existing Flow script. Do not
    # replicate its names in this evidence collector.
    roster = subprocess.run(
        ["bash", str(ROOT / "scripts/ci/list-flow-acceptance-cases.sh"), executable],
        capture_output=True,
        text=True,
        check=False,
    )
    if roster.returncode or ignored or parse_case_listing(roster.stdout) != expected:
        raise ValueError("flow_roster_drift")


def verify_renewal_unit_roster(
    arguments: list[str], expected: set[str], ignored: set[str]
) -> None:
    if (
        arguments != [RENEWAL_UNIT_PREFIX, "--test-threads=4"]
        or expected != RENEWAL_UNIT_CASES
        or ignored
    ):
        raise ValueError("renewal_unit_roster_drift")


def verify_library_unit_roster(
    arguments: list[str], expected: set[str], ignored: set[str]
) -> None:
    if (
        arguments != ["--test-threads=4"]
        or not RENEWAL_UNIT_CASES <= expected
        or ignored != set(LIBRARY_UNIT_IGNORED_OWNERS)
        or expected & ignored
    ):
        raise ValueError("library_unit_roster_drift")


def flow_source_inputs(owner: str) -> list[dict[str, str]]:
    # These are the runner's direct non-Cargo inputs, not a claim that every
    # internally spawned process or rendered configuration is inventoried.
    paths = (
        "contracts/canvas-worker-consumer-range-oracle.json",
        "scripts/ci/pull-pinned-dockerhub-image.sh",
        "scripts/ci/list-flow-acceptance-cases.sh",
        FLOW_OWNERS[owner],
    )
    return [{"path": path, "sha256": digest(ROOT / path)} for path in paths]


def flow_rendered_first_hop_inputs() -> list[dict[str, str]]:
    # The compiled Flow test invokes this Python renderer, which loads two
    # helpers with runpy. This is only the first non-Cargo hop: the helpers
    # read further scripts and Compose models, so it cannot authorize a skip.
    paths = (
        "scripts/render_flow_native_runtime_fixture.py",
        "scripts/test_base_native_issuance_compose.py",
        "scripts/test_selfhost_native_owner_compose.py",
    )
    caller = (
        ROOT / "rust/crates/flow-acceptance/tests/support/flow_rendered_selection.rs"
    ).read_text(encoding="utf-8")
    if re.findall(r'\.arg\(root\(\)\.join\("([^"]+)"\)\)', caller) != [paths[0]]:
        raise ValueError("flow_renderer_source_drift")
    try:
        if _flow_renderer_runpy_edges(paths[0]) != paths[1:]:
            raise ValueError("flow_renderer_source_drift")
    except ValueError as error:
        raise ValueError("flow_renderer_source_drift") from error
    return [{"path": path, "sha256": digest(ROOT / path)} for path in paths]


FLOW_RENDERER_RUNPY_EDGES = {
    "scripts/render_flow_native_runtime_fixture.py": (
        "scripts/test_base_native_issuance_compose.py",
        "scripts/test_selfhost_native_owner_compose.py",
    ),
    "scripts/test_base_native_issuance_compose.py": (
        "scripts/test_beta_application_image_compose.py",
        "scripts/conformance_native.py",
        "scripts/test_conformance_native_compose.py",
    ),
    "scripts/test_selfhost_native_owner_compose.py": (
        "scripts/test_canvas_worker_compose_render.py",
        "scripts/test_beta_application_image_compose.py",
        "scripts/test_base_native_issuance_compose.py",
    ),
    "scripts/test_beta_application_image_compose.py": (
        "scripts/test_canvas_worker_compose_render.py",
    )
    * 4,
    "scripts/conformance_native.py": (
        "scripts/validate_beta_didcomm_configuration.py",
        "scripts/prepare_official_beta_release.py",
    ),
    "scripts/test_conformance_native_compose.py": (
        "scripts/conformance_stack.py",
        "scripts/conformance_native.py",
        "scripts/test_canvas_worker_compose_render.py",
        "scripts/test_beta_application_image_compose.py",
    ),
    "scripts/test_canvas_worker_compose_render.py": ("scripts/conformance_stack.py",),
    "scripts/conformance_stack.py": ("scripts/conformance_native.py",),
    "scripts/validate_beta_didcomm_configuration.py": (),
    "scripts/prepare_official_beta_release.py": ("scripts/kms_core_release.py",),
    "scripts/kms_core_release.py": (),
}


def flow_renderer_python_imports() -> list[dict[str, object]]:
    """Inventory static imports; reject unobserved direct local loaders."""
    observed = []
    suffixes = (
        *importlib.machinery.SOURCE_SUFFIXES,
        *importlib.machinery.BYTECODE_SUFFIXES,
        *importlib.machinery.EXTENSION_SUFFIXES,
    )
    for path in FLOW_RENDERER_RUNPY_EDGES:
        try:
            tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeError, OSError) as error:
            raise ValueError("flow_renderer_import_drift") from error
        parents = {
            child: node
            for node in ast.walk(tree)
            for child in ast.iter_child_nodes(node)
        }
        runpy_imports = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            and any(alias.name == "runpy" for alias in node.names)
        ]
        expected_runpy = bool(FLOW_RENDERER_RUNPY_EDGES[path])
        if len(runpy_imports) != int(expected_runpy) or (
            expected_runpy and runpy_imports[0] not in tree.body
        ):
            raise ValueError("flow_renderer_import_drift")
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.split(".", 1)[0]
                    if (
                        module in {"importlib", "builtins"}
                        or (module == "runpy" and alias.asname)
                        or alias.asname == "runpy"
                    ):
                        raise ValueError("flow_renderer_import_drift")
                    modules.add(module)
            elif isinstance(node, ast.ImportFrom):
                if node.level or node.module is None:
                    raise ValueError("flow_renderer_import_drift")
                module = node.module.split(".", 1)[0]
                if module in {"runpy", "importlib", "builtins"} or any(
                    alias.asname == "runpy" for alias in node.names
                ):
                    raise ValueError("flow_renderer_import_drift")
                modules.add(module)
            elif isinstance(node, ast.arg) and node.arg == "runpy":
                raise ValueError("flow_renderer_import_drift")
            elif (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.name == "runpy"
            ):
                raise ValueError("flow_renderer_import_drift")
            elif isinstance(node, ast.ExceptHandler) and node.name == "runpy":
                raise ValueError("flow_renderer_import_drift")
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == "runpy":
                raise ValueError("flow_renderer_import_drift")
            elif isinstance(node, ast.MatchMapping) and node.rest == "runpy":
                raise ValueError("flow_renderer_import_drift")
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                if node.id in {
                    "__builtins__",
                    "__import__",
                    "exec",
                    "eval",
                    "getattr",
                    "globals",
                    "locals",
                    "vars",
                    "run_path",
                    "run_module",
                    "import_module",
                    "spec_from_file_location",
                    "module_from_spec",
                }:
                    raise ValueError("flow_renderer_import_drift")
                if node.id == "runpy":
                    attribute = parents.get(node)
                    call = parents.get(attribute)
                    if not (
                        isinstance(attribute, ast.Attribute)
                        and attribute.attr == "run_path"
                        and isinstance(call, ast.Call)
                        and call.func is attribute
                    ):
                        raise ValueError("flow_renderer_import_drift")
            elif isinstance(node, ast.Name) and node.id == "runpy":
                raise ValueError("flow_renderer_import_drift")
            elif isinstance(node, ast.Attribute):
                if node.attr == "run_path":
                    if not (
                        isinstance(node.value, ast.Name)
                        and node.value.id == "runpy"
                        and isinstance(parents.get(node), ast.Call)
                        and parents[node].func is node
                    ):
                        raise ValueError("flow_renderer_import_drift")
                elif node.attr in {
                    "import_module",
                    "run_module",
                    "__import__",
                    "__dict__",
                    "modules",
                    "exec",
                    "eval",
                    "spec_from_file_location",
                    "module_from_spec",
                }:
                    raise ValueError("flow_renderer_import_drift")
        modules.discard("__future__")
        if not modules <= (sys.stdlib_module_names | {"yaml"}):
            raise ValueError("flow_renderer_import_drift")
        for module in modules:
            for directory in (ROOT, ROOT / "scripts"):
                local_package = directory / module
                if local_package.exists() or local_package.is_symlink() or any(
                    (directory / f"{module}{suffix}").exists()
                    or (directory / f"{module}{suffix}").is_symlink()
                    for suffix in suffixes
                ):
                    raise ValueError("flow_renderer_import_drift")
        observed.append({"path": path, "modules": sorted(modules)})
    return observed


def _flow_renderer_runpy_edges(path: str) -> tuple[str, ...]:
    try:
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    except SyntaxError as error:
        raise ValueError("flow_renderer_subgraph_drift") from error
    edges = []
    uses_root = False
    calls = sorted(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "runpy"
            and node.func.attr == "run_path"
        ),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for call in calls:
        if call.keywords or len(call.args) != 1:
            raise ValueError("flow_renderer_subgraph_drift")
        argument = call.args[0]
        if not (
            isinstance(argument, ast.Call)
            and isinstance(argument.func, ast.Name)
            and argument.func.id == "str"
            and len(argument.args) == 1
            and not argument.keywords
        ):
            raise ValueError("flow_renderer_subgraph_drift")
        value = argument.args[0]
        if (
            isinstance(value, ast.BinOp)
            and isinstance(value.op, ast.Div)
            and isinstance(value.left, ast.Name)
            and value.left.id == "ROOT"
            and isinstance(value.right, ast.Constant)
            and isinstance(value.right.value, str)
        ):
            uses_root = True
            edge = value.right.value
        elif (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "with_name"
            and isinstance(value.func.value, ast.Call)
            and isinstance(value.func.value.func, ast.Name)
            and value.func.value.func.id == "Path"
            and len(value.func.value.args) == 1
            and isinstance(value.func.value.args[0], ast.Name)
            and value.func.value.args[0].id == "__file__"
            and len(value.args) == 1
            and isinstance(value.args[0], ast.Constant)
            and isinstance(value.args[0].value, str)
            and not value.keywords
        ):
            edge = f"scripts/{value.args[0].value}"
        else:
            raise ValueError("flow_renderer_subgraph_drift")
        if edge not in FLOW_RENDERER_RUNPY_EDGES:
            raise ValueError("flow_renderer_subgraph_drift")
        edges.append(edge)
    if uses_root:
        canonical = ast.parse("ROOT = Path(__file__).resolve().parents[1]").body[0]
        path_imports = [
            node
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
            and node.module == "pathlib"
            and any(alias.name == "Path" and alias.asname is None for alias in node.names)
        ]
        stores = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == "ROOT"
            and isinstance(node.ctx, ast.Store)
        ]
        assignments = [
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "ROOT"
                for target in node.targets
            )
        ]
        if (
            len(path_imports) != 1
            or len(stores) != 1
            or len(assignments) != 1
            or ast.dump(assignments[0]) != ast.dump(canonical)
        ):
            raise ValueError("flow_renderer_subgraph_drift")
    return tuple(edges)


def _flow_compose_edges(path: str) -> dict[str, str]:
    """Resolve Compose YAML (including anchors) without recording values."""
    # The flow lane adds its pinned PyYAML venv to GITHUB_PATH before invoking
    # this recorder. Keep the import local so other runner lanes stay stdlib-only.
    try:
        import yaml
    except ImportError as error:
        raise ValueError("flow_renderer_subgraph_drift") from error
    try:
        model = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    except (yaml.YAMLError, ValueError, OSError) as error:
        raise ValueError("flow_renderer_subgraph_drift") from error
    if not isinstance(model, dict) or "include" in model:
        raise ValueError("flow_renderer_subgraph_drift")
    services = model.get("services")
    if not isinstance(services, dict):
        raise ValueError("flow_renderer_subgraph_drift")
    edges = {}
    for name, service in services.items():
        if not isinstance(service, dict):
            raise ValueError("flow_renderer_subgraph_drift")
        if "include" in service:
            raise ValueError("flow_renderer_subgraph_drift")
        if "extends" in service:
            extension = service["extends"]
            if not (
                isinstance(extension, dict)
                and set(extension) == {"file", "service"}
                and extension["service"] == "issuance-native"
                and isinstance(extension["file"], str)
            ):
                raise ValueError("flow_renderer_subgraph_drift")
            edges[name] = extension["file"]
    return edges


def _flow_literal_assignment(path: str, name: str) -> str:
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == name
    ]
    if (
        len(assignments) != 1
        or not isinstance(assignments[0].value, ast.Constant)
        or not isinstance(assignments[0].value.value, str)
    ):
        raise ValueError("flow_renderer_subgraph_drift")
    return assignments[0].value.value


def flow_renderer_subgraph_inputs() -> list[dict[str, str]]:
    """Observed static runpy graph and selected source files, not runtime closure."""
    flow_rendered_first_hop_inputs()
    flow_renderer_python_imports()
    for path, expected in FLOW_RENDERER_RUNPY_EDGES.items():
        if _flow_renderer_runpy_edges(path) != expected:
            raise ValueError("flow_renderer_subgraph_drift")
    # These are the literal models selected by render(), plus extends files.
    # Generated images.env, secrets, loader outputs and external tools are not
    # source files and are deliberately not hashed into this evidence.
    compose = (
        "docker-compose.base.yml",
        "docker-compose.profile.issuance-native.yml",
        "docker-compose.service.issuance-native-runtime.yml",
        "docker-compose.selfhost.prod.yml",
        "selfhost-kms-only-model.keyless-tls.snapshot.yml",
        "docker-compose.service.issuance-native.yml",
    )
    expected_compose_edges = {
        compose[0]: {"issuance-native": compose[1]},
        compose[1]: {"issuance-native": compose[2]},
        compose[2]: {},
        compose[3]: {"issuance-native": compose[2]},
        compose[4]: {"issuance-native": compose[2]},
        compose[5]: {"issuance-native": compose[2]},
    }
    for path, expected in expected_compose_edges.items():
        if _flow_compose_edges(path) != expected:
            raise ValueError("flow_renderer_subgraph_drift")
    for path, name, expected in (
        ("scripts/test_base_native_issuance_compose.py", "PROFILE", compose[1]),
        ("scripts/test_conformance_native_compose.py", "RUNTIME", compose[2]),
        ("scripts/test_conformance_native_compose.py", "COMMON", compose[5]),
        ("scripts/test_selfhost_native_owner_compose.py", "APPROVED", compose[4]),
        ("scripts/test_canvas_worker_compose_render.py", "BASE", compose[3]),
    ):
        if _flow_literal_assignment(path, name) != expected:
            raise ValueError("flow_renderer_subgraph_drift")
    # The renderer calls this helper with fixed flags. Match its complete AST
    # so an added or conditional Compose input cannot silently escape the set.
    helper_tree = ast.parse(
        (ROOT / "scripts/test_base_native_issuance_compose.py").read_text(
            encoding="utf-8"
        )
    )
    file_functions = [
        node
        for node in helper_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "files"
    ]
    expected_files_function = ast.parse(
        """def files(*, native, local, authcrypt):
    result = [ROOT / "docker-compose.base.yml"]
    if not local:
        result.append(ROOT / "docker-compose.profile.ghcr.yml")
    if native:
        result.append(ROOT / PROFILE)
        if not local:
            result.append(ROOT / IMAGES)
        if authcrypt:
            result.append(ROOT / POLICY_PROFILE)
    return result
"""
    ).body[0]
    if len(file_functions) != 1 or ast.dump(file_functions[0]) != ast.dump(
        expected_files_function
    ):
        raise ValueError("flow_renderer_subgraph_drift")
    renderer_tree = ast.parse(
        (ROOT / "scripts/render_flow_native_runtime_fixture.py").read_text(
            encoding="utf-8"
        )
    )
    render_functions = [
        node
        for node in renderer_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "render"
    ]
    if len(render_functions) != 1:
        raise ValueError("flow_renderer_subgraph_drift")
    selected_calls = sorted(
        ast.unparse(node)
        for node in ast.walk(render_functions[0])
        if isinstance(node, ast.Call)
        and ast.unparse(node.func) in {"BASE['source']", "BASE['files']", "compose"}
    )
    expected_calls = sorted(
        ast.unparse(ast.parse(expression, mode="eval").body)
        for expression in (
            'BASE["source"]("docker-compose.base.yml")',
            'BASE["source"](BASE["PROFILE"])',
            'BASE["source"](BASE["RUNTIME"])',
            'compose(*BASE["files"](native=False, local=True, authcrypt=False))',
            'compose(*BASE["files"](native=True, local=True, authcrypt=False))',
            'BASE["files"](native=False, local=True, authcrypt=False)',
            'BASE["files"](native=True, local=True, authcrypt=False)',
            'compose(ROOT / SELFHOST["APPROVED"])',
            'compose(ROOT / SELFHOST["GATE"]["BASE"])',
        )
    )
    if selected_calls != expected_calls:
        raise ValueError("flow_renderer_subgraph_drift")
    sources = (
        "scripts/load-secrets-env.sh",
        "rust/services/signing-keys/tests/fixtures/public_certificates/root-ca.pem",
        "rust/services/gateway/src/config.rs",
        "rust/services/issuance/src/config.rs",
        "rust/services/issuance/src/canvas_credentials_publication.rs",
    )
    literals = {
        "scripts/render_flow_native_runtime_fixture.py": (
            compose[0],
            sources[1],
        ),
        "scripts/test_base_native_issuance_compose.py": (
            compose[0],
            compose[1],
            sources[2],
            sources[3],
            sources[4],
        ),
        "scripts/test_selfhost_native_owner_compose.py": (
            compose[4],
            sources[2],
            sources[3],
        ),
        "scripts/test_conformance_native_compose.py": (compose[5], compose[2]),
        "scripts/test_canvas_worker_compose_render.py": (compose[0], compose[3]),
        "rust/crates/flow-acceptance/tests/support/flow_rendered_selection.rs": (
            sources[0],
        ),
    }
    for script, expected in literals.items():
        content = (ROOT / script).read_text(encoding="utf-8")
        if any(f'"{path}"' not in content for path in expected):
            raise ValueError("flow_renderer_subgraph_drift")
    paths = (*FLOW_RENDERER_RUNPY_EDGES, *compose, *sources)
    return [{"path": path, "sha256": digest(ROOT / path)} for path in paths]


def selfhost_source_inputs(owner: str) -> list[dict[str, str]]:
    # Direct runner/pin inputs only. The caller separately validates the local
    # image ID; this is not retained image provenance or a full source graph.
    paths = [
        "contracts/canvas-worker-consumer-range-oracle.json",
        "scripts/ci/pull-pinned-dockerhub-image.sh",
        SELFHOST_OWNER,
    ]
    if owner == "selfhost":
        paths.append("scripts/ci/run-db-contract-groups.py")
    return [{"path": path, "sha256": digest(ROOT / path)} for path in paths]


def selfhost_configured_inputs() -> dict[str, str]:
    """Non-secret configured identities, not image or package provenance."""
    image_id = os.environ["MARTY_SELFHOST_TEST_IMAGE"]
    revision = os.environ["MARTY_SELFHOST_TEST_REVISION"]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        raise ValueError("invalid_selfhost_image_id")
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("invalid_selfhost_revision")

    def binary_sha256(variable: str) -> str:
        supplied = Path(os.environ[variable])
        try:
            resolved = supplied.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ValueError("invalid_selfhost_binary") from error
        before = resolved.stat()
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024**3:
            raise ValueError("invalid_selfhost_binary")
        checksum = digest(resolved)
        after = resolved.stat()
        try:
            same_path = supplied.resolve(strict=True) == resolved
        except (OSError, RuntimeError):
            same_path = False
        if not same_path or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("changed_selfhost_binary")
        return checksum

    return {
        "image_id": image_id,
        "source_revision": revision,
        "packager_sha256": binary_sha256("MARTY_SELFHOST_TEST_PACKAGER_BINARY"),
        "compose_sha256": binary_sha256("MARTY_SELFHOST_BUNDLE_TEST_COMPOSE"),
    }


def expected_cases(
    executable: str,
    arguments: list[str],
    *,
    allow_nocapture: bool = False,
    allow_skip: bool = False,
) -> tuple[set[str], set[str]]:
    selectors, mode = selection(
        arguments, allow_nocapture=allow_nocapture, allow_skip=allow_skip
    )
    listing = [
        executable,
        *selectors,
        "--list",
        "--format",
        "terse",
        "--color",
        "never",
    ]
    selected = list_cases(listing)
    ignored = list_cases([*listing, "--ignored"])
    if not ignored <= selected:
        raise ValueError("inconsistent_ignored_discovery")
    if mode == "ignored":
        return ignored, set()
    if mode == "include-ignored":
        return selected, set()
    return selected - ignored, ignored


def case_results(lines: list[str]) -> dict[str, str]:
    cases = {}
    for line in lines:
        if match := CASE_RESULT.fullmatch(line):
            name, outcome = match[2], "FAILED" if match[1] == "failed" else match[1]
        elif match := IGNORED_RESULT.fullmatch(line):
            name, outcome = match[1], "ignored"
        else:
            raise ValueError("unrecognized_libtest_result")
        if name in cases:
            raise ValueError("duplicate_executed_case")
        cases[name] = outcome
    return cases


def verify_execution(
    lines: list[str], result_lines: list[str], expected: set[str], ignored: set[str]
) -> dict:
    cases = case_results(result_lines)
    summaries = [match.groups() for line in lines if (match := SUMMARY.fullmatch(line))]
    executed = {name for name, status in cases.items() if status in {"ok", "FAILED"}}
    actually_ignored = {name for name, status in cases.items() if status == "ignored"}
    if len(summaries) != 1:
        raise ValueError("missing_or_ambiguous_libtest_summary")
    status, passed, failed, skipped, measured, _filtered = summaries[0]
    if (
        executed != expected
        or actually_ignored != ignored
        or int(passed) != sum(value == "ok" for value in cases.values())
        or int(failed) != sum(value == "FAILED" for value in cases.values())
        or int(skipped) != len(ignored)
        or int(measured) != 0
    ):
        raise ValueError("selected_executed_mismatch")
    return {
        "executed": sorted(executed),
        "ignored": sorted(actually_ignored),
        "passed": int(passed),
        "failed": int(failed),
        "summary_status": status,
    }


def emit(evidence: dict) -> None:
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    unit = evidence["schema"] in {
        "marty.rust-unit-obligation/v1",
        "marty.rust-library-obligation/v1",
    }
    runner_temp = os.environ.get("RUNNER_TEMP")
    canvas = evidence["schema"] == "marty.rust-canvas-obligation/v1"
    if runner_temp:
        name = (
            UNIT_EVIDENCE_NAME
            if unit
            else CANVAS_EVIDENCE_NAMES[evidence["name"]]
            if canvas
            else EVIDENCE_NAME
        )
        output = Path(runner_temp) / "rust-build-evidence" / name
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded + "\n")
    # Libtest can leave an unterminated progress row before cancellation.
    print(
        "\n" + (UNIT_PREFIX if unit else CANVAS_PREFIX if canvas else PREFIX) + encoded,
        flush=True,
    )


class HarnessInterrupted(Exception):
    def __init__(self, signum: int):
        self.signum = signum


def settle_owned_child(
    child: subprocess.Popen, initial_signal: int = signal.SIGTERM
) -> None:
    """Stop only this harness's process group, then reap its direct child."""
    if os.name != "posix":
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
        child.wait(timeout=5)
        return

    try:
        os.killpg(child.pid, initial_signal)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        child.poll()
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)


def run_owned_harness(
    command: list[str], result_log: Path, evidence: dict
) -> tuple[int, str]:
    """Keep signals attached to the exact libtest and its owned descendants."""
    child = None
    previous = {}
    interrupted = False
    interruption_signal = signal.SIGTERM
    spawning = True
    pending_signal = None

    def interrupt(signum: int, _frame: object) -> None:
        nonlocal pending_signal
        if spawning:
            pending_signal = signum
            return
        raise HarnessInterrupted(signum)

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, interrupt)
        child = subprocess.Popen(
            [
                *command,
                "--format",
                "pretty",
                "--color",
                "never",
                "--logfile",
                str(result_log),
            ],
            stdout=subprocess.PIPE,
            start_new_session=os.name == "posix",
        )
        spawning = False
        if pending_signal is not None:
            raise HarnessInterrupted(pending_signal)
        output = []
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while chunk := child.stdout.read1(65536):
            decoded = decoder.decode(chunk)
            print(decoded, end="", flush=True)
            output.append(decoded)
        remaining = decoder.decode(b"", final=True)
        print(remaining, end="", flush=True)
        output.append(remaining)
        status = child.wait()
        evidence["command_status"] = status
        return status, "".join(output)
    except HarnessInterrupted as error:
        interrupted = True
        interruption_signal = error.signum
        evidence["command_status"] = 128 + error.signum
        raise
    finally:
        for signum in previous:
            signal.signal(signum, signal.SIG_IGN)
        try:
            if child is not None:
                if interrupted or child.poll() is None:
                    settle_owned_child(child, interruption_signal)
                if child.stdout is not None:
                    child.stdout.close()
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)


def run_contract(name: str, command: list[str], owner: str = "contracts") -> int:
    flow = name == "flow_acceptance"
    selfhost = name == "selfhost_acceptance"
    canvas = name in CANVAS_EVIDENCE_NAMES
    renewal_unit = name == "renewal_unit"
    library_unit = name == "issuance_library_unit"
    unit = renewal_unit or library_unit
    if flow:
        gate = f"test-rust-services/{'flow' if owner == 'flow-pr' else 'canvas'}"
        runner = FLOW_OWNERS.get(owner)
        fixture = FLOW_FIXTURE_OWNER
    elif selfhost:
        gate = f"test-rust-services/{'selfhost' if owner == 'selfhost' else 'canvas'}"
        runner = SELFHOST_OWNER
        fixture = SELFHOST_FIXTURE_OWNER
    elif canvas:
        gate = "test-rust-services/canvas"
        runner = "scripts/ci/run-published-canvas-contracts.sh"
        fixture = "rust/services/issuance/tests/support/canvas_published_database.rs"
    elif unit:
        gate = "test-rust-services/renewal-unit"
        runner = "scripts/ci/rust_db_obligations.py"
        fixture = (
            "rust/services/issuance/src/lib.rs"
            if library_unit
            else "rust/services/issuance/src/canvas_sync_worker_retry_tests.rs"
        )
    else:
        gate = "test-rust-services/contracts"
        runner = RUNNER_OWNER
        fixture = FIXTURE_OWNER
    evidence = {
        "name": name,
        "schema": (
            "marty.rust-library-obligation/v1"
            if library_unit
            else "marty.rust-unit-obligation/v1"
            if renewal_unit
            else "marty.rust-canvas-obligation/v1"
            if canvas
            else "marty.rust-db-obligation/v1"
        ),
        "gate": gate,
        "owner": runner,
        "runtime_fixture_owner": fixture,
        "result_source": "libtest_logfile",
        "run": {key: os.environ.get(key) for key in RUN_IDENTITY},
        "status": "failed",
    }
    status = 1
    try:
        if (
            (flow and owner not in FLOW_OWNERS)
            or (selfhost and owner not in {"selfhost", "canvas"})
            or (canvas and owner != "canvas")
            or (unit and owner != "renewal-unit")
            or (not flow and not selfhost and not canvas and not unit and owner != "contracts")
        ):
            raise ValueError("invalid_dispatch_owner")
        package, target, inputs = obligation(name)
        if flow:
            for item in inputs:
                item["owner"] = FLOW_OWNERS[owner]
                if item["provisioner"] != ".github/workflows/ci.yml":
                    item["provisioner"] = FLOW_OWNERS[owner]
            evidence["direct_source_inputs"] = flow_source_inputs(owner)
            evidence["observed_first_hop_source_inputs"] = (
                flow_rendered_first_hop_inputs()
            )
            evidence["observed_renderer_subgraph_source_inputs"] = (
                flow_renderer_subgraph_inputs()
            )
            evidence["observed_renderer_python_imports"] = (
                flow_renderer_python_imports()
            )
        if selfhost:
            evidence["direct_source_inputs"] = selfhost_source_inputs(owner)
        if canvas:
            qualification = os.environ.get("MARTY_CANVAS_FULL_QUALIFICATION", "0")
            if qualification not in {"0", "1"}:
                raise ValueError("invalid_canvas_qualification_mode")
            evidence["canvas_qualification_mode"] = (
                "full" if qualification == "1" else "routine"
            )
            evidence["published_image_inputs"] = canvas_published_image_inputs()
            if name == "canvas_worker_acceptance":
                tiers = {
                    variable: os.environ.get(variable)
                    for variable in (
                        "MARTY_CANVAS_WORKER_RETRY_AFTER_TIER",
                        "MARTY_CANVAS_WORKER_VALIDATION_TIER",
                    )
                }
                if any(value not in {None, "full", "routine"} for value in tiers.values()):
                    raise ValueError("invalid_canvas_worker_tier")
                if (tiers["MARTY_CANVAS_WORKER_RETRY_AFTER_TIER"] is None) != (
                    tiers["MARTY_CANVAS_WORKER_VALIDATION_TIER"] is None
                ):
                    raise ValueError("incomplete_canvas_worker_tier")
                evidence["worker_tiers"] = tiers
        if flow or selfhost or canvas:
            evidence["observed_first_hop_rust_source_inputs"] = (
                acceptance_rust_first_hop_inputs(name)
            )
            evidence["transitive_source_closure"] = "incomplete"
        evidence.update(
            name=name, package=package, target=target, runtime_inputs=inputs
        )
        if os.environ.get("GITHUB_ACTIONS") == "true" and not all(
            evidence["run"].values()
        ):
            raise ValueError("missing_run_identity")
        executable = Path(command[0])
        evidence.update(
            artifact_identity(executable, package, target, library_test=True)
            if unit
            else artifact_identity(
                executable,
                package,
                target,
                record_compiler_inputs=flow or selfhost or canvas,
            )
        )
        # Never probe --list on custom harnesses, which may ignore the flag and
        # execute their bodies. All current dispatches use standard libtest.
        evidence["harness"] = libtest_harness(package, target)
        selection(
            command[1:], allow_nocapture=flow or selfhost or canvas,
            allow_skip=canvas,
        )  # Validate before evidence.
        evidence["selection_arguments"] = command[1:]
        expected, ignored = expected_cases(
            command[0], command[1:], allow_nocapture=flow or selfhost or canvas,
            allow_skip=canvas,
        )
        if renewal_unit:
            verify_renewal_unit_roster(command[1:], expected, ignored)
        if library_unit:
            verify_library_unit_roster(command[1:], expected, ignored)
            evidence["ignored_case_owners"] = LIBRARY_UNIT_IGNORED_OWNERS
        if flow:
            if os.environ.get("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST") != "1":
                raise ValueError("missing_published_schema_gate")
            verify_flow_roster(command[0], expected, ignored)
        if selfhost:
            if os.environ.get("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST") != "1":
                raise ValueError("missing_published_schema_gate")
            # The shell runner owns the exact names. This bounds its selected
            # cardinality without maintaining a second 17-name roster here.
            if len(expected) != 17 or ignored:
                raise ValueError("selfhost_selection_drift")
        evidence["selected"] = sorted(expected)
        evidence["selected_ignored"] = sorted(ignored)
        if not expected:
            raise ValueError("zero_selected_tests")
        for item in inputs:
            if item["requirement"] == "required" and not os.environ.get(item["name"]):
                raise ValueError("missing_required_runtime_input")
        if selfhost:
            evidence["configured_input_identities"] = selfhost_configured_inputs()
        # Preserve every selection/serialism argument and all live raw output.
        # A separate libtest result stream identifies case completion even when
        # inherited child stdout splits the human `test name ... ok` framing.
        with tempfile.TemporaryDirectory(prefix="marty-libtest-results-") as directory:
            result_log = Path(directory) / "results.log"
            status, output = run_owned_harness(command, result_log, evidence)
            if not result_log.is_file():
                raise ValueError("missing_libtest_result_log")
            result_lines = result_log.read_text(encoding="utf-8").splitlines()
        lines = output.splitlines()
        evidence["observed_cases"] = [
            {"name": name, "outcome": outcome}
            for name, outcome in case_results(result_lines).items()
        ]
        evidence.update(verify_execution(lines, result_lines, expected, ignored))
        if status != 0 or evidence["failed"] or evidence["summary_status"] != "ok":
            raise ValueError("libtest_execution_failed")
        evidence["status"] = "ok"
    except HarnessInterrupted as error:
        status = 128 + error.signum
        evidence["reason"] = "interrupted"
    except (OSError, ValueError, KeyError, IndexError) as error:
        # Exception text can contain filesystem/environment values. Only our
        # fixed reason codes are evidence; the unchanged child stream has logs.
        reason = (
            str(error)
            if type(error) is ValueError
            else "inventory_io_or_metadata_error"
        )
        evidence["reason"] = (
            reason if re.fullmatch("[a-z_]+", reason) else "invalid_inventory_data"
        )
        status = status or 1
    emit(evidence)
    return status if status >= 0 else 128 - status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--owner", default="contracts")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    return run_contract(args.name, command, args.owner)


if __name__ == "__main__":
    sys.exit(main())
