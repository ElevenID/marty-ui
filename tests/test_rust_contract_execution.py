"""Fail closed when direct Rust CI harnesses select no tests."""

import json
import importlib.util
import os
import re
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_SPEC = importlib.util.spec_from_file_location(
    "rust_db_obligations", ROOT / "scripts/ci/rust_db_obligations.py"
)
INVENTORY = importlib.util.module_from_spec(INVENTORY_SPEC)
INVENTORY_SPEC.loader.exec_module(INVENTORY)
RUNNER = ROOT / "scripts/ci/run-rust-db-contracts.sh"
CANVAS_RUNNER = ROOT / "scripts/ci/run-published-canvas-contracts.sh"
GIT_BASH = Path("C:/Program Files/Git/bin/bash.exe")
if os.name == "nt":
    BASH = str(GIT_BASH) if GIT_BASH.is_file() else None
else:
    BASH = shutil.which("bash")


@pytest.mark.parametrize(
    "step_name,guarded_calls",
    [
        ("Verify feature-regression observer isolation", 1),
        ("Test native Canvas AGS/NRPS over real HTTPS", 1),
        ("Test native passport Gateway signed webhook on PostgreSQL", 1),
        ("Exercise authenticated Signing Keys Gateway to Rust routes", 2),
        ("Exercise OIDF keyless HTTPS edge against disposable OpenBao", 1),
        ("Exercise self-host workload TLS bootstrap against disposable OpenBao", 1),
        ("Exercise live Signing Keys public contracts on disposable Redis", 1),
        ("Test beta passport reconciliation and native batch on PostgreSQL", 1),
        ("Run Flow database contract after workspace suite", 1),
    ],
)
def test_focused_rust_ci_cases_require_positive_execution(
    step_name: str, guarded_calls: int
) -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    [step] = [entry for entry in steps if entry.get("name") == step_name]
    script = step["run"]
    assert "source " in script and "rust_contract_execution.sh" in script
    assert script.count("run_timed ") == guarded_calls
    if BASH is not None:
        syntax = subprocess.run(
            [BASH, "-n", "-c", script], capture_output=True, text=True, check=False
        )
        assert syntax.returncode == 0, syntax.stderr


def test_selfhost_tls_bootstrap_runs_live_scoped_openbao_probe() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    [step] = [
        entry
        for entry in steps
        if entry.get("name")
        == "Exercise self-host workload TLS bootstrap against disposable OpenBao"
    ]
    script = step["run"]
    assert "--profile selfhost-bootstrap -- cargo run --locked" in script
    assert "--bin marty-passport-tls-bootstrap" in script
    probe = (ROOT / "scripts/with_disposable_event_stream_kms.py").read_text(
        encoding="utf-8"
    )
    assert "validate_selfhost_tls_bootstrap(bao, output, root_token)" in probe


def test_https_grant_probe_requires_positive_rust_execution() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    [step] = [
        entry
        for entry in steps
        if entry.get("name")
        == "Exercise scoped grant and managed passport chain over disposable HTTPS OpenBao"
    ]
    assert (
        step["run"]
        == "python3 scripts/probe_signing_keys_openbao_policy.py --grant-verifier"
    )
    probe = (ROOT / "scripts/probe_signing_keys_openbao_policy.py").read_text(
        encoding="utf-8"
    )
    assert "def rust_test_succeeded(" in probe
    assert "([1-9][0-9]*) passed; 0 failed" in probe
    for case in (
        "authenticated_gateway_reaches_remaining_rust_signing_handlers",
        "authenticated_gateway_rotates_only_a_dedicated_signing_service",
        "authenticated_gateway_generates_profile_scoped_passport_csrs_in_openbao",
        "authenticated_gateway_generates_a_dedicated_service_csr_in_openbao",
        "authenticated_gateway_issues_dsc_with_operator_grant_and_dedicated_key",
        "managed_passport_chain_issues_and_verifies_sod_without_exporting_private_keys",
    ):
        assert case in probe


def test_release_operator_catalog_tests_require_positive_execution() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/cd.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["build-operator-catalog"]["steps"]
    [step] = [
        entry
        for entry in steps
        if entry.get("name") == "Build and test the native operator binary"
    ]
    script = step["run"]
    assert "source scripts/ci/rust_contract_execution.sh" in script
    assert (
        "run_timed deployment_catalog_release cargo test --locked "
        "--manifest-path rust/Cargo.toml -p marty-deployment-catalog"
    ) in script
    if BASH is not None:
        syntax = subprocess.run(
            [BASH, "-n", "-c", script], capture_output=True, text=True, check=False
        )
        assert syntax.returncode == 0, syntax.stderr


def test_database_runner_uses_positive_execution_guard() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert (
        'source "$(dirname "${BASH_SOURCE[0]}")/rust_contract_execution.sh"' in source
    )
    assert source.count("run_timed ") == 19
    assert 'run_timed_rust_test contract "$name" python3 "$obligation_runner"' in source
    assert 'rust_db_obligations.py"' in source


PASSPORT_RECONCILIATION_CASES = (
    "beta_reconciliation_replays_only_exact_material_and_binds_first_receipt",
    "beta_batch_http_binds_exact_flow_pair_and_replays_after_artifact_scrub",
    "beta_batch_http_completes_receipts_when_wire_kms_fails",
    "beta_batch_http_rejects_retained_response_with_wrong_receipt_mapping",
    "beta_batch_http_never_creates_a_missing_batch_row_through_single_submit",
)


def _assert_explicit_passport_reconciliation_fixture(source: str, script: str) -> None:
    for name in PASSPORT_RECONCILIATION_CASES:
        assert re.search(
            r'#\[tokio::test\]\s*#\[ignore = "requires the owned passport '
            r'reconciliation PostgreSQL fixture"\]\s*async fn '
            + re.escape(name)
            + r"\(",
            source,
        ), name
        assert re.search(
            r"^\s+" + re.escape(name) + r"(?:\s*\\|; do)$", script, re.MULTILINE
        )
    assert source.count('std::env::var("MARTY_PASSPORT_RECONCILIATION_TEST_URL")') == 2
    assert "let Ok(database_url) = std::env::var(" not in source
    assert (
        source.count(
            '.unwrap_or_else(|_| panic!("owned passport reconciliation PostgreSQL URL is absent"))'
        )
        == 2
    )
    assert "--lib passport_http::reconciliation_tests:: -- --ignored --list" in script
    assert '"passport_http::reconciliation_tests::$name: test"' in script
    assert "[[ ${#cases[@]} == 5 ]]" in script
    assert (
        "--lib passport_http::reconciliation_tests:: -- --ignored --test-threads=1"
        in script
    )


def test_passport_reconciliation_cases_require_owned_postgres_and_exact_roster() -> (
    None
):
    source = (
        ROOT / "rust/services/issuance/src/passport_http_reconciliation_tests.rs"
    ).read_text(encoding="utf-8")
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    [step] = [
        item
        for item in workflow["jobs"]["test-rust-services"]["steps"]
        if item.get("name")
        == "Test beta passport reconciliation and native batch on PostgreSQL"
    ]
    script = step["run"]
    _assert_explicit_passport_reconciliation_fixture(source, script)
    with pytest.raises(AssertionError):
        _assert_explicit_passport_reconciliation_fixture(
            source.replace(
                '#[ignore = "requires the owned passport reconciliation PostgreSQL fixture"]',
                "",
                1,
            ),
            script,
        )
    with pytest.raises(AssertionError):
        _assert_explicit_passport_reconciliation_fixture(
            source.replace(
                '.unwrap_or_else(|_| panic!("owned passport reconciliation PostgreSQL URL is absent"))',
                ".unwrap_or_default()",
                1,
            ),
            script,
        )
    with pytest.raises(AssertionError):
        _assert_explicit_passport_reconciliation_fixture(
            source.replace(
                '.unwrap_or_else(|_| panic!("owned passport reconciliation PostgreSQL URL is absent"))',
                '.expect("owned passport reconciliation PostgreSQL URL")',
                1,
            ),
            script,
        )
    with pytest.raises(AssertionError):
        _assert_explicit_passport_reconciliation_fixture(
            source, script.replace("--ignored --test-threads=1", "--test-threads=1")
        )


def test_db_inventory_covers_every_current_dispatch_and_owned_runtime_input() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    names = re.findall(r"^\s*run_timed ([a-z0-9_]+) ", source, re.MULTILINE)
    assert len(names) == len(set(names)) == 18
    canvas = [
        path.stem
        for path in (ROOT / "rust/services/issuance/tests").glob(
            "canvas_*_postgres_contract.rs"
        )
    ] + ["proof_nonce_postgres_contract"]
    assert len(canvas) == 11
    for name in [*names, *canvas]:
        package, target, inputs = INVENTORY.obligation(name)
        assert INVENTORY.libtest_harness(package, target)["harness"] == "libtest"
        assert package.startswith("marty-")
        assert target and inputs
        assert all(item["consumer"] == package for item in inputs)
        for item in inputs:
            assert set(item) == {
                "name",
                "consumer",
                "owner",
                "provisioner",
                "requirement",
            }
            assert re.fullmatch(r"[A-Z][A-Z0-9_]+", item["name"])
            if item["requirement"] == "required":
                assert (
                    item["name"] in source
                    or item["name"] == "MARTY_TEST_REDIS_DISPOSABLE_NONCE"
                )
    with pytest.raises(ValueError, match="unknown_dispatch"):
        INVENTORY.obligation("unclassified_new_dispatch")


def test_db_inventory_never_probes_custom_or_unregistered_harnesses(
    tmp_path, monkeypatch
) -> None:
    manifest_dir = tmp_path / "rust/services/signing-keys"
    manifest_dir.mkdir(parents=True)
    manifest = manifest_dir / "Cargo.toml"
    monkeypatch.setattr(INVENTORY, "ROOT", tmp_path)
    manifest.write_text('[package]\nname = "marty-signing-keys"\nautotests = false\n')
    with pytest.raises(ValueError, match="missing_libtest_target"):
        INVENTORY.libtest_harness("marty-signing-keys", "custom")
    manifest.write_text(
        manifest.read_text() + '\n[[test]]\nname = "custom"\nharness = false\n'
    )
    with pytest.raises(ValueError, match="unsupported_test_harness"):
        INVENTORY.libtest_harness("marty-signing-keys", "custom")


def test_renewal_unit_required_roster_remains_in_the_two_owned_sources() -> None:
    source = ROOT / "rust/services/issuance/src"
    retry = (source / "canvas_sync_worker_retry_tests.rs").read_text(encoding="utf-8")
    renewal = (source / "canvas_sync_worker_renewal_tests.rs").read_text(
        encoding="utf-8"
    )
    direct = set(
        re.findall(
            r"#\[(?:tokio::)?test(?:\([^]]*\))?\]\s*(?:async )?fn\s+(\w+)",
            retry,
        )
    )
    primary = renewal.split("primary_cases! {", 1)[1].split("\n}", 1)[0]
    generated = set(re.findall(r"^\s*(\w+):\s*\"", primary, re.MULTILINE))
    secondary = set(
        re.findall(r"#\[tokio::test\([^]]*\)\]\s*async fn\s+(\w+)", renewal)
    )
    assert len(direct) >= 4 and len(generated) == 15 and len(secondary) >= 4
    expected = {INVENTORY.RENEWAL_UNIT_PREFIX + name for name in direct} | {
        INVENTORY.RENEWAL_UNIT_PREFIX + "renewal_tests::" + name
        for name in generated | secondary
    }
    assert INVENTORY.RENEWAL_UNIT_CASES <= expected
    assert len(INVENTORY.RENEWAL_UNIT_CASES) == 23
    package, target, inputs = INVENTORY.obligation("renewal_unit")
    assert (package, target, inputs) == (
        "marty-issuance-service",
        "marty_issuance_service",
        [],
    )
    assert INVENTORY.libtest_harness(package, target)["harness"] == "libtest"


def test_renewal_unit_selection_rejects_missing_substituted_ignored_or_extra_cases() -> (
    None
):
    args = [INVENTORY.RENEWAL_UNIT_PREFIX, "--test-threads=4"]
    selected = set(INVENTORY.RENEWAL_UNIT_CASES)
    INVENTORY.verify_renewal_unit_roster(args, selected, set())
    cases = sorted(selected)
    for invalid in (
        selected - {cases[0]},
        (selected - {cases[0]}) | {"foreign::same_count_substitution"},
        selected | {"foreign::extra_case"},
    ):
        with pytest.raises(ValueError, match="renewal_unit_roster_drift"):
            INVENTORY.verify_renewal_unit_roster(args, invalid, set())
    with pytest.raises(ValueError, match="renewal_unit_roster_drift"):
        INVENTORY.verify_renewal_unit_roster(args, selected, {cases[0]})
    with pytest.raises(ValueError, match="renewal_unit_roster_drift"):
        INVENTORY.verify_renewal_unit_roster(["--test-threads=4"], selected, set())


def test_library_unit_selection_allows_new_ordinary_cases_but_not_unowned_ignored() -> (
    None
):
    expected = set(INVENTORY.RENEWAL_UNIT_CASES) | {"new_module::new_ordinary_case"}
    ignored = set(INVENTORY.LIBRARY_UNIT_IGNORED_OWNERS)
    INVENTORY.verify_library_unit_roster(["--test-threads=4"], expected, ignored)
    assert len(ignored) == 14
    assert INVENTORY.obligation("issuance_library_unit") == INVENTORY.obligation(
        "renewal_unit"
    )
    for arguments, selected, excluded in (
        ([INVENTORY.RENEWAL_UNIT_PREFIX, "--test-threads=4"], expected, ignored),
        (["--ignored", "--test-threads=4"], expected, ignored),
        (
            ["--test-threads=4"],
            expected - {next(iter(INVENTORY.RENEWAL_UNIT_CASES))},
            ignored,
        ),
        (["--test-threads=4"], expected, ignored - {next(iter(ignored))}),
        (["--test-threads=4"], expected, ignored | {"foreign::unowned_fixture"}),
        (
            ["--test-threads=4"],
            expected,
            (ignored - {next(iter(ignored))}) | {"foreign::substitute"},
        ),
        (["--test-threads=4"], expected | ignored, ignored),
    ):
        with pytest.raises(ValueError, match="library_unit_roster_drift"):
            INVENTORY.verify_library_unit_roster(arguments, selected, excluded)


def test_library_unit_ignored_inventory_matches_actual_fixture_and_child_sources() -> (
    None
):
    roots = ROOT / "rust/services/issuance/src"
    ignored = set()
    for filename, prefix in (
        ("credential_builder.rs", "credential_builder::tests::"),
        ("canvas_readiness_runtime.rs", "canvas_readiness_runtime::tests::"),
        (
            "internal_application_diagnostics.rs",
            "internal_application_diagnostics::tests::",
        ),
        (
            "passport_http_reconciliation_tests.rs",
            "passport_http::reconciliation_tests::",
        ),
        ("canvas_operation_http.rs", "canvas_operation_http::tests::"),
    ):
        source = (roots / filename).read_text(encoding="utf-8")
        ignored.update(
            prefix + name
            for name in re.findall(
                r'#\[ignore\s*=\s*"[^"\n]+"\]\s*(?:async\s+)?fn\s+(\w+)',
                source,
            )
        )
    assert ignored == set(INVENTORY.LIBRARY_UNIT_IGNORED_OWNERS)
    assert all(INVENTORY.LIBRARY_UNIT_IGNORED_OWNERS.values())


@pytest.mark.parametrize("child_status", [0, 7])
def test_whole_library_recorder_accounts_all_discovered_outcomes(
    tmp_path,
    monkeypatch,
    capsys,
    child_status,
) -> None:
    selected = set(INVENTORY.RENEWAL_UNIT_CASES) | {"new_module::new_ordinary_case"}
    ignored = set(INVENTORY.LIBRARY_UNIT_IGNORED_OWNERS)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr(INVENTORY, "artifact_identity", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        INVENTORY, "expected_cases", lambda *args, **kwargs: (selected, ignored)
    )
    calls = []

    def run(command, log, evidence):
        calls.append(command)
        evidence["command_status"] = child_status
        failed = {"new_module::new_ordinary_case"} if child_status else set()
        log.write_text(
            "".join(
                ("failed " if name in failed else "ok ") + name + "\n"
                for name in sorted(selected)
            )
            + "".join("ignored " + name + "\n" for name in sorted(ignored))
        )
        return child_status, (
            f"test result: {'FAILED' if failed else 'ok'}. {len(selected) - len(failed)} passed; "
            f"{len(failed)} failed; {len(ignored)} ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        )

    monkeypatch.setattr(INVENTORY, "run_owned_harness", run)
    command = ["harness", "--test-threads=4"]
    assert (
        INVENTORY.run_contract("issuance_library_unit", command, "renewal-unit")
        == child_status
    )
    assert calls == [command]
    evidence = json.loads(
        (tmp_path / "rust-build-evidence" / INVENTORY.UNIT_EVIDENCE_NAME).read_text()
    )
    assert evidence["schema"] == "marty.rust-library-obligation/v1"
    assert set(evidence["executed"]) == selected
    assert set(evidence["ignored"]) == ignored
    assert evidence["ignored_case_owners"] == INVENTORY.LIBRARY_UNIT_IGNORED_OWNERS
    assert evidence["status"] == ("failed" if child_status else "ok")
    assert not (tmp_path / "rust-build-evidence" / INVENTORY.EVIDENCE_NAME).exists()
    assert INVENTORY.UNIT_PREFIX in capsys.readouterr().out


def test_whole_library_rejects_unknown_ignored_owner_before_execution(
    monkeypatch,
) -> None:
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("MARTY_CANVAS_FULL_QUALIFICATION", raising=False)
    monkeypatch.delenv("MARTY_CANVAS_WORKER_RETRY_AFTER_TIER", raising=False)
    monkeypatch.delenv("MARTY_CANVAS_WORKER_VALIDATION_TIER", raising=False)
    monkeypatch.setattr(INVENTORY, "artifact_identity", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        INVENTORY,
        "expected_cases",
        lambda *args, **kwargs: (
            set(INVENTORY.RENEWAL_UNIT_CASES),
            set(INVENTORY.LIBRARY_UNIT_IGNORED_OWNERS) | {"unowned::ignored_case"},
        ),
    )
    monkeypatch.setattr(
        INVENTORY,
        "run_owned_harness",
        lambda *args: pytest.fail("unowned case executed"),
    )
    assert (
        INVENTORY.run_contract(
            "issuance_library_unit", ["harness", "--test-threads=4"], "renewal-unit"
        )
        == 1
    )


def test_renewal_unit_artifact_requires_same_run_library_test_profile(
    tmp_path, monkeypatch
) -> None:
    executable = tmp_path / "marty_issuance_service-harness"
    executable.write_bytes(b"bounded synthetic harness")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    record = {
        "reason": "compiler-artifact",
        "package_id": "path+file:///checkout#marty-issuance-service@0.1.0",
        "target": {"kind": ["lib"], "name": "marty_issuance_service"},
        "profile": {"test": True},
        "executable": str(executable),
    }
    artifacts = tmp_path / "rust-test-artifacts.json"
    for invalid in (
        [],
        [{**record, "profile": {"test": False}}],
        [{**record, "target": {"kind": ["bin"], "name": record["target"]["name"]}}],
        [{**record, "package_id": "path+file:///checkout#foreign@0.1.0"}],
        [record, record],
        [record, {**record, "executable": str(tmp_path / "other-harness")}],
    ):
        artifacts.write_text("".join(json.dumps(row) + "\n" for row in invalid))
        with pytest.raises(ValueError):
            INVENTORY.artifact_identity(
                executable,
                "marty-issuance-service",
                "marty_issuance_service",
                library_test=True,
            )
    artifacts.write_text(json.dumps(record) + "\n")
    assert (
        INVENTORY.artifact_identity(
            executable,
            "marty-issuance-service",
            "marty_issuance_service",
            library_test=True,
        )["binding"]
        == "same_path"
    )


def test_renewal_unit_evidence_is_separate_from_database_claims(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    evidence = {"schema": "marty.rust-unit-obligation/v1", "status": "ok"}
    INVENTORY.emit(evidence)
    output = tmp_path / "rust-build-evidence" / INVENTORY.UNIT_EVIDENCE_NAME
    assert json.loads(output.read_text()) == evidence
    assert INVENTORY.UNIT_PREFIX in capsys.readouterr().out
    assert not (tmp_path / "rust-build-evidence" / INVENTORY.EVIDENCE_NAME).exists()


def test_flow_inventory_binds_exact_crate_and_shared_roster(monkeypatch) -> None:
    package, target, inputs = INVENTORY.obligation("flow_acceptance")
    assert (package, target) == (
        "marty-flow-acceptance",
        "flow_published_schema_contract",
    )
    assert INVENTORY.libtest_harness(package, target)["manifest"] == (
        "rust/crates/flow-acceptance/Cargo.toml"
    )
    assert {item["name"] for item in inputs} == {
        "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST",
        "MARTY_ISSUANCE_TEST_BINARY",
        "MARTY_BASE_COMPOSE_BINARY",
        "MARTY_DIDCOMM_TEST_PYTHON",
        "MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE",
    }
    assert INVENTORY.selection(
        ["--nocapture", "--test-threads=4"], allow_nocapture=True
    ) == (
        ["--nocapture", "--test-threads=4"],
        "default",
    )
    with pytest.raises(ValueError, match="unsupported_selection_argument"):
        INVENTORY.selection(["--nocapture", "--test-threads=4"])
    sources = INVENTORY.flow_source_inputs("flow-pr")
    assert {entry["path"] for entry in sources} == {
        "contracts/canvas-worker-consumer-range-oracle.json",
        "scripts/ci/pull-pinned-dockerhub-image.sh",
        "scripts/ci/list-flow-acceptance-cases.sh",
        "scripts/ci/run-flow-acceptance-contracts.sh",
    }
    assert all(
        entry["sha256"] == INVENTORY.digest(ROOT / entry["path"]) for entry in sources
    )
    first_hop = INVENTORY.flow_rendered_first_hop_inputs()
    assert {entry["path"] for entry in first_hop} == {
        "scripts/render_flow_native_runtime_fixture.py",
        "scripts/test_base_native_issuance_compose.py",
        "scripts/test_selfhost_native_owner_compose.py",
    }
    assert all(
        entry["sha256"] == INVENTORY.digest(ROOT / entry["path"]) for entry in first_hop
    )
    subgraph = INVENTORY.flow_renderer_subgraph_inputs()
    assert len(subgraph) == 22
    assert {entry["path"] for entry in subgraph} == {
        *INVENTORY.FLOW_RENDERER_RUNPY_EDGES,
        "docker-compose.base.yml",
        "docker-compose.profile.issuance-native.yml",
        "docker-compose.service.issuance-native-runtime.yml",
        "docker-compose.selfhost.prod.yml",
        "selfhost-kms-only-model.keyless-tls.snapshot.yml",
        "docker-compose.service.issuance-native.yml",
        "scripts/load-secrets-env.sh",
        "rust/services/signing-keys/tests/fixtures/public_certificates/root-ca.pem",
        "rust/services/gateway/src/config.rs",
        "rust/services/issuance/src/config.rs",
        "rust/services/issuance/src/canvas_credentials_publication.rs",
    }
    assert all(
        entry["sha256"] == INVENTORY.digest(ROOT / entry["path"]) for entry in subgraph
    )
    imports = INVENTORY.flow_renderer_python_imports()
    assert {entry["path"] for entry in imports} == set(
        INVENTORY.FLOW_RENDERER_RUNPY_EDGES
    )
    assert any("yaml" in entry["modules"] for entry in imports)
    assert all(
        set(entry["modules"]) <= (INVENTORY.sys.stdlib_module_names | {"yaml"})
        for entry in imports
    )

    def fake_roster(command, **_kwargs):
        assert command == [
            "bash",
            str(ROOT / "scripts/ci/list-flow-acceptance-cases.sh"),
            "owned-harness",
        ]
        return subprocess.CompletedProcess(
            command, 0, "happy: test\n1 test, 0 benchmarks\n", ""
        )

    monkeypatch.setattr(INVENTORY, "discover_harness", fake_roster)
    INVENTORY.verify_flow_roster("owned-harness", {"happy"}, set())
    with pytest.raises(ValueError, match="flow_roster_drift"):
        INVENTORY.verify_flow_roster("owned-harness", {"other"}, set())
    with pytest.raises(ValueError, match="flow_roster_drift"):
        INVENTORY.verify_flow_roster("owned-harness", {"happy"}, {"ignored"})


def test_flow_renderer_first_hop_fails_closed_on_source_drift(
    tmp_path, monkeypatch
) -> None:
    caller = (
        tmp_path
        / "rust/crates/flow-acceptance/tests/support/flow_rendered_selection.rs"
    )
    caller.parent.mkdir(parents=True)
    caller.write_text("no renderer call", encoding="utf-8")
    renderer = tmp_path / "scripts/render_flow_native_runtime_fixture.py"
    renderer.parent.mkdir(parents=True)
    renderer.write_text("no helper imports", encoding="utf-8")
    monkeypatch.setattr(INVENTORY, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="flow_renderer_source_drift"):
        INVENTORY.flow_rendered_first_hop_inputs()
    caller.write_text(
        '.arg(root().join("scripts/render_flow_native_runtime_fixture.py"))',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="flow_renderer_source_drift"):
        INVENTORY.flow_rendered_first_hop_inputs()
    renderer.write_text(
        "\n".join(
            f'runpy.run_path(str(ROOT / "{path}"))'
            for path in (
                "scripts/test_base_native_issuance_compose.py",
                "scripts/test_selfhost_native_owner_compose.py",
                "scripts/extra_helper.py",
            )
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="flow_renderer_source_drift"):
        INVENTORY.flow_rendered_first_hop_inputs()


def test_flow_renderer_subgraph_fails_closed_on_edge_and_compose_drift(
    tmp_path, monkeypatch
) -> None:
    paths = {
        *(entry["path"] for entry in INVENTORY.flow_renderer_subgraph_inputs()),
        "rust/crates/flow-acceptance/tests/support/flow_rendered_selection.rs",
    }
    for path in paths:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / path, target)
    monkeypatch.setattr(INVENTORY, "ROOT", tmp_path)
    assert len(INVENTORY.flow_renderer_subgraph_inputs()) == 22

    helper = tmp_path / "scripts/test_beta_application_image_compose.py"
    original = helper.read_text(encoding="utf-8")
    for added in (
        "import extra_flow_helper\n",
        "from scripts import extra_flow_helper\n",
        '__import__("extra_flow_helper")\n',
        'loader = __import__\nloader("extra_flow_helper")\n',
        'loader = __builtins__["__import__"]\nloader("extra_flow_helper")\n',
        'loader = sys.modules["importlib"].import_module\nloader("extra_flow_helper")\n',
        'loader = sys.modules["runpy"].__dict__["run_path"]\nloader("extra_flow_helper.py")\n',
        'runpy = object()\n',
        'import os as runpy\n',
        'def shadow(runpy):\n    return runpy\n',
        'match 1:\n    case runpy:\n        pass\n',
        'match []:\n    case [*runpy]:\n        pass\n',
        'match {}:\n    case {**runpy}:\n        pass\n',
        'from runpy import run_path\nrun_path("scripts/extra_flow_helper.py")\n',
        'import runpy as loader\nloader.run_path("scripts/extra_flow_helper.py")\n',
        'from importlib import import_module\nimport_module("extra_flow_helper")\n',
        'loader = runpy.run_path\nloader("scripts/extra_flow_helper.py")\n',
        'getattr(runpy, "run_path")("scripts/extra_flow_helper.py")\n',
    ):
        helper.write_text(original + "\n" + added, encoding="utf-8")
        with pytest.raises(ValueError, match="flow_renderer_import_drift"):
            INVENTORY.flow_renderer_subgraph_inputs()
    helper.write_text(original, encoding="utf-8")
    helper.write_text(original.replace("import runpy\n", "", 1), encoding="utf-8")
    with pytest.raises(ValueError, match="flow_renderer_import_drift"):
        INVENTORY.flow_renderer_subgraph_inputs()
    helper.write_text(original, encoding="utf-8")

    shadow = tmp_path / "scripts/json.py"
    shadow.write_text("# test shadow\n", encoding="utf-8")
    with pytest.raises(ValueError, match="flow_renderer_import_drift"):
        INVENTORY.flow_renderer_python_imports()
    shadow.unlink()
    extension = tmp_path / (
        "scripts/json" + INVENTORY.importlib.machinery.EXTENSION_SUFFIXES[0]
    )
    extension.write_bytes(b"test shadow")
    with pytest.raises(ValueError, match="flow_renderer_import_drift"):
        INVENTORY.flow_renderer_python_imports()
    extension.unlink()

    helper.write_text(
        original + '\nrunpy.run_path(str(ROOT / "scripts/new_helper.py"))\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="flow_renderer_subgraph_drift"):
        INVENTORY.flow_renderer_subgraph_inputs()
    helper.write_text(original, encoding="utf-8")

    owner = tmp_path / "scripts/test_base_native_issuance_compose.py"
    original = owner.read_text(encoding="utf-8")
    owner.write_text(
        original.replace(
            "    return result\n",
            '    result.append(ROOT / "docker-compose.extra.yml")\n    return result\n',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="flow_renderer_subgraph_drift"):
        INVENTORY.flow_renderer_subgraph_inputs()
    owner.write_text(original, encoding="utf-8")

    owner.write_text(
        original.replace(
            'PROFILE = "docker-compose.profile.issuance-native.yml"',
            'PROFILE = "docker-compose.other.yml"',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="flow_renderer_subgraph_drift"):
        INVENTORY.flow_renderer_subgraph_inputs()
    owner.write_text(original, encoding="utf-8")

    model = tmp_path / "docker-compose.profile.issuance-native.yml"
    original = model.read_text(encoding="utf-8")
    model.write_text(
        original.replace(
            "file: docker-compose.service.issuance-native-runtime.yml",
            "file: docker-compose.other.yml",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="flow_renderer_subgraph_drift"):
        INVENTORY.flow_renderer_subgraph_inputs()
    model.write_text(original, encoding="utf-8")

    model.write_text(
        original.replace(
            "  issuance-native:\n",
            "  unexpected:\n"
            "    extends:\n"
            "      file: docker-compose.other.yml\n"
            "      service: issuance-native\n"
            "  issuance-native:\n",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="flow_renderer_subgraph_drift"):
        INVENTORY.flow_renderer_subgraph_inputs()
    model.write_text(original, encoding="utf-8")

    model.write_text(
        original.replace(
            "  issuance-native:\n",
            "  unexpected:\n"
            "    extends :\n"
            "      file: docker-compose.other.yml\n"
            "      service: issuance-native\n"
            "  issuance-native:\n",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="flow_renderer_subgraph_drift"):
        INVENTORY.flow_renderer_subgraph_inputs()
    model.write_text(original, encoding="utf-8")

    model.write_text(
        original + "\ninclude:\n  - docker-compose.other.yml\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="flow_renderer_subgraph_drift"):
        INVENTORY.flow_renderer_subgraph_inputs()
    model.write_text(original, encoding="utf-8")

    model.write_text("services: [private-marker\n", encoding="utf-8")
    with pytest.raises(ValueError) as malformed:
        INVENTORY.flow_renderer_subgraph_inputs()
    assert str(malformed.value) == "flow_renderer_subgraph_drift"
    assert "private-marker" not in str(malformed.value)
    model.write_text(original, encoding="utf-8")

    renderer = tmp_path / "scripts/render_flow_native_runtime_fixture.py"
    original = renderer.read_text(encoding="utf-8")
    renderer.write_text(
        original.replace(
            "ROOT = Path(__file__).resolve().parents[1]",
            "ROOT = Path(__file__).resolve().parents[2]",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="flow_renderer_source_drift"):
        INVENTORY.flow_rendered_first_hop_inputs()
    renderer.write_text(original, encoding="utf-8")

    renderer.write_text(
        original.replace(
            'BASE = runpy.run_path',
            'ROOT = Path.cwd()\nBASE = runpy.run_path',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="flow_renderer_subgraph_drift"):
        INVENTORY._flow_renderer_runpy_edges(
            "scripts/render_flow_native_runtime_fixture.py"
        )
    renderer.write_text(original, encoding="utf-8")

    renderer.write_text(
        original.replace(
            'BASE["source"]("docker-compose.base.yml")',
            'BASE["source"]("docker-compose.other.yml")',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="flow_renderer_subgraph_drift"):
        INVENTORY.flow_renderer_subgraph_inputs()


def test_flow_inventory_real_nocapture_child_stdout_and_failure_guards(
    tmp_path, monkeypatch, real_obligation_harness, capsys
) -> None:
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    original_artifact_identity = INVENTORY.artifact_identity
    monkeypatch.setattr(INVENTORY, "artifact_identity", lambda *args, **kwargs: {})
    monkeypatch.setattr(INVENTORY, "verify_flow_roster", lambda *_args: None)
    for item in INVENTORY.obligation("flow_acceptance")[2]:
        monkeypatch.setenv(item["name"], "private-runtime-value")
    monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST", "1")
    binary = str(real_obligation_harness)
    command = [binary, "happy", "--exact", "--nocapture", "--test-threads=4"]
    assert INVENTORY.run_contract("flow_acceptance", command, "flow-pr") == 0
    output = capsys.readouterr().out
    record = next(
        json.loads(line.removeprefix(INVENTORY.PREFIX))
        for line in output.splitlines()
        if line.startswith(INVENTORY.PREFIX)
    )
    assert record["gate"] == "test-rust-services/flow"
    assert record["owner"] == INVENTORY.FLOW_OWNERS["flow-pr"]
    assert record["selected"] == record["executed"] == ["happy"]
    assert record["observed_cases"] == [{"name": "happy", "outcome": "ok"}]
    assert record["observed_first_hop_source_inputs"] == (
        INVENTORY.flow_rendered_first_hop_inputs()
    )
    assert record["observed_renderer_subgraph_source_inputs"] == (
        INVENTORY.flow_renderer_subgraph_inputs()
    )
    assert record["observed_renderer_python_imports"] == (
        INVENTORY.flow_renderer_python_imports()
    )
    assert record["observed_first_hop_rust_source_inputs"] == (
        INVENTORY.acceptance_rust_first_hop_inputs("flow_acceptance")
    )
    assert record["transitive_source_closure"] == "incomplete"
    assert "child-inherited-stdout" in output
    assert "private-runtime-value" not in json.dumps(record)
    monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST", "0")
    assert INVENTORY.run_contract("flow_acceptance", command, "canvas") != 0
    assert "missing_published_schema_gate" in capsys.readouterr().out
    monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST", "1")
    assert INVENTORY.run_contract("flow_acceptance", command, "contracts") != 0
    assert "invalid_dispatch_owner" in capsys.readouterr().out
    monkeypatch.setenv("MARTY_LIBTEST_FORCE_FAILURE", "1")
    failing = [
        binary,
        "fixture_case_extra",
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=4",
    ]
    assert INVENTORY.run_contract("flow_acceptance", failing, "canvas") != 0
    assert '"failed":1' in capsys.readouterr().out
    monkeypatch.delenv("MARTY_LIBTEST_FORCE_FAILURE")
    monkeypatch.setattr(INVENTORY, "artifact_identity", original_artifact_identity)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    assert INVENTORY.run_contract("flow_acceptance", command, "canvas") != 0
    assert "inventory_io_or_metadata_error" in capsys.readouterr().out


def test_flow_inventory_nested_libtest_summary_stays_owned(
    tmp_path, monkeypatch, capsys
) -> None:
    rustc = shutil.which("rustc")
    if rustc is None:
        pytest.skip("rustc unavailable for the nested libtest protocol check")
    binary = tmp_path / ("nested.exe" if os.name == "nt" else "nested")
    build = subprocess.run(
        [
            rustc,
            "--test",
            str(ROOT / "tests/fixtures/rust_flow_nested_obligation_harness.rs"),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(INVENTORY, "artifact_identity", lambda *args, **kwargs: {})
    monkeypatch.setattr(INVENTORY, "verify_flow_roster", lambda *_args: None)
    for item in INVENTORY.obligation("flow_acceptance")[2]:
        monkeypatch.setenv(item["name"], "owned-fixture")
    monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST", "1")
    assert (
        INVENTORY.run_contract(
            "flow_acceptance",
            [
                str(binary),
                "nested_parent",
                "--exact",
                "--nocapture",
                "--test-threads=4",
            ],
            "canvas",
        )
        == 0
    )
    output = capsys.readouterr().out
    assert output.count("test result: ok.") == 1
    record = next(
        json.loads(line.removeprefix(INVENTORY.PREFIX))
        for line in output.splitlines()
        if line.startswith(INVENTORY.PREFIX)
    )
    assert record["selected"] == record["executed"] == ["nested_parent"]
    assert "captured nested libtest child" in output
    assert "owned child diagnostic" not in output


def test_selfhost_inventory_binds_exact_owner_and_direct_inputs() -> None:
    package, target, inputs = INVENTORY.obligation("selfhost_acceptance")
    assert (package, target) == (
        "marty-selfhost-acceptance",
        "selfhost_public_image_contract",
    )
    assert INVENTORY.libtest_harness(package, target)["manifest"] == (
        "rust/crates/selfhost-acceptance/Cargo.toml"
    )
    assert {item["name"] for item in inputs} == {
        "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST",
        "MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE",
        "MARTY_SELFHOST_TEST_IMAGE",
        "MARTY_SELFHOST_TEST_REVISION",
        "MARTY_SELFHOST_TEST_PACKAGER_BINARY",
        "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE",
    }
    assert all(item["consumer"] == package for item in inputs)
    sources = INVENTORY.selfhost_source_inputs("selfhost")
    assert {entry["path"] for entry in sources} == {
        "contracts/canvas-worker-consumer-range-oracle.json",
        "scripts/ci/pull-pinned-dockerhub-image.sh",
        "scripts/ci/run-db-contract-groups.py",
        "scripts/ci/run-published-canvas-contracts.sh",
    }
    assert all(
        entry["sha256"] == INVENTORY.digest(ROOT / entry["path"]) for entry in sources
    )
    assert "scripts/ci/run-db-contract-groups.py" not in {
        entry["path"] for entry in INVENTORY.selfhost_source_inputs("canvas")
    }


def test_selfhost_inventory_real_outer_libtest_and_fail_closed(
    tmp_path, monkeypatch, capsys
) -> None:
    rustc = shutil.which("rustc")
    if rustc is None:
        pytest.skip("rustc unavailable for the selfhost libtest protocol check")
    binary = tmp_path / (
        "selfhost-harness.exe" if os.name == "nt" else "selfhost-harness"
    )
    build = subprocess.run(
        [
            rustc,
            "--test",
            str(ROOT / "tests/fixtures/rust_selfhost_obligation_harness.rs"),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(INVENTORY, "artifact_identity", lambda *args, **kwargs: {})
    for item in INVENTORY.obligation("selfhost_acceptance")[2]:
        monkeypatch.setenv(item["name"], "private-runtime-value")
    monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST", "1")
    monkeypatch.setenv("MARTY_SELFHOST_TEST_IMAGE", "sha256:" + "a" * 64)
    monkeypatch.setenv("MARTY_SELFHOST_TEST_REVISION", "b" * 40)
    packager = tmp_path / "packager"
    compose = tmp_path / "compose"
    packager.write_bytes(b"owned test packager")
    compose.write_bytes(b"owned test renderer")
    monkeypatch.setenv("MARTY_SELFHOST_TEST_PACKAGER_BINARY", str(packager))
    monkeypatch.setenv("MARTY_SELFHOST_BUNDLE_TEST_COMPOSE", str(compose))
    command = [str(binary), "--nocapture", "--test-threads=4"]
    assert INVENTORY.run_contract("selfhost_acceptance", command, "selfhost") == 0
    output = capsys.readouterr().out
    record = next(
        json.loads(line.removeprefix(INVENTORY.PREFIX))
        for line in output.splitlines()
        if line.startswith(INVENTORY.PREFIX)
    )
    assert record["gate"] == "test-rust-services/selfhost"
    assert record["owner"] == INVENTORY.SELFHOST_OWNER
    assert len(record["selected"]) == 17
    assert record["selected"] == record["executed"]
    assert record["passed"] == 17 and record["failed"] == 0
    assert record["configured_input_identities"] == {
        "image_id": "sha256:" + "a" * 64,
        "source_revision": "b" * 40,
        "packager_sha256": INVENTORY.digest(packager),
        "compose_sha256": INVENTORY.digest(compose),
    }
    assert record["observed_first_hop_rust_source_inputs"] == (
        INVENTORY.acceptance_rust_first_hop_inputs("selfhost_acceptance")
    )
    assert record["transitive_source_closure"] == "incomplete"
    assert output.count("test result: ok.") == 1
    assert "nested child summary captured" in output
    assert "private-runtime-value" not in json.dumps(record)
    for cardinality, ignored in [(12, set()), (16, set()), (18, set()), (17, {"case17"})]:
        names = {f"case{number:02d}" for number in range(1, cardinality + 1)}
        with monkeypatch.context() as scoped:
            scoped.setattr(
                INVENTORY,
                "expected_cases",
                lambda *_args, **_kwargs: (names, ignored),
            )
            assert INVENTORY.run_contract("selfhost_acceptance", command, "selfhost") != 0
        rejected = capsys.readouterr().out
        refusal = next(
            json.loads(line.removeprefix(INVENTORY.PREFIX))
            for line in rejected.splitlines()
            if line.startswith(INVENTORY.PREFIX)
        )
        assert refusal["reason"] == "selfhost_selection_drift"
        assert "selected" not in refusal
        assert "observed_cases" not in refusal
        assert "test result:" not in rejected
    assert INVENTORY.run_contract("selfhost_acceptance", command, "canvas") == 0
    assert '"gate":"test-rust-services/canvas"' in capsys.readouterr().out
    packager.write_bytes(b"mutated owned test packager")
    assert INVENTORY.run_contract("selfhost_acceptance", command, "selfhost") == 0
    assert (
        f'"packager_sha256":"{INVENTORY.digest(packager)}"' in capsys.readouterr().out
    )
    monkeypatch.setenv("MARTY_SELFHOST_TEST_IMAGE", "mutable:latest")
    assert INVENTORY.run_contract("selfhost_acceptance", command, "selfhost") != 0
    assert "invalid_selfhost_image_id" in capsys.readouterr().out
    monkeypatch.setenv("MARTY_SELFHOST_TEST_IMAGE", "sha256:" + "a" * 64)
    monkeypatch.setenv("MARTY_SELFHOST_TEST_REVISION", "mutable-main")
    assert INVENTORY.run_contract("selfhost_acceptance", command, "selfhost") != 0
    assert "invalid_selfhost_revision" in capsys.readouterr().out
    monkeypatch.setenv("MARTY_SELFHOST_TEST_REVISION", "b" * 40)
    monkeypatch.setenv("MARTY_SELFHOST_TEST_PACKAGER_BINARY", str(tmp_path / "absent"))
    assert INVENTORY.run_contract("selfhost_acceptance", command, "selfhost") != 0
    assert "invalid_selfhost_binary" in capsys.readouterr().out
    monkeypatch.setenv("MARTY_SELFHOST_TEST_PACKAGER_BINARY", str(packager))
    assert INVENTORY.run_contract("selfhost_acceptance", command, "contracts") != 0
    assert "invalid_dispatch_owner" in capsys.readouterr().out
    assert (
        INVENTORY.run_contract(
            "selfhost_acceptance",
            [str(binary), "case01", "--exact", "--nocapture"],
            "selfhost",
        )
        != 0
    )
    assert "selfhost_selection_drift" in capsys.readouterr().out
    monkeypatch.setenv("MARTY_SELFHOST_SYNTHETIC_FAIL", "1")
    assert INVENTORY.run_contract("selfhost_acceptance", command, "selfhost") != 0
    assert '"failed":1' in capsys.readouterr().out
    monkeypatch.delenv("MARTY_SELFHOST_SYNTHETIC_FAIL")
    monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST", "0")
    assert INVENTORY.run_contract("selfhost_acceptance", command, "selfhost") != 0
    assert "missing_published_schema_gate" in capsys.readouterr().out


def test_selfhost_runner_keeps_roster_preflight_and_both_evidence_call_sites() -> None:
    source = CANVAS_RUNNER.read_text(encoding="utf-8")
    dedicated = source.split('if [[ "$mode" == selfhost-only ]]; then', 1)[1].split(
        "\nfi", 1
    )[0]
    assert (
        dedicated.count('require_selfhost_tests "$("$selfhost_executable" --list)"')
        == 1
    )
    assert dedicated.index("require_selfhost_tests") < dedicated.index(
        "pull_published_postgres"
    )
    assert dedicated.index("pull_published_postgres") < dedicated.index(
        "--name selfhost_acceptance --owner selfhost --"
    )
    assert dedicated.count('"$selfhost_executable" --nocapture --test-threads=4') == 1
    assert dedicated.count("17 passed; 0 failed; 0 ignored;") == 1
    assert source.count("--name selfhost_acceptance --owner canvas --") == 1
    assert source.count('"$selfhost_executable" --nocapture --test-threads=4') == 2
    assert source.index('require_selfhost_tests "$selfhost_tests"') < source.index(
        "--name selfhost_acceptance --owner canvas --"
    )
    assert 'if [[ -n "$selfhost_pid" ]]; then kill "$selfhost_pid"' in source
    assert 'if [[ -n "$selfhost_pid" ]]; then wait "$selfhost_pid"' in source


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups are the CI owner")
@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
def test_obligation_wrapper_reaps_owned_harness_and_descendant(
    tmp_path, signum
) -> None:
    rustc = shutil.which("rustc")
    if rustc is None:
        pytest.skip("rustc unavailable for the signal-ownership probe")
    binary = tmp_path / "signal-harness"
    build = subprocess.run(
        [
            rustc,
            "--test",
            str(ROOT / "tests/fixtures/rust_obligation_signal_harness.rs"),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    temporary = tmp_path / "owned-temporary"
    temporary.mkdir()
    environment = os.environ.copy()
    environment.pop("RUNNER_TEMP", None)
    environment.pop("GITHUB_ACTIONS", None)
    environment.update(
        TMPDIR=str(temporary),
        MARTY_TEST_REDIS_URL="redis://owned-test-only",
        MARTY_TEST_REDIS_DISPOSABLE_NONCE="owned-test-sentinel",
        MARTY_SIGNAL_PID_DIR=str(tmp_path),
        MARTY_SIGNAL_PYTHON=sys.executable,
    )
    wrapper = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "scripts/ci/rust_db_obligations.py"),
            "--name",
            "issuer_profile",
            "--",
            str(binary),
            "holding",
            "--exact",
            "--test-threads=1",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    try:
        deadline = time.monotonic() + 10
        while not (tmp_path / "descendant.pid").is_file():
            assert wrapper.poll() is None, (
                "wrapper exited before owned descendant started"
            )
            assert time.monotonic() < deadline, "owned descendant did not start"
            time.sleep(0.05)
        pids = [
            int((tmp_path / name).read_text())
            for name in ("harness.pid", "descendant.pid")
        ]
        os.kill(wrapper.pid, signum)
        stdout, _stderr = wrapper.communicate(timeout=15)
        assert wrapper.returncode == 128 + signum
        records = [
            json.loads(line.removeprefix(INVENTORY.PREFIX))
            for line in stdout.splitlines()
            if line.startswith(INVENTORY.PREFIX)
        ]
        assert len(records) == 1
        assert records[0]["status"] == "failed"
        assert records[0]["reason"] == "interrupted"
        assert records[0]["command_status"] == 128 + signum
        observed_signal = tmp_path / "received-signal"
        assert observed_signal.is_file()
        assert observed_signal.read_text() == str(signum)
        for pid in pids:
            state = Path(f"/proc/{pid}/stat")
            deadline = time.monotonic() + 3
            while state.exists() and state.read_text().split()[2] != "Z":
                assert time.monotonic() < deadline, (
                    f"owned process {pid} survived cancellation"
                )
                time.sleep(0.05)
        assert not list(temporary.glob("marty-libtest-results-*"))
    finally:
        if wrapper.poll() is None:
            wrapper.kill()
            wrapper.communicate(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="POSIX signal ownership is the CI owner")
def test_obligation_signal_during_spawn_still_settles_assigned_child(
    tmp_path, monkeypatch
) -> None:
    import io

    settled = []

    class Child:
        def __init__(self, *_args, **_kwargs):
            self.stdout = io.BytesIO()
            handler = signal.getsignal(signal.SIGTERM)
            assert callable(handler)
            handler(signal.SIGTERM, None)

        def poll(self):
            return None

    monkeypatch.setattr(INVENTORY, "spawn_harness", Child)
    monkeypatch.setattr(
        INVENTORY,
        "settle_owned_child",
        lambda child, initial_signal: settled.append((child, initial_signal)),
    )
    evidence = {}
    with pytest.raises(INVENTORY.HarnessInterrupted):
        INVENTORY.run_owned_harness(["fake"], tmp_path / "log", evidence)
    assert len(settled) == 1
    assert settled[0][1] == signal.SIGTERM
    assert evidence["command_status"] == 143


@pytest.mark.parametrize("child_status", [0, 7])
def test_db_inventory_preserves_child_failure_and_saves_observed_outcomes(
    tmp_path, monkeypatch, capsys, child_status
) -> None:
    import io

    class Child:
        stdout = io.BytesIO(b"test happy ... FAILED\n")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def wait(self):
            return child_status

        def poll(self):
            return child_status

    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("MARTY_TEST_REDIS_URL", "private-credential-value")
    monkeypatch.setenv("MARTY_TEST_REDIS_DISPOSABLE_NONCE", "owned-test-sentinel")
    monkeypatch.setattr(INVENTORY, "artifact_identity", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        INVENTORY, "expected_cases", lambda *args, **kwargs: ({"happy"}, set())
    )
    result_paths = []

    def fake_child(command, **kwargs):
        result_log = Path(command[command.index("--logfile") + 1])
        result_log.write_text("failed happy\n", encoding="utf-8")
        result_paths.append(result_log)
        return Child()

    monkeypatch.setattr(INVENTORY, "spawn_harness", fake_child)
    assert INVENTORY.run_contract("issuer_profile", ["harness"]) == (child_status or 1)
    evidence = json.loads(
        (tmp_path / "rust-build-evidence" / INVENTORY.EVIDENCE_NAME).read_text()
    )
    assert evidence["status"] == "failed"
    assert evidence["command_status"] == child_status
    assert evidence["observed_cases"] == [{"name": "happy", "outcome": "FAILED"}]
    assert evidence["reason"] == "missing_or_ambiguous_libtest_summary"
    assert "private-credential-value" not in capsys.readouterr().out
    assert all(not path.parent.exists() for path in result_paths)


@pytest.fixture(scope="module")
def real_obligation_harness(tmp_path_factory):
    rustc = shutil.which("rustc")
    if rustc is None:
        pytest.skip("rustc unavailable for the real libtest protocol check")
    directory = tmp_path_factory.mktemp("libtest-obligation")
    binary = directory / ("harness.exe" if os.name == "nt" else "harness")
    build = subprocess.run(
        [
            rustc,
            "--test",
            str(ROOT / "tests/fixtures/rust_obligation_harness.rs"),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stderr
    return binary


@pytest.mark.parametrize(
    "arguments,selected,ignored",
    [
        ([], {"happy", "happy_extra"}, {"fixture_case", "fixture_case_extra"}),
        (["--ignored"], {"fixture_case", "fixture_case_extra"}, set()),
        (
            ["--include-ignored"],
            {"happy", "happy_extra", "fixture_case", "fixture_case_extra"},
            set(),
        ),
        (["happy"], {"happy", "happy_extra"}, set()),
        (["happy", "--exact"], {"happy"}, set()),
        (["fixture_case", "--ignored", "--exact"], {"fixture_case"}, set()),
        (["fixture_case", "--exact"], set(), {"fixture_case"}),
    ],
)
def test_db_inventory_agrees_with_real_libtest_ignored_and_filter_selection(
    tmp_path, real_obligation_harness, arguments, selected, ignored
) -> None:
    executable = str(real_obligation_harness)
    actual_selected, actual_ignored = INVENTORY.expected_cases(executable, arguments)
    assert actual_selected == selected
    assert actual_ignored == ignored
    result_log = tmp_path / "libtest-results.log"
    run = subprocess.run(
        [
            executable,
            *arguments,
            "--test-threads=1",
            "--format",
            "pretty",
            "--color",
            "never",
            "--logfile",
            str(result_log),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    evidence = INVENTORY.verify_execution(
        run.stdout.splitlines(), result_log.read_text().splitlines(), selected, ignored
    )
    assert evidence["executed"] == sorted(selected)
    assert evidence["ignored"] == sorted(ignored)
    if "happy" in selected:
        assert '"diagnostic":"direct-stdout"' in run.stdout
        assert "child-inherited-stdout" in run.stdout
        assert "test happy ... ok" not in run.stdout


@pytest.mark.parametrize(
    ("qualification", "expected_mode"),
    [("0", "routine"), ("1", "full")],
)
def test_canvas_inventory_records_real_libtest_skips_without_changing_db_selection(
    real_obligation_harness, monkeypatch, capsys, qualification, expected_mode
) -> None:
    executable = str(real_obligation_harness)
    arguments = ["--skip", "fixture_case", "--nocapture", "--test-threads=1"]
    assert INVENTORY.expected_cases(
        executable, arguments, allow_skip=True, allow_nocapture=True
    ) == ({"happy", "happy_extra"}, set())
    with pytest.raises(ValueError, match="unsupported_selection_argument"):
        INVENTORY.expected_cases(executable, arguments, allow_nocapture=True)
    for invalid in (["--skip"], ["--skip", "../foreign"]):
        with pytest.raises(ValueError):
            INVENTORY.selection(invalid, allow_skip=True)
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("MARTY_CANVAS_FULL_QUALIFICATION", qualification)
    monkeypatch.delenv("MARTY_CANVAS_WORKER_RETRY_AFTER_TIER", raising=False)
    monkeypatch.delenv("MARTY_CANVAS_WORKER_VALIDATION_TIER", raising=False)
    monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST", "1")
    monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE", "synthetic-image")
    monkeypatch.setenv("MARTY_CANVAS_WORKER_TEST_BINARY", "synthetic-worker")
    assert INVENTORY.run_contract(
        "canvas_worker_acceptance", [executable, *arguments], owner="canvas"
    ) == 0
    records = [
        json.loads(line.removeprefix(INVENTORY.CANVAS_PREFIX))
        for line in capsys.readouterr().out.splitlines()
        if line.startswith(INVENTORY.CANVAS_PREFIX)
    ]
    assert len(records) == 1
    assert records[0]["schema"] == "marty.rust-canvas-obligation/v1"
    assert records[0]["selected"] == records[0]["executed"] == [
        "happy",
        "happy_extra",
    ]
    assert records[0]["ignored"] == []
    assert records[0]["gate"] == "test-rust-services/canvas"
    assert records[0]["canvas_qualification_mode"] == expected_mode
    assert set(records[0]["worker_tiers"].values()) == {None}


def test_canvas_obligation_declares_kms_and_tier_names_without_values() -> None:
    composition = INVENTORY.obligation("canvas_composition_acceptance")[2]
    worker = INVENTORY.obligation("canvas_worker_acceptance")[2]
    composition_inputs = {item["name"]: item for item in composition}
    worker_inputs = {item["name"]: item for item in worker}
    assert {
        "MARTY_CANVAS_OPENBAO_URL",
        "MARTY_CANVAS_OPENBAO_ROOT_TOKEN",
        "MARTY_CANVAS_OPENBAO_CA_CERT_FILE",
    } <= composition_inputs.keys()
    assert {
        "MARTY_CANVAS_WORKER_RETRY_AFTER_TIER",
        "MARTY_CANVAS_WORKER_VALIDATION_TIER",
    } <= worker_inputs.keys()
    for item in (*composition, *worker):
        assert set(item) == {
            "name",
            "consumer",
            "owner",
            "provisioner",
            "requirement",
        }
        assert item["owner"] == "scripts/ci/run-published-canvas-contracts.sh"


def test_canvas_published_images_bind_exact_digest_and_selected_registry(
    monkeypatch,
) -> None:
    pins = json.loads(
        (ROOT / "contracts/canvas-worker-consumer-range-oracle.json").read_text(
            encoding="utf-8"
        )
    )
    postgres = pins["observed_postgres_image"]
    probe = pins["observed_image"]
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    for selected, expected in (
        (postgres, "canonical"),
        (f"mirror.gcr.io/library/{postgres}", "digest_preserving_mirror"),
    ):
        monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE", selected)
        evidence = INVENTORY.canvas_published_image_inputs()
        assert evidence["postgres_reference"] == postgres
        assert evidence["probe_reference"] == probe
        assert evidence["postgres_selection"] == expected
        assert evidence["pin_source_sha256"] == INVENTORY.digest(
            ROOT / evidence["pin_source"]
        )
        assert evidence["source_closure"] == "incomplete"


def test_canvas_published_image_selection_fails_closed_without_leaking_value(
    monkeypatch,
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    for selected in ("", "postgres:latest", "private-token@sha256:" + "0" * 64):
        monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE", selected)
        with pytest.raises(ValueError, match="canvas_published_postgres_selection_drift") as error:
            INVENTORY.canvas_published_image_inputs()
        if selected:
            assert selected not in str(error.value)


def test_canvas_published_image_pin_changes_require_review(tmp_path, monkeypatch) -> None:
    source = ROOT / "contracts/canvas-worker-consumer-range-oracle.json"
    destination = tmp_path / "contracts/canvas-worker-consumer-range-oracle.json"
    destination.parent.mkdir()
    pins = json.loads(source.read_text(encoding="utf-8"))
    pins["observed_postgres_image"] = "postgres:latest"
    destination.write_text(json.dumps(pins), encoding="utf-8")
    monkeypatch.setattr(INVENTORY, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="canvas_published_image_pin_drift"):
        INVENTORY.canvas_published_image_inputs()


def test_canvas_published_image_pin_must_exist(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(INVENTORY, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="canvas_published_image_pin_drift"):
        INVENTORY.canvas_published_image_inputs()


@pytest.mark.parametrize(
    ("name", "fixture"),
    (
        (
            "flow_acceptance",
            "rust/services/issuance/tests/support/canvas_published_database.rs",
        ),
        (
            "selfhost_acceptance",
            "rust/crates/canvas-acceptance/tests/support/owned_cleanup.rs",
        ),
        (
            "canvas_composition_acceptance",
            "rust/services/issuance/tests/support/canvas_published_database_diagnostic_tests.rs",
        ),
        (
            "canvas_worker_acceptance",
            "contracts/canvas-worker-body-timeout-oracle.json",
        ),
    ),
)
def test_acceptance_rust_first_hop_inputs_record_exact_source_hashes(name, fixture) -> None:
    inputs = INVENTORY.acceptance_rust_first_hop_inputs(name)
    paths = [item["path"] for item in inputs]
    assert paths == sorted(set(paths))
    assert INVENTORY.ACCEPTANCE_RUST_TEST_SOURCES[name] in paths
    assert fixture in paths
    if name == "canvas_composition_acceptance":
        assert {
            "rust/services/issuance/tests/support/bounded_fixture_command.rs",
            "rust/services/issuance/tests/support/bounded_fixture_command_tests.rs",
            "rust/services/issuance/tests/support/canvas_published_database.rs",
            "rust/services/issuance/tests/support/canvas_published_database_diagnostic_tests.rs",
        } <= set(paths)
    assert all(
        item["sha256"] == INVENTORY.digest(ROOT / item["path"]) for item in inputs
    )


@pytest.mark.parametrize(
    "source_content",
    (
        '#[path = concat!("private-", "fixture.rs")]\nmod fixture;\n',
        'include!(concat!("private-", "fixture.rs"));\n',
    ),
)
def test_acceptance_rust_first_hop_inputs_reject_unrecognized_import(
    tmp_path, monkeypatch, source_content
) -> None:
    source_path = INVENTORY.ACCEPTANCE_RUST_TEST_SOURCES["canvas_worker_acceptance"]
    source = tmp_path / source_path
    source.parent.mkdir(parents=True)
    source.write_text(source_content, encoding="utf-8")
    manifest = source.parent.parent / "Cargo.toml"
    manifest.write_text(
        '[package]\nname = "marty-canvas-worker-acceptance"\n'
        '[[test]]\nname = "canvas_published_worker_contract"\n'
        'path = "tests/canvas_published_worker_contract.rs"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(INVENTORY, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="acceptance_rust_source_input_drift") as error:
        INVENTORY.acceptance_rust_first_hop_inputs("canvas_worker_acceptance")
    assert "private-" not in str(error.value)


def test_canvas_composition_inventory_never_records_the_kms_token(
    real_obligation_harness, monkeypatch, capsys
) -> None:
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("MARTY_CANVAS_FULL_QUALIFICATION", raising=False)
    monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST", "1")
    monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE", "synthetic-image")
    monkeypatch.setenv("MARTY_ISSUANCE_TEST_BINARY", "synthetic-issuance")
    monkeypatch.setenv("MARTY_CANVAS_OPENBAO_URL", "https://127.0.0.1:1")
    monkeypatch.setenv("MARTY_CANVAS_OPENBAO_ROOT_TOKEN", "private-kms-token")
    monkeypatch.setenv("MARTY_CANVAS_OPENBAO_CA_CERT_FILE", "synthetic-ca")
    assert INVENTORY.run_contract(
        "canvas_composition_acceptance",
        [str(real_obligation_harness), "happy", "--exact", "--test-threads=1"],
        owner="canvas",
    ) == 0
    output = capsys.readouterr().out
    assert "private-kms-token" not in output
    record = next(
        json.loads(line.removeprefix(INVENTORY.CANVAS_PREFIX))
        for line in output.splitlines()
        if line.startswith(INVENTORY.CANVAS_PREFIX)
    )
    assert record["selected"] == record["executed"] == ["happy"]
    assert record["runtime_fixture_owner"].endswith("canvas_published_database.rs")
    assert record["transitive_source_closure"] == "incomplete"
    assert record["observed_first_hop_rust_source_inputs"] == (
        INVENTORY.acceptance_rust_first_hop_inputs("canvas_composition_acceptance")
    )


def test_canvas_obligation_files_are_separate_for_parallel_targets(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    for name in INVENTORY.CANVAS_EVIDENCE_NAMES:
        INVENTORY.emit(
            {"name": name, "schema": "marty.rust-canvas-obligation/v1", "status": "ok"}
        )
    assert capsys.readouterr().out.count(INVENTORY.CANVAS_PREFIX) == 2
    for name, filename in INVENTORY.CANVAS_EVIDENCE_NAMES.items():
        path = tmp_path / "rust-build-evidence" / filename
        assert json.loads(path.read_text(encoding="utf-8"))["name"] == name


def test_canvas_inventory_rejects_unreviewed_tier_before_harness_execution(
    real_obligation_harness, monkeypatch, capsys
) -> None:
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST", "1")
    monkeypatch.setenv("MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE", "synthetic-image")
    monkeypatch.setenv("MARTY_CANVAS_WORKER_TEST_BINARY", "synthetic-worker")
    monkeypatch.setenv("MARTY_CANVAS_FULL_QUALIFICATION", "0")
    monkeypatch.setenv("MARTY_CANVAS_WORKER_RETRY_AFTER_TIER", "unreviewed")
    monkeypatch.setenv("MARTY_CANVAS_WORKER_VALIDATION_TIER", "routine")
    assert INVENTORY.run_contract(
        "canvas_worker_acceptance",
        [str(real_obligation_harness), "happy", "--exact", "--test-threads=1"],
        owner="canvas",
    ) == 1
    output = capsys.readouterr().out
    assert "test happy ... ok" not in output
    record = next(
        json.loads(line.removeprefix(INVENTORY.CANVAS_PREFIX))
        for line in output.splitlines()
        if line.startswith(INVENTORY.CANVAS_PREFIX)
    )
    assert record["status"] == "failed"
    assert record["reason"] == "invalid_canvas_worker_tier"


def test_canvas_runner_routes_all_worker_and_composition_bodies_through_inventory() -> None:
    source = CANVAS_RUNNER.read_text(encoding="utf-8")
    assert source.count("--name canvas_worker_acceptance --owner canvas") == 9
    assert source.count("--name canvas_composition_acceptance --owner canvas") == 3
    for line in source.splitlines():
        if (
            ("$worker_executable" in line or "$composition_executable" in line)
            and "--nocapture" in line
        ):
            assert 'python3 "$obligation_runner" --name canvas_' in line


@pytest.mark.parametrize(
    "lines,results,reason",
    [
        (
            [
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            ],
            ["ok other"],
            "selected_executed_mismatch",
        ),
        ([], ["ok happy", "ok happy"], "duplicate_executed_case"),
        ([], ["ok happy"], "missing_or_ambiguous_libtest_summary"),
        (
            [
                "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            ],
            ["ok happy"],
            "selected_executed_mismatch",
        ),
        (
            [
                "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            ],
            ["ignored happy"],
            "selected_executed_mismatch",
        ),
        ([], ["private-runtime-value"], "unrecognized_libtest_result"),
    ],
)
def test_db_inventory_rejects_incomplete_or_inconsistent_execution(
    lines, results, reason
) -> None:
    with pytest.raises(ValueError, match=reason):
        INVENTORY.verify_execution(lines, results, {"happy"}, set())


def test_db_inventory_discards_ignored_reason_values() -> None:
    cases = INVENTORY.case_results(
        ["ignored: credential-sentinel fixture_case", "ok happy"]
    )
    assert cases == {"fixture_case": "ignored", "happy": "ok"}
    assert "credential-sentinel" not in json.dumps(cases)


def test_db_inventory_missing_result_log_fails_closed_and_cleans_temp_directory(
    tmp_path, monkeypatch
) -> None:
    import io

    class Child:
        stdout = io.BytesIO(
            b"test happy ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        )

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def wait(self):
            return 0

        def poll(self):
            return 0

    result_paths = []

    def fake_child(command, **kwargs):
        result_paths.append(Path(command[command.index("--logfile") + 1]))
        return Child()

    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("MARTY_TEST_REDIS_URL", "owned-fixture")
    monkeypatch.setenv("MARTY_TEST_REDIS_DISPOSABLE_NONCE", "owned-test-sentinel")
    monkeypatch.setattr(INVENTORY, "artifact_identity", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        INVENTORY, "expected_cases", lambda *args, **kwargs: ({"happy"}, set())
    )
    monkeypatch.setattr(INVENTORY, "spawn_harness", fake_child)
    assert INVENTORY.run_contract("issuer_profile", ["harness"]) == 1
    evidence = json.loads(
        (tmp_path / "rust-build-evidence" / INVENTORY.EVIDENCE_NAME).read_text()
    )
    assert evidence["reason"] == "missing_libtest_result_log"
    assert evidence["status"] == "failed"
    assert all(not path.parent.exists() for path in result_paths)


def test_db_inventory_records_real_failed_case_without_repeating_it(
    tmp_path, monkeypatch, real_obligation_harness, capsys
) -> None:
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("MARTY_TEST_REDIS_URL", "owned-fixture")
    monkeypatch.setenv("MARTY_TEST_REDIS_DISPOSABLE_NONCE", "owned-test-sentinel")
    monkeypatch.setenv("MARTY_LIBTEST_FORCE_FAILURE", "1")
    assert (
        INVENTORY.run_contract(
            "issuer_profile",
            [
                str(real_obligation_harness),
                "fixture_case_extra",
                "--ignored",
                "--exact",
                "--test-threads=1",
            ],
        )
        != 0
    )
    record = next(
        json.loads(line.removeprefix(INVENTORY.PREFIX))
        for line in capsys.readouterr().out.splitlines()
        if line.startswith(INVENTORY.PREFIX)
    )
    assert record["status"] == "failed"
    assert record["command_status"] != 0
    assert record["failed"] == 1
    assert record["executed"] == ["fixture_case_extra"]
    assert record["observed_cases"] == [
        {"name": "fixture_case_extra", "outcome": "FAILED"}
    ]


def test_db_inventory_is_run_bound_and_excludes_runtime_values(
    tmp_path, monkeypatch, real_obligation_harness, capsys
) -> None:
    executable = real_obligation_harness
    metadata = {
        "reason": "compiler-artifact",
        "package_id": "path+file:///checkout#marty-signing-keys@0.1.0",
        "target": {"kind": ["test"], "name": "issuer_profile_storage_contract"},
        "executable": str(executable),
        "features": ["default"],
    }
    (tmp_path / "rust-test-artifacts.json").write_text(json.dumps(metadata) + "\n")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    for key, value in zip(INVENTORY.RUN_IDENTITY, ("123", "2", "contracts", "a" * 40)):
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("MARTY_TEST_REDIS_URL", "redis://secret-value-never-recorded")
    monkeypatch.setenv("MARTY_TEST_REDIS_DISPOSABLE_NONCE", "sentinel-value-never-recorded")
    assert (
        INVENTORY.run_contract("issuer_profile", [str(executable), "happy", "--exact"])
        == 0
    )
    output = tmp_path / "rust-build-evidence" / INVENTORY.EVIDENCE_NAME
    record = json.loads(output.read_text())
    assert record["selected"] == record["executed"] == ["happy"]
    assert record["target"] == metadata["target"]["name"]
    assert record["package"] == "marty-signing-keys"
    assert record["run"] == dict(
        zip(INVENTORY.RUN_IDENTITY, ("123", "2", "contracts", "a" * 40))
    )
    assert record["executable_sha256"] == INVENTORY.digest(executable)
    assert record["compiler_artifacts_sha256"] == INVENTORY.digest(
        tmp_path / "rust-test-artifacts.json"
    )
    assert record["runtime_inputs"][0]["name"] == "MARTY_TEST_REDIS_URL"
    assert record["runtime_inputs"][0]["owner"] == INVENTORY.RUNNER_OWNER
    assert record["runtime_inputs"][1]["name"] == "MARTY_TEST_REDIS_DISPOSABLE_NONCE"
    assert "sentinel-value-never-recorded" not in output.read_text()
    assert (
        "secret-value-never-recorded"
        not in output.read_text() + capsys.readouterr().out
    )
    assert (
        INVENTORY.run_contract("issuer_profile", [str(executable), "absent", "--exact"])
        != 0
    )
    assert (
        json.loads(output.read_text().splitlines()[-1])["reason"]
        == "zero_selected_tests"
    )
    assert (
        INVENTORY.run_contract("issuer_profile", [str(executable), "--payload=secret"])
        != 0
    )
    assert "--payload=secret" not in output.read_text()
    for threads in ("--test-threads=thread-credential-value", "--test-threads=0"):
        assert INVENTORY.run_contract("issuer_profile", [str(executable), threads]) != 0
        assert threads not in output.read_text() + capsys.readouterr().out


def test_db_inventory_rejects_stale_foreign_ambiguous_or_missing_artifacts(
    tmp_path, monkeypatch, real_obligation_harness
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    executable = real_obligation_harness
    record = {
        "reason": "compiler-artifact",
        "package_id": "path+file:///checkout#marty-signing-keys@0.1.0",
        "target": {"kind": ["test"], "name": "registry_storage_contract"},
        "executable": str(executable),
    }
    artifact_file = tmp_path / "rust-test-artifacts.json"
    for records in (
        [],
        [dict(record, executable=str(tmp_path / "old-build"))],
        [dict(record, package_id="path+file:///checkout#foreign@0.1.0")],
        [dict(record, target={"kind": ["test"], "name": "document_storage_contract"})],
        [record, dict(record, executable=str(tmp_path / "another-build"))],
    ):
        artifact_file.write_text("".join(json.dumps(value) + "\n" for value in records))
        with pytest.raises(ValueError):
            INVENTORY.artifact_identity(
                executable, "marty-signing-keys", "registry_storage_contract"
            )
    artifact_file.write_text(json.dumps(record) + "\n")
    assert (
        INVENTORY.artifact_identity(
            executable, "marty-signing-keys", "registry_storage_contract"
        )["provenance"]
        == "same_run_compiler_artifact"
    )
    copied = tmp_path / "readable-contract-alias"
    shutil.copyfile(executable, copied)
    assert (
        INVENTORY.artifact_identity(
            copied, "marty-signing-keys", "registry_storage_contract"
        )["binding"]
        == "byte_identical_copy"
    )
    copied.write_bytes(b"stale contract build")
    with pytest.raises(ValueError, match="compiler_artifact_content_mismatch"):
        INVENTORY.artifact_identity(
            copied, "marty-signing-keys", "registry_storage_contract"
        )


def test_compiler_depfile_records_nested_source_and_embedded_fixture(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "checkout"
    executable = root / "rust/target/debug/deps/flow_acceptance-abcd.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"test executable")
    source = root / "rust/crates/flow-acceptance/tests/support/nested.rs"
    source.parent.mkdir(parents=True)
    source.write_text("// nested source\n", encoding="utf-8")
    fixture = root / "contracts/flow-oracle.json"
    fixture.parent.mkdir(parents=True)
    fixture.write_text('{"public":true}\n', encoding="utf-8")
    depfile = executable.with_suffix(".d")
    depfile.write_text(
        f"{depfile}: crates/flow-acceptance/tests/support/nested.rs "
        "../contracts/flow-oracle.json\n\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(INVENTORY, "ROOT", root)
    observed = INVENTORY.compiler_target_source_inputs(executable)
    assert observed == {
        "compiler_depfile_sha256": INVENTORY.digest(depfile),
        "compiler_target_source_scope": "single_rustc_test_target",
        "observed_compiler_target_source_inputs": [
            {"path": "contracts/flow-oracle.json", "sha256": INVENTORY.digest(fixture)},
            {
                "path": "rust/crates/flow-acceptance/tests/support/nested.rs",
                "sha256": INVENTORY.digest(source),
            },
        ],
    }
    artifacts = tmp_path / "rust-test-artifacts.json"
    artifacts.write_text(
        json.dumps(
            {
                "reason": "compiler-artifact",
                "package_id": "path+file:///checkout#marty-flow-acceptance@0.1.0",
                "target": {"kind": ["test"], "name": "flow_published_schema_contract"},
                "executable": str(executable),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    identity = INVENTORY.artifact_identity(
        executable,
        "marty-flow-acceptance",
        "flow_published_schema_contract",
        record_compiler_inputs=True,
    )
    assert identity["observed_compiler_target_source_inputs"] == observed[
        "observed_compiler_target_source_inputs"
    ]
    assert identity["binding"] == "same_path"
    alias = tmp_path / "flow-acceptance-alias"
    shutil.copyfile(executable, alias)
    aliased = INVENTORY.artifact_identity(
        alias,
        "marty-flow-acceptance",
        "flow_published_schema_contract",
        record_compiler_inputs=True,
    )
    assert aliased["binding"] == "byte_identical_copy"
    assert aliased["observed_compiler_target_source_inputs"] == observed[
        "observed_compiler_target_source_inputs"
    ]
    depfile.unlink()
    with pytest.raises(ValueError, match="compiler_target_source_input_drift"):
        INVENTORY.artifact_identity(
            executable,
            "marty-flow-acceptance",
            "flow_published_schema_contract",
            record_compiler_inputs=True,
        )


@pytest.mark.parametrize(
    "rule",
    [
        "wrong-target.d: crates/flow-acceptance/tests/support/nested.rs",
        "{depfile}: ../../private-source.rs",
        "{depfile}: crates/flow-acceptance/tests/support/missing.rs",
        "{depfile}: crates/flow-acceptance/tests/support/nested\\ source.rs",
        "{depfile}: ",
    ],
)
def test_compiler_depfile_rejects_unproved_or_foreign_inputs(
    tmp_path, monkeypatch, rule
) -> None:
    root = tmp_path / "checkout"
    executable = root / "rust/target/debug/deps/flow_acceptance-abcd.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"test executable")
    source = root / "rust/crates/flow-acceptance/tests/support/nested.rs"
    source.parent.mkdir(parents=True)
    source.write_text("// nested source\n", encoding="utf-8")
    (tmp_path / "private-source.rs").write_text("private\n", encoding="utf-8")
    depfile = executable.with_suffix(".d")
    depfile.write_text(rule.format(depfile=depfile) + "\n", encoding="utf-8")
    monkeypatch.setattr(INVENTORY, "ROOT", root)
    with pytest.raises(ValueError, match="compiler_target_source_input_drift") as error:
        INVENTORY.compiler_target_source_inputs(executable)
    assert "private-source" not in str(error.value)


def test_canvas_database_contracts_use_same_run_artifact_resolver() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    [step] = [
        entry
        for entry in steps
        if entry.get("name") == "Prepare database contract executables"
    ]
    assert "source ../scripts/ci/rust_contract_execution.sh" in step["run"]
    assert "resolve_issuance_canvas_contracts >/dev/null" in step["run"]
    runner = RUNNER.read_text(encoding="utf-8")
    assert 'if [[ -n "${RUNNER_TEMP:-}" ]]; then' in runner
    canvas_block = runner.split('if [[ -n "${RUNNER_TEMP:-}" ]]; then', 1)[1]
    assert (
        'canvas_contract_paths="$(resolve_issuance_canvas_contracts)"' in canvas_block
    )
    assert canvas_block.index("resolve_issuance_canvas_contracts") < canvas_block.index(
        "find target/debug/deps"
    )


def test_database_contract_preparation_uses_package_scoped_artifacts() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    [step] = [
        entry
        for entry in steps
        if entry.get("name") == "Prepare database contract executables"
    ]
    script = step["run"]
    assert "source ../scripts/ci/rust_contract_execution.sh" in script
    assert "tail -n 1" not in script
    assert "jq -r" not in script
    for package, target in (
        ("marty-revocation-profile", "contracts"),
        ("marty-signing-keys", "registry_storage_contract"),
        ("marty-signing-keys", "document_storage_contract"),
        ("marty-signing-keys", "issuer_profile_storage_contract"),
        ("marty-credential-template", "postgres_integration"),
        ("marty-credential-template", "migration_contract"),
        ("marty-presentation-policy", "postgres_integration"),
        ("marty-issuance-service", "issuance_transaction_postgres_contract"),
        ("marty-issuance-service", "credential_postgres_contract"),
        ("marty-issuance-service", "oid4vci_migration_postgres_contract"),
        ("marty-issuance-service", "application_template_postgres_contract"),
        ("marty-trust-profile", "migration_contract"),
        ("marty-organization", "migration_contract"),
        ("marty-organization", "application_postgres_integration"),
        ("marty-organization", "postgres_integration"),
        ("marty-flow", "postgres_integration"),
        ("marty-verification-service", "credentials_compat_postgres"),
        ("marty-gateway", "redis_runtime"),
    ):
        assert f"resolve_recorded_contract_executable {package} {target}" in script
    runner = RUNNER.read_text(encoding="utf-8")
    assert 'resolve_recorded_contract_executable "$package" "$target"' in runner


@pytest.mark.skipif(
    BASH is None or shutil.which("jq") is None,
    reason="Bash and jq are required to exercise the Cargo artifact resolver",
)
def test_recorded_contract_resolver_rejects_ambiguous_and_foreign_artifacts(
    tmp_path: Path,
) -> None:
    selected = tmp_path / "selected"
    foreign = tmp_path / "foreign"
    for executable in (selected, foreign):
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
    artifacts = tmp_path / "rust-test-artifacts.json"
    selected_record = {
        "reason": "compiler-artifact",
        "package_id": "path+file:///test#marty-organization@0.1.0",
        "target": {"name": "migration_contract", "kind": ["test"]},
        "executable": str(selected),
    }
    foreign_record = {
        **selected_record,
        "package_id": "path+file:///test#marty-trust-profile@0.1.0",
        "executable": str(foreign),
    }

    def resolve(entries: list[dict]) -> subprocess.CompletedProcess[str]:
        artifacts.write_text(
            "".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8"
        )
        return subprocess.run(
            [
                BASH,
                "-c",
                "set -euo pipefail; source scripts/ci/rust_contract_execution.sh; "
                "resolve_recorded_contract_executable marty-organization migration_contract",
            ],
            cwd=ROOT,
            env={**os.environ, "RUNNER_TEMP": str(tmp_path)},
            capture_output=True,
            text=True,
            check=False,
        )

    valid = resolve([selected_record, foreign_record])
    assert valid.returncode == 0, valid.stderr
    assert valid.stdout.strip() == str(selected)
    assert resolve([foreign_record]).returncode != 0
    assert (
        resolve(
            [selected_record, dict(selected_record, executable=str(foreign))]
        ).returncode
        != 0
    )
    assert (
        resolve(
            [
                dict(
                    selected_record,
                    target={"name": "migration_contract", "kind": ["bin"]},
                )
            ]
        ).returncode
        != 0
    )
    assert resolve([dict(selected_record, executable="/missing")]).returncode != 0


@pytest.mark.skipif(
    BASH is None or shutil.which("jq") is None,
    reason="Bash and jq are required to exercise the Cargo artifact resolver",
)
def test_canvas_database_contracts_resolve_only_this_runs_artifacts(
    tmp_path: Path,
) -> None:
    names = sorted(
        path.stem
        for path in (ROOT / "rust/services/issuance/tests").glob(
            "canvas_*_postgres_contract.rs"
        )
    ) + ["proof_nonce_postgres_contract"]
    assert len(names) == 11
    records = []
    paths = []
    for name in names:
        executable = tmp_path / name
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        paths.append(str(executable))
        records.append(
            {
                "reason": "compiler-artifact",
                "package_id": "path+file:///test#marty-issuance-service@0.1.0",
                "target": {"name": name, "kind": ["test"]},
                "executable": str(executable),
            }
        )
    unrelated = dict(records[0], package_id="path+file:///test#other@0.1.0")
    artifacts = tmp_path / "rust-test-artifacts.json"
    env = {**os.environ, "RUNNER_TEMP": str(tmp_path)}

    def resolve(entries: list[dict]) -> subprocess.CompletedProcess[str]:
        artifacts.write_text(
            "".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8"
        )
        return subprocess.run(
            [
                BASH,
                "-c",
                "set -euo pipefail; source scripts/ci/rust_contract_execution.sh; "
                "resolve_issuance_canvas_contracts",
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    valid = resolve([*records, unrelated])
    assert valid.returncode == 0, valid.stderr
    assert valid.stdout.splitlines() == sorted(paths)
    assert resolve(records[:-1]).returncode != 0
    duplicate = dict(records[0], executable=str(tmp_path / names[1]))
    assert resolve([*records, duplicate]).returncode != 0
    assert (
        resolve(
            [*records[:1], dict(records[1], executable="/missing"), *records[2:]]
        ).returncode
        != 0
    )


def test_canvas_serial_runner_uses_positive_execution_guard() -> None:
    source = CANVAS_RUNNER.read_text(encoding="utf-8")
    assert (
        'source "$(dirname "${BASH_SOURCE[0]}")/rust_contract_execution.sh"' in source
    )
    assert (
        'if [[ "$phase" == canvas_serial ]]; then\n    run_timed_rust_test "$phase" "$name" "$@"'
        in source
    )
    assert source.count("timed canvas_serial ") == 9


@pytest.mark.skipif(BASH is None, reason="Bash unavailable")
@pytest.mark.parametrize(
    "phase,invocation",
    [
        ("contract", "run_timed synthetic"),
        ("canvas_serial", "run_timed_rust_test canvas_serial synthetic"),
    ],
)
@pytest.mark.parametrize(
    "summary,exit_status,expected_status",
    [
        (
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s",
            0,
            0,
        ),
        (
            "test result: ok. 11 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.00s",
            0,
            0,
        ),
        (
            "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            0,
            1,
        ),
        ("no test summary", 0, 1),
        (
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s",
            7,
            7,
        ),
    ],
)
def test_direct_rust_test_requires_positive_summary_and_command_success(
    phase: str, invocation: str, summary: str, exit_status: int, expected_status: int
) -> None:
    result = subprocess.run(
        [
            BASH,
            "-c",
            # Exercise the real policy adapter as well as shell status propagation.
            f'python3() {{ "{Path(sys.executable).as_posix()}" "$@"; }}; '
            "source scripts/ci/rust_contract_execution.sh; "
            f'{invocation} bash tests/fixtures/fake_rust_contract.sh "$1" "$2"',
            "synthetic",
            str(exit_status),
            summary,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected_status, (result.stdout, result.stderr)
    assert summary in result.stdout
    marker = next(
        line.removeprefix("MARTY_CI_PHASE_V1 ")
        for line in result.stdout.splitlines()
        if line.startswith("MARTY_CI_PHASE_V1 ")
    )
    timing = json.loads(marker)
    assert timing["phase"] == phase
    assert timing["name"] == "synthetic"
    assert timing["duration_ms"] >= 0
    assert timing["status"] == ("ok" if expected_status == 0 else "failed")


def test_native_summary_policy_preserves_verbose_output_and_duplicate_refusal():
    # A legitimate child may print more than 16 MiB before its actual summary.
    summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s"
    assert INVENTORY.native_execution_policy("positive-summary", lines=["x" * (17 * 1024 * 1024), summary]) is True
    with pytest.raises(ValueError, match="missing_or_ambiguous_libtest_summary"):
        INVENTORY.verify_execution([summary, summary], ["ok happy"], {"happy"}, set())


def test_native_execution_identity_failure_emits_sanitized_refusal(monkeypatch):
    monkeypatch.setenv("MARTY_CI_EXECUTION_BIN", "private-path-sentinel")
    monkeypatch.setenv("MARTY_CI_EXECUTION_BIN_SHA256", "invalid")
    with pytest.raises(ValueError, match="^native_execution_policy_unavailable$"):
        INVENTORY.selection(["happy"])


def test_execution_policy_is_prepared_before_workflow_consumers():
    for workflow, job in [("ci.yml", "test-rust-services"), ("ci.yml", "test-release-contracts"), ("cd.yml", "build-operator-catalog")]:
        steps = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())["jobs"][job]["steps"]
        prepared = next(i for i, step in enumerate(steps) if step.get("run") == "bash scripts/ci/prepare-native-ci-execution.sh")
        consumed = next(i for i, step in enumerate(steps) if "rust_contract_execution.sh" in step.get("run", "") or step.get("name") == "Run repository release checks")
        if job == "test-release-contracts":
            assert "-m pytest tests " in steps[consumed]["run"]
        assert prepared < consumed


def test_native_case_results_preserve_completion_order():
    assert list(INVENTORY.case_results(["ok zeta", "ok alpha"])) == ["zeta", "alpha"]
