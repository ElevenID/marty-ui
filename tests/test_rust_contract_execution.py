"""Fail closed when direct Rust CI harnesses select no tests."""

import json
import importlib.util
import os
import re
import shutil
import subprocess
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

    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("MARTY_TEST_REDIS_URL", "private-credential-value")
    monkeypatch.setattr(INVENTORY, "artifact_identity", lambda *args: {})
    monkeypatch.setattr(INVENTORY, "expected_cases", lambda *args: ({"happy"}, set()))
    monkeypatch.setattr(INVENTORY.subprocess, "Popen", lambda *args, **kwargs: Child())
    assert INVENTORY.run_contract("issuer_profile", ["harness"]) == (child_status or 1)
    evidence = json.loads(
        (tmp_path / "rust-build-evidence" / INVENTORY.EVIDENCE_NAME).read_text()
    )
    assert evidence["status"] == "failed"
    assert evidence["command_status"] == child_status
    assert evidence["observed_cases"] == [{"name": "happy", "outcome": "FAILED"}]
    assert evidence["reason"] == "missing_or_ambiguous_libtest_summary"
    assert "private-credential-value" not in capsys.readouterr().out


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
    real_obligation_harness, arguments, selected, ignored
) -> None:
    executable = str(real_obligation_harness)
    actual_selected, actual_ignored = INVENTORY.expected_cases(executable, arguments)
    assert actual_selected == selected
    assert actual_ignored == ignored
    run = subprocess.run(
        [
            executable,
            *arguments,
            "--test-threads=1",
            "--format",
            "pretty",
            "--color",
            "never",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    evidence = INVENTORY.verify_execution(run.stdout.splitlines(), selected, ignored)
    assert evidence["executed"] == sorted(selected)
    assert evidence["ignored"] == sorted(ignored)


@pytest.mark.parametrize(
    "lines,reason",
    [
        (
            [
                "test other ... ok",
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            ],
            "selected_executed_mismatch",
        ),
        (["test happy ... ok", "test happy ... ok"], "duplicate_executed_case"),
        (["test happy ... ok"], "missing_or_ambiguous_libtest_summary"),
        (
            [
                "test happy ... ok",
                "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            ],
            "selected_executed_mismatch",
        ),
        (
            [
                "test happy ... ignored",
                "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s",
            ],
            "selected_executed_mismatch",
        ),
    ],
)
def test_db_inventory_rejects_incomplete_or_inconsistent_execution(
    lines, reason
) -> None:
    with pytest.raises(ValueError, match=reason):
        INVENTORY.verify_execution(lines, {"happy"}, set())


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
            # Git Bash on Windows has no python3; only the guard is under test.
            "python3() { date +%s%N; }; "
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
