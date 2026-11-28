from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
import tomllib
import yaml

ROOT = Path(__file__).parents[1]
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_TEST_COMMAND = (
    "set -euo pipefail\n"
    "printf 'release-contract memory counters before:\\n'\n"
    "cat /sys/fs/cgroup/memory.events 2>/dev/null || true\n"
    "grep '^oom_kill ' /proc/vmstat 2>/dev/null || true\n"
    "trap 'status=$?; printf \"release-contract memory counters after:\\n\"; "
    "cat /sys/fs/cgroup/memory.events 2>/dev/null || true; "
    "grep \"^oom_kill \" /proc/vmstat 2>/dev/null || true; exit \"$status\"' EXIT\n"
    "python -X faulthandler -m pytest tests -n 2 --dist=loadscope -v --tb=short --durations=20\n"
)
ROOT_OPTIONAL_SECRET_CASES = (
    "test_creates_exact_seven_empty_private_files",
    "test_enabled_integration_cannot_receive_empty_secret",
    "test_late_mode_failure_rolls_back_owned_outputs",
)


def test_disposable_tls_root_contracts_have_executed_release_owner() -> None:
    _, workflow = _workflow(CI_PATH)
    steps = workflow["jobs"]["test-release-contracts"]["steps"]
    named = {step.get("name"): step for step in steps}
    general = named["Run repository release checks"]
    root = named["Exercise root-owned disposable TLS staging contracts"]
    assert root["if"] == general["if"]
    assert steps.index(root) == steps.index(general) + 1
    assert root["shell"] == "bash"
    command = root["run"]
    assert 'python_bin="$(command -v python)"' in command
    assert "sudo env PYTHONPATH=packages PYTHONDONTWRITEBYTECODE=1" in command
    assert "-p no:cacheprovider --junitxml=" in command
    for name in (
        "test_stages_only_public_tls_outputs_into_existing_private_root",
        "test_ownership_failure_removes_all_staged_tls_inputs",
        "test_metadata_cleanup_failure_still_rolls_back_all_secrets",
        "test_timeout_cleanup_retains_id_only_if_removal_fails",
    ):
        assert command.count(f"test_provision_selfhost_disposable_tls.py::{name}") == 1
    assert "len(cases) != 6" in command
    for required in ('("tests", 6)', '("skipped", 0)', '("failures", 0)', '("errors", 0)'):
        assert required in command


def test_fresh_vm_creation_has_required_root_release_owner() -> None:
    _, workflow = _workflow(CI_PATH)
    steps = workflow["jobs"]["test-release-contracts"]["steps"]
    named = {step.get("name"): step for step in steps}
    general = named["Run repository release checks"]
    tls = named["Exercise root-owned disposable TLS staging contracts"]
    vm = named["Exercise root-owned fresh VM creation contracts"]
    assert vm["if"] == general["if"]
    assert steps.index(vm) == steps.index(tls) + 1
    assert vm["shell"] == "bash"
    command = vm["run"]
    assert "qemu-utils ubuntu-keyring" in command
    assert "cloud-image-utils openssh-client cloud-init" in command
    assert "sudo env PYTHONPATH=packages PYTHONDONTWRITEBYTECODE=1" in command
    assert command.count("tests/test_installer_candidate_vm_create.py") == 1
    assert command.count("tests/test_installer_candidate_vm_runtime.py") == 1
    assert command.count("tests/test_installer_candidate_vm_seed.py") == 1
    assert command.count("tests/test_installer_candidate_vm_launch.py") == 1
    assert command.count("tests/test_installer_candidate_vm_live_observe.py") == 1
    assert command.count("tests/test_installer_candidate_vm_target.py") == 1
    assert command.count("tests/test_installer_candidate_vm_host_probe.py") == 1
    assert command.count("tests/test_installer_candidate_vm_host_preflight.py") == 1
    assert command.count("tests/test_installer_candidate_vm_exchange.py") == 1
    assert command.count("tests/test_installer_candidate_vm_rootless.py") == 1
    assert command.count("tests/test_installer_engineering_trial.py") == 1
    assert "-p no:cacheprovider --junitxml=" in command
    for required in ('len(cases) != 158', '("tests", 158)', '("skipped", 0)',
                     '("failures", 0)', '("errors", 0)'):
        assert required in command


def test_optional_secret_staging_has_required_root_release_owner() -> None:
    _, workflow = _workflow(CI_PATH)
    steps = workflow["jobs"]["test-release-contracts"]["steps"]
    named = {step.get("name"): step for step in steps}
    general = named["Run repository release checks"]
    vm = named["Exercise root-owned fresh VM creation contracts"]
    root = named["Exercise root-owned optional secret staging contracts"]
    assert root["if"] == general["if"]
    assert steps.index(root) == steps.index(vm) + 1
    assert root["shell"] == "bash"
    assert root.get("continue-on-error", False) is False
    command = root["run"]
    assert command.startswith("set -euo pipefail\n")
    assert 'python_bin="$(command -v python)"' in command
    assert 'sudo env PYTHONPATH=packages PYTHONDONTWRITEBYTECODE=1 "$python_bin"' in command
    assert re.findall(r"\btests/[^\s\\]+", command) == [
        f"tests/test_stage_selfhost_disabled_optional_secrets.py::{name}"
        for name in ROOT_OPTIONAL_SECRET_CASES
    ]
    # Resolve the actual selected tests, rather than comparing two copies of
    # a selector that could both retain a deleted test name.
    selectors = [
        f"tests/test_stage_selfhost_disabled_optional_secrets.py::{name}"
        for name in ROOT_OPTIONAL_SECRET_CASES
    ]
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:cacheprovider", *selectors],
        cwd=ROOT,
        env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert collected.returncode == 0, collected.stdout + collected.stderr
    assert [line for line in collected.stdout.splitlines()
            if line.startswith("tests/")] == selectors
    assert "-p no:cacheprovider --junitxml=" in command
    for required in ('len(cases) != 3', '("tests", 3)', '("skipped", 0)',
                     '("failures", 0)', '("errors", 0)'):
        assert required in command


@pytest.mark.parametrize(
    "attributes,case_tag,case_count,name_override,passes",
    [
        ({}, "", 3, None, True),
        ({"skipped": "1"}, "skipped", 3, None, False),
        ({}, "skipped", 3, None, False),
        ({"failures": "1"}, "failure", 3, None, False),
        ({}, "failure", 3, None, False),
        ({"errors": "1"}, "error", 3, None, False),
        ({}, "error", 3, None, False),
        ({"tests": "2"}, "", 2, None, False),
        ({}, "", 2, None, False),
        ({}, "", 3, ROOT_OPTIONAL_SECRET_CASES[1], False),
        ({}, "", 3, "test_unrelated", False),
    ],
)
def test_optional_secret_root_report_requires_executed_passing_cases(
    tmp_path: Path,
    attributes: dict[str, str],
    case_tag: str,
    case_count: int,
    name_override: str | None,
    passes: bool,
) -> None:
    _, workflow = _workflow(CI_PATH)
    command = next(
        step["run"] for step in workflow["jobs"]["test-release-contracts"]["steps"]
        if step.get("name") == "Exercise root-owned optional secret staging contracts"
    )
    validator = command.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    counters = {"tests": "3", "skipped": "0", "failures": "0", "errors": "0"}
    counters.update(attributes)
    names = list(ROOT_OPTIONAL_SECRET_CASES[:case_count])
    if name_override is not None:
        names[0] = name_override
    cases = "".join(
        f'<testcase name="{name}">'
        + (f"<{case_tag}/>" if case_tag and index == 0 else "")
        + "</testcase>"
        for index, name in enumerate(names)
    )
    report = tmp_path / "root-optional-secrets.xml"
    summary = " ".join(f'{name}="{value}"' for name, value in counters.items())
    report.write_text(
        f"<testsuites><testsuite {summary}>{cases}</testsuite></testsuites>",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-", str(report)], input=validator,
        text=True, capture_output=True, check=False,
    )
    assert (result.returncode == 0) is passes, result.stderr


def test_crawler_uses_the_locally_installed_puppeteer_browser_cli() -> None:
    job = yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))["jobs"][
        "test-ui-crawler-artifacts"
    ]
    bootstrap = next(
        step["run"]
        for step in job["steps"]
        if step.get("name") == "Bootstrap released UI dependencies"
    )
    assert bootstrap.index("PUPPETEER_SKIP_DOWNLOAD=true bun install") < bootstrap.index(
        "bun x --no-install puppeteer browsers install"
    )
    assert "timeout 180s bun x --no-install puppeteer browsers install" in bootstrap
    assert 'if [ "$attempt" -eq 3 ]; then' in bootstrap
    assert "exit 1" in bootstrap


def test_selfhost_operator_guide_is_a_packaged_input() -> None:
    manifest = json.loads(
        (ROOT / "deploy-config" / "bundles" / "selfhost.json").read_text(
            encoding="utf-8"
        )
    )
    assert "SELFHOST_BUNDLE.md" in manifest["assets"]
    assert (ROOT / "SELFHOST_BUNDLE.md").is_file()


def test_platform_release_contracts_have_linux_ci_dependencies():
    job = yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))["jobs"][
        "test-release-contracts"
    ]
    assert job["runs-on"] == "ubuntu-24.04"
    setup_python = next(
        step for step in job["steps"]
        if step.get("uses", "").startswith("actions/setup-python@")
    )
    assert setup_python["with"]["python-version"] == "3.12.10"
    steps = {step.get("name"): step for step in job["steps"]}
    installation = steps["Install released test dependencies"]["run"]
    command = next(
        line
        for line in installation.splitlines()
        if "uv pip install --system pytest" in line
    )
    assert {"pytest", "pytest-xdist==3.8.0", "sqlalchemy", "playwright"} <= set(command.split())
    assert "'jsonschema[format]>=4.23'" in command.split()
    browser = steps["Install Python browser transport runtime"]
    assert browser["run"] == "python -m playwright install --with-deps --only-shell chromium"
    assert browser["if"] == steps["Run repository release checks"]["if"]
    assert job["steps"].index(steps["Install released test dependencies"]) < job["steps"].index(browser)
    assert job["steps"].index(browser) < job["steps"].index(steps["Run repository release checks"])
    bun = steps["Set up the native auth callback build runtime"]
    companion = steps["Install locked native auth callback build dependencies"]
    assert bun["uses"] == "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6"
    assert bun["with"]["bun-version"] == "1.4.4"
    assert companion["working-directory"] == "integrations/supabase-auth-ui"
    assert shlex.split(companion["run"]) == [
        "bun", "install", "--frozen-lockfile", "--ignore-scripts",
    ]
    for bootstrap in (bun, companion):
        assert bootstrap["if"] == steps["Run repository release checks"]["if"]
        assert not bootstrap.get("continue-on-error", False)
    assert job["steps"].index(bun) < job["steps"].index(companion)
    assert job["steps"].index(companion) < job["steps"].index(steps["Run repository release checks"])
    assert (
        steps["Run repository release checks"]["run"]
        == RELEASE_TEST_COMMAND
    )


def _workflow(path: Path) -> tuple[str, dict[str, object]]:
    source = path.read_text(encoding="utf-8")
    return source, yaml.safe_load(source)


def test_off_path_ci_qualifies_full_platform_without_weakening_pr_gates() -> None:
    source, document = _workflow(CI_PATH)
    assert "  workflow_dispatch:\n" in source
    assert document[True]["schedule"] == [{"cron": "17 4 * * 0"}]
    import runpy
    assert runpy.run_path(str(ROOT / "scripts/ci/affected_components.py"))["FULL_MATRIX"] == ["contracts", "flow", "selfhost"]
    classifier = next(
        step
        for step in document["jobs"]["changes"]["steps"]
        if step.get("id") == "classify"
    )
    assert 'elif [[ "$EVENT_NAME" != pull_request ]]; then\n  all=true' in (ROOT / "scripts/ci/affected_components.sh").read_text()
    assert (
        "github.event.pull_request.base.sha || github.event.merge_group.base_sha || ''"
        in (classifier["env"]["BASE_SHA"])
    )
    rust_steps = document["jobs"]["test-rust-services"]["steps"]
    database = next(step for step in rust_steps if step.get("name") == "Run isolated database contract suites concurrently")
    assert database["if"] == "matrix.lane != 'renewal-unit'"
    for command in ("bash ../scripts/ci/run-flow-acceptance-contracts.sh",
                    "bash ../scripts/ci/run-selfhost-acceptance-contracts.sh",
                    "python3 ../scripts/ci/run-db-contract-groups.py rust-db"):
        assert command in database["run"]
    assert "continue-on-error" not in database


def _assert_python_service_job_preserves_full_suite(document) -> None:
    job = document["jobs"]["test-services"]
    assert job["needs"] == ["changes", "release-preflight"]
    assert job["if"] == "needs.changes.outputs.python == 'true'"
    assert not job.get("continue-on-error", False)
    assert not job.get("services")
    assert not job.get("env")
    tests = [step for step in job["steps"] if step.get("name") == "Run tests"]
    assert len(tests) == 1
    assert tests[0] == {
        "name": "Run tests",
        "working-directory": "services",
        "run": "python -m pytest -v --tb=short -x",
    }
    rust = document["jobs"]["test-rust-services"]
    assert not rust.get("services")
    fixtures = yaml.safe_load(
        (ROOT / ".github/compose/rust-ci-fixtures.yml").read_text(encoding="utf-8")
    )["services"]
    assert set(fixtures) == {"postgres", "redis", "openbao"}
    for service, port in (("postgres", 5432), ("redis", 6379)):
        fixture = fixtures[service]
        assert fixture["pull_policy"] == "never"
        assert fixture["ports"] == [f"{port}:{port}"]
        assert fixture["healthcheck"]["retries"] >= 20
    openbao = fixtures["openbao"]
    assert openbao["image"].startswith("quay.io/openbao/openbao@sha256:")
    assert openbao["pull_policy"] == "never"
    assert openbao["ports"] == ["8200:8200"]
    assert openbao["environment"] == {
        "BAO_DEV_ROOT_TOKEN_ID": "test-only",
        "BAO_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
    }
    setup = next(
        step for step in rust["steps"]
        if step.get("name") == "Start digest-pinned Rust test services after registry setup"
    )
    assert setup["if"] == "matrix.lane != 'selfhost' && matrix.lane != 'renewal-unit'"
    for image in (
        "postgres:15-alpine@sha256:fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c",
        "redis:7.4-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99",
        openbao["image"],
    ):
        assert image in setup["run"]
    assert "up -d --wait --wait-timeout 90" in setup["run"]
    cleanup = next(
        step for step in rust["steps"]
        if step.get("name") == "Remove owned Rust test services and volumes"
    )
    assert cleanup["if"] == (
        "always() && matrix.lane != 'selfhost' && matrix.lane != 'renewal-unit'"
    )
    assert "down --volumes --remove-orphans" in cleanup["run"]
    chain_step_name = (
        "Exercise scoped grant and managed passport chain over disposable HTTPS OpenBao"
    )
    managed_chain = next(
        step for step in rust["steps"] if step.get("name") == chain_step_name
    )["run"]
    assert managed_chain == "python3 scripts/probe_signing_keys_openbao_policy.py --grant-verifier"
    policy_probe = (ROOT / "scripts/probe_signing_keys_openbao_policy.py").read_text(
        encoding="utf-8"
    )
    assert '"passport_managed_kms_chain"' in policy_probe
    assert "managed_passport_chain_issues_and_verifies_sod_without_exporting_private_keys" in policy_probe
    assert '"service_certificate_live_kms"' in policy_probe
    assert "live_grant_verification_is_one_use_before_kms_signing" in policy_probe
    for suite in (
        "vdsnc_registration_live_contract",
        "public_key_metadata_live_contract",
        "public_config_resolve_mock_contract",
        "service_rotation_mock_contract",
        "persisted_registry_credentials_use_real_openbao_ciphertext",
    ):
        assert suite in policy_probe
    for case in (
        "authenticated_gateway_reaches_remaining_rust_signing_handlers",
        "authenticated_gateway_rotates_only_a_dedicated_signing_service",
        "authenticated_gateway_generates_profile_scoped_passport_csrs_in_openbao",
        "authenticated_gateway_generates_a_dedicated_service_csr_in_openbao",
        "authenticated_gateway_issues_dsc_with_operator_grant_and_dedicated_key",
    ):
        assert case in policy_probe
    redis_contracts = next(
        step["run"]
        for step in rust["steps"]
        if step.get("name") == "Exercise live Signing Keys public contracts on disposable Redis"
    )
    assert "--test public_key_metadata_live_contract" not in redis_contracts
    assert rust["env"]["FLOW_POSTGRES_TEST_URL"].endswith(
        "localhost:5432/marty_atomic_test"
    )
    assert rust["env"]["VERIFICATION_SESSION_TEST_DATABASE_URL"].endswith(
        "localhost:5432/marty_atomic_test"
    )


def test_gateway_signing_acceptance_discovery_fails_on_any_missing_case() -> None:
    _, document = _workflow(CI_PATH)
    steps = document["jobs"]["test-rust-services"]["steps"]
    guard = next(
        step
        for step in steps
        if step.get("name") == "Require all Gateway Signing acceptance cases"
    )
    script = guard["run"]
    assert guard["if"] == "matrix.lane == 'contracts'"
    assert guard["working-directory"] == "rust"
    assert "rust-test-artifacts.json" in script
    assert 'select(.target.name == "gateway_signing_acceptance")' in script
    assert 'contains("#marty-service-acceptance@")' in script
    assert script.count('"$acceptance_executable" --list') == 1
    assert "cargo " not in script
    names_source = script.split("for test_name in", 1)[1].split("; do", 1)[0]
    names = re.findall(r"(?:authenticated_gateway_|byok_gateway_)[a-z_]+", names_source)
    rust_source = (
        ROOT / "rust/crates/service-acceptance/tests/gateway_signing_acceptance.rs"
    ).read_text(encoding="utf-8")
    actual = re.findall(
        r"(?m)^async fn ((?:authenticated_gateway_|byok_gateway_)[a-z_]+)\(",
        rust_source,
    )
    assert len(names) == len(set(names)) == 7
    assert set(names) == set(actual)

    # Execute the workflow's real membership loop with synthetic discovery
    # output, without compiling Rust or contacting Redis/OpenBao.
    loop = script[script.index("for test_name in") :]
    bash = "bash"
    if os.name == "nt":
        git = shutil.which("git")
        assert git is not None
        bash = str(Path(git).parent.parent / "bin/bash.exe")
    for missing in (None, *names):
        listed = "\n".join(f"{name}: test" for name in names if name != missing)
        result = subprocess.run(
            [
                bash,
                "-c",
                f'set -euo pipefail\nlisted_tests="$1"\n{loop}',
                "guard",
                listed,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if missing is None:
            assert result.returncode == 0, result.stderr
        else:
            assert result.returncode != 0
            assert (
                f"Missing Gateway Signing acceptance case: {missing}" in result.stderr
            )


def test_gateway_live_config_case_has_exact_contracts_lane_invocation() -> None:
    _, document = _workflow(CI_PATH)
    steps = document["jobs"]["test-rust-services"]["steps"]
    execution = next(
        step
        for step in steps
        if step.get("name") == "Exercise authenticated Signing Keys Gateway to Rust routes"
    )
    assert execution["if"] == "matrix.lane == 'contracts'"
    script = execution["run"]
    assert "MARTY_TEST_REDIS_DISPOSABLE_NONCE=\"$nonce\"" in script
    assert "with_disposable_event_stream_kms.py" in script
    assert "--profile signing-transit" in script
    assert "BAO_TOKEN=test-only" not in script
    assert "-p marty-service-acceptance --test gateway_signing_acceptance" in script
    assert re.search(
        r"byok_gateway_proxies_to_live_signing_keys_without_persisting_private_material"
        r"\s+\\\s+-- --ignored --exact",
        script,
    )
    acceptance = (
        ROOT / "rust/crates/service-acceptance/tests/gateway_signing_acceptance.rs"
    ).read_text(encoding="utf-8")
    assert "async fn byok_gateway_proxies_to_live_signing_keys_without_persisting_private_material(" in acceptance
    assert "byok_gateway_proxies_to_live_signing_keys_without_persisting_private_material" not in (
        ROOT / "rust/services/gateway/src/runtime.rs"
    ).read_text(encoding="utf-8")


def test_oidf_keyless_edge_has_live_https_kms_contracts_lane_invocation() -> None:
    _, document = _workflow(CI_PATH)
    steps = document["jobs"]["test-rust-services"]["steps"]
    [execution] = [
        step for step in steps
        if step.get("name") == "Exercise OIDF keyless HTTPS edge against disposable OpenBao"
    ]
    assert execution["if"] == "matrix.lane == 'contracts'"
    script = execution["run"]
    assert "--profile oidf-edge" in script
    assert "tests::oidf_https_handshake_signs_with_versioned_remote_key" in script
    assert "-- --ignored --exact --nocapture" in script


def test_remote_holder_live_kms_has_one_acceptance_owner_and_exact_ci_call() -> None:
    target = "holder_remote_live_kms"
    case = "registration_provision_sign_and_deactivate_delete_remote_key"
    acceptance = ROOT / "rust/crates/service-acceptance"
    source = acceptance / "tests" / f"{target}.rs"
    assert source.is_file()
    assert f"async fn {case}()" in source.read_text(encoding="utf-8")
    assert not (ROOT / "rust/services/device-registration/tests" / f"{target}.rs").exists()
    acceptance_manifest = (acceptance / "Cargo.toml").read_text(encoding="utf-8")
    assert f'name = "{target}"\npath = "tests/{target}.rs"' in acceptance_manifest
    device_manifest = (
        ROOT / "rust/services/device-registration/Cargo.toml"
    ).read_text(encoding="utf-8")
    assert "marty-signing-keys" not in device_manifest
    _, workflow = _workflow(CI_PATH)
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    execution = next(
        step for step in steps
        if step.get("name")
        == "Qualify scoped provider callback verification against disposable OpenBao"
    )
    assert execution["if"] == "matrix.lane == 'contracts'"
    assert execution["run"] == (
        "python3 scripts/probe_signing_keys_openbao_policy.py --rust-adapter"
    )
    assert all(
        "holder_remote_live_kms" not in step.get("run", "") for step in steps
    )
    probe = (ROOT / "scripts/probe_signing_keys_openbao_policy.py").read_text(
        encoding="utf-8"
    )
    assert probe.count('"--test", "holder_remote_live_kms"') == 1
    assert f'"{case}"' in probe
    assert '"--", "--ignored", "--exact", "--nocapture"' in probe
    assert '"BAO_CACERT": str(ca_file)' in probe
    assert '"MARTY_TEST_OPENBAO_TOKEN": managed' in probe
    assert "if not rust_test_succeeded(result):" in probe


def test_python_service_job_retires_only_unused_fixture_provisioning() -> None:
    _assert_python_service_job_preserves_full_suite(_workflow(CI_PATH)[1])


def _classify_changed_paths(
    changed_paths: list[str],
    tmp_path: Path,
    *,
    combined: bool = False,
    event: str = "pull_request",
    include_rust_plan: bool = False,
    include_rollback_plan: bool = False,
    include_k8s_plan: bool = False,
    include_didcomm_plan: bool = False,
    include_shadow: bool = False,
    proof_failure: bool = False,
    fetch_failure: bool = False,
    missing_base: bool = False,
    working_directory: Path | None = None,
) -> list[dict[str, str]]:
    """Exercise the real Bash classifier against synthetic diffs."""
    _, document = _workflow(CI_PATH)
    [classifier] = [
        step
        for step in document["jobs"]["changes"]["steps"]
        if step.get("id") == "classify"
    ]
    assert event in {"pull_request", "merge_group", "push", "workflow_dispatch", "schedule"}
    assert classifier["run"].strip() == "source scripts/ci/affected_components.sh"
    script = (ROOT / "scripts/ci/affected_components.sh").read_text()
    classifier_path = shlex.quote((ROOT / "scripts/ci/affected_components.py").as_posix())
    script = script.replace("python3 scripts/ci/affected_components.py", "python3 " + classifier_path)
    assert "${{" not in script
    # Run the actual Bash classifier, not a Python copy of its path patterns.
    # Git is a shell-local synthetic owner, so neither fetch nor diff touches a
    # repository or network. Results go to an owned synthetic output file, not
    # the real Actions output file (/dev/stdout is unavailable in Git Bash).
    prelude = """
git() {
  case "$1" in
    fetch) return 0 ;;
    rev-parse) printf '%s\\n' "$SOURCE_SHA" ;;
    diff)
      [[ " $* " == *" -z "* && " $* " == *" --no-renames "* ]] || return 98
      printf '%s\\0' "$SYNTHETIC_CHANGED_PATH" ;;
    *) return 99 ;;
  esac
}
python3() {
  if [[ "$1" == tests/test_rust_test_only_docker_context.py &&
        "${2:-}" == --emit-verified-leaves ]]; then
    # Every synthetic diff in this one Bash process uses the same immutable
    # checkout. Run the real proof once, but exercise the real classifier and
    # exact output independently for each diff. A failed proof is never cached.
    if [[ "${SYNTHETIC_LEAVES_READY:-false}" != true ]]; then
      "$SYNTHETIC_PYTHON" "$@" > "$RUNNER_TEMP/synthetic-verified-leaves" || return
      SYNTHETIC_LEAVES_READY=true
    fi
    cat "$RUNNER_TEMP/synthetic-verified-leaves"
  else
    "$SYNTHETIC_PYTHON" "$@"
  fi
}
SYNTHETIC_LEAVES_READY=false
export BASE_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
index=0
while IFS= read -r -d '' SYNTHETIC_CHANGED_PATH; do
  export SYNTHETIC_CHANGED_PATH
  export GITHUB_OUTPUT="$RUNNER_TEMP/synthetic-actions-output-$index"
  : > "$GITHUB_OUTPUT"
"""
    epilogue = """
  index=$((index + 1))
done < "$SYNTHETIC_PATHS_FILE"
"""
    if proof_failure:
        start = prelude.index("python3() {")
        end = prelude.index("\nexport BASE_SHA=", start)
        prelude = prelude[:start] + 'python3() { if [[ "$1" == tests/test_rust_test_only_docker_context.py ]]; then return 43; else "$SYNTHETIC_PYTHON" "$@"; fi; }' + prelude[end:]
    if fetch_failure:
        prelude = prelude.replace("fetch) return 0 ;;", "fetch) return 44 ;;")
    if missing_base:
        prelude = prelude.replace(
            "export BASE_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "export BASE_SHA=''"
        )
    if event not in {"pull_request", "merge_group"}:
        prelude = prelude.replace("export BASE_SHA=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "export BASE_SHA=''")
    paths_to_run = changed_paths
    if combined:
        # One git diff containing multiple paths must preserve every selected
        # obligation, not just the last matching case arm.
        diff_file = tmp_path / "synthetic-combined-diff"
        diff_file.write_bytes(
            (b"\0".join(path.encode("utf-8") for path in changed_paths) + b"\0")
            if changed_paths
            else b""
        )
        prelude = prelude.replace(
            "printf '%s\\0' \"$SYNTHETIC_CHANGED_PATH\"",
            'cat "$SYNTHETIC_DIFF_FILE"',
        )
        assert 'cat "$SYNTHETIC_DIFF_FILE"' in prelude
        paths_to_run = ["combined"]
    # Windows' system bash launcher may point at an unconfigured WSL distro;
    # use the Git Bash already required for this checkout's shell workflows.
    git_bash = Path("C:/Program Files/Git/bin/bash.exe")
    bash = (
        str(git_bash)
        if os.name == "nt" and git_bash.is_file()
        else shutil.which("bash")
    )
    assert bash, "Bash is required to execute the workflow classifier regression"
    environment = dict(os.environ)
    environment.pop("BASH_ENV", None)
    environment.pop("ENV", None)
    environment.update(EVENT_NAME=event, SOURCE_SHA="a" * 40, HEAD_SHA="a" * 40)
    environment["RUNNER_TEMP"] = tmp_path.as_posix()
    environment["SYNTHETIC_PYTHON"] = Path(sys.executable).as_posix()
    if combined:
        environment["SYNTHETIC_DIFF_FILE"] = diff_file.as_posix()
    path_file = tmp_path / "synthetic-changed-paths"
    path_file.write_bytes(
        b"\0".join(path.encode("utf-8") for path in paths_to_run) + b"\0"
    )
    environment["SYNTHETIC_PATHS_FILE"] = path_file.as_posix()
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-s"],
        input=prelude + script + epilogue,
        text=True,
        capture_output=True,
        check=False,
        # This executes the complete tracked-source ownership proof, not just
        # a string classifier. Bound hangs without treating runner load as
        # failure evidence; no ownership or full-plan fallback is relaxed.
        timeout=120,
        env=environment,
        cwd=working_directory or ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    outputs = [
        {
            key: value
            for key, value in (
                line.split("=", 1) for line in output.read_text().splitlines()
            )
            if (
                key not in {"website", "website_only", "plan"}
                and (include_rust_plan or key not in {"rust_runtime", "rust_matrix"})
                and (include_rollback_plan or key != "rollback_test_only")
                and (include_k8s_plan or key != "k8s_policy_test_only")
                and (include_didcomm_plan or key != "didcomm_release_test_only")
            )
        }
        for output in (
            tmp_path / f"synthetic-actions-output-{index}"
            for index in range(len(paths_to_run))
        )
    ]
    if include_shadow:
        marker = "MARTY_CI_HISTORICAL_INPUT_SHADOW_V1 "
        records = [
            json.loads(line.removeprefix(marker))
            for line in result.stderr.splitlines()
            if line.startswith(marker)
        ]
        assert len(records) == len(outputs), result.stderr
        for output, record in zip(outputs, records, strict=True):
            output["historical_shadow"] = json.dumps(record, sort_keys=True)
    return outputs


def _classify_changed_path(changed_path: str, tmp_path: Path) -> dict[str, str]:
    return _classify_changed_paths([changed_path], tmp_path)[0]


def test_merge_group_historical_input_shadow_keeps_full_validation(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    checkout = workflow["jobs"]["changes"]["steps"][0]
    assert "if" not in checkout
    assert checkout["with"]["persist-credentials"] is False
    for path, candidate in (
        ("contracts/http-json-diagnostic-scenarios.json", "true"),
        ("scripts/run_outbound_http_timeout_oracle.py", "true"),
        ("rust/services/issuance/migrations/20260101.sql", "true"),
        ("rust/services/issuance/src/outbound_http.rs", "false"),
    ):
        selected = _classify_changed_paths(
            [path], tmp_path, event="merge_group", include_shadow=True
        )[0]
        observed = json.loads(selected.pop("historical_shadow"))
        assert set(selected.values()) == {"true"}
        assert observed == {
            "event": "merge_group",
            "diff": "proved",
            "path_count": 1,
            "candidate": candidate,
            "authority": "shadow-only",
        }
    mixed = _classify_changed_paths(
        [
            "contracts/http-json-diagnostic-scenarios.json",
            "rust/services/issuance/src/outbound_http.rs",
        ],
        tmp_path,
        combined=True,
        event="merge_group",
        include_shadow=True,
    )[0]
    assert json.loads(mixed.pop("historical_shadow")) == {
        "event": "merge_group",
        "diff": "proved",
        "path_count": 2,
        "candidate": "true",
        "authority": "shadow-only",
    }
    assert set(mixed.values()) == {"true"}
    for failure in ({"fetch_failure": True}, {"missing_base": True}):
        with pytest.raises(AssertionError):
            _classify_changed_paths(
                ["contracts/http-json-diagnostic-scenarios.json"], tmp_path,
                event="merge_group", include_shadow=True, **failure,
            )


def test_verified_rust_test_leaves_select_owned_unit_or_contracts_not_runtime(
    tmp_path: Path,
) -> None:
    verified = subprocess.run(
        [
            sys.executable,
            "tests/test_rust_test_only_docker_context.py",
            "--emit-verified-leaves",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    assert verified[-1] == b"" and len(verified) == 7
    leaves = [value.decode("utf-8") for value in verified[:-1]]
    unit_leaves = [
        (
            "rust/services/issuance/src/initiation_didcomm/tests/"
            "initiation_didcomm_renewal_tests.rs"
        ),
        "rust/services/issuance/src/signing_http_response_tests.rs",
        "rust/services/issuance/src/token_rate_limit_http_tests.rs",
    ]
    assert set(unit_leaves) <= set(leaves)
    assert leaves[-2:] == [
        "rust/crates/oid4vp-contract/tests/contract_vectors.rs",
        "rust/crates/oid4vp-contract/tests/transport_metadata.rs",
    ]
    nested = (
        "rust/services/issuance/src/initiation_didcomm/tests/"
        "initiation_didcomm_renewal_tests.rs"
    )
    assert nested in leaves
    assert nested in unit_leaves
    assert (
        "rust/services/issuance/src/passport_http_reconciliation_tests.rs"
        not in unit_leaves
    )
    for leaf, selected in zip(
        leaves,
        _classify_changed_paths(leaves, tmp_path, include_rust_plan=True),
        strict=True,
    ):
        assert selected == {
            "all": "false",
            "ui": "false",
            "python": "false",
            "rust": "true",
            "rust_runtime": "false",
            "rust_matrix": (
                '["renewal-unit"]' if leaf in unit_leaves else '["contracts"]'
            ),
            "openbao": "false",
            "release": "false",
            "verification": "false",
            "security": "false",
        }
    assert (
        _classify_changed_paths(
            leaves, tmp_path, combined=True, include_rust_plan=True
        )[0]["rust_matrix"]
        == '["contracts"]'
    )
    assert (
        _classify_changed_paths(
            unit_leaves, tmp_path, combined=True, include_rust_plan=True
        )[0]["rust_matrix"]
        == '["renewal-unit"]'
    )
    assert (
        _classify_changed_paths(
            [unit_leaves[0], leaves[-1]], tmp_path,
            combined=True, include_rust_plan=True,
        )[0]["rust_matrix"]
        == '["contracts"]'
    )

    mixed = _classify_changed_paths(
        [leaves[0], "rust/services/issuance/src/lib.rs"],
        tmp_path,
        combined=True,
        include_rust_plan=True,
    )[0]
    assert mixed["rust_runtime"] == "true"
    assert mixed["rust_matrix"] == '["contracts","flow","selfhost"]'
    for paths in (
        ["rust/services/issuance/src/unreviewed_tests.rs"],
        ["rust/crates/oid4vp-contract/tests/unreviewed.rs"],
        ["rust/crates/oid4vp-contract/tests/contract_vectors.rs\nother"],
        ["rust/crates/oid4vp-contract/src/lib.rs"],
        ["contracts/oid4vp-authenticated-contract-v1.json"],
        [leaves[0], "docs/renamed-test-source.md"],
        [leaves[-1], "rust/crates/oid4vp-contract/src/lib.rs"],
        [leaves[-1], "rust/crates/oid4vp-contract/tests/renamed_metadata.rs"],
    ):
        selected = _classify_changed_paths(
            paths, tmp_path, combined=True, include_rust_plan=True
        )[0]
        assert selected["rust_runtime"] == "true"
        assert selected["rust_matrix"] == '["contracts","flow","selfhost"]'
    # A deleted leaf cannot pass the source-ownership proof in the checkout.
    deleted = _classify_changed_paths(
        [leaves[0]], tmp_path, include_rust_plan=True, proof_failure=True
    )[0]
    assert deleted["rust_runtime"] == "true"
    assert deleted["rust_matrix"] == '["contracts","flow","selfhost"]'
    unit_without_proof = _classify_changed_paths(
        [unit_leaves[0]], tmp_path, include_rust_plan=True, proof_failure=True
    )[0]
    assert unit_without_proof["rust_runtime"] == "true"
    assert unit_without_proof["rust_matrix"] == '["contracts","flow","selfhost"]'
    nested_without_proof = _classify_changed_paths(
        [nested], tmp_path, include_rust_plan=True, proof_failure=True
    )[0]
    assert nested_without_proof["rust_runtime"] == "true"
    assert nested_without_proof["rust_matrix"] == '["contracts","flow","selfhost"]'
    oid_without_proof = _classify_changed_paths(
        [leaves[-1]], tmp_path, include_rust_plan=True, proof_failure=True
    )[0]
    assert oid_without_proof["rust_runtime"] == "true"
    assert oid_without_proof["rust_matrix"] == '["contracts","flow","selfhost"]'
    oid_deleted = _classify_changed_paths(
        [leaves[-2]], tmp_path, include_rust_plan=True, proof_failure=True
    )[0]
    assert oid_deleted["rust_runtime"] == "true"
    assert oid_deleted["rust_matrix"] == '["contracts","flow","selfhost"]'
    empty = _classify_changed_paths(
        [], tmp_path, combined=True, include_rust_plan=True
    )[0]
    assert empty["rust"] == empty["rust_runtime"] == "false"
    assert empty["rust_matrix"] == '["contracts","flow","selfhost"]'
    queued = _classify_changed_paths(
        [unit_leaves[0]], tmp_path, event="merge_group", include_rust_plan=True
    )[0]
    assert queued["all"] == queued["rust_runtime"] == "true"
    assert queued["rust_matrix"] == '["contracts","flow","selfhost"]'
    on_main = _classify_changed_paths(
        [leaves[-1]], tmp_path, event="push", include_rust_plan=True
    )[0]
    assert on_main["rust_runtime"] == "true"
    assert on_main["rust_matrix"] == '["contracts","flow","selfhost"]'


def test_verified_contract_test_sources_select_contracts_only_on_pr(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    [classifier] = [
        step
        for step in workflow["jobs"]["changes"]["steps"]
        if step.get("id") == "classify"
    ]
    # Keep headroom below GitHub's 21,000-character expression limit.
    assert len(classifier["run"].encode("utf-8")) < 20_500
    assert (
        (ROOT / "scripts/ci/affected_components.sh").read_text().index("rust/crates/service-acceptance/tests/*|")
        < (ROOT / "scripts/ci/affected_components.sh").read_text().index("--select-contract-tests")
    )
    assert (
        (ROOT / "scripts/ci/affected_components.sh").read_text().index("rust/services/signing-keys/tests/*)")
        < (ROOT / "scripts/ci/affected_components.sh").read_text().index("--select-contract-tests")
    )
    verified = subprocess.run(
        [
            sys.executable,
            "tests/test_rust_test_only_docker_context.py",
            "--emit-verified-contract-tests",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    assert verified[-1] == b"" and len(verified) == 11
    contract_tests = [value.decode("utf-8") for value in verified[:-1]]
    assert contract_tests == [
        "rust/crates/service-acceptance/tests/csca_capability_contract.rs",
        "rust/crates/service-acceptance/tests/gateway_signing_acceptance.rs",
        "rust/crates/service-acceptance/tests/holder_remote_live_kms.rs",
        "rust/crates/service-acceptance/tests/passport_gateway_postgres.rs",
        "rust/crates/service-acceptance/tests/passport_managed_kms_chain.rs",
        "rust/crates/service-acceptance/tests/tls_openbao_keyless.rs",
        "rust/crates/service-acceptance/tests/support/holder_issuer_authority.rs",
        "rust/crates/service-acceptance/tests/support/holder_native_receipt.rs",
        "rust/services/signing-keys/tests/csca_lifecycle_behavior.rs",
        "rust/services/signing-keys/tests/csca_lifecycle_storage_contract.rs",
    ]
    expected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "true",
        "rust_runtime": "false",
        "rust_matrix": '["contracts"]',
        "openbao": "false",
        "release": "false",
        "verification": "false",
        "security": "false",
    }
    assert (
        _classify_changed_paths(contract_tests, tmp_path, include_rust_plan=True)
        == [expected] * len(contract_tests)
    )
    assert _classify_changed_paths(
        contract_tests, tmp_path, combined=True, include_rust_plan=True
    ) == [expected]
    for paths in (
        [contract_tests[0], "docs/architecture-feedback-improvement-plan.md"],
        [contract_tests[1], "rust/crates/service-acceptance/Cargo.toml"],
        [contract_tests[2], "rust/crates/service-acceptance/tests/unreviewed.rs"],
        [
            contract_tests[0],
            "rust/crates/selfhost-acceptance/tests/selfhost_public_image_contract.rs",
        ],
        [contract_tests[0] + "\nother"],
        [contract_tests[4], "rust/services/signing-keys/tests/unreviewed.rs"],
        [contract_tests[5], "rust/services/signing-keys/Cargo.toml"],
    ):
        selected = _classify_changed_paths(
            paths, tmp_path, combined=True, include_rust_plan=True
        )[0]
        assert selected["rust_runtime"] == "true"
        assert selected["rust_matrix"] == '["contracts","flow","selfhost"]'
    unverified = _classify_changed_paths(
        [contract_tests[0]], tmp_path, include_rust_plan=True, proof_failure=True
    )[0]
    assert unverified["rust_runtime"] == "true"
    assert unverified["rust_matrix"] == '["contracts","flow","selfhost"]'
    queued = _classify_changed_paths(
        [contract_tests[-1]], tmp_path, event="merge_group", include_rust_plan=True
    )[0]
    assert queued["all"] == queued["rust_runtime"] == "true"
    assert queued["rust_matrix"] == '["contracts","flow","selfhost"]'
    on_main = _classify_changed_paths(
        [contract_tests[-1]], tmp_path, event="push", include_rust_plan=True
    )[0]
    assert on_main["rust_runtime"] == "true"
    assert on_main["rust_matrix"] == '["contracts","flow","selfhost"]'
    jobs = yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))["jobs"]
    assert jobs["test-rust-services"]["if"] == "needs.changes.outputs.rust == 'true'"
    contract_steps = jobs["test-rust-services"]["steps"]
    [workspace_owner] = [
        step for step in contract_steps if step.get("name") == "Run safe Rust contract groups concurrently"
    ]
    assert "cargo test --locked --workspace" in workspace_owner["run"]
    assert "--exclude marty-signing-keys" not in workspace_owner["run"]
    assert "source ../scripts/ci/rust_contract_execution.sh" in workspace_owner["run"]
    assert (
        workspace_owner["run"].count(
            "run_timed verification target/debug/verification-postgres-contract"
        )
        == 1
    )
    assert (
        workspace_owner["run"].count(
            "run_timed gateway target/debug/gateway-redis-contract"
        )
        == 1
    )
    [live_owner] = [
        step for step in contract_steps
        if step.get("name") == "Exercise live Signing Keys public contracts on disposable Redis"
    ]
    assert "csca_lifecycle_storage_contract:2" in live_owner["run"]
    assert live_owner["if"] == "matrix.lane == 'contracts'"
    assert "test-rust-services" in jobs["ci-gate"]["needs"]
    assert (
        'require_selected test-rust-services "$RUST_SERVICES_RESULT" "$RUST_SELECTED"'
        in jobs["ci-gate"]["steps"][0]["run"]
    )


def test_verified_flow_test_sources_select_only_flow_on_pr(tmp_path: Path) -> None:
    verified = subprocess.run(
        [
            sys.executable,
            "tests/test_rust_test_only_docker_context.py",
            "--emit-verified-flow-tests",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    assert verified[-1] == b"" and len(verified) == 12
    flow_tests = [value.decode("utf-8") for value in verified[:-1]]
    assert flow_tests == [
        "rust/crates/flow-acceptance/tests/flow_published_schema_contract.rs",
        "rust/crates/flow-acceptance/tests/support/base_runtime_redis.rs",
        "rust/crates/flow-acceptance/tests/support/didcomm_flow_grpc_admission.rs",
        "rust/crates/flow-acceptance/tests/support/didcomm_gateway_replay.rs",
        "rust/crates/flow-acceptance/tests/support/flow_admission.rs",
        "rust/crates/flow-acceptance/tests/support/flow_legacy_physical_http.rs",
        "rust/crates/flow-acceptance/tests/support/flow_native_consumer.rs",
        "rust/crates/flow-acceptance/tests/support/flow_public_startup.rs",
        "rust/crates/flow-acceptance/tests/support/flow_public_startup_peers.rs",
        "rust/crates/flow-acceptance/tests/support/flow_rendered_selection.rs",
        "rust/crates/flow-acceptance/tests/support/managed_http_provider_tls.rs",
    ]
    expected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "true",
        "rust_runtime": "false",
        "rust_matrix": '["flow"]',
        "openbao": "false",
        "release": "false",
        "verification": "false",
        "security": "false",
    }
    assert _classify_changed_paths(
        flow_tests, tmp_path, include_rust_plan=True
    ) == [expected] * 11
    assert _classify_changed_paths(
        flow_tests, tmp_path, combined=True, include_rust_plan=True
    ) == [expected]
    for paths in (
        [flow_tests[0], "docs/architecture-feedback-improvement-plan.md"],
        [flow_tests[1], "rust/crates/flow-acceptance/Cargo.toml"],
        [flow_tests[-1], "rust/acceptance/support/base_runtime_redis.rs"],
        ["rust/crates/flow-acceptance/tests/support/unreviewed.rs"],
        [flow_tests[2] + "\nother"],
    ):
        selected = _classify_changed_paths(
            paths, tmp_path, combined=True, include_rust_plan=True
        )[0]
        assert selected["rust_runtime"] == "true"
        assert selected["rust_matrix"] == '["contracts","flow","selfhost"]'
    without_proof = _classify_changed_paths(
        [flow_tests[0]], tmp_path, include_rust_plan=True, proof_failure=True
    )[0]
    assert without_proof["rust_runtime"] == "true"
    assert without_proof["rust_matrix"] == '["contracts","flow","selfhost"]'
    queued = _classify_changed_paths(
        [flow_tests[0]], tmp_path, event="merge_group", include_rust_plan=True
    )[0]
    assert queued["all"] == queued["rust_runtime"] == "true"
    assert queued["rust_matrix"] == '["contracts","flow","selfhost"]'


def test_verified_selfhost_test_sources_select_only_selfhost_on_pr(
    tmp_path: Path,
) -> None:
    verified = subprocess.run(
        [
            sys.executable,
            "tests/test_rust_test_only_docker_context.py",
            "--emit-verified-selfhost-tests",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    assert verified[-1] == b"" and len(verified) == 4
    selfhost_tests = [value.decode("utf-8") for value in verified[:-1]]
    assert selfhost_tests == [
        "rust/crates/selfhost-acceptance/tests/selfhost_public_image_contract.rs",
        "rust/crates/selfhost-acceptance/tests/support/selfhost_packaged_runtime.rs",
        "rust/crates/selfhost-acceptance/tests/support/selfhost_runtime_sidecar.rs",
    ]
    expected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "true",
        "rust_runtime": "false",
        "rust_matrix": '["selfhost"]',
        "openbao": "false",
        "release": "false",
        "verification": "false",
        "security": "false",
    }
    assert _classify_changed_paths(
        selfhost_tests, tmp_path, include_rust_plan=True
    ) == [expected] * 3
    assert _classify_changed_paths(
        selfhost_tests, tmp_path, combined=True, include_rust_plan=True
    ) == [expected]
    for paths in (
        [selfhost_tests[0], "docs/architecture-feedback-improvement-plan.md"],
        [selfhost_tests[1], "rust/crates/selfhost-acceptance/Cargo.toml"],
        [selfhost_tests[-1], "rust/services/issuance/tests/support/platform_test_database.rs"],
        ["rust/crates/selfhost-acceptance/tests/support/unreviewed.rs"],
        [selfhost_tests[2] + "\nother"],
    ):
        selected = _classify_changed_paths(
            paths, tmp_path, combined=True, include_rust_plan=True
        )[0]
        assert selected["rust_runtime"] == "true"
        assert selected["rust_matrix"] == '["contracts","flow","selfhost"]'
    without_proof = _classify_changed_paths(
        [selfhost_tests[0]], tmp_path, include_rust_plan=True, proof_failure=True
    )[0]
    assert without_proof["rust_runtime"] == "true"
    assert without_proof["rust_matrix"] == '["contracts","flow","selfhost"]'
    queued = _classify_changed_paths(
        [selfhost_tests[0]], tmp_path, event="merge_group", include_rust_plan=True
    )[0]
    assert queued["all"] == queued["rust_runtime"] == "true"
    assert queued["rust_matrix"] == '["contracts","flow","selfhost"]'


def test_generated_beta_image_inputs_retain_full_runtime_matrix(
    tmp_path: Path,
) -> None:
    # The generated-image check is owned by the runtime/image job. None of
    # its production, Compose, helper, or workflow inputs may take leaf-only CI.
    for path in (
        "rust/services/issuance/src/lib.rs",
        "docker-compose.beta.yml",
        "scripts/beta-application-image-plan.ps1",
        "scripts/test_beta_application_image_compose.py",
        ".github/workflows/ci.yml",
    ):
        assert (ROOT / path).is_file(), path
        selected = _classify_changed_paths([path], tmp_path, include_rust_plan=True)[0]
        assert selected["rust"] == selected["rust_runtime"] == "true", path
        assert selected["rust_matrix"] == '["contracts","flow","selfhost"]', path
    queued = _classify_changed_paths(
        ["rust/services/issuance/src/lib.rs"],
        tmp_path,
        event="merge_group",
        include_rust_plan=True,
    )[0]
    assert queued["all"] == queued["rust_runtime"] == "true"
    assert queued["rust_matrix"] == '["contracts","flow","selfhost"]'


def test_openbao_plugin_changes_select_required_image_lane(tmp_path: Path) -> None:
    for path in (
        "openbao/didcomm-authcrypt/backend/haip.go",
        "docker/openbao-haip-migration-audit-policy.hcl",
        "keycloak/openbao-provider/src/main/java/dev/marty/keycloak/kms/RemoteDirectJwe.java",
        "scripts/probe_keycloak_remote_rs256.py",
        "scripts/sql/keycloak-kms-only-verify.sql",
    ):
        selected = _classify_changed_path(path, tmp_path)
        assert selected["openbao"] == selected["rust"] == selected["security"] == "true"
    for path in (
        "rust/services/flow/src/request_object.rs",
        "rust/services/flow/src/verification_submission.rs",
        "rust/services/flow/src/http_providers.rs",
        "rust/services/flow/tests/haip_live_signing.rs",
        "rust/services/signing-keys/src/flow_envelope.rs",
        "rust/services/signing-keys/src/http.rs",
        "rust/services/signing-keys/src/http/certificate_operations.rs",
        "rust/services/signing-keys/src/kms.rs",
        "rust/services/signing-keys/src/kms_azure.rs",
        "rust/services/signing-keys/src/kms_gcp.rs",
        "rust/services/signing-keys/src/kms_aws.rs",
        "rust/crates/oid4vp-contract/src/haip_key.rs",
    ):
        selected = _classify_changed_path(path, tmp_path)
        assert selected["openbao"] == selected["rust"] == selected["security"] == "true"
    assert (
        _classify_changed_path("rust/services/flow/src/lib.rs", tmp_path)["openbao"]
        == "false"
    )
    assert (
        _classify_changed_paths(
            ["rust/services/flow/src/lib.rs"], tmp_path, event="merge_group"
        )[0]["openbao"]
        == "true"
    )

    _, document = _workflow(CI_PATH)
    job = document["jobs"]["test-openbao-didcomm-plugin"]
    assert job["if"] == "needs.changes.outputs.openbao == 'true'"
    image_build = next(
        step for step in job["steps"]
        if step.get("name") == "Test and build the pinned OpenBao plugin image"
    )
    assert image_build["with"]["file"] == "openbao/didcomm-authcrypt/Dockerfile"
    keycloak_build = next(
        step for step in job["steps"]
        if step.get("name") == "Build the pinned Keycloak remote-key image"
    )
    assert keycloak_build["with"]["file"] == "keycloak/openbao-provider/Dockerfile"
    keycloak_gate = next(
        step for step in job["steps"]
        if step.get("name") == "Qualify Keycloak browser, CIBA, KMS-loss, and PostgreSQL custody"
    )
    assert keycloak_gate["env"]["MARTY_PASSKEY_PACKAGED_IMAGE"] == "marty-keycloak-openbao:ci"
    assert keycloak_gate["env"]["MARTY_PASSKEY_PACKAGED_OPENBAO_IMAGE"] == "marty-openbao-didcomm:ci"
    assert "tests/test_keycloak_passkey_packaged.py::test_packaged_passkeys_keep_remote_custody_and_surviving_authentication_methods" in keycloak_gate["run"]
    assert "google-chrome --version" in keycloak_gate["run"]
    # The composite proof must still invoke the complete prior custody/browser
    # probe, and add qualification inside its live PostgreSQL/KMS lifetime.
    packaged = (ROOT / "tests/test_keycloak_passkey_packaged.py").read_text()
    assert "kms.probe(KEYCLOAK_IMAGE, OPENBAO_IMAGE" in packaged
    assert "require_browser=True, qualify_ready=qualify_passkeys" in packaged
    storage_gate = next(
        step
        for step in job["steps"]
        if step.get("name")
        == "Qualify packaged plugin storage and self-host Raft behavior"
    )
    assert (
        storage_gate["env"]["MARTY_OPENBAO_PROBE_IMAGE"] == "marty-openbao-didcomm:ci"
    )
    for probe in (
        "probe_didcomm_issuance_token.py",
        "probe_didcomm_openbao_file_storage.py",
        "probe_selfhost_openbao_raft_bootstrap.py",
        "probe_didcomm_openbao_ha.py",
    ):
        assert probe in storage_gate["run"]
    assert not any(
        step.get("name") == "Qualify live Raft snapshot export and recovery"
        for step in job["steps"]
    )
    coordinated_gate = next(
        step
        for step in job["steps"]
        if step.get("name")
        == "Qualify Rust integration-secret recovery with coordinated PostgreSQL and Raft restore"
    )
    assert (
        coordinated_gate["env"]["MARTY_OPENBAO_PROBE_IMAGE"]
        == "marty-openbao-didcomm:ci"
    )
    assert coordinated_gate["env"]["CARGO_PROFILE_DEV_DEBUG"] == 0
    assert coordinated_gate["env"]["CARGO_PROFILE_TEST_DEBUG"] == 0
    assert "probe_integration_secret_coordinated_restore.py" in coordinated_gate["run"]
    assert job["timeout-minutes"] >= 30
    assert "CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go vet ./..." in (
        ROOT / "openbao/didcomm-authcrypt/Dockerfile"
    ).read_text(encoding="utf-8")
    assert "test-openbao-didcomm-plugin" in document["jobs"]["ci-gate"]["needs"]


@pytest.mark.parametrize(
    "primary,retry,expected_success",
    [
        ("success", "skipped", True),
        ("failure", "success", True),
        ("failure", "failure", False),
        ("failure", "skipped", False),
        ("failure", "cancelled", False),
        ("cancelled", "skipped", False),
        ("skipped", "skipped", False),
        ("skipped", "success", False),
        ("success", "failure", False),
        ("success", "success", False),
        ("", "", False),
        ("unknown", "success", False),
    ],
)
def test_keycloak_image_retry_keeps_build_and_integration_required(
    primary: str, retry: str, expected_success: bool
) -> None:
    _, document = _workflow(CI_PATH)
    job = document["jobs"]["test-openbao-didcomm-plugin"]
    steps = job["steps"]
    first = next(step for step in steps if step.get("id") == "keycloak_image_build")
    second = next(step for step in steps if step.get("id") == "keycloak_image_retry")
    pause = next(
        step for step in steps
        if step.get("name") == "Wait before retrying the pinned Keycloak image"
    )
    gate = next(
        step for step in steps
        if step.get("name") == "Require the pinned Keycloak image build"
    )
    image_builds = [
        step for step in steps
        if step.get("with", {}).get("file") == "keycloak/openbao-provider/Dockerfile"
    ]
    assert image_builds == [first, second]
    assert steps.index(first) < steps.index(pause) < steps.index(second) < steps.index(gate)
    assert not job.get("continue-on-error")
    assert "test-openbao-didcomm-plugin" in document["jobs"]["ci-gate"]["needs"]
    assert not first.get("if")
    assert first["continue-on-error"] is second["continue-on-error"] is True
    assert pause["if"] == second["if"] == "steps.keycloak_image_build.outcome == 'failure'"
    assert pause["run"] == "sleep 10"
    assert not pause.get("continue-on-error")
    assert first["uses"] == second["uses"] == (
        "docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc"
    )
    assert first["with"] == second["with"] == {
        "context": ".",
        "file": "keycloak/openbao-provider/Dockerfile",
        "load": True,
        "push": False,
        "tags": "marty-keycloak-openbao:ci",
        "provenance": False,
    }
    assert gate["if"] == "always()"
    assert gate["shell"] == "bash"
    assert not gate.get("continue-on-error")
    assert gate["env"] == {
        "PRIMARY_OUTCOME": "${{ steps.keycloak_image_build.outcome }}",
        "RETRY_OUTCOME": "${{ steps.keycloak_image_retry.outcome }}",
    }
    for name in (
        "Qualify Keycloak browser, CIBA, KMS-loss, and PostgreSQL custody",
        "Qualify packaged plugin storage and self-host Raft behavior",
        "Qualify Rust integration-secret recovery with coordinated PostgreSQL and Raft restore",
    ):
        integration = next(step for step in steps if step.get("name") == name)
        assert steps.index(gate) < steps.index(integration)
        assert not integration.get("if") and not integration.get("continue-on-error")

    git_bash = Path("C:/Program Files/Git/bin/bash.exe")
    bash = str(git_bash) if os.name == "nt" and git_bash.is_file() else shutil.which("bash")
    assert bash, "Bash is required to exercise the Keycloak image gate"
    environment = {**os.environ, "PRIMARY_OUTCOME": primary, "RETRY_OUTCOME": retry}
    environment.pop("BASH_ENV", None)
    environment.pop("ENV", None)
    result = subprocess.run(
        [bash, "-c", gate["run"]], env=environment, capture_output=True,
        text=True, check=False,
    )
    assert (result.returncode == 0) is expected_success
    if not expected_success:
        assert "Pinned Keycloak image build did not succeed" in result.stderr


@pytest.mark.parametrize(
    "mutation",
    [
        "drop-tests",
        "narrow-tests",
        "ignore-tests",
        "skip-step",
        "skip-job",
        "tolerate-failure",
        "restore-fixture",
        "restore-url",
        "drop-rust-postgres",
        "drop-rust-redis",
        "drop-rust-openbao",
        "wrong-directory",
    ],
)
def test_python_service_cleanup_guard_rejects_weakened_coverage(mutation) -> None:
    document = _workflow(CI_PATH)[1]
    job = document["jobs"]["test-services"]
    step = next(step for step in job["steps"] if step.get("name") == "Run tests")
    if mutation == "drop-tests":
        job["steps"].remove(step)
    elif mutation == "narrow-tests":
        step["run"] += " -k image_strategy"
    elif mutation == "ignore-tests":
        step["run"] += " --ignore=common/tests"
    elif mutation == "skip-step":
        step["if"] = "false"
    elif mutation == "skip-job":
        job["if"] = "false"
    elif mutation == "tolerate-failure":
        step["continue-on-error"] = True
    elif mutation == "restore-fixture":
        job["services"] = {"redis": {"image": "redis:7"}}
    elif mutation == "restore-url":
        job["env"] = {"FLOW_POSTGRES_TEST_URL": "postgresql://localhost:5432/unused"}
    elif mutation.startswith("drop-rust-"):
        setup = next(
            step for step in document["jobs"]["test-rust-services"]["steps"]
            if step.get("name") == "Start digest-pinned Rust test services after registry setup"
        )
        setup["run"] = setup["run"].replace(
            {"postgres": "postgres:15-alpine@sha256:fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c",
             "redis": "redis:7.4-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99",
             "openbao": "quay.io/openbao/openbao@sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878"}[
                mutation.removeprefix("drop-rust-")
            ], "removed")
    elif mutation == "wrong-directory":
        step["working-directory"] = "tests"
    else:
        raise AssertionError("unreviewed mutation")
    with pytest.raises(AssertionError):
        _assert_python_service_job_preserves_full_suite(document)


def test_pull_request_classifier_is_conservative_and_merge_queue_is_complete() -> None:
    source, document = _workflow(CI_PATH)
    jobs = document["jobs"]
    changes = jobs["changes"]

    assert changes["name"] == "Classify Changes"
    assert set(changes["outputs"]) == {
        "all",
        "ui",
        "website",
        "website_only",
        "plan",
        "python",
        "rust",
        "rust_runtime",
        "rust_matrix",
        "openbao",
        "rollback_test_only",
        "didcomm_release_test_only",
        "k8s_policy_test_only",
        "release",
        "verification",
        "security",
    }
    classifier_source = (ROOT / "scripts/ci/affected_components.sh").read_text()
    assert '"$EVENT_NAME" == merge_group' in classifier_source
    assert "Unknown paths deliberately receive the complete suite." in classifier_source

    conditional_jobs = {
        "test-website",
        "fast-feedback",
        "test-ui",
        "test-ui-crawler-artifacts",
        "test-ui-crawler-nginx",
        "test-services",
        "test-rust-feature-probe",
        "test-rust-services",
        "test-openbao-didcomm-plugin",
        "test-native-operator",
        "rust-lint-policy",
        "test-rust-service-images",
        "public-protocol-contract",
        "test-release-contracts",
        "test-credential-lifecycle-browser",
        "security",
        "rust-supply-chain",
    }
    for name in conditional_jobs:
        assert jobs[name]["needs"] == ["changes", "release-preflight"]
        assert jobs[name]["if"]

    gate_needs = set(jobs["ci-gate"]["needs"])
    assert gate_needs == conditional_jobs | {"changes", "lint", "release-preflight", "test-windows-owner-source"}
    gate_script = jobs["ci-gate"]["steps"][0]["run"]
    assert (
        'require_selected test-rust-services "$RUST_SERVICES_RESULT" "$RUST_SELECTED"'
        in gate_script
    )
    assert '[[ "$result" == success ]]' in gate_script


def test_ci_gate_accepts_only_planned_pr_skips_and_all_successful_merge_groups() -> (
    None
):
    _, document = _workflow(CI_PATH)
    jobs = document["jobs"]
    gate = jobs["ci-gate"]
    result_env = {}
    for key, value in gate["env"].items():
        match = re.fullmatch(r"\$\{\{ needs\.([a-z0-9-]+)\.result \}\}", value)
        if match:
            result_env[match.group(1)] = key
    assert set(result_env) == set(gate["needs"])
    assert gate["env"]["CI_LANE_RESULTS"] == "${{ join(needs.*.result, ' ') }}"

    groups = {
        "website": {"test-website"},
        "ui": {
            "fast-feedback",
            "test-ui-crawler-artifacts",
            "test-ui-crawler-nginx",
            "test-ui",
            "test-credential-lifecycle-browser",
        },
        "python": {"test-services"},
        "rust": {
            "test-rust-services",
            "test-native-operator",
            "rust-lint-policy",
            "rust-supply-chain",
        },
        "openbao": {"test-openbao-didcomm-plugin"},
        "rust_runtime": {
            "test-rust-feature-probe",
            "test-rust-service-images",
        },
        "security": {"security"},
    }
    for flag, names in groups.items():
        for name in names:
            assert jobs[name]["if"] == f"needs.changes.outputs.{flag} == 'true'"
    assert set(gate["needs"]) == {
        "changes",
        "lint",
        "release-preflight",
        "public-protocol-contract",
        "test-release-contracts",
        "test-windows-owner-source",
    } | set().union(*groups.values())
    assert (
        "needs.changes.outputs.ui == 'true'" in jobs["public-protocol-contract"]["if"]
    )
    assert (
        "needs.changes.outputs.release == 'true'"
        in jobs["public-protocol-contract"]["if"]
    )
    assert (
        "needs.changes.outputs.verification == 'true'"
        in jobs["test-release-contracts"]["if"]
    )

    selections = {
        "WEBSITE_SELECTED": "website",
        "UI_SELECTED": "ui",
        "PYTHON_SELECTED": "python",
        "RUST_SELECTED": "rust",
        "RUST_RUNTIME_SELECTED": "rust_runtime",
        "OPENBAO_SELECTED": "openbao",
        "RELEASE_SELECTED": "release",
        "VERIFICATION_SELECTED": "verification",
        "SECURITY_SELECTED": "security",
    }
    for key, flag in selections.items():
        assert gate["env"][key] == f"${{{{ needs.changes.outputs.{flag} }}}}"
    assert gate["env"]["RUST_MATRIX"] == "${{ needs.changes.outputs.rust_matrix }}"
    assert gate["env"]["ROLLBACK_TEST_ONLY"] == (
        "${{ needs.changes.outputs.rollback_test_only }}"
    )
    assert gate["env"]["DIDCOMM_RELEASE_TEST_ONLY"] == (
        "${{ needs.changes.outputs.didcomm_release_test_only }}"
    )
    bash = "bash"
    if os.name == "nt":
        git = shutil.which("git")
        assert git is not None
        bash = str(Path(git).parent.parent / "bin" / "bash.exe")

    def exercise(
        flags=(),
        overrides=None,
        event="pull_request",
        result_count=None,
        selection_overrides=None,
        leaf_only=False,
        flow_only=False,
        selfhost_only=False,
        repository_private=False,
    ):
        selected = set(flags)
        if "ui" in selected:
            selected.add("website")
        if "rust" in selected and not (
            leaf_only or flow_only or selfhost_only
        ):
            selected.add("rust_runtime")
        active = {"changes", "lint", "release-preflight"}
        if not repository_private:
            active.add("test-windows-owner-source")
        for flag, names in groups.items():
            if flag in selected:
                active.update(names)
        if selected & {"ui", "python", "rust", "release"}:
            active.add("public-protocol-contract")
        if selected & {"release", "verification", "rust"}:
            active.add("test-release-contracts")
        results = {
            name: "success" if name in active else "skipped" for name in gate["needs"]
        }
        results.update(overrides or {})
        environment = os.environ.copy()
        environment.update(
            {
                key: "true" if flag in selected else "false"
                for key, flag in selections.items()
            }
        )
        environment.update(selection_overrides or {})
        environment.setdefault("WEBSITE_ONLY", "false")
        environment["REPOSITORY_PRIVATE"] = str(repository_private).lower()
        environment.setdefault("ROLLBACK_TEST_ONLY", "false")
        environment.setdefault("DIDCOMM_RELEASE_TEST_ONLY", "false")
        environment["RUST_MATRIX"] = (
            '["flow"]'
            if flow_only
            else '["selfhost"]'
            if selfhost_only
            else '["contracts"]'
            if leaf_only
            else '["contracts","flow","selfhost"]'
        )
        environment.update(selection_overrides or {})
        environment.update({key: results[name] for name, key in result_env.items()})
        values = [results[name] for name in gate["needs"]]
        environment["CI_LANE_RESULTS"] = " ".join(values[:result_count])
        assert len(values[:result_count]) == (result_count or len(gate["needs"]))
        script = gate["steps"][0]["run"].replace("${{ github.event_name }}", event)
        return subprocess.run(
            [bash, "-c", script],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    for flags in (
        (),
        ("ui",),
        ("rust",),
        ("rust", "openbao", "security"),
        ("python", "security"),
        ("release",),
        ("release", "verification"),
        tuple(selections.values()),
    ):
        result = exercise(flags)
        assert result.returncode == 0, (flags, result.stdout, result.stderr)
    assert exercise(("rust",), {"test-rust-services": "skipped"}).returncode != 0
    assert exercise(("rust",), leaf_only=True).returncode == 0
    unit_plan = {"RUST_MATRIX": '["renewal-unit"]'}
    assert exercise(
        ("rust",), leaf_only=True, selection_overrides=unit_plan
    ).returncode == 0
    assert exercise(
        ("rust",), leaf_only=True, selection_overrides=unit_plan,
        event="merge_group",
    ).returncode != 0
    assert exercise(
        ("rust",), leaf_only=True, selection_overrides=unit_plan,
        overrides={"test-rust-services": "skipped"},
    ).returncode != 0
    assert exercise(
        ("rust",), leaf_only=True, selection_overrides=unit_plan,
        overrides={"rust-supply-chain": "skipped"},
    ).returncode != 0
    assert exercise(("rust",), flow_only=True).returncode == 0
    assert exercise(("rust",), flow_only=True).returncode == 0
    assert exercise(("rust",), selfhost_only=True).returncode == 0
    assert exercise(("rust",), selfhost_only=True, event="merge_group").returncode != 0
    assert (
        exercise(("rust",), selfhost_only=True, overrides={"test-release-contracts": "skipped"})
        .returncode
        != 0
    )
    assert (
        exercise(("rust",), selfhost_only=True, overrides={"rust-supply-chain": "skipped"})
        .returncode
        != 0
    )
    assert exercise(("rust",), flow_only=True, event="merge_group").returncode != 0
    assert (
        exercise(("rust",), flow_only=True, overrides={"rust-supply-chain": "skipped"})
        .returncode
        != 0
    )
    assert (
        exercise(("rust",), flow_only=True, overrides={"test-release-contracts": "skipped"})
        .returncode
        != 0
    )
    assert exercise(("rust",), flow_only=True, event="merge_group").returncode != 0
    assert (
        exercise(
            ("rust",),
            flow_only=True,
            selection_overrides={"RUST_RUNTIME_SELECTED": "true"},
        ).returncode
        != 0
    )
    assert (
        exercise(
            ("rust",),
            flow_only=True,
            selection_overrides={"RUST_MATRIX": '["contracts","flow"]'},
        ).returncode
        != 0
    )
    assert (
        exercise(
            ("rust",), flow_only=True, overrides={"rust-lint-policy": "skipped"}
        ).returncode
        != 0
    )
    assert (
        exercise(
            ("rust",), flow_only=True, overrides={"rust-supply-chain": "skipped"}
        ).returncode
        != 0
    )
    assert (
        exercise(
            ("rust",), flow_only=True, overrides={"test-release-contracts": "skipped"}
        ).returncode
        != 0
    )
    assert (
        exercise(
            ("rust",),
            leaf_only=True,
            selection_overrides={"RUST_MATRIX": '["contracts","flow","selfhost"]'},
        ).returncode
        != 0
    )
    assert (
        exercise(
            ("rust",), leaf_only=True, overrides={"test-rust-service-images": "success"}
        ).returncode
        != 0
    )
    assert (
        exercise(
            ("rust",), selection_overrides={"RUST_MATRIX": '["contracts"]'}
        ).returncode
        != 0
    )
    assert (
        exercise(
            ("rust",), selection_overrides={"RUST_MATRIX": '["contracts","unknown"]'}
        ).returncode
        != 0
    )
    assert exercise((), {"test-rust-services": "success"}).returncode != 0
    assert exercise(("ui",), {"fast-feedback": "failure"}).returncode != 0
    assert exercise((), {"changes": "failure"}).returncode != 0
    assert exercise((), {"release-preflight": "failure"}).returncode != 0
    assert exercise((), {"release-preflight": "skipped"}).returncode != 0
    assert exercise((), selection_overrides={"RUST_SELECTED": ""}).returncode != 0
    assert exercise((), result_count=16).returncode != 0
    for event, flags in (("pull_request", ()), ("merge_group", tuple(selections.values()))):
        for bad_result in ("failure", "cancelled", "skipped", ""):
            assert exercise(flags, {"test-windows-owner-source": bad_result}, event=event).returncode != 0
        assert exercise(flags, event=event, repository_private=True).returncode == 0
        assert exercise(flags, {"test-windows-owner-source": "success"}, event=event,
                        repository_private=True).returncode != 0
    assert exercise(tuple(selections.values()), {"security": "skipped"}, event="merge_group",
                    repository_private=True).returncode != 0
    for visibility in ("", "TRUE", "public"):
        assert exercise(selection_overrides={"REPOSITORY_PRIVATE": visibility}).returncode != 0
    didcomm_mode = {"DIDCOMM_RELEASE_TEST_ONLY": "true"}
    assert exercise(("release",), selection_overrides=didcomm_mode).returncode == 0
    assert (
        exercise(
            ("release",),
            overrides={"test-release-contracts": "skipped"},
            selection_overrides=didcomm_mode,
        ).returncode
        != 0
    )
    assert exercise(("ui", "release"), selection_overrides=didcomm_mode).returncode != 0
    assert exercise(("release",), event="merge_group", selection_overrides=didcomm_mode).returncode != 0
    assert exercise(("release",), event="workflow_dispatch", selection_overrides=didcomm_mode).returncode != 0
    for invalid in ("", "TRUE", "invalid"):
        assert exercise(("release",), selection_overrides={"DIDCOMM_RELEASE_TEST_ONLY": invalid}).returncode != 0
    assert (
        exercise(("release", "openbao"), selection_overrides=didcomm_mode).returncode
        != 0
    )
    assert exercise(tuple(selections.values()), event="merge_group").returncode == 0
    assert (
        exercise(
            ("release", "security"),
            selection_overrides={"ROLLBACK_TEST_ONLY": "true"},
        ).returncode
        != 0
    )
    assert (
        exercise(
            ("release",), selection_overrides={"ROLLBACK_TEST_ONLY": "true"}
        ).returncode
        != 0
    )
    assert (
        exercise(
            tuple(selections.values()),
            event="merge_group",
            selection_overrides={"ROLLBACK_TEST_ONLY": "true"},
        ).returncode
        != 0
    )
    assert (
        exercise(
            ("release", "security"),
            selection_overrides={"ROLLBACK_TEST_ONLY": "missing"},
        ).returncode
        != 0
    )
    assert exercise(("rust",), event="merge_group", leaf_only=True).returncode != 0
    assert (
        exercise(
            tuple(selections.values()), {"security": "skipped"}, event="merge_group"
        ).returncode
        != 0
    )


def test_ci_gate_keeps_required_lanes_strict_when_optional_telemetry_fails() -> None:
    _, document = _workflow(CI_PATH)
    gate = document["jobs"]["ci-gate"]
    assert not gate.get("continue-on-error", False)
    assert [step["name"] for step in gate["steps"]] == [
        "Require every CI lane",
        "Checkout source for the closed plan guard",
        "Bind every result to the exact CI plan",
        "Summarize CI performance",
    ]
    required, checkout, plan_guard, telemetry = gate["steps"]
    assert plan_guard["run"] == "python3 scripts/ci/affected_components.py gate"
    assert "continue-on-error" not in plan_guard
    assert "if" not in plan_guard
    assert not required.get("continue-on-error", False)
    assert '[[ "$result" == success ]]' in required["run"]
    assert (
        'require_selected test-rust-services "$RUST_SERVICES_RESULT" "$RUST_SELECTED"'
        in required["run"]
    )
    assert (
        'require_selected security "$SECURITY_RESULT" "$SECURITY_SELECTED"'
        in required["run"]
    )
    assert telemetry["continue-on-error"] is True
    script = telemetry["with"]["script"]
    assert "[502, 503, 504]" in script
    assert "attempt <= 3" in script
    assert "attempt === 3" in script
    assert "retryTransient('getWorkflowRun'" in script
    assert "retryTransient('listJobsForWorkflowRun'" in script


def test_independent_rust_lanes_remain_required_without_transferring_builds() -> None:
    _, document = _workflow(CI_PATH)
    jobs = document["jobs"]
    service_names = {step.get("name") for step in jobs["test-rust-services"]["steps"]}
    probe = jobs["test-rust-feature-probe"]
    assert probe["needs"] == ["changes", "release-preflight"]
    assert probe["if"] == "needs.changes.outputs.rust_runtime == 'true'"
    assert jobs["test-rust-services"]["if"] == "needs.changes.outputs.rust == 'true'"
    assert "test-rust-feature-probe" in jobs["ci-gate"]["needs"]
    assert "test-rust-passport-image" not in jobs
    assert "Verify frozen Rust feature-regression probe" not in service_names
    assert "Build opt-in passport test-mode image" not in service_names
    assert "Verify opt-in passport test-mode image boundary" not in service_names
    assert {step.get("name") for step in probe["steps"]} >= {
        "Verify frozen Rust feature-regression probe"
    }
    assert "Build public selfhost image" in service_names
    assert not any(
        step.get("uses", "").startswith("actions/download-artifact@")
        for step in probe["steps"]
    )


def _assert_gone_or_zombie_process(pid: str, *, wait_seconds: float = 0) -> None:
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            observed = Path(f"/proc/{pid}/stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            # Linux can remove a task after procfs open succeeds but before read.
            return
        if observed.rsplit(") ", 1)[1].startswith("Z "):
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed-out worker {pid} survived its exit grace period")
        time.sleep(0.02)


@pytest.mark.parametrize("error", [FileNotFoundError, ProcessLookupError])
def test_native_operator_timeout_accepts_process_disappearance(monkeypatch, error) -> None:
    def read_stat(path):
        assert path == Path("/proc/123/stat")
        raise error("synthetic task disappeared")

    monkeypatch.setattr(Path, "read_text", read_stat)
    _assert_gone_or_zombie_process("123")


@pytest.mark.parametrize("state", ["R", "S", "D"])
def test_native_operator_timeout_rejects_surviving_process(monkeypatch, state) -> None:
    monkeypatch.setattr(Path, "read_text", lambda _: f"123 (cargo worker) {state} 1 2 3")
    with pytest.raises(AssertionError):
        _assert_gone_or_zombie_process("123")


def test_native_operator_timeout_accepts_unreaped_zombie(monkeypatch) -> None:
    monkeypatch.setattr(Path, "read_text", lambda _: "123 (cargo worker) Z 1 2 3")
    _assert_gone_or_zombie_process("123")


def test_native_operator_timeout_accepts_worker_settling_after_timeout(monkeypatch) -> None:
    states = iter(("R", "Z"))
    monkeypatch.setattr(Path, "read_text", lambda _: f"123 (cargo worker) {next(states)} 1 2 3")
    _assert_gone_or_zombie_process("123", wait_seconds=0.2)


def test_native_operator_timeout_rejects_survivor_after_grace(monkeypatch) -> None:
    monkeypatch.setattr(Path, "read_text", lambda _: "123 (cargo worker) R 1 2 3")
    with pytest.raises(AssertionError, match="survived its exit grace period"):
        _assert_gone_or_zombie_process("123", wait_seconds=0.04)


def test_native_operator_timeout_preserves_unavailable_procfs_failure(monkeypatch) -> None:
    def read_stat(_):
        raise PermissionError("synthetic procfs access denied")

    monkeypatch.setattr(Path, "read_text", read_stat)
    with pytest.raises(PermissionError):
        _assert_gone_or_zombie_process("123")


@pytest.mark.parametrize("arch,cpu,budget", [("amd64", "x86_64", 30), ("arm64", "aarch64", 25)])
@pytest.mark.parametrize("scenario,expected_status,expected_modes", [
    ("success", 0, ["fetch", "test", "build"]),
    ("transient", 0, ["fetch", "fetch", "test", "build"]),
    ("exhausted", 1, ["fetch", "fetch"]),
    ("timeout", 1, ["fetch", "fetch"]),
    ("test-failure", 37, ["fetch", "test"]),
    ("build-failure", 38, ["fetch", "test", "build"]),
])
def test_native_operator_acquires_locked_targets_before_single_offline_execution(
    tmp_path: Path, arch: str, cpu: str, budget: int,
    scenario: str, expected_status: int, expected_modes: list[str],
) -> None:
    bash, timeout = shutil.which("bash"), shutil.which("timeout")
    if sys.platform != "linux" or not bash or not timeout:
        pytest.skip("Linux workflow process deadlines require Bash and GNU timeout")
    _, document = _workflow(CI_PATH)
    job = document["jobs"]["test-native-operator"]
    row = next(item for item in job["strategy"]["matrix"]["include"] if item["arch"] == arch)
    assert row["timeout_minutes"] == budget
    assert row["target"] == f"{cpu}-unknown-linux-musl"
    assert job["timeout-minutes"] == "${{ matrix.timeout_minutes }}"
    steps = job["steps"]
    fetch = next(step for step in steps if step.get("name") == "Fetch locked native operator dependencies")
    exercise = next(step for step in steps if step.get("name") == "Exercise the static native operator against real HTTPS")
    position = steps.index(fetch)
    assert steps[position - 2]["uses"] == "dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8"
    assert steps[position - 2]["with"] == {"toolchain": "1.95.0", "targets": "${{ matrix.target }}"}
    assert steps[position - 1] == {
        "name": "Fetch locked private fork dependencies",
        "if": "vars.PRIVATE_FORKS_ENABLED == 'true'",
        "timeout-minutes": 5,
        "shell": "bash",
        "working-directory": "${{ github.workspace }}",
        "env": {"PRIVATE_FORKS_READ_TOKEN": "${{ secrets.PRIVATE_FORKS_READ_TOKEN }}"},
        "run": 'python3 ".github/scripts/private-forks.py" fetch --manifest-path "rust/Cargo.toml"',
    }
    assert steps[position + 1] is exercise
    assert steps[0]["with"]["persist-credentials"] is False
    assert fetch["timeout-minutes"] == 5 and fetch["shell"] == "bash"
    assert fetch["env"] == {"GIT_TERMINAL_PROMPT": "0"}
    for step in (fetch, exercise):
        assert not step.get("continue-on-error") and not step.get("if")
        assert "PRIVATE_FORKS_READ_TOKEN" not in str(step)

    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    # Record actual workflow commands; only the acquisition may fail and retry.
    fake_source = f"#!{sys.executable}\n" + '''import json, os, signal, sys, time
from pathlib import Path
name, args = Path(sys.argv[0]).name, sys.argv[1:]
log = Path(os.environ["TEST_COMMAND_LOG"])
with log.open("a") as stream:
    stream.write(json.dumps({"name": name, "args": args, "prompt": os.environ.get("GIT_TERMINAL_PROMPT")}) + "\\n")
if name == "rustc":
    print("rustc 1.95.0\\nhost: " + os.environ["TEST_HOST_TARGET"])
elif name == "cargo":
    scenario = os.environ["TEST_SCENARIO"]
    if "fetch" in args:
        count = sum(row["name"] == "cargo" and "fetch" in row["args"] for row in map(json.loads, log.read_text().splitlines()))
        if scenario == "timeout":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            with Path(os.environ["TEST_FETCH_PIDS"]).open("a") as stream:
                stream.write(str(os.getpid()) + "\\n")
            while True:
                time.sleep(10)
        if scenario == "exhausted" or (scenario == "transient" and count == 1):
            print("synthetic public Git transfer failure", file=sys.stderr)
            sys.exit(128)
    elif args[0] == "test" and scenario == "test-failure":
        sys.exit(37)
    elif args[0] == "build" and scenario == "build-failure":
        sys.exit(38)
'''
    for name in ("cargo", "rustc", "sleep"):
        path = fake_bin / name
        path.write_text(fake_source, encoding="utf-8")
        path.chmod(0o755)
    shim = fake_bin / "timeout"
    shim.write_text('''#!/usr/bin/env bash
set -euo pipefail
printf '%s %s\\n' "$1" "$2" >> "$TEST_TIMEOUT_CALLS"
[[ "$1" == --kill-after=5s && "$2" == 120s ]]
shift 2
if [[ "$TEST_SCENARIO" == timeout ]]; then
  exec "$TEST_REAL_TIMEOUT" --kill-after=0.2s 0.2s "$@"
fi
exec "$TEST_REAL_TIMEOUT" --kill-after=1s 5s "$@"
''', encoding="utf-8")
    shim.chmod(0o755)
    host_target, target = f"{cpu}-unknown-linux-gnu", row["target"]
    log, calls, pids = (tmp_path / name for name in ("commands.jsonl", "timeouts", "pids"))
    environment = dict(os.environ, PATH=f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                       TARGET=target, TEST_HOST_TARGET=host_target, TEST_SCENARIO=scenario,
                       TEST_COMMAND_LOG=str(log), TEST_TIMEOUT_CALLS=str(calls),
                       TEST_FETCH_PIDS=str(pids), TEST_REAL_TIMEOUT=timeout)
    environment.pop("BASH_ENV", None)
    environment.pop("ENV", None)
    result = subprocess.run([bash, "--noprofile", "--norc", "-s"], input=fetch["run"],
                            cwd=tmp_path, env={**environment, **fetch["env"]},
                            capture_output=True, text=True, timeout=15)
    acquisition_status, acquisition_stdout, acquisition_stderr = result.returncode, result.stdout, result.stderr
    if acquisition_status == 0:
        # Execute the exact existing test/build commands, without provisioning.
        commands = exercise["run"].split("cargo test ", 1)[1].split('export MARTY_DEPLOY_BIN=', 1)[0]
        result = subprocess.run([bash, "--noprofile", "--norc", "-s"],
                                input="set -euo pipefail\ncargo test " + commands,
                                cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=15)
    assert result.returncode == expected_status, result.stderr
    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    cargo = [event for event in events if event["name"] == "cargo"]
    modes = ["fetch" if "fetch" in event["args"] else event["args"][0] for event in cargo]
    assert modes == expected_modes
    expected_arguments = {
        "fetch": ["--config", "net.git-fetch-with-cli=true", "fetch", "--locked",
                  "--manifest-path", "rust/Cargo.toml", "--target", host_target, "--target", target],
        "test": ["test", "--locked", "--offline", "--manifest-path", "rust/Cargo.toml", "-p", "marty-managed-key-reference"],
        "build": ["build", "--locked", "--offline", "--target", target, "--manifest-path",
                  "rust/Cargo.toml", "-p", "marty-deployment-catalog", "--bin", "marty-deploy"],
    }
    for event, mode in zip(cargo, modes):
        assert event["args"] == expected_arguments[mode]
        if mode == "fetch":
            assert event["prompt"] == "0"
    attempts = modes.count("fetch")
    assert calls.read_text(encoding="utf-8").splitlines() == ["--kill-after=5s 120s"] * attempts
    assert [event["args"] for event in events if event["name"] == "sleep"] == [["2"]] * (attempts - 1)
    if attempts == 2:
        status = 137 if scenario == "timeout" else 128
        assert f"attempt 1 failed (exit {status})." in acquisition_stderr
    if scenario in {"transient", "exhausted"}:
        assert "synthetic public Git transfer failure" in acquisition_stderr
    annotations = [line for line in acquisition_stdout.splitlines() if line.startswith("::error::")]
    assert annotations == (["::error::Locked native operator dependency acquisition failed after two bounded attempts."]
                           if acquisition_status else [])
    if scenario == "timeout":
        assert len(pids.read_text(encoding="utf-8").splitlines()) == 2
        for pid in pids.read_text(encoding="utf-8").splitlines():
            _assert_gone_or_zombie_process(pid, wait_seconds=1)


def test_rust_matrix_keeps_platform_owners_local_and_contracts_parallel() -> None:
    _, document = _workflow(CI_PATH)
    job = document["jobs"]["test-rust-services"]
    assert job["strategy"]["fail-fast"] is False
    matrix = job["strategy"]["matrix"]["lane"]
    assert "github.event_name == 'pull_request'" in matrix
    assert matrix.count("ci-renewal-unit-diagnostic") == 1
    assert "ci-selfhost-diagnostic" in matrix
    assert "|| needs.changes.outputs.rust_matrix) }}" in matrix
    for literal in re.findall(r"'(\[[^']+\])'", matrix):
        assert set(json.loads(literal)) in ({"contracts", "flow", "selfhost"},
                                          {"contracts", "flow", "selfhost", "renewal-unit"})
    steps = {step.get("name"): step for step in job["steps"] if step.get("name")}
    names = [step.get("name") for step in job["steps"]]
    contracts = {
        "Prepare database contract executables",
        "Create isolated Rust contract databases",
        "Run safe Rust contract groups concurrently",
        "Exercise live Signing Keys public contracts on disposable Redis",
        "Exercise scoped grant and managed passport chain over disposable HTTPS OpenBao",
        "Run Flow database contract after workspace suite",
        "Exercise managed Policy evidence through Flow PostgreSQL commit",
        "Test beta passport reconciliation and native batch on PostgreSQL",
        "Test native passport Gateway signed webhook on PostgreSQL",
        "Test native outbound HTTP timeout TLS parity",
    }
    for name in (
        "Build public selfhost image",
        "Prepare public selfhost image loader acceptance",
        "Verify local passport signing is forbidden",
    ):
        assert steps[name]["if"] == "matrix.lane == 'selfhost'"
        assert not steps[name].get("continue-on-error", False)
    assert steps["Expose public image compiler cache credentials"]["if"] == (
        "vars.PRIVATE_FORKS_ENABLED != 'true' && (matrix.lane == 'selfhost')"
    )
    assert not steps["Expose public image compiler cache credentials"].get("continue-on-error", False)
    for name in contracts:
        assert steps[name]["if"] == "matrix.lane == 'contracts'"
        assert not steps[name].get("continue-on-error", False)
    live_signing = steps["Exercise live Signing Keys public contracts on disposable Redis"]["run"]
    assert "csca_lifecycle_storage_contract:2" in live_signing
    assert "managed_key_create_live_contract" not in live_signing
    assert "--rust-adapter" in steps[
        "Qualify scoped provider callback verification against disposable OpenBao"
    ]["run"]
    assert "document_storage_contract:1" in live_signing
    assert "didcomm_publication_routes:2" in live_signing
    assert "service_rotation_live_contract" not in live_signing
    assert "vdsnc_registration_live_contract" not in live_signing
    live_openbao = steps[
        "Exercise scoped grant and managed passport chain over disposable HTTPS OpenBao"
    ]["run"]
    assert live_openbao == "python3 scripts/probe_signing_keys_openbao_policy.py --grant-verifier"
    assert steps["Prepare pinned standalone Compose renderer for Rust contracts"][
        "if"
    ] == "matrix.lane == 'contracts' || matrix.lane == 'flow' || matrix.lane == 'selfhost'"
    renderer = steps["Prepare pinned standalone Compose renderer for Rust contracts"]
    assert "bash scripts/ci/install-compose-renderer.sh" in renderer["run"]
    assert "MARTY_BASE_COMPOSE_BINARY=%s" in renderer["run"]
    assert "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE=%s" in renderer["run"]
    # Each runner owns local compilation and execution.
    assert (
        names.index("Build public selfhost image")
        < names.index("Retire completed selfhost builder cache")
        < names.index("Compile reusable Rust test executables")
    )
    assert (
        names.index("Compile reusable Rust test executables")
        < names.index("Prepare pinned standalone Compose renderer for Rust contracts")
        < names.index("Run safe Rust contract groups concurrently")
    )
    assert "if" not in steps["Compile reusable Rust test executables"]
    assert steps["Run isolated database contract suites concurrently"]["if"] == (
        "matrix.lane != 'renewal-unit'"
    )
    for name in (
        "Prefer cached Docker Hub images without restarting the runner daemon",
        "Select the exact BuildKit image with registry fallback",
    ):
        assert steps[name]["if"] == "matrix.lane != 'renewal-unit'"
    assert next(
        step for step in job["steps"] if step.get("uses", "").startswith("docker/setup-buildx-action@")
    )["if"] == "matrix.lane != 'renewal-unit'"
    observer = steps["Verify feature-regression observer isolation"]
    assert observer["if"] == "matrix.lane == 'contracts' || matrix.lane == 'renewal-unit'"
    assert "--features feature-regression-observer" in observer["run"]
    assert not observer.get("continue-on-error", False)
    focused = steps["Execute ordinary Issuance library obligations"]
    assert focused["if"] == "matrix.lane == 'renewal-unit'"
    assert "--name issuance_library_unit --owner renewal-unit" in focused["run"]
    assert '"${executables[0]}" --test-threads=4' in focused["run"]
    compile_step = steps["Compile reusable Rust test executables"]["run"]
    assert "cargo test --locked -p marty-issuance-service --lib --no-run" in compile_step
    assert "--renewal-unit-only \"$artifacts\" target" in compile_step
    assert "${{ matrix.lane }}" in steps["Upload Rust build evidence"]["with"]["name"]
    runner = (ROOT / "scripts/ci/run-flow-acceptance-contracts.sh").read_text(encoding="utf-8")
    assert "pull-pinned-dockerhub-image.sh" in runner
    assert "redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2" in runner
    assert 'docker tag "$redis_image" redis:7-alpine' in runner
    assert "docker pull redis:7-alpine" not in runner


@pytest.mark.parametrize(
    "changed_path,rust_selected,python_selected,security_selected,all_selected",
    [
        (
            "rust/services/issuance/src/new_type_contract.md",
            False,
            False,
            False,
            False,
        ),
        ("rust/services/issuance/src/outbound_http.rs", True, False, False, False),
        (
            "docs/architecture/external-learner-association.md",
            False,
            False,
            False,
            False,
        ),
        ("README.md", False, False, False, False),
        # The bundle manifest packages this otherwise documentation-shaped file.
        ("SELFHOST_BUNDLE.md", True, False, False, False),
        ("rust/services/issuance/README.md", False, False, False, False),
        ("docs/line\nbreak.md", False, False, False, False),
        ("rust/services/issuance/src/line\nbreak.rs", True, False, False, False),
        # Auth's Rust executable smoke test embeds this shell script with include_str!.
        ("services/entrypoint.sh", True, True, True, False),
        ("scripts/compose_config_model.py", True, True, True, True),
        ("unclassified-synthetic-input", True, True, True, True),
    ],
)
def test_actual_classifier_selects_gates_for_compiler_and_runtime_inputs(
    changed_path: str,
    rust_selected: bool,
    python_selected: bool,
    security_selected: bool,
    all_selected: bool,
    tmp_path: Path,
) -> None:
    actual = _classify_changed_path(changed_path, tmp_path)
    expected = {
        key: str(all_selected).lower()
        for key in (
            "all",
            "ui",
            "python",
            "rust",
            "openbao",
            "release",
            "verification",
            "security",
        )
    }
    expected["rust"] = str(rust_selected).lower()
    expected["python"] = str(python_selected).lower()
    expected["security"] = str(security_selected).lower()
    assert actual == expected


def test_evidence_test_sources_keep_their_release_owner_without_runtime_lanes(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    assert any(
        step.get("run") == RELEASE_TEST_COMMAND
        for step in workflow["jobs"]["test-release-contracts"]["steps"]
    )
    paths = (
        "tests/test_python_value_fast_obligations.py",
    )
    selected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "openbao": "false",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    ci_source = CI_PATH.read_text(encoding="utf-8") + (ROOT / "scripts/ci/affected_components.sh").read_text()
    for path in paths:
        assert (ROOT / path).is_file(), f"stale release-only selector: {path}"
        assert ci_source.count(path) == 1, f"other direct CI consumer: {path}"
        for other_workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
            if other_workflow != CI_PATH:
                assert path not in other_workflow.read_text(encoding="utf-8")
        assert _classify_changed_path(path, tmp_path) == selected

    # A test-only edit does not demote the manifest, corpus, or executable
    # inputs that the tests inspect; mixed/unknown edits also fail closed.
    for path in (
        "contracts/python-value-fast-obligations.json",
    ):
        actual = _classify_changed_path(path, tmp_path)
        assert actual["rust"] == actual["release"] == "true"
    assert (
        _classify_changed_path("scripts/http_multibyte_codec_oracle.py", tmp_path)[
            "all"
        ]
        == "true"
    )
    assert (
        _classify_changed_path("tests/test_ci_database_groups_helpers.py", tmp_path)["all"]
        == "true"
    )
    assert (
        _classify_changed_paths(
            [paths[0], "rust/services/issuance/src/lib.rs"], tmp_path, combined=True
        )[0]["rust"]
        == "true"
    )
    assert all(
        value == "true"
        for value in _classify_changed_paths([paths[0]], tmp_path, event="merge_group")[
            0
        ].values()
    )


def test_runner_registration_inputs_keep_release_coverage_without_full_pr_matrix(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    release = workflow["jobs"]["test-release-contracts"]
    assert any(
        step.get("run") == RELEASE_TEST_COMMAND
        for step in release["steps"]
    ), "The release lane must still execute the runner policy tests"

    # A newly introduced executable/script consumer must be reviewed before
    # these exact inputs can retain their narrower PR selection.
    consumers = {
        "runner-host-capacity-policy.ps1": {"tests/test_runner_routing_labels.py"},
        "runner-routing-label-policy.ps1": {"tests/test_runner_routing_labels.py"},
    }
    for name, expected in consumers.items():
        references = subprocess.run(
            ["git", "grep", "-l", "-F", "--", name],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        assert {
            path
            for path in references.stdout.splitlines()
            if not path.endswith(".md")
            and path
            not in {".github/workflows/ci.yml", "scripts/ci/affected_components.sh", "tests/test_ci_workflow_performance.py"}
        } == expected, f"Review new consumer of {name} before narrowing its gate"

    selected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "openbao": "false",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    for path in (
        *(f"scripts/{name}" for name in consumers),
        "tests/test_runner_routing_labels.py",
    ):
        assert _classify_changed_path(path, tmp_path) == selected
    assert (
        _classify_changed_path(
            "scripts/unknown-runner-helper.ps1", tmp_path
        )["all"]
        == "true"
    )
    assert (
        _classify_changed_path(
            "tests/test_unreviewed_runner_topology.py", tmp_path
        )["all"]
        == "true"
    )


def test_release_contract_test_sources_keep_their_release_owner(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    release = workflow["jobs"]["test-release-contracts"]
    assert any(
        step.get("run") == RELEASE_TEST_COMMAND
        for step in release["steps"]
    ), "The release lane must execute every narrowed test module"

    selected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "openbao": "false",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    for path in (
        "tests/test_stack_tag_gate.py",
        "tests/test_release_transaction.py",
        "tests/test_stack_release_contract.py",
        "tests/test_check_release_absent.py",
        "tests/test_github_release_environment_preflight.py",
        "tests/test_release_environment_workflow_contract.py",
        "tests/test_create_local_release_manifest.py",
        "tests/test_build_stack_manifest.py",
        "tests/test_prepare_official_beta_release.py",
        "tests/test_stack_pre_promotion.py",
        "tests/test_local_beta_release_runner.py",
        "tests/test_selfhost_packager_reference.py",
    ):
        assert (ROOT / path).is_file(), f"stale release-only selector: {path}"
        assert _classify_changed_path(path, tmp_path) == selected
    assert (
        _classify_changed_path(
            "tests/test_stack_release_contract_helpers.py", tmp_path
        )["all"]
        == "true"
    )
    assert (
        _classify_changed_path(
            "tests/test_selfhost_packager_reference_helpers.py", tmp_path
        )["all"]
        == "true"
    )

    combined = _classify_changed_paths(
        ["tests/test_stack_tag_gate.py", "services/entrypoint.sh"],
        tmp_path,
        combined=True,
    )[0]
    assert combined["release"] == combined["rust"] == combined["python"] == "true"
    assert combined["security"] == "true"

    # The separate merge-group contract below still requires every CI lane.


def test_release_owned_policy_test_sources_have_no_second_execution_owner(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    assert any(
        step.get("run") == RELEASE_TEST_COMMAND
        for step in workflow["jobs"]["test-release-contracts"]["steps"]
    )
    assert any(
        step.get("run")
        == "python -m pytest --collect-only -q tests/test_ci_workflow_performance.py"
        for step in workflow["jobs"]["test-release-contracts"]["steps"]
    )
    selected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "openbao": "false",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    candidates = (
        "tests/test_sanitize_sccache_stats.py",
        "tests/test_oss_boundary.py",
        "tests/test_public_protocol_documentation.py",
        "tests/test_gateway_public_protocol_contract.py",
        "tests/test_public_vector_execution.py",
        "tests/test_ci_database_groups.py",
        "tests/test_rust_ownership.py",
        "tests/test_ci_workflow_performance.py",
        "tests/test_kubernetes_resolved_runtime.py",
        "tests/test_base_native_runtime_fixture.py",
        "tests/test_envoy_native_configuration.py",
        "tests/test_flow_public_startup.py",
        "tests/test_selfhost_runtime_model.py",
        "tests/test_passport_supported_rust_model.py",
        "tests/test_passport_supported_compose_ownership.py",
    )
    ci_source = CI_PATH.read_text(encoding="utf-8") + (ROOT / "scripts/ci/affected_components.sh").read_text()
    for path in candidates:
        assert (ROOT / path).is_file(), f"stale release-only selector: {path}"
        # The policy owner has one classifier reference, one collection
        # command, and two mutually exclusive test-source-only PR invocations.
        expected_refs = 4 if path == "tests/test_ci_workflow_performance.py" else 1
        assert ci_source.count(path) == expected_refs, (
            f"other direct CI consumer: {path}"
        )
        for other_workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
            if other_workflow == CI_PATH:
                continue
            assert path not in other_workflow.read_text(encoding="utf-8")
        assert _classify_changed_path(path, tmp_path) == selected

    assert (
        _classify_changed_path(
            "tests/test_sanitize_sccache_stats_helpers.py", tmp_path
        )["all"]
        == "true"
    )
    assert (
        _classify_changed_path(
            "tests/test_public_vector_execution_helpers.py", tmp_path
        )["all"]
        == "true"
    )
    assert (
        _classify_changed_path("tests/test_ci_database_groups_helpers.py", tmp_path)["all"]
        == "true"
    )
    assert (
        _classify_changed_path(
            "tests/test_kubernetes_resolved_runtime_helpers.py", tmp_path
        )["all"]
        == "true"
    )

    assert (
        _classify_changed_path(
            "scripts/ci/run-flow-acceptance-contracts.sh", tmp_path
        )["all"]
        == "true"
    )
    assert (
        _classify_changed_path(
            "scripts/render_base_native_runtime_fixture.py", tmp_path
        )["all"]
        == "true"
    )
    assert (
        _classify_changed_path(
            "rust/crates/flow-acceptance/tests/flow_published_schema_contract.rs",
            tmp_path,
        )["rust"]
        == "true"
    )
    assert (
        _classify_changed_path("scripts/ci/check_public_vector_execution.py", tmp_path)[
            "all"
        ]
        == "true"
    )
    assert (
        _classify_changed_paths(
            [
                "tests/test_public_vector_execution.py",
                "rust/services/gateway/src/lib.rs",
            ],
            tmp_path,
            combined=True,
        )[0]["rust"]
        == "true"
    )
    assert (
        _classify_changed_paths(
            ["tests/test_ci_database_groups.py", "rust/services/issuance/src/outbound_http.rs"],
            tmp_path,
            combined=True,
        )[0]["rust"]
        == "true"
    )
    assert (
        _classify_changed_paths(
            [
                "tests/test_base_native_runtime_fixture.py",
                "scripts/render_base_native_runtime_fixture.py",
            ],
            tmp_path,
            combined=True,
        )[0]["all"]
        == "true"
    )
    assert all(
        value == "true"
        for value in _classify_changed_paths(
            ["tests/test_ci_database_groups.py"],
            tmp_path,
            event="merge_group",
        )[0].values()
    )
    assert (
        _classify_changed_paths(
            ["tests/test_oss_boundary.py", "services/entrypoint.sh"],
            tmp_path,
            combined=True,
        )[0]["all"]
        == "false"
    )
    assert (
        _classify_changed_paths(
            ["tests/test_oss_boundary.py", "unknown-new-input.txt"],
            tmp_path,
            combined=True,
        )[0]["all"]
        == "true"
    )
    assert (
        _classify_changed_paths(
            [
                "tests/test_ci_workflow_performance.py",
                "rust/services/issuance/src/lib.rs",
            ],
            tmp_path,
            combined=True,
        )[0]["rust"]
        == "true"
    )
    assert (
        _classify_changed_path("tests/test_ci_workflow_performance.py", tmp_path)["all"]
        == "false"
    )
    assert all(
        value == "true"
        for value in _classify_changed_paths(
            ["tests/test_ci_workflow_performance.py"],
            tmp_path,
            event="merge_group",
        )[0].values()
    )


def test_model_and_compose_policy_sources_select_only_their_release_owner(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    assert any(
        step.get("run") == RELEASE_TEST_COMMAND
        for step in workflow["jobs"]["test-release-contracts"]["steps"]
    )
    candidates = (
        "tests/test_issuance_rust_candidate.py",
        "tests/test_kubernetes_native_issuance.py",
        "tests/test_shared_rust_service_image.py",
        "tests/test_passport_supported_provisioning_producer.py",
        "tests/test_issuance_passport_native_compose.py",
        "tests/test_conformance_native.py",
        "tests/test_passport_supported_disposable_compose.py",
        "tests/test_gateway_rust_cutover.py",
        "tests/test_issuance_consumer_bindings.py",
        "tests/test_kubernetes_app_service_coverage.py",
        "tests/test_check_kubernetes_services_release.py",
        "tests/test_kubernetes_token_hmac_secret.py",
        "tests/test_passport_supported_k8s_deployment.py",
        "tests/test_passport_supported_consumer_routing.py",
    )
    ci_source = CI_PATH.read_text(encoding="utf-8") + (ROOT / "scripts/ci/affected_components.sh").read_text()
    for path in candidates:
        assert (ROOT / path).is_file(), f"stale release-only selector: {path}"
        expected_references = 3 if path in candidates[-6:] else 1
        assert ci_source.count(path) == expected_references, f"other direct CI consumer: {path}"
        for other_workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
            if other_workflow != CI_PATH:
                assert path not in other_workflow.read_text(encoding="utf-8")
    expected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "openbao": "false",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    assert _classify_changed_paths(candidates, tmp_path) == [expected] * len(candidates)
    assert (
        _classify_changed_path("tests/test_gateway_rust_cutover_helpers.py", tmp_path)[
            "all"
        ]
        == "true"
    )
    assert (
        _classify_changed_path("tests/test_kubernetes_app_service_coverage_helpers.py", tmp_path)[
            "all"
        ]
        == "true"
    )
    mixed = _classify_changed_paths(
        [candidates[0], "services/Dockerfile"], tmp_path, combined=True
    )[0]
    assert all(
        mixed[name] == "true" for name in ("release", "rust", "python", "security")
    )
    protected = _classify_changed_paths([candidates[0]], tmp_path, event="merge_group")[
        0
    ]
    assert protected["all"] == protected["rust"] == "true"


def test_kubernetes_policy_test_source_pr_keeps_full_protected_checks(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    assert workflow["jobs"]["changes"]["outputs"]["k8s_policy_test_only"] == (
        "${{ steps.classify.outputs.k8s_policy_test_only }}"
    )
    cohort = (
        "tests/test_issuance_consumer_bindings.py",
        "tests/test_kubernetes_app_service_coverage.py",
        "tests/test_check_kubernetes_services_release.py",
        "tests/test_kubernetes_token_hmac_secret.py",
        "tests/test_passport_supported_k8s_deployment.py",
        "tests/test_passport_supported_consumer_routing.py",
    )

    def classify(paths, **kwargs):
        return _classify_changed_paths(
            paths,
            tmp_path,
            combined=True,
            include_rust_plan=True,
            include_rollback_plan=True,
            include_k8s_plan=True,
            **kwargs,
        )[0]

    expected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "rust_runtime": "false",
        "rust_matrix": '["contracts","flow","selfhost"]',
        "openbao": "false",
        "rollback_test_only": "false",
        "k8s_policy_test_only": "true",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    for path in cohort:
        assert classify([path]) == expected
    assert classify(list(cohort)) == expected
    assert classify([])["k8s_policy_test_only"] == "false"
    assert classify([cohort[0], cohort[0]])["k8s_policy_test_only"] == "false"
    for other in (
        "docs/architecture-feedback-improvement-plan.md",
        "tests/test_passport_supported_consumer_routing_helpers.py",
        "k8s/oracle/07-microservices.yaml",
        "scripts/deploy-kubernetes.sh",
        ".github/workflows/ci.yml",
    ):
        selected = classify([cohort[0], other])
        assert selected["k8s_policy_test_only"] == "false", other
        assert selected["release"] == "true", other
    protected = classify([cohort[0]], event="merge_group")
    assert protected["all"] == protected["release"] == "true"
    assert protected["k8s_policy_test_only"] == "false"
    assert classify([cohort[0]], event="push")["k8s_policy_test_only"] == "false"
    with pytest.raises(AssertionError):
        classify([cohort[0]], missing_base=True)

    absent = tmp_path / "absent-k8s-policy-source"
    absent.mkdir()
    assert classify([cohort[0]], working_directory=absent)[
        "k8s_policy_test_only"
    ] == "false"
    linked = tmp_path / "linked-k8s-policy-source"
    (linked / "tests").mkdir(parents=True)
    try:
        (linked / cohort[0]).symlink_to(ROOT / cohort[0])
    except (OSError, NotImplementedError):
        pass  # Windows without symlink privilege; protected Linux checks it.
    else:
        assert classify([cohort[0]], working_directory=linked)[
            "k8s_policy_test_only"
        ] == "false"

    steps = {
        step.get("name"): step
        for step in workflow["jobs"]["test-release-contracts"]["steps"]
    }
    bounded = steps["Run Kubernetes policy test-source PR checks"]
    assert bounded["if"] == "needs.changes.outputs.k8s_policy_test_only == 'true'"
    assert bounded["run"].split() == [
        "python", "-m", "pytest", *cohort,
        "tests/test_ci_workflow_performance.py", "-v", "--tb=short",
    ]
    full_only = (
        ""
        "needs.changes.outputs.k8s_policy_test_only != 'true' && "
        "needs.changes.outputs.didcomm_release_test_only != 'true'"
    )
    for name in (
        "Run repository release checks",
        "Configure the pinned containerd image store",
        "Configure the pinned OCI exporter",
        "Require the exact supported OCI backend",
        "Prove the same OCI archive through the future consumer path",
    ):
        assert steps[name]["if"] == full_only
        assert not steps[name].get("continue-on-error", False)
    assert steps["Run repository release checks"]["run"] == (
        RELEASE_TEST_COMMAND
    )


def test_didcomm_policy_test_sources_have_exact_release_owner(
    tmp_path: Path,
) -> None:
    cases = {
        "tests/test_didcomm_native_consumer_ownership.py": 38,
    }
    _, workflow = _workflow(CI_PATH)
    ci_source = CI_PATH.read_text(encoding="utf-8") + (ROOT / "scripts/ci/affected_components.sh").read_text()

    def classify(paths: list[str], **kwargs: object) -> dict[str, str]:
        return _classify_changed_paths(paths, tmp_path, combined=True, **kwargs)[0]

    selected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "openbao": "false",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    assert classify([])["release"] == "false"
    for source, count in cases.items():
        assert ci_source.count(source) == 3  # Proof, classifier arm and owned test command.
        assert (ROOT / source).is_file() and not (ROOT / source).is_symlink()
        for other_workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
            if other_workflow != CI_PATH:
                assert source not in other_workflow.read_text(encoding="utf-8")
        assert classify([source]) == selected
        for paths in (
            [source, source],
            [source, "docs/architecture-feedback-improvement-plan.md"],
            [source, "contracts/didcomm-native-consumer-ownership.json"],
            [source, "docker-compose.base.yml"],
            [source, "tests/test_didcomm_native_consumer_ownership_helper.py"],
            ["tests/renamed_didcomm_owner.py", source],
            *([source, other] for other in cases if other != source),
        ):
            assert classify(paths)["all"] == "true", paths
        assert classify([source], event="merge_group")["all"] == "true"
        assert classify([source], event="push")["all"] == "true"
        with pytest.raises(AssertionError):
            classify([source], missing_base=True)

        absent = tmp_path / f"absent-{Path(source).stem}"
        absent.mkdir()
        assert classify([source], working_directory=absent)["all"] == "true"
        linked = tmp_path / f"linked-{Path(source).stem}"
        (linked / "tests").mkdir(parents=True)
        try:
            (linked / source).symlink_to(ROOT / source)
        except (OSError, NotImplementedError):
            pass  # Windows without symlink privilege; protected Linux checks it.
        else:
            assert classify([source], working_directory=linked)["all"] == "true"

        collected = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", source],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        assert f"{count} tests collected" in collected.stdout

    release = workflow["jobs"]["test-release-contracts"]
    assert "needs.changes.outputs.release == 'true'" in release["if"]
    assert any(
        step.get("run") == RELEASE_TEST_COMMAND for step in release["steps"]
    )
    assert "tests" in RELEASE_TEST_COMMAND.split()
    assert sum(cases.values()) == 38


def test_exact_didcomm_release_pr_path_preserves_full_release_fallback(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    assert workflow["jobs"]["changes"]["outputs"]["didcomm_release_test_only"] == (
        "${{ steps.classify.outputs.didcomm_release_test_only }}"
    )
    sources = (
        "tests/test_didcomm_native_consumer_ownership.py",
    )

    def classify(paths: list[str], **kwargs: object) -> dict[str, str]:
        return _classify_changed_paths(
            paths, tmp_path, combined=True, include_didcomm_plan=True, **kwargs
        )[0]

    for source in sources:
        selected = classify([source])
        assert selected["didcomm_release_test_only"] == "true"
        assert selected["release"] == "true"
        assert all(selected[name] == "false" for name in (
            "all", "ui", "python", "rust", "openbao", "verification", "security"
        ))
        for other in (
            source,
            *(path for path in sources if path != source),
            "docs/architecture-feedback-improvement-plan.md",
            "contracts/didcomm-native-consumer-ownership.json",
            "docker-compose.base.yml",
            "tests/unknown_didcomm_test.py",
            "tests/test_didcomm_native_credentials_release.py",
            "tests/test_issuance_retention_credentials_release.py",
            "renamed/old_didcomm_test.py",
        ):
            mixed = classify([source, other])
            assert mixed["didcomm_release_test_only"] == "false", other
            assert mixed["all"] == "true", other
        for event in ("merge_group", "push"):
            protected = classify([source], event=event)
            assert protected["didcomm_release_test_only"] == "false"
            assert protected["all"] == "true"
        for event in ("workflow_dispatch", "schedule"):
            official = classify([source], event=event, missing_base=True)
            assert official["didcomm_release_test_only"] == "false"
            assert official["all"] == "true"
        with pytest.raises(AssertionError):
            classify([source], missing_base=True)
    for retired in (
        "tests/test_didcomm_native_credentials_release.py",
        "tests/test_issuance_retention_credentials_release.py",
    ):
        fallback = classify([retired])
        assert fallback["didcomm_release_test_only"] == "false"
        assert fallback["all"] == "true"
    assert classify([])["didcomm_release_test_only"] == "false"

    release = workflow["jobs"]["test-release-contracts"]
    assert release["name"] == "Release Contract Tests"
    steps = {step.get("name"): step for step in release["steps"]}
    focused_flag = "needs.changes.outputs.didcomm_release_test_only"
    focused = steps["Run exact DIDComm test-source PR checks"]
    assert focused["if"] == f"{focused_flag} == 'true'"
    assert focused["run"].split() == [
        "python", "-m", "pytest", *sources,
        "tests/test_ci_workflow_performance.py::test_didcomm_policy_test_sources_have_exact_release_owner",
        "-v", "--tb=short",
    ]
    # Missing or malformed output must run the existing full path, not the
    # focused one. The other bounded PR modes retain their own exclusions.
    full_only = (
        ""
        "needs.changes.outputs.k8s_policy_test_only != 'true' && "
        f"{focused_flag} != 'true'"
    )
    for name in (
        "Run repository release checks",
        "Configure the pinned containerd image store",
        "Configure the pinned OCI exporter",
        "Require the exact supported OCI backend",
        "Prove the same OCI archive through the future consumer path",
    ):
        assert steps[name]["if"] == full_only
    assert steps["Run repository release checks"]["run"] == RELEASE_TEST_COMMAND
    for name in (
        "Install released test dependencies",
        "Verify released mdoc binding evidence contract",
        "Enforce OSS commerce boundary",
        "Require workflow policy test collection",
    ):
        assert "if" not in steps[name]
    assert "if" not in release["steps"][0]  # Main checkout remains mandatory.
    assert workflow["jobs"]["ci-gate"]["env"]["DIDCOMM_RELEASE_TEST_ONLY"] == (
        f"${{{{ {focused_flag} }}}}"
    )


def test_retired_worker_rollback_leaf_cannot_narrow_validation(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    source = "tests/test_beta_worker_launch_rollback.py"
    assert workflow["jobs"]["changes"]["outputs"]["rollback_test_only"] == (
        "${{ steps.classify.outputs.rollback_test_only }}"
    )

    def classify(paths, **kwargs):
        return _classify_changed_paths(
            paths,
            tmp_path,
            combined=True,
            include_rust_plan=True,
            include_rollback_plan=True,
            **kwargs,
        )[0]

    exact = classify([source])
    assert exact == {
        "all": "true", "ui": "true", "python": "true", "rust": "true",
        "rust_runtime": "true", "rust_matrix": '["contracts","flow","selfhost"]',
        "openbao": "true", "rollback_test_only": "false", "release": "true",
        "verification": "true", "security": "true",
    }
    from scripts.ci import affected_components as plan
    forged = dict.fromkeys(plan.FLAGS, False)
    forged.update(rollback_test_only=True, release=True, security=True)
    with pytest.raises(ValueError, match="retired rollback-only selection"):
        plan.validate_flags(forged, plan.FULL_MATRIX, "pull_request")
    assert classify([])["rollback_test_only"] == "false"
    for other in (
        "docs/architecture-feedback-improvement-plan.md",
        "scripts/beta-worker-launch-contract.ps1",
        "scripts/deploy-local-beta-release.ps1",
        "scripts/restore-local-beta-release.ps1",
        ".github/workflows/ci.yml",
        "tests/test_beta_worker_launch_rollback_helper.py",
        "tests/package-lock.json",
        "rust/services/issuance/src/main.rs",
        "unrecognized/rollback-input.bin",
        "renamed/rollback-contract.py",
    ):
        mixed = classify([source, other])
        assert mixed["rollback_test_only"] == "false", other
        assert mixed["all"] == "true", other
    assert classify([source, source])["all"] == "true"
    with pytest.raises(AssertionError):
        classify([source], missing_base=True)
    protected = classify([source], event="merge_group")
    assert protected["all"] == "true"
    assert protected["rollback_test_only"] == "false"
    assert classify([source], event="push")["rollback_test_only"] == "false"
    with pytest.raises(AssertionError):
        classify([source], fetch_failure=True)

    # A deleted or symlinked source is not the reviewed test-only leaf.
    absent = tmp_path / "absent-source"
    (absent / "tests").mkdir(parents=True)
    assert classify([source], working_directory=absent)["all"] == "true"
    linked = tmp_path / "linked-source"
    (linked / "tests").mkdir(parents=True)
    try:
        (linked / source).symlink_to(ROOT / source)
    except (OSError, NotImplementedError):
        pass  # Windows without symlink privilege; the Linux CI case executes it.
    else:
        assert classify([source], working_directory=linked)["all"] == "true"

    release = workflow["jobs"]["test-release-contracts"]
    steps = {step.get("name"): step for step in release["steps"]}
    assert "Run rollback-test-owned PR checks" not in steps
    assert '[[ "$ROLLBACK_TEST_ONLY" == false ]]' in workflow["jobs"]["ci-gate"]["steps"][0]["run"]
    assert steps["Run repository release checks"]["run"] == (
        RELEASE_TEST_COMMAND
    )
    full_only = (
        ""
        "needs.changes.outputs.k8s_policy_test_only != 'true' && "
        "needs.changes.outputs.didcomm_release_test_only != 'true'"
    )
    for name in (
        "Run repository release checks",
        "Configure the pinned containerd image store",
        "Configure the pinned OCI exporter",
        "Require the exact supported OCI backend",
        "Prove the same OCI archive through the future consumer path",
    ):
        assert steps[name]["if"] == full_only
        assert not steps[name].get("continue-on-error", False)
    for name in (
        "Install released test dependencies",
        "Verify released mdoc binding evidence contract",
        "Enforce OSS commerce boundary",
        "Require workflow policy test collection",
    ):
        assert "if" not in steps[name]
    assert workflow["jobs"]["security"]["if"] == (
        "needs.changes.outputs.security == 'true'"
    )
    for dockerfile in ("services/Dockerfile", "docker/ui.Dockerfile"):
        assert "COPY tests" not in (ROOT / dockerfile).read_text(encoding="utf-8")
    gate = workflow["jobs"]["ci-gate"]
    assert {"security", "test-release-contracts"} <= set(gate["needs"])
    assert (
        'require_selected security "$SECURITY_RESULT" "$SECURITY_SELECTED"'
        in (gate["steps"][0]["run"])
    )


def test_frozen_reference_test_sources_select_only_release_on_prs(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    assert any(
        step.get("run") == RELEASE_TEST_COMMAND
        for step in workflow["jobs"]["test-release-contracts"]["steps"]
    )
    paths = (
        "tests/test_signing_response_reference.py",
        "tests/test_token_rate_reference.py",
    )
    selected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "openbao": "false",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    ci_source = CI_PATH.read_text(encoding="utf-8") + (ROOT / "scripts/ci/affected_components.sh").read_text()
    for path in paths:
        assert (ROOT / path).is_file(), f"stale release-only selector: {path}"
        assert ci_source.count(path) == 1, f"other direct CI consumer: {path}"
        for other_workflow in (ROOT / ".github/workflows").glob("*.yml"):
            if other_workflow != CI_PATH:
                assert path not in other_workflow.read_text(encoding="utf-8")
        assert _classify_changed_path(path, tmp_path) == selected

    # This selector is for exact test sources, not reference artifacts or
    # support implementations. Their existing Rust/full owners must remain.
    for path in (
        "contracts/signing-response-python-reference.json",
        "contracts/token-rate-python-reference.json",
    ):
        assert _classify_changed_path(path, tmp_path)["rust"] == "true"
    for path in (
        "scripts/new-unregistered-database-probe.py",
        "tests/test_signing_response_reference_helpers.py",
        "unknown-new-input.txt",
    ):
        assert _classify_changed_path(path, tmp_path)["all"] == "true"

    service = _classify_changed_paths(
        [paths[0], "services/entrypoint.sh"], tmp_path, combined=True
    )[0]
    assert service == {
        **selected,
        "python": "true",
        "rust": "true",
        "security": "true",
    }
    assert _classify_changed_paths(
        [paths[1], "unknown-new-input.txt"], tmp_path, combined=True
    )[0] == dict.fromkeys(selected, "true")
    assert _classify_changed_paths([paths[0]], tmp_path, event="merge_group")[
        0
    ] == dict.fromkeys(selected, "true")

    # The security lane audits dependency graphs and reports on services/
    # and packages/, not root tests/. Any scanner-scope change requires a
    # selector re-audit; these assertions document the current scope only.
    security_source = CI_PATH.read_text(encoding="utf-8")
    assert "pip-audit -r requirements-services.txt" in security_source
    assert "npm audit --package-lock-only --audit-level=low" in security_source
    assert "bandit -r services/ packages/" in security_source
    assert (
        "semgrep scan --config=auto --json --output semgrep-report.json services/ packages/"
        in security_source
    )


def test_selfhost_reference_test_is_not_a_service_image_input() -> None:
    """Keep the release-only selector honest if CI image contexts expand."""
    dockerfiles = [
        ROOT / "services/Dockerfile",
        ROOT / "services/Dockerfile.migrations",
        ROOT / "openbao/didcomm-authcrypt/Dockerfile",
        ROOT / "keycloak/openbao-provider/Dockerfile",
        ROOT / "rust/services/Dockerfile.ci",
        *(ROOT / "rust/services").glob("*/Dockerfile"),
    ]
    scanned = {path.relative_to(ROOT).as_posix() for path in dockerfiles}
    for workflow, excluded in (
        (CI_PATH, set()),
        # Official-only UI and tunnel-wrapper roles do not compile Rust
        # service binaries; their separate release ownership is asserted by
        # test_selfhost_release_preparation.py.
        (
            ROOT / ".github/workflows/cd.yml",
            {
                "docker/ui.Dockerfile",
                "docker/cloudflared-wrapper.Dockerfile",
            },
        ),
    ):
        image_inputs = set(
            re.findall(
                r"(?m)^\s*file:\s+([^\s#]*Dockerfile[^\s#]*)\s*$",
                workflow.read_text(encoding="utf-8"),
            )
        )
        assert image_inputs - excluded <= scanned, workflow
    for dockerfile in dockerfiles:
        assert dockerfile.is_file()
        for line in dockerfile.read_text(encoding="utf-8").splitlines():
            if not re.match(r"^\s*(COPY|ADD)\s", line):
                continue
            # A new whole-context, JSON-form, or root-test copy needs an
            # explicit selector review before test-only PRs skip image lanes.
            instruction = re.sub(r"^\s*(?:COPY|ADD)\s+", "", line)
            assert not re.match(r"(?:--\S+\s+)*\[", instruction), dockerfile
            sources = [
                part for part in instruction.split()[:-1] if not part.startswith("--")
            ]
            assert sources, dockerfile
            assert all(
                source not in {".", "./", "tests", "./tests"}
                and not source.startswith(("tests/", "./tests/"))
                and not any(char in source for char in "*?[]$")
                for source in sources
            ), dockerfile


def test_external_rust_include_inputs_select_rust_validation(tmp_path: Path) -> None:
    """Every direct embedded input outside rust/ must select its Rust consumer."""
    macro_start = re.compile(r"\binclude(?:_(?:str|bytes))?!\s*[({\[]")
    resolved_macro = re.compile(
        r'\binclude(?:_(?:str|bytes))?!\s*\(\s*(?:"(?P<literal>[^"]+)"\s*|'
        r'concat!\s*\(\s*env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)\s*,\s*'
        r'"(?P<manifest>[^"]+)"\s*\)\s*)\)',
        re.DOTALL,
    )
    external_inputs: set[str] = set()
    macro_count = 0
    matched_count = 0
    tracked = subprocess.run(
        ["git", "ls-files", "-z", "--", "rust"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    sources = (
        ROOT / path.decode("utf-8")
        for path in tracked.split(b"\0")
        if path.endswith(b".rs")
    )
    for source in sources:
        text = source.read_text(encoding="utf-8")
        macro_count += len(macro_start.findall(text))
        for match in resolved_macro.finditer(text):
            matched_count += 1
            if literal := match.group("literal"):
                target = (source.parent / literal).resolve()
            else:
                manifest_path = match.group("manifest")
                assert manifest_path and manifest_path.startswith("/")
                package = next(
                    parent
                    for parent in source.parents
                    if (parent / "Cargo.toml").is_file()
                )
                target = (package / manifest_path.removeprefix("/")).resolve()
            assert target.is_relative_to(ROOT), f"Embedded input leaves repo: {source}"
            assert target.is_file(), f"Missing embedded input: {source} -> {target}"
            relative = target.relative_to(ROOT).as_posix()
            if not relative.startswith("rust/"):
                external_inputs.add(relative)
    assert macro_count == matched_count, (
        "Review new include macro forms before classifying inputs"
    )
    assert external_inputs, "Expected external Rust compiler inputs"
    paths = sorted(external_inputs)
    for path, actual in zip(
        paths, _classify_changed_paths(paths, tmp_path), strict=True
    ):
        assert actual["rust"] == "true", f"Rust consumer skipped for {path}"


def test_classifier_diff_failure_fails_closed(tmp_path: Path) -> None:
    _, document = _workflow(CI_PATH)
    [classifier] = [
        step
        for step in document["jobs"]["changes"]["steps"]
        if step.get("id") == "classify"
    ]
    script = classifier["run"].replace("${{ github.event_name }}", "pull_request")
    git_bash = Path("C:/Program Files/Git/bin/bash.exe")
    bash = (
        str(git_bash)
        if os.name == "nt" and git_bash.is_file()
        else shutil.which("bash")
    )
    assert bash
    environment = dict(os.environ)
    environment.pop("BASH_ENV", None)
    environment.pop("ENV", None)
    environment.update(BASE_SHA="b" * 40, SOURCE_SHA="a" * 40, HEAD_SHA="a" * 40, EVENT_NAME="pull_request")
    environment["RUNNER_TEMP"] = tmp_path.as_posix()
    output = tmp_path / "synthetic-actions-output"
    environment["GITHUB_OUTPUT"] = output.as_posix()
    prelude = 'git() { case "$1" in fetch) return 0 ;; rev-parse) printf "%s\\n" "$SOURCE_SHA" ;; *) return 42 ;; esac; }\n'
    prelude += 'python3() { '+shlex.quote(Path(sys.executable).as_posix())+' "$@"; }\n'
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-s"],
        input=prelude + script,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
        env=environment,
    )
    assert result.returncode == 42
    assert not output.exists()


def test_classifier_diff_reports_both_rename_endpoints(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    git_environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    git_environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

    def git(*arguments: str) -> bytes:
        return subprocess.run(
            ["git", *arguments],
            cwd=repository,
            env=git_environment,
            check=True,
            capture_output=True,
        ).stdout

    git("init", "-q")
    git("config", "user.name", "CI classifier test")
    git("config", "user.email", "ci-classifier@example.invalid")
    old_path = repository / "rust" / "source.rs"
    old_path.parent.mkdir()
    old_path.write_text("fn main() {}\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "original input")
    (repository / "docs").mkdir()
    git("mv", "rust/source.rs", "docs/source.md")
    git("commit", "-qm", "move input")

    changed = git("diff", "--name-only", "-z", "--no-renames", "HEAD~", "HEAD")
    assert set(changed.split(b"\0")) == {
        b"rust/source.rs",
        b"docs/source.md",
        b"",
    }


def test_native_socket_timeout_gate_is_explicit_and_mandatory() -> None:
    _, document = _workflow(CI_PATH)
    steps = document["jobs"]["test-rust-services"]["steps"]
    gate = next(
        step
        for step in steps
        if step.get("name") == "Test native outbound HTTP timeout TLS parity"
    )
    assert gate["if"] == "matrix.lane == 'contracts'"
    assert not gate.get("continue-on-error", False)
    matrix = document["jobs"]["test-rust-services"]["strategy"]["matrix"]["lane"]
    for literal in re.findall(r"'(\[[^']+\])'", matrix):
        lanes = json.loads(literal)
        assert {"contracts", "flow", "selfhost"} <= set(lanes)
    compile_step = next(
        step["run"]
        for step in steps
        if step.get("name") == "Compile reusable Rust test executables"
    )
    assert 'elif [[ "${{ matrix.lane }}" == contracts ]]; then' in compile_step
    assert "cargo test --locked --workspace --no-run" in compile_step
    assert (
        "grep -Fx 'outbound_http::tests::native_socket_case: test'"
        in gate["run"]
    )
    assert "--native-executable" in gate["run"]
    assert "--qualification 1" in gate["run"]
    assert "select(.profile.test == true)" in gate["run"]
    assert "cryptography==44.0.3" in gate["run"]
    source = (ROOT / "rust/services/issuance/src/outbound_http.rs").read_text(
        encoding="utf-8"
    )
    assert (
        '#[tokio::test]\n    #[ignore = "requires the owned loopback TLS '
        'and historical socket fixture"]\n    async fn native_socket_case()'
    ) in source
    assert 'let Ok(raw) = std::env::var("MARTY_OUTBOUND_TIMEOUT_NATIVE_CASE")' not in source
    assert '.unwrap_or_else(|_| panic!("owned native outbound socket case is absent"))' in source
    assert '.expect("owned native outbound socket case")' not in source
    runner = (ROOT / "scripts/run_outbound_http_timeout_oracle.py").read_text(
        encoding="utf-8"
    )
    assert '"outbound_http::tests::native_socket_case",\n                    "--exact",\n                    "--ignored",' in runner


def _assert_no_rust_executable_transfer(steps) -> None:
    # These allowlisted uploads contain diagnostics, build timings, and JSON evidence,
    # never compiled tests. Other artifact transfers remain forbidden.
    expected_uploads = {
        "Upload Rust build evidence": "${{ runner.temp }}/rust-build-evidence/",
        "Upload successful PR Rust checkout identity": "${{ runner.temp }}/pr-rust-checkout-attestation.json",
    }
    uploads = {}
    for step in steps:
        action = step.get("uses", "")
        assert not action.startswith("actions/download-artifact@")
        if action.startswith("actions/upload-artifact@"):
            name = step.get("name")
            assert name in expected_uploads and name not in uploads
            assert step.get("with", {}).get("path") == expected_uploads[name]
            uploads[name] = step
    assert set(uploads) == set(expected_uploads)


@pytest.mark.parametrize(
    "fault", ["binary", "broad", "build-binary", "build-broad", "extra", "download"]
)
def test_rust_executable_transfer_guard_rejects_non_diagnostic_artifacts(fault):
    _, document = _workflow(CI_PATH)
    steps = document["jobs"]["test-rust-services"]["steps"]
    upload = next(
        step
        for step in steps
        if step.get("name") == "Upload successful PR Rust checkout identity"
    )
    if fault == "binary":
        upload["with"]["path"] = "rust/target/debug/*"
    elif fault == "broad":
        upload["with"]["path"] = "${{ runner.temp }}/**"
    elif fault in {"build-binary", "build-broad"}:
        build_upload = next(
            step for step in steps if step.get("name") == "Upload Rust build evidence"
        )
        build_upload["with"]["path"] = (
            "rust/target/debug/*"
            if fault == "build-binary"
            else "${{ runner.temp }}/**"
        )
    elif fault == "extra":
        steps.append(dict(upload))
    else:
        steps.append({"uses": "actions/download-artifact@unexpected"})
    with pytest.raises(AssertionError):
        _assert_no_rust_executable_transfer(steps)


def test_rust_contracts_reuse_local_executables_without_artifact_transfer() -> None:
    source, document = _workflow(CI_PATH)
    rust_job = document["jobs"]["test-rust-services"]
    step_names = {step.get("name") for step in rust_job["steps"]}

    assert rust_job["env"]["CARGO_PROFILE_TEST_DEBUG"] == 0
    assert "Run safe Rust contract groups concurrently" in step_names
    assert "Run Flow database contract after workspace suite" in step_names
    assert "Run isolated database contract suites concurrently" in step_names
    orchestrator = (ROOT / "scripts/ci/run-db-contract-groups.py").read_text(
        encoding="utf-8"
    )
    assert "run-rust-db-contracts.sh" in orchestrator
    assert "ThreadPoolExecutor(max_workers=2)" in orchestrator
    assert "test-rust-db-contracts" not in document["jobs"]
    assert "rust-db-test-bundle" not in source
    _assert_no_rust_executable_transfer(rust_job["steps"])
    for group in ("workspace", "verification", "gateway"):
        assert f"rust-{group}.status" in source
    assert "run_timed flow_postgres target/debug/flow-postgres-contract --test-threads=1" in source
    assert "target/debug/verification-postgres-contract" in source
    assert "target/debug/gateway-redis-contract" in source
    assert (
        "FLOW_POSTGRES_TEST_URL: postgresql://postgres:postgres@127.0.0.1:5432/marty_atomic_test"
        in source
    )
    assert "FLOW_CONTRACT_POSTGRES_URL" not in source
    assert "POSTGRES_DB=marty_atomic_test" not in source
    assert "cargo test --locked -p marty-flow --test postgres_integration" not in source


def test_released_native_backend_is_verified_without_rebuilding_it() -> None:
    source, document = _workflow(CI_PATH)
    service_job = document["jobs"]["test-services"]
    service_source = "\n".join(str(step) for step in service_job["steps"])

    assert "Verify released native trust-registry backend" in service_source
    assert '"trust_registry_sync"' in service_source
    assert "maturin" not in service_source
    assert "ElevenID/marty-core" not in service_source
    assert "MARTY_CORE_TRUST_REGISTRY_REF" not in source


def test_ui_timing_refresh_runs_after_the_required_ci_gate() -> None:
    source, document = _workflow(
        ROOT / ".github" / "workflows" / "refresh-ui-test-timings.yml"
    )

    assert "workflow_run:" in source
    assert "workflows: [CI]" in source
    refresh = document["jobs"]["refresh"]
    assert refresh["if"] == "github.event.workflow_run.conclusion == 'success'"
    assert (
        "refresh-ui-test-timings"
        not in yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))["jobs"]
    )


@pytest.mark.parametrize(
    ("primary", "retry", "expected_success"),
    [
        ("success", "skipped", True),
        ("failure", "success", True),
        ("failure", "failure", False),
    ],
)
def test_ui_timing_upload_retry_keeps_tests_and_artifact_required(
    primary: str, retry: str, expected_success: bool
) -> None:
    _, document = _workflow(CI_PATH)
    steps = document["jobs"]["test-ui"]["steps"]
    unit = next(step for step in steps if step.get("name") == "Unit tests")
    first = next(step for step in steps if step.get("id") == "ui_timing_upload")
    second = next(step for step in steps if step.get("id") == "ui_timing_retry")
    gate = next(
        step
        for step in steps
        if step.get("name") == "Require per-file test timings upload"
    )

    assert (
        steps.index(unit) < steps.index(first) < steps.index(second) < steps.index(gate)
    )
    assert "test-ui" in document["jobs"]["ci-gate"]["needs"]
    assert unit["run"] == "node scripts/run-vitest-shard.mjs ${{ matrix.shard }} 4"
    assert unit["env"]["VITEST_TIMING_OUTPUT"] == (
        "${{ runner.temp }}/ui-vitest-timing-${{ matrix.shard }}.json"
    )
    assert not unit.get("continue-on-error") and not unit.get("if")
    assert first["if"] == "always()"
    assert second["if"] == "always() && steps.ui_timing_upload.outcome == 'failure'"
    assert (retry != "skipped") is (primary == "failure")
    assert first["continue-on-error"] is True
    assert second["continue-on-error"] is True
    assert (
        first["uses"]
        == second["uses"]
        == ("actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9")
    )
    for upload in (first, second):
        assert upload["with"]["name"] == "ui-vitest-timing-${{ matrix.shard }}"
        assert upload["with"]["path"] == (
            "${{ runner.temp }}/ui-vitest-timing-${{ matrix.shard }}.json"
        )
        assert upload["with"]["retention-days"] == 14
        assert upload["with"]["if-no-files-found"] == "error"
    assert second["with"]["overwrite"] is True
    assert not first["with"].get("overwrite")
    assert gate["if"] == "always()"
    assert not gate.get("continue-on-error")
    assert gate["env"] == {
        "PRIMARY_OUTCOME": "${{ steps.ui_timing_upload.outcome }}",
        "RETRY_OUTCOME": "${{ steps.ui_timing_retry.outcome }}",
    }

    git_bash = Path("C:/Program Files/Git/bin/bash.exe")
    bash = (
        str(git_bash)
        if os.name == "nt" and git_bash.is_file()
        else shutil.which("bash")
    )
    assert bash, "Bash is required to exercise the timing artifact gate"
    environment = {
        **os.environ,
        "PRIMARY_OUTCOME": primary,
        "RETRY_OUTCOME": retry,
    }
    environment.pop("BASH_ENV", None)
    environment.pop("ENV", None)
    result = subprocess.run(
        [bash, "-c", gate["run"]],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is expected_success
    if not expected_success:
        assert "Both per-file timing artifact uploads failed" in result.stderr


@pytest.mark.parametrize(
    "scenario",
    ["missing", "empty", "unrelated", "nested", "malformed", "not_directory"],
)
def test_ui_timing_refresh_checks_actual_reports(tmp_path: Path, scenario: str) -> None:
    _, document = _workflow(
        ROOT / ".github" / "workflows" / "refresh-ui-test-timings.yml"
    )
    steps = document["jobs"]["refresh"]["steps"]
    guard = next(step for step in steps if step.get("id") == "observations")
    assert guard["if"] == "steps.download.outcome == 'success'"
    for name in ("Produce refreshed timing plan", "Upload refreshed timing plan"):
        step = next(step for step in steps if step.get("name") == name)
        assert step["if"] == "steps.observations.outputs.available == 'true'"

    reports = tmp_path / "reports"
    output = tmp_path / "github-output"
    if scenario == "not_directory":
        reports.write_text("not a directory", encoding="utf-8")
    elif scenario != "missing":
        reports.mkdir()
        if scenario == "unrelated":
            (reports / "notes.txt").write_text("no reports", encoding="utf-8")
            (reports / "directory.json").mkdir()
        elif scenario in {"nested", "malformed"}:
            nested = reports / "shard-1"
            nested.mkdir()
            report = {
                "testResults": [
                    {
                        "name": "/home/runner/work/marty-ui/marty-ui/ui/src/refresh.test.ts",
                        "startTime": 100,
                        "endTime": 150,
                    }
                ]
            }
            (nested / "results.json").write_text(
                json.dumps(report) if scenario == "nested" else "not JSON",
                encoding="utf-8",
            )

    script = guard["run"].split("<<'NODE'\n", 1)[1].rsplit("\nNODE", 1)[0]
    result = subprocess.run(
        ["node", "--input-type=module", "--eval", script],
        env={
            **os.environ,
            "TIMINGS_DIRECTORY": str(reports),
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
        text=True,
    )
    if scenario == "not_directory":
        assert result.returncode != 0
        assert not output.exists()
        return
    assert result.returncode == 0, result.stderr
    available = scenario in {"nested", "malformed"}
    assert (
        output.read_text(encoding="utf-8").strip()
        == f"available={str(available).lower()}"
    )
    if not available:
        assert "skipping timing refresh" in result.stdout
        return

    plan = tmp_path / "plan.json"
    refresh = subprocess.run(
        [
            "node",
            str(ROOT / "ui/scripts/update-vitest-timings.mjs"),
            str(reports),
            "--output",
            str(plan),
        ],
        capture_output=True,
        text=True,
    )
    if scenario == "malformed":
        assert refresh.returncode != 0
        assert not plan.exists()
    else:
        assert refresh.returncode == 0, refresh.stderr
        assert (
            json.loads(plan.read_text(encoding="utf-8"))["tests"]["src/refresh.test.ts"]
            == 50
        )


def test_advanced_codeql_keeps_full_merge_and_scheduled_coverage() -> None:
    rust_source, rust_workflow = _workflow(
        ROOT / ".github" / "workflows" / "codeql-rust.yml"
    )
    actions_source, actions_workflow = _workflow(
        ROOT / ".github" / "workflows" / "codeql-actions.yml"
    )
    production = yaml.safe_load(
        (ROOT / ".github" / "codeql" / "codeql-production.yml").read_text(
            encoding="utf-8"
        )
    )
    full = yaml.safe_load(
        (ROOT / ".github" / "codeql" / "codeql-full.yml").read_text(encoding="utf-8")
    )
    policy = json.loads(
        (ROOT / ".github" / "stack-tag-policy.json").read_text(encoding="utf-8")
    )

    assert "merge_group:" in rust_source
    assert "merge_group:" in actions_source
    assert "schedule:" in rust_source
    assert "schedule:" in actions_source
    assert "github.event_name == 'schedule'" in rust_source
    rust_events = rust_workflow.get("on") or rust_workflow[True]
    actions_events = actions_workflow.get("on") or actions_workflow[True]
    assert rust_events["pull_request"] == {"branches": ["main"]}
    assert actions_events["pull_request"] == {"branches": ["main"]}
    rust_job = rust_workflow["jobs"]["analyze-rust"]
    actions_job = actions_workflow["jobs"]["analyze-actions"]
    for job in (rust_job, actions_job):
        assert "if" not in job
        assert job["env"]["CODEQL_ADVANCED_ENABLED"] == (
            "${{ vars.CODEQL_ADVANCED_ENABLED }}"
        )
        guard = job["steps"][0]
        assert guard["name"] == "Require the completed advanced CodeQL cutover"
        assert 'test "$CODEQL_ADVANCED_ENABLED" = "true"' in guard["run"]
        assert job["permissions"]["pull-requests"] == "read"
        scope = next(step for step in job["steps"] if step.get("id") == "scope")
        source_guard = next(step for step in job["steps"] if step.get("name") == "Validate the complete source-bound analysis diff")
        assert source_guard["run"] == "python3 scripts/ci/codeql_scope.py"
        assert "github.paginate" not in scope["with"]["script"]
        assert "scope.files" in scope["with"]["script"]
        assert "context.eventName !== 'pull_request'" in scope["with"]["script"]
        assert any(
            step.get("name") == "Record scoped analysis skip" for step in job["steps"]
        )
        analysis_steps = [
            step for step in job["steps"] if step.get("name", "").startswith("Analyze")
        ]
        assert analysis_steps
        expected_condition = "steps.scope.outputs.analyze == 'true'"
        if job is rust_job:
            expected_condition += " && steps.test_only.outputs.skip != 'true'"
            proof = next(step for step in job["steps"] if step.get("id") == "test_only")
            assert proof["if"] == "steps.scope.outputs.test_only_candidate == 'true'"
            assert "--emit-verified-flow-tests" in proof["with"]["script"]
            assert "--emit-verified-selfhost-tests" in proof["with"]["script"]
            init = next(
                step for step in job["steps"]
                if step.get("name") == "Initialize production-focused analysis"
            )
            assert init["with"]["languages"] == "rust"
            assert init["with"]["build-mode"] == "none"
            assert init["with"]["dependency-caching"] is False
            assert init["with"]["trap-caching"] is False
            assert init["with"]["debug"] is False
            assert init["with"]["config-file"] == (
                "${{ (github.event_name == 'schedule' || "
                "github.event_name == 'workflow_dispatch') && "
                "'./.github/codeql/codeql-full.yml' || "
                "'./.github/codeql/codeql-production.yml' }}"
            )
        assert all(step["if"] == expected_condition for step in analysis_steps)
    assert "filename.startsWith('rust/')" in rust_source
    assert "filename.startsWith('.github/codeql/')" in rust_source
    assert "filename === '.github/workflows/codeql-rust.yml'" in rust_source
    assert "filename.startsWith('.github/')" in actions_source
    assert production["paths"] == ["rust/crates/**", "rust/services/**"]
    assert "rust/third_party/**" in production["paths-ignore"]
    assert full["paths"] == ["rust/**"]
    required = policy["required_workflows"]
    assert {
        "path": ".github/workflows/codeql-rust.yml",
        "event": "merge_group",
    } in required
    assert {
        "path": ".github/workflows/codeql-actions.yml",
        "event": "merge_group",
    } in required
    assert {
        "path": "dynamic/github-code-scanning/codeql",
        "event": "dynamic",
    } not in required


def test_rust_codeql_test_only_scope_fails_closed() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable for the GitHub Script policy test")
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/codeql-rust.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["analyze-rust"]["steps"]
    scope = next(step for step in steps if step.get("id") == "scope")["with"]["script"]
    proof = next(step for step in steps if step.get("id") == "test_only")["with"]["script"]
    workflow_source = (ROOT / ".github/workflows/codeql-rust.yml").read_text(
        encoding="utf-8"
    )
    config = (ROOT / ".github/codeql/codeql-production.yml").read_text(
        encoding="utf-8"
    )
    selfhost = "rust/crates/selfhost-acceptance/tests/support/selfhost_runtime_sidecar.rs"
    service_acceptance = "rust/crates/service-acceptance/tests/gateway_signing_acceptance.rs"
    signing_csca = "rust/services/signing-keys/tests/csca_lifecycle_behavior.rs"
    proofs = {
        "--emit-verified-flow-tests": {
            "status": 0,
            "stdout": "rust/crates/flow-acceptance/tests/flow_published_schema_contract.rs\0",
        },
        "--emit-verified-selfhost-tests": {"status": 0, "stdout": selfhost + "\0"},
        "--emit-verified-contract-tests": {
            "status": 0,
            "stdout": service_acceptance + "\0" + signing_csca + "\0",
        },
    }
    harness = r"""
      const fs = require('node:fs');
      const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
      const outputs = {};
      const core = { setOutput: (key, value) => { outputs[key] = value; }, info: () => {} };
      const github = {
        paginate: async () => payload.files,
        rest: { pulls: { listFiles: {} } },
      };
      const context = {
        eventName: payload.event,
        repo: { owner: 'ElevenID', repo: 'marty-ui' },
        payload: { pull_request: { number: 1228 } },
      };
      (async () => {
        const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
        const scopeRequire = name => {
          if (name !== 'node:fs') throw new Error('unexpected scope module');
          return {readFileSync: () => JSON.stringify({event: payload.event, files: payload.files, website_only: false})};
        };
        await new AsyncFunction('core', 'github', 'context', 'require', 'process', payload.scope)(
          core, github, context, scopeRequire, {env: {CODEQL_SCOPE_FILE: 'bound-scope.json'}}
        );
        if (outputs.test_only_candidate === 'true') {
          const mockedRequire = name => {
            if (name === 'node:fs') return { readFileSync: path =>
              path.endsWith('codeql-production.yml') ? payload.config : payload.workflow
            };
            if (name === 'node:child_process') return {
              spawnSync: (_program, args) => payload.proofs[args[1]] ||
                { status: 1, stderr: 'unverified', stdout: '' },
            };
            throw new Error(`unexpected module: ${name}`);
          };
          await new AsyncFunction('core', 'require', 'process', payload.proof)(
            core, mockedRequire, { env: { CANDIDATE_PATHS: outputs.candidate_paths } }
          );
        }
        process.stdout.write(JSON.stringify(outputs));
      })().catch(error => { console.error(error); process.exitCode = 1; });
    """

    def classify(files: list[dict], *, event: str = "pull_request",
                 codeql_config: str = config, workflow_text: str = workflow_source,
                 proof_results: dict = proofs) -> dict:
        result = subprocess.run(
            [node, "-e", harness],
            input=json.dumps({
                "files": files, "event": event, "config": codeql_config,
                "workflow": workflow_text,
                "proofs": proof_results, "scope": scope, "proof": proof,
            }),
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    exact = [{"filename": selfhost, "status": "modified"}]
    assert classify(exact)["skip"] == "true"
    assert classify([{"filename": service_acceptance, "status": "modified"}])["skip"] == "true"
    assert classify([{"filename": signing_csca, "status": "modified"}])["skip"] == "true"
    assert classify([
        {"filename": service_acceptance, "status": "modified"},
        {"filename": selfhost, "status": "modified"},
    ])["skip"] == "true"
    for path in [
        "rust/crates/flow-acceptance/tests/flow_published_schema_contract.rs",
    ]:
        assert classify([{"filename": path, "status": "modified"}])["skip"] == "true"
    for changed in [
        exact + [{"filename": "README.md", "status": "modified"}],
        [{"filename": selfhost, "status": "added"}],
        [{"filename": selfhost, "status": "renamed", "previous_filename": "old.rs"}],
        [{"filename": "rust/services/issuance/src/main.rs", "status": "modified"}],
    ]:
        assert "skip" not in classify(changed)
    assert "skip" not in classify([{
        "filename": "rust/crates/selfhost-acceptance/tests/support/unverified.rs",
        "status": "modified",
    }])
    assert "skip" not in classify([{
        "filename": "rust/crates/service-acceptance/tests/unverified.rs",
        "status": "modified",
    }])
    for status in ("added", "renamed"):
        assert "skip" not in classify([{
            "filename": service_acceptance,
            "status": status,
            "previous_filename": "old.rs" if status == "renamed" else None,
        }])
    assert "skip" not in classify(exact, codeql_config=config + "# changed\n")
    assert "skip" not in classify(
        exact, workflow_text=workflow_source.replace("build-mode: none", "build-mode: manual")
    )
    assert "skip" not in classify(
        exact, workflow_text=workflow_source.replace(
            "|| './.github/codeql/codeql-production.yml'",
            "|| './.github/codeql/codeql-full.yml'",
        )
    )
    failed_proofs = {**proofs, "--emit-verified-selfhost-tests": {
        "status": 1, "stdout": "", "stderr": "proof failed"
    }}
    assert "skip" not in classify(exact, proof_results=failed_proofs)
    failed_service_proof = {**proofs, "--emit-verified-contract-tests": {
        "status": 1, "stdout": "", "stderr": "proof failed"
    }}
    assert "skip" not in classify(
        [{"filename": service_acceptance, "status": "modified"}],
        proof_results=failed_service_proof,
    )
    assert "skip" not in classify(
        [{"filename": signing_csca, "status": "modified"}],
        proof_results=failed_service_proof,
    )
    assert classify(exact, event="merge_group")["analyze"] == "true"
    assert classify([{"filename": "README.md", "status": "modified"}])["analyze"] == "false"


def test_warm_cache_uses_the_same_rust_test_profile() -> None:
    _source, document = _workflow(ROOT / ".github" / "workflows" / "warm-ci-caches.yml")
    assert document["jobs"]["rust"]["env"]["CARGO_PROFILE_TEST_DEBUG"] == 0


def test_ephemeral_ci_reads_only_shared_python_and_browser_caches() -> None:
    _, ci = _workflow(CI_PATH)
    _, warm = _workflow(ROOT / ".github/workflows/warm-dependency-caches.yml")
    python_jobs = (
        "test-services",
        "public-protocol-contract",
        "test-release-contracts",
    )
    setup_uv = "astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2"
    expected_inputs = {
        "version": "0.11.3",
        "enable-cache": True,
        "cache-dependency-glob": "requirements-services.txt\nrelease/stack-lock.json\n",
        "cache-suffix": "python-services",
    }
    for job_name in python_jobs:
        steps = ci["jobs"][job_name]["steps"]
        setup = next(step for step in steps if step.get("uses") == setup_uv)
        assert setup["with"]["save-cache"] is False
        assert {key: setup["with"][key] for key in expected_inputs} == expected_inputs

    python_warmer = warm["jobs"]["python"]
    assert python_warmer["if"] == "github.ref == 'refs/heads/main'"
    assert python_warmer["runs-on"] == "ubuntu-24.04"
    python_versions = python_warmer["strategy"]["matrix"]["python-version"]
    assert python_versions == ["3.12", "3.12.10"]
    for job_name in python_jobs:
        setup_python = next(
            step
            for step in ci["jobs"][job_name]["steps"]
            if step.get("uses", "").startswith("actions/setup-python@")
        )
        assert setup_python["with"]["python-version"] in python_versions
    warm_setup = next(
        step for step in python_warmer["steps"] if step.get("uses") == setup_uv
    )
    assert warm_setup["id"] == "uv-cache"
    assert {key: warm_setup["with"][key] for key in expected_inputs} == expected_inputs
    warm_install = next(
        step
        for step in python_warmer["steps"]
        if step.get("name") == "Warm shared Python dependencies"
    )
    assert warm_install["if"] == "steps.uv-cache.outputs.cache-hit != 'true'"
    protocol_install = next(
        step
        for step in ci["jobs"]["public-protocol-contract"]["steps"]
        if step.get("name") == "Install contract-check dependencies"
    )
    format_aware_install = (
        "uv pip install --system -r requirements-services.txt "
        "'jsonschema[format]>=4.23'"
    )
    assert protocol_install["run"] == format_aware_install
    assert (
        warm_install["run"]
        == format_aware_install
    )

    browser_steps = ci["jobs"]["test-credential-lifecycle-browser"]["steps"]
    # Browser coverage remains in the mandatory credential-lifecycle gate.
    browser_cache = next(
        step for step in browser_steps if step.get("id") == "playwright-cache"
    )
    warm_browser = warm["jobs"]["browser"]
    assert warm_browser["if"] == "github.ref == 'refs/heads/main'"
    warm_cache = next(
        step for step in warm_browser["steps"] if step.get("id") == "playwright-cache"
    )
    assert browser_cache["uses"] == warm_cache["uses"].replace(
        "actions/cache@", "actions/cache/restore@"
    )
    assert browser_cache["with"] == warm_cache["with"]
    warm_browser_install = next(
        step
        for step in warm_browser["steps"]
        if step.get("name") == "Install pinned Playwright CLI"
    )
    assert (
        warm_browser_install["if"]
        == "steps.playwright-cache.outputs.cache-hit != 'true'"
    )
    assert "requirements-services.txt" in warm[True]["push"]["paths"]
    assert ".python-version" in warm[True]["push"]["paths"]
    assert "release/stack-lock.json" in warm[True]["push"]["paths"]
    assert "tests/package-lock.json" in warm[True]["push"]["paths"]
    assert ".github/workflows/ci.yml" in warm[True]["push"]["paths"]
    assert "rust/**" not in warm[True]["push"]["paths"]


def test_closed_pull_request_cache_cleanup_uses_reviewed_shared_owner() -> None:
    _, document = _workflow(ROOT / ".github/workflows/cleanup-ci-caches.yml")
    cleanup = document["jobs"]["cleanup"]
    # Runtime queue/reopened/rate-limit cases are owned by the shared action's
    # actions/cleanup-ci-caches/cleanup.test.cjs in ElevenID/.github.
    assert len(cleanup["steps"]) == 1
    step = cleanup["steps"][0]
    assert step["uses"] == (
        "ElevenID/.github/actions/cleanup-ci-caches@"
        "3883ccbf1f612a43a746db1d9321015d561efeb1"
    )
    assert step["with"] == {
        "max-deletions": "2000",
        "include-queue-on-close": "true",
    }
    assert cleanup["permissions"] == {
        "actions": "write", "contents": "read", "pull-requests": "read"
    }
    assert document[True]["pull_request"]["types"] == ["closed"]
    assert document["concurrency"]["cancel-in-progress"] is False


def test_compiler_cache_writes_are_reserved_for_trusted_main() -> None:
    _, ci = _workflow(CI_PATH)
    _, warm = _workflow(ROOT / ".github/workflows/warm-ci-caches.yml")
    for name in ("test-rust-services", "rust-lint-policy"):
        assert ci["jobs"][name]["env"]["SCCACHE_GHA_RW_MODE"] == "READ_ONLY"
    for name, job in warm["jobs"].items():
        assert job["if"] == (
            "vars.PRIVATE_FORKS_ENABLED != 'true' && (github.ref == 'refs/heads/main')"
            if name in {"rust", "images", "public-services"}
            else "github.ref == 'refs/heads/main'"
        )
    for job, mode in (
        (ci["jobs"]["test-rust-service-images"], "READ_ONLY"),
        (warm["jobs"]["images"], "READ_WRITE"),
    ):
        credential_step = next(
            step
            for step in job["steps"]
            if step.get("name", "").startswith("Expose compiler")
        )
        script = credential_step["with"]["script"]
        assert "core.setSecret(token)" in script
        assert f"'SCCACHE_GHA_RW_MODE', '{mode}'" in script
        build = next(
            step for step in job["steps"] if "secret-envs" in step.get("with", {})
        )
        assert "sccache_token=SCCACHE_GHA_RUNTIME_TOKEN" in build["with"]["secret-envs"]
        assert "SCCACHE" not in build["with"].get("build-args", "")
    assert all(
        "cache-to" not in step.get("with", {})
        for step in ci["jobs"]["test-rust-service-images"]["steps"]
    )
    dockerfile = (ROOT / "rust/services/Dockerfile.ci").read_text(encoding="utf-8")
    assert (
        "ADD --checksum=sha256:aec995a83ad3dff3d14b6314e08858b7b73d35ca85a5bcf3d3a9ec07dee35588"
        in dockerfile
    )
    assert "--mount=type=secret,id=sccache_token" in dockerfile
    assert "export RUSTC_WRAPPER=sccache" in dockerfile
    assert "cargo build --locked --release" in dockerfile
    assert "sccache --stop-server" in dockerfile
    assert "ENV SCCACHE_GHA_RUNTIME_TOKEN" not in dockerfile
    assert 'ACTIONS_RESULTS_URL="$(cat /run/secrets/sccache_url)"' in dockerfile
    assert 'ACTIONS_RUNTIME_TOKEN="$(cat /run/secrets/sccache_token)"' in dockerfile
    assert "sccache --start-server && sccache --stop-server" in dockerfile
    assert "FROM compiler_cache AS builder" in dockerfile
    assert dockerfile.count("ACTIONS_CACHE_SERVICE_V2=true") == 3
    assert dockerfile.index("FROM compiler_cache AS builder") < dockerfile.index(
        "cargo chef cook"
    )


def test_required_rust_lanes_use_uncached_compiler_only_when_optional_cache_fails(
    tmp_path: Path,
) -> None:
    git_bash = Path("C:/Program Files/Git/bin/bash.exe")
    bash = (
        str(git_bash)
        if os.name == "nt" and git_bash.is_file()
        else shutil.which("bash")
    )
    if bash is None:
        pytest.skip("Bash workflow behavior requires Bash")
    _, ci = _workflow(CI_PATH)
    steps = ci["jobs"]["rust-lint-policy"]["steps"]
    names = [step.get("name") for step in steps]
    cache = names.index("Enable compiler cache")
    fallback = names.index("Keep Rust lint independent of optional compiler cache")
    lint = names.index("Lint Rust services")
    assert cache < fallback < names.index("Check formatting") < lint
    assert not steps[fallback].get("continue-on-error", False)
    assert steps[fallback]["if"] == "vars.PRIVATE_FORKS_ENABLED != 'true'"
    services = ci["jobs"]["test-rust-services"]
    service_steps = services["steps"]
    service_names = [step.get("name") for step in service_steps]
    service_cache = service_names.index("Enable compiler cache")
    service_fallback = service_names.index(
        "Keep Rust service tests independent of optional compiler cache"
    )
    assert (
        service_cache
        < service_fallback
        < service_names.index("Compile reusable Rust test executables")
    )
    assert not service_steps[service_fallback].get("continue-on-error", False)
    assert service_steps[service_fallback]["if"] == "vars.PRIVATE_FORKS_ENABLED != 'true'"
    expected_wrapper = "${{ vars.PRIVATE_FORKS_ENABLED != 'true' && 'sccache' || '' }}"
    assert services["env"]["RUSTC_WRAPPER"] == expected_wrapper
    assert ci["jobs"]["rust-lint-policy"]["env"]["RUSTC_WRAPPER"] == expected_wrapper
    fallback_command = "bash scripts/ci/optional-sccache-fallback.sh"
    assert (
        steps[fallback]["run"]
        == service_steps[service_fallback]["run"]
        == fallback_command
    )
    assert (
        steps[lint]["run"]
        == "cargo clippy --locked --workspace --all-targets -- -D warnings"
    )
    assert not steps[lint].get("continue-on-error", False)
    assert (
        "cargo test --locked --workspace --no-run"
        in service_steps[service_names.index("Compile reusable Rust test executables")][
            "run"
        ]
    )

    script = ROOT / "scripts/ci/optional-sccache-fallback.sh"
    assert script.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash\n")

    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    fake = fake_bin / "sccache"
    fake.write_text(
        '#!/usr/bin/env bash\nprintf "%s\\n" "$*" > "$PWD/sccache-call"\nexit "$TEST_SCCACHE_EXIT"\n',
        encoding="utf-8",
        newline="\n",
    )
    fake.chmod(0o755)
    rustup = fake_bin / "rustup"
    rustup.write_text(
        '#!/usr/bin/env bash\nprintf "%s\\n" "$*" > "$PWD/rustup-call"\nprintf "%s\\n" rustc-synthetic\n',
        encoding="utf-8",
        newline="\n",
    )
    rustup.chmod(0o755)
    for exit_code, expected_env in (("0", ""), ("17", "RUSTC_WRAPPER=\n")):
        (tmp_path / "github-env").write_text("", encoding="utf-8")
        environment = dict(
            os.environ,
            TEST_SCCACHE_EXIT=exit_code,
            CACHE_FALLBACK_SCRIPT=str(script),
        )
        environment.pop("BASH_ENV", None)
        environment.pop("ENV", None)
        result = subprocess.run(
            [
                bash,
                "--noprofile",
                "--norc",
                "-s",
            ],
            input=(
                'export PATH="$PWD/fake-bin:/usr/bin:/bin"\n'
                'export GITHUB_ENV="$PWD/github-env"\n'
                'bash "$CACHE_FALLBACK_SCRIPT"\n'
            ),
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert (tmp_path / "rustup-call").read_text(encoding="utf-8").strip() == (
            "which rustc --toolchain 1.95.0"
        )
        assert (tmp_path / "sccache-call").read_text(encoding="utf-8").strip() == (
            "rustc-synthetic -vV"
        )
        assert (tmp_path / "github-env").read_text(encoding="utf-8") == expected_env


def test_bookworm_compile_keeps_exact_offline_platform_targets() -> None:
    _, ci = _workflow(CI_PATH)
    steps = {step.get("name"): step for step in ci["jobs"]["test-rust-services"]["steps"]}
    compile_step = steps["Compile reusable Rust test executables"]["run"]
    assert "--network none --read-only" in compile_step
    assert "--locked --offline" in compile_step
    assert 'host_mold="$(command -v mold)"' in compile_step
    assert '"$(realpath "$host_mold")" == /usr/local/bin/mold' in compile_step
    assert "mold 2[.]41[.]0" in compile_step
    assert "--env 'RUSTFLAGS=-C link-arg=-fuse-ld=mold'" in compile_step
    assert '--volume "$host_mold:/usr/local/bin/ld.mold:ro"' in compile_step
    assert "cargo fetch --locked" in compile_step
    assert "pull-pinned-dockerhub-image.sh" in compile_step
    assert "cargo test --locked --offline -p marty-flow-acceptance" in compile_step
    assert "cargo test --locked --offline -p marty-selfhost-acceptance" in compile_step
    assert "--bin marty-issuance-service --message-format=json" in compile_step
    assert "--bin marty-flow --message-format=json" in compile_step
    assert "verify-platform-test-artifacts.py" in compile_step
    for scope in ("flow", "selfhost", "renewal-unit"):
        assert f'--{scope}-only "$artifacts" target' in compile_step
    assert '*) exit 2 ;;' in compile_step
    assert "cargo test --locked --workspace --no-run" in compile_step
    assert steps["Capture host compiler cache counters after compile"]["if"] == (
        "vars.PRIVATE_FORKS_ENABLED != 'true' && (always())"
    )


def test_optional_cache_stats_failure_cannot_fail_required_rust_lanes(
    tmp_path: Path,
) -> None:
    git_bash = Path("C:/Program Files/Git/bin/bash.exe")
    bash = (
        str(git_bash)
        if os.name == "nt" and git_bash.is_file()
        else shutil.which("bash")
    )
    if bash is None:
        pytest.skip("Bash workflow behavior requires Bash")
    _, ci = _workflow(CI_PATH)
    jobs = ci["jobs"]
    scripts = {}
    for job_name in ("test-rust-services", "rust-lint-policy"):
        step_name = (
            "Capture host compiler cache counters after compile"
            if job_name == "test-rust-services"
            else "Report compiler cache effectiveness"
        )
        step = next(
            step for step in jobs[job_name]["steps"] if step.get("name") == step_name
        )
        assert step["if"] == "vars.PRIVATE_FORKS_ENABLED != 'true' && (always())"
        assert not step.get("continue-on-error", False)
        scripts[job_name] = step["run"]
    service_steps = jobs["test-rust-services"]["steps"]
    service_names = [step.get("name") for step in service_steps]
    assert service_names.index(
        "Capture host compiler cache counters after compile"
    ) == (service_names.index("Compile reusable Rust test executables") + 1)
    late_report = service_steps[
        service_names.index("Report compiler cache effectiveness")
    ]["run"]
    assert "sccache --show-stats" not in late_report
    assert "cp rust/target/cargo-timings/cargo-timing.html" in late_report

    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    sccache = fake_bin / "sccache"
    sccache.write_text(
        '#!/usr/bin/env bash\nprintf "stats\\n"\nexit "$TEST_SCCACHE_EXIT"\n',
        encoding="utf-8",
        newline="\n",
    )
    sccache.chmod(0o755)
    python = fake_bin / "python3"
    python.write_text(
        '#!/usr/bin/env bash\ncat >/dev/null\nprintf "{\\"cache\\":true}\\n"\n',
        encoding="utf-8",
        newline="\n",
    )
    python.chmod(0o755)
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    stats_file = runner_temp / "rust-build-evidence" / "sccache-stats.json"
    for exit_code in ("0", "17"):
        for job_name, script in scripts.items():
            stats_file.unlink(missing_ok=True)
            environment = dict(
                os.environ, TEST_SCCACHE_EXIT=exit_code, RUSTC_WRAPPER="sccache"
            )
            environment.pop("BASH_ENV", None)
            environment.pop("ENV", None)
            result = subprocess.run(
                [bash, "--noprofile", "--norc", "-s"],
                input=(
                    'export PATH="$PWD/fake-bin:/usr/bin:/bin"\n'
                    'export RUNNER_TEMP="$PWD/runner-temp"\n' + script
                ),
                cwd=tmp_path,
                env=environment,
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, (job_name, exit_code, result.stderr)
            assert stats_file.exists() == (
                job_name == "test-rust-services" and exit_code == "0"
            )
            if exit_code == "17":
                assert "Optional compiler cache stats unavailable" in result.stdout

    # The late report may copy Cargo timings, but cannot replace the early
    # snapshot with idle-daemon zero counters or an unavailable-cache result.
    stats_file.write_text('{"early":true}\n', encoding="utf-8")
    environment = dict(os.environ, TEST_SCCACHE_EXIT="17", RUSTC_WRAPPER="sccache")
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-s"],
        input='export RUNNER_TEMP="$PWD/runner-temp"\n' + late_report,
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert stats_file.read_text(encoding="utf-8") == '{"early":true}\n'
    stats_file.unlink()
    environment["RUSTC_WRAPPER"] = ""
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-s"],
        input='export RUNNER_TEMP="$PWD/runner-temp"\n' + scripts["test-rust-services"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0 and not stats_file.exists()
    assert "Optional compiler cache unavailable" in result.stdout


def test_release_cache_probe_is_main_only_and_cannot_invalidate_builder() -> None:
    _, warm = _workflow(ROOT / ".github/workflows/warm-ci-caches.yml")
    job = warm["jobs"]["images"]
    assert job["if"] == "vars.PRIVATE_FORKS_ENABLED != 'true' && (github.ref == 'refs/heads/main')"
    probe = next(
        step
        for step in job["steps"]
        if step.get("with", {}).get("target") == "cache_probe"
    )
    assert "continue-on-error" not in probe
    assert "github.run_id" in probe["with"]["build-args"]
    assert "github.run_attempt" in probe["with"]["build-args"]
    dockerfile = (ROOT / "rust/services/Dockerfile.ci").read_text(encoding="utf-8")
    assert "FROM compiler_cache AS cache_probe" in dockerfile
    builder = dockerfile.split("FROM compiler_cache AS builder", 1)[1]
    assert "CACHE_PROBE_NONCE" not in builder
    assert "--from=cache_probe" not in builder
    script = (ROOT / "scripts/ci/verify-release-cache.sh").read_text(encoding="utf-8")
    assert "ACTIONS_CACHE_SERVICE_V2=true" in script
    assert script.index("SCCACHE_GHA_RW_MODE=READ_WRITE") < script.index(
        "SCCACHE_GHA_RW_MODE=READ_ONLY"
    )
    assert script.count("sccache rustc") == 2
    assert script.count("--emit=link,dep-info") == 2
    assert script.count("sccache --stop-server") == 2
    assert "exit !hit" in script


def test_image_context_excludes_integration_tests_but_keeps_build_inputs() -> None:
    ignore = (ROOT / "rust/services/Dockerfile.ci.dockerignore").read_text(
        encoding="utf-8"
    )
    for item in (
        "!rust/**",
        "!proto/**",
        "!contracts/**",
        "!services/entrypoint.sh",
        "!scripts/load-secrets-env.sh",
        "!scripts/ci/verify-release-cache.sh",
        "rust/services/*/tests",
        "rust/crates/*/tests",
        "rust/**/target",
        "rust/**/.env*",
    ):
        assert item in ignore.splitlines()
    # Never drop embedded production contracts or vendored build-script inputs.
    assert "rust/third_party" not in ignore
    assert "contracts/*-oracle.json" not in ignore


@pytest.mark.parametrize(
    "package",
    [
        "services/issuance",
        "crates/service-acceptance",
        "crates/flow-acceptance",
    ],
)
def test_every_issuance_and_acceptance_integration_test_remains_registered(
    package,
) -> None:
    directory = ROOT / "rust" / package
    manifest = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8"))
    assert manifest["package"]["autotests"] is False
    targets = manifest["test"]
    assert len({target["name"] for target in targets}) == len(targets)
    registered = [target["path"] for target in targets]
    harness_path = directory / "tests/behavior_suite.rs"
    harness = harness_path.read_text(encoding="utf-8") if harness_path.exists() else ""
    grouped = re.findall(r'#\[path = "([^"]+)"\]', harness)
    assert set(grouped) == (
        {
            "issued_credential_adapter_behavior.rs",
            "migration_contract.rs",
            "proof_nonce_behavior.rs",
        }
        if package == "services/issuance"
        else set()
    )
    registered.extend(f"tests/{name}" for name in grouped)
    actual = {
        path.relative_to(directory).as_posix()
        for path in (directory / "tests").glob("*.rs")
    }
    assert len(registered) == len(set(registered))
    assert set(registered) == actual, (
        "new test files must be registered, never silently skipped"
    )
    assert all(
        "postgres" not in path and "executable_smoke" not in path for path in grouped
    )


def test_service_acceptance_keeps_composition_dependencies_in_test_targets() -> (
    None
):
    directory = ROOT / "rust/crates/service-acceptance"
    acceptance = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8"))
    issuance = tomllib.loads(
        (ROOT / "rust/services/issuance/Cargo.toml").read_text(encoding="utf-8")
    )
    workspace = tomllib.loads((ROOT / "rust/Cargo.toml").read_text(encoding="utf-8"))
    assert "crates/service-acceptance" in workspace["workspace"]["members"]
    assert {target["name"] for target in acceptance["test"]} == {
        "passport_managed_kms_chain", "passport_gateway_postgres", "gateway_signing_acceptance",
        "csca_capability_contract", "tls_openbao_keyless", "holder_remote_live_kms",
    }
    assert not acceptance.get("dependencies")
    assert not acceptance.get("build-dependencies")
    assert (directory / "src/lib.rs").is_file()  # Survives Docker test exclusions.
    assert acceptance["package"]["publish"] is False
    assert {"marty-issuance-service", "marty-signing-keys"} <= set(
        acceptance["dev-dependencies"]
    )
    _assert_signing_keys_fixture_dependency(
        issuance, workspace["workspace"]["dependencies"], "../signing-keys"
    )


def _dependency_packages(
    manifest: dict, workspace_dependencies: dict, kinds: tuple[str, ...]
) -> set[str]:
    tables = []
    for owner in (manifest, *manifest.get("target", {}).values()):
        tables.extend(owner.get(key, {}) for key in kinds)
    packages = set()
    for dependencies in tables:
        for alias, declaration in dependencies.items():
            package = alias
            if isinstance(declaration, dict):
                inherited = workspace_dependencies.get(alias, {})
                if declaration.get("workspace") and isinstance(inherited, dict):
                    package = inherited.get("package", package)
                package = declaration.get("package", package)
            packages.add(package)
    return packages


def _dev_dependency_packages(
    manifest: dict, workspace_dependencies: dict
) -> set[str]:
    return _dependency_packages(
        manifest, workspace_dependencies, ("dev-dependencies", "dev_dependencies")
    )


def _assert_service_fixture_dependency(
    manifest: dict, workspace_dependencies: dict, dependency: str, path: str
) -> None:
    # Registered composition fixtures must never reach production or build scripts,
    # including renamed, workspace-inherited, or target-specific declarations.
    assert manifest["dev-dependencies"][dependency] == {"path": path}
    assert dependency not in _dependency_packages(
        manifest,
        workspace_dependencies,
        ("dependencies", "build-dependencies", "build_dependencies"),
    )


def _assert_signing_keys_fixture_dependency(
    manifest: dict, workspace_dependencies: dict, path: str
) -> None:
    _assert_service_fixture_dependency(
        manifest, workspace_dependencies, "marty-signing-keys", path
    )


def test_service_dev_dependencies_only_allow_registered_composition_edges() -> (
    None
):
    rust = ROOT / "rust"
    workspace = tomllib.loads((rust / "Cargo.toml").read_text(encoding="utf-8"))
    manifests = sorted((rust / "services").glob("*/Cargo.toml"))
    assert manifests
    documents = {
        path: tomllib.loads(path.read_text(encoding="utf-8")) for path in manifests
    }
    service_packages = {document["package"]["name"] for document in documents.values()}
    workspace_dependencies = workspace["workspace"]["dependencies"]
    edges = {
        (document["package"]["name"], dependency)
        for document in documents.values()
        for dependency in _dev_dependency_packages(document, workspace_dependencies)
        if dependency in service_packages
    }
    # DIDComm exercises the real signing service; the existing issuance_credential
    # PostgreSQL contract exercises template storage and the explicit-profile
    # migration together. Managed evidence needs Policy's private native fixture
    # and real gRPC acquisition through Flow's durable owner repository; keeping
    # that joined test here avoids a public test-only authority constructor.
    # The same fixture now persists the guarded template and exercises native
    # Issuance through an authenticated Flow owner and non-exportable signer.
    assert edges == {
        ("marty-issuance-service", "marty-signing-keys"),
        ("marty-issuance-service", "marty-credential-template"),
        ("marty-presentation-policy", "marty-flow"),
        ("marty-presentation-policy", "marty-credential-template"),
        ("marty-presentation-policy", "marty-issuance-service"),
        ("marty-flow", "marty-presentation-policy"),
        ("marty-flow", "marty-organization"),
        ("marty-gateway", "marty-auth"),
        ("marty-delegated-use", "marty-credential-template"),
        ("marty-delegated-use", "marty-presentation-policy"),
        ("marty-delegated-use", "marty-issuance-service"),
        ("marty-delegated-use", "marty-signing-keys"),
        ("marty-delegated-use", "marty-trust-profile"),
    }, (
        "Only registered DIDComm, explicit-profile, managed-evidence and delegated-use fixtures may add service test edges: "
        f"{sorted(edges)}"
    )
    _assert_service_fixture_dependency(
        documents[rust / "services/flow/Cargo.toml"], workspace_dependencies,
        "marty-presentation-policy", "../presentation-policy",
    )
    # Flow's delegated ingress fixture exercises current Organization-owned
    # machine permissions, including withdrawal during signing and recovery.
    _assert_service_fixture_dependency(
        documents[rust / "services/flow/Cargo.toml"], workspace_dependencies,
        "marty-organization", "../organization",
    )
    # The actual delegated-use host fixtures compose native template/policy
    # reads, fresh issuance, remote signing custody and issuer trust records.
    # Register only these exact test edges; none may enter the serving graph.
    delegated_use = documents[rust / "services/delegated-use/Cargo.toml"]
    for dependency, path in (
        ("marty-credential-template", "../credential-template"),
        ("marty-presentation-policy", "../presentation-policy"),
        ("marty-issuance-service", "../issuance"),
        ("marty-signing-keys", "../signing-keys"),
        ("marty-trust-profile", "../trust-profile"),
    ):
        _assert_service_fixture_dependency(
            delegated_use, workspace_dependencies, dependency, path,
        )
    issuance = documents[rust / "services/issuance/Cargo.toml"]
    _assert_signing_keys_fixture_dependency(
        issuance, workspace_dependencies, "../signing-keys"
    )
    _assert_service_fixture_dependency(
        issuance, workspace_dependencies, "marty-credential-template", "../credential-template"
    )
    _assert_service_fixture_dependency(
        documents[rust / "services/presentation-policy/Cargo.toml"],
        workspace_dependencies, "marty-flow", "../flow",
    )
    _assert_service_fixture_dependency(
        documents[rust / "services/presentation-policy/Cargo.toml"],
        workspace_dependencies, "marty-credential-template", "../credential-template",
    )
    _assert_service_fixture_dependency(
        documents[rust / "services/presentation-policy/Cargo.toml"],
        workspace_dependencies, "marty-issuance-service", "../issuance",
    )

    # The Gateway own-session guard is qualified against the actual Auth gRPC
    # service. Its test dependency must not become production coupling.
    _assert_service_fixture_dependency(
        documents[rust / "services/gateway/Cargo.toml"],
        workspace_dependencies, "marty-auth", "../auth",
    )


def test_service_dev_edge_guard_resolves_aliases_and_target_specific_deps() -> None:
    manifest = {
        "dev-dependencies": {
            "gateway_alias": {"package": "marty-gateway", "path": "../gateway"},
            "inherited_alias": {"workspace": True},
        },
        "dev_dependencies": {
            "signing_alias": {"package": "marty-signing-keys", "path": "../signing-keys"}
        },
        "target": {
            "cfg(unix)": {
                "dev-dependencies": {
                    "flow_alias": {"package": "marty-flow", "path": "../flow"}
                },
                "dev_dependencies": {
                    "issuance_alias": {
                        "package": "marty-issuance-service",
                        "path": "../issuance",
                    }
                }
            }
        },
    }
    workspace_dependencies = {
        "inherited_alias": {"package": "marty-auth", "path": "services/auth"}
    }
    assert _dev_dependency_packages(manifest, workspace_dependencies) == {
        "marty-gateway",
        "marty-auth",
        "marty-flow",
        "marty-signing-keys",
        "marty-issuance-service",
    }


@pytest.mark.parametrize("kind", ["dependencies", "build-dependencies", "build_dependencies"])
@pytest.mark.parametrize("target_specific", [False, True])
@pytest.mark.parametrize("dependency,path", [
    ("marty-signing-keys", "../signing-keys"),
    ("marty-credential-template", "../credential-template"),
    ("marty-flow", "../flow"),
    ("marty-auth", "../auth"),
    ("marty-issuance-service", "../issuance"),
    ("marty-presentation-policy", "../presentation-policy"),
    ("marty-trust-profile", "../trust-profile"),
    ("marty-organization", "../organization"),
])
def test_service_fixture_dependencies_reject_production_edges(
    kind: str, target_specific: bool, dependency: str, path: str
) -> None:
    manifest = {
        "dev-dependencies": {dependency: {"path": path}}
    }
    owner = manifest
    if target_specific:
        owner = manifest.setdefault("target", {}).setdefault("cfg(unix)", {})
    owner[kind] = {"renamed_service": {"workspace": True}}
    workspace_dependencies = {
        "renamed_service": {
            "package": dependency, "path": f"services/{path.removeprefix('../')}"
        }
    }
    with pytest.raises(AssertionError):
        _assert_service_fixture_dependency(
            manifest, workspace_dependencies, dependency, path
        )


def test_passport_webhook_boundary_has_one_acceptance_owner_and_a_real_db_gate() -> (
    None
):
    acceptance = tomllib.loads(
        (ROOT / "rust/crates/service-acceptance/Cargo.toml").read_text(encoding="utf-8")
    )
    gateway = tomllib.loads(
        (ROOT / "rust/services/gateway/Cargo.toml").read_text(encoding="utf-8")
    )
    assert "marty-issuance-service" not in gateway["dev-dependencies"]
    assert (
        sum(
            target["name"] == "passport_gateway_postgres"
            and target["path"] == "tests/passport_gateway_postgres.rs"
            for target in acceptance["test"]
        )
        == 1
    )
    _, workflow = _workflow(ROOT / ".github/workflows/ci.yml")
    contracts = workflow["jobs"]["test-rust-services"]["steps"]
    gate = next(
        step
        for step in contracts
        if step.get("name")
        == "Test native passport Gateway signed webhook on PostgreSQL"
    )
    names = [step.get("name") for step in contracts]
    assert names.count(gate["name"]) == 1
    assert (
        names.index("Create isolated Rust contract databases")
        < names.index(gate["name"])
        < names.index("Run safe Rust contract groups concurrently")
    )
    create = next(
        step
        for step in contracts
        if step.get("name") == "Create isolated Rust contract databases"
    )
    assert "marty_passport_gateway_test" in create["run"]
    assert gate["if"] == "matrix.lane == 'contracts'"
    assert gate["env"]["MARTY_PASSPORT_GATEWAY_TEST_URL"].endswith(
        "/marty_passport_gateway_test"
    )
    assert "--test passport_gateway_postgres" in gate["run"]
    assert "-- --exact" in gate["run"]
    source = (
        ROOT / "rust/crates/service-acceptance/tests/passport_gateway_postgres.rs"
    ).read_text(encoding="utf-8")
    assert '"marty_passport_gateway_test"' in source
    assert 'sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")' in source
    assert "migration::migrate_passport(&pool).await.unwrap();" in source


@pytest.mark.parametrize(
    "scenario", ["valid", "empty", "negative", "huge", "traversal", "malformed"]
)
def test_reviewed_timing_adoption_validates_data_and_preserves_tests(
    tmp_path: Path, scenario: str
) -> None:
    paths = sorted(
        path.relative_to(ROOT / "ui").as_posix()
        for path in (ROOT / "ui/src").rglob("*")
        if path.is_file() and re.search(r"\.(test|spec)\.(ts|tsx)$", path.name)
    )
    plan = {"defaultMilliseconds": 500, "tests": {paths[0]: 123}}
    if scenario == "empty":
        plan["tests"] = {}
    elif scenario in {"negative", "huge"}:
        plan["tests"][paths[0]] = -1 if scenario == "negative" else 3_600_001
    elif scenario == "traversal":
        plan["tests"]["src/../../outside.test.ts"] = 1
    source = tmp_path / "observations.json"
    source.write_text(
        "not JSON" if scenario == "malformed" else json.dumps(plan), encoding="utf-8"
    )
    output = tmp_path / "review.json"
    result = subprocess.run(
        [
            "node",
            str(ROOT / "ui/scripts/adopt-vitest-timings.mjs"),
            str(source),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    if scenario != "valid":
        assert result.returncode != 0
        assert not output.exists()
    else:
        assert result.returncode == 0, result.stderr
        adopted = json.loads(output.read_text(encoding="utf-8"))
        assert set(adopted["tests"]) == set(paths)
        assert adopted["tests"][paths[0]] == 123


def test_native_kms_schema_acceptance_is_mandatory_in_contracts_lane() -> None:
    _, ci = _workflow(CI_PATH)
    steps = ci["jobs"]["test-rust-services"]["steps"]
    gate = next(step for step in steps if step.get("name") ==
                "Prove native migration and profile KMS custody on fresh databases")
    assert gate["if"] == "matrix.lane == 'contracts'"
    assert not gate.get("continue-on-error", False)
    run = gate["run"]
    assert "set -euo pipefail" in run
    assert "resolve_recorded_contract_executable marty-selfhost-acceptance native_kms_schema_contract" in run
    assert "native_owners_preserve_kms_only_custody --ignored --exact --nocapture" in run
    for name in ("AUTH_CONTRACT", "ORGANIZATION_CONTRACT", "CREDENTIAL_TEMPLATE_CONTRACT",
                 "PRESENTATION_POLICY_CONTRACT", "FLOW_CONTRACT", "VERIFICATION_BINARY",
                 "DEPLOYMENT_BINARY", "COMPLIANCE_BINARY"):
        assert "MARTY_KMS_" + name + "=" in run
        assert "export MARTY_KMS_" + name in run
    assert "|| true" not in run
    workflow = CI_PATH.read_text(encoding="utf-8")
    assert "cargo build --locked -p marty-deployment-profile -p marty-compliance-profile -p marty-verification-service --bins --message-format=json" in workflow


def test_native_kms_audit_changes_keep_contracts_ci_selected(tmp_path: Path) -> None:
    selected = _classify_changed_paths(
        ["rust/crates/selfhost-acceptance/tests/native_kms_schema_contract.rs"],
        tmp_path, include_rust_plan=True)[0]
    assert selected["rust"] == "true"
    assert "contracts" in json.loads(selected["rust_matrix"])


def test_registry_source_render_uses_pinned_renderer_without_changing_docker_plugin() -> None:
    _, ci = _workflow(CI_PATH)
    steps = ci["jobs"]["test-release-contracts"]["steps"]
    prepare = next(step for step in steps if step.get("name") == "Prepare source-only deployment registry renderer")
    release = next(step for step in steps if step.get("name") == "Run repository release checks")
    assert steps.index(prepare) < steps.index(release)
    assert prepare["if"] == release["if"]
    assert prepare["run"] == "bash scripts/ci/install-compose-renderer.sh"
    assert release["env"]["MARTY_COMPOSE_RENDERER"] == "${{ runner.temp }}/compose-render-v5.4.0"
    assert release["run"] == RELEASE_TEST_COMMAND
    assert not prepare.get("continue-on-error", False)


def test_retired_shadow_planner_paths_cannot_bypass_full_validation(tmp_path: Path) -> None:
    # Deleted source paths and any later reintroduction use conservative CI.
    for path in ("scripts/ci/plan_affected_rust.py", "tests/test_plan_affected_rust.py"):
        for event in ("pull_request", "merge_group"):
            selected = _classify_changed_paths([path], tmp_path, event=event)[0]
            assert selected["all"] == selected["rust"] == selected["release"] == "true"
    _, workflow = _workflow(CI_PATH)
    assert "planner_only" not in workflow["jobs"]["changes"]["outputs"]
    assert not any("shadow mode" in step.get("name", "")
                   for step in workflow["jobs"]["test-release-contracts"]["steps"])


def test_managed_policy_evidence_ci_requires_real_positive_fixture_execution() -> None:
    _, document = _workflow(CI_PATH)
    steps = document["jobs"]["test-rust-services"]["steps"]
    named = {step.get("name"): step for step in steps}
    name = "Exercise managed Policy evidence through Flow PostgreSQL commit"
    step = named[name]
    assert step["if"] == "matrix.lane == 'contracts'"
    assert not step.get("continue-on-error", False)
    assert steps.index(named["Run Flow database contract after workspace suite"]) < steps.index(step)
    assert step["env"]["FLOW_POSTGRES_TEST_URL"].endswith("/marty_atomic_test")
    run = step["run"]
    assert '"#marty-presentation-policy@"' in run
    assert 'select(.target.kind | index("lib"))' in run
    assert 'select(.profile.test == true)' in run
    assert '"$RUNNER_TEMP/rust-test-artifacts.json"' in run
    assert 'live_keyless_managed_policy_evidence' in run
    assert 'resolve_recorded_contract_executable marty-presentation-policy control_plane_behavior' in run
    assert 'managed_authority_http::live_keyless_managed_owner_channels' in run
    assert run.count('--ignored --exact --list') == 2
    assert run.count('--ignored --exact --nocapture') == 2
    assert run.count('1 passed; 0 failed; 0 ignored;') == 2
    assert run.count('with_disposable_policy_owner_kms.py') == 2
    image = re.search(r'image=(quay\.io/openbao/openbao@sha256:[a-f0-9]{64})', run).group(1)
    assert image.split('@')[1] in (ROOT / 'openbao/didcomm-authcrypt/Dockerfile').read_text()
    assert '028992583c693c4de6350b8aa52ff85e30375a99' in run


def test_platform_acceptance_runners_require_complete_executed_rosters() -> None:
    _, workflow = _workflow(CI_PATH)
    step = next(step for step in workflow["jobs"]["test-rust-services"]["steps"]
                if step.get("name") == "Run isolated database contract suites concurrently")
    assert step["if"] == "matrix.lane != 'renewal-unit'"
    assert not step.get("continue-on-error", False)
    for owner, count in (("flow", 18), ("selfhost", 17)):
        script = f"run-{owner}-acceptance-contracts.sh"
        assert f"bash ../scripts/ci/{script}" in step["run"]
        runner = (ROOT / "scripts/ci" / script).read_text(encoding="utf-8")
        assert "set -euo pipefail" in runner
        assert f"{count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;" in runner
        assert "rust_db_obligations.py" in runner
    inventory = (ROOT / "scripts/ci/list-flow-acceptance-cases.sh").read_text(encoding="utf-8")
    assert "exact eighteen-case owner inventory" in inventory
    assert 'flow_tests=$("$1" --list)' in inventory
    for case in ("platform_fixture_uses_current_owned_schema_without_provider_objects",
                 "managed_http_provider_tls::native_flow_clients_use_only_selected_ca_and_verify_hostnames",
                 "managed_http_provider_tls::selected_ca_cannot_enable_plaintext_or_accept_key_material",
                 "didcomm_http_admission_recovers_real_keyed_reservation",
                 "didcomm_flow_grpc_provider_preserves_keyed_admission"):
        assert f"{case}: test" in inventory
