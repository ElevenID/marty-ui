from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomllib
import yaml

ROOT = Path(__file__).parents[1]
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"


def test_selfhost_operator_guide_is_a_packaged_input() -> None:
    manifest = json.loads(
        (ROOT / "deploy-config" / "bundles" / "selfhost.json").read_text(
            encoding="utf-8"
        )
    )
    assert "SELFHOST_BUNDLE.md" in manifest["assets"]
    assert (ROOT / "SELFHOST_BUNDLE.md").is_file()


def test_worker_fixture_integrity_and_process_containment_have_linux_ci_dependencies():
    job = yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))["jobs"][
        "test-release-contracts"
    ]
    assert job["runs-on"] == "ubuntu-latest"
    steps = {step.get("name"): step for step in job["steps"]}
    installation = steps["Install released test dependencies"]["run"]
    command = next(
        line
        for line in installation.splitlines()
        if "uv pip install --system pytest" in line
    )
    assert {"pytest", "sqlalchemy"} <= set(command.split())
    assert (
        steps["Run repository release checks"]["run"]
        == "python -m pytest tests -v --tb=short"
    )


def test_canvas_native_oracle_decodes_artifacts_and_child_output_as_utf8() -> None:
    source = (ROOT / "scripts/run_canvas_timeout_consumer_oracle.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    native = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_native"
    )
    reads = [
        node
        for node in ast.walk(native)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "read_text"
    ]
    children = [
        node
        for node in ast.walk(native)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
    ]
    assert len(reads) == 2 and len(children) == 1
    for call in reads + children:
        assert any(
            keyword.arg == "encoding"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value == "utf-8"
            for keyword in call.keywords
        )


def test_canvas_native_oracle_preserves_unicode_line_separators(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = (ROOT / "scripts/run_canvas_timeout_consumer_oracle.py").read_text(
        encoding="utf-8"
    )
    native = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "run_native"
    )
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    case = {"name": "synthetic_unicode_record"}
    observation = {
        "name": case["name"],
        "status": 403,
        "body": {"body_excerpt": "NEL\u0085LINE\u2028PARA\u2029"},
    }
    (contracts / "canvas-timeout-consumer-scenarios.json").write_text(
        json.dumps({"cases": [case]}), encoding="utf-8"
    )
    (contracts / "canvas-timeout-consumer-oracle.json").write_text(
        json.dumps({"cases": [observation]}, ensure_ascii=False), encoding="utf-8"
    )
    child = SimpleNamespace(
        returncode=0,
        stderr="",
        stdout="CANVAS_TIMEOUT_NATIVE="
        + json.dumps(observation, ensure_ascii=False)
        + "\n",
    )
    namespace = {
        "__file__": str(tmp_path / "scripts" / "oracle.py"),
        "Path": Path,
        "json": json,
        "os": SimpleNamespace(environ={}),
        "FROZEN_NATIVE_CASE_COUNT": 1,
        "ROUTINE_NATIVE_CASES": frozenset({case["name"]}),
        "subprocess": SimpleNamespace(run=lambda *args, **kwargs: child),
        "loopback_tls": lambda: nullcontext(
            ("https://127.0.0.1:1", None, tmp_path / "synthetic.pem")
        ),
    }
    exec(
        compile(
            ast.Module(body=[native], type_ignores=[]), "<owned-native-oracle>", "exec"
        ),
        namespace,
    )
    namespace["run_native"](tmp_path / "never-executed")
    assert json.loads(capsys.readouterr().out) == {
        "native_timeout_cases": 1,
        "status": "passed",
    }


@pytest.mark.parametrize("qualification,expected_count", [("0", 2), ("1", 104)])
def test_canvas_native_timeout_tiers_preserve_exact_frozen_observations(
    qualification: str,
    expected_count: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = (ROOT / "scripts/run_canvas_timeout_consumer_oracle.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    native = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_native"
    )
    routine_assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "ROUTINE_NATIVE_CASES"
            for target in node.targets
        )
    )
    assert isinstance(routine_assignment.value, ast.Call)
    routine_names = frozenset(ast.literal_eval(routine_assignment.value.args[0]))
    assert routine_names == {"body_timeout", "untrusted_certificate"}
    cases = json.loads(
        (ROOT / "contracts/canvas-timeout-consumer-scenarios.json").read_text(
            encoding="utf-8"
        )
    )["cases"]
    expected = json.loads(
        (ROOT / "contracts/canvas-timeout-consumer-oracle.json").read_text(
            encoding="utf-8"
        )
    )["cases"]
    by_name = dict(zip((case["name"] for case in cases), expected, strict=True))
    seen: list[str] = []

    def child(*_args, env, **_kwargs):
        name = json.loads(env["MARTY_CANVAS_TIMEOUT_NATIVE_CASE"])["name"]
        seen.append(name)
        return SimpleNamespace(
            returncode=0,
            stderr="",
            stdout="CANVAS_TIMEOUT_NATIVE=" + json.dumps(by_name[name]) + "\n",
        )

    namespace = {
        "__file__": str(ROOT / "scripts/run_canvas_timeout_consumer_oracle.py"),
        "Path": Path,
        "json": json,
        "os": SimpleNamespace(environ={}),
        "subprocess": SimpleNamespace(run=child),
        "loopback_tls": lambda: nullcontext(("https://127.0.0.1:1", None, Path("synthetic.pem"))),
        "ROUTINE_NATIVE_CASES": routine_names,
        "FROZEN_NATIVE_CASE_COUNT": 104,
    }
    exec(compile(ast.Module(body=[native], type_ignores=[]), "<native-tier>", "exec"), namespace)
    namespace["run_native"](Path("unused"), qualification)
    assert len(seen) == expected_count
    assert seen == (
        [case["name"] for case in cases]
        if qualification == "1"
        else ["body_timeout", "untrusted_certificate"]
    )
    assert json.loads(capsys.readouterr().out) == {
        "native_timeout_cases": expected_count,
        "status": "passed",
    }


def _workflow(path: Path) -> tuple[str, dict[str, object]]:
    source = path.read_text(encoding="utf-8")
    return source, yaml.safe_load(source)


def test_off_path_ci_qualifies_full_canvas_without_weakening_pr_gates() -> None:
    source, document = _workflow(CI_PATH)
    assert "  workflow_dispatch:\n" in source
    assert document[True]["schedule"] == [{"cron": "17 4 * * 0"}]
    assert document["env"]["MARTY_CANVAS_FULL_QUALIFICATION"] == (
        "${{ (github.event_name == 'workflow_dispatch' || github.event_name == 'schedule') && '1' || '0' }}"
    )
    classifier = next(
        step
        for step in document["jobs"]["changes"]["steps"]
        if step.get("id") == "classify"
    )
    assert 'elif [[ -z "$BASE_SHA" ]]; then\n  all=true' in classifier["run"]
    assert (
        "github.event.pull_request.base.sha || github.event.merge_group.base_sha || ''"
        in (classifier["env"]["BASE_SHA"])
    )
    rust_steps = document["jobs"]["test-rust-services"]["steps"]
    assert any(
        step.get("run") == "python3 ../scripts/ci/run-db-contract-groups.py preflights"
        for step in rust_steps
    )


def _assert_python_service_job_preserves_full_suite(document) -> None:
    job = document["jobs"]["test-services"]
    assert job["needs"] == "changes"
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
    assert set(rust["services"]) == {"postgres", "redis", "openbao"}
    for service, port in (("postgres", 5432), ("redis", 6379)):
        fixture = rust["services"][service]
        assert fixture["image"].startswith(f"{service}:")
        assert "@sha256:" in fixture["image"]
        assert fixture["ports"] == [f"{port}:{port}"]
        assert "--health-cmd" in fixture["options"]
    openbao = rust["services"]["openbao"]
    assert openbao["image"].startswith("quay.io/openbao/openbao@sha256:")
    assert openbao["ports"] == ["8200:8200"]
    assert openbao["env"] == {
        "BAO_DEV_ROOT_TOKEN_ID": "test-only",
        "BAO_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
    }
    chain_step_name = (
        "Exercise Gateway CSR and managed passport chain with disposable OpenBao"
    )
    managed_chain = next(
        step for step in rust["steps"] if step.get("name") == chain_step_name
    )["run"]
    assert "--test passport_managed_kms_chain" in managed_chain
    assert (
        "-p marty-service-acceptance --test passport_managed_kms_chain" in managed_chain
    )
    assert '-- --list | grep -Fx "$chain_test: test"' in managed_chain
    assert '"$chain_test" -- --ignored --exact' in managed_chain
    chain_test_name = (
        "managed_passport_chain_issues_and_verifies_sod_without_exporting_private_keys"
    )
    assert chain_test_name in managed_chain
    assert (
        "test_name='authenticated_gateway_issues_dsc_with_operator_grant_and_dedicated_key'"
        in managed_chain
    )
    assert (
        managed_chain.count(
            "-p marty-service-acceptance --test gateway_signing_acceptance"
        )
        == 4
    )
    for case in (
        "authenticated_gateway_generates_profile_scoped_passport_csrs_in_openbao",
        "authenticated_gateway_generates_a_dedicated_service_csr_in_openbao",
        "authenticated_gateway_issues_dsc_with_operator_grant_and_dedicated_key",
    ):
        assert case in managed_chain
    assert '-- --list | grep -Fx "$test_name: test"' in managed_chain
    assert '"$test_name" -- --ignored --exact' in managed_chain
    assert "-- --ignored --exact" in managed_chain
    signing_routes = next(
        step["run"]
        for step in rust["steps"]
        if step.get("name")
        == "Exercise authenticated Signing Keys Gateway to Rust routes"
    )
    assert (
        signing_routes.count(
            "-p marty-service-acceptance --test gateway_signing_acceptance"
        )
        == 3
    )
    for case in (
        "authenticated_gateway_reaches_remaining_rust_signing_handlers",
        "authenticated_gateway_reaches_rust_managed_key_route_without_custody",
        "authenticated_gateway_rotates_only_a_dedicated_signing_service",
    ):
        assert case in signing_routes
    assert signing_routes.count("-- --ignored --exact") == 3
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
    names = re.findall(r"authenticated_gateway_[a-z_]+", names_source)
    rust_source = (
        ROOT / "rust/crates/service-acceptance/tests/gateway_signing_acceptance.rs"
    ).read_text(encoding="utf-8")
    actual = re.findall(r"(?m)^async fn (authenticated_gateway_[a-z_]+)\(", rust_source)
    assert len(names) == len(set(names)) == 6
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


def test_python_service_job_retires_only_unused_fixture_provisioning() -> None:
    _assert_python_service_job_preserves_full_suite(_workflow(CI_PATH)[1])


def _classify_changed_paths(
    changed_paths: list[str],
    tmp_path: Path,
    *,
    combined: bool = False,
    event: str = "pull_request",
    include_rust_plan: bool = False,
    include_planner_plan: bool = False,
    include_rollback_plan: bool = False,
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
    assert event in {"pull_request", "merge_group", "push"}
    script = classifier["run"].replace("${{ github.event_name }}", event)
    assert "${{" not in script
    # Run the actual Bash classifier, not a Python copy of its path patterns.
    # Git is a shell-local synthetic owner, so neither fetch nor diff touches a
    # repository or network. Results go to an owned synthetic output file, not
    # the real Actions output file (/dev/stdout is unavailable in Git Bash).
    prelude = """
git() {
  case "$1" in
    fetch) return 0 ;;
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
export BASE_SHA=synthetic-base
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
        prelude = prelude[:start] + "python3() { return 43; }" + prelude[end:]
    if fetch_failure:
        prelude = prelude.replace("fetch) return 0 ;;", "fetch) return 44 ;;")
    if missing_base:
        prelude = prelude.replace("export BASE_SHA=synthetic-base", "export BASE_SHA=''")
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
        timeout=30,
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
                (include_rust_plan or key not in {"rust_runtime", "rust_matrix"})
                and (include_planner_plan or key != "planner_only")
                and (include_rollback_plan or key != "rollback_test_only")
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
    assert checkout["if"] == (
        "github.event_name == 'pull_request' || github.event_name == 'merge_group'"
    )
    assert checkout["with"]["persist-credentials"] is False
    for path, candidate in (
        ("contracts/canvas-json-depth-scenarios.json", "true"),
        ("scripts/run_canvas_json_depth_oracle.py", "true"),
        ("rust/services/issuance/migrations/20260101.sql", "true"),
        ("rust/services/issuance/src/canvas_operation_http.rs", "false"),
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
            "contracts/canvas-json-depth-scenarios.json",
            "rust/services/issuance/src/canvas_operation_http.rs",
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
    unavailable = _classify_changed_paths(
        ["contracts/canvas-json-depth-scenarios.json"],
        tmp_path,
        event="merge_group",
        include_shadow=True,
        fetch_failure=True,
    )[0]
    observed = json.loads(unavailable.pop("historical_shadow"))
    assert set(unavailable.values()) == {"true"}
    assert observed == {
        "event": "merge_group",
        "diff": "unavailable",
        "path_count": 0,
        "candidate": "unknown",
        "authority": "shadow-only",
    }
    absent_base = _classify_changed_paths(
        ["contracts/canvas-json-depth-scenarios.json"],
        tmp_path,
        event="merge_group",
        include_shadow=True,
        missing_base=True,
    )[0]
    assert json.loads(absent_base.pop("historical_shadow")) == observed
    assert set(absent_base.values()) == {"true"}


def test_verified_rust_test_leaves_select_only_contracts_not_runtime(
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
    assert verified[-1] == b"" and len(verified) == 13
    leaves = [value.decode("utf-8") for value in verified[:-1]]
    assert leaves[-2:] == [
        "rust/crates/oid4vp-contract/tests/contract_vectors.rs",
        "rust/crates/oid4vp-contract/tests/transport_metadata.rs",
    ]
    nested = (
        "rust/services/issuance/src/initiation_didcomm/tests/"
        "initiation_didcomm_renewal_tests.rs"
    )
    assert nested in leaves
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
            "rust_matrix": '["contracts"]',
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

    mixed = _classify_changed_paths(
        [leaves[0], "rust/services/issuance/src/lib.rs"],
        tmp_path,
        combined=True,
        include_rust_plan=True,
    )[0]
    assert mixed["rust_runtime"] == "true"
    assert mixed["rust_matrix"] == '["canvas","contracts"]'
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
        assert selected["rust_matrix"] == '["canvas","contracts"]'
    # A deleted leaf cannot pass the source-ownership proof in the checkout.
    deleted = _classify_changed_paths(
        [leaves[0]], tmp_path, include_rust_plan=True, proof_failure=True
    )[0]
    assert deleted["rust_runtime"] == "true"
    assert deleted["rust_matrix"] == '["canvas","contracts"]'
    nested_without_proof = _classify_changed_paths(
        [nested], tmp_path, include_rust_plan=True, proof_failure=True
    )[0]
    assert nested_without_proof["rust_runtime"] == "true"
    assert nested_without_proof["rust_matrix"] == '["canvas","contracts"]'
    oid_without_proof = _classify_changed_paths(
        [leaves[-1]], tmp_path, include_rust_plan=True, proof_failure=True
    )[0]
    assert oid_without_proof["rust_runtime"] == "true"
    assert oid_without_proof["rust_matrix"] == '["canvas","contracts"]'
    oid_deleted = _classify_changed_paths(
        [leaves[-2]], tmp_path, include_rust_plan=True, proof_failure=True
    )[0]
    assert oid_deleted["rust_runtime"] == "true"
    assert oid_deleted["rust_matrix"] == '["canvas","contracts"]'
    empty = _classify_changed_paths(
        [], tmp_path, combined=True, include_rust_plan=True
    )[0]
    assert empty["rust"] == empty["rust_runtime"] == "false"
    assert empty["rust_matrix"] == '["canvas","contracts"]'
    queued = _classify_changed_paths(
        [leaves[0]], tmp_path, event="merge_group", include_rust_plan=True
    )[0]
    assert queued["all"] == queued["rust_runtime"] == "true"
    assert queued["rust_matrix"] == '["canvas","contracts"]'
    on_main = _classify_changed_paths(
        [leaves[-1]], tmp_path, event="push", include_rust_plan=True
    )[0]
    assert on_main["rust_runtime"] == "true"
    assert on_main["rust_matrix"] == '["canvas","contracts"]'


def test_generated_beta_image_inputs_retain_runtime_and_canvas_matrix(
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
        assert selected["rust_matrix"] == '["canvas","contracts"]', path
    queued = _classify_changed_paths(
        ["rust/services/issuance/src/lib.rs"],
        tmp_path,
        event="merge_group",
        include_rust_plan=True,
    )[0]
    assert queued["all"] == queued["rust_runtime"] == "true"
    assert queued["rust_matrix"] == '["canvas","contracts"]'


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
        del document["jobs"]["test-rust-services"]["services"][
            mutation.removeprefix("drop-rust-")
        ]
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
        "python",
        "rust",
        "rust_runtime",
        "rust_matrix",
        "planner_only",
        "rollback_test_only",
        "release",
        "verification",
        "security",
    }
    assert 'if [[ "${{ github.event_name }}" == merge_group ]]' in source
    assert "Unknown paths deliberately receive the complete suite." in source

    conditional_jobs = {
        "fast-feedback",
        "test-ui",
        "test-ui-crawler-artifacts",
        "test-ui-crawler-nginx",
        "test-services",
        "test-passport-fence-postgres",
        "test-rust-feature-probe",
        "test-rust-passport-image",
        "test-rust-services",
        "rust-lint-policy",
        "test-rust-service-images",
        "public-protocol-contract",
        "test-release-contracts",
        "test-credential-lifecycle-browser",
        "security",
        "rust-supply-chain",
    }
    for name in conditional_jobs:
        assert jobs[name]["needs"] == "changes"
        assert jobs[name]["if"]

    gate_needs = set(jobs["ci-gate"]["needs"])
    assert gate_needs == conditional_jobs | {"changes", "lint"}
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
            "rust-lint-policy",
            "rust-supply-chain",
        },
        "rust_runtime": {
            "test-passport-fence-postgres",
            "test-rust-feature-probe",
            "test-rust-passport-image",
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
        "public-protocol-contract",
        "test-release-contracts",
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
        "UI_SELECTED": "ui",
        "PYTHON_SELECTED": "python",
        "RUST_SELECTED": "rust",
        "RUST_RUNTIME_SELECTED": "rust_runtime",
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
    ):
        selected = set(flags)
        if "rust" in selected and not leaf_only:
            selected.add("rust_runtime")
        active = {"changes", "lint"}
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
        environment.setdefault("ROLLBACK_TEST_ONLY", "false")
        environment["RUST_MATRIX"] = (
            '["contracts"]' if leaf_only else '["canvas","contracts"]'
        )
        environment.update(selection_overrides or {})
        environment.update({key: results[name] for name, key in result_env.items()})
        values = [results[name] for name in gate["needs"]]
        environment["CI_LANE_RESULTS"] = " ".join(values[:result_count])
        assert len(environment["CI_LANE_RESULTS"].split()) == (result_count or 18)
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
        ("python", "security"),
        ("release",),
        ("release", "verification"),
        tuple(selections.values()),
    ):
        result = exercise(flags)
        assert result.returncode == 0, (flags, result.stdout, result.stderr)
    assert exercise(("rust",), {"test-rust-services": "skipped"}).returncode != 0
    assert exercise(("rust",), leaf_only=True).returncode == 0
    assert (
        exercise(
            ("rust",),
            leaf_only=True,
            selection_overrides={"RUST_MATRIX": '["canvas","contracts"]'},
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
            ("rust",), selection_overrides={"RUST_MATRIX": '["contracts","canvas"]'}
        ).returncode
        != 0
    )
    assert exercise((), {"test-rust-services": "success"}).returncode != 0
    assert exercise(("ui",), {"fast-feedback": "failure"}).returncode != 0
    assert exercise((), {"changes": "failure"}).returncode != 0
    assert exercise((), selection_overrides={"RUST_SELECTED": ""}).returncode != 0
    assert exercise((), result_count=17).returncode != 0
    assert exercise(tuple(selections.values()), event="merge_group").returncode == 0
    assert (
        exercise(
            ("release", "security"),
            selection_overrides={"ROLLBACK_TEST_ONLY": "true"},
        ).returncode
        == 0
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
        "Summarize CI performance",
    ]
    required, telemetry = gate["steps"]
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
    passport = jobs["test-rust-passport-image"]
    assert probe["needs"] == passport["needs"] == "changes"
    assert (
        probe["if"] == passport["if"] == "needs.changes.outputs.rust_runtime == 'true'"
    )
    assert jobs["test-rust-services"]["if"] == "needs.changes.outputs.rust == 'true'"
    assert {"test-rust-feature-probe", "test-rust-passport-image"} <= set(
        jobs["ci-gate"]["needs"]
    )
    assert "Verify frozen Rust feature-regression probe" not in service_names
    assert "Build opt-in passport test-mode image" not in service_names
    assert "Verify opt-in passport test-mode image boundary" not in service_names
    assert {step.get("name") for step in probe["steps"]} >= {
        "Verify frozen Rust feature-regression probe"
    }
    passport_names = [step.get("name") for step in passport["steps"]]
    assert passport_names.index(
        "Build opt-in passport test-mode image"
    ) < passport_names.index("Verify opt-in passport test-mode image boundary")
    assert "Build public selfhost image" in service_names
    for job in (probe, passport):
        assert not any(
            step.get("uses", "").startswith("actions/download-artifact@")
            for step in job["steps"]
        )


def test_rust_matrix_keeps_canvas_state_local_and_contracts_parallel() -> None:
    _, document = _workflow(CI_PATH)
    job = document["jobs"]["test-rust-services"]
    assert job["strategy"] == {
        "fail-fast": False,
        "matrix": {"lane": "${{ fromJSON(needs.changes.outputs.rust_matrix) }}"},
    }
    steps = {step.get("name"): step for step in job["steps"] if step.get("name")}
    canvas = {
        "Prepare isolated Canvas worker harness dependencies",
        "Require Kubernetes deployment contract executables",
        "Fail fast on image-free Canvas renewal configuration",
        "Compile Bookworm-compatible base runtime acceptance",
        "Test native Canvas AGS/NRPS over real HTTPS",
        "Test Canvas publication adapter over real HTTPS",
        "Prepare required rendered base executable acceptance",
        "Expose public image compiler cache credentials",
        "Build public selfhost image",
        "Prepare public selfhost image loader acceptance",
        "Verify default passport test-mode boundary",
        "Preflight published worker parity in two isolated groups",
        "Prepare owned runtime failure diagnostics",
        "Test native Canvas operation timeout TLS parity",
    }
    contracts = {
        "Prepare pinned standalone Compose renderer for Rust contracts",
        "Verify feature-regression observer isolation",
        "Prepare database contract executables",
        "Create isolated Rust contract databases",
        "Run safe Rust contract groups concurrently",
        "Exercise authenticated Signing Keys Gateway to Rust routes",
        "Exercise live Signing Keys public contracts on disposable Redis",
        "Exercise Gateway CSR and managed passport chain with disposable OpenBao",
        "Run Flow database contract after workspace suite",
        "Test packaged passport self-signed mode",
        "Test beta passport reconciliation and native batch on PostgreSQL",
        "Test native passport Gateway signed webhook on PostgreSQL",
    }
    for name in canvas:
        assert steps[name]["if"] == "matrix.lane == 'canvas'"
        assert not steps[name].get("continue-on-error", False)
    for name in contracts:
        assert steps[name]["if"] == "matrix.lane == 'contracts'"
        assert not steps[name].get("continue-on-error", False)
    renderer = steps["Prepare pinned standalone Compose renderer for Rust contracts"]
    assert "bash scripts/ci/install-compose-renderer.sh" in renderer["run"]
    assert "MARTY_BASE_COMPOSE_BINARY=%s" in renderer["run"]
    assert "MARTY_SELFHOST_BUNDLE_TEST_COMPOSE=%s" in renderer["run"]
    names = [step.get("name") for step in job["steps"]]
    early = steps["Fail fast on image-free Canvas renewal configuration"]["run"]
    assert early.count("bash scripts/ci/install-compose-renderer.sh") == 1
    assert "run-canvas-config-proofs.py run" in early
    assert "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1" in early
    assert "MARTY_DIDCOMM_TEST_PYTHON" in early
    assert "docker " not in early and "cargo " not in early
    assert (
        "install-compose-renderer.sh"
        not in steps["Prepare required rendered base executable acceptance"]["run"]
    )
    late = steps["Prepare required rendered base executable acceptance"]["run"]
    assert "docker pull redis:7-alpine" in late
    assert "docker build --tag marty-envoy:native-contract config/envoy" in late
    assert (
        names.index("Compile reusable Rust test executables")
        < names.index("Fail fast on image-free Canvas renewal configuration")
        < names.index("Compile Bookworm-compatible base runtime acceptance")
        < names.index("Build public selfhost image")
    )
    assert (
        names.index("Compile reusable Rust test executables")
        < names.index("Prepare pinned standalone Compose renderer for Rust contracts")
        < names.index("Run safe Rust contract groups concurrently")
    )
    for name in (
        "Compile reusable Rust test executables",
        "Run isolated database contract suites concurrently",
    ):
        assert "if" not in steps[name]
    assert steps["Preserve synthetic runtime failure diagnostics"]["if"] == (
        "always() && matrix.lane == 'canvas'"
    )
    assert "${{ matrix.lane }}" in steps["Upload Rust build evidence"]["with"]["name"]


@pytest.mark.parametrize(
    "changed_path,rust_selected,python_selected,security_selected,all_selected",
    [
        (
            "rust/services/issuance/src/canvas_sync_processor_contract.md",
            True,
            False,
            False,
            False,
        ),
        ("rust/services/issuance/src/canvas_sync_worker.rs", True, False, False, False),
        (
            "docs/rust-migrations/canvas-worker-dispatch-reconciliation.md",
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
        ("scripts/test_canvas_worker_compose_render.py", True, True, True, True),
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
            "release",
            "verification",
            "security",
        )
    }
    expected["rust"] = str(rust_selected).lower()
    expected["python"] = str(python_selected).lower()
    expected["security"] = str(security_selected).lower()
    assert actual == expected


def test_canvas_inventory_inputs_select_their_actual_owners_without_full_pr_matrix(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    release = workflow["jobs"]["test-release-contracts"]
    assert any(
        step.get("run") == "python -m pytest tests -v --tb=short"
        for step in release["steps"]
    ), "The release lane must still execute the inventory tests"
    inventory_consumers = {
        "canvas-worker-oracle-producers.json": {
            ".github/workflows/ci.yml",
            "contracts/canvas-worker-tier-obligations.json",
            "scripts/ci/check_canvas_tier_obligations.py",
            "tests/test_ci_workflow_performance.py",
            "tests/test_canvas_worker_oracle_producer_inventory.py",
            "tests/test_canvas_worker_oracle_script_closure.py",
        },
        "canvas-worker-oracle-script-imports.json": {
            ".github/workflows/ci.yml",
            "contracts/canvas-worker-tier-obligations.json",
            "tests/test_ci_workflow_performance.py",
            "tests/test_canvas_worker_oracle_script_closure.py",
            "tests/test_canvas_worker_rest_input_evidence.py",
            "tests/test_canvas_worker_startup_input_evidence.py",
            "rust/crates/canvas-acceptance/tests/support/canvas_startup_attestation.rs",
        },
        "canvas-worker-rest-current-inputs.json": {
            ".github/workflows/ci.yml",
            "tests/test_ci_workflow_performance.py",
            "tests/test_canvas_worker_rest_input_evidence.py",
        },
        "canvas-worker-startup-current-inputs.json": {
            ".github/workflows/ci.yml",
            "tests/test_ci_workflow_performance.py",
            "tests/test_canvas_worker_startup_input_evidence.py",
            "rust/crates/canvas-acceptance/tests/support/canvas_startup_attestation.rs",
        },
        "canvas-worker-tier-obligations.json": {
            ".github/workflows/ci.yml",
            "scripts/ci/check_canvas_tier_obligations.py",
            "scripts/test_canvas_worker_rest_https.py",
            "tests/test_canvas_tier_obligations.py",
            "tests/test_canvas_worker_validation_tier.py",
            "tests/test_ci_workflow_performance.py",
        },
        "python-value-fast-obligations.json": {
            ".github/workflows/ci.yml",
            "scripts/ci/check_python_value_fast_obligations.py",
            "tests/test_python_value_fast_obligations.py",
            "tests/test_ci_workflow_performance.py",
        },
        "canvas-renewal-profile-obligations.json": {
            ".github/workflows/ci.yml",
            "tests/test_canvas_renewal_profile_obligations.py",
            "tests/test_ci_workflow_performance.py",
        },
    }
    for manifest, expected in inventory_consumers.items():
        references = subprocess.run(
            ["git", "grep", "-l", "-F", "--", manifest],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        assert {
            path
            for path in references.stdout.splitlines()
            if not path.endswith((".md", ".dockerignore"))
        } == expected, f"Review new consumer of {manifest} before narrowing its gate"
    tracked = subprocess.run(
        ["git", "ls-files", "--", "*Dockerfile*"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    copying_contracts = {
        path
        for path in tracked.stdout.splitlines()
        if (ROOT / path).is_file()
        and re.search(
            r"(?m)^(?:COPY|ADD)\s+(?:--\S+\s+)*contracts(?:/|\s)",
            (ROOT / path).read_text(encoding="utf-8"),
        )
    }
    image_contexts = {
        "services/Dockerfile": "services/Dockerfile.dockerignore",
        "rust/services/Dockerfile.ci": "rust/services/Dockerfile.ci.dockerignore",
        "rust/services/event-stream/Dockerfile": ".dockerignore",
        "rust/services/revocation-profile/Dockerfile": ".dockerignore",
    }
    assert copying_contracts == set(image_contexts), (
        "Review every image context that copies contracts before narrowing this gate"
    )
    for ignore_path in set(image_contexts.values()):
        lines = (ROOT / ignore_path).read_text(encoding="utf-8").splitlines()
        for manifest in inventory_consumers:
            exclusion = f"contracts/{manifest}"
            assert lines.count(exclusion) == 1, (
                f"Inventory manifest must be excluded from {ignore_path}"
            )
            assert not any(
                line.startswith("!contracts")
                for line in lines[lines.index(exclusion) + 1 :]
            ), f"Later rule re-includes {exclusion} in {ignore_path}"
    for path in (
        "contracts/canvas-worker-oracle-producers.json",
        "contracts/canvas-worker-oracle-script-imports.json",
        "contracts/canvas-worker-tier-obligations.json",
        "contracts/python-value-fast-obligations.json",
        "contracts/canvas-renewal-profile-obligations.json",
        "tests/test_canvas_worker_oracle_producer_inventory.py",
        "tests/test_canvas_worker_oracle_script_closure.py",
        "tests/test_canvas_worker_rest_input_evidence.py",
        "tests/test_canvas_worker_startup_input_evidence.py",
        "tests/test_canvas_worker_validation_tier.py",
        "tests/test_python_value_fast_obligations.py",
        "tests/test_canvas_renewal_profile_obligations.py",
    ):
        actual = _classify_changed_path(path, tmp_path)
        assert actual == {
            "all": "false",
            "ui": "false",
            "python": "false",
            "rust": str(path.startswith("contracts/")).lower(),
            "release": "true",
            "verification": "false",
            "security": "false",
        }
    assert (
        _classify_changed_path(
            "contracts/canvas-worker-startup-current-inputs.json", tmp_path
        )["rust"]
        == "true"
    )
    assert (
        _classify_changed_path(
            "contracts/canvas-worker-startup-current-inputs.json", tmp_path
        )["release"]
        == "true"
    )
    assert _classify_changed_path(
        "contracts/canvas-worker-rest-current-inputs.json", tmp_path
    ) == {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "true",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    # A new sibling test or changed corpus is not covered by this narrow rule.
    assert (
        _classify_changed_path(
            "tests/test_canvas_worker_oracle_script_closure_helpers.py", tmp_path
        )["all"]
        == "true"
    )
    assert (
        _classify_changed_path(
            "contracts/canvas-worker-startup-scenarios.json", tmp_path
        )["rust"]
        == "true"
    )
    combined = _classify_changed_paths(
        [
            "contracts/canvas-worker-oracle-script-imports.json",
            "contracts/canvas-worker-startup-scenarios.json",
        ],
        tmp_path,
        combined=True,
    )[0]
    assert combined["release"] == combined["rust"] == "true"
    assert combined["all"] == "false"
    unknown = _classify_changed_paths(
        [
            "contracts/canvas-worker-oracle-script-imports.json",
            "tests/test_canvas_worker_oracle_script_closure_helpers.py",
        ],
        tmp_path,
        combined=True,
    )[0]
    assert all(value == "true" for value in unknown.values())


def test_evidence_test_sources_keep_their_release_owner_without_runtime_lanes(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    assert any(
        step.get("run") == "python -m pytest tests -v --tb=short"
        for step in workflow["jobs"]["test-release-contracts"]["steps"]
    )
    paths = (
        "tests/test_canvas_worker_startup_input_evidence.py",
        "tests/test_canvas_worker_validation_tier.py",
        "tests/test_python_value_fast_obligations.py",
        "tests/test_canvas_renewal_profile_obligations.py",
    )
    selected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    ci_source = CI_PATH.read_text(encoding="utf-8")
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
        "contracts/canvas-worker-startup-current-inputs.json",
        "contracts/canvas-worker-tier-obligations.json",
        "contracts/python-value-fast-obligations.json",
        "contracts/canvas-renewal-profile-obligations.json",
    ):
        actual = _classify_changed_path(path, tmp_path)
        assert actual["rust"] == actual["release"] == "true"
    assert (
        _classify_changed_path("scripts/test_canvas_worker_rest_https.py", tmp_path)[
            "all"
        ]
        == "true"
    )
    assert (
        _classify_changed_path(
            "tests/test_canvas_worker_validation_tier_helpers.py", tmp_path
        )["all"]
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


def test_canvas_current_input_helper_has_only_release_test_consumers(
    tmp_path: Path,
) -> None:
    helper = "scripts/ci/canvas_oracle_current_inputs.py"
    owners = {
        "tests/test_canvas_worker_startup_input_evidence.py",
        "tests/test_canvas_worker_rest_input_evidence.py",
        "tests/test_canvas_worker_oracle_producer_inventory.py",
    }
    assert (ROOT / helper).is_file()
    references = subprocess.run(
        ["git", "grep", "-l", "-F", "--", "canvas_oracle_current_inputs"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert {
        path
        for path in references.stdout.splitlines()
        if not path.endswith(".md") and path != "tests/test_ci_workflow_performance.py"
    } == owners | {".github/workflows/ci.yml"}, (
        "Review a new Canvas helper consumer before narrowing its PR checks"
    )
    for path in owners:
        source = (ROOT / path).read_text(encoding="utf-8")
        assert "from scripts.ci.canvas_oracle_current_inputs import" in source

    _, workflow = _workflow(CI_PATH)
    release = workflow["jobs"]["test-release-contracts"]
    assert any(
        step.get("run") == "python -m pytest tests -v --tb=short"
        for step in release["steps"]
    )
    assert CI_PATH.read_text(encoding="utf-8").count(helper) == 1
    for other in (ROOT / ".github/workflows").glob("*.yml"):
        if other != CI_PATH:
            assert helper not in other.read_text(encoding="utf-8")
    for dockerfile, ignore in (
        ("services/Dockerfile", "services/Dockerfile.dockerignore"),
        ("rust/services/Dockerfile.ci", "rust/services/Dockerfile.ci.dockerignore"),
    ):
        source = (ROOT / dockerfile).read_text(encoding="utf-8")
        assert helper not in source
        assert not re.search(r"(?m)^(?:COPY|ADD)\s+(?:--\S+\s+)*(?:\.|scripts/?|scripts/ci/?)\s", source)
        included = [
            line
            for line in (ROOT / ignore).read_text(encoding="utf-8").splitlines()
            if line.startswith("!scripts/ci/") and line != "!scripts/ci/"
        ]
        assert included == (
            ["!scripts/ci/run-public-rust-build.sh", "!scripts/ci/public-sccache-stats.awk"]
            if dockerfile == "services/Dockerfile"
            else ["!scripts/ci/verify-release-cache.sh"]
        )

    selected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    for path in (helper, *owners):
        assert _classify_changed_path(path, tmp_path) == selected
    assert _classify_changed_path("scripts/ci/new_helper.py", tmp_path)["all"] == "true"
    assert _classify_changed_paths(
        [helper, "unknown-new-input.txt"], tmp_path, combined=True
    )[0] == {key: "true" for key in selected}
    mixed = _classify_changed_paths(
        [helper, "rust/services/issuance/src/lib.rs"], tmp_path, combined=True
    )[0]
    assert mixed["rust"] == mixed["release"] == "true"
    assert all(
        value == "true"
        for value in _classify_changed_paths([helper], tmp_path, event="merge_group")[
            0
        ].values()
    )


def test_runner_registration_inputs_keep_release_coverage_without_full_pr_matrix(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    release = workflow["jobs"]["test-release-contracts"]
    assert any(
        step.get("run") == "python -m pytest tests -v --tb=short"
        for step in release["steps"]
    ), "The release lane must still execute the runner policy tests"

    # A newly introduced executable/script consumer must be reviewed before
    # these exact inputs can retain their narrower PR selection.
    consumers = {
        "register-canvas-oss-runner.ps1": {
            "scripts/setup-canvas-oss-runner.ps1",
            "tests/test_canvas_oss_acceptance_topology.py",
            "tests/test_canvas_oss_runner_quarantine.py",
        },
        "runner-routing-label-policy.ps1": {
            "scripts/register-canvas-oss-runner.ps1",
            "tests/test_canvas_oss_runner_quarantine.py",
            "tests/test_runner_routing_labels.py",
        },
        "setup-canvas-oss-runner.ps1": {
            "scripts/register-canvas-oss-runner.ps1",
            "tests/test_canvas_oss_acceptance_topology.py",
        },
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
            not in {".github/workflows/ci.yml", "tests/test_ci_workflow_performance.py"}
        } == expected, f"Review new consumer of {name} before narrowing its gate"

    selected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    for path in (
        *(f"scripts/{name}" for name in consumers),
        "tests/test_runner_routing_labels.py",
        "tests/test_canvas_oss_runner_quarantine.py",
    ):
        assert _classify_changed_path(path, tmp_path) == selected
    assert (
        _classify_changed_path(
            "scripts/register-canvas-oss-runner-helper.ps1", tmp_path
        )["all"]
        == "true"
    )
    assert (
        _classify_changed_path(
            "tests/test_canvas_oss_acceptance_topology.py", tmp_path
        )["all"]
        == "true"
    )


def test_release_contract_test_sources_keep_their_release_owner(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    release = workflow["jobs"]["test-release-contracts"]
    assert any(
        step.get("run") == "python -m pytest tests -v --tb=short"
        for step in release["steps"]
    ), "The release lane must execute every narrowed test module"

    selected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
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
        step.get("run") == "python -m pytest tests -v --tb=short"
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
        "tests/test_canvas_published_preflight.py",
        "tests/test_rust_ownership.py",
        "tests/test_ci_workflow_performance.py",
        "tests/test_kubernetes_resolved_runtime.py",
        "tests/test_base_native_runtime_fixture.py",
        "tests/test_envoy_native_configuration.py",
        "tests/test_flow_public_startup.py",
        "tests/test_selfhost_runtime_model.py",
        "tests/test_passport_supported_rust_model.py",
        "tests/test_passport_supported_compose_ownership.py",
        "tests/test_ci_canvas_compile_scope.py",
    )
    ci_source = CI_PATH.read_text(encoding="utf-8")
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
        _classify_changed_path(
            "tests/test_canvas_published_preflight_helpers.py", tmp_path
        )["all"]
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
            "scripts/ci/run-published-canvas-contracts.sh", tmp_path
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
            "rust/crates/canvas-acceptance/tests/canvas_published_schema_contract.rs",
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
            [
                "tests/test_canvas_published_preflight.py",
                "rust/crates/canvas-acceptance/tests/canvas_published_worker_contract.rs",
            ],
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
            ["tests/test_canvas_published_preflight.py"],
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
        step.get("run") == "python -m pytest tests -v --tb=short"
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
    )
    ci_source = CI_PATH.read_text(encoding="utf-8")
    for path in candidates:
        assert (ROOT / path).is_file(), f"stale release-only selector: {path}"
        assert ci_source.count(path) == 1, f"other direct CI consumer: {path}"
        for other_workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
            if other_workflow != CI_PATH:
                assert path not in other_workflow.read_text(encoding="utf-8")
    expected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    assert _classify_changed_paths(candidates, tmp_path) == [expected] * len(candidates)
    assert _classify_changed_path(
        "tests/test_gateway_rust_cutover_helpers.py", tmp_path
    )["all"] == "true"
    mixed = _classify_changed_paths(
        [candidates[0], "services/Dockerfile"], tmp_path, combined=True
    )[0]
    assert all(mixed[name] == "true" for name in ("release", "rust", "python", "security"))
    protected = _classify_changed_paths(
        [candidates[0]], tmp_path, event="merge_group"
    )[0]
    assert protected["all"] == protected["rust"] == "true"


def test_shadow_planner_sources_use_existing_release_owner_on_prs(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    release = workflow["jobs"]["test-release-contracts"]
    assert "needs.changes.outputs.rust == 'true'" in release["if"]
    assert "needs.changes.outputs.release == 'true'" in release["if"]
    release_steps = {step.get("name"): step for step in release["steps"]}
    assert release_steps["Run repository release checks"]["run"] == (
        "python -m pytest tests -v --tb=short"
    )
    shadow = release_steps["Report affected Rust packages in shadow mode"]
    assert shadow["if"] == "github.event_name == 'pull_request'"
    assert shadow["run"] == "python3 scripts/ci/plan_affected_rust.py"
    assert shadow["env"] == {
        "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "HEAD_SHA": "${{ github.sha }}",
    }
    assert not any(
        step.get("name") == "Report affected Rust packages in shadow mode"
        for step in workflow["jobs"]["rust-lint-policy"]["steps"]
    )

    paths = ("scripts/ci/plan_affected_rust.py", "tests/test_plan_affected_rust.py")
    for path in paths:
        assert (ROOT / path).is_file()
        selected = _classify_changed_path(path, tmp_path)
        assert selected == {
            "all": "false",
            "ui": "false",
            "python": "false",
            "rust": "false",
            "release": "true",
            "verification": "false",
            "security": "false",
        }
        for other_workflow in (ROOT / ".github/workflows").glob("*.yml"):
            if other_workflow != CI_PATH:
                assert path not in other_workflow.read_text(encoding="utf-8")

    docker_context = (ROOT / "services/Dockerfile.dockerignore").read_text(
        encoding="utf-8"
    )
    assert docker_context.startswith("# Only public service build and runtime inputs.")
    assert "\n**\n" in docker_context
    assert "!scripts/ci/run-public-rust-build.sh" in docker_context
    assert "!scripts/ci/plan_affected_rust.py" not in docker_context
    assert "plan_affected_rust.py" not in (ROOT / "services/Dockerfile").read_text(
        encoding="utf-8"
    )

    assert _classify_changed_paths(paths, tmp_path, combined=True)[0]["rust"] == "false"
    assert (
        _classify_changed_paths(
            [paths[0], "rust/services/flow/src/lib.rs"], tmp_path, combined=True
        )[0]["rust"]
        == "true"
    )
    assert (
        _classify_changed_path("scripts/ci/unknown_planner.py", tmp_path)["all"]
        == "true"
    )
    assert (
        _classify_changed_path("tests/test_plan_affected_rust_helper.py", tmp_path)[
            "all"
        ]
        == "true"
    )
    assert (
        _classify_changed_paths([paths[0]], tmp_path, event="merge_group")[0]["all"]
        == "true"
    )


def test_planner_only_pr_feedback_retains_full_protected_release_checks(
    tmp_path: Path,
) -> None:
    _, workflow = _workflow(CI_PATH)
    changes = workflow["jobs"]["changes"]["outputs"]
    assert changes["planner_only"] == "${{ steps.classify.outputs.planner_only }}"
    planner_paths = [
        "scripts/ci/plan_affected_rust.py",
        "tests/test_plan_affected_rust.py",
        "docs/architecture-feedback-improvement-plan.md",
    ]
    exact = _classify_changed_paths(
        planner_paths, tmp_path, combined=True, include_planner_plan=True
    )[0]
    assert exact["planner_only"] == exact["release"] == "true"
    assert exact["all"] == exact["rust"] == "false"
    for source in planner_paths[:2]:
        selected = _classify_changed_paths(
            [source], tmp_path, include_planner_plan=True
        )[0]
        assert selected["planner_only"] == selected["release"] == "true"
    document_only = _classify_changed_paths(
        [planner_paths[2]], tmp_path, include_planner_plan=True
    )[0]
    assert document_only["planner_only"] == "false"
    empty_diff = _classify_changed_paths(
        [], tmp_path, combined=True, include_planner_plan=True
    )[0]
    assert empty_diff["planner_only"] == "false"
    for other in (
        "SELFHOST_BUNDLE.md",
        "rust/crates/selfhost-bundle/src/lib.rs",
        ".github/workflows/ci.yml",
        "tests/test_plan_affected_rust_helper.py",
    ):
        mixed = _classify_changed_paths(
            [planner_paths[0], other],
            tmp_path,
            combined=True,
            include_planner_plan=True,
        )[0]
        assert mixed["planner_only"] == "false", other
    protected = _classify_changed_paths(
        planner_paths,
        tmp_path,
        combined=True,
        event="merge_group",
        include_planner_plan=True,
    )[0]
    assert protected["planner_only"] == "false"
    assert protected["all"] == protected["release"] == "true"
    no_base = _classify_changed_paths(
        [planner_paths[0]],
        tmp_path,
        missing_base=True,
        include_planner_plan=True,
    )[0]
    assert no_base["planner_only"] == "false"
    assert no_base["all"] == "true"

    release = workflow["jobs"]["test-release-contracts"]
    steps = {step.get("name"): step for step in release["steps"]}
    assert steps["Run planner-owned PR checks"]["if"] == (
        "needs.changes.outputs.planner_only == 'true'"
    )
    planner_command = steps["Run planner-owned PR checks"]["run"]
    assert "tests/test_plan_affected_rust.py" in planner_command
    assert "tests/test_ci_workflow_performance.py" in planner_command
    complete_only = (
        "needs.changes.outputs.planner_only != 'true' && "
        "needs.changes.outputs.rollback_test_only != 'true'"
    )
    assert steps["Run repository release checks"]["if"] == complete_only
    assert steps["Run repository release checks"]["run"] == (
        "python -m pytest tests -v --tb=short"
    )
    for name in (
        "Replay Canvas mirror oracle in exact Credentials release image",
        "Configure the pinned containerd image store",
        "Configure the pinned OCI exporter",
        "Require the exact supported OCI backend",
        "Prove the same OCI archive through the future consumer path",
        "Require a compatible Credentials image for native DIDComm consumers",
        "Require the event-owner migration for native retention",
    ):
        assert steps[name]["if"] == complete_only
    assert steps["Report affected Rust packages in shadow mode"]["if"] == (
        "github.event_name == 'pull_request'"
    )


def test_rollback_test_only_pr_keeps_full_mixed_and_protected_validation(
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
            include_planner_plan=True,
            include_rollback_plan=True,
            **kwargs,
        )[0]

    exact = classify([source])
    assert exact == {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "rust_runtime": "false",
        "rust_matrix": '["canvas","contracts"]',
        "planner_only": "false",
        "rollback_test_only": "true",
        "release": "true",
        "verification": "false",
        "security": "true",
    }
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
    no_base = classify([source], missing_base=True)
    assert no_base["all"] == "true"
    assert no_base["rollback_test_only"] == "false"
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
    bounded = steps["Run rollback-test-owned PR checks"]
    assert bounded["if"] == "needs.changes.outputs.rollback_test_only == 'true'"
    assert bounded["run"].split() == [
        "python",
        "-m",
        "pytest",
        source,
        "tests/test_ci_workflow_performance.py",
        "-v",
        "--tb=short",
    ]
    assert steps["Run repository release checks"]["run"] == (
        "python -m pytest tests -v --tb=short"
    )
    full_only = (
        "needs.changes.outputs.planner_only != 'true' && "
        "needs.changes.outputs.rollback_test_only != 'true'"
    )
    for name in (
        "Replay Canvas mirror oracle in exact Credentials release image",
        "Run repository release checks",
        "Configure the pinned containerd image store",
        "Configure the pinned OCI exporter",
        "Require the exact supported OCI backend",
        "Prove the same OCI archive through the future consumer path",
        "Require a compatible Credentials image for native DIDComm consumers",
        "Require the event-owner migration for native retention",
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
    assert steps["Report affected Rust packages in shadow mode"]["if"] == (
        "github.event_name == 'pull_request'"
    )
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
        step.get("run") == "python -m pytest tests -v --tb=short"
        for step in workflow["jobs"]["test-release-contracts"]["steps"]
    )
    paths = (
        "tests/test_signing_response_reference.py",
        "tests/test_token_rate_reference.py",
        "tests/test_canvas_url_template_reference.py",
    )
    selected = {
        "all": "false",
        "ui": "false",
        "python": "false",
        "rust": "false",
        "release": "true",
        "verification": "false",
        "security": "false",
    }
    ci_source = CI_PATH.read_text(encoding="utf-8")
    for path in paths:
        assert (ROOT / path).is_file(), f"stale release-only selector: {path}"
        assert ci_source.count(path) == 1, f"other direct CI consumer: {path}"
        for other_workflow in (ROOT / ".github/workflows").glob("*.yml"):
            if other_workflow != CI_PATH:
                assert path not in other_workflow.read_text(encoding="utf-8")
        assert _classify_changed_path(path, tmp_path) == selected

    # This selector is for exact test sources, not reference artifacts or
    # capture implementations. Their existing Rust/full owners must remain.
    for path in (
        "contracts/signing-response-python-reference.json",
        "contracts/token-rate-python-reference.json",
        "contracts/canvas-url-template-python-reference.json",
    ):
        assert _classify_changed_path(path, tmp_path)["rust"] == "true"
    for path in (
        "scripts/capture_signing_response_reference.py",
        "scripts/capture_token_rate_reference.py",
        "scripts/capture_canvas_url_template_reference.py",
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
    assert _classify_changed_paths([paths[2]], tmp_path, event="merge_group")[
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
        ROOT / "rust/services/Dockerfile.ci",
        *(ROOT / "rust/services").glob("*/Dockerfile"),
    ]
    scanned = {path.relative_to(ROOT).as_posix() for path in dockerfiles}
    for workflow, excluded in (
        (CI_PATH, set()),
        # Official-only UI and tunnel-wrapper roles do not compile Rust
        # service binaries; their separate release ownership is asserted by
        # test_selfhost_release_preparation.py.
        (ROOT / ".github/workflows/cd.yml", {
            "docker/ui.Dockerfile", "docker/cloudflared-wrapper.Dockerfile",
        }),
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
    environment["BASE_SHA"] = "synthetic-base"
    environment["RUNNER_TEMP"] = tmp_path.as_posix()
    output = tmp_path / "synthetic-actions-output"
    environment["GITHUB_OUTPUT"] = output.as_posix()
    prelude = 'git() { if [[ "$1" == fetch ]]; then return 0; fi; return 42; }\n'
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-s"],
        input=prelude + script,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
        env=environment,
    )
    assert result.returncode != 0
    assert not output.exists()


def test_classifier_diff_reports_both_rename_endpoints(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    def git(*arguments: str) -> bytes:
        return subprocess.run(
            ["git", *arguments],
            cwd=repository,
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


def _assert_required_canvas_target_completion(published: str) -> None:
    assert "(( composition_status == 0 && worker_status == 0 ))" in published
    assert published.index(
        "(( composition_status == 0 && worker_status == 0 ))"
    ) < published.index("if (( expected_skipped_config_tests == 0 )); then")
    assert 'run-canvas-config-proofs.py" verify "$composition_executable"' in published
    assert (
        published.count("grep -Fo 'RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1'") == 2
    )
    assert (
        published.count("grep -Fo 'RESOLVED_KUBERNETES_RENEWAL_CONFIG_2X2_COMPLETE_V1'")
        == 2
    )
    assert (
        published.count("grep -Fo 'DIDCOMM_RENEWAL_PRIVATE_IP_PG_REFUSAL_COMPLETE_V1'")
        == 1
    )
    assert (
        "[[ $((all_tests - parallel_tests)) == $((2 + expected_skipped_worker_tests + expected_skipped_config_tests + expected_skipped_timeout_tests)) ]]"
        in published
    )
    assert '"${config_skips[@]}" "${timeout_skips[@]}" --nocapture --test-threads=4' in published
    assert published.rstrip().endswith(
        'python3 "$(dirname "${BASH_SOURCE[0]}")/check_canvas_tier_obligations.py" '
        '--require-execution canvas "$worker_log"'
    )


def test_published_canvas_schema_gate_is_explicit_and_mandatory() -> None:
    _, document = _workflow(CI_PATH)
    steps = document["jobs"]["test-rust-services"]["steps"]
    gate = next(
        step
        for step in steps
        if step.get("name") == "Run isolated database contract suites concurrently"
    )
    assert "if" not in gate
    assert not gate.get("continue-on-error", False)
    assert gate["run"] == (
        "python3 ../scripts/ci/run-db-contract-groups.py "
        "${{ matrix.lane == 'canvas' && 'canvas' || 'rust-db' }}"
    )
    published = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text(
        encoding="utf-8"
    )
    assert 'export MARTY_CANVAS_PUBLISHED_SCHEMA_TEST="1"' in published
    assert "canvas-worker-consumer-range-oracle.json" in published
    assert "canvas_published_schema_contract" in published
    assert 'composition_tests=$("$composition_executable" --list)' in published
    assert 'worker_tests=$("$worker_executable" --list)' in published
    assert "grep -Fx 'heartbeat_readiness_matches_published_python: test'" in published
    assert "grep -Fx 'operations_match_frozen_published_python: test'" in published
    assert (
        "grep -Fx 'operations_gateway_candidate_preserves_trusted_actor_and_frozen_routes: test'"
        in published
    )
    assert (
        "grep -Fx 'operations_reads_match_frozen_published_python: test'" in published
    )
    assert (
        "grep -Fx 'operations_inputs_match_frozen_published_python: test'" in published
    )
    assert "grep -Fx 'operations_jobs_match_frozen_published_python: test'" in published
    assert "grep -Fx 'operations_jobs_are_atomic_and_concurrent: test'" in published
    assert "grep -Fx 'enqueue_inputs_match_frozen_published_python: test'" in published
    assert (
        "grep -Fx 'operations_resolution_matches_corrected_published_schema: test'"
        in published
    )
    assert (
        "grep -Fx 'operations_resolution_fences_and_lifecycle_delegate: test'"
        in published
    )
    assert "grep -Fx 'review_inputs_match_published_python: test'" in published
    assert "grep -Fx 'review_lifecycle_matches_published_python: test'" in published
    assert "grep -Fx 'status_provider_matches_published_python: test'" in published
    assert "grep -Fx 'status_provider_matches_frozen_protocol: test'" in published
    assert (
        "grep -Fx 'status_runtime_matches_utf7_full_credential_routes: test'"
        in published
    )
    assert (
        "grep -Fx 'status_provider_matches_json_consumer_reference: test'" in published
    )
    assert (
        "grep -Fx 'status_runtime_matches_json_full_credential_routes: test'"
        in published
    )
    assert "grep -Fx 'status_provider_matches_json_depth_reference: test'" in published
    assert (
        "grep -Fx 'worker_rest_reference_matches_published_process: test'" in published
    )
    assert "grep -Fx 'worker_rest_matches_frozen_published_process: test'" in published
    assert "grep -Fx 'worker_rest_native_child: test'" in published
    assert "grep -Fx 'worker_retry_matches_frozen_published_process: test'" in published
    assert (
        "grep -Fx 'worker_provider_recovery_matches_frozen_published_process: test'"
        in published
    )
    assert "grep -Fx 'worker_provider_recovery_native_child: test'" in published
    assert "grep -Fx 'worker_provider_final_native_child: test'" in published
    assert "grep -Fx 'worker_provider_concurrent_native_child: test'" in published
    assert "grep -Fx 'worker_provider_reclaimers_native_child: test'" in published
    assert "grep -Fx 'worker_provider_reclaimers_retry_native_child: test'" in published
    assert (
        "grep -Fx 'worker_provider_reclaimers_retry_matches_frozen_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_provider_reclaimers_matches_frozen_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_reclaimers_reference_matches_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_reclaimers_retry_reference_matches_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_provider_concurrent_matches_frozen_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_concurrent_reference_matches_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_provider_final_matches_frozen_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_provider_final_reference_matches_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_provider_recovery_reference_matches_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_provider_signals_match_frozen_published_process: test'"
        in published
    )
    assert "grep -Fx 'worker_provider_signals_native_child: test'" in published
    assert (
        "grep -Fx 'worker_provider_signals_reference_matches_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_retry_reference_matches_published_process: test'" in published
    )
    assert (
        "grep -Fx 'worker_retry_after_reference_matches_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_validation_reference_matches_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_validation_repository_matches_frozen_errors: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_validation_matches_frozen_published_process: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_retry_after_matches_frozen_published_process: test'"
        in published
    )
    assert "grep -Fx 'worker_facts_match_frozen_published_process: test'" in published
    for name in [
        "worker_roster_failure_reference_matches_published_process",
        "worker_roster_failure_matches_frozen_published_process",
    ]:
        assert f"grep -Fx '{name}: test'" in published
    for name in [
        "worker_oauth_revocation_reference_matches_published_process",
        "worker_oauth_revocation_matches_frozen_published_process",
        "worker_oauth_revocation_native_child",
        "worker_oauth_revocation_fence_reference_matches_published_process",
        "worker_oauth_revocation_fence_matches_frozen_published_process",
        "worker_oauth_revocation_patch_reference_matches_published_process",
        "worker_oauth_revocation_patch_matches_frozen_published_process",
        "worker_oauth_revocation_retry_after_reference_matches_published_process",
        "worker_oauth_revocation_retry_after_matches_frozen_published_process",
        "worker_oauth_revocation_backoff_reference_matches_published_process",
        "worker_oauth_revocation_backoff_matches_frozen_published_process",
        "worker_oauth_revocation_queue_reference_matches_published_process",
        "worker_oauth_revocation_queue_matches_frozen_published_process",
        "worker_oauth_revocation_repository_selection_matches_published_order",
        "worker_oauth_revocation_lease_reference_matches_published_process",
        "worker_oauth_revocation_lease_matches_frozen_published_process",
        "worker_oauth_revocation_counters_reference_matches_published_cycle",
        "worker_oauth_revocation_counters_matches_frozen_published_cycle",
        "worker_oauth_revocation_secrets_reference_matches_published_process",
        "worker_oauth_revocation_secrets_matches_frozen_published_process",
        "worker_oauth_revocation_secret_reference_constraints_match_published_schema",
        "worker_oauth_revocation_empty_token_is_not_dispatched",
        "worker_provider_generation_reference_matches_published_process",
        "worker_provider_generation_preserves_stronger_recovery_fence",
        "worker_provider_generation_native_child",
        "worker_final_completion_race_has_one_repository_winner",
        "worker_effect_transaction_obeys_real_database_lease_expiry",
        "worker_deadline_reference_matches_published_process",
        "worker_deadline_matches_frozen_published_process",
        "worker_deadline_native_child",
        "canvas_published_borrowed_database::outer_database_owner_survives_forced_borrower_exit",
        "canvas_published_borrowed_database::borrower_child",
        "worker_timeout_reference_matches_published_process",
        "worker_body_timeout_reference_matches_published_process",
        "worker_lease_expiry_reference_matches_published_process",
        "worker_body_timeout_matches_frozen_published_process",
        "worker_body_timeout_native_child",
        "worker_timeout_matches_frozen_published_process",
        "worker_timeout_native_child",
        "worker_mixed_roster_reference_matches_published_process",
        "worker_mixed_roster_matches_frozen_published_process",
        "worker_mixed_roster_native_child",
        "worker_provider_completion_reference_matches_published_process",
        "worker_provider_completion_preserves_atomic_terminal_winner",
        "worker_provider_completion_native_child",
        "canvas_worker_provider_completion_replay::completion_atomicity_check_rejects_reference_or_target_drift",
        "worker_provider_recovery_first_reference_matches_published_process",
        "worker_provider_recovery_first_preserves_terminal_winner",
        "worker_provider_recovery_first_native_child",
        "canvas_worker_provider_completion_replay::rejected_owner_check_rejects_unrelated_or_reference_drift",
        "canvas_worker_provider_recovery_replay::newer_generation_check_rejects_any_target_mutation",
        "worker_oauth_revocation_selection_reference_matches_published_repository",
        "worker_oauth_revocation_selection_repository_matches_published",
    ]:
        assert f"grep -Fx '{name}: test'" in published
    assert (
        "grep -Fx 'worker_facts_reference_matches_published_process: test'" in published
    )
    assert (
        "grep -Fx 'worker_startup_matches_published_process_and_idle_heartbeat: test'"
        in published
    )
    assert (
        "grep -Fx 'status_runtime_matches_json_depth_full_credential_routes: test'"
        in published
    )
    for decoder in ("unicode", "charset", "iso2022", "ordinal", "utf7_label"):
        assert (
            f"grep -Fx 'status_runtime_preserves_{decoder}_failures_and_recovery: test'"
            in published
        )
    assert (
        "grep -Fx 'provider_configuration_matches_published_helpers: test'" in published
    )
    assert "grep -Fx 'validation_boundary_matches_published_http: test'" in published
    assert (
        "grep -Fx 'json_consumer_diagnostic_matches_published_boundaries: test'"
        in published
    )
    assert (
        "grep -Fx 'json_depth_diagnostic_matches_published_boundaries: test'"
        in published
    )
    assert (
        "grep -Fx 'timeout_consumer_matches_published_socket_behavior: test'"
        in published
    )
    assert (
        "grep -Fx 'utf7_consumer_diagnostic_matches_published_boundaries: test'"
        in published
    )
    assert (
        "grep -Fx 'status_runtime_preserves_credential_and_delivery_effects: test'"
        in published
    )
    assert (
        "grep -Fx 'status_runtime_composes_review_resolution_with_configured_http: test'"
        in published
    )
    assert (
        "grep -Fx 'didcomm_native_composes_crypto_https_and_published_durability: test'"
        in published
    )
    assert (
        "grep -Fx 'canvas_base_review_gateway_matches_corrected_published_schema: test'"
        in published
    )
    assert (
        "grep -Fx 'didcomm_fresh_http_admission_composes_reservation_and_delivery: test'"
        in published
    )
    assert (
        "grep -Fx 'didcomm_http_admission_recovers_real_keyed_reservation: test'"
        in published
    )
    assert (
        "grep -Fx 'didcomm_fresh_gateway_admission_preserves_public_projection_without_legacy_fallback: test'"
        in published
    )
    assert (
        "grep -Fx 'didcomm_historical_keyed_http_recovers_before_fresh_admission_guard: test'"
        in published
    )
    assert (
        "grep -Fx 'didcomm_flow_grpc_provider_preserves_keyed_admission: test'"
        in published
    )
    assert (
        "grep -Fx 'flow_native_consumer_preserves_artifacts_retries_and_legacy_physical_http: test'"
        in published
    )
    assert (
        "grep -Fx 'flow_rendered_settings_select_native_rpc_and_preserve_legacy_http: test'"
        in published
    )
    assert (
        "grep -Fx 'didcomm_unkeyed_grpc_initiation_composes_real_delivery: test'"
        in published
    )
    assert (
        "grep -Fx 'didcomm_gateway_candidate_preserves_real_delivery_without_legacy_fallback: test'"
        in published
    )
    assert (
        "grep -Fx 'didcomm_transport_reloads_valid_ca_bundles_without_disabling_tls: test'"
        in published
    )
    assert (
        "grep -Fx 'status_main_process_resolves_reviews_with_real_http_publication_and_mirror: test'"
        in published
    )
    assert (
        "grep -Fx 'worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings: test'"
        in published
    )
    assert (
        "grep -Fx 'cancelled_pool_release_does_not_wait_for_blocked_query: test'"
        in published
    )
    _assert_required_canvas_target_completion(published)
    assert (
        published.splitlines().count(
            '"$composition_executable" --skip "$serial_composition_test" "${config_skips[@]}" "${timeout_skips[@]}" --nocapture --test-threads=4 >"$composition_log" 2>&1 &'
        )
        == 1
    )
    assert (
        published.splitlines().count(
            'MARTY_CANVAS_WORKER_RETRY_AFTER_TIER="$retry_after_tier" MARTY_CANVAS_WORKER_VALIDATION_TIER="$validation_tier" "$worker_executable" --skip "$serial_test" "${preflight_skips[@]}" --nocapture --test-threads=4 >"$worker_log" 2>&1 &'
        )
        == 1
    )
    assert 'kill "$composition_pid" "$worker_pid"' in published
    assert 'tail --pid="$pid"' in published
    assert (
        'relay_target_timing "$composition_pid" "$composition_log" "$composition_end" &'
        in published
    )
    assert (
        'relay_target_timing "$worker_pid" "$worker_log" "$worker_end" &' in published
    )
    assert 'wait "$composition_pid" || composition_status=$?' in published
    assert 'wait "$worker_pid" || worker_status=$?' in published
    assert (
        '"$worker_executable" "$serial_test" --exact --nocapture --test-threads=1'
        in published
    )
    assert (
        '"$composition_executable" "$serial_composition_test" --exact --nocapture --test-threads=1'
        in published
    )
    assert '"$composition_executable" --nocapture --test-threads=1' not in published
    assert (
        '"$composition_executable" --skip "$serial_composition_test" "${config_skips[@]}" "${timeout_skips[@]}" --nocapture --test-threads=4'
        in published
    )
    assert '[[ ${#matches[@]} == 1 && -x "${matches[0]}" ]]' in published


def test_native_canvas_socket_timeout_gate_is_explicit_and_mandatory() -> None:
    _, document = _workflow(CI_PATH)
    steps = document["jobs"]["test-rust-services"]["steps"]
    gate = next(
        step
        for step in steps
        if step.get("name") == "Test native Canvas operation timeout TLS parity"
    )
    assert gate["if"] == "matrix.lane == 'canvas'"
    assert not gate.get("continue-on-error", False)
    assert (
        "grep -Fx 'canvas_operation_http::tests::native_socket_case: test'"
        in gate["run"]
    )
    assert "--native-executable" in gate["run"]
    assert '--qualification "$MARTY_CANVAS_FULL_QUALIFICATION"' in gate["run"]
    assert "select(.profile.test == true)" in gate["run"]
    assert "httpx==0.26.0 cryptography==44.0.3" in gate["run"]


GATEWAY_REGISTRATIONS = [
    (
        "operations_gateway_candidate_preserves_trusted_actor_and_frozen_routes",
        "canvas_operations_gateway_replay",
        "start_with_review_recovery",
        4,
        "gateway operations replay must not deadlock",
    ),
    (
        "operations_gateway_candidate_preserves_review_lifecycle",
        "canvas_gateway_lifecycle_replay",
        "start_with_status_provider",
        5,
        "gateway lifecycle replay must not deadlock",
    ),
]


def _assert_gateway_operations_registration(
    published: str, source: str, registration
) -> None:
    name, module, database, connections, message = registration
    inventory = f"printf '%s\\n' \"$all_test_names\" | grep -Fx '{name}: test'"
    assert published.splitlines().count(inventory) == 1
    assert 'export MARTY_CANVAS_PUBLISHED_SCHEMA_TEST="1"' in published
    _assert_required_canvas_target_completion(published)
    assert (
        published.splitlines().count(
            '"$composition_executable" --skip "$serial_composition_test" "${config_skips[@]}" "${timeout_skips[@]}" --nocapture --test-threads=4 >"$composition_log" 2>&1 &'
        )
        == 1
    )
    assert (
        published.splitlines().count(
            'MARTY_CANVAS_WORKER_RETRY_AFTER_TIER="$retry_after_tier" MARTY_CANVAS_WORKER_VALIDATION_TIER="$validation_tier" "$worker_executable" --skip "$serial_test" "${preflight_skips[@]}" --nocapture --test-threads=4 >"$worker_log" 2>&1 &'
        )
        == 1
    )
    assert (
        f'#[path = "../../../services/issuance/tests/support/{module}.rs"]\nmod {module};'
    ) in source
    matches = re.findall(
        r"((?:^#\[[^\n]+\]\s*\n)+)" + rf"^async fn {name}\(\) \{{(.*?)^\}}",
        source,
        re.M | re.S,
    )
    assert len(matches) == 1
    attributes, body = matches[0]
    assert attributes.strip() == "#[tokio::test]"
    # Pin the small orchestration wrapper, not the replay implementation. Exact
    # statements reject an extra opt-in, early success, dormant closure, ignored
    # test, or omitted cleanup while allowing ordinary Rustfmt whitespace.
    expected = """
        if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
            return;
        }
        let owned = canvas_published_database::PublishedDatabase::start_with_review_recovery()
            .await.unwrap();
        let pool = PgPoolOptions::new().max_connections(4)
            .connect(&owned.url).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(300),
            canvas_operations_gateway_replay::run(&pool, &owned.url),
        ).await.expect("gateway operations replay must not deadlock");
        pool.close().await;
        owned.close().unwrap();
    """
    expected = expected.replace("canvas_operations_gateway_replay", module)
    expected = expected.replace("start_with_review_recovery", database)
    expected = expected.replace("max_connections(4)", f"max_connections({connections})")
    expected = expected.replace("gateway operations replay must not deadlock", message)
    assert re.sub(r"\s+", "", body) == re.sub(r"\s+", "", expected)


@pytest.mark.parametrize("registration", GATEWAY_REGISTRATIONS)
def test_gateway_operations_candidate_is_required_and_not_dormant(registration) -> None:
    published = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text(
        encoding="utf-8"
    )
    source = (
        ROOT / "rust/crates/canvas-acceptance/tests/canvas_published_schema_contract.rs"
    ).read_text(encoding="utf-8")
    _assert_gateway_operations_registration(published, source, registration)


@pytest.mark.parametrize(
    "mutation",
    [
        "inventory",
        "duplicate-inventory",
        "ignored",
        "extra-opt-in",
        "helper",
        "database",
        "wrong-specialized-database",
        "cleanup",
        "pool-cleanup",
        "timeout",
        "disabled-schema",
        "filtered-full-run",
        "filtered-composition-run",
    ],
)
@pytest.mark.parametrize("registration", GATEWAY_REGISTRATIONS)
def test_gateway_operations_registration_rejects_disabled_or_incomplete_gate(
    mutation, registration
):
    published = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text(
        encoding="utf-8"
    )
    source = (
        ROOT / "rust/crates/canvas-acceptance/tests/canvas_published_schema_contract.rs"
    ).read_text(encoding="utf-8")
    name, module, database, _connections, _message = registration
    if mutation == "inventory":
        published = "\n".join(
            line for line in published.splitlines() if name not in line
        )
    elif mutation == "ignored":
        source = source.replace(f"async fn {name}", f"#[ignore]\nasync fn {name}")
    elif mutation == "duplicate-inventory":
        line = next(
            line for line in published.splitlines() if f"'{name}: test'" in line
        )
        published = published.replace(line, line + "\n" + line)
    elif mutation == "disabled-schema":
        published = published.replace(
            'export MARTY_CANVAS_PUBLISHED_SCHEMA_TEST="1"',
            'export MARTY_CANVAS_PUBLISHED_SCHEMA_TEST="0"',
        )
    elif mutation == "filtered-full-run":
        published = published.replace(
            'MARTY_CANVAS_WORKER_RETRY_AFTER_TIER="$retry_after_tier" MARTY_CANVAS_WORKER_VALIDATION_TIER="$validation_tier" "$worker_executable" --skip "$serial_test" "${preflight_skips[@]}" --nocapture --test-threads=4',
            'MARTY_CANVAS_WORKER_RETRY_AFTER_TIER="$retry_after_tier" MARTY_CANVAS_WORKER_VALIDATION_TIER="$validation_tier" "$worker_executable" unrelated_filter --skip "$serial_test" "${preflight_skips[@]}" --nocapture --test-threads=4',
        )
    elif mutation == "filtered-composition-run":
        published = published.replace(
            '"$composition_executable" --skip "$serial_composition_test" "${config_skips[@]}" "${timeout_skips[@]}" --nocapture --test-threads=4',
            '"$composition_executable" unrelated_filter --skip "$serial_composition_test" "${config_skips[@]}" "${timeout_skips[@]}" --nocapture --test-threads=4',
        )
    else:
        start = source.index(f"async fn {name}")
        end = source.index("\n}", start)
        body = source[start:end]
        original, changed = {
            "extra-opt-in": (
                "    let owned =",
                "    if true { return; }\n    let owned =",
            ),
            "helper": (f"{module}::run", "unused_replay::run"),
            "database": (f"{database}()", "start()"),
            "wrong-specialized-database": (
                f"{database}()",
                "start_with_review_recovery()"
                if database == "start_with_status_provider"
                else "start_with_status_provider()",
            ),
            "cleanup": ("    owned.close().unwrap();", ""),
            "pool-cleanup": ("    pool.close().await;", ""),
            "timeout": ("from_secs(300)", "from_secs(3000)"),
        }[mutation]
        assert original in body
        source = source[:start] + body.replace(original, changed) + source[end:]
    with pytest.raises(AssertionError):
        _assert_gateway_operations_registration(published, source, registration)


def test_canvas_lti_https_gate_requires_real_linux_parent_test() -> None:
    _source, document = _workflow(CI_PATH)
    gate = next(
        step
        for step in document["jobs"]["test-rust-services"]["steps"]
        if step.get("name") == "Test native Canvas AGS/NRPS over real HTTPS"
    )
    assert gate["if"] == "matrix.lane == 'canvas'"
    assert not gate.get("continue-on-error", False)
    assert "python3 --version" in gate["run"] and "openssl version" in gate["run"]
    assert "canvas_oauth_behavior" in gate["run"]
    assert "length == 1" in gate["run"]
    assert "actual_ags_nrps_https_uses_child_scoped_trust" in gate["run"]
    assert '"$https_executable" --list' in gate["run"]
    assert (
        '"$https_executable" "$https_test" --exact --nocapture --test-threads=1'
        in gate["run"]
    )


def _assert_no_rust_executable_transfer(steps) -> None:
    # These allowlisted uploads contain diagnostics, build timings, and JSON evidence,
    # never compiled tests. Other artifact transfers remain forbidden.
    expected_uploads = {
        "Preserve synthetic runtime failure diagnostics": (
            "${{ runner.temp }}/marty-owned-runtime-diagnostics/*.*"
        ),
        "Upload Rust build evidence": "${{ runner.temp }}/rust-build-evidence/",
        "Preserve fresh full-main startup attestation": "${{ runner.temp }}/canvas-startup-fresh-run.json",
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
        if step.get("name") == "Preserve synthetic runtime failure diagnostics"
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
    assert "run-published-canvas-contracts.sh" in orchestrator
    assert "run-rust-db-contracts.sh" in orchestrator
    assert "ThreadPoolExecutor(max_workers=2)" in orchestrator
    assert orchestrator.index('"published-canvas"') < orchestrator.index('"rust-db"')
    assert "test-rust-db-contracts" not in document["jobs"]
    assert "rust-db-test-bundle" not in source
    _assert_no_rust_executable_transfer(rust_job["steps"])
    for group in ("workspace", "verification", "gateway"):
        assert f"rust-{group}.status" in source
    assert "target/debug/flow-postgres-contract --test-threads=1" in source
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
        == ("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a")
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
        scope = job["steps"][1]
        assert scope["id"] == "scope"
        assert "github.paginate(github.rest.pulls.listFiles" in scope["with"]["script"]
        assert "context.eventName !== 'pull_request'" in scope["with"]["script"]
        assert any(
            step.get("name") == "Record scoped analysis skip" for step in job["steps"]
        )
        analysis_steps = [
            step for step in job["steps"] if step.get("name", "").startswith("Analyze")
        ]
        assert analysis_steps
        assert all(
            step["if"] == "steps.scope.outputs.analyze == 'true'"
            for step in analysis_steps
        )
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
    setup_uv = "astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7"
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
    assert (
        warm_install["run"]
        == "uv pip install --system -r requirements-services.txt jsonschema"
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


def test_closed_pull_request_cache_cleanup_is_rate_limit_safe() -> None:
    source, document = _workflow(
        ROOT / ".github" / "workflows" / "cleanup-ci-caches.yml"
    )
    cleanup = document["jobs"]["cleanup"]
    script = cleanup["steps"][0]["with"]["script"]

    assert "Promise.all" not in script
    assert "await delay(500)" in script
    assert "error.status === 429 || error.status === 403" in script
    assert "const maxAttempts = 7" in script
    assert "retry-after" in script
    assert "2_000 * (2 ** attempt)" in script
    assert "maxDeletions = 2000" in source


def test_compiler_cache_writes_are_reserved_for_trusted_main() -> None:
    _, ci = _workflow(CI_PATH)
    _, warm = _workflow(ROOT / ".github/workflows/warm-ci-caches.yml")
    for name in ("test-rust-services", "rust-lint-policy"):
        assert ci["jobs"][name]["env"]["SCCACHE_GHA_RW_MODE"] == "READ_ONLY"
    for job in warm["jobs"].values():
        assert job["if"] == "github.ref == 'refs/heads/main'"
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
    assert not steps[fallback].get("if")
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
    assert not service_steps[service_fallback].get("if")
    assert services["env"]["RUSTC_WRAPPER"] == "sccache"
    assert ci["jobs"]["rust-lint-policy"]["env"]["RUSTC_WRAPPER"] == "sccache"
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
        assert step["if"] == "always()"
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
    assert job["if"] == "github.ref == 'refs/heads/main'"
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
    ["services/issuance", "crates/service-acceptance", "crates/canvas-acceptance"],
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
            "canvas_lti_tool_signing_behavior.rs",
            "canvas_management_contract.rs",
            "canvas_mirror_native_behavior.rs",
            "canvas_publication_behavior.rs",
            "canvas_sync_worker_behavior.rs",
            "canvas_sync_worker_configuration_oracle.rs",
            "canvas_worker_result_oracle.rs",
            "issued_credential_adapter_behavior.rs",
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


def test_service_acceptance_keeps_composition_dependencies_out_of_service_builds() -> (
    None
):
    directory = ROOT / "rust/crates/service-acceptance"
    acceptance = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8"))
    issuance = tomllib.loads(
        (ROOT / "rust/services/issuance/Cargo.toml").read_text(encoding="utf-8")
    )
    workspace = tomllib.loads((ROOT / "rust/Cargo.toml").read_text(encoding="utf-8"))
    assert "crates/service-acceptance" in workspace["workspace"]["members"]
    assert not acceptance.get("dependencies")
    assert not acceptance.get("build-dependencies")
    assert (directory / "src/lib.rs").is_file()  # Survives Docker test exclusions.
    assert acceptance["package"]["publish"] is False
    assert {"marty-issuance-service", "marty-signing-keys"} <= set(
        acceptance["dev-dependencies"]
    )
    assert "marty-signing-keys" not in issuance.get("dev-dependencies", {})


def test_canvas_acceptance_has_distinct_targets_without_signing_kms_dependencies() -> (
    None
):
    canvas = tomllib.loads(
        (ROOT / "rust/crates/canvas-acceptance/Cargo.toml").read_text(encoding="utf-8")
    )
    gateway = tomllib.loads(
        (ROOT / "rust/crates/service-acceptance/Cargo.toml").read_text(encoding="utf-8")
    )
    workspace = tomllib.loads((ROOT / "rust/Cargo.toml").read_text(encoding="utf-8"))
    assert "crates/canvas-acceptance" in workspace["workspace"]["members"]
    assert {target["name"] for target in canvas["test"]} == {
        "canvas_published_worker_contract",
        "canvas_published_schema_contract",
    }
    assert {target["name"] for target in gateway["test"]} == {
        "passport_managed_kms_chain",
        "passport_gateway_postgres",
        "gateway_signing_acceptance",
    }
    assert "marty-signing-keys" not in canvas["dev-dependencies"]
    assert "marty-signing-keys" in gateway["dev-dependencies"]
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    runner = (ROOT / "scripts/ci/run-published-canvas-contracts.sh").read_text(
        encoding="utf-8"
    )
    groups = (ROOT / "scripts/ci/run-db-contract-groups.py").read_text(encoding="utf-8")
    assert "-p marty-canvas-acceptance" in workflow
    assert 'contains("#marty-canvas-acceptance@")' in workflow
    assert "package=marty-canvas-acceptance" in runner
    assert '"#marty-canvas-acceptance@"' in groups


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
    assert gate["env"]["MARTY_PASSPORT_GATEWAY_TEST_URL"].endswith(
        "/marty_passport_gateway_test"
    )
    assert "--test passport_gateway_postgres" in gate["run"]
    assert "-- --exact" in gate["run"]


@pytest.mark.parametrize("event", ["pull_request", "workflow_dispatch"])
@pytest.mark.parametrize("reopened", [False, True])
def test_cache_cleanup_includes_queue_refs_but_preserves_active_and_main(
    event: str, reopened: bool
) -> None:
    _, document = _workflow(ROOT / ".github/workflows/cleanup-ci-caches.yml")
    script = document["jobs"]["cleanup"]["steps"][0]["with"]["script"]
    harness = (
        r"""
      const deleted = [];
      const entries = [
        {id: 1, ref: 'refs/pull/23/merge'},
        {id: 2, ref: 'refs/heads/gh-readonly-queue/main/pr-23-abcdef'},
        {id: 3, ref: 'refs/heads/main'},
        {id: 4, ref: 'refs/pull/24/merge'},
        {id: 5, ref: 'refs/heads/gh-readonly-queue/main/pr-24-abcdef'},
        {id: 6, ref: 'refs/heads/feature'},
      ];
      const github = {
        request: async (_, params) => {
          if (params.ref) throw new Error('ref filter hides queue caches');
          return {data: {actions_caches: entries}};
        },
        rest: {
          pulls: {get: async ({pull_number}) => ({data: {state: pull_number === 23 && !REOPENED ? 'closed' : 'open'}})},
          actions: {deleteActionsCacheById: async ({cache_id}) => { deleted.push(cache_id); }},
        },
      };
      const summary = {addHeading() {return this}, addRaw() {return this}, async write() {}};
      const core = {info() {}, warning() {}, summary};
      const context = {repo: {owner: 'test', repo: 'test'}, eventName: EVENT,
        payload: {pull_request: {number: 23}}};
      const AsyncFunction = Object.getPrototypeOf(async function() {}).constructor;
      await new AsyncFunction('github', 'context', 'core', 'setTimeout', SCRIPT)(
        github, context, core, callback => callback());
      if (JSON.stringify(deleted) !== (REOPENED ? '[]' : '[1,2]')) throw new Error(JSON.stringify(deleted));
    """.replace("EVENT", json.dumps(event))
        .replace("REOPENED", json.dumps(reopened))
        .replace("SCRIPT", json.dumps(script))
    )
    result = subprocess.run(
        ["node", "--input-type=module", "--eval", harness],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


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


def test_renewal_matrix_preserves_real_deadlines_and_all_combinations() -> None:
    source = (
        ROOT
        / "rust/services/issuance/tests/support/canvas_worker_renewal_job_outcomes.rs"
    ).read_text(encoding="utf-8")
    assert "tokio::join!(" in source
    for stage in ("lease", "target", "process"):
        assert f'isolated_group(pool, "{stage}")' in source
    assert "Uuid::new_v4().simple()" in source
    assert "catch_unwind().await" in source.replace("\n", "").replace(" ", "")
    assert "pool.close().await" in source
    assert "Duration::from_secs(20)" in source
    assert "Duration::from_secs(30)" in source
    assert "sum::<usize>(),60" in re.sub(r"\s+", "", source)
