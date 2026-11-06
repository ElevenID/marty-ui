"""Keep private dependency source out of public caches and build credentials."""
from pathlib import Path
import os
import re
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
NATIVE = {
    "codeql-rust.yml": {"analyze-rust"},
    "ci.yml": {"test-rust-feature-probe", "test-openbao-didcomm-plugin", "test-rust-services", "test-native-operator", "rust-lint-policy", "test-rust-service-images", "test-release-contracts", "rust-supply-chain", "installer-trial-image"},
    "cd.yml": {"build-services", "official-gate-evidence", "verifier-differential", "didcomm-plugin-image-qualification", "prepare-selfhost-image-lock", "build-operator-catalog"},
    "e2e-tests.yml": {"full-stack-credential-lifecycle"},
    "nightly-release.yml": {"build-images", "prepare-native"},
    "product-packages.yml": {"build"},
    "passport-supported-consumer-acceptance.yml": {"collect"},
    "verification-candidate-build.yml": {"build"},
    "wallet-conformance.yml": {"attest-release"},
    "rust-security.yml": {"rust-supply-chain"},
}
DOCKERFILES = {"services/Dockerfile", "services/Dockerfile.migrations", "rust/services/Dockerfile.ci"}


def workflow(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def test_native_access_is_checked_before_any_reader_step():
    for file, names in NATIVE.items():
        jobs = workflow(file)["jobs"]
        for name in names:
            job = jobs[name]
            assert "PRIVATE_FORKS_READ_TOKEN" not in job.get("env", {}), (file, name)
            steps = job["steps"]
            checks = [i for i, step in enumerate(steps) if step.get("name") == "Authorize private fork access"]
            assert len(checks) == 1, (file, name)
            check = steps[checks[0]]
            assert "PRIVATE_FORKS_ENABLED == 'true'" in check["if"]
            assert " check" in check["run"]
            assert "PRIVATE_FORKS_READ_TOKEN" not in str(check)
            readers = []
            for i, step in enumerate(steps):
                if "secrets.PRIVATE_FORKS_READ_TOKEN" not in str(step):
                    continue
                readers.append(i)
                assert checks[0] < i, (file, name, step.get("name"))
                if "run" in step:
                    assert "private-forks.py\" fetch" in step["run"] or "private-forks.py fetch" in step["run"]
                    assert "cargo build" not in step["run"] and "cargo test" not in step["run"]
                    assert "PRIVATE_FORKS_ENABLED == 'true'" in step["if"]
                else:
                    assert "docker/build-push-action@" in step["uses"] or step["uses"] == "./.github/actions/build-product-image"
            assert readers, (file, name)


def test_native_cache_actions_and_warmers_are_disabled_in_private_mode():
    for file, names in NATIVE.items():
        for name in names:
            job = workflow(file)["jobs"][name]
            for step in job["steps"]:
                uses = step.get("uses", "")
                native_cache = "sccache-action@" in uses or "rust-cache@" in uses
                native_cache |= "actions/cache" in uses and "bookworm-sccache" in str(step.get("with", {}))
                if native_cache:
                    assert "PRIVATE_FORKS_ENABLED != 'true'" in step.get("if", ""), (file, name, step)
                if job.get("env", {}).get("RUSTC_WRAPPER"):
                    assert "PRIVATE_FORKS_ENABLED != 'true'" in job["env"]["RUSTC_WRAPPER"]
    for name in ("rust", "images", "public-services"):
        assert "PRIVATE_FORKS_ENABLED != 'true'" in workflow("warm-ci-caches.yml")["jobs"][name]["if"]


def test_native_docker_calls_use_secret_mounts_and_no_private_cache_exports():
    for file, names in NATIVE.items():
        for name in names:
            for step in workflow(file)["jobs"][name]["steps"]:
                opts = step.get("with", {})
                if opts.get("file") not in DOCKERFILES:
                    continue
                assert "PRIVATE_FORKS_ENABLED=" in opts["build-args"]
                assert "PRIVATE_FORKS_READ_TOKEN" not in opts["build-args"]
                assert "private_forks_read_token=PRIVATE_FORKS_READ_TOKEN" in opts["secret-envs"]
                assert "PRIVATE_FORKS_ENABLED == 'true'" in step["env"]["PRIVATE_FORKS_READ_TOKEN"]
                for field in ("cache-from", "cache-to"):
                    if opts.get(field):
                        assert "PRIVATE_FORKS_ENABLED != 'true'" in opts[field]


def test_docker_reader_mount_only_fetches_and_never_reaches_compilation():
    for name in DOCKERFILES:
        source = (ROOT / name).read_text()
        instructions = source.replace("\\\n", " ").splitlines()
        mounted = [line for line in instructions if "--mount=type=secret,id=private_forks_read_token" in line]
        assert len(mounted) == 1, name
        assert "fetch --container --token-file /run/secrets/private_forks_read_token" in mounted[0]
        assert not re.search(r"cargo (build|test|check|clippy)\b", mounted[0])
        if "cargo chef cook" in mounted[0]:
            assert "cargo chef cook --no-build" in mounted[0]
        assert "CARGO_HOME=/opt/private-cargo" in source
        assert not any("PRIVATE_FORKS_READ_TOKEN" in line for line in instructions if line.startswith(("ARG ", "ENV ")))
        final = source[source.rfind("\nFROM "):]
        assert "/opt/private-cargo" not in final
        assert "marty-private-forks.py" not in final
        for instruction in instructions:
            if instruction.startswith("RUN "):
                command = re.sub(r"^RUN (?:--mount=\S+\s+)*", "", instruction)
                subprocess.run(["sh", "-n", "-c", command], check=True, capture_output=True)


def test_frozen_probe_and_release_core_graphs_are_fetched_separately():
    ci = workflow("ci.yml")["jobs"]
    for name in ("test-rust-feature-probe", "rust-lint-policy"):
        fetch = next(step for step in ci[name]["steps"] if step.get("name") == "Fetch locked private fork dependencies")
        assert ".github/feature-regression/rust-probe/Cargo.toml" in fetch["run"]
    steps = workflow("cd.yml")["jobs"]["verifier-differential"]["steps"]
    names = [step.get("name") for step in steps]
    prepare = names.index("Prepare the exact attested Core KMS verifier source")
    fetch = names.index("Fetch the attested Core private fork dependencies")
    compile_ = names.index("Build the exact attested Core KMS verifier producer")
    assert prepare < fetch < compile_
    assert "PRIVATE_FORKS_READ_TOKEN" not in str(steps[prepare])
    assert "PRIVATE_FORKS_READ_TOKEN" not in str(steps[compile_])
    assert "core-source/Cargo.toml" in steps[fetch]["run"]


def test_historical_wallet_source_keeps_the_reviewed_workflow_helper():
    steps = workflow("wallet-conformance.yml")["jobs"]["attest-release"]["steps"]
    check = next(i for i, step in enumerate(steps) if step.get("name") == "Authorize private fork access")
    old_source = next(i for i, step in enumerate(steps) if "tooling_sha" in str(step.get("with", {})))
    fetch = next(i for i, step in enumerate(steps) if step.get("name") == "Fetch locked private fork dependencies")
    assert check < old_source < fetch
    assert 'cp ".github/scripts/private-forks.py" "$RUNNER_TEMP/marty-private-forks.py"' in steps[check]["run"]
    assert '${RUNNER_TEMP}/marty-private-forks.py' in steps[fetch]["run"]


def test_lifecycle_lineage_compilers_fetch_before_validating_source_runs():
    for file, name, validator in (
        ("wallet-conformance.yml", "attest-release", "Require successful immutable source runs"),
        ("e2e-tests.yml", "full-stack-credential-lifecycle", "Bind lifecycle to the successful stack release"),
    ):
        steps = workflow(file)["jobs"][name]["steps"]
        names = [step.get("name") for step in steps]
        check = names.index("Authorize private fork access")
        fetch = names.index("Fetch current release evidence dependencies")
        lineage = names.index(validator)
        later_graph = names.index("Fetch locked private fork dependencies")
        assert check < fetch < lineage < later_graph
        assert '--manifest-path "rust/Cargo.toml"' in steps[fetch]["run"]
        assert "cargo run --locked" in steps[lineage]["run"]
        assert "PRIVATE_FORKS_READ_TOKEN" not in str(steps[lineage])


def test_codeql_private_reader_preserves_scope_and_disables_source_exports():
    job = workflow("codeql-rust.yml")["jobs"]["analyze-rust"]
    steps = job["steps"]
    names = [step.get("name") for step in steps]
    scope = names.index("Classify Rust analysis scope")
    proof = names.index("Prove test-only sources are outside production Rust analysis")
    check = names.index("Authorize private fork access")
    debug = names.index("Reject private source debug exports")
    fetch = names.index("Fetch locked private fork dependencies")
    init = names.index("Initialize production-focused analysis")
    analyze = names.index("Analyze Rust")
    assert scope < proof < check < debug < fetch < init < analyze
    condition = (
        "vars.PRIVATE_FORKS_ENABLED == 'true' && steps.scope.outputs.analyze == 'true' "
        "&& steps.test_only.outputs.skip != 'true'"
    )
    for index in (check, debug, fetch):
        assert steps[index]["if"] == condition
        assert not steps[index].get("continue-on-error", False)
    assert steps[check]["run"] == 'python3 ".github/scripts/private-forks.py" check'
    assert steps[fetch]["run"] == (
        'python3 ".github/scripts/private-forks.py" fetch --manifest-path "rust/Cargo.toml"'
    )
    assert steps[fetch]["env"] == {
        "PRIVATE_FORKS_READ_TOKEN": "${{ secrets.PRIVATE_FORKS_READ_TOKEN }}",
    }
    for index, step in enumerate(steps):
        if index != fetch:
            assert "PRIVATE_FORKS_READ_TOKEN" not in str(step)
        if index < check:
            assert "secrets." not in str(step)
        assert not any(action in step.get("uses", "") for action in (
            "actions/cache", "rust-cache", "sccache-action", "actions/upload-artifact",
        ))
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
    assert job["env"]["CODEQL_OVERLAY_DATABASE_MODE"] == "none"
    assert job["env"]["CODEQL_ACTION_DEBUG_COMBINED_SARIF"] == "false"
    for option in ("dependency-caching", "trap-caching", "debug"):
        assert steps[init]["with"][option] is False
    assert steps[analyze]["with"] == {
        "category": "/language:rust", "upload-database": False,
    }


@pytest.mark.parametrize("runner_debug,expected_status", [("", 0), ("0", 0), ("1", 1)])
def test_codeql_debug_guard_stops_before_private_source_fetch(runner_debug, expected_status):
    job = workflow("codeql-rust.yml")["jobs"]["analyze-rust"]
    guard = next(step for step in job["steps"] if step.get("name") == "Reject private source debug exports")
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", guard["run"]],
        env={**os.environ, "RUNNER_DEBUG": runner_debug},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == expected_status
    assert ("Actions step debug logging to be disabled" in result.stdout) == bool(expected_status)


def test_service_image_catalog_checks_prepare_host_rust_without_leaking_reader():
    document = workflow("ci.yml")
    job = document["jobs"]["test-rust-service-images"]
    steps = job["steps"]
    names = [step.get("name") for step in steps]
    check = names.index("Authorize private fork access")
    consumer = names.index("Verify complete Canvas worker consumer configurations")
    toolchains = [i for i, step in enumerate(steps)
                  if step.get("uses") == "dtolnay/rust-toolchain@02cb101ec7c40f2c49e1d9714d64511d8e1b74de"]
    fetches = [i for i, step in enumerate(steps)
               if step.get("name") == "Fetch locked private fork dependencies"]
    assert len(toolchains) == len(fetches) == 1
    toolchain, fetch = toolchains[0], fetches[0]
    assert check < toolchain < fetch < consumer
    assert steps[toolchain]["with"] == {"toolchain": "1.95.0"}
    assert not steps[toolchain].get("if")
    assert steps[check]["if"] == steps[fetch]["if"] == "vars.PRIVATE_FORKS_ENABLED == 'true'"
    assert steps[fetch]["run"] == (
        'python3 ".github/scripts/private-forks.py" fetch --manifest-path "rust/Cargo.toml"'
    )
    assert steps[fetch]["working-directory"] == "${{ github.workspace }}"
    assert steps[fetch]["timeout-minutes"] == 5
    assert steps[fetch]["env"] == {
        "PRIVATE_FORKS_READ_TOKEN": "${{ secrets.PRIVATE_FORKS_READ_TOKEN }}",
    }
    assert job["permissions"] == {"actions": "write", "contents": "read"}
    for env in (document.get("env", {}), job.get("env", {})):
        assert "PRIVATE_FORKS_READ_TOKEN" not in env
        assert "CARGO_HOME" not in env
    for index, step in enumerate(steps[:consumer + 1]):
        if index != fetch:
            assert "PRIVATE_FORKS_READ_TOKEN" not in str(step)
        assert "CARGO_HOME" not in str(step)
        assert not step.get("continue-on-error", False)
        assert not any(action in step.get("uses", "") for action in (
            "actions/cache", "rust-cache", "sccache-action", "actions/upload-artifact",
        ))
    # Keep both authoritative suites, the pinned renderer, and every assertion.
    assert steps[consumer]["run"] == (
        'set -euo pipefail\n'
        'bash scripts/ci/install-compose-renderer.sh\n'
        'compose_renderer="$RUNNER_TEMP/compose-render-v5.4.0"\n'
        'python3 scripts/test_canvas_worker_compose_render.py \\\n'
        '  --suite bundle --compose-command "$compose_renderer"\n'
        'python3 scripts/test_canvas_worker_compose_render.py \\\n'
        '  --suite consumers --compose-command "$compose_renderer"\n'
    )
