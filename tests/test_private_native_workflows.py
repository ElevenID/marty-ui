"""Keep private dependency source out of public caches and build credentials."""
from pathlib import Path
import re
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[1]
NATIVE = {
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
