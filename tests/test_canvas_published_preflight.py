"""Exercise the real CI shell with local command doubles, never Docker/network."""

from __future__ import annotations

from contextlib import nullcontext
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/ci/run-published-canvas-contracts.sh"
TARGET = "worker_mixed_roster_matches_frozen_published_process"
TIMEOUT_TARGET = "worker_timeout_matches_frozen_published_process"
BODY_TIMEOUT_TARGET = "worker_body_timeout_matches_frozen_published_process"
PREFLIGHTS = [
    ("mixed-roster-preflight", TARGET),
    ("timeout-preflight", TIMEOUT_TARGET),
    ("body-timeout-preflight", BODY_TIMEOUT_TARGET),
]
SCHEMA_ENV = "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST"
PINS = [
    f"registry.invalid/{name}@sha256:{letter * 64}"
    for name, letter in (("postgres", "a"), ("issuance", "b"))
]


def required_registrations():
    # The existing CI-workflow suite pins the mandatory inventory. Here derive
    # it to exercise every current check without copying another long roster.
    names = re.findall(r"grep -Fx '([^']+): test'", SCRIPT.read_text(encoding="utf-8"))
    assert names and all(target in names for _, target in PREFLIGHTS)
    # Keep each mandatory registration's full-mode place without copying it.
    return [name for index, name in enumerate(names) if name not in names[index + 1 :]]


@pytest.fixture
def shell_case(tmp_path):
    if os.name == "nt":
        git = shutil.which("git")
        assert git is not None
        bash = str(Path(git).resolve().parents[1] / "bin/bash.exe")
    else:
        bash = shutil.which("bash")
    assert bash and Path(bash).is_file(), (
        "Executable Bash is mandatory for CI shell contracts"
    )
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    doubles = {
        "docker": r"""#!/usr/bin/env bash
set -euo pipefail
record=docker
for argument in "$@"; do record+="|$argument"; done
printf '%s\n' "$record" >> "$TEST_LOG"
[[ $# == 2 && "$1" == pull ]] || exit 90
[[ "$TEST_FAILURE" != docker ]] || exit 13
""",
        "jq": r"""#!/usr/bin/env bash
set -euo pipefail
printf 'jq|%s\n' "$1" >> "$TEST_LOG"
if [[ "$1" == -er ]]; then
  [[ "$#" == 3 && "$3" == ../contracts/canvas-worker-consumer-range-oracle.json ]] || exit 90
  [[ "$TEST_FAILURE" != images ]] || exit 17
  printf '%s\n' "$TEST_POSTGRES_IMAGE" "$TEST_PYTHON_IMAGE"
else
  [[ "$#" == 3 && "$1" == -r && "$3" == "$RUNNER_TEMP/rust-test-artifacts.json" ]] || exit 90
  [[ "$2" == *canvas_published_schema_contract* && "$2" == *marty-issuance-service* ]] || exit 90
  [[ "$TEST_FAILURE" != artifacts ]] || exit 18
  if [[ "$TEST_FAILURE" == missing-executable ]]; then
    printf './does-not-exist\n'
  elif [[ "$TEST_FAILURE" == duplicate-executables ]]; then
    printf './contract\n./different-contract\n'
  else
    printf './contract\n'
  fi
fi
""",
        "grep": r"""#!/usr/bin/env bash
set -euo pipefail
record=grep
for argument in "$@"; do record+="|$argument"; done
printf '%s\n' "$record" >> "$TEST_LOG"
exec /usr/bin/grep "$@"
""",
    }
    for name, source in doubles.items():
        path = fake_bin / name
        path.write_text(source, encoding="utf-8", newline="\n")
        path.chmod(0o755)
    contract = tmp_path / "contract"
    contract.write_text(
        r"""#!/usr/bin/env bash
set -euo pipefail
record="child|${MARTY_CANVAS_PUBLISHED_SCHEMA_TEST:-absent}"
for argument in "$@"; do record+="|$argument"; done
printf '%s\n' "$record" >> "$TEST_LOG"
if [[ "$#" == 1 && "$1" == --list ]]; then
  [[ "$TEST_FAILURE" != list ]] || exit 19
  while IFS= read -r registration; do printf '%s\n' "$registration"; done < registrations
else
  [[ "$TEST_FAILURE" != execute ]] || exit 23
fi
""",
        encoding="utf-8",
        newline="\n",
    )
    contract.chmod(0o755)

    def run(arguments=(), *, failure="", registrations=None, pins=PINS):
        lines = (
            registrations
            if registrations is not None
            else [f"{name}: test" for name in required_registrations()]
        )
        (tmp_path / "registrations").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
        log = tmp_path / "calls"
        log.write_text("", encoding="utf-8")
        environment = dict(os.environ)
        environment.update(
            {
                "TEST_FAILURE": failure,
                "TEST_POSTGRES_IMAGE": pins[0],
                "TEST_PYTHON_IMAGE": pins[1],
                "CONTRACT_SOURCE": SCRIPT.as_posix(),
                SCHEMA_ENV: "0",
            }
        )
        # Fake binaries shadow commands even if the shell uses `command docker`.
        wrapper = """export PATH="$PWD/fake-bin:/usr/bin:/bin"
export TEST_LOG="$PWD/calls" RUNNER_TEMP="$PWD"
source "$CONTRACT_SOURCE" "$@"
"""
        result = subprocess.run(
            [bash, "--noprofile", "--norc", "-c", wrapper, "synthetic-ci", *arguments],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )
        calls = [
            line.split("|") for line in log.read_text(encoding="utf-8").splitlines()
        ]
        return result, calls

    return run


@pytest.mark.parametrize("arguments", [[], ["full"]])
def test_default_and_explicit_full_keep_all_registrations_and_unfiltered_run(
    shell_case, arguments
):
    result, calls = shell_case(arguments)
    assert result.returncode == 0, result.stderr
    checks = [call[2] for call in calls if call[0] == "grep"]
    assert checks == [f"{name}: test" for name in required_registrations()]
    children = [call for call in calls if call[0] == "child"]
    assert children[-1] == ["child", "1", "--nocapture", "--test-threads=1"]
    assert children[:-1] == [["child", "1", "--list"]] * len(checks)
    assert [call for call in calls if call[0] == "docker"] == [
        ["docker", "pull", pin] for pin in PINS
    ]


@pytest.mark.parametrize("mode,target", PREFLIGHTS)
def test_preflight_requires_only_exact_target_and_forces_configured_serial_execution(
    shell_case, mode, target
):
    result, calls = shell_case([mode], registrations=[f"{target}: test"])
    assert result.returncode == 0, result.stderr
    assert [call for call in calls if call[0] == "grep"] == [
        ["grep", "-Fx", f"{target}: test"]
    ]
    assert [call for call in calls if call[0] == "child"] == [
        ["child", "1", "--list"],
        ["child", "1", target, "--exact", "--nocapture", "--test-threads=1"],
    ]


@pytest.mark.parametrize(
    "arguments",
    [
        [""],
        ["unknown"],
        ["--help"],
        [TARGET],
        [TIMEOUT_TARGET],
        [BODY_TIMEOUT_TARGET],
        ["full", "extra"],
        ["mixed-roster-preflight", "extra"],
        ["timeout-preflight", "extra"],
        ["timeout-preflight", ""],
        ["timeout-preflight; docker ps"],
        ["body-timeout-preflight", "extra"],
        ["body-timeout-preflight", ""],
        ["body-timeout-preflight; docker ps"],
    ],
)
def test_invalid_mode_or_extra_argument_fails_before_any_external_work(
    shell_case, arguments
):
    result, calls = shell_case(arguments)
    assert result.returncode == 2
    assert calls == []


@pytest.mark.parametrize("mode,target", PREFLIGHTS)
@pytest.mark.parametrize(
    "shape", ["missing", "bare", "prefix", "suffix", "other-preflight"]
)
def test_preflight_rejects_missing_or_inexact_registration_without_running_it(
    shell_case, mode, target, shape
):
    registration = {
        "missing": "",
        "bare": target,
        "prefix": f"prefix::{target}: test",
        "suffix": f"{target}_suffix: test",
        "other-preflight": f"{TIMEOUT_TARGET if target == TARGET else TARGET}: test",
    }[shape]
    result, calls = shell_case([mode], registrations=[registration])
    assert result.returncode != 0
    assert [call for call in calls if call[0] == "child"] == [["child", "1", "--list"]]


@pytest.mark.parametrize(
    "failure",
    [
        "images",
        "docker",
        "artifacts",
        "missing-executable",
        "duplicate-executables",
        "list",
        "execute",
    ],
)
@pytest.mark.parametrize("mode,target", PREFLIGHTS)
def test_preflight_propagates_preparation_listing_and_test_failures(
    shell_case, mode, target, failure
):
    result, calls = shell_case([mode], failure=failure)
    assert result.returncode != 0
    children = [call for call in calls if call[0] == "child"]
    expected = []
    if failure in ("list", "execute"):
        expected.append(["child", "1", "--list"])
    if failure == "execute":
        expected.append(
            ["child", "1", target, "--exact", "--nocapture", "--test-threads=1"]
        )
        assert result.returncode == 23
    assert children == expected


@pytest.mark.parametrize(
    "missing",
    [
        "heartbeat_readiness_matches_published_python",
        TARGET,
        TIMEOUT_TARGET,
        BODY_TIMEOUT_TARGET,
        "worker_body_timeout_reference_matches_published_process",
        "worker_body_timeout_native_child",
        "worker_provider_recovery_first_native_child",
    ],
)
def test_full_mode_still_fails_on_missing_mandatory_registration(shell_case, missing):
    names = required_registrations()
    assert missing in names
    result, calls = shell_case(
        registrations=[f"{name}: test" for name in names if name != missing]
    )
    assert result.returncode != 0
    assert all(call[2:] == ["--list"] for call in calls if call[0] == "child")


def test_workflow_runs_preflight_immediately_after_executable_preparation_and_keeps_full_gate():
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    names = [step.get("name") for step in steps]
    prepare = names.index("Prepare database contract executables")
    timeout = names.index("Preflight timeout published worker parity")
    body = names.index("Preflight body-timeout published worker parity")
    preflight = names.index("Preflight mixed-roster published worker parity")
    databases = names.index("Create isolated Rust contract databases")
    full = names.index("Run isolated database contract suites concurrently")
    assert prepare + 1 == timeout
    assert timeout + 1 == body
    assert body + 1 == preflight < databases < full
    assert steps[timeout]["working-directory"] == "rust"
    assert steps[timeout]["shell"] == "bash"
    assert steps[timeout]["run"] == (
        "bash ../scripts/ci/run-published-canvas-contracts.sh timeout-preflight"
    )
    assert steps[preflight]["working-directory"] == "rust"
    assert steps[body]["working-directory"] == "rust"
    assert steps[body]["shell"] == "bash"
    assert steps[body]["run"] == (
        "bash ../scripts/ci/run-published-canvas-contracts.sh body-timeout-preflight"
    )
    assert (
        steps[preflight]["run"]
        == "bash ../scripts/ci/run-published-canvas-contracts.sh mixed-roster-preflight"
    )
    assert steps[full]["run"] == "python3 ../scripts/ci/run-db-contract-groups.py"
    for index in (timeout, body, preflight, full):
        assert "if" not in steps[index]
        assert not steps[index].get("continue-on-error", False)
    images = workflow["jobs"]["test-rust-service-images"]["steps"]
    gate_index = next(
        index
        for index, step in enumerate(images)
        if step.get("name") == "Verify captured worker rollback launch configuration"
    )
    gate = images[gate_index]
    assert gate["run"] == "python3 scripts/test_beta_worker_launch_compose.py"
    assert "if" not in gate and not gate.get("continue-on-error", False)
    builds = [
        index
        for index, step in enumerate(images)
        if step.get("uses", "").startswith("docker/build-push-action@")
    ]
    assert builds and gate_index < min(builds)


def test_database_group_owner_still_invokes_default_full_mode(tmp_path, monkeypatch):
    module = runpy.run_path(str(ROOT / "scripts/ci/run-db-contract-groups.py"))
    observed = {}

    def groups(commands, directory):
        observed.update(commands)
        for name in commands:
            (directory / f"{name}.log").write_text(
                "synthetic result\n", encoding="utf-8"
            )
        return dict.fromkeys(commands, 0)

    namespace = module["main"].__globals__
    monkeypatch.setitem(namespace, "run_groups", groups)
    monkeypatch.setitem(
        namespace,
        "tempfile",
        SimpleNamespace(TemporaryDirectory=lambda **kwargs: nullcontext(str(tmp_path))),
    )
    assert module["main"]() == 0
    assert observed["published-canvas"] == ["bash", str(SCRIPT)]
    assert "rust-db" in observed
