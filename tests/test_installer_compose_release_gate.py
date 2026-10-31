"""Keep both signed-release paths on the supported, actually executed parser gate."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts/ci/qualify-installer-compose-model.sh"
CASES = (
    "native_filtering_merge_and_restart_layer_semantics",
    "packaged_source_installer_layers_keep_native_dependencies_and_exclude_setup_on_restart",
)
PINS = {
    "x86_64": "47737f4236e6d3ccea7291995203f8f018058783b4c3a9469119811a0b5db8c0",
    "aarch64": "42cfa75f51ad0ccf290bad37899e0038a8c10a0069e85233ecc1d53e3ff1347d",
}


@pytest.mark.parametrize(
    ("workflow", "job", "target"),
    [
        ("nightly-release.yml", "prepare-installation", '"$RUNNER_TEMP/tools"'),
        ("cd.yml", "build-operator-catalog", '"$GITHUB_WORKSPACE/rust/target"'),
    ],
)
def test_both_release_paths_require_the_shared_native_gate(workflow, job, target):
    text = (ROOT / ".github/workflows" / workflow).read_text()
    steps = yaml.safe_load(text)["jobs"][job]["steps"]
    [gate] = [s for s in steps if s.get("name") == "Require real Compose installer model compatibility"]
    command = f"bash scripts/ci/qualify-installer-compose-model.sh {target}"
    if workflow == "cd.yml":
        expected = [
            "set -euo pipefail",
            "source scripts/ci/rust_contract_execution.sh",
            "run_timed installer_compose_model " + command,
        ]
    else:
        expected = ["set -euo pipefail", command]
    assert gate["run"].strip().splitlines() == expected
    assert "if" not in gate and "continue-on-error" not in gate
    assert "installer_application_model" not in text
    target_source = ROOT / "rust/crates/deployment-catalog/tests/installer_compose_native.rs"
    native = target_source.read_text()
    for case in CASES:
        assert len(re.findall(rf"^fn {case}\(\)", native, re.MULTILINE)) == 1
    assert native.count("assert_actual_installer_layers(&executable, &bundle,") == 2


def test_gate_keeps_independent_architecture_pins_and_checks_before_execution():
    script = GATE.read_text()
    for pin in PINS.values():
        assert pin in script
    assert "releases/download/v5.6.1/docker-compose-linux-$installer_compose_arch" in script
    assert script.index("sha256sum --check --strict") < script.index('chmod 700 "$installer_compose"')
    assert script.index('chmod 700 "$installer_compose"') < script.index('"$installer_compose" version --short')
    assert '"${installer_compose_version#v}" == 5.6.1' in script
    assert "--test installer_compose_native" in script
    assert '--ignored --exact "$installer_case"' in script
    assert "docker compose" not in script and "--features" not in script
    subprocess.run(["bash", "-n", str(GATE)], check=True)


STUB = r'''
import json
import os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
fault = os.environ["GATE_FAULT"]
with Path(os.environ["GATE_CALLS"]).open("a") as calls:
    calls.write(json.dumps({"tool": name, "args": args}) + "\n")
if name == "uname":
    print("Linux" if args == ["-s"] else os.environ["GATE_ARCH"])
elif name == "curl":
    if fault == "download":
        raise SystemExit(22)
    target = Path(args[args.index("--output") + 1])
    assert args[-1].endswith("v5.6.1/docker-compose-linux-" + os.environ["GATE_ARCH"])
    version = "5.6.0" if fault == "version" else "5.6.1"
    target.write_text("#!/bin/sh\nprintf '%s\\n' " + version + "\n")
elif name == "sha256sum":
    assert sys.stdin.read().split()[0] == os.environ["GATE_EXPECTED_PIN"]
    if fault == "checksum":
        raise SystemExit(1)
elif name == "cargo":
    assert args[0:2] == ["test", "--locked"]
    assert args[args.index("--test") + 1] == "installer_compose_native"
    assert "--ignored" in args and "--exact" in args
    assert os.environ["MARTY_INSTALLER_COMPOSE_EXECUTABLE"].endswith("/docker-compose")
    case = args[args.index("--exact") + 1]
    second = case.startswith("packaged_source_")
    # Fail the second invocation so a prior passing test cannot mask it.
    if second and fault == "cargo_failure":
        print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.1s")
        raise SystemExit(101)
    if second and fault == "zero_selection":
        print("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.0s")
    elif second and fault == "ignored":
        print(f"test {case} ... ignored")
        print("test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2 filtered out; finished in 0.0s")
    else:
        print(f"test {'wrong_case' if second and fault == 'wrong_case' else case} ... ok")
        if not (second and fault == "missing_summary"):
            print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.1s")
elif name == "tee":
    content = sys.stdin.read()
    Path(args[0]).write_text(content)
    print(content, end="")
    if fault == "log_failure":
        raise SystemExit(1)
else:
    raise AssertionError(name)
'''


def run_gate(tmp_path, arch="x86_64", fault="none", optimize=""):
    executables = tmp_path / "bin"
    executables.mkdir()
    for name in ("uname", "curl", "sha256sum", "cargo", "tee"):
        path = executables / name
        path.write_text(f"#!{sys.executable}\n" + STUB)
        path.chmod(0o700)
    calls = tmp_path / "calls.jsonl"
    result = subprocess.run(
        ["bash", str(GATE), str(tmp_path / "cargo-target")],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": str(executables) + os.pathsep + os.environ["PATH"],
            "RUNNER_TEMP": str(tmp_path),
            "GATE_ARCH": arch,
            "GATE_EXPECTED_PIN": PINS.get(arch, "unsupported"),
            "GATE_FAULT": fault,
            "GATE_CALLS": str(calls),
            "PYTHONOPTIMIZE": optimize,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    return result, [json.loads(line) for line in calls.read_text().splitlines()]


@pytest.mark.parametrize("arch", PINS)
def test_supported_architectures_execute_both_exact_cases(tmp_path, arch):
    result, calls = run_gate(tmp_path, arch=arch)
    assert result.returncode == 0, result.stdout + result.stderr
    cargo = [call["args"] for call in calls if call["tool"] == "cargo"]
    assert [args[args.index("--exact") + 1] for args in cargo] == list(CASES)
    order = [call["tool"] for call in calls]
    assert order.index("curl") < order.index("sha256sum") < order.index("cargo")


@pytest.mark.parametrize("fault", ["download", "checksum", "version"])
def test_unverified_or_wrong_baseline_never_reaches_native_tests(tmp_path, fault):
    result, calls = run_gate(tmp_path, fault=fault)
    assert result.returncode != 0
    assert not any(call["tool"] == "cargo" for call in calls)


def test_unsupported_architecture_never_downloads_or_executes(tmp_path):
    result, calls = run_gate(tmp_path, arch="riscv64")
    assert result.returncode != 0
    assert not any(call["tool"] in {"curl", "cargo"} for call in calls)


@pytest.mark.parametrize(
    "fault", ["cargo_failure", "zero_selection", "ignored", "wrong_case", "missing_summary", "log_failure"]
)
def test_each_case_requires_observed_success_and_preserved_log(tmp_path, fault):
    result, _ = run_gate(tmp_path, fault=fault)
    assert result.returncode != 0, result.stdout + result.stderr


def test_optimized_python_cannot_disable_zero_selection_guard(tmp_path):
    result, _ = run_gate(tmp_path, fault="zero_selection", optimize="1")
    assert result.returncode != 0, result.stdout + result.stderr
