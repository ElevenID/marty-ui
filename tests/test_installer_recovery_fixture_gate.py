"""The unprivileged CI gate must execute its entire named fixture set.

Synthetic executables below test the gate's selection/result accounting only;
the actual Rust fixture execution is a separate required CI step.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts/ci/qualify-installer-recovery-fixtures.sh"
UNPRIVILEGED = os.name == "posix" and os.geteuid() != 0 and os.getegid() != 0


def test_contracts_lane_runs_the_default_recorded_library_after_compilation():
    steps = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]["test-rust-services"]["steps"]
    [gate] = [step for step in steps if step.get("name") == "Require unprivileged installer recovery fixtures"]
    compile_index = next(index for index, step in enumerate(steps) if step.get("name") == "Compile reusable Rust test executables")
    assert steps.index(gate) > compile_index
    assert gate["if"] == "matrix.lane == 'contracts'"
    assert gate["timeout-minutes"] == 10
    assert "continue-on-error" not in gate
    assert gate["run"] == 'bash scripts/ci/qualify-installer-recovery-fixtures.sh "$RUNNER_TEMP/rust-test-artifacts.json"'
    subprocess.run(["bash", "-n", str(GATE)], check=True)


STUB = r'''
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
Path(os.environ["FIXTURE_GATE_CALLS"]).write_text(json.dumps(args))
assert args[-5:] == ["--ignored", "--exact", "--test-threads=1", "--color", "never"]
cases = args[:-5]
fault = os.environ["FIXTURE_GATE_FAULT"]
if fault == "zero":
    print("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 900 filtered out; finished in 0.0s")
    raise SystemExit(0)
print(f"running {len(cases)} tests")
for index, case in enumerate(cases):
    if index == len(cases) - 1:
        if fault == "missing":
            continue
        if fault == "wrong":
            case = "wrong_case"
        if fault == "ignored":
            print(f"test {case} ... ignored")
            continue
    print(f"test {case} ... ok")
if fault == "extra":
    print("test unrequested_case ... ok")
summary = f"test result: ok. {len(cases)} passed; 0 failed; 0 ignored; 0 measured; 900 filtered out; finished in 0.1s"
if fault != "no-summary":
    print(summary)
if fault == "two-summaries":
    print(summary)
raise SystemExit(1 if fault == "exit" else 0)
'''


def run_gate(tmp_path, *, fault="none", artifact_change=None):
    source = tmp_path / "source"
    script = source / "scripts/ci" / GATE.name
    script.parent.mkdir(parents=True)
    shutil.copyfile(GATE, script)
    binary = source / "rust/target/debug/deps/catalog-fixtures"
    binary.parent.mkdir(parents=True)
    binary.write_text(f"#!{sys.executable}\n" + STUB)
    binary.chmod(0o700)
    row = dict(reason="compiler-artifact", manifest_path=str(source / "rust/crates/deployment-catalog/Cargo.toml"),
               target=dict(name="marty_deployment_catalog", kind=["lib"]), profile=dict(test=True),
               features=[], executable=str(binary))
    rows = [row, dict(reason="build-finished", success=True)]
    if artifact_change is not None:
        artifact_change(rows)
    artifact = tmp_path / "cargo-artifacts.json"
    artifact.write_text("".join(json.dumps(item) + "\n" for item in rows))
    calls = tmp_path / "calls.json"
    result = subprocess.run(["bash", str(script), str(artifact)], cwd=source,
                            env={**os.environ, "RUNNER_TEMP": str(tmp_path),
                                 "FIXTURE_GATE_CALLS": str(calls), "FIXTURE_GATE_FAULT": fault},
                            text=True, capture_output=True, timeout=20)
    return result, json.loads(calls.read_text()) if calls.exists() else None


@pytest.mark.skipif(not UNPRIVILEGED, reason="gate intentionally requires a real ordinary UID/GID")
def test_exact_named_cases_are_executed_under_real_no_new_privileges(tmp_path):
    result, calls = run_gate(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    text = GATE.read_text()
    cases = re.search(r"installer_cases=\(\n(.*?)\n\)", text, re.S).group(1).split()
    assert len(cases) == 14 and len(set(cases)) == 14
    assert calls == cases + ["--ignored", "--exact", "--test-threads=1", "--color", "never"]


@pytest.mark.skipif(not UNPRIVILEGED, reason="gate intentionally requires a real ordinary UID/GID")
@pytest.mark.parametrize("fault", ["zero", "missing", "wrong", "ignored", "extra", "no-summary", "two-summaries", "exit"])
def test_zero_partial_unexpected_or_unsuccessful_execution_cannot_pass(tmp_path, fault):
    result, calls = run_gate(tmp_path, fault=fault)
    assert calls is not None
    assert result.returncode != 0


@pytest.mark.skipif(not UNPRIVILEGED, reason="gate intentionally requires a real ordinary UID/GID")
@pytest.mark.parametrize("change", [
    lambda rows: rows[0].update(features=["installer-development"]),
    lambda rows: rows[0].update(profile=dict(test=False)),
    lambda rows: rows[0]["target"].update(kind=["bin"]),
    lambda rows: rows[0].update(manifest_path="/unrelated/Cargo.toml"),
    lambda rows: rows[1].update(success=False),
    lambda rows: rows.pop(),
    lambda rows: rows.insert(1, {**rows[0], "executable": rows[0]["executable"] + "-old"}),
    lambda rows: rows[0].update(executable="/bin/true"),
])
def test_wrong_ambiguous_or_unsigned_build_never_executes(tmp_path, change):
    result, calls = run_gate(tmp_path, artifact_change=change)
    assert result.returncode != 0
    assert calls is None
