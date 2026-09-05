"""Execute the workflow shell with local command doubles; never dispatch a run.

Rust's unit/CLI suites test semantic validation. This suite checks that the real
workflow passes the correct inputs, respects failures, and isolates private data.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("failure", ["", "download", "api", "validator", "token", "run_id"])
def test_private_intake_consumer_shell_is_ordered_and_fail_closed(tmp_path: Path, failure: str) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/e2e-tests.yml").read_text())
    steps = workflow["jobs"]["full-stack-credential-lifecycle"]["steps"]
    script = next(step["run"] for step in steps if step.get("name") == "Require completed private demo qualification")
    (tmp_path / "tests/artifacts").mkdir(parents=True)
    (tmp_path / "private temp").mkdir()
    if os.name == "nt":
        git = shutil.which("git")
        assert git is not None
        bash = str(Path(git).resolve().parents[1] / "bin/bash.exe")
    else:
        bash = shutil.which("bash")
    assert bash is not None and Path(bash).is_file(), "Bash is required for workflow contracts"

    # Functions shadow external commands: no network, cargo builds, or secrets.
    doubles = r'''
gh() {
  if [[ "$1 $2" == 'run download' ]]; then
    printf 'download\n' >> calls
    [[ "$TEST_FAILURE" != download ]] || return 11
    [[ "$#" == 9 && "$3" == "$DEMO_QUALIFICATION_RUN_ID" ]]
    [[ "$4" == --repo && "$5" == ElevenID/marty-demo-recorder ]]
    [[ "$6" == --name && "$7" == "demo-release-qualification-$RELEASE_VERSION" ]]
    [[ "$8" == --dir && "$9" == "$RUNNER_TEMP"/*/report ]]
    mkdir -p "$9"
    printf '{"privateMetadata":"private-value"}\n' > "$9/release-qualification.json"
  elif [[ "$1" == api ]]; then
    printf 'api\n' >> calls
    [[ "$TEST_FAILURE" != api ]] || return 12
    [[ "$#" == 2 && "$2" == "repos/ElevenID/marty-demo-recorder/actions/runs/$DEMO_QUALIFICATION_RUN_ID" ]]
    printf '{"privateMetadata":"private-value"}\n'
  else
    return 90
  fi
}
cargo() {
  printf 'validate\n' >> calls
  [[ "$#" == 19 ]]
  [[ "$1 $2 $3 $4 $5 $6 $7 $8 $9 ${10}" == 'run --locked --quiet --manifest-path rust/Cargo.toml -p marty-release-evidence --bin validate-demo-qualification --' ]]
  shift 10
  [[ "$1" == "$RUNNER_TEMP"/*/run.json && -f "$1" ]]
  [[ "$2" == "$RUNNER_TEMP"/*/report/release-qualification.json && -f "$2" ]]
  [[ "$3" == "$DEMO_QUALIFICATION_RUN_ID" && "$4" == "$DEMO_RECORDER_SHA" ]]
  [[ "$5" == "$RELEASE_VERSION" && "$6" == "$MARTY_UI_RELEASE_SHA" && "$7" == "$BETA_SOURCE_ID" ]]
  [[ "$8" == "$DEMO_DEPLOYMENT_MANIFEST_SHA256" && "$9" == "$STACK_MANIFEST_SHA256" ]]
  [[ "$TEST_FAILURE" != validator ]] || return 13
  printf '{"qualified":true,"fixtureOnly":true}\n'
}
'''
    env = dict(os.environ)
    env.update({
        "TEST_FAILURE": failure,
        "GH_TOKEN": "" if failure == "token" else "synthetic-token",
        "RUNNER_TEMP": "private temp",
        "DEMO_QUALIFICATION_RUN_ID": "invalid" if failure == "run_id" else "123",
        "DEMO_RECORDER_SHA": "3" * 40,
        "RELEASE_VERSION": "1.1.217",
        "MARTY_UI_RELEASE_SHA": "2" * 40,
        "BETA_SOURCE_ID": "1" * 40,
        "DEMO_DEPLOYMENT_MANIFEST_SHA256": "a" * 64,
        "STACK_MANIFEST_SHA256": "b" * 64,
    })
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-euo", "pipefail", "-c",
         doubles + "\n" + script + "\nprintf eligible > browser-eligible\n"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30,
    )
    assert (result.returncode == 0) == (failure == ""), result.stderr
    assert (tmp_path / "browser-eligible").exists() == (failure == "")
    expected_calls = {
        "": ["download", "api", "validate"], "download": ["download"],
        "api": ["download", "api"], "validator": ["download", "api", "validate"],
        "token": [], "run_id": [],
    }[failure]
    calls = tmp_path / "calls"
    assert (calls.read_text().splitlines() if calls.exists() else []) == expected_calls
    public_files = list((tmp_path / "tests/artifacts").rglob("*"))
    assert all(path.name == "demo-qualification.json" for path in public_files)
    for path in public_files:
        content = path.read_text()
        assert "private-value" not in content
        if failure:
            assert content == ""
    assert "private-value" not in result.stdout + result.stderr
    assert "synthetic-token" not in result.stdout + result.stderr
