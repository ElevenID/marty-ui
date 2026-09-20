"""Mandatory, narrowly scoped synthetic-container failure artifact boundary."""

from copy import deepcopy
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PREPARE = "Prepare owned runtime failure diagnostics"
UPLOAD = "Preserve synthetic runtime failure diagnostics"


def steps():
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"][
        "test-rust-services"
    ]["steps"]


def validate(items):
    names = [item.get("name") for item in items]
    assert names.count(PREPARE) == names.count(UPLOAD) == 1
    before, suite, after = (
        names.index(PREPARE),
        names.index("Run isolated database contract suites concurrently"),
        names.index(UPLOAD),
    )
    assert before < suite < after
    prepare, upload = items[before], items[after]
    assert set(prepare) == {"name", "shell", "run"}
    assert prepare["shell"] == "bash"
    assert (
        'diagnostics="$RUNNER_TEMP/marty-owned-runtime-diagnostics"' in prepare["run"]
    )
    assert 'mkdir -m 700 "$diagnostics"' in prepare["run"]
    assert "set -o noclobber" in prepare["run"]
    assert "MARTY_RUNTIME_DIAGNOSTICS_OWNER" in prepare["run"]
    assert set(upload) == {"name", "if", "uses", "with"}
    assert upload["if"] == "always()"
    assert (
        upload["uses"]
        == "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    )
    assert upload["with"] == {
        "name": "owned-runtime-failure-diagnostics-${{ github.run_id }}-${{ github.run_attempt }}",
        "path": "${{ runner.temp }}/marty-owned-runtime-diagnostics/*.*",
        "if-no-files-found": "ignore",
        "retention-days": 3,
    }


@pytest.mark.parametrize(
    "fault",
    [None, "missing", "late", "optional", "conditional", "broad", "long", "hidden"],
)
def test_diagnostic_workflow_is_mandatory_and_upload_scope_is_closed(fault):
    items = deepcopy(steps())
    validate(items)
    prepare = next(v for v in items if v.get("name") == PREPARE)
    upload = next(v for v in items if v.get("name") == UPLOAD)
    if fault == "missing":
        items.remove(prepare)
    elif fault == "late":
        items.remove(prepare)
        items.append(prepare)
    elif fault == "optional":
        prepare["continue-on-error"] = True
    elif fault == "conditional":
        upload["if"] = "success()"
    elif fault == "broad":
        upload["with"]["path"] = "${{ runner.temp }}/**"
    elif fault == "long":
        upload["with"]["retention-days"] = 90
    elif fault == "hidden":
        upload["with"]["include-hidden-files"] = True
    if fault:
        with pytest.raises((AssertionError, ValueError)):
            validate(items)


def test_actual_setup_creates_owned_directory_and_refuses_reuse(tmp_path):
    if os.name == "nt":
        git = shutil.which("git")
        assert git
        bash = Path(git).resolve().parents[1] / "bin/bash.exe"
    else:
        bash = Path(shutil.which("bash") or "missing")
    source = next(v["run"] for v in steps() if v.get("name") == PREPARE)
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
    }
    environment.update(RUNNER_TEMP=".", GITHUB_ENV="published-env")
    if os.name == "nt":
        # Windows/OneDrive cannot apply POSIX mkdir mode 0700. Validate that
        # exact invocation at a closed port; Linux executes the real mkdir.
        environment["TEST_PYTHON"] = sys.executable
        source = (
            "mkdir() {\n"
            '[[ "$#" == 3 && "$1" == -m && "$2" == 700 ]] || return 90\n'
            '"$TEST_PYTHON" -c \'import os, sys; os.mkdir(sys.argv[1])\' "$3"\n'
            '}\npython3() { "$TEST_PYTHON" "$@"; }\n' + source
        )
    result = subprocess.run(
        [str(bash), "-c", source],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, "Synthetic diagnostic setup failed"
    directory = tmp_path / "marty-owned-runtime-diagnostics"
    marker = (directory / ".owner").read_text()
    assert str(uuid.UUID(marker)) == marker and uuid.UUID(marker).version == 4
    assert sorted(v.name for v in directory.iterdir()) == [".owner"]
    published = (tmp_path / "published-env").read_text()
    assert (
        published
        == f"MARTY_RUNTIME_DIAGNOSTICS=./marty-owned-runtime-diagnostics\nMARTY_RUNTIME_DIAGNOSTICS_OWNER={marker}\n"
    )
    result = subprocess.run(
        [str(bash), "-c", source],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode != 0
    assert (directory / ".owner").read_text() == marker
    assert (tmp_path / "published-env").read_text() == published


def test_both_stream_capture_is_bounded_before_failure_artifact_write():
    support = ROOT / "rust/services/issuance/tests/support"
    source = (support / "base_runtime_container.rs").read_text()
    assert (
        "let diagnostics = super::runtime_failure_diagnostics::Diagnostics::from_environment()?;"
        in source
    )
    assert source.index("Diagnostics::from_environment()?") < source.index(
        "container.creation_attempted = true"
    )
    assert "docker_output_with_timeout(" in source
    assert "super::runtime_failure_diagnostics::STREAM_LIMIT" in source
    assert "&output.stdout," in source and "&output.stderr," in source
    assert (
        "mod runtime_failure_diagnostics;"
        in (support.parent / "canvas_published_schema_contract.rs").read_text()
    )
