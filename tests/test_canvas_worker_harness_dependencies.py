"""Exercise the CI dependency lane without installing packages or opening a DB."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
STEP = "Prepare isolated Canvas worker harness dependencies"
PINS = ("SQLAlchemy==2.0.52", "greenlet==3.4.0", "typing_extensions==4.15.0")


def workflow_steps():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    return workflow["jobs"]["test-rust-services"]["steps"]


def setup_source():
    return next(step["run"] for step in workflow_steps() if step.get("name") == STEP)


def smoke_source():
    source = setup_source()
    return source.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]


def test_dependency_setup_precedes_compile_and_all_native_preflights():
    steps = workflow_steps()
    names = [step.get("name") for step in steps]
    setup = names.index(STEP)
    assert setup < names.index("Compile reusable Rust test executables")
    preflights = [
        index
        for index, step in enumerate(steps)
        if "run-published-canvas-contracts.sh" in step.get("run", "")
    ]
    assert len(preflights) == 3 and all(setup < index for index in preflights)
    assert setup < names.index("Run isolated database contract suites concurrently")
    interpreter = [
        step
        for step in steps[:setup]
        if step.get("uses", "").startswith("actions/setup-python@")
    ]
    assert len(interpreter) == 1
    assert interpreter[0]["with"]["python-version"] == "3.12"
    assert steps[setup]["shell"] == "bash"


@pytest.fixture
def setup_shell(tmp_path):
    if os.name == "nt":
        git = shutil.which("git")
        assert git is not None
        bash = Path(git).resolve().parents[1] / "bin/bash.exe"
    else:
        bash = Path(shutil.which("bash") or "missing-bash")
    assert bash.is_file(), "Executable Bash is mandatory for the CI dependency contract"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    (tmp_path / "runner").mkdir()
    python = fake_bin / "python3"
    python.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
printf 'venv\\n' >> "$TEST_LOG"
[[ "$#" == 3 && "$1" == -m && "$2" == venv ]] || exit 90
[[ "$TEST_FAILURE" != venv ]] || exit 11
mkdir -p "$3/bin"
cp "$TEST_VENV_PYTHON" "$3/bin/python"
chmod +x "$3/bin/python"
""",
        encoding="utf-8",
        newline="\n",
    )
    python.chmod(0o755)
    venv_python = tmp_path / "venv-python"
    venv_python.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == -m && "$2" == pip ]]; then
  printf 'install' >> "$TEST_LOG"
  for argument in "$@"; do printf '|%s' "$argument" >> "$TEST_LOG"; done
  printf '\\n' >> "$TEST_LOG"
  [[ "$TEST_FAILURE" != install ]] || exit 12
elif [[ "$#" == 3 && "$1" == -I && "$2" == - && "$3" == synthetic-workspace ]]; then
  printf 'smoke\\n' >> "$TEST_LOG"
  cat > "$TEST_SMOKE"
  [[ "$TEST_FAILURE" != smoke ]] || exit 13
else
  exit 90
fi
""",
        encoding="utf-8",
        newline="\n",
    )
    venv_python.chmod(0o755)
    script = tmp_path / "setup.sh"
    script.write_text(setup_source(), encoding="utf-8", newline="\n")
    environment = os.environ.copy()
    environment.update(
        PATH=str(fake_bin) + os.pathsep + environment.get("PATH", ""),
        RUNNER_TEMP="runner",
        GITHUB_WORKSPACE="synthetic-workspace",
        GITHUB_PATH="github-path",
        TEST_LOG="events",
        TEST_SMOKE="smoke.py",
        TEST_VENV_PYTHON="venv-python",
        TEST_FAILURE="none",
    )
    return bash, script, environment


@pytest.mark.parametrize(
    "failure,expected_events",
    [
        ("none", ["venv", "install", "smoke"]),
        ("venv", ["venv"]),
        ("install", ["venv", "install"]),
        ("smoke", ["venv", "install", "smoke"]),
    ],
)
def test_actual_setup_shell_is_closed_and_publishes_path_only_after_success(
    tmp_path, setup_shell, failure, expected_events
):
    bash, script, environment = setup_shell
    environment["TEST_FAILURE"] = failure
    result = subprocess.run(
        [str(bash), script.name],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    events = (tmp_path / "events").read_text().splitlines()
    assert [event.split("|", 1)[0] for event in events] == expected_events
    assert (result.returncode == 0) is (failure == "none")
    if "install" in expected_events:
        actual = next(event for event in events if event.startswith("install|")).split(
            "|"
        )[1:]
        assert actual == [
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--only-binary=:all:",
            "--no-deps",
            *PINS,
        ]
    if "smoke" in expected_events:
        assert (tmp_path / "smoke.py").read_text().rstrip() == smoke_source().rstrip()
    published = tmp_path / "github-path"
    if failure == "none":
        assert published.read_text() == "runner/canvas-worker-harness/bin\n"
    else:
        assert not published.exists()


def test_actual_isolated_smoke_imports_real_dependencies_and_frozen_controller():
    # CI installs into a venv. This offline regression uses the real packages
    # already provisioned for repository tests, without global/PYTHONPATH import
    # inheritance or fake modules. No provider run, DB driver, or Docker call.
    dependency_roots = set()
    for name in ("sqlalchemy", "greenlet", "typing_extensions"):
        spec = importlib.util.find_spec(name)
        assert spec is not None and spec.origin is not None
        path = Path(spec.origin)
        dependency_roots.add(
            str(path.parent.parent if spec.submodule_search_locations else path.parent)
        )
    bootstrap = (
        "import sys\n"
        f"sys.path.extend({sorted(dependency_roots)!r})\n"
        f"sys.argv = ['-', {str(ROOT)!r}]\n"
        f"exec(compile({smoke_source()!r}, '<workflow-body-harness-smoke>', 'exec'))\n"
    )
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-"],
        input=bootstrap,
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (
        result.stdout
        == "Native Canvas BODY harness imports and frozen inputs verified\n"
    )
    assert result.stderr == ""


def test_smoke_contains_no_capture_or_environment_mutation():
    import ast

    tree = ast.parse(smoke_source())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    controller_calls = [
        node.func.attr
        for node in calls
        if isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "controller"
    ]
    assert controller_calls == ["load_inputs"]
    # The immutable corpus and captured source inputs remain independently pinned.
    corpus = json.loads(
        (ROOT / "contracts/canvas-worker-body-timeout-oracle.json").read_bytes()
    )
    import hashlib

    for name, digest in corpus[0]["worker_body_timeout"][
        "capture_source_sha256"
    ].items():
        directory = "contracts" if name.endswith(".json") else "scripts"
        assert (
            hashlib.sha256(
                (ROOT / directory / name).read_text(encoding="utf-8").encode()
            ).hexdigest()
            == digest
        )
