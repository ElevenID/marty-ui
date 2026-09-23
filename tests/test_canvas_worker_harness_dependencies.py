"""Exercise the CI dependency lane without installing packages or opening a DB."""

import importlib.util
import copy
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
PINS = (
    "SQLAlchemy==2.0.52",
    "greenlet==3.4.0",
    "typing_extensions==4.15.0",
    "PyYAML==6.0.3",
)


def workflow_steps():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    return workflow["jobs"]["test-rust-services"]["steps"]


def setup_source():
    return next(step["run"] for step in workflow_steps() if step.get("name") == STEP)


def smoke_source():
    source = setup_source()
    return source.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]


def assert_dependency_setup(steps):
    names = [step.get("name") for step in steps]
    assert names.count(STEP) == 1
    setup = names.index(STEP)
    assert "if" not in steps[setup] and "continue-on-error" not in steps[setup]
    assert setup < names.index("Compile reusable Rust test executables")
    rendered = names.index("Prepare required rendered base executable acceptance")
    assert (
        setup
        < rendered
        < names.index("Run isolated database contract suites concurrently")
    )
    assert '"$(command -v python3)"' in steps[rendered]["run"]
    source = steps[setup]["run"]
    install = '"$RUNNER_TEMP/canvas-worker-harness/bin/python" -m pip install'
    smoke = '"$RUNNER_TEMP/canvas-worker-harness/bin/python" -I - "$GITHUB_WORKSPACE"'
    publish = (
        '''printf '%s\\n' "$RUNNER_TEMP/canvas-worker-harness/bin" >> "$GITHUB_PATH"'''
    )
    assert source.index(install) < source.index(smoke) < source.index(publish)
    assert "PyYAML==6.0.3" in source[source.index(install) : source.index(smoke)]
    assert "import yaml" in source[source.index(smoke) : source.index(publish)]
    assert 'assert yaml.__version__ == "6.0.3"' in source
    assert (
        'assert yaml.safe_load("services: {issuance-native: {command: []}}")' in source
    )
    preflight_name = "Preflight published worker parity in two isolated groups"
    assert names.count(preflight_name) == 1
    preflight = names.index(preflight_name)
    preflight_steps = [
        index
        for index, step in enumerate(steps)
        if "run-db-contract-groups.py preflights" in step.get("run", "")
        or "run-published-canvas-contracts.sh" in step.get("run", "")
    ]
    assert preflight_steps == [preflight]
    assert setup < preflight < names.index(
        "Run isolated database contract suites concurrently"
    )
    assert steps[preflight]["run"] == (
        "python3 ../scripts/ci/run-db-contract-groups.py preflights"
    )
    assert steps[preflight]["working-directory"] == "rust"
    assert steps[preflight]["shell"] == "bash"
    assert "if" not in steps[preflight]
    assert not steps[preflight].get("continue-on-error", False)
    interpreter = [
        step
        for step in steps[:setup]
        if step.get("uses", "").startswith("actions/setup-python@")
    ]
    assert len(interpreter) == 1
    assert interpreter[0]["with"]["python-version"] == "3.12"
    assert steps[setup]["shell"] == "bash"


def test_dependency_setup_precedes_compile_and_all_native_preflights():
    assert_dependency_setup(workflow_steps())


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "late",
        "optional",
        "conditional",
        "duplicate",
        "pin",
        "interpreter",
        "import",
        "yaml_parse",
        "extra_preflight_before_setup",
    ],
)
def test_renderer_dependency_guard_rejects_missing_or_ineffective_setup(mutation):
    steps = copy.deepcopy(workflow_steps())
    setup = next(step for step in steps if step.get("name") == STEP)
    if mutation == "missing":
        steps.remove(setup)
    elif mutation == "late":
        steps.remove(setup)
        steps.append(setup)
    elif mutation == "optional":
        setup["continue-on-error"] = True
    elif mutation == "conditional":
        setup["if"] = "false"
    elif mutation == "duplicate":
        steps.append(copy.deepcopy(setup))
    elif mutation == "pin":
        setup["run"] = setup["run"].replace("PyYAML==6.0.3", "")
    elif mutation == "interpreter":
        setup["run"] = setup["run"].replace(
            '"$RUNNER_TEMP/canvas-worker-harness/bin/python" -m pip', "python3 -m pip"
        )
    elif mutation == "import":
        setup["run"] = setup["run"].replace("import yaml", "")
    elif mutation == "extra_preflight_before_setup":
        steps.insert(
            0,
            {
                "name": "Unexpected direct Canvas preflight",
                "run": "bash ../scripts/ci/run-published-canvas-contracts.sh timeout-preflight",
            },
        )
    else:
        setup["run"] = setup["run"].replace(
            "assert yaml.safe_load", "assert disabled.safe_load"
        )
    with pytest.raises((AssertionError, ValueError)):
        assert_dependency_setup(steps)


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
    for name in ("sqlalchemy", "greenlet", "typing_extensions", "yaml"):
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
        == "Native Canvas BODY and lease-expiry harness imports and frozen inputs verified\n"
    )
    assert result.stderr == ""


def test_smoke_contains_no_capture_or_environment_mutation():
    import ast

    tree = ast.parse(smoke_source())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    for controller in ("controller", "expiry_controller"):
        controller_calls = [
            node.func.attr
            for node in calls
            if isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == controller
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
