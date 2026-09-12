"""Configuration/comparison/ownership tests; packaged runtime is a separate gate."""

import importlib
import json
from pathlib import Path
import subprocess

import pytest


@pytest.fixture
def startup(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("test_canvas_worker_image_startup")


def test_every_reference_case_is_used_in_each_configuration_mode(startup):
    spec = startup.contract("canvas-worker-image-startup-scenarios.json")
    cases = startup.contract(spec["startup_scenarios"])["cases"]
    references = startup.contract(spec["startup_reference"])["cases"]
    assert len(cases) == len(references) == 8
    assert {case["name"] for case in cases} == {case["name"] for case in references}
    assert [mode["name"] for mode in spec["modes"]] == [
        "direct",
        "files_template",
        "selected_environment",
    ]
    identities = set()
    for mode in spec["modes"]:
        for case in cases:
            identity, environment = startup.configuration(case, mode)
            identities.add(identity)
            assert environment["SERVICE_NAME"] in {
                "canvas_sync_worker",
                "canvas-sync-worker",
            }
            assert "CANVAS_SYNC_PROCESSOR" not in environment
            assert environment["CANVAS_SYNC_WORKER_POLL_SECONDS"] == "60"
            assert all(
                environment[key] == value for key, value in case["environment"].items()
            )
            if mode["name"] == "files_template":
                assert "DATABASE_URL" not in environment
                assert "${MARTY_DB_PASSWORD}" in environment["DATABASE_URL_TEMPLATE"]
                for key in startup.SECRETS:
                    assert key not in environment
                    assert environment[f"{key}_FILE"] == f"/synthetic-secrets/{key}"
            elif mode["name"] == "selected_environment":
                assert "INTEGRATION_SECRET_MASTER_KEY" not in environment
                assert "INTEGRATION_SECRET_MASTER_KEY_FILE" not in environment
                selected = environment["INTEGRATION_SECRET_MASTER_KEY_ENV"]
                assert environment[selected] == startup.MASTER_KEY
            else:
                assert (
                    environment["INTEGRATION_SECRET_MASTER_KEY"] == startup.MASTER_KEY
                )
    assert len(identities) == 24


@pytest.mark.parametrize("mutation", ["exit", "alive", "job", "heartbeat", "extra"])
def test_comparison_does_not_relax_startup_observations(startup, mutation):
    expected = startup.contract("canvas-worker-startup-oracle.json")["cases"][0]
    native = {**expected, "exit_code_after_interrupt": 130}
    startup.assert_observation(native, expected)
    if mutation == "exit":
        native["exit_code_after_interrupt"] = 0
    elif mutation == "alive":
        native["alive_after_idle"] = False
    elif mutation == "job":
        native["job_count"] = 1
    elif mutation == "heartbeat":
        native["heartbeat"] = None
    else:
        native["unexpected"] = True
    with pytest.raises(AssertionError):
        startup.assert_observation(native, expected)


@pytest.mark.parametrize("failure", [None, "start", "query", "comparison"])
def test_packaged_worker_is_cleaned_up_on_all_observation_paths(
    startup, monkeypatch, tmp_path, failure
):
    owner = importlib.import_module("test_canvas_worker_image_entrypoint")
    expected = startup.contract("canvas-worker-startup-oracle.json")["cases"][0]
    case = startup.contract("canvas-worker-startup-scenarios.json")["cases"][0]
    mode = startup.contract("canvas-worker-image-startup-scenarios.json")["modes"][0]
    owned_id = "b" * 64
    calls = []

    def docker(*arguments, **options):
        calls.append((arguments, options))
        operation = arguments[0]
        if operation == "create":
            return owned_id
        if (operation == "start" and failure == "start") or (
            operation == "exec" and failure == "query"
        ):
            raise subprocess.CalledProcessError(1, ["docker", operation])
        if operation == "inspect":
            return "true"
        if operation == "exec":
            if "count(*)" in arguments[-1]:
                return "1" if failure == "comparison" else "0"
            return json.dumps(expected["heartbeat"])
        if operation == "wait":
            return "130"
        return ""

    monkeypatch.setattr(owner, "docker", docker)
    monkeypatch.setattr(startup, "docker", docker)
    if failure:
        with pytest.raises((subprocess.CalledProcessError, AssertionError)):
            startup.exercise(
                "synthetic-image", "a" * 64, tmp_path, case, mode, expected
            )
    else:
        startup.exercise("synthetic-image", "a" * 64, tmp_path, case, mode, expected)
        assert (("kill", "--signal=SIGINT", owned_id), {}) in calls
    assert calls[-1][0] == ("rm", "--force", owned_id)
    create = calls[0][0]
    assert "--publish" not in create
    assert create[create.index("--network") + 1] == "container:" + "a" * 64
    assert "--no-healthcheck" in create


def test_ci_runs_both_image_preflight_and_database_startup():
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert (
        "python3 scripts/test_canvas_worker_image_entrypoint.py marty-issuance:ci"
        in workflow
    )
    assert (
        "python3 scripts/test_canvas_worker_image_startup.py marty-issuance:ci"
        in workflow
    )


def test_wait_stops_at_its_deadline(startup, monkeypatch):
    ticks = iter([0, 0, 2])
    sleeps = []
    monkeypatch.setattr(startup.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(startup.time, "sleep", sleeps.append)
    with pytest.raises(
        AssertionError, match="Timed out waiting for synthetic heartbeat"
    ):
        startup.wait_for(lambda: None, "synthetic heartbeat", seconds=1)
    assert sleeps == [0.1]
