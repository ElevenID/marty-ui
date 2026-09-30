"""Protect the shared beta Docker host from misrouted passport jobs."""

import json
import sys
from pathlib import Path

import pytest
import yaml

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from check_passport_beta_runner import (  # noqa: E402
    check_disposable_quarantine,
    production_inventory,
)


def fake_docker(all_containers=(), running_containers=(), networks=(), volumes=()):
    inventories = {
        ("ps", "-a"): all_containers,
        ("ps",): running_containers,
        ("network", "ls"): networks,
        ("volume", "ls"): volumes,
    }

    def run(*args):
        assert args[-2:] == ("--format", "{{json .}}")
        return "\n".join(json.dumps(item) for item in inventories[args[:-2]])

    return run


def test_quarantine_rejects_a_leftover_disposable_container(tmp_path):
    runner = fake_docker(all_containers=(
        {"Names": "marty-passport-fence-disposable-20260929", "Labels": ""},
    ))
    with pytest.raises(RuntimeError, match="containers=1"):
        check_disposable_quarantine(runner, tmp_path)


def test_quarantine_rejects_a_labeled_network_without_matching_name(tmp_path):
    runner = fake_docker(networks=(
        {"Name": "unrelated-name",
         "Labels": "com.docker.compose.project=marty-passport-acceptance-123"},
    ))
    with pytest.raises(RuntimeError, match="networks=1"):
        check_disposable_quarantine(runner, tmp_path)


def test_production_inventory_rejects_a_stopped_container():
    names = (
        "marty-selfhost-prod-edge-1",
        "marty-selfhost-prod-gateway-1",
        "marty-selfhost-prod-postgres-1",
        "marty-selfhost-prod-cloudflared-1",
    )
    running = tuple({"Names": name} for name in names)
    all_containers = (*running, {"Names": "marty-selfhost-prod-worker-1"})
    with pytest.raises(RuntimeError, match="production container is stopped"):
        production_inventory(fake_docker(all_containers, running))


def test_passport_jobs_have_dedicated_label_and_in_job_preflight():
    workflows = Path(__file__).resolve().parents[1] / ".github/workflows"
    passport_jobs = 0
    for path in workflows.glob("passport-*.yml"):
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in value.get("jobs", {}).values():
            labels = job.get("runs-on")
            if not isinstance(labels, list) or "self-hosted" not in labels:
                continue
            passport_jobs += 1
            assert labels == ["self-hosted", "linux", "x64", "passport-beta-wsl2"]
            first_script = next(step["run"] for step in job["steps"] if "run" in step)
            assert "python3 scripts/check_passport_beta_runner.py" in first_script
    assert passport_jobs == 10
