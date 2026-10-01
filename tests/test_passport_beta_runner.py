"""Protect the shared beta Docker host from misrouted passport jobs."""

import json
import sys
from pathlib import Path

import pytest
import yaml

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from check_passport_beta_runner import (  # noqa: E402
    HISTORICAL_EXIT_CODES,
    NO_HEALTHCHECK_PRODUCTION,
    REQUIRED_PRODUCTION,
    check_disposable_quarantine,
    check_production_baseline,
    production_inventory,
)


def fake_docker(all_containers=(), running_containers=(), networks=(), volumes=(),
                inspect_states=None):
    inventories = {
        ("ps", "-a"): all_containers,
        ("ps", "-a", "--no-trunc"): all_containers,
        ("ps",): running_containers,
        ("network", "ls"): networks,
        ("volume", "ls"): volumes,
    }

    def run(*args):
        if args[0] == "inspect":
            assert args[1:3] == (
                "--format", "{{.Id}}|{{.State.StartedAt}}|{{.RestartCount}}")
            states = inspect_states or {}
            return "\n".join(
                f"{container_id}|{states.get(container_id, ('2026-09-01T00:00:00Z', '0'))[0]}"
                f"|{states.get(container_id, ('2026-09-01T00:00:00Z', '0'))[1]}"
                for container_id in args[3:])
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


def production_containers():
    running = tuple({
        "Names": name, "ID": name + "-id", "State": "running",
        "Status": "Up 1 minute", "HealthStatus": (
            "none" if name in NO_HEALTHCHECK_PRODUCTION else "healthy"),
    } for name in sorted(REQUIRED_PRODUCTION))
    stopped = tuple({
        "Names": name, "ID": name + "-id", "State": "exited",
        "Status": f"Exited ({code}) 3 weeks ago", "HealthStatus": "none",
    } for name, code in sorted(HISTORICAL_EXIT_CODES.items()))
    return running + stopped


def test_production_inventory_rejects_a_stopped_container():
    all_containers = (*production_containers(), {
        "Names": "marty-selfhost-prod-worker-1", "ID": "worker-id",
        "State": "exited", "Status": "Exited (0) 1 minute ago",
        "HealthStatus": "none",
    })
    with pytest.raises(RuntimeError, match="Production container inventory changed"):
        production_inventory(fake_docker(all_containers))


def test_production_inventory_allows_existing_completed_and_retired_containers():
    inventory = production_inventory(fake_docker(production_containers()))
    assert set(inventory) == REQUIRED_PRODUCTION | set(HISTORICAL_EXIT_CODES)
    assert inventory["marty-selfhost-prod-issuance-migrations-1"]["ExitCode"] == "1"
    containers = list(production_containers())
    for item in containers:
        if item["Names"] in NO_HEALTHCHECK_PRODUCTION:
            item["HealthStatus"] = ""
    assert production_inventory(fake_docker(containers))


def test_production_inventory_rejects_missing_runtime_and_new_failure():
    containers = list(production_containers())
    containers = [item for item in containers if item["Names"] != "marty-selfhost-prod-auth-1"]
    with pytest.raises(RuntimeError, match="runtime inventory changed"):
        production_inventory(fake_docker(containers))
    containers = [item for item in production_containers()
                  if item["Names"] != "marty-selfhost-prod-billing-1"]
    with pytest.raises(RuntimeError, match="Production container inventory changed"):
        production_inventory(fake_docker(containers))
    containers = list(production_containers())
    stopped = next(item for item in containers if item["Names"].endswith("db-migrate-1"))
    stopped["Status"] = "Exited (1) 1 minute ago"
    with pytest.raises(RuntimeError, match="exit state changed"):
        production_inventory(fake_docker(containers))


def test_production_baseline_rejects_replacement_and_health_change(tmp_path):
    inventory = production_inventory(fake_docker(production_containers()))
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"schema": "marty.passport-beta-runner-host/v1",
                                    "production_identity": inventory}), encoding="utf-8")
    check_production_baseline(inventory, baseline)
    changed = {name: dict(item) for name, item in inventory.items()}
    changed["marty-selfhost-prod-auth-1"]["ID"] = "replacement-id"
    with pytest.raises(RuntimeError, match="identity or state changed"):
        check_production_baseline(changed, baseline)
    restarted = production_inventory(fake_docker(
        production_containers(), inspect_states={
            "marty-selfhost-prod-auth-1-id": ("2026-10-01T00:00:00Z", "1"),
        }))
    with pytest.raises(RuntimeError, match="identity or state changed"):
        check_production_baseline(restarted, baseline)


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
