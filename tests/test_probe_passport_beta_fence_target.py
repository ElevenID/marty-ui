"""The beta fence inventory reveals no secrets and fails on target drift."""

from __future__ import annotations

from copy import deepcopy

import pytest

from scripts import probe_passport_beta_fence_target as target
from scripts.probe_passport_beta_host import HostProbeError


def records() -> dict[str, dict]:
    result = {}
    for index, service in enumerate(target.REQUIRED_SERVICES, start=1):
        container_id = f"{index:064x}"
        environment = ["UNRELATED_SECRET=do-not-print"]
        if service in target.DATABASE_SERVICES:
            environment.append(
                "DATABASE_URL=postgresql://marty:do-not-print@postgres:5432/marty"
            )
        result[container_id] = {
            "Id": container_id,
            "Image": "sha256:" + "a" * 64,
            "Config": {
                "Image": "ghcr.io/elevenid/test@sha256:" + "a" * 64,
                "Labels": {
                    "com.docker.compose.project": "elevenid-beta",
                    "com.docker.compose.service": service,
                },
                "Env": environment,
            },
            "State": {"Running": True, "Status": "running", "StartedAt": "now"},
        }
    return result


def inventory(monkeypatch: pytest.MonkeyPatch, items: dict[str, dict]) -> dict:
    monkeypatch.setattr(target, "ids", lambda project, runner: list(items))
    monkeypatch.setattr(target, "inspect", lambda container_id, runner: items[container_id])
    return target.service_inventory(lambda command: "unused")


def test_inventory_pins_beta_services_and_redacts_database_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    found = inventory(monkeypatch, records())
    assert set(found) == set(target.REQUIRED_SERVICES)
    assert found["issuance"]["database_target"] == "postgres:5432/marty"
    assert found["gateway"]["passport_route_selector"] == "unset"
    assert "do-not-print" not in repr(found)


@pytest.mark.parametrize("drift", (
    "foreign_project", "prod_db", "query_host_override", "duplicate_env", "stopped",
))
def test_inventory_rejects_wrong_target_or_ambiguous_configuration(
    monkeypatch: pytest.MonkeyPatch, drift: str,
) -> None:
    items = deepcopy(records())
    flow_id = next(
        container_id for container_id, record in items.items()
        if record["Config"]["Labels"]["com.docker.compose.service"] == "flow"
    )
    flow = items[flow_id]
    if drift == "foreign_project":
        flow["Config"]["Labels"]["com.docker.compose.project"] = "marty-selfhost-prod"
    elif drift == "prod_db":
        flow["Config"]["Env"][1] = (
            "DATABASE_URL=postgresql://marty:do-not-print@production:5432/marty"
        )
    elif drift == "query_host_override":
        flow["Config"]["Env"][1] += "?host=production"
    elif drift == "duplicate_env":
        flow["Config"]["Env"].append(flow["Config"]["Env"][1])
    else:
        flow["State"]["Running"] = False
    with pytest.raises(HostProbeError):
        inventory(monkeypatch, items)
