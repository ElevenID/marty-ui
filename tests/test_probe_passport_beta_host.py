"""Read-only production and beta drain probes fail on drift or unsafe rows."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from scripts.probe_passport_beta_host import (
    ACTIVE_PHYSICAL_FLOWS_SQL, HostProbeError, assert_production_unchanged, beta_legacy_drain,
    production_snapshot,
)


def runner(*, pending: str = "0", legacy: str = "0", active_flow: str = "0",
           altered: bool = False, stopped_project: bool = False, unhealthy: bool = False):
    commands = []

    def execute(command: list[str]) -> str:
        commands.append(command)
        if command[1] == "ps":
            project = command[command.index("--filter") + 1].split("=")[-1]
            return {"marty-selfhost-prod": "prod-id\nprod-db-id\nprod-ui-id", "marty-selfhost-openbao": "bao-id",
                    "elevenid-beta": "beta-postgres-id"}.get(project, "")
        if command[1] == "inspect":
            container_id = command[2]
            project, service = {
                "prod-id": ("marty-selfhost-prod", "gateway"),
                "prod-db-id": ("marty-selfhost-prod", "postgres"),
                "prod-ui-id": ("marty-selfhost-prod", "ui"),
                "bao-id": ("marty-selfhost-openbao", "openbao"),
                "beta-postgres-id": ("elevenid-beta", "postgres"),
            }[container_id]
            return json.dumps([{ "Id": container_id, "Image": "sha256:" + "a" * 64,
                "Name": "/" + container_id, "Mounts": [],
                "Config": {"Labels": {"com.docker.compose.project": project,
                                      "com.docker.compose.service": service}},
                "State": {"Running": not stopped_project, "Status": "exited" if stopped_project else "running",
                          "Health": {"Status": "unhealthy" if unhealthy else "healthy"},
                          "StartedAt": "changed" if altered and container_id == "prod-id" else "fixed"}}])
        if command[1] == "exec":
            sql = command[-1]
            if "to_regclass" in sql:
                return "t"
            if "status NOT IN" in sql:
                return pending
            if "flow_service.flow_instances AS instance" in sql:
                return active_flow
            return legacy
        raise AssertionError(command)

    return commands, execute


def test_reads_production_identity_without_mutating_it() -> None:
    commands, execute = runner()
    before = production_snapshot(execute)
    after = production_snapshot(execute)
    result = assert_production_unchanged(before, after)
    assert result["verified"] is True
    assert result["evidence"]["scope"] == "acceptance-run-window-only"
    assert result["evidence"]["container_counts"] == {"marty-selfhost-prod": 3,
                                                       "marty-selfhost-openbao": 1}
    assert all(command[1] in ("ps", "inspect") for command in commands)
    _, drifted_execute = runner(altered=True)
    with pytest.raises(HostProbeError, match="changed"):
        assert_production_unchanged(before, production_snapshot(drifted_execute))
    for variant in ({"stopped_project": True}, {"unhealthy": True}):
        _, invalid_execute = runner(**variant)
        with pytest.raises(HostProbeError):
            production_snapshot(invalid_execute)


def test_beta_drain_queries_live_table_and_rejects_nonzero_counts() -> None:
    commands, execute = runner()
    result = beta_legacy_drain(execute)
    assert result["verified"] is True
    assert result["evidence"]["in_flight_jobs"] == 0
    assert result["evidence"]["legacy_or_unknown_artifacts"] == 0
    assert result["evidence"]["active_physical_document_flows"] == 0
    assert all(command[1] in ("ps", "inspect", "exec") for command in commands)
    assert all(command[2] == "beta-postgres-id" for command in commands if command[1] == "exec")
    for pending, legacy, active_flow in (("1", "0", "0"), ("0", "1", "0"), ("bad", "0", "0"), ("0", "0", "1")):
        _, unsafe = runner(pending=pending, legacy=legacy, active_flow=active_flow)
        with pytest.raises(HostProbeError):
            beta_legacy_drain(unsafe)


def test_active_flow_drain_stays_equal_to_beta_cutover_preflight() -> None:
    deploy = (Path(__file__).resolve().parents[1] / "scripts/deploy-local-beta-release.ps1").read_text(encoding="utf-8")
    match = re.search(r"\$activeFlowsSql = @'\s*(.*?)\s*'@", deploy, re.DOTALL)
    assert match is not None
    assert " ".join(match.group(1).split()) == " ".join(ACTIVE_PHYSICAL_FLOWS_SQL.split())
