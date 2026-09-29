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


def test_fenced_observer_uses_postinstall_identity_without_prefence_acl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = {name: {"container_id": f"{index:064x}",
                       "image_id": target.QUALIFIED_POSTGRES_IMAGE_ID}
                for index, name in enumerate(target.REQUIRED_SERVICES, start=1)}
    postgres = selected["postgres"]["container_id"]
    monkeypatch.setattr(target, "service_inventory", lambda runner: selected)
    monkeypatch.setattr(target, "database_network_binding",
                        lambda inventory, runner: {"id": "a" * 64,
                                                   "postgres_container_id": postgres})
    monkeypatch.setattr(target, "beta_postgres_container", lambda runner: postgres)
    monkeypatch.setattr(target, "inspect", lambda container, runner: {"Id": postgres})
    monkeypatch.setattr(target, "beta_psql", lambda query, runner, container: (
        "150017" if query == "SHOW server_version_num" else "123456|789"))
    monkeypatch.setattr(target, "beta_legacy_drain", lambda runner: {"verified": True})
    monkeypatch.setattr(target, "production_snapshot",
                        lambda runner: {"sha256": "b" * 64,
                                        "container_counts": {"marty-selfhost-prod": 1}})

    def runner(command: list[str]) -> str:
        return "desktop-linux" if command[:3] == ["docker", "context", "show"] else "daemon"

    receipt = target.observe_fenced(runner)
    assert receipt["schema"] == "marty.passport-beta-fence-postinstall-target/v1"
    assert receipt["beta"]["postgres_system_identifier"] == "123456"
    assert receipt["beta"]["database_oid"] == "789"
    assert receipt["beta"]["services"]["postgres"]["container_id"] == postgres
    assert receipt["production"]["sha256"] == "b" * 64


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


def test_database_network_binding_rejects_competing_postgres_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    items = records()
    network_id = "a" * 64
    for record in items.values():
        service = record["Config"]["Labels"]["com.docker.compose.service"]
        record["Config"]["Hostname"] = service
        record["HostConfig"] = {"NetworkMode": target.BETA_NETWORK,
                                "ExtraHosts": [], "Links": None,
                                "Dns": [], "DnsSearch": [], "DnsOptions": []}
        record["Mounts"] = []
        names = [service, "postgres"] if service == "postgres" else [service]
        record["NetworkSettings"] = {"Networks": {
            target.BETA_NETWORK: {"NetworkID": network_id,
                                  "Aliases": names, "DNSNames": names}
        }}
    selected = inventory(monkeypatch, items)

    def run_network(command: list[str]) -> str:
        assert command[:5] == ["docker", "ps", "--all", "--filter",
                               f"network={target.BETA_NETWORK}"]
        return "\n".join(items)

    bound = target.database_network_binding(selected, run_network)
    assert bound["postgres_container_id"] == selected["postgres"]["container_id"]
    assert bound["id"] == network_id

    rogue_id = "f" * 64
    rogue = deepcopy(next(iter(items.values())))
    rogue["Id"] = rogue_id
    rogue["Config"]["Labels"]["com.docker.compose.project"] = "foreign"
    rogue["NetworkSettings"]["Networks"][target.BETA_NETWORK]["Aliases"] = ["postgres"]
    items[rogue_id] = rogue
    with pytest.raises(HostProbeError, match="does not uniquely select"):
        target.database_network_binding(selected, run_network)


def test_database_network_binding_rejects_secondary_client_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    items = records()
    for record in items.values():
        service = record["Config"]["Labels"]["com.docker.compose.service"]
        record["Config"]["Hostname"] = service
        record["HostConfig"] = {"NetworkMode": target.BETA_NETWORK,
                                "ExtraHosts": [], "Links": None,
                                "Dns": [], "DnsSearch": [], "DnsOptions": []}
        record["Mounts"] = []
        record["NetworkSettings"] = {"Networks": {target.BETA_NETWORK: {
            "NetworkID": "a" * 64,
            "Aliases": ["postgres"] if service == "postgres" else [service],
            "DNSNames": ["postgres"] if service == "postgres" else [service],
        }}}
    selected = inventory(monkeypatch, items)
    flow = next(record for record in items.values()
                if record["Config"]["Labels"]["com.docker.compose.service"] == "flow")
    flow["NetworkSettings"]["Networks"]["other-network"] = {
        "NetworkID": "b" * 64, "Aliases": ["postgres"], "DNSNames": ["postgres"]}
    with pytest.raises(HostProbeError, match="ambiguous database network route"):
        target.database_network_binding(selected, lambda command: "\n".join(items))


@pytest.mark.parametrize("override", ("extra_host", "extra_host_equals", "hostname",
                                      "hostname_fqdn",
                                      "dns", "hosts_mount", "link"))
def test_database_network_binding_rejects_client_dns_override(
    monkeypatch: pytest.MonkeyPatch, override: str,
) -> None:
    items = records()
    for record in items.values():
        service = record["Config"]["Labels"]["com.docker.compose.service"]
        record["Config"]["Hostname"] = service
        record["HostConfig"] = {"NetworkMode": target.BETA_NETWORK,
                                "ExtraHosts": [], "Links": None,
                                "Dns": [], "DnsSearch": [], "DnsOptions": []}
        record["Mounts"] = []
        record["NetworkSettings"] = {"Networks": {target.BETA_NETWORK: {
            "NetworkID": "a" * 64,
            "Aliases": ["postgres"] if service == "postgres" else [service],
            "DNSNames": ["postgres"] if service == "postgres" else [service],
        }}}
    selected = inventory(monkeypatch, items)
    flow = next(record for record in items.values()
                if record["Config"]["Labels"]["com.docker.compose.service"] == "flow")
    if override == "extra_host":
        flow["HostConfig"]["ExtraHosts"] = ["postgres:192.0.2.5"]
    elif override == "extra_host_equals":
        flow["HostConfig"]["ExtraHosts"] = ["postgres=192.0.2.5"]
    elif override == "hostname":
        flow["Config"]["Hostname"] = "postgres"
    elif override == "hostname_fqdn":
        flow["Config"]["Hostname"] = "postgres.example"
    elif override == "dns":
        flow["HostConfig"]["Dns"] = ["192.0.2.5"]
    elif override == "hosts_mount":
        flow["Mounts"] = [{"Destination": "/etc/hosts"}]
    else:
        flow["HostConfig"]["Links"] = ["foreign:postgres"]
    with pytest.raises(HostProbeError, match="overrides the bound postgres DNS route"):
        target.database_network_binding(selected, lambda command: "\n".join(items))


def test_postgres_runtime_matches_frozen_verifier_qualification() -> None:
    assert target.qualified_postgres_runtime(
        target.QUALIFIED_POSTGRES_IMAGE_ID,
        target.QUALIFIED_POSTGRES_VERSION_NUM,
    )["server_version_num"] == "150017"
    with pytest.raises(HostProbeError, match="differs from fence qualification"):
        target.qualified_postgres_runtime(target.QUALIFIED_POSTGRES_IMAGE_ID, "160000")
    with pytest.raises(HostProbeError, match="differs from fence qualification"):
        target.qualified_postgres_runtime("sha256:" + "a" * 64, "150017")
