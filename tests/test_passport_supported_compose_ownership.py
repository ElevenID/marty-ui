"""A rollback must never trust an unowned disposable Compose project."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

import pytest

from scripts.check_passport_supported_compose_ownership import (
    OwnershipError, REQUIRED_ROLLBACK, verify,
)
from scripts.check_passport_supported_rollback_model import (
    ISOLATED_DEPENDENCIES, SELECTED,
)


PROJECT = "marty-passport-acceptance-base-abcdef"
IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
MIGRATIONS = "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "b" * 64
LEGACY = "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "c" * 64
NOW = datetime(2026, 9, 27, 12, tzinfo=timezone.utc)
LABELS = {
    "com.docker.compose.project": PROJECT,
    "com.marty.passport.acceptance.owner": "supported-consumer",
    "com.marty.passport.acceptance.run-id": "123456",
    "com.marty.passport.acceptance.source-commit": "b" * 40,
    "com.marty.passport.acceptance.services-image": IMAGE,
}


def fixture() -> tuple[dict, dict[tuple[str, ...], str]]:
    containers = {name: format(i + 1, "064x") for i, name in
                  enumerate(sorted(SELECTED | ISOLATED_DEPENDENCIES | REQUIRED_ROLLBACK))}
    network_name = PROJECT + "_private"
    network_id = "e" * 64
    volume_name = PROJECT + "_postgres"
    record = {
        "schema": "marty.passport-supported-compose-ownership/v1",
        "project": PROJECT, "run_id": "123456", "source_commit": "b" * 40,
        "services_reference": IMAGE,
        "migrations_reference": MIGRATIONS, "legacy_reference": LEGACY,
        "created_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=55)).isoformat(),
        "containers": containers, "networks": {network_name: network_id},
        "volumes": [volume_name],
    }
    calls: dict[tuple[str, ...], str] = {
        ("ps", "-aq", "--no-trunc", "--filter", f"label=com.docker.compose.project={PROJECT}"):
            "\n".join(containers.values()),
        ("network", "ls", "-q", "--no-trunc", "--filter",
         f"label=com.docker.compose.project={PROJECT}"): network_id,
        ("volume", "ls", "-q", "--filter",
         f"label=com.docker.compose.project={PROJECT}"): volume_name,
    }
    for service, identifier in containers.items():
        calls[("container", "inspect", identifier)] = json.dumps([{
            "Id": identifier, "Name": f"/{PROJECT}-{service}-1",
            "State": {"Running": True, "Status": "running",
                      "Health": {"Status": "healthy"}},
            "Config": {"Labels": {**LABELS, "com.docker.compose.service": service},
                       "Image": (LEGACY if service == "issuance" else
                                 MIGRATIONS if service == "db-migrate" else
                                 IMAGE if service in SELECTED | {"signing-keys"} else
                                 "postgres@sha256:" + "c" * 64)},
            "NetworkSettings": {"Networks": {network_name: {"NetworkID": network_id}}},
        }])
    calls[("network", "inspect", network_id)] = json.dumps([{
        "Id": network_id, "Name": network_name, "Driver": "bridge",
        "Internal": True, "Labels": LABELS,
        "Containers": {identifier: {} for identifier in containers.values()},
    }])
    calls[("volume", "inspect", volume_name)] = json.dumps([{
        "Name": volume_name, "Driver": "local", "Options": None,
        "Labels": LABELS,
    }])
    return record, calls


def run(record: dict, calls: dict[tuple[str, ...], str]) -> dict:
    return verify(record, "base", NOW, lambda args: calls[tuple(args)])


def add_migration(record: dict, calls: dict[tuple[str, ...], str],
                  service: str, exit_code: int) -> None:
    identifier = "d" * 64
    record["containers"][service] = identifier
    list_key = ("ps", "-aq", "--no-trunc", "--filter",
                f"label=com.docker.compose.project={PROJECT}")
    calls[list_key] += "\n" + identifier
    calls[("container", "inspect", identifier)] = json.dumps([{
        "Id": identifier, "Name": f"/{PROJECT}-{service}-1",
        "State": {"Running": False, "Status": "exited", "ExitCode": exit_code},
        "Config": {"Labels": {**LABELS, "com.docker.compose.service": service},
                   "Image": "migrations@sha256:" + "c" * 64},
        "NetworkSettings": {"Networks": {}},
    }])


def test_exact_live_project_ownership_is_read_only_and_still_blocked() -> None:
    record, calls = fixture()
    observed = []
    def runner(args: list[str]) -> str:
        observed.append(args)
        return calls[tuple(args)]
    report = verify(record, "base", NOW, runner)
    assert report["live_ownership_verified"] is True
    assert report["status"] == "blocked"
    assert report["rollback_accepted"] is False
    assert all(args[0] in {"ps", "container", "network", "volume"}
               and "rm" not in args and "up" not in args for args in observed)
    assert ["ps", "-aq", "--no-trunc", "--filter",
            f"label=com.docker.compose.project={PROJECT}"] in observed
    assert ["network", "ls", "-q", "--no-trunc", "--filter",
            f"label=com.docker.compose.project={PROJECT}"] in observed


def test_successful_completed_migration_service_is_allowed() -> None:
    record, calls = fixture()
    add_migration(record, calls, "issuance-migrations", 0)
    assert run(record, calls)["live_ownership_verified"] is True


def test_completed_migration_may_remain_in_network_member_listing() -> None:
    record, calls = fixture()
    add_migration(record, calls, "issuance-migrations", 0)
    key = ("network", "inspect", "e" * 64)
    item = json.loads(calls[key])
    item[0]["Containers"]["d" * 64] = {}
    calls[key] = json.dumps(item)
    assert run(record, calls)["live_ownership_verified"] is True


@pytest.mark.parametrize("network_id", ["", "e" * 64])
def test_completed_migration_may_keep_configured_detached_network(
    network_id: str,
) -> None:
    record, calls = fixture()
    add_migration(record, calls, "issuance-migrations", 0)
    key = ("container", "inspect", "d" * 64)
    item = json.loads(calls[key])
    item[0]["NetworkSettings"]["Networks"] = {
        PROJECT + "_private": {"NetworkID": network_id}}
    calls[key] = json.dumps(item)
    assert run(record, calls)["live_ownership_verified"] is True


def test_completed_migration_rejects_foreign_configured_network_id() -> None:
    record, calls = fixture()
    add_migration(record, calls, "issuance-migrations", 0)
    key = ("container", "inspect", "d" * 64)
    item = json.loads(calls[key])
    item[0]["NetworkSettings"]["Networks"] = {
        PROJECT + "_private": {"NetworkID": "f" * 64}}
    calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="network identity"):
        run(record, calls)


@pytest.mark.parametrize("service,exit_code", [
    ("issuance-migrations", 1), ("gateway-helper", 0), ("notification", 0),
])
def test_only_exact_successful_init_service_may_be_exited(
    service: str, exit_code: int,
) -> None:
    record, calls = fixture()
    add_migration(record, calls, service, exit_code)
    with pytest.raises(OwnershipError, match="service ownership|stopped or unhealthy"):
        run(record, calls)


@pytest.mark.parametrize("mutate,match", [
    (lambda record, calls: record.update(project="marty-selfhost-prod"), "project"),
    (lambda record, calls: record.update(run_id="0"), "run ID"),
    (lambda record, calls: record.update(expires_at=(NOW + timedelta(hours=5)).isoformat()),
     "lease"),
    (lambda record, calls: record["containers"].pop("postgres"), "service ownership"),
    (lambda record, calls: record["containers"].update({
        "prod-sidecar": "f" * 64}), "service ownership"),
    (lambda record, calls: calls.update({
        ("ps", "-aq", "--no-trunc", "--filter", f"label=com.docker.compose.project={PROJECT}"):
            "f" * 64}), "container set"),
    (lambda record, calls: calls.update({
        ("ps", "-aq", "--no-trunc", "--filter", f"label=com.docker.compose.project={PROJECT}"):
            "\n".join(identifier[:12] for identifier in record["containers"].values())}),
     "container set"),
    (lambda record, calls: calls.update({
        ("network", "ls", "-q", "--no-trunc", "--filter",
         f"label=com.docker.compose.project={PROJECT}"): "f" * 64}), "network set"),
    (lambda record, calls: calls.update({
        ("volume", "ls", "-q", "--filter",
         f"label=com.docker.compose.project={PROJECT}"): "other_volume"}), "volume set"),
])
def test_rejects_bad_lease_identity_and_resource_sets(mutate, match: str) -> None:
    record, calls = fixture()
    mutate(record, calls)
    with pytest.raises(OwnershipError, match=match):
        run(record, calls)


@pytest.mark.parametrize("resource,change,match", [
    ("gateway", lambda item: item["Config"]["Labels"].update({
        "com.marty.passport.acceptance.run-id": "other"}), "runner ownership"),
    ("gateway", lambda item: item["NetworkSettings"]["Networks"].update({
        "marty-selfhost-prod_default": {}}), "unowned network"),
    ("gateway", lambda item: item.update(NetworkSettings=None),
     "network state is missing"),
    ("gateway", lambda item: item["NetworkSettings"]["Networks"][
        PROJECT + "_private"].update(NetworkID="f" * 64), "network identity"),
    ("gateway", lambda item: item["Config"].update({
        "Image": "ghcr.io/other/services@sha256:" + "a" * 64}), "signed release"),
    ("issuance", lambda item: item["Config"].update({
        "Image": "ghcr.io/other/issuance@sha256:" + "c" * 64}), "signed release"),
    ("db-migrate", lambda item: item["Config"].update({
        "Image": "ghcr.io/other/migrations@sha256:" + "b" * 64}), "signed release"),
    ("signing-keys", lambda item: item["Config"].update({
        "Image": "ghcr.io/other/signing-keys@sha256:" + "a" * 64}), "signed release"),
    ("gateway", lambda item: item.update(Name="/marty-selfhost-prod-gateway-1"),
     "named Compose service"),
    ("gateway", lambda item: item.update(Mounts=[{
        "Type": "bind", "Source": "/srv/marty-selfhost-prod/secrets"}]),
     "unowned mount"),
    ("gateway", lambda item: item["State"].update(Running=False, Status="exited"),
     "stopped or unhealthy"),
    ("gateway", lambda item: item["State"]["Health"].update(Status="unhealthy"),
     "stopped or unhealthy"),
    ("network", lambda item: item.update(Internal=False), "isolation"),
    ("network", lambda item: item["Containers"].update({"f" * 64: {}}),
     "unowned member"),
    ("volume", lambda item: item.update(Options={"device": "/srv/prod"}),
     "options"),
])
def test_rejects_cross_project_or_shared_resource(resource, change, match: str) -> None:
    record, calls = fixture()
    if resource == "network":
        key = ("network", "inspect", "e" * 64)
    elif resource == "volume":
        key = ("volume", "inspect", PROJECT + "_postgres")
    else:
        key = ("container", "inspect", record["containers"][resource])
    item = deepcopy(json.loads(calls[key]))
    change(item[0])
    calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match=match):
        run(record, calls)
