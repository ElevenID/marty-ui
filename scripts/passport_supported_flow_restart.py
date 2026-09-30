#!/usr/bin/env python3
"""Recreate owned disposable Rust services at a durable Flow checkpoint."""

from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Callable

if __package__:
    from .check_passport_supported_compose_ownership import _inspect, docker, verify
else:
    from check_passport_supported_compose_ownership import _inspect, docker, verify


SERVICES = ("flow", "issuance-native")


def restart_owned_rust(
    record: dict, surface: str, compose: list[str], environment: dict[str, str],
    *, inspector: Callable[[list[str]], str] = docker,
    run: Callable[[list[str], dict[str, str], int], bool],
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Require new owned containers with the same released image and healthy state."""
    if verify(record, surface, datetime.now(timezone.utc), inspector).get(
            "live_ownership_verified") is not True:
        raise ValueError("Disposable Rust restart ownership is unverified")
    containers = record["containers"]
    before = {service: _inspect("container", containers[service], inspector)
              for service in SERVICES}
    for service, item in before.items():
        if item.get("Id") != containers[service] or not item.get("State", {}).get("StartedAt"):
            raise ValueError("Disposable Rust restart baseline is invalid")
    if not run([*compose, "up", "-d", "--no-deps", "--force-recreate",
                "--wait", "--wait-timeout", "120", *SERVICES], environment, 300):
        raise ValueError("Disposable Rust service recreation failed")
    project = record["project"]
    for attempt in range(40):
        try:
            ids = inspector(["ps", "-aq", "--no-trunc", "--filter",
                             f"label=com.docker.compose.project={project}"]).split()
            current = {}
            for identifier in ids:
                item = _inspect("container", identifier, inspector)
                labels = item.get("Config", {}).get("Labels", {})
                service = labels.get("com.docker.compose.service")
                if service in SERVICES:
                    if service in current or item.get("Id") != identifier:
                        raise ValueError("Disposable Rust service identity is ambiguous")
                    current[service] = identifier
            if (set(current) == set(SERVICES)
                    and all(current[service] != containers[service]
                            for service in SERVICES)):
                after = {service: _inspect("container", current[service], inspector)
                         for service in SERVICES}
                if all(after[service].get("Image") == before[service].get("Image")
                       and isinstance(after[service].get("Image"), str)
                       and after[service]["Image"].startswith("sha256:")
                       and after[service].get("State", {}).get("StartedAt")
                       for service in SERVICES):
                    updated = {**record, "containers": {**containers, **current}}
                    proof = verify(updated, surface, datetime.now(timezone.utc), inspector)
                    if proof.get("live_ownership_verified") is True:
                        record["containers"] = updated["containers"]
                        record["pre_restart_native_container_id"] = containers["issuance-native"]
                        return True
        except (OSError, ValueError):
            pass
        if attempt < 39:
            sleep(3)
    raise ValueError("Disposable Rust services did not resume in new owned containers")
