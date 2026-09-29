#!/usr/bin/env python3
"""Restart only owned disposable Rust services at a durable Flow checkpoint."""

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
    """Require the same owned containers to start new processes and become healthy."""
    if verify(record, surface, datetime.now(timezone.utc), inspector).get(
            "live_ownership_verified") is not True:
        raise ValueError("Disposable Rust restart ownership is unverified")
    containers = record["containers"]
    before = {service: _inspect("container", containers[service], inspector)
              for service in SERVICES}
    for service, item in before.items():
        if item.get("Id") != containers[service] or not item.get("State", {}).get("StartedAt"):
            raise ValueError("Disposable Rust restart baseline is invalid")
    if not run([*compose, "restart", *SERVICES], environment, 120):
        raise ValueError("Disposable Rust service restart failed")
    for attempt in range(40):
        try:
            proof = verify(record, surface, datetime.now(timezone.utc), inspector)
            if proof.get("live_ownership_verified") is True:
                after = {service: _inspect("container", containers[service], inspector)
                         for service in SERVICES}
                if all(after[service].get("Id") == containers[service]
                       and after[service].get("State", {}).get("StartedAt")
                       != before[service]["State"]["StartedAt"]
                       for service in SERVICES):
                    return True
        except (OSError, ValueError):
            pass
        if attempt < 39:
            sleep(3)
    raise ValueError("Disposable Rust services did not resume healthy in place")
