"""Pure host observation policies for qualification and engineering trials.

Neither policy authorizes execution or creates acceptance evidence. Controllers
must separately authenticate source, custody, freshness and the consumed nonce.
"""
from __future__ import annotations

import installer_release as release
from installer_host_probe import DEVTOOLS


def _host_state(raw: bytes, engine: str) -> dict:
    value = release.decode(raw)
    release.require(
        value.get("schema") == "elevenid.installer-host-observation/v1"
        and value.get("acceptance") is False
        and value.get("engine_id") == engine,
        "host identity differs",
    )
    predicates = value.get("predicates", {})
    release.exact(predicates, {"capacity", "initial_docker_clean"}, "host predicates")
    release.require(
        type(predicates["capacity"]) is bool
        and predicates["initial_docker_clean"] is True,
        "guest pre-pull state differs",
    )
    release.require(
        value.get("resource_counts")
        == dict(containers=0, images=0, volumes=0, networks=3),
        "guest resources present",
    )
    release.exact(value.get("credential_file_presence"),
                  {"docker_config", "containers_auth", "runtime_containers_auth"},
                  "credential observation")
    release.exact(value.get("development_tool_presence"), set(DEVTOOLS),
                  "development-tool observation")
    release.require(
        value.get("credential_environment_names") == []
        and all(v is False for v in value["credential_file_presence"].values())
        and all(v is False for v in value["development_tool_presence"].values()),
        "observed credential/development tool present",
    )
    # Narrow observations do not prove exhaustive source/credential absence.
    return value


def host_admission(raw: bytes, engine: str) -> dict:
    value = _host_state(raw, engine)
    for key in ("docker_memory_bytes", "guest_memory_bytes"):
        release.require(
            type(value.get(key)) is int
            and value[key] >= release.acceptance.MIN_MEMORY_BYTES,
            "qualification RAM unavailable",
        )
    disk = value.get("docker_data_filesystem", {})
    release.require(
        type(disk.get("free_bytes")) is int
        and disk["free_bytes"] >= release.acceptance.MIN_DISK_FREE_BYTES,
        "qualification disk unavailable",
    )
    release.require(value["predicates"]["capacity"] is True,
                    "guest pre-pull state differs")
    return value


def engineering_host_admission(raw: bytes, engine: str) -> dict:
    """Admit a measured small-host experiment; never establish qualification."""
    value = _host_state(raw, engine)
    memories = [value.get(key) for key in ("docker_memory_bytes", "guest_memory_bytes")]
    release.require(all(type(v) is int and v > 0 for v in memories),
                    "engineering RAM measurement unavailable")
    disk = value.get("docker_data_filesystem", {})
    release.require(
        type(disk.get("free_bytes")) is int
        and disk["free_bytes"] >= release.acceptance.MIN_DISK_FREE_BYTES,
        "qualification disk unavailable",
    )
    capacity = min(memories) >= release.acceptance.MIN_MEMORY_BYTES
    release.require(value["predicates"]["capacity"] is capacity,
                    "engineering capacity measurement differs")
    return value
