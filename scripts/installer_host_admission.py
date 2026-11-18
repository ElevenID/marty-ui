"""Pure host observation policies for qualification and engineering trials.

Neither policy authorizes execution or creates acceptance evidence. Controllers
must separately authenticate source, custody, freshness and the consumed nonce.
"""
from __future__ import annotations

import installer_release as release
from installer_host_probe import DEVTOOLS, MAX_RESOURCES

LEGACY_PROFILE = "qualification-32gib"
STARTUP_PROFILE = "startup-8gib"
ENGINEERING_PROFILE = "engineering-measured"
ROOTLESS_STARTUP_PROFILE = "rootless-startup-8gib"
ROOTLESS_FUNCTIONAL_PROFILE = "rootless-functional-recovery-8gib"
ROOTLESS_PROFILES = {ROOTLESS_STARTUP_PROFILE, ROOTLESS_FUNCTIONAL_PROFILE}
# These are preflight resource policies, not proof of startup or product capacity.
# The nominal 8 GiB target permits kernel-reserved RAM. The controller separately
# records the advertised VM size; both real guest and Docker measurements remain
# in the immutable host observation. The legacy release gate is unchanged.
RESOURCE_PROFILES = {
    LEGACY_PROFILE: release.acceptance.MIN_MEMORY_BYTES,
    STARTUP_PROFILE: 7 * 1024**3,
    ENGINEERING_PROFILE: 1,
    ROOTLESS_STARTUP_PROFILE: 7 * 1024**3,
    ROOTLESS_FUNCTIONAL_PROFILE: 7 * 1024**3,
}


def resource_profile(profile: str) -> int:
    release.require(type(profile) is str and profile in RESOURCE_PROFILES,
                    "host resource profile unsupported")
    return RESOURCE_PROFILES[profile]


def resource_snapshot(value: dict) -> dict:
    resources = release.exact(value.get("resources"), {"containers", "images", "volumes", "networks"}, "host resources")
    counts = release.exact(value.get("resource_counts"), set(resources), "host resource counts")
    for name, pattern in (("containers", r"[0-9a-f]{64}"), ("images", r"sha256:[0-9a-f]{64}"),
                          ("volumes", r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")):
        entries = resources[name]
        release.require(type(entries) is list and len(entries) <= MAX_RESOURCES
                        and all(release.acceptance.matches(item, pattern) for item in entries)
                        and entries == sorted(set(entries)), "host resource census differs")
    networks = resources["networks"]
    release.require(type(networks) is list and 3 <= len(networks) <= MAX_RESOURCES, "host network census differs")
    for network in networks:
        release.exact(network, {"id", "name", "driver", "attached_count"}, "host network")
        release.require(release.acceptance.matches(network["id"], r"[0-9a-f]{64}")
                        and release.acceptance.matches(network["name"], r"[A-Za-z0-9_.-]{1,255}")
                        and release.acceptance.matches(network["driver"], r"[A-Za-z0-9_.-]{1,128}")
                        and type(network["attached_count"]) is int and 0 <= network["attached_count"] <= MAX_RESOURCES,
                        "host network shape differs")
    ids = [network["id"] for network in networks]
    release.require(ids == sorted(set(ids)), "host network identities differ")
    release.require(all(type(counts[name]) is int and counts[name] == len(entries)
                        for name, entries in resources.items()), "host resource counts differ")
    return resources


def _host_state(raw: bytes, engine: str, *, owned_isolation=False) -> dict:
    value = release.decode(raw)
    release.require(
        value.get("schema") in ("elevenid.installer-host-observation/v1", "elevenid.installer-host-observation/v2")
        and value.get("acceptance") is False
        and value.get("engine_id") == engine,
        "host identity differs",
    )
    if value["schema"] == "elevenid.installer-host-observation/v2":
        runtime = release.exact(value.get("runtime"), {
            "profile", "uid", "docker_host", "socket_device", "socket_inode",
        }, "rootless host observation")
        controls = release.exact(value.get("rootless_resource_controls"), {
            "cgroup_version", "cgroup_driver", "memory_limit",
        }, "rootless resource controls")
        release.require(
            runtime["profile"] == "rootless" and type(runtime["uid"]) is int
            and 0 < runtime["uid"] <= 4_294_967_294
            and runtime["docker_host"] == f'unix:///run/user/{runtime["uid"]}/docker.sock'
            and all(type(runtime[key]) is int and runtime[key] >= 0
                    for key in ("socket_device", "socket_inode"))
            and controls["cgroup_version"] == "2"
            and controls["cgroup_driver"] == "systemd"
            and controls["memory_limit"] is True,
            "rootless host control observations differ",
        )
    if owned_isolation:
        release.require(value["schema"] == "elevenid.installer-host-observation/v2"
                        and value["runtime"]["socket_inode"] > 0,
                        "versioned qualification requires observed rootless runtime")
        release.exact(value, {"schema", "acceptance", "runtime", "rootless_resource_controls", "engine_id",
            "docker_version", "compose_version", "docker_memory_bytes", "guest_memory_bytes", "docker_data_filesystem",
            "resources", "resource_counts", "predicates", "credential_file_presence", "credential_environment_names",
            "development_tool_presence", "limitations"}, "versioned host observation")
        for name in ("docker_version", "compose_version"):
            release.require(release.acceptance.matches(value[name], r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.~-]+)?")
                and len(value[name]) <= 128, "observed runtime version differs")
        disk = release.exact(value["docker_data_filesystem"], {"device", "free_bytes"}, "observed Docker filesystem")
        release.require(type(disk["device"]) is int and disk["device"] >= 0, "observed Docker filesystem identity differs")
        release.require(type(value["limitations"]) is list and 0 < len(value["limitations"]) <= 16
                        and all(type(item) is str and 0 < len(item) <= 256 for item in value["limitations"]),
                        "host observation limitations missing")
    predicates = value.get("predicates", {})
    release.exact(predicates, {"capacity", "initial_docker_clean"}, "host predicates")
    release.require(
        type(predicates["capacity"]) is bool
        and type(predicates["initial_docker_clean"]) is bool
        and (owned_isolation or predicates["initial_docker_clean"] is True),
        "guest pre-pull state differs",
    )
    if owned_isolation:
        resources = resource_snapshot(value)
        defaults = {"bridge": "bridge", "host": "host", "none": "null"}
        networks = resources["networks"]
        clean = (not (resources["containers"] or resources["images"] or resources["volumes"])
                 and len(networks) == 3 and {v["name"] for v in networks} == set(defaults)
                 and all(v["driver"] == defaults[v["name"]] and v["attached_count"] == 0 for v in networks))
        release.require(predicates["initial_docker_clean"] is clean, "recorded baseline cleanliness differs")
    else:
        release.require(value.get("resource_counts") == dict(containers=0, images=0, volumes=0, networks=3),
                        "guest resources present")
    release.exact(value.get("credential_file_presence"),
                  {"docker_config", "containers_auth", "runtime_containers_auth"},
                  "credential observation")
    release.exact(value.get("development_tool_presence"), set(DEVTOOLS),
                  "development-tool observation")
    if owned_isolation:
        names = value.get("credential_environment_names")
        release.require(type(names) is list and len(names) <= 128
                        and all(type(v) is str and 0 < len(v) <= 128 for v in names)
                        and names == sorted(set(names))
                        and all(type(v) is bool for v in value["credential_file_presence"].values())
                        and all(type(v) is bool for v in value["development_tool_presence"].values()),
                        "host presence observations differ")
    else:
        release.require(value.get("credential_environment_names") == []
                        and all(v is False for v in value["credential_file_presence"].values())
                        and all(v is False for v in value["development_tool_presence"].values()),
                        "observed credential/development tool present")
    # Narrow observations do not prove exhaustive source/credential absence.
    return value


def host_admission(raw: bytes, engine: str, *, profile: str = LEGACY_PROFILE) -> dict:
    minimum = resource_profile(profile)
    value = _host_state(raw, engine, owned_isolation=profile in ROOTLESS_PROFILES)
    for key in ("docker_memory_bytes", "guest_memory_bytes"):
        release.require(
            type(value.get(key)) is int
            and value[key] >= minimum,
            "qualification RAM unavailable",
        )
    disk = value.get("docker_data_filesystem", {})
    release.require(
        type(disk.get("free_bytes")) is int
        and disk["free_bytes"] >= release.acceptance.MIN_DISK_FREE_BYTES,
        "qualification disk unavailable",
    )
    # v1 observations report the historical 32 GiB predicate. Do not relabel that
    # result when selecting another preflight policy, or trust a false assertion.
    legacy_capacity = min(value["docker_memory_bytes"], value["guest_memory_bytes"]) >= release.acceptance.MIN_MEMORY_BYTES
    release.require(value["predicates"]["capacity"] is legacy_capacity,
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
