"""Explicit disposable-rootless policy and exact evidence; no VM is launched."""
from copy import deepcopy
import ast
import base64
import json
from pathlib import Path
import shlex
import sys

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_candidate_vm_policy as policy
import installer_candidate_vm_seed as seed
import installer_candidate_vm_launch as launch
import installer_candidate_vm_launch_evidence as evidence
import installer_candidate_vm_guest_readiness as readiness
import installer_candidate_vm_live_observe as live
import installer_candidate_vm_target as target
import installer_candidate_vm_host_preflight as preflight
import installer_candidate_qemu_observe as diagnostic
import installer_release as release
from test_installer_candidate_vm_guest_readiness import responses
from test_installer_candidate_vm_launch_evidence import chain, refresh_links
from test_installer_candidate_qemu_observe import initial_observation

PROFILE = policy.ROOTLESS_STARTUP_PROFILE
OTHER = policy.ROOTLESS_FUNCTIONAL_PROFILE
OBSERVATION_ID = "77777777-7777-4777-8777-777777777777"
INSTALLATION_ID = "88888888-8888-4888-8888-888888888888"


def rootless_responses():
    values = {key.replace(readiness.DOCKER, readiness.ROOTLESS_DOCKER): value
              for key, value in responses().items()}
    values["/usr/bin/id -u; /usr/bin/id -un; /usr/bin/stat -c '%u:%a:%F' /home/installer"] = (
        f"{policy.ROOTLESS_UID}\ninstaller\n{policy.ROOTLESS_UID}:700:directory")
    values.update({"/usr/bin/dpkg-query -W -f='${Status}\\t${Version}' " + name:
                   "install ok installed\t" + version
                   for name, version in policy.ROOTLESS_PACKAGES.items()})
    values[readiness.ROOTLESS_SYSTEMCTL + " is-active docker"] = "active"
    values[readiness.ROOTLESS_SYSTEMCTL + " is-enabled docker"] = "enabled"
    values["/usr/bin/loginctl show-user installer -p Linger --value"] = "yes"
    for name in ("docker.service", "docker.socket"):
        values["/usr/bin/systemctl show --property=ActiveState --value " + name] = "inactive"
    values[readiness.ROOTLESS_INFO_QUERY] = json.dumps(dict(
        ID="engine-12345678", OSType="linux", Architecture="x86_64",
        SecurityOptions=["name=rootless", "name=seccomp,profile=builtin"],
        CgroupVersion="2", CgroupDriver="systemd", MemoryLimit=True,
        MemTotal=7 * 1024**3, DockerRootDir=readiness.ROOTLESS_DOCKER_ROOT,
        ServerVersion="29.1.3"))
    values[readiness.ROOTLESS_DOCKER + " info --format '{{json .ID}}'"] = '"engine-12345678"'
    values[readiness.ROOTLESS_SOCKET_QUERY] = json.dumps(dict(
        runtime=dict(profile="rootless", uid=policy.ROOTLESS_UID,
                     docker_host=policy.ROOTLESS_DOCKER_HOST,
                     socket_device=9, socket_inode=123),
        runtime_directory_device=9, runtime_directory_inode=100))
    values[readiness.ROOTLESS_RESOURCE_QUERY] = json.dumps(dict(
        guest_memory_bytes=7 * 1024**3,
        docker_data_filesystem=dict(device=4, free_bytes=24 * 1024**3)))
    return values


def guest_facts():
    return readiness.inspect_guest(rootless_responses().__getitem__, user=policy.GUEST_USER,
                                    packages=policy.ROOTLESS_PACKAGES, resource_profile=PROFILE)


def rootless_chain():
    entries, boot = chain()
    for name in ("seed_intent", "seed_receipt"):
        entries[name].update(schema=seed.ROOTLESS_SCHEMA, packages=policy.ROOTLESS_PACKAGES,
                             **policy.rootless_seed_fields(PROFILE))
    for name in ("launch_intent", "launch_receipt"):
        entries[name].update(schema=launch.ROOTLESS_SCHEMA, resource_profile=PROFILE,
                             memory_mib=8192,
                             args=launch._arguments(Path("/runtime/vm"), entries[name]["vm_id"],
                                                    22022, PROFILE))
    refresh_links(entries)
    return entries, boot


def target_evidence():
    entries, boot = rootless_chain()
    records = {name: release.encode(value) for name, value in entries.items()}
    hashes = evidence.bind_provisioned_launch(**records, boot_id=boot)
    launched = entries["launch_receipt"]
    initial = dict(schema=live.ROOTLESS_GUEST_SCHEMA, phase="guest-ready",
                   vm_id=launched["vm_id"], controller_boot_id=boot,
                   process_pid=launched["pid"], process_start_ticks=launched["start_ticks"],
                   process_disk_fd=launched["disk_fd"], disk_device=1, disk_inode=5,
                   runtime_dir_device=1, runtime_dir_inode=2,
                   control_dir_device=3, control_dir_inode=4,
                   record_sha256=hashes, observed_at=1010, qualified=False,
                   dispatch_authorized=False, guest=guest_facts())
    current = deepcopy(initial)
    current.update(schema=live.ROOTLESS_PRE_DISPATCH_SCHEMA, phase="pre-dispatch",
                   observation_id=OBSERVATION_ID, observed_at=1011,
                   initial_guest_readiness_sha256=release.digest(release.encode(initial)))
    current["guest"]["docker_data_filesystem"]["free_bytes"] -= 1024**3
    return records, initial, current


def bind_target(records, initial, current):
    return target.bind_target(records, release.encode(initial), current,
                              observation_id=OBSERVATION_ID,
                              installation_id=INSTALLATION_ID, now=1012)


def test_legacy_seed_bytes_and_4gib_launch_are_unchanged():
    rendered = seed._cloud_config("ssh-ed25519 controller", "ssh-ed25519 host", "private fixture\n")
    assert release.digest(rendered) == "098a7b8ba9f0b43fafa2f2acd7811db8c00cecfcb38020ef1e9ded4dbb567dd1"
    args = launch._arguments(Path("/runtime/vm"), "vm", 22022)
    assert args[args.index("-m") + 1] == "4096"
    assert preflight.purpose_policy(preflight.ENGINEERING)[0] == preflight.ENGINEERING_SCHEMA


@pytest.mark.parametrize("profile", [PROFILE, OTHER])
def test_rootless_seed_is_explicit_pinned_guest_code_only(profile):
    rendered = seed._cloud_config("ssh-ed25519 controller", "ssh-ed25519 host",
                                  "private fixture\n", resource_profile=profile)
    config = yaml.safe_load(rendered)
    assert len(rendered) < 65536
    [user] = config["users"]
    assert user["uid"] == policy.ROOTLESS_UID and user["sudo"] is None
    assert user["groups"] == ""  # Empty arrays fail cloud-init's groups schema.
    assert dict(config["packages"]) == policy.ROOTLESS_PACKAGES
    assert config["package_upgrade"] is False
    sources = {Path(item["path"]).name: item for item in config["write_files"] if item.get("encoding") == "b64"}
    assert set(sources) == set(policy.ROOTLESS_ASSETS_SHA256)
    for name, expected in policy.ROOTLESS_ASSETS_SHA256.items():
        assert release.digest(base64.b64decode(sources[name]["content"])) == expected
        assert sources[name]["owner"] == "root:root"
    commands = config["runcmd"]
    assert commands[0] == "set -eu"
    ast.parse(commands[2][-1])  # Parse generated guest prerequisite code; do not run it.
    assert ["/usr/bin/loginctl", "enable-linger", "installer"] in commands
    setup = next(item for item in commands if type(item) is list and item[-1] == "install")
    assert setup[:4] == ["/usr/sbin/runuser", "-u", "installer", "--"]
    assert setup[-2] == policy.ROOTLESS_GUEST_DIRECTORY + "/dockerd-rootless-setuptool.sh"
    assert not any(value in json.dumps(commands) for value in ("--force", "--skip-iptables", "curl", "sysctl"))
    args = launch._arguments(Path("/runtime/vm"), "vm", 22022, profile)
    assert args[args.index("-m") + 1] == "8192"
    assert policy.rootless_seed_fields(profile)["resource_profile"] == profile


def test_missing_or_changed_upstream_asset_refuses_render_before_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "ROOTLESS_ASSET_DIRECTORY", tmp_path)
    with pytest.raises(FileNotFoundError):
        seed._cloud_config("a", "b", "c", resource_profile=PROFILE)
    (tmp_path / "dockerd-rootless.sh").write_bytes(b"substituted source")
    with pytest.raises(ValueError, match="source asset differs"):
        seed._cloud_config("a", "b", "c", resource_profile=PROFILE)


def test_nominal_8gib_requires_10gib_available_host_headroom(monkeypatch):
    monkeypatch.setattr(Path, "read_bytes", lambda _path: b"MemAvailable: 9437184 kB\n")
    assert launch._host_headroom() == 9 * 1024**3
    with pytest.raises(ValueError, match="headroom"):
        launch._host_headroom(PROFILE)
    monkeypatch.setattr(Path, "read_bytes", lambda _path: b"MemAvailable: 10485760 kB\n")
    assert launch._host_headroom(PROFILE) == 10 * 1024**3


def test_rootless_probe_binds_exact_uid_socket_and_actual_capacity():
    result = guest_facts()
    assert result["runtime"]["uid"] == result["guest_uid"] == policy.ROOTLESS_UID
    assert result["runtime"]["docker_host"] == policy.ROOTLESS_DOCKER_HOST
    assert result["runtime"]["socket_inode"] == 123
    assert result["guest_memory_bytes"] == result["docker_memory_bytes"] == 7 * 1024**3
    assert result["docker_initially_empty"] is True
    for command in (readiness.ROOTLESS_SOCKET_QUERY, readiness.ROOTLESS_RESOURCE_QUERY):
        ast.parse(shlex.split(command)[-1])


@pytest.mark.parametrize("section,field,value", [
    ("info", "SecurityOptions", ["name=userns"]),
    ("info", "SecurityOptions", ["name=rootless", "name=rootless"]),
    ("info", "CgroupVersion", "1"),
    ("info", "CgroupDriver", "cgroupfs"),
    ("info", "MemoryLimit", False),
    ("info", "MemTotal", 7 * 1024**3 - 1),
    ("info", "DockerRootDir", "/var/lib/docker"),
    ("runtime", "uid", 1000),
    ("runtime", "docker_host", "unix:///var/run/docker.sock"),
    ("runtime", "socket_inode", 0),
    ("resources", "guest_memory_bytes", 7 * 1024**3 - 1),
    ("resources", "docker_data_filesystem", dict(device=4, free_bytes=20 * 1024**3 - 1)),
])
def test_rootless_probe_refuses_control_or_measurement_substitution(section, field, value):
    values = rootless_responses()
    query = {"info": readiness.ROOTLESS_INFO_QUERY, "runtime": readiness.ROOTLESS_SOCKET_QUERY,
             "resources": readiness.ROOTLESS_RESOURCE_QUERY}[section]
    data = json.loads(values[query])
    (data["runtime"] if section == "runtime" else data)[field] = value
    values[query] = json.dumps(data)
    with pytest.raises(ValueError):
        readiness.inspect_guest(values.__getitem__, user=policy.GUEST_USER,
                                 packages=policy.ROOTLESS_PACKAGES, resource_profile=PROFILE)


@pytest.mark.parametrize("query,value", [
    (readiness.ROOTLESS_SYSTEMCTL + " is-enabled docker", "disabled"),
    ("/usr/bin/loginctl show-user installer -p Linger --value", "no"),
    ("/usr/bin/systemctl show --property=ActiveState --value docker.service", "active"),
])
def test_rootless_probe_requires_boot_persistence_without_rootful_daemon(query, value):
    values = rootless_responses()
    values[query] = value
    with pytest.raises(ValueError, match="boot policy"):
        readiness.inspect_guest(values.__getitem__, user=policy.GUEST_USER,
                                 packages=policy.ROOTLESS_PACKAGES, resource_profile=PROFILE)


def test_socket_inode_change_during_readonly_probe_refuses():
    values = rootless_responses()
    reads = 0
    def guest(command):
        nonlocal reads
        if command == readiness.ROOTLESS_SOCKET_QUERY:
            reads += 1
            data = json.loads(values[command])
            if reads > 1:
                data["runtime"]["socket_inode"] += 1
            return json.dumps(data)
        return values[command]
    with pytest.raises(ValueError, match="socket changed"):
        readiness.inspect_guest(guest, user=policy.GUEST_USER,
                                 packages=policy.ROOTLESS_PACKAGES, resource_profile=PROFILE)


def test_full_v2_chain_retains_four_field_target_and_separate_measured_runtime():
    records, initial, current = target_evidence()
    bound = bind_target(records, initial, current)
    assert set(bound["target"]) == {"guest_id", "disk_id", "engine_id", "installation_id"}
    assert bound["resource_profile"] == PROFILE
    assert bound["runtime"] == initial["guest"]["runtime"]
    assert bound["docker_data_filesystem"]["free_bytes"] == 23 * 1024**3
    assert bound["qualified"] is bound["dispatch_authorized"] is False
    checked = {key: value for key, value in current.items() if key != "guest"}
    checked.update(schema=live.ROOTLESS_PROCESS_CHECK_SCHEMA, phase="process-check")
    live.bind_process_check(release.encode(initial), checked,
                            observation_id=OBSERVATION_ID, now=1012)


@pytest.mark.parametrize("change", ["memory", "profile", "seed_version", "asset", "uid"])
def test_rehashed_v2_provisioning_cannot_change_closed_policy(change):
    entries, boot = rootless_chain()
    if change == "memory":
        for name in ("launch_intent", "launch_receipt"):
            entries[name]["memory_mib"] = 4096
    elif change == "profile":
        for name in ("launch_intent", "launch_receipt"):
            entries[name]["resource_profile"] = OTHER
    else:
        for name in ("seed_intent", "seed_receipt"):
            if change == "seed_version":
                entries[name]["schema"] = seed.SCHEMA
            elif change == "uid":
                entries[name]["guest_uid"] = 0
            else:
                entries[name]["rootless_assets_sha256"] = {"dockerd-rootless.sh": "0" * 64}
    refresh_links(entries)
    with pytest.raises(ValueError):
        evidence.bind_provisioned_launch(**{name: release.encode(value) for name, value in entries.items()},
                                         boot_id=boot)


@pytest.mark.parametrize("field,value", [("guest_uid", 0), ("resource_profile", OTHER),
                                         ("guest_memory_bytes", 4096 * 1024**2)])
def test_v2_guest_metadata_cannot_replace_seed_or_capacity(field, value):
    records, initial, current = target_evidence()
    initial["guest"][field] = current["guest"][field] = value
    current["initial_guest_readiness_sha256"] = release.digest(release.encode(initial))
    with pytest.raises(ValueError):
        bind_target(records, initial, current)


def test_v2_process_check_cannot_be_relabelled_v1_and_profile_is_explicit():
    records, initial, current = target_evidence()
    bound = bind_target(records, initial, current)
    with pytest.raises(ValueError, match="explicit"):
        preflight._require_profile(bound, None)
    with pytest.raises(ValueError):
        preflight.purpose_policy(preflight.ENGINEERING, PROFILE)
    current["schema"] = live.PRE_DISPATCH_SCHEMA
    with pytest.raises(ValueError):
        bind_target(records, initial, current)


def test_diagnostic_rootless_v3_still_cannot_authorize_dispatch():
    initial = initial_observation(INSTALLATION_ID)
    initial.update(schema="elevenid.installer-qemu-trial-observation/v3",
                   guest_uid=policy.ROOTLESS_UID, guest_user=policy.GUEST_USER,
                   vm_memory_mib=8192)
    guest = guest_facts()
    initial.update({key: guest[key] for key in readiness.ROOTLESS_FACT_FIELDS})
    diagnostic.validate_initial(initial, initial["target"]["installation_id"])
    assert initial["capacity_qualified"] is initial["clean_host_qualified"] is initial["dispatch_authorized"] is False
    changed = deepcopy(initial)
    changed["runtime"]["socket_inode"] += 1
    with pytest.raises(ValueError, match="runtime changed"):
        diagnostic.require_same_vm(initial, changed)
