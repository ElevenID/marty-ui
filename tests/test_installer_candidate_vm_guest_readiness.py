"""Exact guest baseline requires cloud-init, package and empty-Docker facts."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_candidate_vm_guest_readiness as readiness
from installer_candidate_vm_policy import GUEST_USER, PACKAGES


def responses():
    docker = readiness.DOCKER
    values = {
        "/usr/bin/id -u; /usr/bin/id -un; /usr/bin/stat -c '%u:%a:%F' /home/installer":
            "1000\ninstaller\n1000:700:directory",
        "/usr/bin/cloud-init status --format json":
            '{"status":"done","extended_status":"done",'
            '"errors":[],"recoverable_errors":{}}',
        "/usr/bin/systemctl is-active docker": "active",
        "/usr/bin/uname -m": "x86_64",
        docker + " info --format '{{json .ID}}'": '"engine-1"',
        docker + " info --format '{{json .OSType}}'": '"linux"',
        docker + " info --format '{{json .Architecture}}'": '"x86_64"',
        docker + " ps -aq": "", docker + " image ls -aq": "",
        docker + " volume ls -q": "",
        docker + " network ls --format '{{.Name}}'": "bridge\nhost\nnone",
        docker + " network inspect --format '{{.Driver}}:{{.Scope}}' bridge":
            "bridge:local",
        docker + " network inspect --format '{{.Driver}}:{{.Scope}}' host":
            "host:local",
        docker + " network inspect --format '{{.Driver}}:{{.Scope}}' none":
            "null:local",
    }
    values.update({"/usr/bin/dpkg-query -W -f='${Status}\\t${Version}' " + name:
                   "install ok installed\t" + version
                   for name, version in PACKAGES.items()})
    return values


def probe(values):
    return readiness.inspect_guest(values.__getitem__, user=GUEST_USER,
                                   packages=PACKAGES)


def test_exact_guest_baseline_is_diagnostic():
    result = probe(responses())
    assert result["docker_initially_empty"] is True
    assert result["guest_uid"] == 1000
    assert result["packages"] == PACKAGES


@pytest.mark.parametrize("query,replacement", [
    ("/usr/bin/cloud-init status --format json",
     '{"status":"error","extended_status":"error","errors":[]}'),
    ("/usr/bin/cloud-init status --format json",
     '{"status":"done","extended_status":"done",'
     '"errors":["module failed"]}'),
    ("/usr/bin/cloud-init status --format json",
     '{"status":"done","extended_status":"degraded done",'
     '"errors":[],"recoverable_errors":{"WARNING":["degraded"]}}'),
    ("/usr/bin/dpkg-query -W -f='${Status}\\t${Version}' docker.io",
     "install ok installed\twrong-version"),
    ("/usr/bin/dpkg-query -W -f='${Status}\\t${Version}' docker.io",
     "deinstall ok config-files\t" + PACKAGES["docker.io"]),
    (readiness.DOCKER + " image ls -aq", "sha256:dirty"),
    (readiness.DOCKER + " network ls --format '{{.Name}}'", "bridge\nhost"),
    (readiness.DOCKER + " network ls --format '{{.Name}}'",
     "bridge\nhost\nnone\nnone"),
    (readiness.DOCKER + " network inspect --format '{{.Driver}}:{{.Scope}}' none",
     "bridge:local"),
    ("/usr/bin/id -u; /usr/bin/id -un; /usr/bin/stat -c '%u:%a:%F' /home/installer",
     "1000\ninstaller\n1000:755:directory"),
])
def test_guest_baseline_refuses_incomplete_or_dirty_state(query, replacement):
    values = responses()
    values[query] = replacement
    with pytest.raises(ValueError):
        probe(values)


def test_engine_must_stay_the_same_across_clean_inventory():
    values = responses()
    query = readiness.DOCKER + " info --format '{{json .ID}}'"
    count = 0

    def guest(command):
        nonlocal count
        if command == query:
            count += 1
            return '"engine-2"' if count == 2 else '"engine-1"'
        return values[command]

    with pytest.raises(ValueError, match="changed"):
        readiness.inspect_guest(guest, user=GUEST_USER, packages=PACKAGES)
