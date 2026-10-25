"""Synthetic observer tests; these do not qualify an actual acceptance host."""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_host_probe as probe


class Files:
    def socket(self):
        pass

    def executable(self, path):
        assert path == Path("/usr/bin/docker")

    def config(self, path):
        assert path == Path("/private/empty")

    def memory(self):
        return 32 * 1024**3

    def disk(self, path):
        assert path == "/var/lib/docker"
        return {"device": 99, "free_bytes": 20 * 1024**3}

    def credential_files(self):
        return {"docker_config": True, "containers_auth": False, "runtime_containers_auth": False}

    def devtools(self):
        return dict.fromkeys(probe.DEVTOOLS, False)


class Docker:
    def __init__(self):
        self.info = dict(ID="engine-1", OSType="linux", Architecture="x86_64",
                         SecurityOptions=["name=seccomp,profile=builtin"],
                         MemTotal=32 * 1024**3, DockerRootDir="/var/lib/docker", ServerVersion="29.1.3")
        self.networks = [dict(Id=str(i) * 64, Name=name, Driver=driver, Containers={})
                         for i, (name, driver) in enumerate((('bridge', 'bridge'), ('host', 'host'), ('none', 'null')), 1)]
        self.resources = {"ps": b"", "image": b"", "volume": b""}
        self.calls = []
        self.drift = False

    def __call__(self, argv, *, env):
        assert argv[:5] == [str(Path("/usr/bin/docker")), "--host", "unix:///var/run/docker.sock", "--config", str(Path("/private/empty"))]
        assert env == {"PATH": probe.SAFE_PATH, "HOME": str(Path("/private/empty")), "LANG": "C", "LC_ALL": "C"}
        args = argv[5:]
        self.calls.append(args)
        if args[0] == "info":
            assert args == ["info", "--format", probe.INFO_FORMAT]
            info = copy.deepcopy(self.info)
            if self.drift and len(self.calls) > 1:
                info["ID"] = "replacement-engine"
            return json.dumps(info).encode()
        if args[0] == "compose":
            assert args == ["compose", "version", "--short"]
            return b"2.40.3+ds1-0ubuntu1~24.04.1\n"
        if args[0] in self.resources:
            return self.resources[args[0]]
        if args == ["network", "ls", "-q", "--no-trunc"]:
            return ("\n".join(v['Id'] for v in self.networks) + "\n").encode()
        assert args[:4] == ["network", "inspect", "--format", probe.NETWORK_FORMAT]
        return ("\n".join(json.dumps({"Id": v["Id"], "Name": v["Name"], "Driver": v["Driver"],
                                    "AttachedCount": len(v["Containers"])}) for v in self.networks) + "\n").encode()


def observe(docker=None, files=None):
    return probe.observe(Path("/usr/bin/docker"), Path("/private/empty"), runner=docker or Docker(),
                         filesystem=files or Files(), ambient={"GH_TOKEN": "NEVER-OUTPUT", "DOCKER_HOST": "tcp://remote",
                                                              "HTTPS_PROXY": "credential", "AWS_SECRET_ACCESS_KEY": "secret"})


def test_readonly_observations_separate_predicates_and_limitations():
    docker = Docker()
    result = observe(docker)
    assert result["predicates"] == {"capacity": True, "initial_docker_clean": True}
    assert result["acceptance"] is False
    assert result["credential_file_presence"]["docker_config"] is True
    assert result["credential_environment_names"] == ["AWS_SECRET_ACCESS_KEY", "GH_TOKEN"]
    assert "source absence not established" in result["limitations"]
    assert "NEVER-OUTPUT" not in json.dumps(result)
    assert "python3" not in result["development_tool_presence"]
    assert all(args[0] in {"info", "compose", "ps", "image", "volume", "network"} for args in docker.calls)


def test_dirty_resources_and_capacity_do_not_become_acceptance():
    docker = Docker()
    docker.info["MemTotal"] -= 1
    docker.resources["ps"] = ("a" * 64 + "\n").encode()
    docker.resources["image"] = (("sha256:" + "b" * 64 + "\n") * 2).encode()
    result = observe(docker)
    assert result["predicates"] == {"capacity": False, "initial_docker_clean": False}
    assert result["resource_counts"]["images"] == 1  # Multiple image tags can repeat an ID.
    assert result["resource_counts"]["containers"] == 1


@pytest.mark.parametrize("key,value", [("SecurityOptions", ["name=rootless"]), ("SecurityOptions", ["name=userns"]),
                                       ("OSType", "windows"), ("Architecture", "arm64"), ("MemTotal", True),
                                       ("ID", "secret\nunsafe"), ("ServerVersion", "bad")])
def test_daemon_policy_refusal(key, value):
    docker = Docker()
    docker.info[key] = value
    with pytest.raises(ValueError):
        observe(docker)


def test_identity_drift_and_filesystem_failure_refuse():
    docker = Docker()
    docker.drift = True
    with pytest.raises(ValueError):
        observe(docker)
    class Unavailable(Files):
        def disk(self, path):
            raise PermissionError("cannot inspect Docker filesystem")
    with pytest.raises(PermissionError):
        observe(files=Unavailable())


def test_resource_duplicates_extra_network_and_unbounded_output():
    docker = Docker()
    docker.resources["ps"] = (("a" * 64 + "\n") * 2).encode()
    with pytest.raises(ValueError):
        observe(docker)
    docker = Docker()
    docker.networks.append(dict(Id="4" * 64, Name="neighbor", Driver="bridge", Containers={}))
    assert observe(docker)["predicates"]["initial_docker_clean"] is False
    with pytest.raises(ValueError):
        probe.decode(b" " * (probe.LIMIT + 1))
    with pytest.raises(ValueError):
        probe.decode(b'{"ID":1,"ID":2}')
