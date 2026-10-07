"""Exercise the Marty plugin across disposable OpenBao 2.5.5 Raft failover.

This probe builds the current candidate source into a local image, then uses
three random, labeled, ephemeral containers and a private Docker network.
It never reads host credentials or contacts an existing OpenBao deployment.
"""

from __future__ import annotations

import concurrent.futures
import json
import re
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


IMAGE = "marty-openbao-ha-probe:local"
ROOT = Path(__file__).resolve().parents[1]


def docker(*args: str, timeout: int = 90) -> str:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False, timeout=timeout
    )
    if result.returncode:
        raise RuntimeError(f"Disposable Docker operation failed: {args[0]}")
    return result.stdout.strip()


def request(
    base: str, method: str, path: str, body: dict | None = None, token: str = ""
) -> tuple[int, dict]:
    payload = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    req = urllib.request.Request(
        f"{base}/v1/{path}", data=payload, method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:  # noqa: S310 - loopback only
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        error.read()
        return error.code, {}


def wait_for(operation: str, check, seconds: float = 30) -> object:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.25)
    raise RuntimeError(f"Disposable HA probe timed out: {operation}")


def require_status(
    base: str, method: str, path: str, token: str, body: dict | None = None
) -> dict:
    status, response = request(base, method, path, body, token)
    if status not in (200, 204):
        raise RuntimeError(
            f"Disposable HA probe failed: {method} {path} status {status}"
        )
    return response


def run() -> None:
    docker(
        "build",
        "-f",
        str(ROOT / "openbao/didcomm-authcrypt/Dockerfile"),
        "-t",
        IMAGE,
        str(ROOT),
        timeout=600,
    )
    suffix = uuid.uuid4().hex[:12]
    network = f"kms-ha-{suffix}"
    names = [f"kms-ha-{suffix}-{index}" for index in range(3)]
    started: list[str] = []
    network_started = False
    try:
        docker("network", "create", "--label", "marty.disposable=kms-ha-probe", network)
        network_started = True
        bases = []
        for index, name in enumerate(names):
            config = {
                "ui": False,
                "disable_mlock": True,
                "api_addr": f"http://{name}:8200",
                "cluster_addr": f"https://{name}:8201",
                "plugin_directory": "/plugins",
                "storage": {"raft": {"path": "/openbao/file", "node_id": name}},
                "listener": [
                    {
                        "tcp": {
                            "address": "0.0.0.0:8200",
                            "cluster_address": "0.0.0.0:8201",
                            "tls_disable": True,
                        }
                    }
                ],
            }
            docker(
                "run",
                "--rm",
                "-d",
                "--name",
                name,
                "--network",
                network,
                "--label",
                "marty.disposable=kms-ha-probe",
                "-p",
                "127.0.0.1::8200",
                "-e",
                f"BAO_LOCAL_CONFIG={json.dumps(config)}",
                IMAGE,
                "server",
            )
            started.append(name)
            port = int(
                docker("port", name, "8200/tcp").splitlines()[0].rsplit(":", 1)[1]
            )
            bases.append(f"http://127.0.0.1:{port}")
        for base in bases:
            wait_for(
                "OpenBao listener",
                lambda base=base: request(base, "GET", "sys/health")[0] in (501, 503),
            )
        initialized = require_status(
            bases[0], "PUT", "sys/init", "", {"secret_shares": 1, "secret_threshold": 1}
        )
        unseal_key = initialized["keys"][0]
        root = initialized["root_token"]
        require_status(bases[0], "PUT", "sys/unseal", "", {"key": unseal_key})
        wait_for(
            "first leader",
            lambda: request(bases[0], "GET", "sys/leader")[1].get("is_self"),
        )
        for base in bases[1:]:
            require_status(
                base,
                "POST",
                "sys/storage/raft/join",
                "",
                {"leader_api_addr": f"http://{names[0]}:8200"},
            )
            require_status(base, "PUT", "sys/unseal", "", {"key": unseal_key})
        for base in bases[1:]:
            wait_for(
                "standby join",
                lambda base=base: request(base, "GET", "sys/leader")[1].get(
                    "leader_address"
                ),
            )

        def all_voters() -> bool:
            status, response = request(
                bases[0], "GET", "sys/storage/raft/configuration", token=root
            )
            if status != 200:
                return False
            servers = response.get("data", {}).get("config", {}).get("servers", [])
            return len(servers) == 3 and all(
                server.get("voter") is True for server in servers
            )

        wait_for("three Raft voters", all_voters, seconds=60)

        binary = docker(
            "exec", names[0], "sha256sum", "/plugins/openbao-didcomm-authcrypt"
        )
        digest = binary.split()[0]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError("Invalid packaged plugin digest")
        require_status(
            bases[0],
            "PUT",
            "sys/plugins/catalog/secret/openbao-didcomm-authcrypt",
            root,
            {"command": "openbao-didcomm-authcrypt", "sha256": digest},
        )
        require_status(
            bases[0],
            "POST",
            "sys/mounts/didcomm",
            root,
            {"type": "openbao-didcomm-authcrypt"},
        )
        did = "did:example:ha-sender"
        path = "didcomm/keys/tenant_a/sender"
        first = require_status(
            bases[0],
            "POST",
            path,
            root,
            {"sender_did": did, "sender_key_id": did + "#agreement-1"},
        )["data"]["version"]
        for base in bases[1:]:
            wait_for(
                "standby plugin/key visibility",
                lambda base=base: request(base, "GET", path, token=root)[0] == 200,
                seconds=30,
            )

        def rotate(index: int) -> str:
            return require_status(bases[index % 3], "POST", path + "/rotate", root, {})[
                "data"
            ]["version"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
            versions = list(pool.map(rotate, range(9)))
        if len(set(versions + [first])) != 10:
            raise RuntimeError("Concurrent rotations reused a version")
        for version in [first, *versions]:
            response = require_status(
                bases[0], "GET", path + "/versions/" + version, root
            )
            if response["data"]["version"] != version:
                raise RuntimeError("Explicit DIDComm version changed")
        current = require_status(bases[0], "GET", path, root)["data"]["version"]
        if current not in versions:
            raise RuntimeError("Current DIDComm pointer is not a committed rotation")

        haip_path = "didcomm/haip/keys/tenant_a/flow_a"
        haip = require_status(bases[1], "POST", haip_path, root, {})["data"]["version"]
        for base in bases:
            wait_for(
                "HAIP key visibility",
                lambda base=base: request(base, "GET", haip_path, token=root)[0] == 200,
                seconds=30,
            )
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            selected = list(
                pool.map(
                    lambda index: require_status(
                        bases[index % 3], "POST", haip_path, root, {}
                    )["data"]["version"],
                    range(6),
                )
            )
        if any(version != haip for version in selected):
            raise RuntimeError("Concurrent HAIP create changed the current key")
        docker("stop", names[0])
        started.remove(names[0])
        survivor = wait_for(
            "Raft failover",
            lambda: next(
                (
                    base
                    for base in bases[1:]
                    if request(base, "GET", "sys/leader")[1].get("is_self")
                ),
                None,
            ),
            seconds=60,
        )
        if (
            require_status(survivor, "GET", path + "/versions/" + first, root)["data"][
                "version"
            ]
            != first
        ):
            raise RuntimeError("Original DIDComm version missing after failover")
        if (
            require_status(survivor, "GET", haip_path + "/versions/" + haip, root)[
                "data"
            ]["version"]
            != haip
        ):
            raise RuntimeError("HAIP version missing after failover")
        if (
            require_status(survivor, "POST", haip_path, root, {})["data"]["version"]
            != haip
        ):
            raise RuntimeError("HAIP current pointer changed after failover")
        advanced = require_status(survivor, "POST", path + "/rotate", root, {})["data"][
            "version"
        ]
        if advanced in versions or advanced == first:
            raise RuntimeError("Post-failover DIDComm rotation reused a version")
        print("Disposable OpenBao Raft forwarding, rotation and failover passed")
    finally:
        for name in reversed(started):
            subprocess.run(
                ["docker", "rm", "-f", name],
                capture_output=True,
                timeout=30,
                check=False,
            )
        if network_started:
            subprocess.run(
                ["docker", "network", "rm", network],
                capture_output=True,
                timeout=30,
                check=False,
            )


if __name__ == "__main__":
    run()
