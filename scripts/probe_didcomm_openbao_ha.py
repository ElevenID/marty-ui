"""Exercise the Marty plugin across disposable OpenBao 2.5.5 Raft failover.

This probe builds the current candidate source into a local image, then uses
three random, labeled, ephemeral containers and a private Docker network.
It never reads host credentials or contacts an existing OpenBao deployment.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path, PurePosixPath


IMAGE = os.environ.get("MARTY_OPENBAO_PROBE_IMAGE", "marty-openbao-ha-probe:local")
ROOT = Path(__file__).resolve().parents[1]


def docker_host_path(path: Path) -> str:
    """Translate an opt-in WSL /mnt path for Docker Desktop bind mounts."""
    host_mnt = os.environ.get("MARTY_OPENBAO_PROBE_HOST_MNT")
    if not host_mnt:
        return str(path)
    source = PurePosixPath(str(path).replace("\\", "/"))
    if not source.is_absolute() or not source.is_relative_to("/mnt"):
        raise ValueError("Docker host path must be under the WSL /mnt root")
    return str(PurePosixPath(host_mnt) / source.relative_to("/mnt"))


def prepare_image() -> None:
    if os.environ.get("MARTY_OPENBAO_PROBE_IMAGE"):
        return
    docker(
        "build",
        "-f",
        str(ROOT / "openbao/didcomm-authcrypt/Dockerfile"),
        "-t",
        IMAGE,
        str(ROOT),
        timeout=600,
    )


def docker_process(command: list[str], *, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    if not command or command[0] != "docker":
        raise ValueError("disposable Docker command is invalid")
    for attempt in range(3):
        result = subprocess.run(
            command, capture_output=True, text=True, check=False,
            timeout=timeout,
        )
        # This WSL interop error occurs before docker.exe starts. Retrying any
        # other failure could repeat a non-idempotent Docker operation.
        if (result.returncode == 0 or not os.environ.get("WSL_INTEROP")
                or "UtilAcceptVsock:271: accept4 failed 110" not in result.stderr
                or attempt == 2):
            break
        time.sleep(1)
    return result


def docker(*args: str, timeout: int = 90) -> str:
    result = docker_process(["docker", *args], timeout=timeout)
    if result.returncode:
        raise RuntimeError(
            f"Disposable Docker operation failed: {args[0]} "
            f"(exit {result.returncode}): {result.stderr.strip()[-1200:]}"
        )
    return result.stdout.strip()


def classify_api_error(raw: bytes, markers: dict[str, str]) -> list[str]:
    """Return only fixed diagnostics; never reflect a key-bearing error body."""
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        return ["UNCLASSIFIED_ERROR"]
    errors = value.get("errors") if isinstance(value, dict) else None
    if not isinstance(errors, list) or not all(isinstance(item, str) for item in errors):
        return ["UNCLASSIFIED_ERROR"]
    text = " ".join(errors).lower()
    return [name for name, marker in markers.items() if marker in text] or ["UNCLASSIFIED_ERROR"]


def classify_unseal_error(raw: bytes) -> list[str]:
    return classify_api_error(raw, {
        "INVALID_KEY_SIZE": "invalid key size",
        "DECRYPTION_FAILED": "failed to decrypt",
        "AUTHENTICATION_FAILED": "message authentication failed",
        "INVALID_UNSEAL_KEY": "invalid key",
        "SEAL_STATE_ERROR": "sealed",
        "UNINITIALIZED": "not initialized",
    })


def classify_revocation_error(raw: bytes) -> list[str]:
    return classify_api_error(raw, {
        "REVOCATION_FAILED": "failed to revoke",
        "STORAGE_WRITE_FAILED": "failed to persist",
        "STORAGE_DELETE_FAILED": "failed to delete",
        "NODE_NOT_ACTIVE": "not active",
        "NODE_SEALED": "sealed",
        "DEADLINE_EXCEEDED": "context deadline exceeded",
        "CONTEXT_CANCELLED": "context canceled",
        "PERMISSION_DENIED": "permission denied",
    })


def request(
    base: str,
    method: str,
    path: str,
    body: dict | None = None,
    token: str = "",
    *,
    timeout: float = 10,
    ca_file: Path | None = None,
    unseal_error_diagnostics: bool = False,
    revocation_error_diagnostics: bool = False,
) -> tuple[int, dict]:
    payload = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    req = urllib.request.Request(
        f"{base}/v1/{path}", data=payload, method=method, headers=headers
    )
    try:
        context = ssl.create_default_context(cafile=str(ca_file)) if ca_file else None
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:  # noqa: S310 - loopback only
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raw = error.read(16 * 1024)
        if unseal_error_diagnostics:
            return error.code, {"error_classes": classify_unseal_error(raw)}
        if revocation_error_diagnostics:
            return error.code, {"error_classes": classify_revocation_error(raw)}
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
    base: str,
    method: str,
    path: str,
    token: str,
    body: dict | None = None,
    *,
    timeout: float = 10,
    ca_file: Path | None = None,
) -> dict:
    status, response = request(
        base, method, path, body, token, timeout=timeout, ca_file=ca_file
    )
    if status not in (200, 204):
        raise RuntimeError(
            f"Disposable HA probe failed: {method} {path} status {status}"
        )
    return response


def run() -> None:
    prepare_image()
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
        # Init can take longer on a cold CI runner; do not retry a timed-out
        # init because the server may have committed it before the response.
        initialized = require_status(
            bases[0],
            "PUT",
            "sys/init",
            "",
            {"secret_shares": 1, "secret_threshold": 1},
            timeout=30,
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
