#!/usr/bin/env python3
"""Start the exact preview's disposable OpenBao; not release qualification."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import time

from provision_selfhost_disposable_tls import exact_images, openbao_network


PROJECT = re.compile(r"marty-preview-[0-9a-f]{16}\Z")
OUTPUTS = (
    "openbao_service_token", "openbao_bootstrap_token",
    "signing_keys_openbao_token", "didcomm_issuance_openbao_token",
    "notification_openbao_token", "haip_kms_token",
)


def run(args: list[str], *, env: dict[str, str] | None = None,
        timeout: int = 30) -> str:
    result = subprocess.run(args, env=env, capture_output=True, text=True,
                            timeout=timeout, check=False)
    if result.returncode:
        # Docker/Compose stderr can contain operator paths or environment data.
        raise RuntimeError("Docker operation failed")
    return result.stdout


def private_dir(path: Path) -> Path:
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or path.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) != 0o700):
        raise ValueError("disposable install directory must be operator-owned and private")
    return path.resolve()


def free_loopback_port(port: int) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError("OpenBao port must be unprivileged")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", port))


def verify_model(model: object, image: str, state: Path, secret_root: Path,
                 bundle: Path, port: int, project: str) -> None:
    if (not isinstance(model, dict) or set(model) != {"name", "networks", "services"}
            or model.get("name") != project):
        raise ValueError("rendered OpenBao project is invalid")
    networks = model.get("networks")
    if (not isinstance(networks, dict) or set(networks) != {"default"}
            or not isinstance(networks["default"], dict)
            or set(networks["default"]) - {"name", "ipam"}
            or networks["default"].get("ipam", {}) != {}
            or networks["default"].get("name") != f"{project}_default"):
        raise ValueError("rendered OpenBao network is invalid")
    services = model.get("services")
    if (not isinstance(services, dict)
            or set(services) != {"openbao-tls-init", "openbao", "openbao-bootstrap"}):
        raise ValueError("rendered OpenBao service set is invalid")
    for name, service in services.items():
        if not isinstance(service, dict) or service.get("image") != image:
            raise ValueError("rendered OpenBao image differs from the lock")
        keys = {"image", "networks", "restart", "volumes", "entrypoint", "command"}
        if name == "openbao":
            keys.update({"depends_on", "ports", "healthcheck"})
        elif name == "openbao-bootstrap":
            keys.update({"depends_on", "environment"})
        if set(service) - keys or service.get("networks") != {"default": None}:
            raise ValueError("rendered OpenBao has unsafe runtime overrides")
        expected_entrypoint = {
            "openbao-tls-init": ["/usr/local/bin/selfhost-tls-init"],
            "openbao": None,
            "openbao-bootstrap": ["/bin/sh", "/scripts/openbao-selfhost-init.sh"],
        }[name]
        expected_command = ["server", "-config=/bao/config/openbao.hcl"] if name == "openbao" else None
        expected_restart = "unless-stopped" if name == "openbao" else "no"
        if (service.get("entrypoint") != expected_entrypoint
                or service.get("command") != expected_command
                or service.get("restart") != expected_restart):
            raise ValueError("rendered OpenBao startup contract differs")
        expected_dependencies = {
            "openbao": {"openbao-tls-init": {
                "condition": "service_completed_successfully", "required": True,
            }},
            "openbao-bootstrap": {"openbao": {
                "condition": "service_started", "required": True,
            }},
        }.get(name)
        if service.get("depends_on") != expected_dependencies:
            raise ValueError("rendered OpenBao dependencies differ")
        if name == "openbao":
            health = service.get("healthcheck")
            if (not isinstance(health, dict)
                    or health.get("test") != ["CMD-SHELL", "bao status -address=https://127.0.0.1:8200 -ca-cert=/bao/data/tls/ca.crt >/dev/null 2>&1"]
                    or health.get("timeout") != "5s"
                    or health.get("interval") != "10s"
                    or health.get("retries") != 12
                    or health.get("start_period") != "20s"
                    or set(health) != {"test", "timeout", "interval", "retries", "start_period"}):
                raise ValueError("rendered OpenBao healthcheck differs")
        if name == "openbao-bootstrap" and service.get("environment") != {
            "BAO_ADDR": "https://openbao:8200",
            "BAO_BOOTSTRAP_TOKEN_FILE": "/bao/runtime/openbao_bootstrap_token",
            "BAO_CACERT": "/bao/data/tls/ca.crt",
            "BAO_DIDCOMM_ISSUANCE_TOKEN_FILE": "/bao/runtime/didcomm_issuance_openbao_token",
            "BAO_HAIP_POLICY_FILE": "/scripts/openbao-haip-workload-policy.hcl",
            "BAO_HAIP_TOKEN_FILE": "/bao/runtime/haip_kms_token",
            "BAO_INIT_FILE": "/bao/data/selfhost-init.json",
            "BAO_NOTIFICATION_TOKEN_FILE": "/bao/runtime/notification_openbao_token",
            "BAO_ROOT_TOKEN_FILE": "/bao/data/root.token",
            "BAO_SERVICE_TOKEN_FILE": "/bao/runtime/openbao_service_token",
            "BAO_SIGNING_KEYS_TOKEN_FILE": "/bao/runtime/signing_keys_openbao_token",
            "BAO_UNSEAL_KEY_FILE": "/bao/data/unseal.key",
            "DIDCOMM_KMS_PLUGIN_REQUIRED": "true",
        }:
            raise ValueError("rendered OpenBao bootstrap environment differs")
        ports = service.get("ports", [])
        if name == "openbao":
            if (not isinstance(ports, list) or len(ports) != 1
                    or not isinstance(ports[0], dict)
                    or ports[0].get("host_ip") != "127.0.0.1"
                    or str(ports[0].get("published")) != str(port)
                    or ports[0].get("target") != 8200
                    or ports[0].get("protocol") != "tcp"):
                raise ValueError("OpenBao must publish only its selected loopback port")
        elif ports:
            raise ValueError("OpenBao helper must not publish ports")
        mounts = service.get("volumes", [])
        if not isinstance(mounts, list):
            raise ValueError("OpenBao bind mounts are invalid")
        actual = {}
        for mount in mounts:
            if (not isinstance(mount, dict) or mount.get("type") != "bind"
                    or not isinstance(mount.get("source"), str)
                    or not isinstance(mount.get("target"), str)
                    or set(mount) - {"type", "source", "target", "read_only", "bind"}
                    or mount.get("bind", {}) != {}
                    or mount["target"] in actual):
                raise ValueError("OpenBao bind mounts are invalid")
            actual[mount["target"]] = (Path(mount["source"]),
                                       mount.get("read_only", False))
        expected = {"/bao/data": (state, False)}
        if name == "openbao":
            expected["/bao/config/openbao.hcl"] = (
                bundle / "docker" / "openbao-selfhost.hcl", True)
        if name == "openbao-bootstrap":
            expected.update({
                "/bao/runtime": (secret_root, False),
                "/scripts/openbao-init.sh": (bundle / "docker" / "openbao-init.sh", True),
                "/scripts/openbao-haip-workload-policy.hcl": (
                    bundle / "docker" / "openbao-haip-workload-policy.hcl", True),
                "/scripts/openbao-selfhost-init.sh": (
                    bundle / "docker" / "openbao-selfhost-init.sh", True),
            })
        if actual != expected:
            raise ValueError("OpenBao bind mounts differ from isolated install")


def wait_healthy(compose: list[str], environment: dict[str, str]) -> None:
    container = run([*compose, "ps", "-q", "openbao"], env=environment).strip()
    if not re.fullmatch(r"[0-9a-f]{12,64}", container):
        raise RuntimeError("OpenBao container identity is invalid")
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        status = run(["docker", "inspect", "--format", "{{.State.Health.Status}}",
                      container], timeout=15).strip()
        if status == "healthy":
            return
        if status not in {"starting", "unhealthy"}:
            raise RuntimeError("OpenBao health state is invalid")
        time.sleep(2)
    raise RuntimeError("OpenBao did not become healthy after bootstrap")


def start(private_root: Path, port: int) -> dict:
    if os.name != "posix" or os.geteuid() == 0:
        raise ValueError("disposable OpenBao startup requires a non-root Linux operator")
    root = private_dir(private_root)
    state = private_dir(root / "openbao-state")
    secret_root = private_dir(root / "secrets")
    report_path = root / "stage.json"
    if report_path.is_symlink() or not report_path.is_file():
        raise ValueError("verified preview stage report is missing")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    bundle = root / "install" / "selfhost-prepared"
    if (report.get("schema") != "marty.selfhost-disposable-stage/v1"
            or report.get("qualification") != "unqualified"
            or report.get("install_root") != str(bundle)
            or bundle.is_symlink() or not bundle.is_dir()
            or (root / "openbao.json").exists()
            or (root / "openbao.json").is_symlink()
            or (root / "openbao-pending.json").exists()
            or (root / "openbao-pending.json").is_symlink()):
        raise ValueError("preview staging lineage is invalid or already started")
    _, image = exact_images(bundle)
    compose_file = bundle / "docker-compose.selfhost.openbao.yml"
    if compose_file.is_symlink() or not compose_file.is_file():
        raise ValueError("preview OpenBao Compose file is missing")
    for name in (*OUTPUTS,):
        if (secret_root / name).exists() or (secret_root / name).is_symlink():
            raise ValueError("OpenBao bootstrap output already exists")
    if any(state.iterdir()):
        raise ValueError("OpenBao state must be fresh")
    free_loopback_port(port)
    project = "marty-preview-" + secrets.token_hex(8)
    if not PROJECT.fullmatch(project):
        raise AssertionError("invalid generated project")
    containers = run(["docker", "ps", "-aq", "--filter",
                      f"label=com.docker.compose.project={project}"])
    networks = run(["docker", "network", "ls", "-q", "--filter",
                    f"label=com.docker.compose.project={project}"])
    named_network = run(["docker", "network", "ls", "-q", "--filter",
                         f"name=^{project}_default$"])
    if containers.strip() or networks.strip() or named_network.strip():
        raise RuntimeError("generated Docker project is already in use")
    environment = os.environ.copy()
    environment.update({
        "MARTY_OPENBAO_DIDCOMM_IMAGE": image,
        "SELFHOST_OPENBAO_STATE_DIR": str(state),
        "SELFHOST_SECRET_DIR": str(secret_root),
        "SELFHOST_OPENBAO_HOST_PORT": str(port),
    })
    compose = ["docker", "compose", "--project-name", project, "-f", str(compose_file)]
    model = json.loads(run([*compose, "config", "--format", "json"], env=environment))
    verify_model(model, image, state, secret_root, bundle, port, project)
    pending = root / "openbao-pending.json"
    with pending.open("x", encoding="utf-8") as output:
        json.dump({"schema": "marty.selfhost-disposable-openbao-pending/v1",
                   "qualification": "unqualified", "project": project,
                   "host_port": port}, output, sort_keys=True)
        output.write("\n")
    pending.chmod(0o600)
    started = False
    try:
        started = True
        run([*compose, "up", "-d", "--pull", "missing", "openbao"],
            env=environment, timeout=330)
        run([*compose, "run", "--no-deps", "--rm", "openbao-bootstrap"],
            env=environment, timeout=240)
        wait_healthy(compose, environment)
        openbao_network(project, state, image, expected_host_port=port)
        for name in OUTPUTS:
            output = secret_root / name
            if output.is_symlink() or not output.is_file() or not output.stat().st_size:
                raise RuntimeError("OpenBao bootstrap did not create all scoped tokens")
        # The locked TLS initializer chowns the state directory to OpenBao.
        # This non-root operator cannot traverse it after bootstrap. The
        # following root-only Keycloak bridge verifies the CA and root-token
        # metadata before using either one.
        public_ca = secret_root / "openbao_tls_ca_cert"
        if (public_ca.is_symlink() or not public_ca.is_file()
                or not 0 < public_ca.stat().st_size <= 64 * 1024):
            raise RuntimeError("OpenBao bootstrap did not stage its public CA")
        result = {
            "schema": "marty.selfhost-disposable-openbao/v1",
            "qualification": "unqualified",
            "source_sha": report["source_sha"],
            "run_id": report["run_id"],
            "project": project,
            "host_port": port,
            "image": image,
        }
        with (root / "openbao.json").open("x", encoding="utf-8") as output:
            json.dump(result, output, sort_keys=True, indent=2)
            output.write("\n")
        pending.unlink()
        return result
    except BaseException:
        if started:
            try:
                run([*compose, "down", "--remove-orphans"], env=environment, timeout=90)
                remaining = run(["docker", "ps", "-aq", "--filter",
                                 f"label=com.docker.compose.project={project}"])
                networks = run(["docker", "network", "ls", "-q", "--filter",
                                f"label=com.docker.compose.project={project}"])
                if remaining.strip() or networks.strip():
                    raise RuntimeError("owned Docker project still exists")
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                raise RuntimeError("OpenBao failed; owned Docker project needs manual cleanup") from error
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--host-port", type=int, default=18200)
    args = parser.parse_args()
    try:
        result = start(args.private_root, args.host_port)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        if isinstance(error, FileNotFoundError) and error.filename == "docker":
            print("disposable OpenBao startup failed [DOCKER_MISSING]: install "
                  "rootful Docker Engine and Compose, then retry with the "
                  "same daemon for operator and sudo", file=sys.stderr)
        else:
            print(f"disposable OpenBao startup failed [UNEXPECTED_{type(error).__name__.upper()}]: "
                  "check the runbook and owned-project cleanup marker", file=sys.stderr)
        return 2
    print(f"Started unqualified OpenBao project {result['project']} on loopback port {result['host_port']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
