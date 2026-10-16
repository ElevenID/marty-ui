#!/usr/bin/env python3
"""Stage keyless workload TLS inputs from the exact self-host services image.

This is a disposable Linux tester-install helper, not production provisioning.
It uses the already-running, separate OpenBao Compose project and never exports
workload private keys or copies the OpenBao root token into the stack secrets.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile

from passport_remote_tls import SELFHOST_CERT_FILES, SELFHOST_TLS_FILES, accept_remote_tls


SERVICES_IMAGE = re.compile(
    r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\Z"
)
OPENBAO_IMAGE = re.compile(
    r"ghcr\.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:[0-9a-f]{64}\Z"
)
PROJECT = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")


class BootstrapCleanupError(RuntimeError):
    """A Docker container may still retain the root-token read-only bind mount."""


def private_root(path: Path) -> Path:
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or stat.S_IMODE(path.stat().st_mode) != 0o700):
        raise ValueError("secret root must be an existing private POSIX directory")
    return path.resolve()


def regular_input(path: Path) -> Path:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise ValueError("OpenBao bootstrap input is missing or invalid")
    return path


def docker_json(args: list[str]) -> object:
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            timeout=30, check=False)
    if result.returncode:
        raise RuntimeError("Docker project inspection failed")
    return json.loads(result.stdout)


def exact_images(bundle: Path) -> tuple[str, str]:
    lock = bundle / ".marty-selfhost-images.json"
    if lock.is_symlink() or not lock.is_file():
        raise ValueError("extracted bundle has no exact image lock")
    data = json.loads(lock.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != "marty.selfhost-image-lock/v1":
        raise ValueError("extracted bundle image lock is invalid")
    services = data.get("services")
    if not isinstance(services, dict):
        raise ValueError("extracted bundle service images are invalid")
    image = services.get("gateway")
    openbao = data.get("openbao_didcomm_image")
    if (not isinstance(image, str) or not SERVICES_IMAGE.fullmatch(image)
            or services.get("signing-keys") != image
            or not isinstance(openbao, str) or not OPENBAO_IMAGE.fullmatch(openbao)):
        raise ValueError("extracted bundle lacks reviewed installer image digests")
    return image, openbao


def openbao_network(project: str, state_root: Path, expected_image: str,
                    *, expected_host_port: int | None = None) -> str:
    if not PROJECT.fullmatch(project):
        raise ValueError("OpenBao Compose project name is invalid")
    listed = subprocess.run(
        ["docker", "ps", "--filter", f"label=com.docker.compose.project={project}",
         "--filter", "label=com.docker.compose.service=openbao",
         "--format", "{{.ID}}"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if listed.returncode or len(listed.stdout.splitlines()) != 1:
        raise RuntimeError("exactly one running OpenBao service is required")
    container_id = listed.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
        raise RuntimeError("exactly one running OpenBao service is required")
    details = docker_json(["inspect", container_id])
    if not isinstance(details, list) or len(details) != 1:
        raise RuntimeError("OpenBao container inspection is invalid")
    container = details[0]
    labels = container.get("Config", {}).get("Labels", {})
    if (container.get("State", {}).get("Running") is not True
            or container.get("Config", {}).get("Image") != expected_image
            or labels.get("com.docker.compose.project") != project
            or labels.get("com.docker.compose.service") != "openbao"):
        raise RuntimeError("OpenBao container does not match the locked bundle image")
    mounts = container.get("Mounts", [])
    if not any(mount.get("Destination") == "/bao/data"
               and mount.get("Type") == "bind"
               and Path(mount.get("Source", "")).resolve() == state_root
               for mount in mounts):
        raise RuntimeError("OpenBao container does not own the selected state root")
    if expected_host_port is not None:
        bindings = container.get("NetworkSettings", {}).get("Ports", {}).get("8200/tcp")
        if (not 1 <= expected_host_port <= 65535
                or not isinstance(bindings, list) or len(bindings) != 1
                or bindings[0].get("HostIp") != "127.0.0.1"
                or bindings[0].get("HostPort") != str(expected_host_port)):
            raise RuntimeError("OpenBao container does not own the loopback HTTPS port")
    networks = container.get("NetworkSettings", {}).get("Networks", {})
    matches = [name for name, binding in networks.items()
               if "openbao" in binding.get("Aliases", [])]
    if len(matches) != 1:
        raise RuntimeError("OpenBao has no unique private service network")
    return matches[0]


def provision(bundle: Path, secret_root: Path, state_root: Path, project: str) -> None:
    if os.name != "posix" or os.geteuid() != 0:
        raise ValueError("disposable TLS staging requires sudo on Linux")
    secret_root = private_root(secret_root)
    if not state_root.is_absolute() or state_root.is_symlink() or not state_root.is_dir():
        raise ValueError("OpenBao state root is invalid")
    state_root = state_root.resolve()
    if (state_root / "tls").is_symlink():
        raise ValueError("OpenBao TLS directory must not be a symlink")
    ca = regular_input(state_root / "tls" / "ca.crt")
    root_file = regular_input(state_root / "root.token")
    image, openbao_image = exact_images(bundle)
    network = openbao_network(project, state_root, openbao_image)
    if any((secret_root / name).exists() or (secret_root / name).is_symlink()
           for name in SELFHOST_TLS_FILES):
        raise ValueError("workload TLS secrets already exist; refusing overwrite")
    with tempfile.TemporaryDirectory(prefix="marty-selfhost-tls-",
                                     dir=secret_root.parent) as temporary:
        output = Path(temporary)
        output.chmod(0o700)
        if any("," in str(path) or "\n" in str(path) for path in (ca, root_file, output)):
            raise ValueError("OpenBao input path cannot be used in a Docker bind mount")
        cidfile = output.parent / f"{output.name}.cid"
        command = [
            "docker", "run", "--rm", "--cidfile", str(cidfile),
            "--pull=missing", "--network", network,
            "--user", "0:0", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,mode=1777",
            "--mount", f"type=bind,src={ca},dst=/input/ca.crt,readonly",
            "--mount", f"type=bind,src={root_file},dst=/input/root.token,readonly",
            "--mount", f"type=bind,src={output},dst=/output",
            "-e", "BAO_ADDR=https://openbao:8200", "-e", "BAO_CACERT=/input/ca.crt",
            "-e", "BAO_ROOT_TOKEN_FILE=/input/root.token",
            "-e", "MARTY_TLS_BOOTSTRAP_PROFILE=selfhost-disposable",
            "-e", "MARTY_SELFHOST_DISPOSABLE_OPENBAO=1",
            "-e", f"MARTY_SELFHOST_PROJECT=marty-selfhost-disposable-{secrets.token_hex(5)}",
            "-e", "SELFHOST_TLS_OUTPUT_DIR=/output",
            "--entrypoint", "/usr/local/bin/marty-passport-tls-bootstrap", image,
        ]
        remove_cidfile = True
        try:
            result = subprocess.run(command, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=180, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            if cidfile.exists():
                remove_cidfile = False
                container_id = cidfile.read_text(encoding="ascii").strip()
                if not re.fullmatch(r"[0-9a-f]{64}", container_id):
                    raise BootstrapCleanupError(
                        f"invalid bootstrap cidfile; inspect {cidfile}"
                    ) from error
                try:
                    removed = subprocess.run(["docker", "rm", "--force", container_id],
                                             stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL,
                                             timeout=30, check=False)
                except (OSError, subprocess.TimeoutExpired) as cleanup_error:
                    raise BootstrapCleanupError(
                        f"manual cleanup required: docker rm --force {container_id}; "
                        f"cidfile retained at {cidfile}"
                    ) from cleanup_error
                if removed.returncode:
                    raise BootstrapCleanupError(
                        f"manual cleanup required: docker rm --force {container_id}; "
                        f"cidfile retained at {cidfile}"
                    ) from error
                remove_cidfile = True
            raise
        finally:
            if remove_cidfile:
                cidfile.unlink(missing_ok=True)
        if result.returncode:
            raise RuntimeError("keyless workload TLS bootstrap failed; no inputs were staged")
        accept_remote_tls(
            output, secret_root, root_file.read_text(encoding="ascii").strip(),
            expected_files=SELFHOST_TLS_FILES, certificate_files=SELFHOST_CERT_FILES,
        )
        owner = secret_root.stat()
        try:
            for name in SELFHOST_TLS_FILES:
                os.chown(secret_root / name, owner.st_uid, owner.st_gid)
        except OSError as error:
            rollback_failed = False
            for name in SELFHOST_TLS_FILES:
                try:
                    (secret_root / name).rename(output / name)
                except OSError:
                    rollback_failed = True
            if rollback_failed:
                raise RuntimeError("workload TLS ownership rollback is incomplete") from error
            raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-root", required=True, type=Path)
    parser.add_argument("--openbao-state-root", required=True, type=Path)
    parser.add_argument("--openbao-project", default="marty-selfhost-openbao")
    args = parser.parse_args()
    try:
        provision(Path(__file__).resolve().parent.parent, args.secret_root,
                  args.openbao_state_root, args.openbao_project)
    except BootstrapCleanupError as error:
        print(f"disposable workload TLS staging failed: {error}", file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired,
            json.JSONDecodeError) as error:
        print(f"disposable workload TLS staging failed: {type(error).__name__}",
              file=sys.stderr)
        return 2
    print(f"Staged {len(SELFHOST_TLS_FILES)} keyless workload TLS inputs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
