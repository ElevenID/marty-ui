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

# This helper runs from inside the extracted, receipt-verified ZIP. Importing
# its sibling module must not add a __pycache__ entry to that immutable tree.
sys.dont_write_bytecode = True
from passport_remote_tls import SELFHOST_CERT_FILES, SELFHOST_TLS_FILES, accept_remote_tls


SERVICES_IMAGE = re.compile(
    r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\Z"
)
OPENBAO_IMAGE = re.compile(
    r"ghcr\.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:[0-9a-f]{64}\Z"
)
PROJECT = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
KEY_METADATA_FILE = "selfhost-tls-kms-roles.json"
KEY_ENV_FRAGMENT_FILE = "selfhost-tls-kms.env.fragment"
KMS_ASSIGNMENT = re.compile(r"([A-Z][A-Z0-9_]*_TLS_KMS_KEY_(?:NAME|VERSION))=([^\r\n]*)\Z")
KMS_REQUIRED_VARIABLE = re.compile(
    r"\$\{([A-Z][A-Z0-9_]*_TLS_KMS_KEY_(?:NAME|VERSION)):\?[^}]*\}\Z"
)
# An independent acceptance contract for the fixed disposable bootstrap role
# names. This is metadata, not a source of key material or a complete env file.
KEY_NAMES = {
    "signing-keys-server": "workload-tls-signing-keys-server",
    "gateway-client": "workload-tls-gateway-auth-client",
    "auth-client": "workload-tls-auth-client",
    "auth-server": "workload-tls-auth-server",
    "compliance-profile-client": "workload-tls-compliance-profile-client",
    "deployment-profile-client": "workload-tls-deployment-profile-client",
    "organization-server": "workload-tls-organization-server",
    "event-stream-server": "workload-tls-event-stream-server",
    "notification-server": "workload-tls-notification-server",
    "revocation-profile-server": "workload-tls-revocation-profile-server",
    "credential-template-server": "workload-tls-credential-template-server",
    "issuance-server": "workload-tls-issuance-server",
    "flow-client": "workload-tls-flow-client",
    "flow-server": "workload-tls-flow-server",
    "pp-server": "workload-tls-presentation-policy-server",
    "verification-client": "workload-tls-verification-client",
}
# Compose/.env prefixes are not derivable from role spelling (ORG, CT, RP,
# GATEWAY, etc.). Keep this independent wiring contract explicit so two valid
# key names cannot be silently interchanged between workloads.
ENV_PREFIX_ROLE = {
    "SIGNING_KEYS": "signing-keys-server",
    "GATEWAY": "gateway-client",
    "AUTH": "auth-client",
    "AUTH_SERVER": "auth-server",
    "COMPLIANCE_PROFILE": "compliance-profile-client",
    "DEPLOYMENT_PROFILE": "deployment-profile-client",
    "ORG": "organization-server",
    "ES": "event-stream-server",
    "NOTIFICATION": "notification-server",
    "RP": "revocation-profile-server",
    "CT": "credential-template-server",
    "ISSUANCE": "issuance-server",
    "FLOW_CLIENT": "flow-client",
    "FLOW_SERVER": "flow-server",
    "PP": "pp-server",
    "VERIFICATION": "verification-client",
}


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


def verified_key_metadata(output: Path) -> dict[str, object]:
    path = output / KEY_METADATA_FILE
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    elif path.is_symlink():
        raise ValueError("OpenBao bootstrap input is missing or invalid")
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise ValueError("OpenBao bootstrap input is missing or invalid") from error
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("OpenBao bootstrap input is missing or invalid")
        if metadata.st_size > 8192:
            raise ValueError("disposable TLS key metadata is oversized")
        chunks: list[bytes] = []
        remaining = 8193
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        contents = b"".join(chunks)
        if len(contents) > 8192:
            raise ValueError("disposable TLS key metadata is oversized")
    finally:
        os.close(fd)

    def unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
        fields = dict(pairs)
        if len(fields) != len(pairs):
            raise ValueError("disposable TLS key metadata has duplicate fields")
        return fields

    document = json.loads(contents.decode("ascii"), object_pairs_hook=unique_fields)
    if (not isinstance(document, dict)
            or set(document) != {"schema", "roles"}
            or document["schema"] != "marty.selfhost-disposable-tls-keys/v1"
            or not isinstance(document["roles"], list)
            or len(document["roles"]) != len(KEY_NAMES)):
        raise ValueError("disposable TLS key metadata has invalid shape")
    roles = document["roles"]
    if any(not isinstance(entry, dict)
           or set(entry) != {"role", "key_name", "version"}
           or not isinstance(entry["role"], str)
           or KEY_NAMES.get(entry["role"]) != entry["key_name"]
           or type(entry["version"]) is not int or entry["version"] != 1
           for entry in roles):
        raise ValueError("disposable TLS key metadata differs from fixed roles")
    if {entry["role"] for entry in roles} != set(KEY_NAMES):
        raise ValueError("disposable TLS key metadata omits or duplicates a role")
    return document


def _bundle_text(path: Path, maximum: int) -> str:
    """Read only a bounded regular input from the extracted bundle."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    elif path.is_symlink():
        raise ValueError("extracted TLS configuration input is invalid")
    try:
        fd = os.open(path, flags)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                raise ValueError("extracted TLS configuration input is invalid")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            contents = b"".join(chunks)
            if len(contents) > maximum:
                raise ValueError("extracted TLS configuration input is invalid")
            return contents.decode("ascii")
        finally:
            os.close(fd)
    except (OSError, UnicodeError) as error:
        raise ValueError("extracted TLS configuration input is invalid") from error


def render_tls_env_fragment(bundle: Path, metadata: dict[str, object]) -> str:
    """Map verified bootstrap roles to only the required shipped KMS env pairs."""
    example = _bundle_text(bundle / ".env.selfhost.production.example", 16 * 1024)
    compose = _bundle_text(bundle / "docker-compose.yml", 128 * 1024)
    example_values: dict[str, str] = {}
    for line in example.splitlines():
        if "_TLS_KMS_KEY_" not in line or line.lstrip().startswith("#"):
            continue
        match = KMS_ASSIGNMENT.fullmatch(line)
        if not match or match[1] in example_values:
            raise ValueError("shipped TLS KMS example assignments are invalid")
        example_values[match[1]] = match[2]
    kms_variables = [match.group() for match in re.finditer(r"\$\{[^}]*\}", compose)
                     if "_TLS_KMS_KEY_" in match.group()]
    required = [KMS_REQUIRED_VARIABLE.fullmatch(variable) for variable in kms_variables]
    if any(match is None for match in required):
        raise ValueError("shipped TLS KMS Compose references are invalid")
    references = [match[1] for match in required]
    names = {key for key in example_values if key.endswith("_KEY_NAME")}
    versions = {key for key in example_values if key.endswith("_KEY_VERSION")}
    if (len(names) != len(KEY_NAMES) or len(versions) != len(KEY_NAMES)
            or set(ENV_PREFIX_ROLE.values()) != set(KEY_NAMES)
            or names != {f"{prefix}_TLS_KMS_KEY_NAME" for prefix in ENV_PREFIX_ROLE}
            or len(references) != 2 * len(KEY_NAMES)
            or set(references) != set(example_values)
            or len(set(references)) != len(references)
            or {key.removesuffix("_NAME") + "_VERSION" for key in names} != versions
            or any(example_values[key] != "1" for key in versions)):
        raise ValueError("shipped TLS KMS example and Compose inventory differ")
    if any(example_values[f"{prefix}_TLS_KMS_KEY_NAME"] != KEY_NAMES[role]
           for prefix, role in ENV_PREFIX_ROLE.items()):
        raise ValueError("shipped TLS KMS example assigns a key to the wrong role")
    roles = metadata["roles"]
    verified_versions = {entry["key_name"]: entry["version"] for entry in roles}
    if (len(verified_versions) != len(KEY_NAMES)
            or set(verified_versions) != {example_values[key] for key in names}
            or any(verified_versions[value] != 1 for value in verified_versions)):
        raise ValueError("shipped TLS KMS names differ from verified roles")
    return "".join(
        f"{key}={example_values[key]}\n"
        f"{key.removesuffix('_NAME')}_VERSION={verified_versions[example_values[key]]}\n"
        for key in sorted(names)
    )


def protected_root_token_metadata(uid: int, mode: int) -> bool:
    return uid == 0 and stat.S_IMODE(mode) == 0o400


def read_protected_root_token(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("OpenBao root token is missing or invalid")
    metadata = path.stat()
    if not protected_root_token_metadata(metadata.st_uid, metadata.st_mode):
        raise ValueError("OpenBao root token has unsafe ownership or mode")
    value = path.read_text(encoding="ascii").strip()
    if not 16 <= len(value) <= 2048 or not re.fullmatch(r"[A-Za-z0-9._-]+", value):
        raise ValueError("OpenBao root token is invalid")
    return value


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
        if not 1 <= expected_host_port <= 65535:
            raise RuntimeError("OpenBao container does not own the loopback HTTPS port")
        binding = [{"HostIp": "127.0.0.1", "HostPort": str(expected_host_port)}]
        ports = container.get("NetworkSettings", {}).get("Ports", {})
        configured = container.get("HostConfig", {}).get("PortBindings", {})
        health = container.get("State", {}).get("Health", {}).get("Status")
        if (ports.get("8200/tcp") != binding
                or configured.get("8200/tcp") != binding
                or health != "healthy"):
            raise RuntimeError("OpenBao container does not own the loopback HTTPS port")
    networks = container.get("NetworkSettings", {}).get("Networks", {})
    matches = [name for name, binding in networks.items()
               if "openbao" in binding.get("Aliases", [])]
    if len(matches) != 1:
        raise RuntimeError("OpenBao has no unique private service network")
    return matches[0]


def verified_openbao_owner(project: str, state_root: Path, install_root: Path,
                           port: int) -> str:
    """Verify the selected endpoint belongs to the locked, healthy container."""
    if install_root.is_symlink() or not install_root.is_dir():
        raise ValueError("extracted self-host install is missing")
    _, image = exact_images(install_root)
    openbao_network(project, state_root, image, expected_host_port=port)
    return image


def preview_openbao_owner(root: Path, state_root: Path, install_root: Path) -> tuple[str, int]:
    """Bind a staged preview's OpenBao report to its locked running container."""
    marker = regular_input(root / "openbao.json")
    report = json.loads(marker.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("disposable OpenBao lineage is invalid")
    project = report.get("project")
    port = report.get("host_port")
    if (report.get("schema") != "marty.selfhost-disposable-openbao/v1"
            or report.get("qualification") != "unqualified"
            or not isinstance(project, str)
            or not re.fullmatch(r"marty-preview-[0-9a-f]{16}", project)
            or type(port) is not int or not 1024 <= port <= 65535):
        raise ValueError("disposable OpenBao lineage is invalid")
    image = verified_openbao_owner(project, state_root, install_root, port)
    if report.get("image") != image:
        raise ValueError("OpenBao runtime image differs from preview lock")
    return project, port


def provision(bundle: Path, secret_root: Path, state_root: Path, project: str) -> None:
    if os.name != "posix" or os.geteuid() != 0:
        raise ValueError("disposable TLS staging requires sudo on Linux")
    secret_root = private_root(secret_root)
    metadata_parent = private_root(secret_root.parent)
    if metadata_parent.stat().st_uid != secret_root.stat().st_uid:
        raise ValueError("disposable TLS key metadata parent has a different owner")
    metadata_destination = metadata_parent / KEY_METADATA_FILE
    fragment_destination = metadata_parent / KEY_ENV_FRAGMENT_FILE
    if any(path.exists() or path.is_symlink()
           for path in (metadata_destination, fragment_destination)):
        raise ValueError("disposable TLS key diagnostic already exists")
    # Check the installed Compose/example pair before starting the disposable
    # container; final values are rendered only from verified live metadata.
    configuration = render_tls_env_fragment(bundle, {
        "roles": [{"key_name": name, "version": 1} for name in KEY_NAMES.values()],
    })
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
        key_metadata = verified_key_metadata(output)
        fragment = render_tls_env_fragment(bundle, key_metadata)
        if fragment != configuration:
            raise ValueError("shipped TLS KMS configuration changed during bootstrap")
        (output / KEY_METADATA_FILE).unlink()
        accept_remote_tls(
            output, secret_root, root_file.read_text(encoding="ascii").strip(),
            expected_files=SELFHOST_TLS_FILES, certificate_files=SELFHOST_CERT_FILES,
        )
        owner = secret_root.stat()
        created_diagnostics: list[Path] = []
        try:
            for name in SELFHOST_TLS_FILES:
                os.chown(secret_root / name, owner.st_uid, owner.st_gid)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            for destination, contents in (
                (metadata_destination, json.dumps(key_metadata, sort_keys=True,
                                                  separators=(",", ":"))),
                (fragment_destination, fragment),
            ):
                fd = os.open(destination, flags, 0o600)
                created_diagnostics.append(destination)
                with os.fdopen(fd, "w", encoding="ascii") as stream:
                    os.fchown(stream.fileno(), owner.st_uid, owner.st_gid)
                    stream.write(contents)
                    stream.flush()
                    os.fsync(stream.fileno())
        except OSError as error:
            rollback_failed = False
            for destination in reversed(created_diagnostics):
                try:
                    destination.unlink(missing_ok=True)
                except OSError:
                    rollback_failed = True
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
