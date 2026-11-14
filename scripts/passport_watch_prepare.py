"""Prepare and inspect the local passport watcher's exact dependency seed.

This is a development image helper, not a release producer or a cache manager.
Preparation never reads a passport plan or creates application resources.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid


SEED_LABEL = "com.marty.passport.watch.seed"
LOCK_LABEL = "com.marty.passport.watch.cargo-lock"
IMAGE_PREFIX = "marty-passport-rust-watch:local-"
BASE_IMAGE = "rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1"
PREPARATION_LABEL = "com.marty.passport.watch.preparation"
TOKEN_TARGET = "/run/secrets/private_forks_read_token"
CACHE_VOLUMES = ("passport_watch_registry", "passport_watch_git", "passport_watch_target")
SOURCE_READER_ENV = ("PRIVATE_FORKS_READ_TOKEN", "PRIVATE_FORKS_TOKEN_FILE")
PREPARATION_FILES = (
    "rust/Cargo.lock",
    "services/Dockerfile.passport-watch",
    "services/Dockerfile.passport-watch.dockerignore",
    ".github/scripts/private-forks.py",
    "scripts/passport_watch_prepare.py",
)
FETCH_MEMORY = 2 * 1024 ** 3
FETCH_PIDS = 128


class WatchPreparationError(RuntimeError):
    """Fixed diagnostics never include credentials or raw Docker output."""


def seed_identity(root: Path) -> tuple[str, str]:
    """Bind dependency inputs and the preparation recipe, allowing Rust edits."""
    root = root.resolve(strict=True)
    paths = set(PREPARATION_FILES)
    paths.update(path.relative_to(root).as_posix()
                 for path in (root / "rust").rglob("Cargo.toml")
                 if not {"target", ".git", ".cargo"}.intersection(path.relative_to(root).parts))
    if "rust/Cargo.toml" not in paths:
        raise WatchPreparationError("Watcher workspace manifest is missing")
    digest = hashlib.sha256(b"marty-passport-watch-seed-v1\0")
    for name in sorted(paths):
        path = root / name
        if not path.is_file() or path.is_symlink() or path.resolve() != path:
            raise WatchPreparationError("Watcher preparation input is missing or redirected")
        digest.update(name.encode("utf-8") + b"\0" + path.read_bytes() + b"\0")
    lock = hashlib.sha256((root / "rust/Cargo.lock").read_bytes()).hexdigest()
    return digest.hexdigest(), lock


def credential_free_environment(environment: dict[str, str]) -> dict[str, str]:
    """No source reader or alternate builder reaches policy/compiler phases."""
    return {name: value for name, value in environment.items()
            if name not in SOURCE_READER_ENV
            and not name.startswith(("BUILDX_", "BUILDKIT_"))
            and name not in ("DOCKER_BUILDKIT", "COMPOSE_BAKE", "COMPOSE_DOCKER_CLI_BUILD")}


def docker_environment(environment: dict[str, str]) -> dict[str, str]:
    # Keep the seed-check CLI usable inside the image without host Docker code.
    if not __package__:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from scripts.local_docker import local_docker_environment
    return local_docker_environment(credential_free_environment(environment))


def _command(args: list[str], environment: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    try:
        selected = docker_environment(environment)
    except (OSError, ValueError) as exc:
        raise WatchPreparationError("Watcher local Docker endpoint is unavailable or changed") from exc
    # --host also binds the built-in default builder when the user's current
    # context is "default" but its stored endpoint is the legacy rootful one.
    return ["docker", "--host", selected["DOCKER_HOST"], *args], selected


def inspect_docker(args: list[str], environment: dict[str, str]) -> str:
    command, selected = _command(args, environment)
    try:
        result = subprocess.run(command, env=selected, capture_output=True,
                                text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise WatchPreparationError("Watcher Docker inspection failed") from exc
    if result.returncode:
        raise WatchPreparationError("Watcher Docker inspection failed; preparation may be required")
    return result.stdout


def require_resource_limits(environment: dict[str, str]) -> None:
    try:
        info = json.loads(inspect_docker(["info", "--format", "{{json .}}"], environment))
    except (ValueError, TypeError) as exc:
        raise WatchPreparationError("Watcher Docker resource inspection is invalid") from exc
    if (not isinstance(info, dict)
        or info.get("OSType") != "linux" or str(info.get("CgroupVersion")) != "2"
        or info.get("CgroupDriver") != "systemd"
        or any(info.get(name) is not True for name in (
            "MemoryLimit", "SwapLimit", "CpuCfsPeriod", "CpuCfsQuota", "PidsLimit",
        ))):
        raise WatchPreparationError("Watcher requires enforced Linux CPU, memory and swap limits")


def require_local_builder(environment: dict[str, str]) -> None:
    selected = docker_environment(environment)
    output = inspect_docker(["buildx", "inspect", "default"], selected)
    drivers = re.findall(r"^Driver:\s*(\S+)\s*$", output, re.MULTILINE)
    endpoints = re.findall(r"^Endpoint:\s*(\S+)\s*$", output, re.MULTILINE)
    names = re.findall(r"^Name:\s*(\S+)\s*$", output, re.MULTILINE)
    statuses = re.findall(r"^Status:\s*(\S+)\s*$", output, re.MULTILINE)
    if (drivers != ["docker"] or names != ["default", "default"]
        or statuses != ["running"] or len(endpoints) != 1
        or endpoints[0] not in ("default", selected["DOCKER_HOST"])):
        raise WatchPreparationError("Watcher preparation requires the existing default local builder")


def checked_token_file(path: Path, root: Path) -> tuple[int, int, int, int]:
    """Admit an explicit private file without importing it into the context."""
    if os.name != "posix" or os.getuid() != os.geteuid():
        raise WatchPreparationError("Watcher preparation requires an ordinary local file owner")
    try:
        root = root.resolve(strict=True)
        if (not path.is_absolute() or path.resolve(strict=True) != path
            or any(character in str(path) for character in (",", "\n", "\r"))
            or path.is_relative_to(root)):
            raise WatchPreparationError("Source-reader file must be canonical and outside the checkout")
        for parent in path.parents:
            parent_info = parent.lstat()
            private_parent = parent == path.parent
            system_temporary = (parent == Path("/tmp") and parent_info.st_uid == 0
                                and parent_info.st_mode & stat.S_ISVTX)
            if (not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid not in (0, os.geteuid())
                or (private_parent and (parent_info.st_uid != os.geteuid()
                                        or stat.S_IMODE(parent_info.st_mode) != 0o700))
                or (not private_parent and parent_info.st_mode & 0o022 and not system_temporary)):
                raise WatchPreparationError("Source-reader file requires a private parent and safe ancestors")
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not 1 <= info.st_size <= 8192):
            raise WatchPreparationError("Source-reader file must be owned, private and nonempty")
        # Validate only shape; never put the value in an environment or argument.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                opened.st_uid, opened.st_mode, opened.st_nlink) != (
                    info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                    info.st_uid, info.st_mode, info.st_nlink):
                raise WatchPreparationError("Source-reader file changed during validation")
            value = stream.read(8193).rstrip(b"\r\n")
        after = path.lstat()
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise WatchPreparationError("Source-reader file changed during validation")
        if not value or b"\r" in value or b"\n" in value or b"\0" in value:
            raise WatchPreparationError("Source-reader file has invalid contents")
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
    except OSError as exc:
        raise WatchPreparationError("Source-reader file is unavailable") from exc


def prepared_image(root: Path, environment: dict[str, str]) -> dict[str, str]:
    seed, lock = seed_identity(root)
    try:
        rows = json.loads(inspect_docker(["image", "inspect", IMAGE_PREFIX + seed], environment))
        image = rows[0] if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) else {}
        config = image.get("Config") or {}
        labels = (config.get("Labels") or {}) if isinstance(config, dict) else {}
        image_id = image.get("Id", "")
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise WatchPreparationError("Prepared watcher image inspection is invalid") from exc
    if (not isinstance(image_id, str) or not isinstance(labels, dict)
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id)
        or labels.get(SEED_LABEL) != seed or labels.get(LOCK_LABEL) != lock):
        raise WatchPreparationError("Watcher image is unprepared or stale; run --prepare first")
    return {"PASSPORT_WATCH_IMAGE": image_id, "PASSPORT_WATCH_SEED_ID": seed,
            "PASSPORT_WATCH_LOCK_SHA256": lock}


def require_current_volumes(project: str, seed: str, environment: dict[str, str]) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]+", project):
        raise WatchPreparationError("Watcher project identity is invalid")
    expected = {f"{project}_{name}": name for name in CACHE_VOLUMES}
    names = inspect_docker([
        "volume", "ls", "--format", "{{.Name}}", "--filter",
        f"name=^{project}_passport_watch_",
    ], environment).splitlines()
    # A resume after bootstrap failure may not have created any watcher volumes.
    if not names:
        return
    if len(names) != len(expected) or set(names) != set(expected):
        raise WatchPreparationError("Watcher cache volume set is incomplete or unexpected")
    try:
        rows = json.loads(inspect_docker(["volume", "inspect", *sorted(names)], environment))
    except (ValueError, TypeError) as exc:
        raise WatchPreparationError("Watcher cache volume inspection is invalid") from exc
    if (not isinstance(rows, list) or len(rows) != len(expected)
        or any(not isinstance(row, dict) for row in rows)
        or {row.get("Name") for row in rows} != set(expected)):
        raise WatchPreparationError("Watcher cache volume inspection is invalid")
    for row in rows:
        labels = row.get("Labels") or {}
        if (not isinstance(labels, dict)
            or row.get("Driver") != "local" or row.get("Scope") != "local"
            or row.get("Options") not in (None, {})
            or labels.get("com.docker.compose.project") != project
            or labels.get("com.docker.compose.volume") != expected[row["Name"]]
            or labels.get(SEED_LABEL) != seed):
            raise WatchPreparationError("Watcher cache seed changed; use a fresh disposable project")


def _source_allowed(name: str) -> bool:
    path = Path(name)
    return (not path.is_absolute() and ".." not in path.parts
            and (name in PREPARATION_FILES or path.parts[:1] == ("rust",))
            and not any(part in (".git", ".cargo", "target") or part.startswith(".env")
                        or part.endswith(".log") for part in path.parts))


def snapshot_source(root: Path, destination: Path, environment: dict[str, str]) -> None:
    """Copy current tracked input bytes, never the checkout's local state."""
    inventory_env = {name: value for name, value in credential_free_environment(environment).items()
                     if not name.startswith("GIT_")}
    inventory_env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                         GIT_CONFIG_SYSTEM=os.devnull)
    try:
        result = subprocess.run(["git", "-C", str(root), "-c", "core.fsmonitor=false",
                                 "ls-files", "--cached", "--full-name", "-z", "--", "rust"],
                                env=inventory_env, capture_output=True,
                                text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise WatchPreparationError("Watcher source inventory failed") from exc
    if result.returncode:
        raise WatchPreparationError("Watcher source inventory failed")
    names = set(result.stdout.rstrip("\0").split("\0")) | set(PREPARATION_FILES)
    destination.mkdir(mode=0o700)
    for name in sorted(name for name in names if _source_allowed(name)):
        path = root / name
        if not path.exists() and not path.is_symlink() and name not in PREPARATION_FILES:
            continue  # A tracked deletion is part of the current source tree.
        if not path.is_file() or path.is_symlink() or path.resolve() != path:
            raise WatchPreparationError("Watcher source input is missing or redirected")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        target.chmod(stat.S_IMODE(path.stat().st_mode) & 0o755)
    if seed_identity(destination) != seed_identity(root):
        raise WatchPreparationError("Watcher snapshot is missing dependency inputs; stage new Cargo manifests first")


def assembly_context(source: Path, context: Path) -> Path:
    """The local builder receives dependency directories, never source or reader."""
    recipe = (source / "services/Dockerfile.passport-watch").read_text()
    instructions = [line.strip() for line in recipe.replace("\\\n", " ").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    if (re.search(r"^\s*#\s*(?:syntax|escape)\s*=", recipe, re.IGNORECASE | re.MULTILINE)
        or any(line.split()[0] not in {"FROM", "ARG", "COPY", "LABEL", "ENV", "WORKDIR", "ENTRYPOINT"}
               for line in instructions)
        or [line for line in instructions if line.startswith("FROM ")] != [f"FROM {BASE_IMAGE}"]
        or [line for line in instructions if line.startswith("COPY ")] != [
            "COPY --chown=0:0 cargo/registry/ /usr/local/cargo/registry/",
            "COPY --chown=0:0 cargo/git/ /usr/local/cargo/git/",
        ]):
        raise WatchPreparationError("Watcher assembly recipe must only copy the two dependency caches")
    context.mkdir(mode=0o700)
    (context / "Dockerfile").write_text(recipe)
    (context / "Dockerfile.dockerignore").write_bytes(
        (source / "services/Dockerfile.passport-watch.dockerignore").read_bytes())
    cargo = context / "cargo"
    cargo.mkdir(mode=0o700)
    for name in ("registry", "git"):
        (cargo / name).mkdir(mode=0o700)
    return cargo


def _private_run(args: list[str], environment: dict[str, str], log: Path, timeout: int = 900) -> None:
    command, selected = _command(args, environment)
    with log.open("ab") as output:
        try:
            result = subprocess.run(command, env=selected, stdout=output, stderr=output,
                                    timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise WatchPreparationError(f"Watcher preparation interrupted; private log: {log}") from exc
    if result.returncode:
        raise WatchPreparationError(f"Watcher preparation failed; private log: {log}")


def _one_record(args: list[str], environment: dict[str, str]) -> dict:
    try:
        rows = json.loads(inspect_docker(args, environment))
    except (ValueError, TypeError) as exc:
        raise WatchPreparationError("Watcher preparation inspection is invalid") from exc
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise WatchPreparationError("Watcher preparation inspection is invalid")
    return rows[0]


def _owned_container(container_id: str, owner: str, name: str, environment: dict[str, str]) -> dict:
    row = _one_record(["container", "inspect", container_id], environment)
    config = row.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (row.get("Id") != container_id or row.get("Name") != "/" + name
        or not isinstance(labels, dict) or labels.get(PREPARATION_LABEL) != owner):
        raise WatchPreparationError("Watcher preparation container ownership changed")
    return row


def _verify_container(row: dict, image_id: str, mounts: list[tuple[Path, str, bool]],
                      expected_env: dict[str, str], phase: str, command: list[str]) -> None:
    host = row.get("HostConfig") or {}
    config = row.get("Config") or {}
    try:
        actual_mounts = sorted((entry["Source"], entry["Destination"], not entry["RW"])
                               for entry in row.get("Mounts", []) if entry.get("Type") == "bind")
        actual_env = dict(entry.split("=", 1) for entry in config.get("Env", []))
    except (ValueError, TypeError, KeyError) as exc:
        raise WatchPreparationError("Watcher preparation container configuration is invalid") from exc
    if (row.get("Image") != image_id or config.get("Image") != BASE_IMAGE
        or config.get("Entrypoint") != ["/bin/bash"] or config.get("Cmd") != command
        or config.get("WorkingDir") != "/workspace/rust" or config.get("User") not in ("", "0", "0:0")
        or actual_env != expected_env or len(actual_env) != len(config.get("Env", []))
        or len(actual_mounts) != len(row.get("Mounts", []))
        or actual_mounts != sorted((str(path), target, readonly) for path, target, readonly in mounts)
        or any(entry.get("Propagation") not in (None, "", "rprivate") for entry in row.get("Mounts", []))
        or host.get("Memory") != FETCH_MEMORY or host.get("MemorySwap") != FETCH_MEMORY
        or host.get("CpuPeriod") != 100000 or host.get("CpuQuota") != 100000
        or host.get("PidsLimit") != FETCH_PIDS or host.get("ReadonlyRootfs") is not True
        or host.get("Privileged") is not False or host.get("CapAdd") not in (None, [])
        or host.get("CapDrop") != ["ALL"] or host.get("SecurityOpt") != ["no-new-privileges"]
        or host.get("NetworkMode") != ("bridge" if phase == "fetch" else "none")
        or host.get("CgroupnsMode") != "private" or host.get("PidMode") not in (None, "")
        or host.get("PortBindings") not in (None, {}) or host.get("PublishAllPorts") is not False
        or host.get("Devices") not in (None, []) or host.get("DeviceRequests") not in (None, [])
        or host.get("Tmpfs") != {"/tmp": "rw,noexec,nosuid,nodev,size=67108864"}
        or (host.get("RestartPolicy") or {}).get("Name") != "no"
        or (row.get("State") or {}).get("Status") != "created"):
        raise WatchPreparationError("Watcher preparation container does not match the bounded isolated configuration")


class WatchPreparationCleanupError(WatchPreparationError):
    """Retain private paths if their owned container could not be removed."""


def _prepare_phase(root: Path, source: Path, cargo: Path, directory: Path, phase: str,
                   token_file: Path, token_identity: tuple[int, int, int, int],
                   identity: tuple[str, str], base: dict, environment: dict[str, str], log: Path) -> None:
    owner = uuid.uuid4().hex
    name = f"marty-passport-prepare-{phase}-{owner}"
    cidfile = directory / f"{phase}-container-id"
    mounts = [(source, "/workspace", True), (cargo, "/cargo-cache", phase == "probe")]
    if phase == "fetch":
        mounts.append((token_file, TOKEN_TARGET, True))
    values = {"CARGO_HOME": "/cargo-cache", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1",
              "CARGO_NET_OFFLINE": "false" if phase == "fetch" else "true",
              "PASSPORT_WATCH_SEED_ID": identity[0], "PASSPORT_WATCH_LOCK_SHA256": identity[1]}
    # Docker's CLI may supply proxy defaults from its config; preparation admits
    # no ambient routing or credentials into either container.
    values.update({name: "" for upper in ("HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "ALL_PROXY", "NO_PROXY")
                   for name in (upper, upper.lower())})
    expected_env = dict(entry.split("=", 1) for entry in base["Config"].get("Env", [])) | values
    command = ["-euc", "exec python3 /workspace/scripts/passport_watch_prepare.py --" + phase + "-dependencies"]
    args = ["create", "--name", name, "--cidfile", str(cidfile), "--pull", "never",
            "--label", f"{PREPARATION_LABEL}={owner}", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--memory", str(FETCH_MEMORY),
            "--memory-swap", str(FETCH_MEMORY), "--cpu-period", "100000", "--cpu-quota", "100000",
            "--pids-limit", str(FETCH_PIDS), "--cgroupns", "private", "--restart", "no",
            "--network", "bridge" if phase == "fetch" else "none",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864", "--workdir", "/workspace/rust",
            "--entrypoint", "/bin/bash"]
    for path, target, readonly in mounts:
        args.extend(["--mount", f"type=bind,src={path},dst={target}" + (",readonly" if readonly else "")])
    for key, value in values.items():
        args.extend(["--env", f"{key}={value}"])
    args.extend([BASE_IMAGE, *command])
    container_id = ""
    try:
        _private_run(args, environment, log, 30)
        container_id = cidfile.read_text().strip()
        if not re.fullmatch(r"[a-f0-9]{64}", container_id):
            raise WatchPreparationError("Watcher preparation container identity is invalid")
        row = _owned_container(container_id, owner, name, environment)
        _verify_container(row, base["Id"], mounts, expected_env, phase, command)
        if seed_identity(root) != identity or seed_identity(source) != identity:
            raise WatchPreparationError("Watcher dependency inputs changed before preparation")
        if phase == "fetch" and checked_token_file(token_file, root) != token_identity:
            raise WatchPreparationError("Source-reader file changed before preparation")
        _private_run(["start", "--attach", container_id], environment, log)
        row = _owned_container(container_id, owner, name, environment)
        state = row.get("State") or {}
        if state.get("Status") != "exited" or state.get("ExitCode") != 0 or state.get("OOMKilled") is not False:
            raise WatchPreparationError(f"Watcher preparation container failed; private log: {log}")
        if seed_identity(root) != identity or seed_identity(source) != identity:
            raise WatchPreparationError("Watcher dependency inputs changed during preparation")
    finally:
        try:
            # The daemon may create a container before an interrupted CLI writes
            # its ID. Discover only our unique name/label pair in that case, then
            # validate the returned immutable ID before removing anything.
            cleanup_ids = ([cidfile.read_text().strip()] if cidfile.exists() else inspect_docker([
                "container", "ls", "--all", "--quiet", "--no-trunc",
                "--filter", f"name=^/{name}$", "--filter", f"label={PREPARATION_LABEL}={owner}",
            ], environment).splitlines())
            if len(cleanup_ids) > 1:
                raise WatchPreparationError("Watcher preparation container identity is ambiguous")
            for cleanup_id in cleanup_ids:
                if not re.fullmatch(r"[a-f0-9]{64}", cleanup_id) or (container_id and cleanup_id != container_id):
                    raise WatchPreparationError("Watcher preparation container identity changed")
                _owned_container(cleanup_id, owner, name, environment)
                _private_run(["rm", "--force", cleanup_id], environment, log, 30)
        except (OSError, ValueError, WatchPreparationError) as exc:
            raise WatchPreparationCleanupError(
                f"Watcher preparation cleanup requires inspection of {name}; private log: {log}") from exc


def prepare(root: Path, token_file: Path, environment: dict[str, str]) -> tuple[dict[str, str], Path]:
    token_identity = checked_token_file(token_file, root)
    root = root.resolve(strict=True)
    selected = docker_environment(environment)
    require_resource_limits(selected)
    require_local_builder(selected)
    identity = seed_identity(root)
    directory = Path(tempfile.mkdtemp(prefix="marty-passport-watch-prepare-", dir="/tmp"))
    if directory.resolve() != directory or directory.is_relative_to(root):
        directory.rmdir()
        raise WatchPreparationError("Watcher preparation requires a private directory outside the checkout")
    log = directory / "prepare.log"
    log.touch(mode=0o600, exist_ok=False)
    source, context, iid = directory / "source", directory / "context", directory / "image-id"
    cleanup_safe = True
    try:
        snapshot_source(root, source, selected)
        cargo = assembly_context(source, context)
        _private_run(["pull", BASE_IMAGE], selected, log)
        base = _one_record(["image", "inspect", BASE_IMAGE], selected)
        if (not re.fullmatch(r"sha256:[a-f0-9]{64}", base.get("Id", ""))
            or not isinstance(base.get("Config"), dict)
            or base["Config"].get("OnBuild") or base["Config"].get("Volumes")):
            raise WatchPreparationError("Pinned watcher base image is invalid")
        for phase in ("probe", "fetch", "offline"):
            _prepare_phase(root, source, cargo, directory, phase, token_file, token_identity,
                           identity, base, selected, log)
        check_seed(source, cargo, {"PASSPORT_WATCH_SEED_ID": identity[0],
                                  "PASSPORT_WATCH_LOCK_SHA256": identity[1]})
        if any((cargo / name).exists() or (cargo / name).is_symlink()
               for name in ("credentials", "credentials.toml", "config", "config.toml")):
            raise WatchPreparationError("Watcher dependency cache contains unexpected Cargo configuration")
        args = ["build", "--builder", "default", "--network", "none", "--file", str(context / "Dockerfile"),
                "--tag", IMAGE_PREFIX + identity[0], "--iidfile", str(iid), "--progress", "plain",
                "--build-arg", f"PASSPORT_WATCH_SEED_ID={identity[0]}",
                "--build-arg", f"PASSPORT_WATCH_LOCK_SHA256={identity[1]}", str(context)]
        require_local_builder(selected)
        _private_run(args, selected, log)
        if seed_identity(root) != identity:
            raise WatchPreparationError("Watcher dependency inputs changed during preparation")
        prepared = prepared_image(root, selected)
        if not iid.is_file() or iid.read_text().strip() != prepared["PASSPORT_WATCH_IMAGE"]:
            raise WatchPreparationError("Prepared watcher image identity changed")
        return prepared, log
    except WatchPreparationCleanupError:
        cleanup_safe = False
        raise
    finally:
        if cleanup_safe:
            for path in (source, context):
                if path.exists():
                    shutil.rmtree(path)


def check_seed(root: Path, cargo_home: Path, environment: dict[str, str]) -> None:
    """Fail before compilation when retained volumes hide another image seed."""
    seed = environment.get("PASSPORT_WATCH_SEED_ID", "")
    lock = environment.get("PASSPORT_WATCH_LOCK_SHA256", "")
    if not all(re.fullmatch(r"[a-f0-9]{64}", value) for value in (seed, lock)):
        raise WatchPreparationError("Watcher dependency seed is not bound")
    if seed_identity(root) != (seed, lock):
        raise WatchPreparationError("Watcher dependency inputs changed; prepare a fresh disposable project")
    for name in ("registry", "git"):
        marker = cargo_home / name / ".marty-passport-watch-seed"
        if marker.is_symlink() or not marker.is_file() or marker.read_text().strip() != seed:
            raise WatchPreparationError("Watcher cache seed is stale; use a fresh disposable project")


def require_runtime_resources(cgroup: Path = Path("/sys/fs/cgroup")) -> None:
    """Check the compiler's actual delegated limits before every build."""
    try:
        actual = {name: (cgroup / name).read_text().strip()
                  for name in ("memory.max", "memory.swap.max", "cpu.max")}
    except OSError as exc:
        raise WatchPreparationError("Watcher runtime resource limits cannot be read") from exc
    if actual != {"memory.max": str(4 * 1024 ** 3), "memory.swap.max": "0",
                  "cpu.max": "100000 100000"}:
        raise WatchPreparationError("Watcher runtime CPU, memory or swap limit is not enforced")


def container_dependencies(phase: str, root: Path, cargo: Path, environment: dict[str, str],
                           cgroup: Path = Path("/sys/fs/cgroup")) -> None:
    """Only this short-lived, bounded fetch process can see the source reader."""
    expected = {"memory.max": str(FETCH_MEMORY), "memory.swap.max": "0",
                "cpu.max": "100000 100000", "pids.max": str(FETCH_PIDS)}
    try:
        actual = {name: (cgroup / name).read_text().strip() for name in expected}
    except OSError as exc:
        raise WatchPreparationError("Watcher fetch resource limits cannot be read") from exc
    if actual != expected:
        raise WatchPreparationError("Watcher fetch CPU, memory, swap or process limit is not enforced")
    seed = environment.get("PASSPORT_WATCH_SEED_ID", "")
    lock = environment.get("PASSPORT_WATCH_LOCK_SHA256", "")
    if seed_identity(root) != (seed, lock):
        raise WatchPreparationError("Watcher dependency inputs changed before fetch")
    if (phase not in ("probe", "fetch", "offline")
        or any(environment.get(name) for name in SOURCE_READER_ENV)
        or environment.get("CARGO_HOME") != str(cargo)
        or any(shutil.which(name) is None for name in ("cargo", "rustc", "git", "curl"))):
        raise WatchPreparationError("Watcher fetch requires the pinned tools and credential-free environment")
    if phase != "fetch" and Path(TOKEN_TARGET).exists():
        raise WatchPreparationError("Watcher probe and offline verification must not receive a source reader")
    if phase == "probe":
        return
    os.umask(0o077)
    if phase == "fetch":
        command = [sys.executable, str(root / ".github/scripts/private-forks.py"), "fetch", "--container",
                   "--token-file", TOKEN_TARGET, "--manifest-path", str(root / "rust/Cargo.toml")]
    else:
        command = ["cargo", "fetch", "--offline", "--locked", "--manifest-path", str(root / "rust/Cargo.toml")]
    try:
        subprocess.run(command, env=environment, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise WatchPreparationError("Watcher locked dependency fetch failed") from exc
    if seed_identity(root) != (seed, lock):
        raise WatchPreparationError("Watcher dependency inputs changed during fetch")
    if phase == "offline":
        for name in ("registry", "git"):
            path = cargo / name
            if not path.is_dir() or path.is_symlink():
                raise WatchPreparationError("Watcher dependency cache is incomplete")
            (path / ".marty-passport-watch-seed").write_text(seed + "\n")


if __name__ == "__main__":
    try:
        source = Path(__file__).resolve().parents[1]
        if sys.argv[1:] == ["--seed-identity"]:
            print(seed_identity(source)[0])
        elif sys.argv[1:] == ["--check-seed"]:
            require_runtime_resources()
            check_seed(source, Path("/usr/local/cargo"), dict(os.environ))
        elif sys.argv[1:] in (["--probe-dependencies"], ["--fetch-dependencies"], ["--offline-dependencies"]):
            container_dependencies(sys.argv[1].removeprefix("--").removesuffix("-dependencies"),
                                   source, Path("/cargo-cache"), dict(os.environ))
        else:
            raise WatchPreparationError("Use passport_local_watch.py --prepare")
    except (OSError, ValueError, WatchPreparationError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
