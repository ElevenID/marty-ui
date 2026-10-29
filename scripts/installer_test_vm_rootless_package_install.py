"""Dormant, one-shot offline package transaction for an installer-only VM.

There is deliberately no CLI or live caller. A future root-private controller
must authenticate the stopped disposable VM, its rollback disk checkpoint,
the admission result, and an operator confirmation before invoking this code.
Local JSON custody is not proof that a VM checkpoint exists or can be restored.
Debian maintainer scripts can have side effects outside dpkg; this module does
not offer automatic rollback or qualify a rootless daemon.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import uuid

import installer_test_vm_rootless_package_admission as archive

SCHEMA = "elevenid.installer-only-rootless-offline-install/v1"
CHECKPOINT_SCHEMA = "elevenid.installer-only-vm-stopped-disk-checkpoint/v1"
CONFIRMATION_SCHEMA = "elevenid.installer-only-rootless-install-confirmation/v1"
CONFIRM_LITERAL = "INSTALL_UIDMAP_ROOTLESSKIT_IN_DISPOSABLE_VM"
STATUS = Path("/var/lib/dpkg/status")
APT = Path("/usr/bin/apt-get")
DOCKER = Path("/usr/bin/docker")
KEYRING = archive.KEYRING
CUSTODY_PARENT = Path("/var/lib/marty-installer-only-rootless-install")
MAX_RECORD = 65536
MAX_PLAN = 65536
HEX = re.compile(r"[0-9a-f]{64}\Z")


class Refused(ValueError):
    """Fixed, nonsensitive refusal. An intent-only state needs manual recovery."""


@dataclass(frozen=True)
class VerifiedAdmission:
    """Future controller's validated #1680 intent/result/source/stage chain.

    This type has no minting function here. It is a local API contract, not a
    cryptographic proof; only trusted root-private controller code may supply
    it after authenticating the complete prior observation and transfer.
    """
    vm_id: str
    result_sha256: str
    intent_sha256: str
    module_sha256: str
    controller_sha256: str
    engine_id: str
    status_sha256: str


@dataclass(frozen=True)
class VerifiedStoppedCheckpoint:
    """Future controller's independently verified stop/snapshot/restore proof."""
    vm_id: str
    record_sha256: str
    disk_sha256: str
    snapshot_sha256: str
    rollback_test_sha256: str


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Refused(reason)


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def private_record(path: Path) -> tuple[bytes, dict]:
    require(path.is_absolute(), "private record path invalid")
    private_root(path.parent)
    raw = archive.private_file(path, MAX_RECORD, uid=0)
    try:
        record = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise Refused("private record invalid") from exc
    require(type(record) is dict and canonical(record) == raw,
            "private record noncanonical")
    return raw, record


def private_root(path: Path) -> None:
    require(path.is_absolute() and
            (path == CUSTODY_PARENT or CUSTODY_PARENT in path.parents),
            "private transaction path outside fixed custody")
    current = path
    while True:
        st = current.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == st.st_gid == 0
                and not st.st_mode & 0o022,
                "private transaction ancestor invalid")
        if current == path or current == CUSTODY_PARENT:
            require(stat.S_IMODE(st.st_mode) == 0o700,
                    "private transaction custody mode invalid")
        if current == current.parent:
            break
        current = current.parent


def _root_custody(root_dir: Path, vm_id: str) -> None:
    require(root_dir == CUSTODY_PARENT / vm_id,
            "transaction directory is not fixed VM root")
    private_root(root_dir)


def _write(parent: Path, name: str, value: dict) -> bytes:
    require(name in ("plan.json", "intent.json", "result.json"),
            "transaction record name invalid")
    data = canonical(value)
    require(len(data) <= MAX_PLAN, "transaction record oversized")
    private_root(parent)
    fd = os.open(parent / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            require(count > 0, "transaction record write stalled")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    held = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                   os.O_CLOEXEC)
    try:
        os.fsync(held)
    finally:
        os.close(held)
    require(archive.private_file(parent / name, MAX_PLAN, uid=0) == data,
            "transaction record changed")
    return data


def _id(value: str) -> str:
    require(type(value) is str, "transaction UUID invalid")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise Refused("transaction UUID invalid") from exc
    require(str(parsed) == value, "transaction UUID noncanonical")
    return value


def _digest(value: str) -> str:
    require(type(value) is str and HEX.fullmatch(value) is not None,
            "transaction digest invalid")
    return value


def _checkpoint(raw: bytes, record: dict, vm_id: str) -> str:
    require(set(record) == {"schema", "vm_id", "controller_boot_id",
                            "stopped_pid", "stopped_start_ticks", "disk_device",
                            "disk_inode", "disk_sha256", "snapshot_sha256",
                            "snapshot_bytes", "rollback_test_sha256",
                            "created_at", "stopped"}
            and record["schema"] == CHECKPOINT_SCHEMA
            and record["vm_id"] == vm_id and record["stopped"] is True
            and type(record["stopped_pid"]) is int and record["stopped_pid"] > 0
            and type(record["stopped_start_ticks"]) is str
            and record["stopped_start_ticks"].isdigit()
            and type(record["disk_device"]) is int and record["disk_device"] > 0
            and type(record["disk_inode"]) is int and record["disk_inode"] > 0
            and type(record["snapshot_bytes"]) is int
            and record["snapshot_bytes"] > 0
            and type(record["created_at"]) is int and record["created_at"] > 0,
            "external disk checkpoint evidence invalid")
    _id(record["controller_boot_id"])
    for key in ("disk_sha256", "snapshot_sha256", "rollback_test_sha256"):
        _digest(record[key])
    return archive.sha(raw)


def _bundle(bundle_dir: Path, manifest: dict, admitted_releases: list[dict],
            now: dt.datetime) -> tuple[list[dict], dict, dict]:
    private_root(bundle_dir)
    require(type(manifest) is dict and set(manifest) == {"packages"}
            and type(manifest["packages"]) is list
            and len(manifest["packages"]) == len(archive.TARGETS),
            "bundle manifest invalid")
    rows_by_package = {}
    package_files = []
    require(type(admitted_releases) is list
            and len(admitted_releases) == len(archive.POCKETS),
            "admitted release set invalid")
    releases = {}
    indexes = []
    keyring = archive.private_file(KEYRING, 1024 * 1024, uid=0)
    for row in admitted_releases:
        require(type(row) is dict and set(row) ==
                {"pocket", "base_url", "inrelease_sha256", "keyring_sha256",
                 "signer_fingerprint", "date", "valid_until"}
                and row["pocket"] in archive.POCKETS
                and row["pocket"] not in releases
                and row["base_url"] == archive.POCKETS[row["pocket"]]
                and row["signer_fingerprint"] == archive.ARCHIVE_FINGERPRINT
                and row["keyring_sha256"] == archive.sha(keyring),
                "admitted release identity invalid")
        releases[row["pocket"]] = row
    require(set(releases) == set(archive.POCKETS),
            "admitted release set incomplete")
    hashes_by_pocket = {}
    for pocket in archive.POCKETS:
        raw = archive.private_file(bundle_dir / f"{pocket}.inrelease",
                                   archive.MAX_INRELEASE, uid=0)
        require(archive.sha(raw) == releases[pocket]["inrelease_sha256"],
                "signed release differs from prior admission")
        fields, hashes = archive._release_fields(archive._release_payload(raw))
        require(fields.get("Origin") == "Ubuntu" and fields.get("Label") == "Ubuntu"
                and fields.get("Suite") == pocket
                and fields.get("Codename") == "noble",
                "admitted release policy changed")
        date = archive._utc(releases[pocket]["date"])
        require(date == archive._utc(fields["Date"]),
                "admitted release date differs")
        if pocket != "noble":
            require(now - date <= dt.timedelta(hours=48)
                    and date <= now + dt.timedelta(minutes=10),
                    "admitted release stale")
        if releases[pocket]["valid_until"] is not None:
            require(now <= archive._utc(releases[pocket]["valid_until"])
                    + dt.timedelta(minutes=10), "admitted release expired")
        hashes_by_pocket[pocket] = hashes
        for component in archive.COMPONENTS:
            relative = f"{component}/binary-amd64/Packages.xz"
            require(relative in hashes, "admitted index missing")
            expected_size, expected_sha = hashes[relative]
            index = archive.private_file(bundle_dir /
                                         f"{pocket}.{component}.packages.xz",
                                         archive.MAX_INDEX, uid=0)
            require(len(index) == expected_size and archive.sha(index) == expected_sha,
                    "admitted index differs")
            indexes.append({"pocket": pocket, "component": component,
                            "sha256": expected_sha, "size": expected_size})
    for row in manifest["packages"]:
        require(type(row) is dict and set(row) == {"package", "version", "sha256",
                                                  "size", "pocket", "component"},
                "bundle package record invalid")
        package = row["package"]
        require(package in archive.TARGETS and package not in rows_by_package
                and row["version"] == archive.EXPECTED_VERSIONS[package]
                and row["pocket"] in archive.POCKETS
                and row["component"] in archive.COMPONENTS,
                "bundle package identity invalid")
        hashes = hashes_by_pocket[row["pocket"]]
        rows = archive.verify_index(bundle_dir /
                                    f"{row['pocket']}.{row['component']}.packages.xz",
                                    hashes, row["component"])
        selected = archive.select_package(rows, package, row["version"])
        require(selected["sha256"] == row["sha256"]
                and selected["size"] == row["size"],
                "bundle package differs from signed index")
        filename = PurePosixPath(selected["filename"])
        require(archive._safe_relative(str(filename)) and filename.parts[0] == "pool",
                "bundle package path invalid")
        deb = bundle_dir / f"{package}.deb"
        require(deb.lstat().st_uid == 0, "bundle package custody invalid")
        archive.verify_deb(deb, selected)
        rows_by_package[package] = row
        package_files.append({"package": package, "relative": str(filename),
                              "sha256": row["sha256"], "size": row["size"]})
    require(set(rows_by_package) == set(archive.TARGETS),
            "bundle fixed set incomplete")
    identity = {"releases": sorted(
                    [{"pocket": pocket, "inrelease_sha256": row["inrelease_sha256"],
                      "keyring_sha256": row["keyring_sha256"]}
                     for pocket, row in releases.items()], key=lambda row: row["pocket"]),
                "indexes": sorted(indexes, key=lambda row: (row["pocket"],
                                                            row["component"]))}
    return sorted(package_files, key=lambda item: item["package"]), rows_by_package, identity


def plan_bytes(*, vm_id: str, engine_id: str, checkpoint_sha256: str,
               admission_sha256: str, status_sha256: str,
               package_files: list[dict], archive_metadata: dict,
               actions: list[dict]) -> bytes:
    _id(vm_id)
    _id(engine_id)
    for value in (checkpoint_sha256, admission_sha256, status_sha256):
        _digest(value)
    require(type(actions) is list and bool(actions), "install actions missing")
    plan = {"schema": SCHEMA, "vm_id": vm_id, "engine_id": engine_id,
            "checkpoint_sha256": checkpoint_sha256,
            "admission_sha256": admission_sha256,
            "status_sha256": status_sha256,
            "package_files": package_files, "archive_metadata": archive_metadata,
            "new_package_actions": actions,
            "install_targets": ["uidmap=" + archive.EXPECTED_VERSIONS["uidmap"],
                                "rootlesskit=" + archive.EXPECTED_VERSIONS["rootlesskit"]],
            "rollback": "restore externally authenticated stopped-VM disk checkpoint",
            "automatic_rollback": False}
    raw = canonical(plan)
    require(len(raw) <= MAX_PLAN, "install plan oversized")
    return raw


def _confirm(record: dict, vm_id: str, engine_id: str,
             checkpoint_sha256: str, plan_sha256: str) -> None:
    require(set(record) == {"schema", "vm_id", "engine_id",
                            "checkpoint_sha256", "plan_sha256", "nonce", "phrase"}
            and record["schema"] == CONFIRMATION_SCHEMA
            and record["vm_id"] == vm_id and record["engine_id"] == engine_id
            and record["checkpoint_sha256"] == checkpoint_sha256
            and record["plan_sha256"] == plan_sha256
            and record["phrase"] == CONFIRM_LITERAL,
            "exact installation confirmation invalid")
    _id(record["nonce"])


def _engine_id() -> str:
    # An observer only. Existing Docker socket access is an external trust gate.
    tool = DOCKER.lstat()
    require(stat.S_ISREG(tool.st_mode) and tool.st_uid == 0
            and not tool.st_mode & 0o022, "Docker observer tool invalid")
    result = archive.run_bounded(
        [str(DOCKER), "info", "--format", "{{.ID}}"],
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"},
        timeout=15, stdout_limit=128, stderr_limit=256)
    require(result.returncode == 0 and not result.stderr,
            "Docker Engine observation unavailable")
    value = result.stdout.decode("ascii", "strict").strip()
    return _id(value)


def _apt(args: list[str], config: Path) -> bytes:
    allowed = (
        ["update"],
        ["--simulate", "--no-install-recommends", "--no-remove", "--no-upgrade", "install",
         "uidmap=" + archive.EXPECTED_VERSIONS["uidmap"],
         "rootlesskit=" + archive.EXPECTED_VERSIONS["rootlesskit"]],
        ["--yes", "--no-install-recommends", "--no-remove", "--no-upgrade",
         "install", "uidmap=" + archive.EXPECTED_VERSIONS["uidmap"],
         "rootlesskit=" + archive.EXPECTED_VERSIONS["rootlesskit"]],
    )
    require(args in allowed, "APT command not admitted")
    tool = APT.lstat()
    require(stat.S_ISREG(tool.st_mode) and tool.st_uid == 0
            and not tool.st_mode & 0o022 and tool.st_mode & 0o111,
            "APT tool custody invalid")
    result = archive.run_bounded(
        [str(APT), *args],
        env={"APT_CONFIG": str(config), "HOME": "/nonexistent", "LC_ALL": "C",
             "PATH": "/usr/bin:/bin", "DEBIAN_FRONTEND": "noninteractive"},
        timeout=180, stdout_limit=65536, stderr_limit=16384)
    require(result.returncode == 0 and not result.stderr,
            "offline APT transaction refused")
    later = APT.lstat()
    require(all(getattr(tool, name) == getattr(later, name) for name in
                ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_size",
                 "st_mtime_ns", "st_ctime_ns")), "APT tool changed")
    return result.stdout


def _mkdir(parent: Path, name: str) -> Path:
    require(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,95}", name) is not None,
            "offline repository component invalid")
    child = parent / name
    child.mkdir(mode=0o700)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                 os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return child


def _blob(parent: Path, name: str, data: bytes) -> None:
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_~-]{0,127}", name) is not None,
            "offline repository file name invalid")
    fd = os.open(parent / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            require(count > 0, "offline repository write stalled")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                        os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    require(archive.private_file(parent / name, max(len(data), 1), uid=0) == data,
            "offline repository content changed")


def _repo(private_dir: Path, bundle_dir: Path, package_files: list[dict]) -> Path:
    """Copy only authenticated bytes into a fresh local signed APT repository."""
    repo = _mkdir(private_dir, "repository")
    dists = _mkdir(repo, "dists")
    for pocket in archive.POCKETS:
        target = _mkdir(dists, pocket)
        _blob(target, "InRelease", archive.private_file(
            bundle_dir / f"{pocket}.inrelease", archive.MAX_INRELEASE, uid=0))
        for component in archive.COMPONENTS:
            binary = _mkdir(_mkdir(target, component), "binary-amd64")
            _blob(binary, "Packages.xz", archive.private_file(
                bundle_dir / f"{pocket}.{component}.packages.xz",
                archive.MAX_INDEX, uid=0))
    pool = _mkdir(repo, "pool")
    for item in package_files:
        relative = PurePosixPath(item["relative"])
        require(relative.parts[0] == "pool" and len(relative.parts) >= 2,
                "offline package location invalid")
        parent = pool
        for component in relative.parts[1:-1]:
            next_path = parent / component
            if next_path.exists():
                st = next_path.lstat()
                require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
                        and stat.S_IMODE(st.st_mode) == 0o700,
                        "offline repository path changed")
                parent = next_path
            else:
                parent = _mkdir(parent, component)
        _blob(parent, relative.name, archive.private_file(
            bundle_dir / f"{item['package']}.deb", archive.MAX_DEB, uid=0))
    return repo


def _config(private_dir: Path, repo: Path) -> Path:
    lists = _mkdir(private_dir, "lists")
    archives = _mkdir(private_dir, "archives")
    empty = _mkdir(private_dir, "empty")
    _blob(private_dir, "blank", b"")
    sources = "".join(f"deb [arch=amd64 signed-by={KEYRING}] "
                      f"{repo.as_uri()} {pocket} main universe\n"
                      for pocket in archive.POCKETS)
    _blob(private_dir, "sources.list", sources.encode("ascii"))
    # APT must run as root to traverse this root-private 0700 repository.
    # This is a deliberate privileged parser boundary. A future guest gate
    # must qualify actual offline APT behavior before any live invocation.
    config = (f'Dir::Etc::sourcelist "{private_dir / "sources.list"}";\n'
              f'Dir::Etc::sourceparts "{empty}";\nDir::Etc::parts "{empty}";\n'
              f'Dir::Etc::main "{private_dir / "blank"}";\n'
              f'Dir::Etc::preferences "{private_dir / "blank"}";\n'
              f'Dir::Etc::preferencesparts "{empty}";\n'
              f'Dir::State::status "{STATUS}";\n'
              f'Dir::State::lists "{lists}";\n'
              f'Dir::Cache::archives "{archives}";\n'
              'Dir::Cache::pkgcache "";\nDir::Cache::srcpkgcache "";\n'
              'Acquire::Languages "none";\nAcquire::By-Hash "false";\n'
              'Acquire::AllowInsecureRepositories "false";\n'
              'APT::Get::AllowUnauthenticated "false";\n'
              'APT::Get::Assume-Yes "false";\n'
              'APT::Get::Upgrade "false";\n'
              'APT::Get::Remove "false";\n'
              'APT::Install-Recommends "false";\n'
              'APT::Sandbox::User "root";\n'
              'Acquire::http::Proxy "false";\n'
              'Acquire::https::Proxy "false";\n')
    _blob(private_dir, "apt.conf", config.encode("ascii"))
    return private_dir / "apt.conf"


def _recheck_repo(repo: Path, bundle_dir: Path, package_files: list[dict],
                  config: Path) -> None:
    require(repo.is_dir() and config.is_file(), "offline repository missing")
    for pocket in archive.POCKETS:
        require(archive.private_file(repo / "dists" / pocket / "InRelease",
                                     archive.MAX_INRELEASE, uid=0) ==
                archive.private_file(bundle_dir / f"{pocket}.inrelease",
                                     archive.MAX_INRELEASE, uid=0),
                "offline signed release changed")
        for component in archive.COMPONENTS:
            require(archive.private_file(repo / "dists" / pocket / component /
                                         "binary-amd64" / "Packages.xz",
                                         archive.MAX_INDEX, uid=0) ==
                    archive.private_file(bundle_dir /
                                         f"{pocket}.{component}.packages.xz",
                                         archive.MAX_INDEX, uid=0),
                    "offline signed index changed")
    for item in package_files:
        staged = archive.private_file(repo / item["relative"],
                                      archive.MAX_DEB, uid=0)
        source = archive.private_file(bundle_dir / f"{item['package']}.deb",
                                      archive.MAX_DEB, uid=0)
        require(staged == source and len(staged) == item["size"]
                and archive.sha(staged) == item["sha256"],
                "offline package changed")
    configuration = archive.private_file(config, 8192, uid=0).decode("ascii", "strict")
    require(configuration.count("deb [arch=amd64 signed-by=") == len(archive.POCKETS)
            and all(f"{repo.as_uri()} {pocket} main universe" in configuration
                    for pocket in archive.POCKETS)
            and "http://" not in configuration
            and "https://" not in configuration,
            "offline APT configuration changed")


def install_once(*, vm_id: str, root_dir: Path,
                 verified_admission: VerifiedAdmission,
                 verified_checkpoint: VerifiedStoppedCheckpoint) -> dict:
    """Run at most one package mutation after external checkpoint admission.

    The external controller must prove VM stopped/checkpoint provenance and
    restore viability, current guest identity, root-private code custody and
    exact confirmation. This primitive refuses if any prior intent exists.
    It never retries, invokes rollback, or starts a daemon.
    """
    require(os.geteuid() == 0 and os.getegid() == 0,
            "root guest transaction identity required")
    _id(vm_id)
    require(type(verified_admission) is VerifiedAdmission
            and type(verified_checkpoint) is VerifiedStoppedCheckpoint
            and verified_admission.vm_id == verified_checkpoint.vm_id == vm_id,
            "externally verified capabilities missing")
    _root_custody(root_dir, vm_id)
    bundle_dir = root_dir / "bundle"
    admission_result_path = root_dir / "admission.json"
    checkpoint_path = root_dir / "checkpoint.json"
    confirmation_path = root_dir / "confirmation.json"
    private_dir = root_dir / "transaction"
    private_root(private_dir)
    require(not any(private_dir.iterdir()), "transaction directory already used")
    admission_raw, admission = private_record(admission_result_path)
    checkpoint_raw, checkpoint = private_record(checkpoint_path)
    checkpoint_sha = _checkpoint(checkpoint_raw, checkpoint, vm_id)
    require(archive.sha(admission_raw) == verified_admission.result_sha256
            and checkpoint_sha == verified_checkpoint.record_sha256
            and checkpoint["disk_sha256"] == verified_checkpoint.disk_sha256
            and checkpoint["snapshot_sha256"] == verified_checkpoint.snapshot_sha256
            and checkpoint["rollback_test_sha256"] ==
                verified_checkpoint.rollback_test_sha256,
            "externally verified evidence differs")
    require(admission.get("schema") ==
            "elevenid.installer-only-vm-rootless-package-admission/v1"
            and admission.get("phase") == "observed"
            and admission.get("vm_id") == vm_id
            and admission.get("transaction_simulated") is True
            and admission.get("rootful_docker_package_simulated_change") is False
            and admission.get("package_actions_authorized") is False
            and admission.get("installation_authorized") is False
            and admission.get("intent_sha256") == verified_admission.intent_sha256
            and admission.get("module_sha256") == verified_admission.module_sha256
            and admission.get("controller_sha256") ==
                verified_admission.controller_sha256
            and admission.get("engine_id") == verified_admission.engine_id
            and admission.get("dpkg_status_sha256") ==
                verified_admission.status_sha256,
            "prior package admission record invalid")
    engine_id = _engine_id()
    require(engine_id == admission.get("engine_id"),
            "current Docker Engine differs from admission")
    status = archive.private_file(STATUS, archive.MAX_STATUS, uid=0)
    status_sha = archive.sha(status)
    require(status_sha == admission.get("dpkg_status_sha256"),
            "current dpkg status differs from admission")
    _, bundle_manifest = private_record(root_dir / "bundle-manifest.json")
    package_files, packages, archive_metadata = _bundle(
        bundle_dir, bundle_manifest, admission.get("archive_releases"),
        dt.datetime.now(dt.timezone.utc))
    require(packages == {row["package"]: row for row in admission.get("packages", [])},
            "bundle differs from admission result")
    actions = admission.get("new_package_actions")
    raw_plan = plan_bytes(vm_id=vm_id, engine_id=engine_id,
                          checkpoint_sha256=checkpoint_sha,
                          admission_sha256=archive.sha(admission_raw),
                          status_sha256=status_sha, package_files=package_files,
                          archive_metadata=archive_metadata,
                          actions=actions)
    plan_sha = archive.sha(raw_plan)
    _, confirmation = private_record(confirmation_path)
    _confirm(confirmation, vm_id, engine_id, checkpoint_sha, plan_sha)
    _write(private_dir, "plan.json", json.loads(raw_plan))
    intent = {"schema": SCHEMA, "phase": "intent", "vm_id": vm_id,
              "plan_sha256": plan_sha, "confirmation_sha256":
              archive.sha(canonical(confirmation)), "checkpoint_sha256": checkpoint_sha,
              "admission_sha256": archive.sha(admission_raw)}
    intent_raw = _write(private_dir, "intent.json", intent)
    phase = "staging"
    try:
        repo = _repo(private_dir, bundle_dir, package_files)
        config = _config(private_dir, repo)
        phase = "simulating"
        _apt(["update"], config)
        simulation = _apt(["--simulate", "--no-install-recommends", "--no-remove",
                           "--no-upgrade",
                           "install", "uidmap=" + archive.EXPECTED_VERSIONS["uidmap"],
                           "rootlesskit=" + archive.EXPECTED_VERSIONS["rootlesskit"]],
                          config)
        require(archive.inspect_simulation(simulation,
                archive._installed_status(status),
                {name: row["version"] for name, row in packages.items()}) == actions,
                "fresh offline simulation differs from confirmed plan")
        require(archive.private_file(STATUS, archive.MAX_STATUS, uid=0) == status
                and _engine_id() == engine_id,
                "guest state changed before installation")
        # Rebind both authenticated source and exact staged APT inputs.
        _recheck_repo(repo, bundle_dir, package_files, config)
        phase = "installing"
        _apt(["--yes", "--no-install-recommends", "--no-remove", "--no-upgrade", "install",
              "uidmap=" + archive.EXPECTED_VERSIONS["uidmap"],
              "rootlesskit=" + archive.EXPECTED_VERSIONS["rootlesskit"]], config)
        phase = "verifying"
        after = archive.private_file(STATUS, archive.MAX_STATUS, uid=0)
        initial = archive._installed_status(status)
        installed = archive._installed_status(after)
        require(set(installed) - set(initial) ==
                {row["package"] for row in actions}
                and all(installed.get(name) == version for name, version in initial.items())
                and all(installed.get(row["package"]) == row["version"]
                        for row in actions)
                and _engine_id() == engine_id,
                "post-install guest preservation unproven")
        result = {"schema": SCHEMA, "phase": "observed-installed", "vm_id": vm_id,
                  "intent_sha256": archive.sha(intent_raw),
                  "plan_sha256": plan_sha, "status_after_sha256": archive.sha(after),
                  "engine_id": engine_id, "new_package_actions": actions,
                  "rollback_performed": False, "rootless_ready": False,
                  "application_deployment_authorized": False}
        _write(private_dir, "result.json", result)
        return result
    except BaseException:
        # After intent, any exception (including interruption) is uncertain.
        # A second invocation refuses the nonempty private directory.
        if not (private_dir / "result.json").exists():
            try:
                _write(private_dir, "result.json",
                       {"schema": SCHEMA, "phase": "uncertain", "vm_id": vm_id,
                        "intent_sha256": archive.sha(intent_raw),
                        "plan_sha256": plan_sha, "last_stage": phase,
                        "rollback_performed": False,
                        "manual_checkpoint_recovery_required": True})
            except (OSError, ValueError):
                pass
        raise
