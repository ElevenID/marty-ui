#!/usr/bin/env python3
"""Copy the old release cache into a distinct owned target, without hardlinks.

Only the exact frozen OID4VC build may consume the resulting receipt. This
operator never runs Cargo or changes an existing target or beta mount.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

from scoped_native_runtime import daemon_source, save_exclusive

SOURCE = Path.home() / ".codex/builds/marty-demo-native-cache-20261021/target"
VOLUME = "marty-oid4vc-native-d2de-target-20261028"
IMAGE = "sha256:236173eb74001afe2f60862de935b74fcbd00adfca247b2c27051a70a6a39a2d"
OWNER = "root-local-oid4vc-current-source-20261028"
TRANSPORT_SHA = "3243ebf197dcb3c0cdb3c628128ecb5d71906abd5db00f96bc7852dcb7b05f1e"
TRANSPORT_SOURCE = (Path.home() / ".codex/private/beta-v258-deployment-20261019/"
                    "canvas-issuer-build-94afb3d6-28cf-45f5-93f0-6a6c65da3957/"
                    "sources/desktop_journal_transport.py")
TRANSPORT_PRIVATE = TRANSPORT_SOURCE.parent.parent
ENGINE = "3dbbbe66-1c98-4e0c-b0a6-f927c05e7341"


def require(value: object, code: str) -> None:
    if not value:
        raise ValueError(code)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_operator(packet_path: Path, packet_sha: str) -> dict:
    private = (Path.home() / ".codex/private").resolve()
    require(packet_path.is_file() and not packet_path.is_symlink()
            and not getattr(packet_path, "is_junction", lambda: False)()
            and packet_path.resolve().is_relative_to(private),
            "SEED_PRIVATE_SOURCE_PACKET_REQUIRED")
    require(re.fullmatch(r"[a-f0-9]{64}", packet_sha) and sha(packet_path) == packet_sha,
            "SEED_SOURCE_PACKET_CHANGED")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    script = Path(__file__).resolve()
    repo = Path(packet["sources"]["ui"]["repository"])
    revision = packet["producerRevision"]
    require(re.fullmatch(r"[a-f0-9]{40}", revision), "SEED_OPERATOR_GIT_OBJECT_CHANGED")
    for file in (script, script.with_name("scoped_native_runtime.py")):
        bound = packet["operatorFiles"][file.name]
        require(file == packet_path.parent.resolve() / "operator" / file.name
                and bound["sha256"] == sha(file) and bound["path"] == str(file)
                and bound["bytes"] == file.stat().st_size,
                "SEED_OPERATOR_OUTSIDE_PUBLISHED_CLOSURE")
        require(subprocess.check_output(["git", "-C", str(repo), "show",
                                         revision + ":scripts/" + file.name]) == file.read_bytes(),
                "SEED_OPERATOR_GIT_OBJECT_CHANGED")
    return packet


def daemon_path(path: Path) -> str:
    value = str(path.resolve())
    require(re.fullmatch(r"[Cc]:\\[^,\r\n\0]+", value), "DOCKER_BIND_PATH_REFUSED")
    return "/run/desktop/mnt/host/c/" + value[3:].replace("\\", "/")


def transport():
    """Reuse the exact previously reviewed Desktop executable and private context."""
    require(sys.version_info >= (3, 12), "PYTHON312_REQUIRED_FOR_REVIEWED_TRANSPORT")
    require(sha(TRANSPORT_SOURCE) == TRANSPORT_SHA, "PINNED_DOCKER_TRANSPORT_CHANGED")
    spec = importlib.util.spec_from_file_location("reviewed_desktop_transport", TRANSPORT_SOURCE)
    require(spec is not None and spec.loader is not None, "PINNED_DOCKER_TRANSPORT_MISSING")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    journal = json.loads((TRANSPORT_PRIVATE / "journal-spec.private.json").read_text(encoding="utf-8"))
    journal_spec = journal["desktop"]
    run_id = journal_spec["volumeName"].removeprefix("marty-d02-journal-")
    client = module.DesktopPrivateJournalTransport(TRANSPORT_PRIVATE, run_id, journal_spec)
    require(client._command(["info", "--format", "{{.ID}}"]).stdout.decode().strip() == ENGINE,
            "PINNED_DOCKER_ENGINE_CHANGED")
    return client


def docker(client, *args: str, timeout: int = 30, check: bool = True):
    return client._command(list(args), timeout=timeout, check=check)


def docker_output(client, *args: str) -> str:
    return docker(client, *args).stdout.decode("utf-8").strip()


def checked_source_mounts(rows: list[dict], source: Path) -> None:
    root = daemon_source(source)
    flow = daemon_source(source / "release/marty-flow")
    for row in rows:
        for mount in row.get("Mounts", []):
            actual = daemon_source(mount.get("Source", "")) if mount.get("Type") == "bind" else ""
            if mount.get("Name") == VOLUME:
                raise ValueError("TARGET_VOLUME_ALREADY_MOUNTED")
            if actual == root or actual.startswith(root + "/"):
                require(actual == flow and mount.get("RW") is False,
                        "SOURCE_CACHE_HAS_WRITER_OR_UNKNOWN_MOUNT")


def operator_mounts() -> list[tuple[str, str, bool]]:
    script = Path(__file__).resolve()
    runtime = script.with_name("scoped_native_runtime.py")
    require(runtime.is_file() and not runtime.is_symlink(), "SEED_RUNTIME_MODULE_MISSING")
    return [(str(script), "/operator.py", True),
            (str(runtime), "/scoped_native_runtime.py", True)]


def owned_helper(client, name: str, mode: str, mounts: list[tuple[str, str, bool]],
                 memory: str, intent: Path, deadline_seconds: int) -> dict:
    """One named Docker create/start; preserve unknown state and terminal evidence."""
    require(re.fullmatch(r"oid4vc-seed-[a-f0-9-]{36}", name), "OWNED_HELPER_NAME_REQUIRED")
    require(mode in ("--inside", "--inside-inspect"), "OWNED_HELPER_MODE_REQUIRED")
    expected_memory = {"2g": 2 * 1024**3, "256m": 256 * 1024**2}
    require(memory in expected_memory, "HELPER_MEMORY_PROFILE_REFUSED")
    require(not intent.exists(), "HELPER_INTENT_ALREADY_EXISTS")
    args = ["create", "--name", name, "--label", "elevenid.owner=" + OWNER,
            "--network", "none", "--read-only", "--pull=never", "--memory", memory,
            "--memory-swap", memory, "--cpus", "0.5", "--pids-limit", "32"]
    for source, destination, readonly in mounts:
        args += ["--mount", "type=" + ("volume" if source == VOLUME else "bind")
                 + ",src=" + (source if source == VOLUME else daemon_source(source))
                 + ",dst=" + destination + (",readonly" if readonly else "")]
    args += ["--entrypoint", "python", IMAGE, "/operator.py", mode]
    save_exclusive(intent, {"state": "CREATE_INTENT", "name": name, "image": IMAGE,
                            "argsSha256": hashlib.sha256(json.dumps(args).encode()).hexdigest(),
                            "engine": ENGINE, "operatorSha256": sha(Path(__file__))})
    cid = docker_output(client, *args)
    require(re.fullmatch(r"[a-f0-9]{64}", cid), "HELPER_CREATE_OUTCOME_UNKNOWN")
    save_exclusive(intent.with_suffix(".created.json"),
                   {"state": "CREATED_NOT_STARTED", "containerId": cid, "name": name,
                    "engine": ENGINE, "image": IMAGE})
    row = json.loads(docker_output(client, "inspect", cid))[0]
    save_exclusive(intent.with_suffix(".inspected.json"),
                   {"state": "CREATED_INSPECTION_OBSERVED_NOT_STARTED", "containerId": cid,
                    "name": name, "image": row.get("Image"), "mounts": row.get("Mounts"),
                    "hostConfig": {key: row.get("HostConfig", {}).get(key) for key in
                                   ("NetworkMode", "ReadonlyRootfs", "Memory", "MemorySwap",
                                    "NanoCpus", "PidsLimit")},
                    "containerState": row.get("State", {}).get("Status")})
    require(row["Id"] == cid and row["Name"] == "/" + name and row["Image"] == IMAGE
            and row["Config"]["Labels"].get("elevenid.owner") == OWNER
            and row["State"]["Status"] == "created" and row["State"]["Running"] is False
            and row["HostConfig"]["NetworkMode"] == "none"
            and row["HostConfig"]["ReadonlyRootfs"] is True
            and row["HostConfig"]["Memory"] == expected_memory[memory]
            and row["HostConfig"]["MemorySwap"] == expected_memory[memory]
            and row["HostConfig"]["NanoCpus"] == 500000000
            and row["HostConfig"]["PidsLimit"] == 32,
            "HELPER_CREATE_IDENTITY_CHANGED")
    actual_mounts = {mount["Destination"]: mount for mount in row["Mounts"]}
    require(len(row["Mounts"]) == len(mounts)
            and len(actual_mounts) == len(mounts)
            and set(actual_mounts) == {destination for _, destination, _ in mounts},
            "HELPER_MOUNT_SET_CHANGED")
    for source, destination, readonly in mounts:
        mount = actual_mounts[destination]
        require(mount["RW"] is not readonly and
                (mount["Type"] == "volume" and mount.get("Name") == VOLUME if source == VOLUME
                 else mount["Type"] == "bind" and daemon_source(mount["Source"]) == daemon_source(source)),
                "HELPER_MOUNT_IDENTITY_CHANGED")
    require(docker_output(client, "start", cid) == cid, "HELPER_START_UNRESOLVED")
    deadline = time.monotonic() + deadline_seconds
    while True:
        row = json.loads(docker_output(client, "inspect", cid))[0]
        require(row["Id"] == cid and row["Name"] == "/" + name, "HELPER_REPLACED")
        if row["State"]["Status"] == "exited":
            break
        require(time.monotonic() < deadline, "HELPER_STILL_RUNNING_NO_AUTORETRY")
        time.sleep(2)
    logs = docker(client, "logs", cid, check=False)
    terminal = {"state": "TERMINAL_RETAINED", "containerId": cid, "name": name,
                "intentPath": str(intent),
                "exitCode": row["State"]["ExitCode"], "oomKilled": row["State"]["OOMKilled"],
                "logsExitCode": logs.returncode,
                "stdout": logs.stdout.decode("utf-8", errors="replace"),
                "stderr": logs.stderr.decode("utf-8", errors="replace")}
    save_exclusive(intent.with_suffix(".terminal.json"), terminal)
    require(terminal["exitCode"] == 0 and terminal["oomKilled"] is False
            and terminal["logsExitCode"] == 0, "HELPER_FAILED_RETAINED")
    return terminal


def retire_helper(client, terminal: dict) -> None:
    cid = terminal["containerId"]
    row = json.loads(docker_output(client, "inspect", cid))[0]
    require(row["Id"] == cid and row["Name"] == "/" + terminal["name"]
            and row["Image"] == IMAGE
            and row["Config"]["Labels"].get("elevenid.owner") == OWNER
            and row["State"]["Status"] == "exited" and row["State"]["ExitCode"] == 0
            and row["State"]["OOMKilled"] is False,
            "HELPER_CLEANUP_IDENTITY_CHANGED")
    require(docker_output(client, "rm", cid) == cid, "HELPER_EXPLICIT_CLEANUP_UNRESOLVED")
    require(not docker_output(client, "ps", "-aq", "--no-trunc", "--filter", "id=" + cid),
            "HELPER_REMOVAL_UNCONFIRMED")
    save_exclusive(Path(terminal["intentPath"]).with_suffix(".cleanup.json"),
                   {"state": "EXACT_HELPER_REMOVED", "containerId": cid,
                    "name": terminal["name"], "exitCode": 0,
                    "oomKilled": False, "engine": ENGINE})


def manifest(root: Path) -> tuple[str, int, int]:
    """Hash every ordinary file; reject links and silent enumeration gaps."""
    require(root.is_dir() and not root.is_symlink()
            and not getattr(root, "is_junction", lambda: False)(), "CACHE_ROOT_CHANGED")
    rows = []
    directories = [root]
    while directories:
        directory = directories.pop()
        for path in directory.iterdir():
            require(not path.is_symlink() and not getattr(path, "is_junction", lambda: False)(),
                    "CACHE_LINK_REFUSED")
            if path.is_dir():
                directories.append(path)
                continue
            require(path.is_file(), "CACHE_SPECIAL_FILE_REFUSED")
            relative = path.relative_to(root).as_posix()
            require(relative and not any(c in relative for c in "\0\r\n"),
                    "CACHE_FILE_NAME_REFUSED")
            with path.open("rb") as content:
                digest = hashlib.file_digest(content, "sha256").hexdigest()
            rows.append((relative, path.stat().st_size, digest))
    rows.sort()
    encoded = json.dumps(rows, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), len(rows), sum(row[1] for row in rows)


def inside() -> None:
    source, target = Path("/source"), Path("/target")
    require(source.is_dir() and target.is_dir() and not any(target.iterdir()),
            "TARGET_NOT_EMPTY_OR_SOURCE_MISSING")
    source_device, target_device = source.stat().st_dev, target.stat().st_dev
    require(source_device != target_device, "TARGET_MUST_BE_SEPARATE_DEVICE")
    before = manifest(source)
    directories = [source]
    while directories:
        directory = directories.pop()
        for item in directory.iterdir():
            relative = item.relative_to(source)
            destination = target / relative
            require(not item.is_symlink(), "SOURCE_LINK_DURING_COPY")
            if item.is_dir():
                destination.mkdir(exist_ok=False)
                directories.append(item)
            else:
                require(item.is_file(), "SOURCE_SPECIAL_DURING_COPY")
                destination.parent.mkdir(parents=True, exist_ok=True)
                require(not destination.exists(), "TARGET_FILE_ALREADY_EXISTS")
                shutil.copy2(item, destination, follow_symlinks=False)
    after, target_manifest = manifest(source), manifest(target)
    require(before == after == target_manifest, "CACHE_SOURCE_OR_TARGET_CHANGED")
    print(json.dumps({"state": "COPIED_AND_READBACK_MATCHED",
                      "sourceManifestSha256": before[0], "targetManifestSha256": target_manifest[0],
                      "fileCount": before[1], "bytes": before[2],
                      "sourceBeforeAfterMatched": True, "sourceMountedReadOnly": True,
                      "targetHardlinksToSource": False}))


def inspect_target(receipt_path: Path) -> dict:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    require(receipt["state"] == "COPIED_AND_READBACK_MATCHED"
            and receipt["targetVolume"] == VOLUME
            and receipt["operatorSha256"] == sha(Path(__file__)),
            "SEED_RECEIPT_OR_OPERATOR_CHANGED")
    client = transport()
    rows = json.loads(docker_output(client, "volume", "inspect", VOLUME))
    require(len(rows) == 1 and rows[0]["Name"] == VOLUME
            and rows[0]["Labels"].get("io.elevenid.demo-audit.owner") == OWNER
            and {key: rows[0][key] for key in ("Name", "Driver", "Scope", "CreatedAt", "Labels", "Mountpoint")}
            == receipt["volumeProof"],
            "OWNED_TARGET_VOLUME_CHANGED")
    require(not docker_output(client, "ps", "-q", "--filter", "volume=" + VOLUME),
            "TARGET_VOLUME_HAS_LIVE_CONSUMER")
    name = "oid4vc-seed-" + str(uuid.uuid4())
    terminal = owned_helper(client, name, "--inside-inspect",
                            [(VOLUME, "/target", True), *operator_mounts()],
                            "256m", receipt_path.with_name(name + ".intent.json"), 600)
    actual = json.loads(terminal["stdout"])
    require(actual["manifestSha256"] == receipt["targetManifestSha256"]
            and actual["fileCount"] == receipt["fileCount"]
            and actual["bytes"] == receipt["bytes"],
            "TARGET_SEED_CHANGED")
    retire_helper(client, terminal)
    return actual


def writer_census(client) -> None:
    process_query = ('@(Get-CimInstance Win32_Process | Where-Object '
                     '{ $_.Name -in @("cargo.exe","rustc.exe") } | '
                     'Select-Object ProcessId,CreationDate) | ConvertTo-Json -Compress')
    writers = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive",
                                       "-Command", process_query], text=True, timeout=30).strip()
    require(writers in ("", "null", "[]"), "WINDOWS_COMPILER_CACHE_WRITER_PRESENT")
    running = docker_output(client, "ps", "-q", "--no-trunc").split()
    for cid in running:
        listing = docker(client, "top", cid).stdout.decode("utf-8", errors="replace")
        require(not re.search(r"(?i)(?:^|[/\\\s])(?:cargo|rustc)(?:\.exe)?(?:\s|$)", listing),
                "DOCKER_COMPILER_CACHE_WRITER_PRESENT")


def copy_capacity(source_bytes: int, output_parent: Path) -> tuple[int, int]:
    free = min(shutil.disk_usage(output_parent).free, shutil.disk_usage(Path("C:/")).free)
    require(free >= source_bytes + 3 * 1024**3, "TARGET_COPY_DISK_HEADROOM")
    available = int(subprocess.check_output(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory"],
        text=True, timeout=30).strip())
    require(available >= 2 * 1024**2, "TARGET_COPY_HOST_MEMORY")
    return free, available


def host(output: Path, execute: bool, packet_path: Path, packet_sha: str) -> None:
    packet = verify_operator(packet_path, packet_sha)
    private = (Path.home() / ".codex/private").resolve()
    output = output.resolve()
    require(output.is_relative_to(private) and output.parent.is_dir() and not output.exists(),
            "NEW_OWNED_RECEIPT_REQUIRED")
    require(not SOURCE.is_symlink() and not getattr(SOURCE, "is_junction", lambda: False)(),
            "SOURCE_CACHE_LINK_REFUSED")
    source = SOURCE.resolve(strict=True)
    require(source.is_dir() and not source.is_symlink(), "SOURCE_CACHE_MISSING")
    private_root = (Path.home() / ".codex").resolve(strict=True)
    require(all(not path.is_symlink() and not getattr(path, "is_junction", lambda: False)()
                for path in (SOURCE, *SOURCE.parents) if path.is_relative_to(private_root)),
            "SOURCE_ROOT_REPARSE_REFUSED")
    client = transport()
    writer_census(client)
    image = json.loads(docker_output(client, "image", "inspect", IMAGE))[0]
    require(image["Id"] == IMAGE and image["Os"] == "linux" and image["Architecture"] == "amd64",
            "COPY_HELPER_IMAGE_CHANGED")
    require(not docker_output(client, "volume", "ls", "-q", "--filter", "name=^" + VOLUME + "$"),
            "TARGET_VOLUME_ALREADY_EXISTS")
    active = docker_output(client, "ps", "-aq", "--no-trunc").split()
    for cid in active:
        checked_source_mounts(json.loads(docker_output(client, "inspect", cid)), source)
    before = manifest(source)
    require(before[1] > 30000 and before[2] >= 16 * 1024**3,
            "EXPECTED_RELEASE_CACHE_CHANGED")
    free, host_available_kib = copy_capacity(before[2], output.parent)
    plan = {"state": "SEED_CHECKED_NO_MUTATION", "sourceTarget": "marty-demo-native-cache-20261021/target",
            "targetVolume": VOLUME, "copyKind": "ordinary-byte-copy-no-hardlinks",
            "sourceManifestSha256": before[0], "sourceFileCount": before[1],
            "sourceBytes": before[2], "freeBytes": free,
            "hostAvailableKiB": host_available_kib, "windowsCompilerWriters": 0,
            "dockerCompilerWriters": 0, "sourceExportSha256": packet_sha,
            "producerRevision": packet["producerRevision"],
            "sourceMountedReadOnly": True, "targetHardlinksToSource": False,
            "owner": OWNER, "operatorSha256": sha(Path(__file__))}
    if not execute:
        print(json.dumps(plan))
        return
    writer_census(client)
    copy_capacity(before[2], output.parent)
    intent = output.with_suffix(".intent.json")
    require(not intent.exists(), "SEED_ATTEMPT_ALREADY_CONSUMED")
    with intent.open("xb") as target:
        raw = (json.dumps(plan, sort_keys=True) + "\n").encode()
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    create_started = datetime.now(timezone.utc).replace(microsecond=0)
    require(docker_output(client, "volume", "create", "--label", "io.elevenid.demo-audit.owner=" + OWNER,
                   "--label", "elevenid.run=" + output.stem, VOLUME) == VOLUME,
            "TARGET_VOLUME_CREATE_UNRESOLVED")
    created = json.loads(docker_output(client, "volume", "inspect", VOLUME))[0]
    created_at = datetime.fromisoformat(created["CreatedAt"].replace("Z", "+00:00"))
    require(created["Name"] == VOLUME and created["Driver"] == "local"
            and created["Scope"] == "local" and not created.get("Options")
            and created["Labels"] == {"io.elevenid.demo-audit.owner": OWNER,
                                       "elevenid.run": output.stem}
            and created_at >= create_started
            and not docker_output(client, "ps", "-aq", "--no-trunc", "--filter", "volume=" + VOLUME),
            "TARGET_VOLUME_OWNER_OR_CONSUMER_CHANGED")
    empty_name = "oid4vc-seed-" + str(uuid.uuid4())
    empty = owned_helper(client, empty_name, "--inside-inspect",
                         [(VOLUME, "/target", True), *operator_mounts()],
                         "256m", output.with_name(empty_name + ".intent.json"), 120)
    empty_state = json.loads(empty["stdout"])
    require(empty_state["fileCount"] == 0 and empty_state["bytes"] == 0,
            "NEW_TARGET_VOLUME_NOT_EMPTY")
    require(empty_state["guestAvailableKiB"] >= 2 * 1024**2,
            "TARGET_COPY_GUEST_MEMORY")
    retire_helper(client, empty)
    writer_census(client)
    copy_capacity(before[2], output.parent)
    name = "oid4vc-seed-" + str(uuid.uuid4())
    terminal = owned_helper(client, name, "--inside",
                            [(str(source), "/source", True), (VOLUME, "/target", False),
                             *operator_mounts()],
                            "2g", output.with_name(name + ".intent.json"), 1800)
    copied = json.loads(terminal["stdout"])
    require(copied["sourceManifestSha256"] == before[0]
            and copied["fileCount"] == before[1] and copied["bytes"] == before[2],
            "CACHE_COPY_READBACK_MISMATCH_PRESERVE_VOLUME")
    after = manifest(source)
    require(after == before, "CACHE_SOURCE_CHANGED_AFTER_COPY_PRESERVE_VOLUME")
    retire_helper(client, terminal)
    volume_proof = {key: created[key] for key in
                    ("Name", "Driver", "Scope", "CreatedAt", "Labels", "Mountpoint")}
    record = {**plan, **copied, "volumeProof": volume_proof, "sourceBeforeAfterMatched": True,
              "sourceMountedReadOnly": True, "targetHardlinksToSource": False}
    with output.open("x", encoding="utf-8") as target:
        json.dump(record, target, sort_keys=True)
        target.write("\n")
    print(json.dumps({"state": record["state"], "targetVolume": VOLUME,
                      "fileCount": record["fileCount"]}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--inside-inspect", action="store_true")
    parser.add_argument("--inspect", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-export", type=Path)
    parser.add_argument("--source-export-sha256")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    require(sum((args.inside, args.inside_inspect, args.inspect, args.run)) <= 1,
            "ONE_SEED_MODE_REQUIRED")
    if args.inside:
        require(args.output is None, "INSIDE_MODE_INPUT_REFUSED")
        inside()
    elif args.inside_inspect:
        require(args.output is None, "INSIDE_MODE_INPUT_REFUSED")
        digest, count, size = manifest(Path("/target"))
        meminfo = Path("/proc/meminfo").read_text()
        available = int(re.search(r"(?m)^MemAvailable:\s+(\d+) kB$", meminfo)[1])
        print(json.dumps({"manifestSha256": digest, "fileCount": count, "bytes": size,
                          "guestAvailableKiB": available}))
    elif args.inspect:
        require(args.output is not None, "SEED_RECEIPT_REQUIRED")
        print(json.dumps(inspect_target(args.output)))
    else:
        require(args.output is not None, "OWNED_OUTPUT_REQUIRED")
        require(args.source_export is not None and args.source_export_sha256,
                "EXACT_SEED_SOURCE_EXPORT_REQUIRED")
        host(args.output, args.run, args.source_export, args.source_export_sha256)


if __name__ == "__main__":
    main()
