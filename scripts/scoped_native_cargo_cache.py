"""Exact-lock cache preparation for source-bound native builds.

The fetch helper is a separate, owned networked operation. The native compiler
continues to mount the same Cargo volume with network=none and offline Cargo.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib
import time


REV = re.compile(r"git\+https://github\.com/ElevenID/([A-Za-z0-9_-]+)\?rev=([0-9a-f]{40})#([0-9a-f]{40})\Z")


def git_sources(original_lock: bytes) -> dict[str, str]:
    """Return the complete pinned Git source set from the original Git lock."""
    rows = tomllib.loads(original_lock.decode("utf-8"))["package"]
    found: dict[str, str] = {}
    for row in rows:
        source = row.get("source", "")
        if not source.startswith("git+"):
            continue
        match = REV.fullmatch(source)
        if match is None or match[2] != match[3]:
            raise ValueError("NATIVE_CACHE_UNPINNED_GIT_SOURCE")
        # More than one revision per repository is valid, e.g. SSI.
        found[match[1] + "@" + match[2]] = source
    if not found:
        raise ValueError("NATIVE_CACHE_GIT_SOURCES_MISSING")
    return dict(sorted(found.items()))


def metadata_git_sources(metadata: bytes) -> dict[str, str]:
    """Confirm offline resolution used the same exact pinned Git source IDs."""
    found: dict[str, str] = {}
    for row in json.loads(metadata)["packages"]:
        source = row.get("source") or ""
        if not source.startswith("git+"):
            continue
        match = REV.fullmatch(source)
        if match is None or match[2] != match[3]:
            raise ValueError("NATIVE_CACHE_OFFLINE_SOURCE_CHANGED")
        found[match[1] + "@" + match[2]] = source
    return dict(sorted(found.items()))


def render_fetch_script(lock_sha256: str, expected_sources: dict[str, str]) -> bytes:
    if re.fullmatch(r"[0-9a-f]{64}", lock_sha256) is None:
        raise ValueError("NATIVE_CACHE_LOCK_DIGEST_REQUIRED")
    # This is the *unlocalized* committed lock. Core path localization belongs
    # to the later offline compiler and has its own guarded lock boundary.
    expected_json = json.dumps(expected_sources, sort_keys=True)
    return ("#!/bin/sh\nset -eu\n"
            "export CARGO_HOME=/cargo CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0\n"
            "sha256sum /src/ui/rust/Cargo.lock > /out/original-lock-before.sha256\n"
            f"printf '%s  %s\\n' '{lock_sha256}' '/src/ui/rust/Cargo.lock' > /out/expected-lock.sha256\n"
            "cmp /out/original-lock-before.sha256 /out/expected-lock.sha256\n"
            "CARGO_NET_OFFLINE=false cargo fetch --locked --manifest-path /src/ui/rust/Cargo.toml > /out/fetch.log 2>&1\n"
            "sha256sum /src/ui/rust/Cargo.lock > /out/original-lock-after.sha256\n"
            "cmp /out/original-lock-before.sha256 /out/original-lock-after.sha256\n"
            "CARGO_NET_OFFLINE=true cargo fetch --offline --locked --manifest-path /src/ui/rust/Cargo.toml > /out/offline-fetch.log 2>&1\n"
            "CARGO_NET_OFFLINE=true cargo metadata --offline --locked --format-version 1 --manifest-path /src/ui/rust/Cargo.toml > /out/original-lock-offline-metadata.json\n"
            f"printf '%s\\n' '{expected_json}' > /out/expected-git-sources.json\n"
            "python3 /build/cache_guard.py verify-checkouts /out/expected-git-sources.json /cargo/git/checkouts /out/checkout-proof.json\n"
            "sha256sum /src/ui/rust/Cargo.lock > /out/original-lock-final.sha256\n"
            "cmp /out/original-lock-before.sha256 /out/original-lock-final.sha256\n").encode("utf-8")


def _git(path: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(path), *args], capture_output=True, timeout=30)
    if result.returncode != 0 or result.stderr:
        raise ValueError("NATIVE_CACHE_GIT_CHECKOUT_UNREADABLE")
    return result.stdout.strip()


def _clean_checkout(path: Path, expected_revision: str) -> dict:
    """Verify exact tracked/index bytes, all nested gitlinks and only Cargo markers."""
    if not path.is_dir() or path.is_symlink() or _git(path, "rev-parse", "HEAD").decode() != expected_revision:
        raise ValueError("NATIVE_CACHE_CHECKOUT_REVISION_CHANGED")
    for args in (("diff", "--quiet", "--no-ext-diff", "--ignore-submodules=all"),
                 ("diff", "--cached", "--quiet", "--no-ext-diff", "--ignore-submodules=all")):
        result = subprocess.run(["git", "-C", str(path), *args], capture_output=True, timeout=60)
        if result.returncode != 0 or result.stderr:
            raise ValueError("NATIVE_CACHE_CHECKOUT_TRACKED_DRIFT")
    status = _git(path, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=all")
    if any(row != b"?? .cargo-ok" for row in status.split(b"\0") if row):
        raise ValueError("NATIVE_CACHE_CHECKOUT_UNEXPECTED_FILE")
    flags = _git(path, "ls-files", "-v", "-z")
    if any(not row.startswith(b"H ") for row in flags.split(b"\0") if row):
        raise ValueError("NATIVE_CACHE_CHECKOUT_INDEX_FLAG")
    children = []
    entries = _git(path, "ls-files", "-s", "-z")
    for row in entries.split(b"\0"):
        if not row or not row.startswith(b"160000 "):
            continue
        header, relative = row.split(b"\t", 1)
        expected_child = header.split()[1].decode()
        name = relative.decode("utf-8")
        if name.startswith("/") or any(part in ("", ".", "..") for part in name.split("/")):
            raise ValueError("NATIVE_CACHE_SUBMODULE_PATH_UNSAFE")
        children.append({"path": name, **_clean_checkout(path / name, expected_child)})
    return {"revision": expected_revision, "tree": _git(path, "rev-parse", "HEAD^{tree}").decode(),
            "clean": True, "submodules": children}


def verify_checkout_root(expected_sources: dict[str, str], root: Path) -> dict:
    """Complete Git-lock checkout proof; a matching HEAD alone is insufficient."""
    if not root.is_dir() or root.is_symlink():
        raise ValueError("NATIVE_CACHE_CHECKOUT_ROOT_MISSING")
    result = {}
    for key in sorted(expected_sources):
        repo, revision = key.split("@", 1)
        if expected_sources[key] != f"git+https://github.com/ElevenID/{repo}?rev={revision}#{revision}":
            raise ValueError("NATIVE_CACHE_EXPECTED_SOURCE_CHANGED")
        candidates = sorted(root.glob(repo + "-*/*"))
        selected = None
        for path in candidates:
            try:
                selected = _clean_checkout(path, revision)
            except ValueError:
                continue
            selected["checkout"] = str(path)
            break
        if selected is None:
            raise ValueError("NATIVE_CACHE_CLEAN_CHECKOUT_MISSING:" + key)
        result[key] = selected
    return result


def confirm_retired(helper, cid: str, engine_id: str) -> None:
    """Successful daemon census, never an arbitrary failed inspect as absence."""
    if not re.fullmatch(r"[0-9a-f]{64}", cid):
        raise ValueError("NATIVE_CACHE_EXACT_CID_REQUIRED")
    current = helper.run("docker", "--context", "desktop-linux", "info", "--format", "{{.ID}}")
    if current.stdout.strip() != engine_id:
        raise ValueError("NATIVE_CACHE_ENGINE_CHANGED_AFTER_RETIREMENT")
    listed = helper.run("docker", "--context", "desktop-linux", "ps", "--all", "--quiet", "--no-trunc",
                        "--filter", "id=" + cid)
    if listed.stdout.strip():
        raise ValueError("NATIVE_CACHE_HELPER_STILL_REGISTERED")


def validate_receipt(plan: dict, receipt: dict, original_lock: bytes,
                     offline_metadata: bytes, checkout_proof: bytes) -> None:
    """Refuse a stale/foreign hydration receipt before any native build intent."""
    digest = hashlib.sha256(original_lock).hexdigest()
    expected = git_sources(original_lock)
    resolved = metadata_git_sources(offline_metadata)
    checkout = json.loads(checkout_proof)
    core_rev = plan["sources"]["core"]["revision"]
    if "marty-core@" + core_rev not in expected:
        raise ValueError("NATIVE_CACHE_FROZEN_CORE_LOCK_CHANGED")
    if not (receipt.get("state") == "LOCKED_FETCH_AND_OFFLINE_READBACK_PASSED"
            and receipt.get("exitCode") == 0 and type(receipt.get("exitCode")) is int
            and receipt.get("oomKilled") is False
            and receipt.get("helperRemoved") is True
            and type(receipt.get("lockedFetchExitCode")) is int and receipt["lockedFetchExitCode"] == 0
            and type(receipt.get("offlineFetchExitCode")) is int and receipt["offlineFetchExitCode"] == 0
            and receipt.get("originalLockSha256") == digest
            and receipt.get("beforeLockSha256") == receipt.get("afterLockSha256") == digest
            and receipt.get("finalLockSha256") == digest
            and receipt.get("gitSources") == expected
            and receipt.get("offlineMetadataGitSources") == resolved
            and set(resolved.items()).issubset(set(expected.items()))
            and receipt.get("checkoutProof") == checkout
            and set(checkout) == set(expected)
            and all(isinstance(checkout[key], dict)
                    and checkout[key].get("revision") == key.split("@", 1)[1]
                    and checkout[key].get("clean") is True
                    and re.fullmatch(r"[0-9a-f]{40}", checkout[key].get("tree", ""))
                    and checkout[key].get("checkout", "").startswith("/cargo/git/checkouts/" + key.split("@", 1)[0] + "-")
                    and isinstance(checkout[key].get("submodules"), list)
                    for key in expected)
            and receipt.get("uiRevision") == plan["sources"]["ui"]["revision"]
            and receipt.get("uiTree") == plan["sources"]["ui"]["tree"]
            and receipt.get("uiInventorySha256") == plan["sources"]["ui"]["inventory"]["sha256"]
            and receipt.get("cargoVolume") == "ui-canvas-cargo"
            and isinstance(receipt.get("cargoVolumeCreatedAt"), str)
            and bool(receipt["cargoVolumeCreatedAt"])
            and receipt.get("engineId") == plan["engineId"]
            and receipt.get("builderImage") == plan["builderImage"]
            and isinstance(receipt.get("journalBackend"), dict)
            and receipt["journalBackend"].get("backend") == "DOCKER_DESKTOP_PRIVATE_JOURNAL_V1"
            and receipt["journalBackend"].get("desktop", {}).get("engineId") == plan["engineId"]
            and receipt.get("offlineMetadataSha256") == hashlib.sha256(offline_metadata).hexdigest()
            and receipt.get("checkoutProofSha256") == hashlib.sha256(checkout_proof).hexdigest()):
        raise ValueError("NATIVE_CACHE_EXACT_LOCK_READBACK_REQUIRED")


def validate_bound_receipt(plan: dict, receipt_path: Path, receipt_sha256: str) -> None:
    """Validate receipt reference and original source lock independently."""
    if (not receipt_path.is_file() or receipt_path.is_symlink()
            or not re.fullmatch(r"[0-9a-f]{64}", receipt_sha256)
            or hashlib.sha256(receipt_path.read_bytes()).hexdigest() != receipt_sha256):
        raise ValueError("NATIVE_CACHE_RECEIPT_CHANGED")
    lock_path = Path(plan["sources"]["ui"]["directory"]) / "rust" / "Cargo.lock"
    if not lock_path.is_file() or lock_path.is_symlink():
        raise ValueError("NATIVE_CACHE_ORIGINAL_LOCK_MISSING")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    metadata_ref = receipt.get("offlineMetadataRef", {})
    metadata_path = Path(metadata_ref.get("path", "")).resolve()
    if (not metadata_path.is_relative_to(receipt_path.parent.resolve())
            or not metadata_path.is_file() or metadata_path.is_symlink()
            or metadata_path.stat().st_size > 64 * 1024 * 1024
            or metadata_ref.get("sha256") != hashlib.sha256(metadata_path.read_bytes()).hexdigest()):
        raise ValueError("NATIVE_CACHE_OFFLINE_METADATA_CHANGED")
    checkout_ref = receipt.get("checkoutProofRef", {})
    checkout_path = Path(checkout_ref.get("path", "")).resolve()
    if (not checkout_path.is_relative_to(receipt_path.parent.resolve())
            or not checkout_path.is_file() or checkout_path.is_symlink()
            or checkout_path.stat().st_size > 1024 * 1024
            or checkout_ref.get("sha256") != hashlib.sha256(checkout_path.read_bytes()).hexdigest()):
        raise ValueError("NATIVE_CACHE_CHECKOUT_PROOF_CHANGED")
    validate_receipt(plan, receipt, lock_path.read_bytes(), metadata_path.read_bytes(), checkout_path.read_bytes())


def hydrate(plan: dict, helper, journal) -> dict:
    """One owned cache-only Docker operation; caller supplies reviewed journal/job.

    A failure or deadline retains the exact helper and journal for diagnosis. This
    never starts the native compiler and never mounts the target volume.
    """
    from scoped_native_runtime import daemon_source, durable_barrier, ref, require, sha

    source = Path(plan["sources"]["ui"]["directory"]).resolve(strict=True)
    output = Path(plan["cacheOutputDirectory"]).resolve(strict=True)
    lock = source / "rust/Cargo.lock"
    require(lock.is_file() and not lock.is_symlink() and not list(output.iterdir()),
            "NATIVE_CACHE_FRESH_SOURCE_OUTPUT_REQUIRED")
    digest = sha(lock)
    expected_sources = git_sources(lock.read_bytes())
    require("marty-core@" + plan["sources"]["core"]["revision"] in expected_sources,
            "NATIVE_CACHE_FROZEN_CORE_LOCK_CHANGED")
    script = Path(plan["cacheScript"]["path"]).resolve(strict=True)
    guard = Path(plan["cacheGuard"]["path"]).resolve(strict=True)
    require(sha(script) == plan["cacheScript"]["sha256"]
            and script.read_bytes() == render_fetch_script(digest, expected_sources)
            and guard == Path(__file__).resolve()
            and sha(guard) == plan["cacheGuard"]["sha256"],
            "NATIVE_CACHE_EXACT_SCRIPT_REQUIRED")
    run_id = plan["cacheRunId"]
    require(re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", run_id),
            "NATIVE_CACHE_OWNED_RUN_REQUIRED")
    name = "marty-native-cache-" + run_id
    require(getattr(journal, "run_id", None) == run_id
            and getattr(journal, "specification", {}).get("backend") == "DOCKER_DESKTOP_PRIVATE_JOURNAL_V1",
            "NATIVE_CACHE_EXACT_DESKTOP_JOURNAL_REQUIRED")
    host_kib = int(helper.run("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                              "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory").stdout.strip())
    require(host_kib >= 2 * 1024 * 1024 + 64 * 1024
            and shutil.disk_usage(output).free >= 1024 ** 3,
            "NATIVE_CACHE_CAPACITY_NOT_ADMITTED")
    engine = helper.run("docker", "--context", "desktop-linux", "info", "--format", "{{.ID}}").stdout.strip()
    require(engine == plan["engineId"], "NATIVE_CACHE_ENGINE_CHANGED")
    image = json.loads(helper.run("docker", "--context", "desktop-linux", "image", "inspect", plan["builderImage"]).stdout)[0]
    require(image["Id"] == plan["builderImage"] and image["Os"] == "linux" and image["Architecture"] == "amd64",
            "NATIVE_CACHE_IMAGE_CHANGED")
    volumes = json.loads(helper.run("docker", "--context", "desktop-linux", "volume", "inspect", "ui-canvas-cargo").stdout)
    require(len(volumes) == 1 and volumes[0]["Name"] == "ui-canvas-cargo" and volumes[0]["Driver"] == "local",
            "NATIVE_CACHE_VOLUME_CHANGED")
    require(not helper.run("docker", "--context", "desktop-linux", "ps", "--quiet", "--no-trunc",
                           "--filter", "volume=ui-canvas-cargo").stdout.strip(),
            "NATIVE_CACHE_LIVE_CONSUMER")
    intent = {"state": "CACHE_FETCH_CREATE_INTENT", "runId": run_id, "uiRevision": plan["sources"]["ui"]["revision"],
              "originalLockSha256": digest, "gitSources": expected_sources, "engineId": engine,
              "builderImage": image["Id"], "cargoVolume": "ui-canvas-cargo",
              "cargoVolumeCreatedAt": volumes[0]["CreatedAt"], "targetMounted": False,
              "compilerStarted": False}
    proof = journal.exclusive("build-apply-intent.json", intent)
    require(durable_barrier(proof), "NATIVE_CACHE_DURABLE_INTENT_REQUIRED")
    args = ["docker", "--context", "desktop-linux", "create", "--pull=never", "--name", name,
            "--label", "elevenid.owner=native-cargo-cache", "--label", "elevenid.run=" + run_id,
            "--network", "bridge", "--memory", "2g", "--memory-swap", "4g", "--cpus", "1",
            "--pids-limit", "64", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--mount", "type=bind,src=" + daemon_source(source) + ",dst=/src/ui,readonly",
            "--mount", "type=bind,src=" + daemon_source(output) + ",dst=/out",
            "--mount", "type=bind,src=" + daemon_source(script) + ",dst=/fetch.sh,readonly",
            "--mount", "type=bind,src=" + daemon_source(guard) + ",dst=/build/cache_guard.py,readonly",
            "--mount", "type=volume,src=ui-canvas-cargo,dst=/cargo",
            "--entrypoint", "/bin/sh", image["Id"], "/fetch.sh"]
    cid = helper.run(*args).stdout.strip()
    require(re.fullmatch(r"[a-f0-9]{64}", cid), "NATIVE_CACHE_CREATED_CID_UNKNOWN")
    journal.state({**intent, "state": "CACHE_FETCH_CREATED", "containerId": cid})
    row = json.loads(helper.run("docker", "--context", "desktop-linux", "inspect", cid).stdout)[0]
    mounts = {m["Destination"]: m for m in row["Mounts"]}
    host = row["HostConfig"]
    require(row["Id"] == cid and row["Image"] == image["Id"] and row["Name"] == "/" + name
            and row["State"]["Status"] == "created"
            and row["Config"]["Labels"]["elevenid.owner"] == "native-cargo-cache"
            and row["Config"]["Labels"]["elevenid.run"] == run_id
            and host["NetworkMode"] == "bridge" and host["Memory"] == 2 * 1024 ** 3
            and host["MemorySwap"] == 4 * 1024 ** 3 and host["PidsLimit"] == 64
            and host["NanoCpus"] == 10 ** 9
            and host["Privileged"] is False and "ALL" in host["CapDrop"]
            and len(row["Mounts"]) == len(mounts) == 5
            and set(mounts) == {"/src/ui", "/out", "/fetch.sh", "/build/cache_guard.py", "/cargo"}
            and mounts["/src/ui"]["RW"] is False and mounts["/fetch.sh"]["RW"] is False
            and mounts["/build/cache_guard.py"]["RW"] is False
            and mounts["/out"]["RW"] is True and mounts["/cargo"]["RW"] is True
            and mounts["/cargo"]["Name"] == "ui-canvas-cargo"
            and daemon_source(mounts["/src/ui"]["Source"]) == daemon_source(source)
            and daemon_source(mounts["/out"]["Source"]) == daemon_source(output)
            and daemon_source(mounts["/fetch.sh"]["Source"]) == daemon_source(script)
            and daemon_source(mounts["/build/cache_guard.py"]["Source"]) == daemon_source(guard),
            "NATIVE_CACHE_CREATED_IDENTITY_CHANGED")
    require(durable_barrier(journal.state({**intent, "state": "CACHE_FETCH_START_INTENT", "containerId": cid})),
            "NATIVE_CACHE_START_DURABILITY_REQUIRED")
    helper.run("docker", "--context", "desktop-linux", "start", cid)
    deadline = time.monotonic() + 600
    while True:
        row = json.loads(helper.run("docker", "--context", "desktop-linux", "inspect", cid).stdout)[0]
        if row["State"]["Status"] == "exited":
            break
        require(time.monotonic() < deadline, "NATIVE_CACHE_TERMINAL_UNKNOWN_RETAIN_HELPER")
        time.sleep(5)
    require(row["Id"] == cid and type(row["State"]["ExitCode"]) is int
            and row["State"]["ExitCode"] == 0 and row["State"]["OOMKilled"] is False,
            "NATIVE_CACHE_FETCH_FAILED_RETAIN_HELPER")
    metadata = (output / "original-lock-offline-metadata.json").read_bytes()
    resolved = metadata_git_sources(metadata)
    require(set(resolved.items()).issubset(set(expected_sources.items())),
            "NATIVE_CACHE_OFFLINE_SOURCE_CHANGED_RETAIN_HELPER")
    checkout_bytes = (output / "checkout-proof.json").read_bytes()
    checkout = json.loads(checkout_bytes)
    require(set(checkout) == set(expected_sources)
            and all(checkout[key].get("revision") == key.split("@", 1)[1]
                    and checkout[key].get("clean") is True for key in expected_sources),
            "NATIVE_CACHE_CHECKOUTS_INCOMPLETE_RETAIN_HELPER")
    before = (output / "original-lock-before.sha256").read_text().split()[0]
    after = (output / "original-lock-after.sha256").read_text().split()[0]
    final = (output / "original-lock-final.sha256").read_text().split()[0]
    require(before == after == final == digest and sha(lock) == digest,
            "NATIVE_CACHE_LOCK_CHANGED_RETAIN_HELPER")
    terminal = {**intent, "state": "CACHE_FETCH_TERMINAL_VERIFIED", "containerId": cid,
                "exitCode": 0, "oomKilled": False, "offlineMetadataSha256": hashlib.sha256(metadata).hexdigest()}
    require(durable_barrier(journal.state(terminal)), "NATIVE_CACHE_TERMINAL_DURABILITY_REQUIRED")
    helper.run("docker", "--context", "desktop-linux", "rm", cid)
    confirm_retired(helper, cid, engine)
    receipt = {**terminal, "state": "LOCKED_FETCH_AND_OFFLINE_READBACK_PASSED",
               "helperRemoved": True, "lockedFetchExitCode": 0, "offlineFetchExitCode": 0,
               "beforeLockSha256": before, "afterLockSha256": after, "finalLockSha256": final,
               "offlineMetadataGitSources": resolved, "offlineMetadataRef": ref(output / "original-lock-offline-metadata.json"),
               "checkoutProof": checkout, "checkoutProofSha256": hashlib.sha256(checkout_bytes).hexdigest(),
               "checkoutProofRef": ref(output / "checkout-proof.json"),
               "uiTree": plan["sources"]["ui"]["tree"], "journalBackend": plan["journalBackend"],
               "uiInventorySha256": plan["sources"]["ui"]["inventory"]["sha256"]}
    journal.exclusive("build-receipt.json", receipt)
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify exact Cargo Git checkout bytes")
    parser.add_argument("command", choices=("verify-checkouts",))
    parser.add_argument("expected", type=Path)
    parser.add_argument("checkouts", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    expected = json.loads(args.expected.read_text(encoding="utf-8"))
    proof = verify_checkout_root(expected, args.checkouts)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(proof, stream, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
