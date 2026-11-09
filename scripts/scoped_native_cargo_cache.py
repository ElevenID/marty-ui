"""Exact-lock cache preparation for source-bound native builds.

The fetch helper is a separate, owned networked operation. The native compiler
continues to mount the same Cargo volume with network=none and offline Cargo.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib
import time


REV = re.compile(r"git\+https://github\.com/ElevenID/([A-Za-z0-9_-]+)\?rev=([0-9a-f]{40})#([0-9a-f]{40})\Z")
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
REGISTRY_CACHE = "index.crates.io-1949cf8c6b5b557f"


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


def registry_archives(original_lock: bytes) -> dict[str, str]:
    """Derive every exact crates.io archive checksum from the original lock."""
    rows = tomllib.loads(original_lock.decode("utf-8"))["package"]
    result = {}
    for row in rows:
        source = row.get("source", "")
        if not source.startswith("registry+"):
            continue
        name, version, checksum = (row.get(key) for key in ("name", "version", "checksum"))
        if (source != REGISTRY_SOURCE or not isinstance(name, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", name)
                or not isinstance(version, str)
                or not re.fullmatch(r"[A-Za-z0-9.+-]{1,64}", version)
                or not isinstance(checksum, str)
                or not re.fullmatch(r"[0-9a-f]{64}", checksum)):
            raise ValueError("NATIVE_CACHE_REGISTRY_SOURCE_CHANGED")
        filename = f"{name}-{version}.crate"
        if filename in result and result[filename] != checksum:
            raise ValueError("NATIVE_CACHE_REGISTRY_ARCHIVE_CONFLICT")
        result[filename] = checksum
    if not result:
        raise ValueError("NATIVE_CACHE_REGISTRY_ARCHIVES_MISSING")
    return dict(sorted(result.items()))


def registry_set_sha256(archives: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(archives, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verified_registry_seed(original_lock: bytes, directory: Path) -> dict[str, str]:
    archives = registry_archives(original_lock)
    if (not directory.is_dir() or directory.is_symlink()
            or getattr(directory, "is_junction", lambda: False)()):
        raise ValueError("NATIVE_CACHE_REGISTRY_SEED_CHANGED")
    for filename, checksum in archives.items():
        file = directory / filename
        if (not file.is_file() or file.is_symlink() or file.stat().st_size > 128 * 1024 ** 2
                or _file_sha256(file) != checksum):
            raise ValueError("NATIVE_CACHE_REGISTRY_ARCHIVE_CHANGED:" + filename)
    return archives


def import_registry_archives(original_lock: bytes, seed: Path, destination: Path,
                             proof_output: Path) -> dict:
    """Copy locked archives into owned Cargo cache with atomic no-replace links."""
    archives = verified_registry_seed(original_lock, seed)
    for part in (destination.parent.parent, destination.parent, destination):
        if part.exists() and (not part.is_dir() or part.is_symlink()):
            raise ValueError("NATIVE_CACHE_REGISTRY_DESTINATION_CHANGED")
    if proof_output.exists() or proof_output.is_symlink():
        raise ValueError("NATIVE_CACHE_REGISTRY_PROOF_ALREADY_EXISTS")
    destination.mkdir(parents=True, exist_ok=True)
    copied = reused = 0
    for filename, checksum in archives.items():
        target = destination / filename
        if target.exists() or target.is_symlink():
            if (not target.is_file() or target.is_symlink()
                    or _file_sha256(target) != checksum):
                raise ValueError("NATIVE_CACHE_REGISTRY_EXISTING_MISMATCH:" + filename)
            reused += 1
            continue
        staged = destination / (".marty-local-import-" + str(os.getpid()) + "-" + filename)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(staged, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as output, (seed / filename).open("rb") as source:
                shutil.copyfileobj(source, output, length=1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
            if _file_sha256(staged) != checksum:
                raise ValueError("NATIVE_CACHE_REGISTRY_STAGE_CHANGED:" + filename)
            try:
                os.link(staged, target)
                copied += 1
            except FileExistsError:
                if (not target.is_file() or target.is_symlink()
                        or _file_sha256(target) != checksum):
                    raise ValueError("NATIVE_CACHE_REGISTRY_RACED_MISMATCH:" + filename) from None
                reused += 1
        finally:
            staged.unlink(missing_ok=True)
        if _file_sha256(target) != checksum:
            raise ValueError("NATIVE_CACHE_REGISTRY_PROMOTION_CHANGED:" + filename)
    proof = {"state": "EXACT_LOCK_REGISTRY_ARCHIVES_READBACK", "count": len(archives),
             "copied": copied, "reused": reused,
             "archiveSetSha256": registry_set_sha256(archives),
             "originalLockSha256": hashlib.sha256(original_lock).hexdigest()}
    with proof_output.open("x", encoding="utf-8") as stream:
        json.dump(proof, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return proof


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


def _local_import_lines(expected_sources: dict[str, str], local_objects: dict) -> str:
    """Import exact Git objects through read-only mounts with network disabled."""
    if set(local_objects) != set(expected_sources) | {"rdfGitlink"}:
        raise ValueError("NATIVE_CACHE_LOCAL_SOURCE_SET_CHANGED")
    lines = []
    imported = set()
    for key in sorted(expected_sources):
        repo, revision = key.split("@", 1)
        row = local_objects[key]
        name, tree = row.get("cargoDbName"), row.get("tree")
        bare = row.get("bare")
        if (row.get("revision") != revision
                or not re.fullmatch(re.escape(repo) + r"-[0-9a-f]{16}", name or "")
                or not re.fullmatch(r"[a-f0-9]{40}", tree or "")
                or type(bare) is not bool or (repo != "marty-core" and bare is not True)):
            raise ValueError("NATIVE_CACHE_LOCAL_OBJECT_PROOF_CHANGED")
        if name in imported:
            continue
        imported.add(name)
        revisions = [(k.split("@", 1)[1], local_objects[k]["tree"])
                     for k in sorted(expected_sources) if local_objects[k]["cargoDbName"] == name]
        lines += [f"test -d /seed/{name}",
                  f"test \"$(git --git-dir=/seed/{name} rev-parse --is-bare-repository)\" = {'true' if bare else 'false'}",
                  f"test -d /cargo/git/db/{name} || git init --bare -q /cargo/git/db/{name}",
                  f"test \"$(git --git-dir=/cargo/git/db/{name} rev-parse --is-bare-repository)\" = true"]
        for rev, expected_tree in revisions:
            if not re.fullmatch(r"[a-f0-9]{40}", expected_tree or ""):
                raise ValueError("NATIVE_CACHE_LOCAL_TREE_PROOF_CHANGED")
            lines += [f"test \"$(git --git-dir=/seed/{name} cat-file -t {rev})\" = commit",
                      f"test \"$(git --git-dir=/seed/{name} rev-parse {rev}^{{tree}})\" = {expected_tree}",
                      f"git --git-dir=/cargo/git/db/{name} fetch -q --no-tags --no-recurse-submodules /seed/{name} {rev}",
                      f"test \"$(git --git-dir=/cargo/git/db/{name} rev-parse {rev}^{{tree}})\" = {expected_tree}"]
    rdf = local_objects["rdfGitlink"]
    rdf_name, rdf_rev, rdf_tree = (rdf.get(k) for k in ("cargoDbName", "revision", "tree"))
    if (not re.fullmatch(r"rdf-dataset-canonicalization-[0-9a-f]{16}", rdf_name or "")
            or not re.fullmatch(r"[a-f0-9]{40}", rdf_rev or "")
            or not re.fullmatch(r"[a-f0-9]{40}", rdf_tree or "")
            or rdf.get("parentSource") not in expected_sources):
        raise ValueError("NATIVE_CACHE_RDF_OBJECT_PROOF_CHANGED")
    lines += [f"test \"$(git --git-dir=/seed/{rdf_name} cat-file -t {rdf_rev})\" = commit",
              f"test \"$(git --git-dir=/seed/{rdf_name} rev-parse {rdf_rev}^{{tree}})\" = {rdf_tree}",
              f"test -d /cargo/git/db/{rdf_name} || git init --bare -q /cargo/git/db/{rdf_name}",
              f"test \"$(git --git-dir=/cargo/git/db/{rdf_name} rev-parse --is-bare-repository)\" = true",
              f"git --git-dir=/cargo/git/db/{rdf_name} fetch -q --no-tags --no-recurse-submodules /seed/{rdf_name} {rdf_rev}",
              f"test \"$(git --git-dir=/cargo/git/db/{rdf_name} rev-parse {rdf_rev}^{{tree}})\" = {rdf_tree}"]
    parent = local_objects[rdf["parentSource"]]
    ssi_name, ssi_rev = parent["cargoDbName"], parent["revision"]
    checkout = f"/cargo/git/checkouts/{ssi_name}/{ssi_rev[:7]}"
    lines += [f"test \"$(git --git-dir=/cargo/git/db/{ssi_name} ls-tree {ssi_rev} crates/rdf/canonicalization | cut -f1 | awk '{{print $3}}')\" = {rdf_rev}",
              f"if [ ! -d {checkout} ]; then",
              f"  mkdir -p /cargo/git/checkouts/{ssi_name}",
              f"  git clone -q --no-hardlinks --no-checkout /cargo/git/db/{ssi_name} {checkout}",
              f"  git -C {checkout} checkout -q --detach {ssi_rev}",
              f"  git -C {checkout} config submodule.crates/rdf/canonicalization.url /cargo/git/db/{rdf_name}",
              f"  git -C {checkout} -c protocol.file.allow=always submodule update --init --recursive",
              f"  touch {checkout}/.cargo-ok",
              "fi",
              f"python3 /build/cache_guard.py verify-one-checkout {checkout} {ssi_rev} /out/ssi-gitlink-preproof.json"]
    return "\n".join(lines) + "\n"


def render_fetch_script(lock_sha256: str, expected_sources: dict[str, str],
                        local_objects: dict | None = None) -> bytes:
    if re.fullmatch(r"[0-9a-f]{64}", lock_sha256) is None:
        raise ValueError("NATIVE_CACHE_LOCK_DIGEST_REQUIRED")
    # This is the *unlocalized* committed lock. Core path localization belongs
    # to the later offline compiler and has its own guarded lock boundary.
    expected_json = json.dumps(expected_sources, sort_keys=True)
    import_lines = _local_import_lines(expected_sources, local_objects) if local_objects is not None else ""
    registry_line = ("python3 /build/cache_guard.py import-registry /src/ui/rust/Cargo.lock "
                     "/seed/registry /cargo/registry/cache/" + REGISTRY_CACHE
                     + " /out/registry-proof.json\n") if local_objects is not None else ""
    fetch = ("CARGO_NET_OFFLINE=true cargo fetch --offline --locked --manifest-path /src/ui/rust/Cargo.toml > /out/fetch.log 2>&1\n"
             if local_objects is not None else
             "CARGO_NET_OFFLINE=false cargo fetch --locked --manifest-path /src/ui/rust/Cargo.toml > /out/fetch.log 2>&1\n")
    return ("#!/bin/sh\nset -eu\n"
            "export CARGO_HOME=/cargo CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0\n"
            "sha256sum /src/ui/rust/Cargo.lock > /out/original-lock-before.sha256\n"
            f"printf '%s  %s\\n' '{lock_sha256}' '/src/ui/rust/Cargo.lock' > /out/expected-lock.sha256\n"
            "cmp /out/original-lock-before.sha256 /out/expected-lock.sha256\n"
            + import_lines + registry_line + fetch +
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


def _git_dir(path: Path, *args: str) -> bytes:
    """Read exact local Git objects without using a remote or credential helper."""
    result = subprocess.run(["git", "--git-dir", str(path), *args],
                            capture_output=True, timeout=30)
    if result.returncode != 0 or result.stderr:
        raise ValueError("NATIVE_CACHE_LOCAL_GIT_OBJECT_UNREADABLE")
    return result.stdout.strip()


def verified_local_objects(original_lock: bytes, sources: dict) -> dict:
    """Bind local read-only object directories to every original lock Git source.

    `sources` is private operator input, never a replacement for Cargo.lock URLs.
    The rdf gitlink is derived from the exact SSI parent tree rather than supplied
    as another Cargo dependency.
    """
    expected = git_sources(original_lock)
    if set(sources) != set(expected) | {"rdfGitlink"}:
        raise ValueError("NATIVE_CACHE_LOCAL_SOURCE_SET_CHANGED")
    result = {}
    mounted_names = {}
    for key, source in expected.items():
        repo, revision = key.split("@", 1)
        row = sources[key]
        if (set(row) != {"gitDirectory", "cargoDbName", "checkoutDirectory"}
                or source != f"git+https://github.com/ElevenID/{repo}?rev={revision}#{revision}"):
            raise ValueError("NATIVE_CACHE_LOCAL_SOURCE_CHANGED")
        directory = Path(row["gitDirectory"])
        if (not directory.is_absolute() or not directory.is_dir() or directory.is_symlink()
                or directory.is_junction()
                or not re.fullmatch(re.escape(repo) + r"-[0-9a-f]{16}", row["cargoDbName"])):
            raise ValueError("NATIVE_CACHE_LOCAL_OBJECT_DIRECTORY_CHANGED")
        resolved = str(directory.resolve())
        if (row["cargoDbName"] in mounted_names
                and mounted_names[row["cargoDbName"]] != resolved):
            raise ValueError("NATIVE_CACHE_LOCAL_SHARED_DB_CHANGED")
        mounted_names[row["cargoDbName"]] = resolved
        bare = _git_dir(directory, "rev-parse", "--is-bare-repository") == b"true"
        if (repo != "marty-core" and not bare):
            raise ValueError("NATIVE_CACHE_LOCAL_SEED_NOT_BARE")
        if (_git_dir(directory, "cat-file", "-t", revision) != b"commit"
                or _git_dir(directory, "rev-parse", revision + "^{tree}") == b""):
            raise ValueError("NATIVE_CACHE_LOCAL_COMMIT_MISSING")
        checkout = row["checkoutDirectory"]
        if checkout is not None:
            checked = Path(checkout)
            proof = _clean_checkout(checked, revision)
            if checked.parent.name != row["cargoDbName"] or proof["revision"] != revision:
                raise ValueError("NATIVE_CACHE_LOCAL_CHECKOUT_CHANGED")
        result[key] = {"gitDirectory": resolved,
                       "cargoDbName": row["cargoDbName"],
                       "revision": revision,
                       "tree": _git_dir(directory, "rev-parse", revision + "^{tree}").decode(),
                       "bare": bare,
                       "checkout": checkout}
    ssi = [key for key in expected if key.startswith("ssi-elevenid@") and
           _git_dir(Path(result[key]["gitDirectory"]), "ls-tree", result[key]["revision"],
                    "crates/rdf/canonicalization")]
    if len(ssi) != 1:
        raise ValueError("NATIVE_CACHE_RDF_GITLINK_SCOPE_CHANGED")
    parent = result[ssi[0]]
    parent_dir = Path(parent["gitDirectory"])
    gitlink = _git_dir(parent_dir, "ls-tree", parent["revision"],
                       "crates/rdf/canonicalization").decode().split()
    if (len(gitlink) != 4 or gitlink[0] != "160000" or gitlink[1] != "commit"
            or gitlink[3] != "crates/rdf/canonicalization"
            or b"url = https://github.com/w3c-ccg/rdf-dataset-canonicalization"
                not in _git_dir(parent_dir, "show", parent["revision"] + ":.gitmodules")):
        raise ValueError("NATIVE_CACHE_RDF_GITLINK_CHANGED")
    rdf_row = sources["rdfGitlink"]
    if set(rdf_row) != {"gitDirectory", "cargoDbName"}:
        raise ValueError("NATIVE_CACHE_RDF_OBJECT_SOURCE_CHANGED")
    rdf_dir = Path(rdf_row["gitDirectory"])
    if (not rdf_dir.is_absolute() or not rdf_dir.is_dir() or rdf_dir.is_symlink()
            or rdf_dir.is_junction()
            or not re.fullmatch(r"rdf-dataset-canonicalization-[0-9a-f]{16}",
                                rdf_row["cargoDbName"])
            or _git_dir(rdf_dir, "rev-parse", "--is-bare-repository") != b"true"
            or _git_dir(rdf_dir, "cat-file", "-t", gitlink[2]) != b"commit"):
        raise ValueError("NATIVE_CACHE_RDF_OBJECT_MISSING")
    result["rdfGitlink"] = {"gitDirectory": str(rdf_dir.resolve()),
                            "cargoDbName": rdf_row["cargoDbName"],
                            "revision": gitlink[2],
                            "tree": _git_dir(rdf_dir, "rev-parse", gitlink[2] + "^{tree}").decode(),
                            "bare": True,
                            "parentSource": ssi[0]}
    return result


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
    local_objects = plan.get("localObjects")
    if local_objects is not None:
        if (receipt.get("cacheMode") != "LOCAL_OFFLINE_OBJECTS"
                or receipt.get("localObjects") != local_objects):
            raise ValueError("NATIVE_CACHE_LOCAL_OBJECT_RECEIPT_CHANGED")
        registry = receipt.get("registryArchiveProof", {})
        archives = registry_archives(original_lock)
        if (registry.get("state") != "EXACT_LOCK_REGISTRY_ARCHIVES_READBACK"
                or registry.get("count") != len(archives)
                or registry.get("archiveSetSha256") != registry_set_sha256(archives)
                or registry.get("originalLockSha256") != digest
                or type(registry.get("copied")) is not int
                or type(registry.get("reused")) is not int
                or registry["copied"] < 0 or registry["reused"] < 0
                or registry["copied"] + registry["reused"] != len(archives)):
            raise ValueError("NATIVE_CACHE_REGISTRY_RECEIPT_CHANGED")
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
    if plan.get("localObjects") is not None:
        registry_ref = receipt.get("registryArchiveProofRef", {})
        registry_path = Path(registry_ref.get("path", "")).resolve()
        if (not registry_path.is_relative_to(receipt_path.parent.resolve())
                or not registry_path.is_file() or registry_path.is_symlink()
                or registry_path.stat().st_size > 1024 * 1024
                or registry_ref.get("sha256") != hashlib.sha256(registry_path.read_bytes()).hexdigest()
                or json.loads(registry_path.read_bytes()) != receipt.get("registryArchiveProof")):
            raise ValueError("NATIVE_CACHE_REGISTRY_PROOF_CHANGED")
    validate_receipt(plan, receipt, lock_path.read_bytes(), metadata_path.read_bytes(), checkout_path.read_bytes())


def cache_budget(local_mode: bool) -> dict:
    """Bound the sequential local-object import separately from networked fetch."""
    if local_mode:
        return {"memoryArg": "1g", "swapArg": "2g",
                "memoryBytes": 1024 ** 3, "swapBytes": 2 * 1024 ** 3,
                "hostFloorKiB": 1024 * 1024 + 64 * 1024}
    return {"memoryArg": "2g", "swapArg": "4g",
            "memoryBytes": 2 * 1024 ** 3, "swapBytes": 4 * 1024 ** 3,
            "hostFloorKiB": 2 * 1024 * 1024 + 64 * 1024}


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
    local_objects = plan.get("localObjects")
    budget = cache_budget(local_objects is not None)
    registry_root = None
    registry_expected = None
    if local_objects is not None:
        require(plan.get("cacheMode") == "LOCAL_OFFLINE_OBJECTS"
                and verified_local_objects(lock.read_bytes(), plan["localObjectSources"]) == local_objects,
                "NATIVE_CACHE_LOCAL_SOURCE_CHANGED")
        registry_root = (Path.home() / ".cargo/registry/cache" / REGISTRY_CACHE).resolve(strict=True)
        if registry_root != Path.home() / ".cargo/registry/cache" / REGISTRY_CACHE:
            raise ValueError("NATIVE_CACHE_REGISTRY_HOST_ROOT_CHANGED")
        registry_expected = verified_registry_seed(lock.read_bytes(), registry_root)
    require("marty-core@" + plan["sources"]["core"]["revision"] in expected_sources,
            "NATIVE_CACHE_FROZEN_CORE_LOCK_CHANGED")
    script = Path(plan["cacheScript"]["path"]).resolve(strict=True)
    guard = Path(plan["cacheGuard"]["path"]).resolve(strict=True)
    require(sha(script) == plan["cacheScript"]["sha256"]
            and script.read_bytes() == render_fetch_script(digest, expected_sources, local_objects)
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
    require(host_kib >= budget["hostFloorKiB"]
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
    if registry_expected is not None:
        intent["registryArchiveSetSha256"] = registry_set_sha256(registry_expected)
        intent["registryArchiveCount"] = len(registry_expected)
    proof = journal.exclusive("build-apply-intent.json", intent)
    require(durable_barrier(proof), "NATIVE_CACHE_DURABLE_INTENT_REQUIRED")
    local_mounts = []
    if local_objects is not None:
        for key in sorted(local_objects):
            source_row = local_objects[key]
            mount_name = source_row["cargoDbName"]
            if mount_name not in {row["name"] for row in local_mounts}:
                local_mounts.append({"name": mount_name, "path": source_row["gitDirectory"]})
    args = ["docker", "--context", "desktop-linux", "create", "--pull=never", "--name", name,
            "--label", "elevenid.owner=native-cargo-cache", "--label", "elevenid.run=" + run_id,
            "--network", "none" if local_objects is not None else "bridge",
            "--memory", budget["memoryArg"], "--memory-swap", budget["swapArg"], "--cpus", "1",
            "--pids-limit", "64", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--mount", "type=bind,src=" + daemon_source(source) + ",dst=/src/ui,readonly",
            "--mount", "type=bind,src=" + daemon_source(output) + ",dst=/out",
            "--mount", "type=bind,src=" + daemon_source(script) + ",dst=/fetch.sh,readonly",
            "--mount", "type=bind,src=" + daemon_source(guard) + ",dst=/build/cache_guard.py,readonly",
            "--mount", "type=volume,src=ui-canvas-cargo,dst=/cargo",
            *(["--mount", "type=bind,src=" + daemon_source(registry_root)
               + ",dst=/seed/registry,readonly"] if registry_root is not None else []),
            *[arg for source_row in local_mounts for arg in
              ("--mount", "type=bind,src=" + daemon_source(source_row["path"])
               + ",dst=/seed/" + source_row["name"] + ",readonly")],
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
            and host["NetworkMode"] == ("none" if local_objects is not None else "bridge")
            and host["Memory"] == budget["memoryBytes"]
            and host["MemorySwap"] == budget["swapBytes"] and host["PidsLimit"] == 64
            and host["NanoCpus"] == 10 ** 9
            and host["Privileged"] is False and "ALL" in host["CapDrop"]
            and len(row["Mounts"]) == len(mounts) == 5 + len(local_mounts) + (1 if registry_root else 0)
            and set(mounts) == {"/src/ui", "/out", "/fetch.sh", "/build/cache_guard.py", "/cargo"}
                | {"/seed/" + source_row["name"] for source_row in local_mounts}
                | ({"/seed/registry"} if registry_root else set())
            and mounts["/src/ui"]["RW"] is False and mounts["/fetch.sh"]["RW"] is False
            and mounts["/build/cache_guard.py"]["RW"] is False
            and mounts["/out"]["RW"] is True and mounts["/cargo"]["RW"] is True
            and mounts["/cargo"]["Name"] == "ui-canvas-cargo"
            and daemon_source(mounts["/src/ui"]["Source"]) == daemon_source(source)
            and daemon_source(mounts["/out"]["Source"]) == daemon_source(output)
            and daemon_source(mounts["/fetch.sh"]["Source"]) == daemon_source(script)
            and daemon_source(mounts["/build/cache_guard.py"]["Source"]) == daemon_source(guard),
            "NATIVE_CACHE_CREATED_IDENTITY_CHANGED")
    for source_row in local_mounts:
        mount = mounts["/seed/" + source_row["name"]]
        require(mount["Type"] == "bind" and mount["RW"] is False
                and daemon_source(mount["Source"]) == daemon_source(source_row["path"]),
                "NATIVE_CACHE_LOCAL_MOUNT_CHANGED")
    if registry_root is not None:
        registry_mount = mounts["/seed/registry"]
        require(registry_mount["Type"] == "bind" and registry_mount["RW"] is False
                and daemon_source(registry_mount["Source"]) == daemon_source(registry_root),
                "NATIVE_CACHE_REGISTRY_MOUNT_CHANGED")
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
    registry_proof = None
    if registry_expected is not None:
        registry_proof = json.loads((output / "registry-proof.json").read_bytes())
        require(registry_proof == {"state": "EXACT_LOCK_REGISTRY_ARCHIVES_READBACK",
                "count": len(registry_expected), "copied": registry_proof.get("copied"),
                "reused": registry_proof.get("reused"),
                "archiveSetSha256": registry_set_sha256(registry_expected),
                "originalLockSha256": digest}
                and type(registry_proof["copied"]) is int and type(registry_proof["reused"]) is int
                and registry_proof["copied"] >= 0 and registry_proof["reused"] >= 0
                and registry_proof["copied"] + registry_proof["reused"] == len(registry_expected),
                "NATIVE_CACHE_REGISTRY_READBACK_CHANGED_RETAIN_HELPER")
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
    if local_objects is not None:
        receipt["cacheMode"] = "LOCAL_OFFLINE_OBJECTS"
        receipt["localObjects"] = local_objects
        receipt["registryArchiveProof"] = registry_proof
        receipt["registryArchiveProofRef"] = ref(output / "registry-proof.json")
    journal.exclusive("build-receipt.json", receipt)
    return receipt


def main() -> None:
    if len(sys.argv) == 6 and sys.argv[1] == "import-registry":
        if sys.argv[2:] != ["/src/ui/rust/Cargo.lock", "/seed/registry",
                            "/cargo/registry/cache/" + REGISTRY_CACHE,
                            "/out/registry-proof.json"]:
            raise ValueError("NATIVE_CACHE_REGISTRY_IMPORT_SCOPE_CHANGED")
        import_registry_archives(Path(sys.argv[2]).read_bytes(), Path(sys.argv[3]),
                                 Path(sys.argv[4]), Path(sys.argv[5]))
        return
    if len(sys.argv) == 5 and sys.argv[1] == "verify-one-checkout":
        revision = sys.argv[3]
        if not re.fullmatch(r"[a-f0-9]{40}", revision):
            raise ValueError("NATIVE_CACHE_EXACT_CHECKOUT_REVISION_REQUIRED")
        proof = _clean_checkout(Path(sys.argv[2]), revision)
        with Path(sys.argv[4]).open("x", encoding="utf-8") as stream:
            json.dump(proof, stream, sort_keys=True)
            stream.write("\n")
        return
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
