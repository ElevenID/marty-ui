#!/usr/bin/env python3
"""Future-only immutable candidate admission across protected-main advances.

This module grants no write or publication authority. Callers must authenticate
the original candidate, the actual executable workflow source and fresh protected
main independently. Unqualified/failed runs never become eligible through this
history check. Old sources without the exact policy marker are refused.
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import subprocess
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[0-9a-f]{40}\Z")
POLICY_PATH = "release/source-authority-policy.json"
POLICY = {"schema": "marty.immutable-source-authority/v1",
          "repository": "ElevenID/marty-ui",
          "scope": "release-program-and-policy/v1",
          "history_limit": 128}
# Include transitive local Python imports, workflow/action/verifier pins and all
# policy definitions. The candidate's own stack lock remains independently bound
# by the original claim, CI, signed transaction and publication checkpoint.
PATHS = (".github", "scripts", "release", ".gitattributes",
         "requirements-proto.txt", "requirements-services.txt",
         ".cargo", "rust/.cargo", "rust-toolchain", "rust-toolchain.toml",
         "rust/rust-toolchain", "rust/rust-toolchain.toml", "Cargo.toml", "Cargo.lock",
         "rust/Cargo.toml", "rust/Cargo.lock", "rust/crates/release-evidence",
         "rust/crates/oid4vp-contract")
EXCLUDED = frozenset({"release/stack-lock.json"})
MAX_FILES = 4096
MAX_BYTES = 24 * 1024 * 1024


class SourceAuthorityError(ValueError):
    """The candidate or executable is not covered by unchanged release policy."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceAuthorityError(message)


class History:
    def __init__(self, repository: Path, timeout_seconds: float) -> None:
        require(type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds)
                and 0 < timeout_seconds <= 60, "source history deadline is invalid")
        self.root = repository
        self.deadline = time.monotonic() + timeout_seconds
        self.environment = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ}
        self.environment.update(GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1",
                                GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, LANG="C")

    def git(self, *arguments: str) -> bytes:
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "source history deadline expired")
        try:
            result = subprocess.run(
                ["git", "--no-replace-objects", "-c", "protocol.allow=never", "-c", "core.fsmonitor=false",
                 "-c", f"core.hooksPath={os.devnull}", *arguments], cwd=self.root,
                env=self.environment, capture_output=True, check=False, timeout=remaining)
        except (OSError, subprocess.SubprocessError) as error:
            raise SourceAuthorityError("source history could not be verified") from error
        require(result.returncode == 0 and len(result.stdout) <= MAX_BYTES,
                "source history is unavailable or exceeds its bound")
        return result.stdout

    def inventory(self, source: str) -> dict[str, tuple[str, str, int]]:
        raw = self.git("ls-tree", "-r", "-l", "-z", "--full-tree", source, "--", *PATHS)
        rows = {}
        total = 0
        for row in raw.split(b"\0"):
            if not row:
                continue
            try:
                metadata, name_raw = row.split(b"\t", 1)
                name = name_raw.decode("ascii")
                mode, kind, oid, size_raw = metadata.split()
                size = int(size_raw)
            except (ValueError, UnicodeError) as error:
                raise SourceAuthorityError("source policy inventory is malformed") from error
            require(name not in rows and not name.startswith("/") and "\\" not in name
                    and all(part not in {"", ".", ".."} for part in name.split("/"))
                    and all(32 <= ord(character) < 127 for character in name)
                    and mode in {b"100644", b"100755"} and kind == b"blob"
                    and SHA.fullmatch(oid.decode("ascii")) is not None
                    and 0 <= size <= 1024 * 1024, "source policy entry is unsafe")
            total += size
            if name in EXCLUDED:
                continue
            rows[name] = (mode.decode("ascii"), oid.decode("ascii"), size)
        require(POLICY_PATH in rows and len(rows) <= MAX_FILES and total <= MAX_BYTES // 2,
                "source policy is absent or exceeds its bound")
        return rows

    def fingerprint(self, source: str, inventory: dict[str, tuple[str, str, int]]) -> str:
        # No extraction. Validate every archive member against Git's ordinary
        # blob inventory, including export-ignore/subst attribute interference.
        paths = [path for path in PATHS if any(name == path or name.startswith(path + "/")
                                              for name in inventory)]
        archive = self.git("archive", "--format=tar", source, "--", *paths)
        observed = {}
        try:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
                for member in stream:
                    if member.isdir() or member.name in EXCLUDED:
                        continue
                    require(member.isfile() and member.name in inventory and member.name not in observed,
                            "source archive differs from policy inventory")
                    mode, oid, size = inventory[member.name]
                    require(member.size == size and (member.mode & 0o111 != 0) == (mode == "100755"),
                            "source archive mode or length differs")
                    reader = stream.extractfile(member)
                    require(reader is not None, "source archive blob is absent")
                    data = reader.read(size + 1)
                    require(len(data) == size and hashlib.sha1(
                        f"blob {size}\0".encode("ascii") + data).hexdigest() == oid,
                        "source archive blob differs from Git")
                    if member.name == POLICY_PATH:
                        require(data == policy_bytes(), "candidate uses an unsupported source policy")
                    observed[member.name] = [mode, size, hashlib.sha256(data).hexdigest()]
        except (tarfile.TarError, OSError) as error:
            raise SourceAuthorityError("source archive could not be verified") from error
        require(set(observed) == set(inventory), "source archive omits release policy inputs")
        return "sha256:" + hashlib.sha256(json.dumps(
            observed, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


def policy_bytes() -> bytes:
    return (json.dumps(POLICY, indent=2) + "\n").encode("ascii")


def require_compatible_source(source: str, executable: str, protected_main: str, *,
                              repository: Path = ROOT, timeout_seconds: float = 30) -> str:
    """Bind immutable S and actual executable O/P to fresh authenticated M.

    Every intervening commit must preserve the complete release-program scope;
    policy revocation followed by restoration cannot revive an old candidate.
    This does not authenticate a GitHub run, approve a release or waive CI.
    """
    require(all(type(value) is str and SHA.fullmatch(value)
                for value in (source, executable, protected_main)), "source identity is malformed")
    history = History(repository, timeout_seconds)
    require(history.git("rev-parse", "--is-shallow-repository").strip() == b"false",
            "source history must be complete")
    require(not history.git("for-each-ref", "--format=%(refname)", "refs/replace").strip(),
            "source history cannot contain replace refs")
    grafts = Path(os.fsdecode(history.git("rev-parse", "--git-path", "info/grafts").strip()))
    if not grafts.is_absolute():
        grafts = repository / grafts
    require(not grafts.exists(), "source history cannot contain grafts")
    for commit in {source, executable, protected_main}:
        require(history.git("cat-file", "-t", commit).strip() == b"commit", "source must be a commit")
    for ancestor in {source, executable}:
        history.git("merge-base", "--is-ancestor", ancestor, protected_main)
    history.git("merge-base", "--is-ancestor", source, executable)
    expected = history.inventory(source)
    fingerprint = history.fingerprint(source, expected)
    commits = history.git("rev-list", f"--max-count={POLICY['history_limit'] + 1}",
                          f"{source}..{protected_main}").splitlines()
    require(len(commits) <= POLICY["history_limit"], "source history exceeds its complete bound")
    for commit in {executable, protected_main, *(row.decode("ascii") for row in commits)}:
        require(SHA.fullmatch(commit) is not None and history.inventory(commit) == expected,
                "release program or policy changed after candidate admission")
    return fingerprint
