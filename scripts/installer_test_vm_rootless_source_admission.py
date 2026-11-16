"""Check a root-owned flat Python controller namespace against an exact Git tree.

This is a pre-import check. It does not fetch, stage, or authenticate the
reviewer's selected commit. A root-private bootstrap must call it under
``python -I -S -B`` before adding the checked directory to ``sys.path``.
Only the complete tracked top-level scripts/*.py namespace is admitted. Nested
packages and runtime asset subtrees require separate authenticated staging and
are refused as extra entries in this flat directory. This check does not
authenticate the bootstrap/verifier itself or grant live execution authority.
No VM, SSH, package, or Docker operation is performed here.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

HEX = re.compile(r"[0-9a-f]{40}\Z")
NAME = re.compile(r"[a-zA-Z_][a-zA-Z_0-9-]*\.py\Z")
MAX_MODULES = 512
MAX_MODULE_BYTES = 1024 * 1024
MAX_TREE_BYTES = 128 * 1024


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("controller source admission refused")


def _private_ancestry(path: Path) -> None:
    _require(path.is_absolute())
    current = path
    while True:
        info = current.lstat()
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                 and info.st_gid == 0 and not info.st_mode & 0o022)
        if current == current.parent:
            return
        current = current.parent


def _git(git_dir: Path, *args: str, limit: int) -> bytes:
    # The bare object database is admitted by root custody, not by Git config.
    process = subprocess.Popen(
        ["/usr/bin/git", "--no-pager", "--git-dir", str(git_dir), *args],
        cwd="/", env={"PATH": "/usr/bin", "HOME": "/nonexistent",
                      "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                      "LC_ALL": "C"}, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + 15
    try:
        with selectors.DefaultSelector() as selector:
            for pipe in (process.stdout, process.stderr):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                _require(time.monotonic() < deadline)
                for key, _ in selector.select(0.1):
                    part = os.read(key.fileobj.fileno(), 8192)
                    if not part:
                        selector.unregister(key.fileobj)
                    elif key.fileobj is process.stdout:
                        output.extend(part)
                        _require(len(output) <= limit)
                    else:
                        _require(len(part) <= 8192)
            while os.waitid(os.P_PID, process.pid,
                            os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                _require(time.monotonic() < deadline)
                time.sleep(0.01)
            os.killpg(process.pid, signal.SIGKILL)
            _require(process.wait() == 0)
        return bytes(output)
    except BaseException:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        raise
    finally:
        process.stdout.close()
        process.stderr.close()


def _bytes(path: Path) -> bytes:
    # O_PATH classification happens before a read-capable procfd reopen.
    fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        initial = os.fstat(fd)
        _require(stat.S_ISREG(initial.st_mode) and initial.st_uid == 0
                 and initial.st_gid == 0 and initial.st_nlink == 1
                 and not initial.st_mode & 0o022
                 and 0 < initial.st_size <= MAX_MODULE_BYTES)
        stamp = lambda row: (row.st_dev, row.st_ino, row.st_uid, row.st_gid,
                             row.st_mode, row.st_nlink, row.st_size,
                             row.st_mtime_ns, row.st_ctime_ns)
        read_fd = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY | os.O_CLOEXEC)
        try:
            _require(stamp(os.fstat(read_fd)) == stamp(initial))
            chunks = []
            remaining = initial.st_size
            while remaining:
                part = os.read(read_fd, min(65536, remaining))
                _require(bool(part))
                chunks.append(part)
                remaining -= len(part)
            _require(os.read(read_fd, 1) == b"")
            current = path.lstat()
            _require(stamp(os.fstat(read_fd)) == stamp(initial)
                     and stamp(current) == stamp(initial))
            return b"".join(chunks)
        finally:
            os.close(read_fd)
    finally:
        os.close(fd)


def _flat_controller_blobs(raw: bytes) -> dict[str, str]:
    """Parse the complete direct Git directory, never a recursive tree listing.

    Every admitted module must exist as exactly one regular file in source_dir.
    A nested package cannot be silently copied into or imported from that flat
    namespace. This does not admit main's separate rootless asset subtree.
    """
    _require(type(raw) is bytes and len(raw) <= MAX_TREE_BYTES)
    tracked: dict[str, str] = {}
    for row in raw.split(b"\0"):
        if not row:
            continue
        left, sep, path = row.partition(b"\t")
        _require(bool(sep) and b"/" not in path)
        if not path.endswith(b".py"):
            continue
        fields = left.split(b" ")
        _require(len(fields) == 3)
        mode, kind, blob = fields
        try:
            name = path.decode("ascii")
            object_id = blob.decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("controller source admission refused") from None
        _require(mode in (b"100644", b"100755") and kind == b"blob"
                 and NAME.fullmatch(name) is not None and name not in tracked
                 and HEX.fullmatch(object_id) is not None and object_id != "0" * 40)
        tracked[name] = object_id
        _require(len(tracked) <= MAX_MODULES)
    _require(bool(tracked))
    return tracked


def admit(*, git_dir: Path, commit: str, source_dir: Path) -> dict[str, str]:
    """Return exact local Python blob digests only after whole closure matches.

    The caller must independently select an approved exact commit and retain
    this root-owned bare Git object store. Returned hashes are private process
    data, not guest/package execution authority.
    """
    _require(os.geteuid() == 0 and type(commit) is str
             and HEX.fullmatch(commit) is not None)
    _private_ancestry(git_dir)
    _private_ancestry(source_dir)
    _require(stat.S_IMODE(source_dir.lstat().st_mode) == 0o700)
    _require(_git(git_dir, "rev-parse", "--verify", commit + "^{commit}",
                  limit=128).strip() == commit.encode("ascii"))
    # The admitted import namespace is flat: top-level scripts/*.py only.
    # Nested packages and assets are not staged or importable from this closure.
    # Their support requires a separately authenticated recursive layout.
    raw = _git(git_dir, "ls-tree", "-z", commit + ":scripts",
               limit=MAX_TREE_BYTES)
    tracked = _flat_controller_blobs(raw)
    observed: set[str] = set()
    with os.scandir(source_dir) as entries:
        for entry in entries:
            _require(entry.name in tracked and entry.name not in observed)
            observed.add(entry.name)
            _require(len(observed) <= MAX_MODULES)
    _require(observed == set(tracked))
    result = {}
    for name, blob in tracked.items():
        actual = _bytes(source_dir / name)
        expected = _git(git_dir, "cat-file", "blob", blob,
                        limit=MAX_MODULE_BYTES + 1)
        _require(actual == expected)
        result[name] = hashlib.sha256(actual).hexdigest()
    return result
