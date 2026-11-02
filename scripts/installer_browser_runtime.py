"""Admit or locally install the exact isolated installer browser runtime.

No download, npm command, lifecycle script or browser launch occurs here. The
signed harness carries the policy and its full manifest; a runtime-supplied
descriptor cannot add files or authorize a different executable.
"""
from __future__ import annotations

import argparse
import ast
from collections.abc import Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys
import tarfile
from types import MappingProxyType
import zipfile


REFUSED = "Pinned browser runtime refused; preserve existing files and use the reviewed local archives"
POLICY_SCHEMA = "elevenid.installer-browser-runtime-policy/v1"
MANIFEST_SCHEMA = "elevenid.installer-browser-runtime-manifest/v1"
IDENTITY_SCHEMA = "elevenid.installer-browser-runtime/v1"
POLICY_PATH = Path(__file__).absolute().with_name("installer_browser_runtime_policy.py")
MANIFEST_PATH = POLICY_PATH.with_name("installer_browser_runtime_manifest.json")
MAX_MANIFEST_BYTES = 256 * 1024
MAX_FILES = 2048
MAX_DIRECTORIES = 512
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TREE_BYTES = 2 * MAX_FILE_BYTES
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 50000
EXECUTABLES = {"node": "node/bin/node", "chromium": "chrome-linux64/chrome",
               "playwright": "playwright-core"}
ARCHIVES = ("node", "playwright", "chromium")
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_DIRECTORY = _READ | os.O_DIRECTORY


def _require(value: bool) -> None:
    if not value:
        raise ValueError(REFUSED)


def _sha(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _relative(value: object) -> str:
    _require(type(value) is str and 0 < len(value) <= 1024 and "\\" not in value
             and all(ord(char) >= 32 and ord(char) != 127 for char in value))
    parts = value.split("/")
    _require(all(part and part not in (".", "..") for part in parts)
             and not PurePosixPath(value).is_absolute())
    return value


def _absolute(value: Path) -> Path:
    _require(isinstance(value, Path) and value.is_absolute() and value != Path("/")
             and ".." not in value.parts and "\\" not in str(value)
             and all(ord(char) >= 32 and ord(char) != 127 for char in str(value)))
    return value


def _decode(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for name, value in items:
            _require(name not in result)
            result[name] = value
        return result
    _require(0 < len(raw) <= MAX_MANIFEST_BYTES)
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError(REFUSED)))
    _require(type(value) is dict)
    return value


def _signature(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_identity(info: os.stat_result) -> tuple:
    # Ancestors may acquire unrelated children. Their path, owner and access
    # bits are pinned; the admitted runtime's own directories use full stamps.
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def _operator_uid() -> int:
    uid = os.geteuid()
    _require(sys.platform == "linux" and platform.machine() in ("x86_64", "amd64")
             and uid > 0 and os.getuid() == uid and os.getgid() == os.getegid())
    return uid


def _keep(stack: ExitStack, descriptor: int) -> int:
    stack.callback(os.close, descriptor)
    return descriptor


@dataclass(frozen=True)
class _Anchor:
    path: Path
    descriptor: int
    # Every absolute ancestor is opened without following symlinks and kept.
    links: tuple[tuple[int, str, int, tuple], ...]

    def check(self) -> None:
        for parent, name, held, expected in self.links:
            _require(_directory_identity(os.fstat(held)) == expected
                     and _directory_identity(os.stat(name, dir_fd=parent,
                                                     follow_symlinks=False)) == expected)


def _anchor(path: Path, stack: ExitStack, uid: int) -> _Anchor:
    _absolute(path)
    current = _keep(stack, os.open("/", _DIRECTORY))
    links = []
    for name in path.parts[1:]:
        child = _keep(stack, os.open(name, _DIRECTORY, dir_fd=current))
        info = os.fstat(child)
        # Root-owned sticky /tmp ancestors are allowed. The runtime root and
        # every entry below it are separately required to be private and owned.
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, uid)
                 and not info.st_mode & (stat.S_ISUID | stat.S_ISGID)
                 and (not info.st_mode & 0o022
                      or (info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX))))
        expected = _directory_identity(info)
        _require(_directory_identity(os.stat(name, dir_fd=current,
                                             follow_symlinks=False)) == expected)
        links.append((current, name, child, expected))
        current = child
    result = _Anchor(path, current, tuple(links))
    result.check()
    return result


def _hash_file(descriptor: int, expected_size: int) -> str:
    before = os.fstat(descriptor)
    _require(before.st_size == expected_size and stat.S_ISREG(before.st_mode))
    value = hashlib.sha256()
    position = 0
    while position < expected_size:
        block = os.pread(descriptor, min(1024 * 1024, expected_size - position), position)
        _require(bool(block))
        value.update(block)
        position += len(block)
    _require(os.pread(descriptor, 1, position) == b""
             and _signature(os.fstat(descriptor)) == _signature(before))
    return value.hexdigest()


@dataclass(frozen=True)
class _Policy:
    archives: Mapping
    directories: tuple[str, ...]
    files: Mapping
    identity: Mapping


def _policy_from(value: dict, manifest: bytes, manifest_sha256: str) -> _Policy:
    """Internal parser; production callers cannot supply their own policy."""
    _require(type(value) is dict and set(value) == {"schema", "platform", "versions", "archives", "executables"}
             and value["schema"] == POLICY_SCHEMA and value["platform"] == "linux-x64"
             and value["executables"] == EXECUTABLES
             and _sha(manifest_sha256) and hashlib.sha256(manifest).hexdigest() == manifest_sha256)
    versions = value["versions"]
    _require(type(versions) is dict and set(versions) == {"node", "playwright", "chromium", "chromium_revision"})
    for name, version in versions.items():
        pattern = r"[1-9][0-9]*" if name == "chromium_revision" else r"[0-9]+(?:\.[0-9]+){2,3}"
        _require(type(version) is str and re.fullmatch(pattern, version) is not None)
    raw_archives = value["archives"]
    _require(type(raw_archives) is dict and set(raw_archives) == set(ARCHIVES))
    archives = {}
    for name in ARCHIVES:
        item = raw_archives[name]
        _require(type(item) is dict and set(item) == {"name", "format", "sha256", "size", "prefix", "destination", "url", "members"})
        _require(item["format"] == {"node": "tar.xz", "playwright": "tar.gz", "chromium": "zip"}[name]
                 and _sha(item["sha256"]) and type(item["size"]) is int and 0 < item["size"] <= MAX_ARCHIVE_BYTES
                 and type(item["prefix"]) is str and item["prefix"].endswith("/")
                 and type(item["url"]) is str and item["url"].startswith("https://"))
        _relative(item["name"])
        _require("/" not in item["name"])
        _relative(item["prefix"][:-1])
        _relative(item["destination"])
        _require(item["destination"] == {"node": "node", "playwright": "playwright-core", "chromium": "chrome-linux64"}[name])
        _require(item["members"] == (["bin/node", "LICENSE"] if name == "node" else None))
        archives[name] = MappingProxyType(dict(item, members=tuple(item["members"]) if item["members"] else None))
    decoded = _decode(manifest)
    _require(set(decoded) == {"schema", "directories", "files"} and decoded["schema"] == MANIFEST_SCHEMA)
    directories = decoded["directories"]
    files = decoded["files"]
    _require(type(directories) is list and 0 < len(directories) <= MAX_DIRECTORIES
             and all(type(path) is str for path in directories) and directories == sorted(set(directories))
             and type(files) is dict and 0 < len(files) <= MAX_FILES)
    for path in directories:
        _relative(path)
    directory_set = set(directories)
    parsed_files = {}
    for path, item in files.items():
        _relative(path)
        _require(path not in directory_set and type(item) is dict and set(item) == {"sha256", "size", "mode"}
                 and _sha(item["sha256"]) and type(item["size"]) is int and 0 <= item["size"] <= MAX_FILE_BYTES
                 and type(item["mode"]) is int and item["mode"] in (0o444, 0o555))
        parsed_files[path] = MappingProxyType(dict(item))
    for path in list(directories) + list(files):
        parent = PurePosixPath(path).parent
        _require(str(parent) == "." or str(parent) in directory_set)
        _require(path.split("/", 1)[0] in {"node", "playwright-core", "chrome-linux64"})
    _require(set(path for path in files if path.startswith("node/")) == {"node/bin/node", "node/LICENSE"}
             and all(path in files and files[path]["mode"] == 0o555 and files[path]["size"] > 0
                     for path in (EXECUTABLES["node"], EXECUTABLES["chromium"]))
             and "playwright-core/package.json" in files
             and sum(item["size"] for item in files.values()) <= MAX_TREE_BYTES)
    identity = MappingProxyType(dict(schema=IDENTITY_SCHEMA, platform="linux/amd64",
        node_version=versions["node"], playwright_version=versions["playwright"],
        chromium_version=versions["chromium"], chromium_revision=versions["chromium_revision"],
        manifest_sha256=manifest_sha256, node_sha256=files[EXECUTABLES["node"]]["sha256"],
        chromium_sha256=files[EXECUTABLES["chromium"]]["sha256"]))
    return _Policy(MappingProxyType(archives), tuple(directories), MappingProxyType(parsed_files), identity)


def _static_bytes(path: Path, maximum: int) -> bytes:
    # These fixed files belong to the authenticated harness source closure;
    # this reader additionally binds the opened regular file to its pathname.
    # Runtime installation roots use the stricter full ancestor admission.
    descriptor = os.open(path, _READ)
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022
                 and info.st_uid in (0, os.geteuid()) and 0 < info.st_size <= maximum)
        raw = os.pread(descriptor, info.st_size + 1, 0)
        _require(len(raw) == info.st_size and _signature(info) == _signature(os.fstat(descriptor))
                 and _signature(info) == _signature(path.lstat()))
        return raw
    finally:
        os.close(descriptor)


def _load_policy() -> _Policy:
    # Do not import the policy: Python's module/bytecode caches are outside the
    # signed source closure. This fixed source permits two literal assignments
    # and an optional docstring, never imports, calls or executable statements.
    try:
        statements = ast.parse(_static_bytes(POLICY_PATH, 32 * 1024)).body
    except SyntaxError as error:
        raise ValueError(REFUSED) from error
    if statements and isinstance(statements[0], ast.Expr) and isinstance(statements[0].value, ast.Constant) \
            and type(statements[0].value.value) is str:
        statements = statements[1:]
    values = {}
    for statement in statements:
        _require(isinstance(statement, ast.Assign) and len(statement.targets) == 1
                 and isinstance(statement.targets[0], ast.Name))
        name = statement.targets[0].id
        _require(name in {"POLICY", "MANIFEST_SHA256"} and name not in values)
        values[name] = ast.literal_eval(statement.value)
    _require(set(values) == {"POLICY", "MANIFEST_SHA256"})
    return _policy_from(values["POLICY"], _static_bytes(MANIFEST_PATH, MAX_MANIFEST_BYTES),
                        values["MANIFEST_SHA256"])


def validate_identity(value: object) -> dict[str, str]:
    """Validate public observation data against the harness's exact policy."""
    expected = _load_policy().identity
    _require(isinstance(value, Mapping) and set(value) == set(expected)
             and all(type(value[name]) is str and value[name] == text for name, text in expected.items()))
    return dict(expected)


@dataclass(frozen=True)
class _Held:
    descriptor: int
    signature: tuple


class Runtime:
    """Live context: paths are useful only while all retained FDs stay open."""
    def __init__(self, anchor: _Anchor, policy: _Policy, uid: int,
                 directories: dict[str, _Held], files: dict[str, _Held]):
        self._anchor, self._policy, self._uid = anchor, policy, uid
        self._directories, self._files = directories, files
        self._process_identity = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
        self._closed = False

    @property
    def node(self) -> Path:
        return self._anchor.path / EXECUTABLES["node"]

    @property
    def chromium(self) -> Path:
        return self._anchor.path / EXECUTABLES["chromium"]

    @property
    def playwright(self) -> Path:
        return self._anchor.path / EXECUTABLES["playwright"]

    @property
    def identity(self) -> Mapping:
        return self._policy.identity

    def check(self) -> None:
        _require(not self._closed and os.geteuid() == self._uid
                 and (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) == self._process_identity)
        self._anchor.check()
        expected_children = {name: set() for name in self._directories}
        for name in list(self._policy.directories) + list(self._policy.files):
            parent = str(PurePosixPath(name).parent)
            expected_children["" if parent == "." else parent].add(PurePosixPath(name).name)
        for name, held in self._directories.items():
            _require(_signature(os.fstat(held.descriptor)) == held.signature
                     and set(os.listdir(held.descriptor)) == expected_children[name])
            if name:
                self._named(name, held)
        for name, held in self._files.items():
            self._named(name, held)
            spec = self._policy.files[name]
            _require(_hash_file(held.descriptor, spec["size"]) == spec["sha256"])
            self._named(name, held)
        for name, held in self._directories.items():
            _require(_signature(os.fstat(held.descriptor)) == held.signature
                     and set(os.listdir(held.descriptor)) == expected_children[name])
            if name:
                self._named(name, held)
        self._anchor.check()

    def _named(self, name: str, held: _Held) -> None:
        path = PurePosixPath(name)
        parent = str(path.parent)
        directory = self._directories["" if parent == "." else parent].descriptor
        _require(_signature(os.fstat(held.descriptor)) == held.signature
                 and _signature(os.stat(path.name, dir_fd=directory, follow_symlinks=False)) == held.signature)


@contextmanager
def _admit(root: Path, policy: _Policy, uid: int):
    with ExitStack() as stack:
        anchor = _anchor(root, stack, uid)
        info = os.fstat(anchor.descriptor)
        _require(info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700)
        directories = {"": _Held(anchor.descriptor, _signature(info))}
        for name in policy.directories:
            path = PurePosixPath(name)
            parent = str(path.parent)
            descriptor = _keep(stack, os.open(path.name, _DIRECTORY,
                dir_fd=directories["" if parent == "." else parent].descriptor))
            info = os.fstat(descriptor)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700)
            directories[name] = _Held(descriptor, _signature(info))
        files = {}
        for name, spec in policy.files.items():
            path = PurePosixPath(name)
            descriptor = _keep(stack, os.open(path.name, _READ, dir_fd=directories[str(path.parent)].descriptor))
            info = os.fstat(descriptor)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
                     and stat.S_IMODE(info.st_mode) == spec["mode"] and info.st_size == spec["size"])
            files[name] = _Held(descriptor, _signature(info))
        runtime = Runtime(anchor, policy, uid, directories, files)
        runtime.check()
        try:
            yield runtime
        finally:
            try:
                runtime.check()
            finally:
                runtime._closed = True


@contextmanager
def admit(runtime_root: Path):
    """Admit only the compiled policy; no caller hash, manifest or URL input."""
    uid = _operator_uid()
    with _admit(_absolute(runtime_root), _load_policy(), uid) as runtime:
        yield runtime


@dataclass(frozen=True)
class _Archive:
    anchor: _Anchor
    name: str
    descriptor: int
    signature: tuple

    def check(self) -> None:
        self.anchor.check()
        _require(_signature(os.fstat(self.descriptor)) == self.signature
                 and _signature(os.stat(self.name, dir_fd=self.anchor.descriptor,
                                        follow_symlinks=False)) == self.signature)


def _archive(path: Path, spec: Mapping, stack: ExitStack, uid: int) -> _Archive:
    _absolute(path)
    anchor = _anchor(path.parent, stack, uid)
    descriptor = _keep(stack, os.open(path.name, _READ, dir_fd=anchor.descriptor))
    info = os.fstat(descriptor)
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
             and not info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
             and info.st_size == spec["size"])
    result = _Archive(anchor, path.name, descriptor, _signature(info))
    result.check()
    _require(_hash_file(descriptor, spec["size"]) == spec["sha256"])
    result.check()
    return result


def _mapped_member(name: str, spec: Mapping) -> str | None:
    _require(type(name) is str and not name.endswith("//"))
    _relative(name.rstrip("/"))
    if name.rstrip("/") == spec["prefix"].rstrip("/"):
        return None
    _require(name.startswith(spec["prefix"]))
    relative = name[len(spec["prefix"]):].rstrip("/")
    _relative(relative)
    if spec["members"] is not None and relative not in spec["members"]:
        return None
    return spec["destination"] + "/" + relative


def _copy(stream, target: str, size: int, directories: dict[str, int], policy: _Policy,
          copied: set[str]) -> None:
    _require(target in policy.files and target not in copied and size == policy.files[target]["size"])
    path = PurePosixPath(target)
    parent = directories[str(path.parent)]
    descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
    try:
        value = hashlib.sha256()
        remaining = size
        while remaining:
            chunk = stream.read(min(remaining, 1024 * 1024))
            _require(type(chunk) is bytes and 0 < len(chunk) <= remaining)
            value.update(chunk)
            remaining -= len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                _require(written > 0)
                view = view[written:]
        _require(stream.read(1) == b"" and value.hexdigest() == policy.files[target]["sha256"])
        os.fchmod(descriptor, policy.files[target]["mode"])
        os.fsync(descriptor)
        os.fsync(parent)
        copied.add(target)
    finally:
        os.close(descriptor)


def _extract(archive: _Archive, spec: Mapping, directories: dict[str, int],
             policy: _Policy, copied: set[str]) -> None:
    archive.check()
    expected_files = {name for name in policy.files if name.startswith(spec["destination"] + "/")}
    selected = {}

    def member(target, entry, size):
        _require(target in expected_files and target not in selected and target not in copied
                 and size == policy.files[target]["size"])
        selected[target] = entry

    with os.fdopen(os.dup(archive.descriptor), "rb") as source:
        source.seek(0)
        if spec["format"] == "zip":
            with zipfile.ZipFile(source) as bundle:
                entries = bundle.infolist()
                _require(len(entries) <= MAX_ARCHIVE_MEMBERS)
                names = set()
                for entry in entries:
                    _require(entry.filename not in names and not entry.flag_bits & 1
                             and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
                    names.add(entry.filename)
                    target = _mapped_member(entry.filename, spec)
                    if target is None:
                        continue
                    mode = entry.external_attr >> 16
                    _require(not stat.S_ISLNK(mode) and stat.S_IFMT(mode)
                             in ((0, stat.S_IFDIR) if entry.is_dir() else (0, stat.S_IFREG)))
                    if entry.is_dir():
                        _require(target in policy.directories)
                    else:
                        member(target, entry, entry.file_size)
                _require(set(selected) == expected_files)
                archive.check()
                for target, entry in selected.items():
                    with bundle.open(entry) as stream:
                        _copy(stream, target, entry.file_size, directories, policy, copied)
        else:
            with tarfile.open(fileobj=source, mode={"tar.xz": "r:xz", "tar.gz": "r:gz"}[spec["format"]]) as bundle:
                names = set()
                for entry in bundle:
                    _require(len(names) < MAX_ARCHIVE_MEMBERS and entry.name not in names)
                    names.add(entry.name)
                    target = _mapped_member(entry.name, spec)
                    if target is None:
                        continue
                    if entry.isdir():
                        _require(target in policy.directories)
                    else:
                        _require(entry.isfile() and not entry.issparse())
                        member(target, entry, entry.size)
                _require(set(selected) == expected_files)
                archive.check()
                for target, entry in selected.items():
                    with bundle.extractfile(entry) as stream:
                        _copy(stream, target, entry.size, directories, policy, copied)
    archive.check()


def _install(root: Path, paths: dict[str, Path], policy: _Policy, uid: int) -> dict[str, str]:
    _absolute(root)
    _require(set(paths) == set(ARCHIVES))
    with ExitStack() as stack:
        # Authenticate all compressed inputs before creating even an empty
        # destination. Existing destinations are never adopted or overwritten.
        sources = {name: _archive(paths[name], policy.archives[name], stack, uid) for name in ARCHIVES}
        parent = _anchor(root.parent, stack, uid)
        info = os.fstat(parent.descriptor)
        _require(info.st_uid == uid and not info.st_mode & 0o022)
        os.mkdir(root.name, 0o700, dir_fd=parent.descriptor)
        os.fsync(parent.descriptor)
        anchor = _anchor(root, stack, uid)
        directories = {"": anchor.descriptor}
        for name in policy.directories:
            relative = PurePosixPath(name)
            enclosing = str(relative.parent)
            directory = directories["" if enclosing == "." else enclosing]
            os.mkdir(relative.name, 0o700, dir_fd=directory)
            descriptor = _keep(stack, os.open(relative.name, _DIRECTORY, dir_fd=directory))
            directories[name] = descriptor
            os.fsync(directory)
        copied: set[str] = set()
        for name in ARCHIVES:
            anchor.check()
            parent.check()
            _extract(sources[name], policy.archives[name], directories, policy, copied)
        _require(copied == set(policy.files))
        for descriptor in reversed(list(directories.values())):
            os.fsync(descriptor)
        anchor.check()
        parent.check()
        for source in sources.values():
            source.check()
        with _admit(root, policy, uid) as runtime:
            return dict(runtime.identity)


def install(runtime_root: Path, *, node_archive: Path, playwright_archive: Path,
            chromium_archive: Path) -> dict[str, str]:
    """Install only the three pinned local archives into a fresh private root."""
    uid = _operator_uid()
    return _install(runtime_root, dict(node=node_archive, playwright=playwright_archive,
                                      chromium=chromium_archive), _load_policy(), uid)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check")
    check.add_argument("--runtime-root", type=Path, required=True)
    setup = commands.add_parser("install")
    setup.add_argument("--runtime-root", type=Path, required=True)
    for name in ARCHIVES:
        setup.add_argument(f"--{name}-archive", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            with admit(args.runtime_root) as runtime:
                result = dict(runtime.identity)
        else:
            result = install(args.runtime_root, node_archive=args.node_archive,
                             playwright_archive=args.playwright_archive, chromium_archive=args.chromium_archive)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (ValueError, OSError, KeyError, TypeError, ImportError, tarfile.TarError, zipfile.BadZipFile):
        print(REFUSED, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
