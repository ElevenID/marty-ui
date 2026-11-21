"""Private, exact-lock Git object transport for credential-free watcher fetches.

Only fresh Git-generated bare repositories cross this boundary. Original Cargo
configuration, credentials, hooks, alternates and replacement refs never do.
Registry packages still come from crates.io and Cargo checks their lock hashes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile

if __package__:
    from .scoped_native_cargo_cache import git_sources, metadata_git_sources, registry_archives
else:
    from scoped_native_cargo_cache import git_sources, metadata_git_sources, registry_archives


SCHEMA = "marty-passport-watch-git-source-seed-v1"
MANIFEST = "git-source-seed.json"
RECORD = ".marty-passport-watch-git-source-seed.json"
MOUNT = "/git-source-seed"
MAX_BYTES = 128 * 1024 ** 2
MAX_FILES = 8192
MAX_SOURCES = 16
MAX_MANIFEST = 2 * 1024 ** 2
BARE_CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n"
RDF_PATH = "crates/rdf/canonicalization"
RDF_REPO = "rdf-dataset-canonicalization"
RDF_URL = "https://github.com/w3c-ccg/" + RDF_REPO
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


class GitSeedError(ValueError):
    """Diagnostics deliberately omit Git output and source contents."""


def git_environment(environment: dict[str, str], *, local_import: bool = False) -> dict[str, str]:
    """No ambient Git/Cargo settings, helpers or network Git transport."""
    result = {"PATH": environment.get("PATH", os.defpath), "HOME": "/tmp", "LANG": "C", "LC_ALL": "C",
              "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
              "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false", "SSH_ASKPASS": "/bin/false",
              "GIT_SSH_COMMAND": "false", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
              "GIT_OPTIONAL_LOCKS": "0", "GIT_PROTOCOL_FROM_USER": "0",
              "GIT_ALLOW_PROTOCOL": "file" if local_import else ""}
    settings = {
        "core.hooksPath": os.devnull, "core.fsmonitor": "false", "core.sshCommand": "false",
        "core.askPass": "/bin/false", "credential.helper": "", "credential.interactive": "false",
        "protocol.allow": "never", "protocol.file.allow": "always" if local_import else "never",
        "fetch.recurseSubmodules": "false", "submodule.recurse": "false", "gc.auto": "0",
        "maintenance.auto": "false", "transfer.fsckObjects": "true", "fetch.fsckObjects": "true",
        "pack.threads": "1", "pack.windowMemory": "32m", "pack.deltaCacheSize": "16m",
    }
    result["GIT_CONFIG_COUNT"] = str(len(settings))
    for index, (name, value) in enumerate(settings.items()):
        result[f"GIT_CONFIG_KEY_{index}"] = name
        result[f"GIT_CONFIG_VALUE_{index}"] = value
    return result


def cargo_environment(environment: dict[str, str], cargo: Path, *, offline: bool) -> dict[str, str]:
    if environment.get("RUSTUP_HOME", "/usr/local/rustup") != "/usr/local/rustup":
        raise GitSeedError("Watcher Cargo requires the pinned image toolchain")
    result = git_environment(environment)
    result.update(CARGO_HOME=str(cargo), RUSTUP_HOME="/usr/local/rustup", CARGO_NET_GIT_FETCH_WITH_CLI="true",
                  CARGO_NET_OFFLINE="true" if offline else "false", CARGO_BUILD_JOBS="1",
                  CARGO_REGISTRIES_CRATES_IO_PROTOCOL="sparse", CARGO_HTTP_PROXY="")
    return result


def _git(args: list[str], environment: dict[str, str]) -> bytes:
    try:
        result = subprocess.run(["git", *args], env=environment, capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitSeedError("Watcher Git seed operation failed") from exc
    if result.returncode:
        raise GitSeedError("Watcher Git seed objects are incomplete or invalid")
    return result.stdout.strip()


def _db(path: Path, environment: dict[str, str], *args: str) -> bytes:
    return _git(["--git-dir", str(path), *args], environment)


def _identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_size, info.st_mtime_ns)


def _private_directory(path: Path, checkout: Path | None = None) -> None:
    if (os.name != "posix" or os.getuid() != os.geteuid() or not path.is_absolute()
        or path.resolve(strict=True) != path or any(c in str(path) for c in (",", "\n", "\r"))
        or (checkout is not None and path.is_relative_to(checkout.resolve(strict=True)))):
        raise GitSeedError("Watcher Git seed must be canonical and outside the checkout")
    for parent in (path, *path.parents):
        info = parent.lstat()
        sticky_tmp = parent == Path("/tmp") and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
            or (parent == path and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700))
            or (parent != path and info.st_mode & 0o022 and not sticky_tmp)):
            raise GitSeedError("Watcher Git seed requires private ownership and safe ancestors")


def _read(path: Path, limit: int, *, private: bool = True) -> bytes:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_size > limit
        or (private and (stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1))
        or (not private and before.st_mode & 0o022)):
        raise GitSeedError("Watcher Git seed file ownership, type or size is invalid")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise GitSeedError("Watcher Git seed file changed while opening")
        value = stream.read(limit + 1)
        if len(value) > limit or _identity(os.fstat(stream.fileno())) != _identity(before):
            raise GitSeedError("Watcher Git seed file changed while reading")
    if _identity(path.lstat()) != _identity(before):
        raise GitSeedError("Watcher Git seed file changed after reading")
    return value


def _write(path: Path, value: bytes) -> None:
    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    if parent.resolve(strict=True) != parent:
        raise GitSeedError("Watcher Git seed output parent is redirected")
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        stream.write(value)


def _db_file(relative: str, names: set[str]) -> bool:
    parts = relative.split("/")
    if len(parts) < 3 or parts[0] != "db" or parts[1] not in names:
        return False
    leaf = "/".join(parts[2:])
    return (leaf in ("HEAD", "config", "shallow")
            or re.fullmatch(r"refs/heads/locked-[0-9a-f]{40}", leaf) is not None
            or re.fullmatch(r"objects/[0-9a-f]{2}/[0-9a-f]{38}", leaf) is not None
            or re.fullmatch(r"objects/pack/pack-[0-9a-f]{40}\.(?:pack|idx|rev)", leaf) is not None)


def _manifest(value: bytes, original_lock: bytes) -> dict:
    def unique(pairs):
        result = {}
        for name, item in pairs:
            if name in result:
                raise GitSeedError("Watcher Git seed manifest has duplicate fields")
            result[name] = item
        return result
    try:
        record = json.loads(value, object_pairs_hook=unique)
        expected = git_sources(original_lock)
        registry_archives(original_lock)  # Only the normal public registry is admitted.
        if (set(record) != {"schema", "cargoLockSha256", "sources", "rdfGitlink", "files"}
            or record["schema"] != SCHEMA
            or record["cargoLockSha256"] != hashlib.sha256(original_lock).hexdigest()
            or set(record["sources"]) != set(expected) or len(expected) > MAX_SOURCES):
            raise GitSeedError("Watcher Git seed does not match the exact dependency lock")
        names = {}
        for key, row in [*record["sources"].items(), ("rdfGitlink", record["rdfGitlink"])]:
            rdf = key == "rdfGitlink"
            repo, revision = (RDF_REPO, row["revision"]) if rdf else key.split("@", 1)
            if (set(row) != {"cargoDbName", "revision", "tree"} | ({"parentSource"} if rdf else set())
                or row["revision"] != revision or not HEX40.fullmatch(revision)
                or not HEX40.fullmatch(row["tree"])
                or not re.fullmatch(re.escape(repo) + r"-[0-9a-f]{16}", row["cargoDbName"])
                or (repo in names and names[repo] != row["cargoDbName"])
                or (rdf and (row["parentSource"] not in expected
                             or not row["parentSource"].startswith("ssi-elevenid@")))):
                raise GitSeedError("Watcher Git seed source identity is invalid")
            names[repo] = row["cargoDbName"]
        files = record["files"]
        if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
            raise GitSeedError("Watcher Git seed inventory is invalid")
        total = 0
        for name, row in files.items():
            if (not _db_file(name, set(names.values())) or set(row) != {"sha256", "size"}
                or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                or type(row["size"]) is not int or not 0 < row["size"] <= MAX_BYTES):
                raise GitSeedError("Watcher Git seed inventory has an unexpected file")
            total += row["size"]
        if total > MAX_BYTES:
            raise GitSeedError("Watcher Git seed exceeds its bounded input size")
        return record
    except (KeyError, TypeError, AttributeError, UnicodeError, json.JSONDecodeError) as exc:
        raise GitSeedError("Watcher Git seed manifest is invalid") from exc


def checked_seed(directory: Path, original_lock: bytes, checkout: Path | None = None) -> tuple[dict, str]:
    _private_directory(directory, checkout)
    value = _read(directory / MANIFEST, MAX_MANIFEST)
    record = _manifest(value, original_lock)
    expected_files = set(record["files"]) | {MANIFEST}
    seen = set()
    for path in directory.rglob("*"):
        info = path.lstat()
        relative = path.relative_to(directory).as_posix()
        if stat.S_ISDIR(info.st_mode):
            if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
                or not any(name.startswith(relative + "/") for name in expected_files)):
                raise GitSeedError("Watcher Git seed contains an unexpected directory")
            continue
        if relative not in expected_files:
            raise GitSeedError("Watcher Git seed contains an unexpected file")
        contents = _read(path, MAX_MANIFEST if relative == MANIFEST else record["files"][relative]["size"])
        if relative != MANIFEST and record["files"][relative] != {
            "sha256": hashlib.sha256(contents).hexdigest(), "size": len(contents),
        }:
            raise GitSeedError("Watcher Git seed file digest changed")
        seen.add(relative)
    if seen != expected_files or _read(directory / MANIFEST, MAX_MANIFEST) != value:
        raise GitSeedError("Watcher Git seed inventory changed")
    rows = [*record["sources"].values(), record["rdfGitlink"]]
    for name in {row["cargoDbName"] for row in rows}:
        path = directory / "db" / name
        revisions = {row["revision"] for row in rows if row["cargoDbName"] == name}
        if (_read(path / "config", 1024) != BARE_CONFIG
            or _read(path / "HEAD", 128).decode() not in {
                f"ref: refs/heads/locked-{revision}\n" for revision in revisions}
            or {part.name for part in (path / "refs/heads").iterdir()} != {
                f"locked-{revision}" for revision in revisions}):
            raise GitSeedError("Watcher Git seed bare metadata is not canonical")
        for revision in revisions:
            if _read(path / "refs/heads" / ("locked-" + revision), 64) != (revision + "\n").encode():
                raise GitSeedError("Watcher Git seed ref changed")
        shallow = path / "shallow"
        if shallow.exists() and (not _read(shallow, MAX_MANIFEST).splitlines()
                                or any(not HEX40.fullmatch(line.decode("ascii"))
                                       for line in _read(shallow, MAX_MANIFEST).splitlines())):
            raise GitSeedError("Watcher Git seed shallow metadata is invalid")
    return record, hashlib.sha256(value).hexdigest()


def stage_seed(source: Path, destination: Path, original_lock: bytes, checkout: Path) -> str:
    record, digest = checked_seed(source, original_lock, checkout)
    destination.mkdir(mode=0o700)
    for name in sorted([MANIFEST, *record["files"]]):
        limit = MAX_MANIFEST if name == MANIFEST else record["files"][name]["size"]
        _write(destination / name, _read(source / name, limit))
    if checked_seed(destination, original_lock)[1] != digest or checked_seed(source, original_lock, checkout)[1] != digest:
        raise GitSeedError("Watcher Git seed changed while staging")
    return digest


def _tree(directory: Path, revision: str, environment: dict[str, str]) -> str:
    if _db(directory, environment, "cat-file", "-t", revision) != b"commit":
        raise GitSeedError("Watcher Git seed locked commit is missing")
    tree = _db(directory, environment, "rev-parse", revision + "^{tree}").decode("ascii")
    if not HEX40.fullmatch(tree):
        raise GitSeedError("Watcher Git seed tree is invalid")
    return tree


def _rdf(sources: dict, databases: Path, environment: dict[str, str]) -> tuple[str, str]:
    found = []
    for key, row in sources.items():
        db = databases / row["cargoDbName"]
        entries = _db(db, environment, "ls-tree", "-r", row["revision"]).splitlines()
        links = [line.decode("utf-8") for line in entries if line.startswith(b"160000 ")]
        if not links:
            continue
        if (not key.startswith("ssi-elevenid@") or len(links) != 1
            or not re.fullmatch(r"160000 commit [0-9a-f]{40}\t" + re.escape(RDF_PATH), links[0])):
            raise GitSeedError("Watcher Git seed has an unsupported submodule")
        modules = _db(db, environment, "show", row["revision"] + ":.gitmodules").decode("utf-8")
        if not re.fullmatch(r'\[submodule "' + re.escape(RDF_PATH) + r'"\]\s+path\s*=\s*'
                            + re.escape(RDF_PATH) + r'\s+url\s*=\s*' + re.escape(RDF_URL), modules):
            raise GitSeedError("Watcher Git seed RDF source changed")
        found.append((key, links[0].split()[2]))
    if len(found) != 1:
        raise GitSeedError("Watcher Git seed requires the exact SSI RDF gitlink")
    return found[0]


def _init(path: Path, environment: dict[str, str]) -> None:
    _git(["init", "--quiet", "--bare", "--template=", "--initial-branch=locked", str(path)], environment)
    if (path / "config").read_bytes() != BARE_CONFIG:
        raise GitSeedError("Watcher Git generated unexpected bare configuration")


def _fetch(source: Path, destination: Path, revision: str, environment: dict[str, str],
           upload_pack: str | None = None) -> None:
    options = ["--upload-pack=" + upload_pack] if upload_pack else []
    _db(destination, environment, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules",
        "--no-write-fetch-head", "--update-shallow", *options,
        str(source), f"{revision}:refs/heads/locked-{revision}")


def _cache_inventory(directory: Path) -> dict:
    objects = directory / "objects"
    if objects.resolve(strict=True) != objects or not objects.is_dir():
        raise GitSeedError("Watcher export object directory is redirected")
    for excluded in (directory / "objects/info/alternates", directory / "refs/replace"):
        if excluded.exists() or excluded.is_symlink():
            raise GitSeedError("Watcher export forbids Git alternates and replacement refs")
    inventory = {}
    total = 0
    for path in objects.rglob("*"):
        info = path.lstat()
        relative = path.relative_to(directory).as_posix()
        # A local partial-clone cache may already contain the complete locked
        # tree. Its marker is never exported; the fresh sender has no promisor
        # remote/config, so any missing object still fails without hydration.
        promisor = (re.fullmatch(r"objects/pack/pack-[0-9a-f]{40}\.promisor", relative) is not None
                    and path.with_suffix(".pack").is_file())
        if (info.st_uid != os.geteuid() or info.st_mode & 0o022
            or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            or (stat.S_ISREG(info.st_mode) and not promisor
                and not _db_file("db/input/" + relative, {"input"}))):
            raise GitSeedError("Watcher export cache objects are redirected, unexpected or writable by another owner")
        if stat.S_ISREG(info.st_mode):
            inventory[relative] = _identity(info)
            total += info.st_size
        if len(inventory) > MAX_FILES or total > MAX_BYTES:
            raise GitSeedError("Watcher export cache database exceeds its bound")
    shallow = directory / "shallow"
    if shallow.exists() or shallow.is_symlink():
        value = _read(shallow, MAX_MANIFEST, private=False)
        if not value.splitlines() or any(not re.fullmatch(rb"[0-9a-f]{40}", line) for line in value.splitlines()):
            raise GitSeedError("Watcher export shallow metadata is invalid")
        inventory["shallow"] = (_identity(shallow.lstat()), hashlib.sha256(value).hexdigest())
    return inventory


def _cache_db(cargo: Path, repo: str) -> Path:
    candidates = [path for path in (cargo / "git/db").iterdir()
                  if re.fullmatch(re.escape(repo) + r"-[0-9a-f]{16}", path.name)]
    if len(candidates) != 1:
        raise GitSeedError("Watcher export requires one explicit cached Git database per repository")
    directory = candidates[0]
    if directory.resolve(strict=True) != directory or not directory.is_dir():
        raise GitSeedError("Watcher export cache path is redirected")
    _cache_inventory(directory)
    return directory


def _source_view(cached: Path, view: Path, safe: dict[str, str]) -> tuple[dict[str, str], str]:
    """Read only object/shallow bytes; never load the input repository's config."""
    _init(view, safe)
    values = {"GIT_OBJECT_DIRECTORY": str(cached / "objects"),
              "GIT_SHALLOW_FILE": str(cached / "shallow")}
    # These variables are confined to the read-only sender, never the receiving
    # Git process, so an import cannot write into the original cache.
    upload_pack = shlex.join(["env", *(f"{name}={value}" for name, value in values.items()), "git", "upload-pack"])
    return safe | values, upload_pack


def export_seed(root: Path, cargo: Path, destination: Path, environment: dict[str, str]) -> dict:
    """Export only locked revisions through ordinary local Git, preserving shallow boundaries."""
    root = root.resolve(strict=True)
    if (not cargo.is_absolute() or cargo.resolve(strict=True) != cargo or cargo.stat().st_uid != os.geteuid()
        or cargo.stat().st_mode & 0o022 or destination.exists() or destination.is_symlink()):
        raise GitSeedError("Watcher export requires an explicit owned cache and a new private output")
    _private_directory(destination.parent, root)
    original_lock = (root / "rust/Cargo.lock").read_bytes()
    sources = git_sources(original_lock)
    registry_archives(original_lock)
    if len(sources) > MAX_SOURCES:
        raise GitSeedError("Watcher export source count exceeds its bound")
    safe = git_environment(environment, local_import=True)
    old_umask = os.umask(0o077)
    destination.mkdir(mode=0o700)
    try:
        rows = {}
        cached_databases = {}
        total_bytes = total_files = 0
        for repo in sorted({key.split("@", 1)[0] for key in sources} | {RDF_REPO}):
            cached = cached_databases[repo] = _cache_db(cargo, repo)
            inventory = _cache_inventory(cached)
            total_files += len(inventory)
            total_bytes += sum((info[0] if name == "shallow" else info)[5] for name, info in inventory.items())
        if total_bytes > MAX_BYTES or total_files > MAX_FILES:
            raise GitSeedError("Watcher export source set exceeds its bounded input size")
        with tempfile.TemporaryDirectory(prefix="marty-watch-git-view-", dir=destination.parent) as temporary:
            views = Path(temporary)
            for key in sources:
                repo, revision = key.split("@", 1)
                cached = cached_databases[repo]
                before_inventory = _cache_inventory(cached)
                view = views / (repo + "-" + revision)
                view_env, upload = _source_view(cached, view, safe)
                before = _tree(view, revision, view_env)
                _db(view, view_env, "update-ref", "refs/heads/locked-" + revision, revision)
                output = destination / "db" / cached.name
                if not output.exists():
                    _init(output, safe)
                _fetch(view, output, revision, safe, upload)
                if _tree(output, revision, safe) != before or _cache_inventory(cached) != before_inventory:
                    raise GitSeedError("Watcher export commit or input objects changed")
                rows[key] = {"cargoDbName": cached.name, "revision": revision, "tree": before}
            parent, revision = _rdf(rows, destination / "db", safe)
            cached = cached_databases[RDF_REPO]
            before_inventory = _cache_inventory(cached)
            view_env, upload = _source_view(cached, views / "rdf", safe)
            tree = _tree(views / "rdf", revision, view_env)
            _db(views / "rdf", view_env, "update-ref", "refs/heads/locked-" + revision, revision)
            output = destination / "db" / cached.name
            _init(output, safe)
            _fetch(views / "rdf", output, revision, safe, upload)
            if _tree(output, revision, safe) != tree or _cache_inventory(cached) != before_inventory:
                raise GitSeedError("Watcher export RDF commit or input objects changed")
            rdf = {"cargoDbName": cached.name, "revision": revision, "tree": tree, "parentSource": parent}
        for row in [*rows.values(), rdf]:
            db = destination / "db" / row["cargoDbName"]
            _db(db, safe, "symbolic-ref", "HEAD", "refs/heads/locked-" + row["revision"])
            _db(db, safe, "fsck", "--connectivity-only", "--no-dangling")
        # Init creates empty directories that carry no objects or authority.
        for path in sorted(destination.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if path.is_dir() and not any(path.iterdir()):
                path.rmdir()
        files = {}
        for path in destination.rglob("*"):
            if path.is_file():
                path.chmod(0o600)
                value = _read(path, MAX_BYTES)
                files[path.relative_to(destination).as_posix()] = {"sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
        record = {"schema": SCHEMA, "cargoLockSha256": hashlib.sha256(original_lock).hexdigest(),
                  "sources": rows, "rdfGitlink": rdf, "files": files}
        _write(destination / MANIFEST, (json.dumps(record, sort_keys=True, indent=2) + "\n").encode())
        checked_seed(destination, original_lock, root)
        if (root / "rust/Cargo.lock").read_bytes() != original_lock:
            raise GitSeedError("Watcher dependency lock changed during export")
        return record
    except Exception:
        shutil.rmtree(destination)
        raise
    finally:
        os.umask(old_umask)


def import_seed(seed: Path, cargo: Path, original_lock: bytes, digest: str,
                environment: dict[str, str]) -> None:
    record, actual = checked_seed(seed, original_lock)
    if actual != digest or any((cargo / "git").iterdir()):
        raise GitSeedError("Watcher Git import requires the bound seed and an empty owned cache")
    safe = git_environment(environment, local_import=True)
    rows = [*record["sources"].values(), record["rdfGitlink"]]
    with tempfile.TemporaryDirectory(prefix="marty-watch-git-import-", dir="/tmp") as temporary:
        for index, row in enumerate(rows):
            view = Path(temporary) / str(index)
            view_env, upload = _source_view(seed / "db" / row["cargoDbName"], view, safe)
            if _tree(view, row["revision"], view_env) != row["tree"]:
                raise GitSeedError("Watcher Git seed source tree changed")
            _db(view, view_env, "update-ref", "refs/heads/locked-" + row["revision"], row["revision"])
            target = cargo / "git/db" / row["cargoDbName"]
            if not target.exists():
                _init(target, safe)
            _fetch(view, target, row["revision"], safe, upload)
            if _tree(target, row["revision"], safe) != row["tree"]:
                raise GitSeedError("Watcher Git imported tree changed")
    if _rdf(record["sources"], cargo / "git/db", safe) != (
        record["rdfGitlink"]["parentSource"], record["rdfGitlink"]["revision"],
    ):
        raise GitSeedError("Watcher Git imported RDF identity changed")
    if any(line.startswith(b"160000 ") for line in _db(
        cargo / "git/db" / record["rdfGitlink"]["cargoDbName"], safe,
        "ls-tree", "-r", record["rdfGitlink"]["revision"]).splitlines()):
        raise GitSeedError("Watcher RDF dependency has an unsupported nested submodule")
    for row in record["sources"].values():
        target = cargo / "git/checkouts" / row["cargoDbName"] / row["revision"][:7]
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _git(["clone", "--quiet", "--no-hardlinks", "--no-checkout", "--template=",
              str(cargo / "git/db" / row["cargoDbName"]), str(target)], safe)
        _git(["-C", str(target), "checkout", "--quiet", "--detach", row["revision"]], safe)
        if row is record["sources"][record["rdfGitlink"]["parentSource"]]:
            _git(["-C", str(target), "config", "submodule." + RDF_PATH + ".url",
                  str(cargo / "git/db" / record["rdfGitlink"]["cargoDbName"])], safe)
            _git(["-C", str(target), "submodule", "update", "--init", "--" , RDF_PATH], safe)
        _write(target / ".cargo-ok", b"\n")
    if checked_seed(seed, original_lock)[1] != digest:
        raise GitSeedError("Watcher Git seed changed during import")
    _write(cargo / RECORD, _read(seed / MANIFEST, MAX_MANIFEST))
    verify_checkouts(record, cargo, git_environment(environment))


def _checkout(path: Path, revision: str, tree: str, environment: dict[str, str]) -> None:
    def run(*args):
        return _git(["-C", str(path), *args], environment)
    if (path.is_symlink() or path.resolve(strict=True) != path
        or run("rev-parse", "HEAD").decode() != revision or run("rev-parse", "HEAD^{tree}").decode() != tree):
        raise GitSeedError("Watcher Git checkout identity changed")
    for args in (("diff", "--quiet", "--no-ext-diff", "--ignore-submodules=all"),
                 ("diff", "--cached", "--quiet", "--no-ext-diff", "--ignore-submodules=all")):
        run(*args)
    if (any(row != b"?? .cargo-ok" for row in run("status", "--porcelain=v1", "-z",
            "--untracked-files=all", "--ignore-submodules=all").split(b"\0") if row)
        or any(not row.startswith(b"H ") for row in run("ls-files", "-v", "-z").split(b"\0") if row)):
        raise GitSeedError("Watcher Git checkout has unverified files or index flags")


def verify_checkouts(record: dict, cargo: Path, environment: dict[str, str]) -> None:
    for key, row in record["sources"].items():
        path = cargo / "git/checkouts" / row["cargoDbName"] / row["revision"][:7]
        _checkout(path, row["revision"], row["tree"], environment)
        if key == record["rdfGitlink"]["parentSource"]:
            rdf = record["rdfGitlink"]
            _checkout(path / RDF_PATH, rdf["revision"], rdf["tree"], environment)


def verify_offline(root: Path, cargo: Path, digest: str, environment: dict[str, str]) -> None:
    original_lock = (root / "rust/Cargo.lock").read_bytes()
    value = _read(cargo / RECORD, MAX_MANIFEST)
    if hashlib.sha256(value).hexdigest() != digest:
        raise GitSeedError("Watcher Git offline proof is not bound to its input")
    record = _manifest(value, original_lock)
    safe = cargo_environment(environment, cargo, offline=True)
    try:
        result = subprocess.run(["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
                                 "--manifest-path", str(root / "rust/Cargo.toml")],
                                env=safe, check=True, capture_output=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitSeedError("Watcher offline dependency resolution failed") from exc
    if (not set(metadata_git_sources(result.stdout).items()).issubset(set(git_sources(original_lock).items()))
        or (root / "rust/Cargo.lock").read_bytes() != original_lock):
        raise GitSeedError("Watcher offline dependency source set changed")
    verify_checkouts(record, cargo, safe)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-home", required=True, type=Path, help="explicit existing authorized Cargo cache")
    parser.add_argument("--output", required=True, type=Path, help="new directory beneath an owned private parent")
    args = parser.parse_args()
    try:
        record = export_seed(Path(__file__).resolve().parents[1], args.cargo_home, args.output, dict(os.environ))
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from None
    print(f"Exported {len(record['sources'])} locked Git sources and the derived RDF gitlink; "
          f"{len(record['files'])} files, {sum(row['size'] for row in record['files'].values())} bytes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
