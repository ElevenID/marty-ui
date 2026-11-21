#!/usr/bin/env python3
"""Create a private versioned source installation and replay its original anchor.

No task, old source, credential, Docker object, or deployment input is changed.
The emitted runner supports read-only selected-input replay only.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import importlib.abc
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import types
import zipfile

SCHEMA = "marty.windows-owner-source-install/v1"
TOOLING_SCHEMA = "marty.windows-owner-source-bootstrap/v1"
REPLAY_SCHEMA = "marty.windows-owner-source-replay/v1"
INSTALLATION = "installation.json"
PENDING = "installation.pending.json"
RUNNER = "replay-owner.py"
BOOTSTRAP = ("package_windows_owner_source.py", "selfhost_windows_inputs.py",
             "selfhost_windows_source_install.py")
MAX_SOURCE = 4 * 1024 * 1024
MAX_RECORD = 64 * 1024
MAX_DIRECTORIES = 4096


def require(condition):
    if not condition:
        raise ValueError("Windows source installation requires inspection; preserve its files")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def packed(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    def constant(_value):
        raise ValueError("Nonfinite source record")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def exact_digest(value, length=64):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value))
    return value


def file_reference(raw):
    return {"sha256": digest(raw), "bytes": len(raw)}


def checked_tooling(raw, expected):
    exact_digest(expected)
    require(type(raw) is bytes and len(raw) <= MAX_RECORD and digest(raw) == expected)
    value = decode(raw)
    require(raw == packed(value) and type(value) is dict
            and set(value) == {"schema", "source_commit", "files"}
            and value["schema"] == TOOLING_SCHEMA)
    exact_digest(value["source_commit"], 40)
    require(type(value["files"]) is dict and set(value["files"]) == set(BOOTSTRAP))
    for reference in value["files"].values():
        require(type(reference) is dict and set(reference) == {"sha256", "bytes"}
                and type(reference["bytes"]) is int and 0 < reference["bytes"] <= MAX_SOURCE)
        exact_digest(reference["sha256"])
    return value


def load_bytes(name, raw, filename):
    """Execute already independently trusted bootstrap bytes, never candidate code."""
    require(name not in sys.modules)
    module = types.ModuleType(name)
    module.__file__ = str(filename)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(filename), "exec"), module.__dict__)
    except BaseException:
        del sys.modules[name]
        raise
    return module


def read_bounded(path, limit):
    with Path(path).open("rb") as source:
        raw = source.read(limit + 1)
    require(len(raw) <= limit)
    return raw


def bootstrap_inventory(repository, commit, package):
    tree, entries = package.object_inventory(repository, commit)
    del tree
    names = ["scripts/" + name for name in BOOTSTRAP]
    require(set(names) <= set(entries))
    bodies = package.read_blobs(repository, {name: entries[name] for name in names})
    return {"schema": TOOLING_SCHEMA, "source_commit": commit,
            "files": {name: file_reference(bodies["scripts/" + name]) for name in BOOTSTRAP}}


@contextmanager
def trusted_tooling(inventory_path, expected_digest, scripts):
    """Caller supplies the inventory digest independently of received artifacts."""
    require(os.name == "nt")
    raw = read_bounded(inventory_path, MAX_RECORD)
    inventory = checked_tooling(raw, expected_digest)
    bodies = {name: read_bounded(Path(scripts) / name, MAX_SOURCE) for name in BOOTSTRAP}
    require({name: file_reference(body) for name, body in bodies.items()} == inventory["files"])
    inputs_name = "_marty_install_trusted_inputs"
    package_name = "_marty_install_trusted_package"
    try:
        windows = load_bytes(inputs_name, bodies["selfhost_windows_inputs.py"],
                             Path(scripts) / "selfhost_windows_inputs.py")
        package = load_bytes(package_name, bodies["package_windows_owner_source.py"],
                             Path(scripts) / "package_windows_owner_source.py")
        with ExitStack() as held:
            require(held.enter_context(windows.hold_public_input(Path(inventory_path), max_bytes=MAX_RECORD)) == raw)
            for name, body in bodies.items():
                require(held.enter_context(windows.hold_public_input(Path(scripts) / name,
                                                                    max_bytes=MAX_SOURCE)) == body)
            yield inventory, bodies, windows, package
    finally:
        sys.modules.pop(inputs_name, None)
        sys.modules.pop(package_name, None)


def archive_files(raw, commit, package):
    package.inspect_archive(raw, digest(raw), commit)
    prefix = "windows-owner-source-" + commit + "/"
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return {item.filename[len(prefix):]: archive.read(item) for item in archive.infolist()}


def runner_bytes(tooling):
    # This runner is a new explicit read-only entrypoint. It cannot be used as
    # a replacement for the production renewal runner or its post-renewal hook.
    return (RUNNER_PREFIX + repr(decode(packed(tooling["files"]))) + RUNNER_SUFFIX).encode("utf-8")


RUNNER_PREFIX = '''#!/usr/bin/env python3
"""Read-only source/selection replay; never a renewal scheduled-task action."""
import argparse,hashlib,pathlib,sys,types
EXPECTED_BOOTSTRAP = '''
RUNNER_SUFFIX = '''
def require(value):
 if not value:raise ValueError('Versioned source replay refused')
def main():
 require(sys.flags.isolated and sys.dont_write_bytecode and sys.platform=='win32')
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--expected-installation-sha256',required=True)
 args=parser.parse_args()
 root=pathlib.Path(__file__).absolute().parent
 bodies={};modules={}
 for filename,expected in EXPECTED_BOOTSTRAP.items():
  path=root/'bootstrap'/filename
  with path.open('rb') as source:raw=source.read(4*1024*1024+1)
  require(len(raw)==expected['bytes'] and hashlib.sha256(raw).hexdigest()==expected['sha256'])
  bodies[filename]=raw
 for filename in EXPECTED_BOOTSTRAP:
  name='_marty_replay_bootstrap_'+filename[:-3]
  require(name not in sys.modules)
  module=types.ModuleType(name);module.__file__=str(root/'bootstrap'/filename)
  sys.modules[name]=module
  exec(compile(bodies[filename],module.__file__,'exec'),module.__dict__)
  modules[filename]=module
 result=modules['selfhost_windows_source_install.py'].replay(
  root,args.expected_installation_sha256,
  windows=modules['selfhost_windows_inputs.py'],
  package=modules['package_windows_owner_source.py'],bootstrap_bodies=bodies)
 import json
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
 try:main()
 except Exception:
  print('Versioned source replay refused; preserve installation and original owner.',file=sys.stderr)
  sys.exit(1)
'''


def membership(files):
    result = {"": set()}
    for name in files:
        parts = name.split("/")
        for index, part in enumerate(parts):
            parent = "/".join(parts[:index])
            result.setdefault(parent, set()).add(part)
            if index < len(parts) - 1:
                result.setdefault("/".join(parts[:index + 1]), set())
            require(len(result) <= MAX_DIRECTORIES)
    return result


def exists(path):
    try:
        Path(path).lstat()
    except FileNotFoundError:
        return False
    return True


def private_write(path, raw, windows, maximum):
    require(type(raw) is bytes and len(raw) <= maximum)
    with path.open("xb") as allocation:
        identities = windows._path_identities(path)
        allocated = os.fstat(allocation.fileno())
        require((allocated.st_dev, allocated.st_ino) == identities[-1])
    with windows._held_private_input(path, raw, max_bytes=maximum,
                                     _expected_identities=identities) as written:
        require(written == raw)


def installation_files(record, archive_raw, source_bodies, bootstrap_bodies, *, ready):
    return {**{"source/" + name: body for name, body in source_bodies.items()},
            **{"bootstrap/" + name: body for name, body in bootstrap_bodies.items()},
            "source.zip": archive_raw, RUNNER: runner_bytes(record["tooling"]),
            INSTALLATION if ready else PENDING: packed(record)}


@contextmanager
def hold_files(root, files, windows, *, promote=False):
    """Private recursive namespace and byte custody; no catalog-derived code runs."""
    directories = membership(files)
    with ExitStack() as held:
        held.enter_context(windows.hold_storage_namespace(root.parent))
        held.enter_context(windows._held_private_input(root, directory=True, mutable_directory=promote))
        require({path.name for path in root.iterdir()} == directories[""])
        if promote:
            require(PENDING in files and INSTALLATION not in files)
            require(held.enter_context(windows._held_private_input(
                root / PENDING, max_bytes=MAX_RECORD, _rename_to=root / INSTALLATION)) == files[PENDING])
        for name in sorted(set(directories) - {""}, key=lambda value: (value.count("/"), value)):
            path = root / name
            held.enter_context(windows._held_private_input(path, directory=True))
            require({item.name for item in path.iterdir()} == directories[name])
        for name, raw in sorted(files.items()):
            if promote and name == PENDING:
                continue
            require(held.enter_context(windows.hold_private_input(root / name,
                max_bytes=max(MAX_SOURCE, len(raw)))) == raw)
        yield
        for name, expected in directories.items():
            require({path.name for path in (root / name).iterdir()} == expected)


def checked_installation(raw, expected, root):
    exact_digest(expected)
    require(type(raw) is bytes and len(raw) <= MAX_RECORD and digest(raw) == expected)
    value = decode(raw)
    require(raw == packed(value) and type(value) is dict and set(value) == {
        "schema", "root", "source", "tooling", "tooling_inventory_sha256", "anchor",
        "project", "runner", "active_callers_migrated", "credential_admission", "runtime_admission"}
        and value["schema"] == SCHEMA and value["root"] == str(root)
        and type(value["source"]) is dict and type(value["tooling"]) is dict)
    require(all(value[name] is False for name in
                ("active_callers_migrated", "credential_admission", "runtime_admission")))
    checked_tooling(packed(value["tooling"]), value["tooling_inventory_sha256"])
    require(type(value["anchor"]) is dict and set(value["anchor"]) == {"path", "sha256"}
            and type(value["anchor"]["path"]) is str and Path(value["anchor"]["path"]).is_absolute())
    exact_digest(value["anchor"]["sha256"])
    require(type(value["project"]) is str and re.fullmatch(r"marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}", value["project"]))
    require(value["runner"] == file_reference(runner_bytes(value["tooling"])))
    source = value["source"]
    exact_digest(source["source_commit"], 40);exact_digest(source["archive_sha256"])
    require(root.name == "windows-owner-source-" + source["source_commit"] + "-" + source["archive_sha256"][:16])
    return value


def install(archive, archive_sha256, commit, destination, anchor, anchor_sha256, project,
            tooling_inventory_path, tooling_inventory_sha256, *, scripts=None):
    require(os.name == "nt")
    exact_digest(archive_sha256);exact_digest(commit, 40);exact_digest(anchor_sha256)
    destination, anchor, archive = Path(destination), Path(anchor), Path(archive)
    require(destination.is_absolute() and anchor.is_absolute() and archive.is_absolute()
            and destination.name == "windows-owner-source-" + commit + "-" + archive_sha256[:16]
            and type(project) is str and re.fullmatch(r"marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}", project)
            and not exists(destination))
    scripts = Path(__file__).parent if scripts is None else Path(scripts)
    with trusted_tooling(tooling_inventory_path, tooling_inventory_sha256, scripts) as (
            tooling, bootstrap_bodies, windows, package):
        with ExitStack() as held:
            archive_raw = held.enter_context(windows.hold_public_input(archive, max_bytes=package.MAX_ARCHIVE_BYTES))
            source = package.inspect_archive(archive_raw, archive_sha256, commit)
            source_bodies = archive_files(archive_raw, commit, package)
            anchor_raw = held.enter_context(windows.hold_private_input(anchor))
            require(digest(anchor_raw) == anchor_sha256 and decode(anchor_raw).get("project") == project)
            held.enter_context(windows.hold_storage_namespace(destination.parent))
            held.enter_context(windows._held_private_input(destination.parent, directory=True, mutable_directory=True))
            require(not exists(destination))
            record = {"schema": SCHEMA, "root": str(destination), "source": source,
                "tooling": tooling, "tooling_inventory_sha256": tooling_inventory_sha256,
                "anchor": {"path": str(anchor), "sha256": anchor_sha256}, "project": project,
                "runner": file_reference(runner_bytes(tooling)), "active_callers_migrated": False,
                "credential_admission": False, "runtime_admission": False}
            record_raw = packed(record)
            require(len(record_raw) <= MAX_RECORD)
            checked_installation(record_raw, digest(record_raw), destination)
            files = installation_files(record, archive_raw, source_bodies, bootstrap_bodies, ready=False)
            directories = membership(files)
            destination.mkdir()
            held.enter_context(windows._held_private_input(destination, directory=True, mutable_directory=True))
            for name in sorted(set(directories) - {""}, key=lambda value: (value.count("/"), value)):
                path = destination / name
                path.mkdir()
                held.enter_context(windows._held_private_input(path, directory=True, mutable_directory=True))
            for name, raw in sorted(files.items()):
                private_write(destination / name, raw, windows, max(MAX_SOURCE, len(raw)))
            with hold_files(destination, files, windows):
                pass
    # Original inputs and all creation handles must exit successfully before a
    # fresh complete private reproof can publish the new installation marker.
    with hold_files(destination, files, windows, promote=True):
        pass
    files[INSTALLATION] = files.pop(PENDING)
    with hold_files(destination, files, windows):
        pass
    return {"schema": SCHEMA, "root": str(destination), "source_commit": commit,
            "installation_sha256": digest(record_raw), "tooling_inventory_sha256": tooling_inventory_sha256,
            "source_private_placement_verified": True, "original_anchor_replayed": False,
            "active_callers_migrated": False, "credential_admission": False, "runtime_admission": False}


class VerifiedLoader(importlib.abc.Loader):
    def __init__(self, path, raw):
        self.path, self.raw = path, raw

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__file__ = str(self.path)
        exec(compile(self.raw, str(self.path), "exec"), module.__dict__)


class VerifiedFinder(importlib.abc.MetaPathFinder):
    def __init__(self, root, bodies):
        self.root = root
        self.modules = {Path(name).stem: (name, raw) for name, raw in bodies.items()
                        if name.startswith("scripts/") and name.count("/") == 1 and name.endswith(".py")}

    def find_spec(self, fullname, path=None, target=None):
        del path, target
        if fullname in self.modules:
            name, raw = self.modules[fullname]
            loader = VerifiedLoader(self.root / name, raw)
            return importlib.util.spec_from_loader(fullname, loader, origin=str(self.root / name))
        return None


def replay(root, expected_installation_sha256, *, windows, package, bootstrap_bodies):
    require(os.name == "nt" and sys.flags.isolated and sys.dont_write_bytecode)
    root = Path(root)
    require(root.is_absolute())
    with ExitStack() as held:
        held.enter_context(windows.hold_storage_namespace(root.parent))
        held.enter_context(windows._held_private_input(root, directory=True))
        raw = held.enter_context(windows.hold_private_input(root / INSTALLATION, max_bytes=MAX_RECORD))
        record = checked_installation(raw, expected_installation_sha256, root)
        require({name: file_reference(body) for name, body in bootstrap_bodies.items()} == record["tooling"]["files"])
        archive_raw = held.enter_context(windows.hold_private_input(root / "source.zip", max_bytes=package.MAX_ARCHIVE_BYTES))
        require(package.inspect_archive(archive_raw, record["source"]["archive_sha256"],
                                         record["source"]["source_commit"]) == record["source"])
        source_bodies = archive_files(archive_raw, record["source"]["source_commit"], package)
        files = installation_files(record, archive_raw, source_bodies, bootstrap_bodies, ready=True)
        held.enter_context(hold_files(root, files, windows))
        anchor = Path(record["anchor"]["path"])
        anchor_raw = held.enter_context(windows.hold_private_input(anchor))
        require(digest(anchor_raw) == record["anchor"]["sha256"]
                and decode(anchor_raw).get("project") == record["project"])
        finder = VerifiedFinder(root / "source", source_bodies)
        require(not (set(finder.modules) & set(sys.modules)))
        sys.meta_path.insert(0, finder)
        try:
            import selfhost_windows_selection as selection
            with selection.selected_inputs(anchor) as lease:
                require(lease.project == record["project"] and type(lease.sequence) is int
                        and type(lease.generation_sequence) is int
                        and 1 <= lease.sequence <= lease.generation_sequence)
                exact_digest(lease.selected_sha256)
                result = {"schema": REPLAY_SCHEMA, "source_commit": record["source"]["source_commit"],
                    "installation_sha256": expected_installation_sha256,
                    "anchor_sha256": record["anchor"]["sha256"], "project": lease.project,
                    "sequence": lease.sequence, "generation_sequence": lease.generation_sequence,
                    "selected_sha256": lease.selected_sha256, "original_anchor_replayed": True,
                    "active_callers_migrated": False, "credential_admission": False,
                    "runtime_admission": False}
            imported = {name for name in finder.modules if name in sys.modules}
            require(imported and all(Path(sys.modules[name].__file__) == finder.root / finder.modules[name][0]
                                     for name in imported))
        finally:
            sys.meta_path.remove(finder)
    # No result is returned until the selected-input lease and every private
    # source/bootstrap/namespace handle have completed their exit checks.
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    inventory = actions.add_parser("bootstrap-inventory")
    inventory.add_argument("--repository", type=Path, required=True)
    inventory.add_argument("--commit", required=True)
    inventory.add_argument("--output", type=Path, required=True)
    installation = actions.add_parser("install")
    for name in ("archive", "archive-sha256", "commit", "destination", "anchor", "anchor-sha256",
                 "project", "tooling-inventory-path", "tooling-inventory-sha256"):
        installation.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "bootstrap-inventory":
            package_path = Path(__file__).with_name("package_windows_owner_source.py")
            package = load_bytes("_marty_inventory_package", read_bounded(package_path, MAX_SOURCE), package_path)
            value = bootstrap_inventory(args.repository, args.commit, package)
            raw = packed(value)
            checked_tooling(raw, digest(raw))
            with args.output.open("xb") as output:
                output.write(raw);output.flush();os.fsync(output.fileno())
            result = {"schema": TOOLING_SCHEMA, "source_commit": args.commit,
                      "tooling_inventory_sha256": digest(raw), "files": len(BOOTSTRAP)}
        else:
            options = vars(args).copy();options.pop("action")
            result = install(**options)
    except Exception:
        parser.exit(1, "Windows source installation refused; preserve source, original owner and any partial output.\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
