"""Portable failure/publication contracts using explicit synthetic NTFS adapters."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import package_windows_owner_source as package
import selfhost_windows_source_install as install
from test_windows_owner_source_bundle import repository, commit


class SyntheticWindows:
    """Tests ordering/identity decisions only; never claims ACL/NTFS evidence."""
    def __init__(self):
        self.events = []
        self.fail = None
        self.replace_before_write = False

    def _path_identities(self, path):
        info = path.stat()
        return [(info.st_dev, info.st_ino)]

    @contextmanager
    def hold_storage_namespace(self, path):
        yield

    @contextmanager
    def _held_private_input(self, path, write_value=None, *, directory=False, max_bytes=65536,
                            mutable_directory=False, _rename_to=None, _expected_identities=None, **unused):
        del unused
        self.events.append(("enter", path.name, write_value is not None, _rename_to is not None))
        if self.replace_before_write and write_value is not None:
            path.rename(path.with_name(path.name + ".replaced"))
            path.write_bytes(b"")
            self.replace_before_write = False
        if _expected_identities is not None:
            install.require(self._path_identities(path) == _expected_identities)
        install.require(not path.is_symlink() and (path.is_dir() if directory else path.is_file()))
        if write_value is not None:
            install.require(path.read_bytes() == b"" and len(write_value) <= max_bytes)
            path.write_bytes(write_value)
        raw = b"" if directory else path.read_bytes()
        install.require(len(raw) <= max_bytes)
        yield raw
        self.events.append(("exit", path.name, write_value is not None, _rename_to is not None))
        if self.fail:
            self.fail(path, write_value, directory, _rename_to)
        if not directory:
            install.require(path.read_bytes() == raw)
        if _rename_to is not None:
            install.require(not _rename_to.exists())
            path.rename(_rename_to)

    def hold_private_input(self, path, *, max_bytes=65536, **kwargs):
        return self._held_private_input(path, max_bytes=max_bytes, **kwargs)

    def hold_public_input(self, path, *, max_bytes=65536):
        return self._held_private_input(path, max_bytes=max_bytes)


@pytest.fixture
def prepared(repository, tmp_path, monkeypatch):
    repo, revision = repository
    raw = package.archive_bytes(repo, revision)
    parent = tmp_path / "synthetic-private"
    parent.mkdir()
    archive = parent / "transfer.zip"
    archive.write_bytes(raw)
    anchor = parent / "original-anchor.json"
    anchor.write_bytes(install.packed({"project": "marty-production-fixture", "synthetic_secret": "NEVER_OUTPUT"}))
    tooling_bodies = {name: (ROOT / "scripts" / name).read_bytes() for name in install.BOOTSTRAP}
    tooling = install.decode(install.packed({"schema": install.TOOLING_SCHEMA, "source_commit": "b" * 40,
        "files": {name: install.file_reference(body) for name, body in tooling_bodies.items()}}))
    inventory = parent / "trusted-tooling.json"
    inventory.write_bytes(install.packed(tooling))
    windows = SyntheticWindows()

    @contextmanager
    def trusted(inventory_path, expected, scripts):
        del scripts
        current = install.checked_tooling(Path(inventory_path).read_bytes(), expected)
        install.require(current == tooling)
        yield tooling, tooling_bodies, windows, package

    monkeypatch.setattr(install, "trusted_tooling", trusted)
    monkeypatch.setattr(install, "os", SimpleNamespace(name="nt", fsync=os.fsync, fstat=os.fstat))
    options = {"archive": archive, "archive_sha256": install.digest(raw), "commit": revision,
        "destination": parent / ("windows-owner-source-" + revision + "-" + install.digest(raw)[:16]),
        "anchor": anchor, "anchor_sha256": install.digest(anchor.read_bytes()), "project": "marty-production-fixture",
        "tooling_inventory_path": inventory, "tooling_inventory_sha256": install.digest(inventory.read_bytes())}
    return options, windows, tooling_bodies, tooling


def test_install_publishes_only_after_creation_and_reproof_exits(prepared):
    options, windows, _bodies, _tooling = prepared
    before = options["anchor"].read_bytes()
    result = install.install(**options)
    root = options["destination"]
    assert result["source_private_placement_verified"] is True
    assert all(result[name] is False for name in
               ("original_anchor_replayed", "active_callers_migrated", "credential_admission", "runtime_admission"))
    assert options["anchor"].read_bytes() == before
    assert not (root / install.PENDING).exists() and (root / install.INSTALLATION).is_file()
    record = install.checked_installation((root / install.INSTALLATION).read_bytes(), result["installation_sha256"], root)
    assert (root / "source.zip").read_bytes() == options["archive"].read_bytes()
    assert (root / install.RUNNER).read_bytes() == install.runner_bytes(record["tooling"])
    promotion = windows.events.index(("exit", install.PENDING, False, True))
    assert any(event[:2] == ("exit", options["anchor"].name) for event in windows.events[:promotion])
    assert any(event[:2] == ("exit", "source.zip") for event in windows.events[:promotion])
    assert any(event[:2] == ("enter", install.INSTALLATION) for event in windows.events[promotion:])
    with pytest.raises(ValueError):
        install.install(**options)


@pytest.mark.parametrize("field", ["archive_sha256", "anchor_sha256", "tooling_inventory_sha256", "project", "destination"])
def test_bad_external_binding_refuses_before_destination_creation(prepared, field):
    options, _windows, _bodies, _tooling = prepared
    target = options["destination"]
    changed = dict(options)
    changed[field] = (target.with_name("not-versioned") if field == "destination" else
                      "marty-production-other" if field == "project" else "0" * 64)
    with pytest.raises(ValueError):
        install.install(**changed)
    assert not target.exists() and not target.with_name("not-versioned").exists()


@pytest.mark.parametrize("name", ["source.zip", "original-anchor.json", "trusted-tooling.json"])
def test_late_creation_input_failure_cannot_publish_ready_marker(prepared, name):
    options, windows, _bodies, _tooling = prepared
    if name == "trusted-tooling.json":
        original = install.trusted_tooling
        @contextmanager
        def fail_after(*args):
            with original(*args) as value:
                yield value
            raise ValueError("synthetic late tooling custody failure")
        install.trusted_tooling = fail_after
    else:
        def fail(path, write_value, directory, rename):
            if path.name == name and write_value is None and not directory and rename is None:
                raise ValueError("synthetic late input custody failure")
        windows.fail = fail
    with pytest.raises(ValueError):
        install.install(**options)
    assert not (options["destination"] / install.INSTALLATION).exists()


def test_late_source_exit_suppresses_pending_marker_promotion(prepared):
    options, windows, _bodies, _tooling = prepared
    promote_entered = lambda: any(row == ("enter", install.PENDING, False, True) for row in windows.events)
    def fail(path, write_value, directory, rename):
        if path.name == "selfhost_windows_selection.py" and promote_entered() and write_value is None:
            raise ValueError("synthetic late source custody failure")
    windows.fail = fail
    with pytest.raises(ValueError):
        install.install(**options)
    root = options["destination"]
    assert (root / install.PENDING).exists() and not (root / install.INSTALLATION).exists()


def test_new_file_allocation_identity_is_preserved_before_write(tmp_path):
    windows = SyntheticWindows()
    windows.replace_before_write = True
    path = tmp_path / "new-source.py"
    with pytest.raises(ValueError):
        install.private_write(path, b"# approved bytes", windows, install.MAX_SOURCE)
    assert path.read_bytes() == b"" and path.with_name(path.name + ".replaced").read_bytes() == b""


def test_extra_source_membership_is_rejected_even_when_file_hashes_match(prepared):
    options, windows, bodies, tooling = prepared
    receipt = install.install(**options)
    root = options["destination"]
    record = install.checked_installation((root / install.INSTALLATION).read_bytes(), receipt["installation_sha256"], root)
    raw = options["archive"].read_bytes()
    files = install.installation_files(record, raw, install.archive_files(raw, options["commit"], package), bodies, ready=True)
    (root / "source/scripts/__pycache__").mkdir()
    with pytest.raises(ValueError):
        with install.hold_files(root, files, windows):
            pytest.fail("Untracked source directory accepted")


def test_runner_bytes_do_not_depend_on_inventory_dictionary_insertion_order(prepared):
    _options, _windows, _bodies, tooling = prepared
    reordered = copy.deepcopy(tooling)
    reordered["files"] = dict(reversed(list(reordered["files"].items())))
    for name, value in reordered["files"].items():
        reordered["files"][name] = dict(reversed(list(value.items())))
    assert install.runner_bytes(tooling) == install.runner_bytes(reordered)


@pytest.mark.parametrize("change", [
    lambda v: v["files"].pop("selfhost_windows_inputs.py"),
    lambda v: v["files"]["selfhost_windows_inputs.py"].update(bytes=True),
    lambda v: v.update(source_commit="main"),
    lambda v: v["files"]["selfhost_windows_inputs.py"].update(sha256="bad"),
])
def test_malformed_bootstrap_inventory_refuses(prepared, change):
    _options, _windows, _bodies, tooling = prepared
    changed = copy.deepcopy(tooling)
    change(changed)
    raw = install.packed(changed)
    with pytest.raises(ValueError):
        install.checked_tooling(raw, install.digest(raw))


def test_generated_runner_requires_isolation_before_bootstrap_reads(prepared):
    options, _windows, _bodies, _tooling = prepared
    receipt = install.install(**options)
    runner = options["destination"] / install.RUNNER
    (options["destination"] / "bootstrap/selfhost_windows_inputs.py").write_text("raise RuntimeError('DO_NOT_EXECUTE')")
    result = subprocess.run([sys.executable, str(runner), "--expected-installation-sha256", receipt["installation_sha256"]],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "DO_NOT_EXECUTE" not in result.stderr and "Versioned source replay refused" in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="Non-Windows refusal")
def test_installation_has_no_posix_privacy_fallback(tmp_path):
    with pytest.raises(ValueError):
        install.install(tmp_path / "absent.zip", "a" * 64, "b" * 40, tmp_path / "destination",
                        tmp_path / "anchor", "c" * 64, "marty-production-fixture", tmp_path / "tooling", "d" * 64)
    assert list(tmp_path.iterdir()) == []


def test_verified_loader_executes_held_bytes_and_retains_module_origin(tmp_path):
    path = tmp_path / "source.py"
    path.write_text("raise RuntimeError('unheld path content')")
    loader = install.VerifiedLoader(path, b"VALUE = 'verified held bytes'\n")
    import types
    module = types.ModuleType("synthetic_source")
    loader.exec_module(module)
    assert module.VALUE == "verified held bytes" and module.__file__ == str(path)


def test_installed_directory_inventory_is_bounded(monkeypatch):
    monkeypatch.setattr(install, "MAX_DIRECTORIES", 3)
    with pytest.raises(ValueError):
        install.membership({"one/two/three/file.py": b"source"})


def test_tooling_inventory_uses_reviewed_git_objects_not_current_files(repository):
    root, _revision = repository
    expected = {}
    for name in install.BOOTSTRAP:
        raw = ("# synthetic committed bootstrap " + name + "\n").encode()
        (root / "scripts" / name).write_bytes(raw)
        expected[name] = install.file_reference(raw)
    revision = commit(root)
    for name in install.BOOTSTRAP:
        (root / "scripts" / name).write_text("# unreviewed working-tree substitute\n")
    result = install.bootstrap_inventory(root, revision, package)
    assert result == {"schema": install.TOOLING_SCHEMA, "source_commit": revision, "files": expected}
    raw = install.packed(result)
    assert install.checked_tooling(raw, install.digest(raw)) == result
