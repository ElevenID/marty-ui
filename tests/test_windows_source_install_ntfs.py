"""Actual NTFS custody and isolated source replay, using synthetic owner data.

The continuation fixture substitutes runtime proofs only while authoring its
history. The generated child uses the committed reader unchanged and invokes no
runtime callbacks. Nothing here reads or changes a deployed owner or task.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import package_windows_owner_source as package
import selfhost_windows_inputs as windows
import selfhost_windows_selection as selection
import selfhost_windows_source_install as install
from test_selfhost_windows_continuation import candidate, advance
from test_selfhost_windows_inputs import private_fixture, powershell
from test_windows_owner_source_bundle import repository, git

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Actual Windows NTFS source installation")


@pytest.fixture(scope="module")
def committed_bootstrap():
    """Read Git objects so autocrlf cannot silently change the trusted bytes."""
    revision = git(ROOT, "rev-parse", "HEAD")
    inventory = install.bootstrap_inventory(ROOT, revision, package)
    _tree, entries = package.object_inventory(ROOT, revision)
    blobs = package.read_blobs(ROOT, {"scripts/" + name: entries["scripts/" + name]
                                     for name in install.BOOTSTRAP})
    bodies = {name: blobs["scripts/" + name] for name in install.BOOTSTRAP}
    assert inventory["files"] == {name: install.file_reference(raw) for name, raw in bodies.items()}
    return revision, inventory, bodies


def options_for(root, raw, revision, bootstrap, *, anchor=None, project="marty-production-fixture"):
    _bootstrap_revision, inventory, bodies = bootstrap
    scripts = root / "reviewed-bootstrap"
    scripts.mkdir()
    for name, body in bodies.items():
        (scripts / name).write_bytes(body)
    inventory_path = root / "reviewed-bootstrap.json"
    inventory_path.write_bytes(install.packed(inventory))
    archive = root / "source-transfer.zip"
    archive.write_bytes(raw)
    if anchor is None:
        anchor = root / "original-anchor.json"
        anchor.write_bytes(install.packed({"project": project, "fixture": "PUBLIC_SYNTHETIC"}))
    return {"archive": archive, "archive_sha256": install.digest(raw), "commit": revision,
            "destination": root / ("windows-owner-source-" + revision + "-" + install.digest(raw)[:16]),
            "anchor": anchor, "anchor_sha256": install.digest(anchor.read_bytes()), "project": project,
            "tooling_inventory_path": inventory_path,
            "tooling_inventory_sha256": install.digest(inventory_path.read_bytes()), "scripts": scripts}


@pytest.fixture
def prepared_native(repository, committed_bootstrap):
    repo, revision = repository
    raw = package.archive_bytes(repo, revision)
    with private_fixture() as (root, _token):
        yield options_for(root, raw, revision, committed_bootstrap), committed_bootstrap[2]


def installed_files(options, receipt, bodies):
    root = options["destination"]
    record = install.checked_installation((root / install.INSTALLATION).read_bytes(),
                                         receipt["installation_sha256"], root)
    raw = options["archive"].read_bytes()
    return install.installation_files(record, raw, install.archive_files(raw, options["commit"], package),
                                      bodies, ready=True)


def broaden_read_acl(path):
    quoted = str(path).replace("'", "''")
    powershell("$p='" + quoted + "';$a=[IO.File]::GetAccessControl($p);"
               "$s=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545');"
               "$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("
               "$s,'Read','Allow'));[IO.File]::SetAccessControl($p,$a)")


def test_native_install_publishes_private_source_and_refuses_overwrite(prepared_native):
    options, bodies = prepared_native
    anchor_before = options["anchor"].read_bytes()
    receipt = install.install(**options)
    root = options["destination"]
    assert receipt["source_private_placement_verified"] is True
    assert all(receipt[key] is False for key in
               ("original_anchor_replayed", "active_callers_migrated", "credential_admission", "runtime_admission"))
    assert options["anchor"].read_bytes() == anchor_before
    assert (root / install.INSTALLATION).is_file() and not (root / install.PENDING).exists()
    files = installed_files(options, receipt, bodies)
    source = root / "source/scripts/selfhost_windows_selection.py"
    with install.hold_files(root, files, windows):
        for mutation in (lambda: source.write_bytes(b"PUBLIC_REPLACEMENT"), source.unlink,
                         lambda: root.rename(root.with_name(root.name + "-moved"))):
            with pytest.raises(OSError):
                mutation()
    before = {name: (root / name).read_bytes() for name in files}
    with pytest.raises(ValueError):
        install.install(**options)
    assert {name: (root / name).read_bytes() for name in files} == before
    assert options["anchor"].read_bytes() == anchor_before


@pytest.mark.parametrize("change", ["broad-acl", "hardlink", "untracked-bytecode", "junction"])
def test_native_source_inventory_refuses_unsafe_placement(prepared_native, change):
    options, bodies = prepared_native
    receipt = install.install(**options)
    root = options["destination"]
    files = installed_files(options, receipt, bodies)
    source = root / "source/scripts/selfhost_windows_selection.py"
    scripts = source.parent
    relocated = root.parent / "relocated-scripts"
    junction_created = False
    try:
        if change == "broad-acl":
            broaden_read_acl(source)
        elif change == "hardlink":
            os.link(source, root.parent / "linked-source.py")
        elif change == "untracked-bytecode":
            cache = scripts / "__pycache__"
            cache.mkdir()
            (cache / "selfhost_windows_selection.cpython-312.pyc").write_bytes(b"PUBLIC_UNTRACKED")
        else:
            scripts.rename(relocated)
            powershell("New-Item -ItemType Junction -Path '" + str(scripts).replace("'", "''")
                       + "' -Target '" + str(relocated).replace("'", "''") + "' | Out-Null")
            junction_created = True
        with pytest.raises(ValueError):
            with install.hold_files(root, files, windows):
                pytest.fail("Unsafe source placement accepted by actual NTFS custody")
    finally:
        if junction_created:
            # Remove the known synthetic junction itself, never its target.
            scripts.rmdir()
        if relocated.exists():
            relocated.rename(scripts)


def test_native_allocation_replacement_is_rejected_before_source_write(monkeypatch):
    with private_fixture() as (root, _token):
        path = root / "allocated-source.py"
        original = windows._held_private_input
        saved = root / "original-allocation.py"
        replaced = []

        @contextmanager
        def replace_before_write(file, value=None, **kwargs):
            if file == path and value is not None:
                file.rename(saved)
                file.write_bytes(b"")
                assert windows._path_identities(file) != kwargs["_expected_identities"]
                replaced.append(True)
            with original(file, value, **kwargs) as raw:
                yield raw

        monkeypatch.setattr(windows, "_held_private_input", replace_before_write)
        with pytest.raises(ValueError):
            install.private_write(path, b"# PUBLIC_APPROVED_SOURCE\n", windows, install.MAX_SOURCE)
        assert replaced == [True]
        assert path.read_bytes() == saved.read_bytes() == b""


def test_native_late_source_acl_failure_preserves_pending_without_ready(monkeypatch, prepared_native):
    options, _bodies = prepared_native
    original = install.hold_files
    changed = []

    @contextmanager
    def fail_during_promotion(root, files, native, *, promote=False):
        with original(root, files, native, promote=promote):
            yield
            if promote:
                broaden_read_acl(root / "source/scripts/selfhost_windows_selection.py")
                changed.append(True)

    monkeypatch.setattr(install, "hold_files", fail_during_promotion)
    with pytest.raises(ValueError):
        install.install(**options)
    root = options["destination"]
    assert changed == [True]
    assert (root / install.PENDING).is_file() and not (root / install.INSTALLATION).exists()
    assert install.digest(options["anchor"].read_bytes()) == options["anchor_sha256"]


# A test-only child driver adds a real ACL change after selected_inputs has
# completed, while the source handles are still held. It executes the same
# exact bootstrap bytes and replay function as the generated runner.
LATE_SOURCE_FAILURE_CHILD = r'''
from contextlib import contextmanager
import hashlib,json,pathlib,subprocess,sys,types
root=pathlib.Path(sys.argv[1]);expected=sys.argv[2];references=json.loads(sys.argv[3])
bodies={};modules={}
for filename,reference in references.items():
 path=root/'bootstrap'/filename
 raw=path.read_bytes()
 assert len(raw)==reference['bytes'] and hashlib.sha256(raw).hexdigest()==reference['sha256']
 bodies[filename]=raw
 name='_source_test_'+filename[:-3]
 module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
 exec(compile(raw,str(path),'exec'),module.__dict__);modules[filename]=module
installer=modules['selfhost_windows_source_install.py'];original=installer.hold_files
@contextmanager
def changed_after_replay(root,files,windows,**kwargs):
 with original(root,files,windows,**kwargs):
  yield
  source=root/'source/scripts/selfhost_windows_selection.py'
  quoted=str(source).replace("'","''")
  command=("$ErrorActionPreference='Stop';$p='"+quoted+"';$a=[IO.File]::GetAccessControl($p);"
   "$s=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545');"
   "$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("
   "$s,'Read','Allow'));[IO.File]::SetAccessControl($p,$a)")
  subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],
                 check=True,capture_output=True,timeout=15)
  print('SOURCE_ACL_CHANGED_AFTER_SELECTION_EXIT',file=sys.stderr)
installer.hold_files=changed_after_replay
try:
 result=installer.replay(root,expected,windows=modules['selfhost_windows_inputs.py'],
  package=modules['package_windows_owner_source.py'],bootstrap_bodies=bodies)
except ValueError:
 print('EXPECTED_LATE_SOURCE_REFUSAL',file=sys.stderr);sys.exit(1)
print(json.dumps(result,sort_keys=True))
'''


def owner_snapshot(root, excluded):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*")
            if path.is_file() and not any(parent == path or parent in path.parents for parent in excluded)}


def test_isolated_generated_runner_resolves_original_anchor_and_refuses_late_source_failure(
        monkeypatch, committed_bootstrap):
    revision, inventory, _bodies = committed_bootstrap
    raw = package.archive_bytes(ROOT, revision)
    with candidate(monkeypatch) as (root, phase, transaction, outcome, anchor, config):
        # Retain the original anchor while moving the selected generation to a
        # later journal, then checkpoint again so local/global sequences differ.
        advance(monkeypatch, anchor)
        next_path, next_config = transaction(2)
        assert selection.prepare(next_path) == 2
        old, new = (Path(next_config[key]) for key in ("current_secrets", "renewed_secrets"))
        with selection.activation_admission(next_config,
                {path.name: path.read_bytes() for path in old.iterdir()},
                {path.name: path.read_bytes() for path in new.iterdir()},
                Path(next_config["current_env"]).read_bytes(), Path(next_config["renewed_env"]).read_bytes()):
            pass
        phase["active"] = new
        outcome(next_config, "activated")
        selection.complete(next_path)
        _prior, newest, _continued = advance(monkeypatch, anchor)
        with selection.selected_inputs(anchor) as lease:
            assert lease.journal_path == newest and lease.secrets_dir == new
            expected = (lease.sequence, lease.generation_sequence, lease.selected_sha256)
        assert expected[:2] == (1, 2)
        options = options_for(root, raw, revision, committed_bootstrap,
                              anchor=anchor, project=config["project"])
        receipt = install.install(**options)
        destination = options["destination"]
        before = owner_snapshot(root, [destination])
        command = [sys.executable, "-I", "-B", str(destination / install.RUNNER),
                   "--expected-installation-sha256", receipt["installation_sha256"]]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stderr
        state = json.loads(result.stdout)
        assert (state["sequence"], state["generation_sequence"], state["selected_sha256"]) == expected
        assert state["original_anchor_replayed"] is True
        assert state["anchor_sha256"] == options["anchor_sha256"] and state["source_commit"] == revision
        assert all(state[key] is False for key in
                   ("active_callers_migrated", "credential_admission", "runtime_admission"))
        assert not list(destination.rglob("*.pyc")) and not list(destination.rglob("__pycache__"))
        assert owner_snapshot(root, [destination]) == before

        # A source exit failure must suppress the completed selection summary.
        failed = subprocess.run([sys.executable, "-I", "-B", "-c", LATE_SOURCE_FAILURE_CHILD,
                                 str(destination), receipt["installation_sha256"],
                                 json.dumps(inventory["files"])],
                                capture_output=True, text=True, timeout=120)
        assert failed.returncode == 1 and failed.stdout == "", (failed.stdout, failed.stderr)
        assert "SOURCE_ACL_CHANGED_AFTER_SELECTION_EXIT" in failed.stderr
        assert "EXPECTED_LATE_SOURCE_REFUSAL" in failed.stderr
        assert owner_snapshot(root, [destination]) == before
        # The original owner can still be read after failed candidate custody.
        with selection.selected_inputs(anchor) as lease:
            assert (lease.sequence, lease.generation_sequence, lease.selected_sha256) == expected
