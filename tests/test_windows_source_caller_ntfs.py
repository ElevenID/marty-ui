"""Fresh isolated caller proofs with actual private NTFS synthetic inputs.

The owner fixture substitutes runtime proofs only when authoring its history.
Every caller check uses committed source bytes, the real Windows custody code,
and an audit hook that refuses any child process. No deployed owner, scheduled
task, Docker daemon, credential or service is read or changed.
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
from test_selfhost_windows_inputs import powershell
from test_windows_source_install_ntfs import (
    committed_bootstrap, options_for, broaden_read_acl, owner_snapshot,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Actual Windows NTFS operational caller")


CHECK_CHILD = r'''
import runpy,sys,types
script,expected,preload=sys.argv[1:]
if preload:
 module=types.ModuleType(preload)
 module.__file__='PUBLIC_PRELOADED_OWNER.py'
 sys.modules[preload]=module
def no_runtime_processes(event,arguments):
 if event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn'}:
  raise AssertionError('Read-only caller attempted a runtime process')
sys.addaudithook(no_runtime_processes)
sys.argv=[script,'--expected-profile-sha256',expected,'--check-only']
runpy.run_path(script,run_name='__main__')
'''


APPEND_CHILD = r'''
import hashlib,pathlib,sys,types
script,script_sha,inputs,inputs_sha,log,line=sys.argv[1:]
def no_runtime_processes(event,arguments):
 if event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn'}:
  raise AssertionError('Log proof attempted a runtime process')
sys.addaudithook(no_runtime_processes)
def verified_module(name,path,expected):
 raw=pathlib.Path(path).read_bytes()
 assert hashlib.sha256(raw).hexdigest()==expected
 module=types.ModuleType(name);module.__file__=path;sys.modules[name]=module
 exec(compile(raw,path,'exec'),module.__dict__)
 return module
caller=verified_module('_public_native_caller_log',script,script_sha)
windows=verified_module('_public_native_inputs_log',inputs,inputs_sha)
try:
 caller.append_log(pathlib.Path(log),bytes.fromhex(line),windows)
except Exception:
 print('EXPECTED_PRIVATE_LOG_REFUSAL',file=sys.stderr);sys.exit(1)
print('PRIVATE_LOG_APPEND_VERIFIED')
'''


# This exercises only the journal writer and the actual read-only selected
# lease, creating test-owned fixture records without a renewal or Google call.
# The late-source action adds one real ACL fault after its pending write.
STATE_CHILD = r'''
from contextlib import ExitStack,contextmanager
import hashlib,json,os,pathlib,subprocess,sys,types
script,script_sha,profile_sha,action=sys.argv[1:]
allow_acl_fault=False
powershell_executable=str(pathlib.Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
def no_runtime_processes(event,arguments):
 if event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn'}:
  if event=='subprocess.Popen' and allow_acl_fault and arguments[0]==powershell_executable:return
  raise AssertionError('Hook-state proof attempted a runtime process')
sys.addaudithook(no_runtime_processes)
path=pathlib.Path(script);raw=path.read_bytes()
assert hashlib.sha256(raw).hexdigest()==script_sha
caller=types.ModuleType('_public_native_caller_state');caller.__file__=script
sys.modules[caller.__name__]=caller;exec(compile(raw,script,'exec'),caller.__dict__)
original_load=caller.load_bootstrap
def instrument(name,raw,path):
 module=original_load(name,raw,path)
 if path.name=='selfhost_windows_source_install.py' and action=='late-source':
  original=module.hold_files
  @contextmanager
  def late_source(root,files,native,**kwargs):
   global allow_acl_fault
   with original(root,files,native,**kwargs):
    yield
    source=root/'source/scripts/selfhost_windows_selection.py'
    quoted=str(source).replace("'","''")
    command=("$ErrorActionPreference='Stop';$p='"+quoted+"';$a=[IO.File]::GetAccessControl($p);"
     "$s=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545');"
     "$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("
     "$s,'Read','Allow'));[IO.File]::SetAccessControl($p,$a)")
    allow_acl_fault=True
    try:
     subprocess.run([powershell_executable,'-NoProfile','-NonInteractive','-Command',command],
                    executable=powershell_executable,capture_output=True,check=True,timeout=15)
    finally:allow_acl_fault=False
    print('SOURCE_ACL_CHANGED_AFTER_SELECTED_EXIT',file=sys.stderr)
  module.hold_files=late_source
 return module
caller.load_bootstrap=instrument
try:
 with ExitStack() as coordination:
  with caller.held_caller(path.parent/'caller.json',profile_sha) as values:
   profile,record,selection,renewal,recovery,native,installer=values
   if action in {'partial-intent','partial-complete'}:
    original=native._held_private_input
    target='000001.'+('intent' if action=='partial-intent' else 'complete')+'.json'
    @contextmanager
    def replace_allocation(file,value=None,**kwargs):
     if file.name==target and value is not None:
      replacement=file.with_name(file.name+'.replaced')
      try:file.rename(replacement)
      except PermissionError as error:
       # A held private state directory may reject the target-parent write
       # needed by MoveFileEx before a replacement can even be installed.
       # Accept only that concrete sharing refusal, with its original empty
       # allocation and identity intact. Other injection errors still fail.
       assert error.winerror==32
       assert native._path_identities(file)==kwargs['_expected_identities']
       assert file.read_bytes()==b'' and not replacement.exists()
       print('HOOK_ALLOCATION_REPLACEMENT_BLOCKED winerror=32',file=sys.stderr)
       raise
      file.write_bytes(b'')
      assert native._path_identities(file)!=kwargs['_expected_identities']
      print('REPLACED_HOOK_RECORD_ALLOCATION',file=sys.stderr)
     with original(file,value,**kwargs) as body:yield body
    native._held_private_input=replace_allocation
   state=coordination.enter_context(caller.held_hook_state(profile,profile_sha,record,native,installer))
   with selection.selected_inputs(pathlib.Path(record['anchor']['path'])) as lease:
    state.begin(lease)
  if action!='pending':state.complete()
 result={'completed':state.completed,'pending':state.pending}
except Exception as error:
 details=[]
 while error is not None and len(details)<5:
  details.append({'error_type':type(error).__name__,'winerror':getattr(error,'winerror',None)})
  error=error.__context__
 print('HOOK_STATE_REFUSAL_DETAILS '+json.dumps(details,sort_keys=True),file=sys.stderr)
 print('EXPECTED_HOOK_STATE_REFUSAL',file=sys.stderr);sys.exit(1)
print(json.dumps(result,sort_keys=True))
'''


@pytest.fixture(scope="module")
def installed_caller(committed_bootstrap):
    """One immutable installation; each test restores its synthetic fault."""
    revision, _inventory, _bodies = committed_bootstrap
    raw = package.archive_bytes(ROOT, revision)
    _tree, entries = package.object_inventory(ROOT, revision)
    name = "scripts/selfhost_windows_source_caller.py"
    body = package.read_blobs(ROOT, {name: entries[name]})[name]
    with pytest.MonkeyPatch.context() as monkeypatch:
        with candidate(monkeypatch) as (root, phase, transaction, outcome, anchor, config):
            # Retain the original anchor across multiple continuation links.
            # Local2/global3 also qualifies a real selected lease for the
            # synthetic hook-journal writer proofs below.
            advance(monkeypatch, anchor)
            for number in (2, 3):
                next_path, next_config = transaction(number)
                assert selection.prepare(next_path) == 2
                old, new = (Path(next_config[key]) for key in ("current_secrets", "renewed_secrets"))
                with selection.activation_admission(next_config,
                        {path.name: path.read_bytes() for path in old.iterdir()},
                        {path.name: path.read_bytes() for path in new.iterdir()},
                        Path(next_config["current_env"]).read_bytes(),
                        Path(next_config["renewed_env"]).read_bytes()):
                    pass
                phase["active"] = new
                outcome(next_config, "activated")
                selection.complete(next_path)
                if number == 2:
                    _prior, newest, _continued = advance(monkeypatch, anchor)
            with selection.selected_inputs(anchor) as lease:
                assert lease.journal_path == newest and lease.secrets_dir == new
                expected_selection = (lease.sequence, lease.generation_sequence, lease.selected_sha256)
            assert expected_selection[:2] == (2, 3)
            options = options_for(root, raw, revision, committed_bootstrap,
                                  anchor=anchor, project=config["project"])
            receipt = install.install(**options)
            caller_root = root / "operational-caller"
            caller_root.mkdir()
            script = caller_root / "run-owner.py"
            script.write_bytes(body)
            helper = root / "google-helper.py"
            helper.write_bytes(b"raise RuntimeError('PUBLIC_HOOK_MUST_NOT_EXECUTE_IN_CHECK_ONLY')\n")
            client_id, client_secret = root / "google-client-id", root / "google-client-secret"
            client_id.write_bytes(b"PUBLIC_SYNTHETIC_CLIENT_ID\n")
            client_secret.write_bytes(b"PUBLIC_SYNTHETIC_CLIENT_SECRET\n")
            docker = root / "synthetic-docker.exe"
            docker.write_bytes(b"PUBLIC_NOT_AN_EXECUTABLE\n")
            log = root / "operational-caller.log"
            log.write_bytes(b"PUBLIC_EXISTING_LOG_ENTRY\n")
            hook_state = root / "hook-state"
            hook_state.mkdir()
            profile = {
                "schema": "marty.windows-owner-source-caller/v1",
                "script_sha256": install.digest(body),
                "python": Path(sys.executable).absolute().as_posix(),
                "installation": {"root": options["destination"].as_posix(),
                                 "sha256": receipt["installation_sha256"]},
                "logical_project": "marty-selfhost-fixture",
                "log": log.as_posix(),
                "hook_state": hook_state.as_posix(),
                "hook": {
                    "helper": helper.as_posix(), "helper_sha256": install.digest(helper.read_bytes()),
                    "client_id": client_id.as_posix(), "client_secret": client_secret.as_posix(),
                    "docker": docker.as_posix(), "image": "python@sha256:" + "4" * 64,
                    "network": config["project"] + "_default", "timeout_seconds": 90,
                    "success_stdout": "PUBLIC_SYNTHETIC_GOOGLE_IDP_OK",
                },
            }
            profile_path = caller_root / "caller.json"
            profile_path.write_bytes(install.packed(profile))
            profile_sha = install.digest(profile_path.read_bytes())
            (hook_state / "owner.json").write_bytes(install.packed({
                "schema": "marty.windows-owner-source-hook-state/v1",
                "profile_sha256": profile_sha, "installation_sha256": receipt["installation_sha256"],
            }))
            (hook_state / "lock").write_bytes(b"")
            yield {
                "root": root, "source": options["destination"], "caller": caller_root,
                "script": script, "profile_path": profile_path, "profile": profile,
                "profile_sha256": profile_sha, "helper": helper, "hook_state": hook_state,
                "log": log, "anchor": anchor, "receipt": receipt,
                "expected_selection": expected_selection, "bootstrap": committed_bootstrap,
            }


def run_check(fixture, *, expected=None, preload=""):
    return subprocess.run([
        sys.executable, "-I", "-B", "-c", CHECK_CHILD, str(fixture["script"]),
        fixture["profile_sha256"] if expected is None else expected, preload,
    ], capture_output=True, timeout=120)


def assert_refused(result):
    assert result.returncode != 0
    assert result.stdout == b""
    assert result.stderr
    for sentinel in (b"PUBLIC_SYNTHETIC_CLIENT_ID", b"PUBLIC_SYNTHETIC_CLIENT_SECRET",
                     b"PUBLIC_HOOK_MUST_NOT_EXECUTE_IN_CHECK_ONLY"):
        assert sentinel not in result.stderr


def test_isolated_caller_check_replays_original_anchor_without_runtime_or_log_writes(installed_caller):
    fixture = installed_caller
    before = owner_snapshot(fixture["root"], [])
    result = run_check(fixture)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    state = json.loads(result.stdout)
    assert (state["sequence"], state["generation_sequence"], state["selected_sha256"]) == fixture["expected_selection"]
    assert state["result"] == "bindings-and-history-verified"
    assert state["source_commit"] == fixture["receipt"]["source_commit"]
    assert all(state[key] is False for key in
               ("active_callers_migrated", "credential_admission", "runtime_admission"))
    assert owner_snapshot(fixture["root"], []) == before


def test_isolated_caller_refuses_wrong_profile_pin_without_owner_or_log_changes(installed_caller):
    before = owner_snapshot(installed_caller["root"], [])
    assert_refused(run_check(installed_caller, expected="0" * 64))
    assert owner_snapshot(installed_caller["root"], []) == before


def test_isolated_caller_refuses_preloaded_owner_module(installed_caller):
    before = owner_snapshot(installed_caller["root"], [])
    assert_refused(run_check(installed_caller, preload="selfhost_windows_selection"))
    assert owner_snapshot(installed_caller["root"], []) == before


@contextmanager
def changed_file(path):
    original = path.read_bytes()
    try:
        path.write_bytes(original + b"\n# PUBLIC_UNREVIEWED_BYTES\n")
        yield
    finally:
        path.write_bytes(original)


@contextmanager
def linked_file(path, target):
    os.link(path, target)
    try:
        yield
    finally:
        target.unlink()


@contextmanager
def unexpected_entry(directory, *, cache=False):
    if cache:
        parent = directory / "__pycache__"
        parent.mkdir()
        path = parent / "unreviewed.cpython-312.pyc"
    else:
        parent = None
        path = directory / "unreviewed.py"
    path.write_bytes(b"PUBLIC_UNTRACKED_SOURCE\n")
    try:
        yield
    finally:
        path.unlink()
        if parent is not None:
            parent.rmdir()


@contextmanager
def junction_directory(directory, target):
    directory.rename(target)
    created = False
    try:
        powershell("New-Item -ItemType Junction -Path '" + str(directory).replace("'", "''")
                   + "' -Target '" + str(target).replace("'", "''") + "' | Out-Null")
        created = True
        yield
    finally:
        if created:
            directory.rmdir()
        target.rename(directory)


@contextmanager
def preserved_acl(path):
    quoted = str(path).replace("'", "''")
    original = subprocess.run([
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "$ErrorActionPreference='Stop';[IO.File]::GetAccessControl('" + quoted
        + "').GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)",
    ], capture_output=True, timeout=15, check=True).stdout.decode().strip()
    try:
        yield
    finally:
        powershell("$a=[Security.AccessControl.FileSecurity]::new();"
                   "$a.SetSecurityDescriptorSddlForm('" + original.replace("'", "''")
                   + "');[IO.File]::SetAccessControl('" + quoted + "',$a)")


@contextmanager
def broadened_acl(path):
    with preserved_acl(path):
        broaden_read_acl(path)
        yield


@pytest.mark.parametrize("change", [
    "source-bytes", "source-hardlink", "source-extra", "source-cache", "source-junction",
    "caller-bytes", "caller-hardlink", "caller-extra", "caller-cache", "caller-junction",
    "profile-bytes", "profile-hardlink", "helper-bytes", "helper-hardlink",
])
def test_isolated_caller_refuses_unreviewed_or_aliased_inputs(installed_caller, change):
    fixture = installed_caller
    before = owner_snapshot(fixture["root"], [])
    component, mutation = change.split("-", 1)
    paths = {
        "source": fixture["source"] / "source/scripts/selfhost_windows_selection.py",
        "caller": fixture["script"], "profile": fixture["profile_path"],
        "helper": fixture["helper"],
    }
    path = paths[component]
    if mutation == "bytes":
        fault = changed_file(path)
    elif mutation == "hardlink":
        fault = linked_file(path, fixture["root"] / "public-test-hardlink")
    elif mutation in {"extra", "cache"}:
        fault = unexpected_entry(path.parent, cache=mutation == "cache")
    else:
        fault = junction_directory(path.parent, fixture["root"] / "public-relocated-directory")
    with fault:
        log_before = fixture["log"].read_bytes()
        assert_refused(run_check(fixture))
        assert fixture["log"].read_bytes() == log_before
    assert owner_snapshot(fixture["root"], []) == before


@pytest.mark.parametrize("component", ["caller", "profile", "helper"])
def test_isolated_caller_requires_private_acl_for_every_new_input(installed_caller, component):
    fixture = installed_caller
    path = {"caller": fixture["script"], "profile": fixture["profile_path"], "helper": fixture["helper"]}[component]
    before = owner_snapshot(fixture["root"], [])
    with broadened_acl(path):
        assert_refused(run_check(fixture))
    assert owner_snapshot(fixture["root"], []) == before


def run_append(fixture, path, line):
    inputs = fixture["source"] / "bootstrap/selfhost_windows_inputs.py"
    return subprocess.run([
        sys.executable, "-I", "-B", "-c", APPEND_CHILD,
        str(fixture["script"]), fixture["profile"]["script_sha256"], str(inputs),
        fixture["bootstrap"][1]["files"]["selfhost_windows_inputs.py"]["sha256"],
        str(path), line.hex(),
    ], capture_output=True, timeout=120)


def test_native_caller_log_append_preserves_prefix_and_verifies_appended_bytes(installed_caller):
    root = installed_caller["root"] / "public-log-proof"
    root.mkdir()
    path = root / "owner.log"
    prefix = b'{"result":"PUBLIC_PRIOR_ENTRY"}\n'
    line = b'{"result":"PUBLIC_NEW_ENTRY"}\n'
    path.write_bytes(prefix)
    try:
        before_identity = path.stat().st_ino
        result = run_append(installed_caller, path, line)
        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
        assert result.stdout == b"PRIVATE_LOG_APPEND_VERIFIED\r\n" or result.stdout == b"PRIVATE_LOG_APPEND_VERIFIED\n"
        assert path.read_bytes() == prefix + line
        assert path.stat().st_ino == before_identity
    finally:
        path.unlink()
        root.rmdir()


@pytest.mark.parametrize("change", ["partial-prefix", "full-log", "hardlink", "broad-acl", "junction"])
def test_native_caller_log_refusal_never_repairs_or_truncates_existing_bytes(installed_caller, change):
    fixture = installed_caller
    root = fixture["root"] / "public-log-refusal"
    root.mkdir()
    path = root / "owner.log"
    prefix = b"PUBLIC_UNFINISHED_ENTRY" if change == "partial-prefix" else (
        b"x" * (8 * 1024 * 1024 - 1) + b"\n" if change == "full-log" else b"PUBLIC_PRIOR_ENTRY\n")
    path.write_bytes(prefix)

    @contextmanager
    def unchanged():
        yield

    fault = (
        linked_file(path, fixture["root"] / "public-log-hardlink") if change == "hardlink" else
        broadened_acl(path) if change == "broad-acl" else
        junction_directory(root, fixture["root"] / "public-relocated-log") if change == "junction" else unchanged()
    )
    try:
        with fault:
            result = run_append(fixture, path, b"PUBLIC_NEW_ENTRY\n")
            assert result.returncode == 1 and result.stdout == b""
            assert b"EXPECTED_PRIVATE_LOG_REFUSAL" in result.stderr
            assert path.read_bytes() == prefix
    finally:
        path.unlink()
        root.rmdir()


def run_state(fixture, action):
    return subprocess.run([
        sys.executable, "-I", "-B", "-c", STATE_CHILD, str(fixture["script"]),
        fixture["profile"]["script_sha256"], fixture["profile_sha256"], action,
    ], capture_output=True, timeout=120)


@contextmanager
def synthetic_state_records(fixture):
    """Restore only this test's isolated synthetic journal after fault proofs."""
    root = fixture["hook_state"]
    before = {path.name: path.read_bytes() for path in root.iterdir()}
    assert set(before) == {"owner.json", "lock"}
    try:
        yield root
    finally:
        for path in root.iterdir():
            if path.name not in before:
                path.unlink()
        for name, raw in before.items():
            if (root / name).read_bytes() != raw:
                (root / name).write_bytes(raw)


def test_native_hook_journal_publishes_and_replays_exact_completed_pair(installed_caller):
    fixture = installed_caller
    before = owner_snapshot(fixture["root"], [fixture["hook_state"]])
    with synthetic_state_records(fixture) as root:
        result = run_state(fixture, "complete")
        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
        assert json.loads(result.stdout) == {"completed": 1, "pending": False}
        intent_raw = (root / "000001.intent.json").read_bytes()
        intent = install.decode(intent_raw)
        complete = install.decode((root / "000001.complete.json").read_bytes())
        assert (intent["sequence"], intent["generation_sequence"], intent["selected_sha256"]) == fixture["expected_selection"]
        assert intent["profile_sha256"] == fixture["profile_sha256"]
        assert intent["installation_sha256"] == fixture["receipt"]["installation_sha256"]
        assert complete["intent_sha256"] == install.digest(intent_raw)
        assert complete["result"] == "google-idp-verified"
        journal_before_check = owner_snapshot(root, [])
        checked = run_check(fixture)
        assert checked.returncode == 0, checked.stderr.decode("utf-8", errors="replace")
        assert owner_snapshot(root, []) == journal_before_check
    assert owner_snapshot(fixture["root"], [fixture["hook_state"]]) == before


@pytest.mark.parametrize("change", [
    "pending", "empty-intent", "empty-completion", "changed-intent", "boolean-completion-attempt", "unexpected-entry",
])
def test_native_hook_history_refuses_pending_or_corrupt_records_without_changes(installed_caller, change):
    fixture = installed_caller
    with synthetic_state_records(fixture) as root:
        result = run_state(fixture, "pending" if change in {"pending", "empty-intent"} else "complete")
        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
        if change in {"empty-intent", "empty-completion"}:
            (root / ("000001.intent.json" if change == "empty-intent" else "000001.complete.json")).write_bytes(b"")
        elif change == "changed-intent":
            path = root / "000001.intent.json"
            value = install.decode(path.read_bytes())
            value["selected_sha256"] = "0" * 64
            path.write_bytes(install.packed(value))
        elif change == "boolean-completion-attempt":
            path = root / "000001.complete.json"
            value = install.decode(path.read_bytes())
            value["attempt"] = True
            path.write_bytes(install.packed(value))
        elif change == "unexpected-entry":
            (root / "unreviewed.json").write_bytes(b"{}\n")
        before = owner_snapshot(fixture["root"], [])
        assert_refused(run_check(fixture))
        assert owner_snapshot(fixture["root"], []) == before


@pytest.mark.parametrize("phase", ["intent", "complete"])
def test_native_hook_record_allocation_replacement_preserves_failed_evidence(installed_caller, phase):
    fixture = installed_caller
    with synthetic_state_records(fixture) as root:
        result = run_state(fixture, "partial-" + phase)
        assert result.returncode == 1 and result.stdout == b""
        replaced = b"REPLACED_HOOK_RECORD_ALLOCATION" in result.stderr
        blocked = b"HOOK_ALLOCATION_REPLACEMENT_BLOCKED winerror=32" in result.stderr
        assert replaced != blocked, result.stderr.decode("utf-8", errors="replace")
        assert b"EXPECTED_HOOK_STATE_REFUSAL" in result.stderr
        path = root / f"000001.{phase}.json"
        assert path.read_bytes() == b""
        replacement = path.with_name(path.name + ".replaced")
        if replaced:
            assert replacement.read_bytes() == b""
        else:
            assert not replacement.exists()
        if phase == "intent":
            assert not (root / "000001.complete.json").exists()
        before = owner_snapshot(fixture["root"], [])
        assert_refused(run_check(fixture))
        assert owner_snapshot(fixture["root"], []) == before


def test_native_hook_intent_survives_late_source_failure_without_completion(installed_caller):
    fixture = installed_caller
    source = fixture["source"] / "source/scripts/selfhost_windows_selection.py"
    before = owner_snapshot(fixture["root"], [fixture["hook_state"]])
    with synthetic_state_records(fixture) as root:
        with preserved_acl(source):
            result = run_state(fixture, "late-source")
            assert result.returncode == 1 and result.stdout == b""
            assert b"SOURCE_ACL_CHANGED_AFTER_SELECTED_EXIT" in result.stderr
            assert b"EXPECTED_HOOK_STATE_REFUSAL" in result.stderr
            assert (root / "000001.intent.json").is_file()
            assert not (root / "000001.complete.json").exists()
        pending = owner_snapshot(root, [])
        assert_refused(run_check(fixture))
        assert owner_snapshot(root, []) == pending
    assert owner_snapshot(fixture["root"], [fixture["hook_state"]]) == before


@pytest.mark.parametrize("change", ["lock-hardlink", "owner-hardlink", "owner-broad-acl", "junction", "held-lock"])
def test_native_hook_state_requires_private_exclusive_custody(installed_caller, change):
    fixture = installed_caller
    state = fixture["hook_state"]
    if change in {"lock-hardlink", "owner-hardlink"}:
        path = state / ("lock" if change == "lock-hardlink" else "owner.json")
        fault = linked_file(path, fixture["root"] / "public-hook-state-hardlink")
    elif change == "owner-broad-acl":
        fault = broadened_acl(state / "owner.json")
    elif change == "junction":
        fault = junction_directory(state, fixture["root"] / "public-relocated-hook-state")
    else:
        fault = windows.hold_private_input(state / "lock", exclusive=True)
    before = owner_snapshot(fixture["root"], [])
    with fault:
        assert_refused(run_check(fixture))
    assert owner_snapshot(fixture["root"], []) == before
