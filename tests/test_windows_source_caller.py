"""Operational caller contracts with explicit, inert owner/runtime adapters.

These tests exercise dispatch, generation binding and publication ordering.
Actual Windows handle, ACL and namespace evidence belongs to the NTFS suite.
"""
from contextlib import contextmanager
import copy
import json
from pathlib import Path, PureWindowsPath
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import selfhost_windows_source_caller as caller
import selfhost_windows_source_install as install
from test_windows_source_install import SyntheticWindows

PROJECT = "marty-production-fixture"
LOGICAL_PROJECT = "marty-selfhost-fixture"
IMAGE = "python@sha256:" + "4" * 64
SUCCESS = "PUBLIC_SYNTHETIC_GOOGLE_IDP_OK"
PROFILE_ROOT = PureWindowsPath(r"C:\Private\owner-caller")


def profile_value():
    profile = {
        "schema": "marty.windows-owner-source-caller/v1",
        "script_sha256": "1" * 64,
        "python": r"C:\Python312\python.exe",
        "installation": {
            "root": r"C:\Private\windows-owner-source-" + "a" * 40 + "-" + "b" * 16,
            "sha256": "2" * 64,
        },
        "logical_project": LOGICAL_PROJECT,
        "log": r"C:\Private\owner.log",
        "hook_state": "C:/Private/hook-state",
        "hook": {
            "helper": r"C:\Private\google_helper.py",
            "helper_sha256": "3" * 64,
            "client_id": r"C:\Private\google_client_id",
            "client_secret": r"C:\Private\google_client_secret",
            "docker": r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
            "image": IMAGE,
            "network": PROJECT + "_default",
            "timeout_seconds": 90,
            "success_stdout": SUCCESS,
        },
    }
    for key in ("python", "log"):
        profile[key] = profile[key].replace("\\", "/")
    profile["installation"]["root"] = profile["installation"]["root"].replace("\\", "/")
    for key in ("helper", "client_id", "client_secret", "docker"):
        profile["hook"][key] = profile["hook"][key].replace("\\", "/")
    return profile


def test_profile_requires_canonical_bytes_and_external_digest():
    value = profile_value()
    raw = install.packed(value)
    assert caller.checked_profile(raw, install.digest(raw), PROFILE_ROOT) == value
    invalid = [
        (raw, "0" * 64),
        (json.dumps(value, indent=2).encode(), None),
        (raw.replace(b'{"hook":', b'{"schema":"duplicate","hook":', 1), None),
        (b"{}\n", None),
        (b"null\n", None),
        (b" " * (64 * 1024 + 1), None),
    ]
    for candidate, expected in invalid:
        with pytest.raises(ValueError):
            caller.checked_profile(candidate, expected or install.digest(candidate), PROFILE_ROOT)


@pytest.mark.parametrize("field,value", [
    (("schema",), "marty.windows-owner-source-caller/v2"),
    (("unexpected",), True),
    (("script_sha256",), "A" * 64),
    (("script_sha256",), "1" * 63),
    (("python",), "python.exe"),
    (("python",), "//server/share/python.exe"),
    (("python",), "C:/Python312/python.exe:stream"),
    (("python",), "C:/Python312/../Python312/python.exe"),
    (("python",), r"C:\Python312\python.exe"),
    (("installation", "extra"), "unreviewed"),
    (("installation", "sha256"), "2" * 63),
    (("logical_project",), PROJECT),
    (("hook_state",), "C:/Private/owner-caller/state"),
    (("hook_state",), "C:/Private"),
    (("hook", "image"), "python:3.12"),
    (("hook", "network"), "default"),
    (("hook", "timeout_seconds"), True),
    (("hook", "timeout_seconds"), 91),
    (("hook", "success_stdout"), ""),
    (("hook", "success_stdout"), "first\nsecond"),
    (("hook", "success_stdout"), "x" * 65537),
    (("hook", "helper_sha256"), "3" * 63),
    (("hook", "client_secret"), "C:/Private/NUL"),
], ids=[
    "schema", "unknown-field", "uppercase-script-hash", "short-script-hash",
    "relative-python", "unc-python", "ads-python", "parent-python",
    "noncanonical-profile-python",
    "unknown-installation-field", "short-installation-hash", "wrong-logical-namespace",
    "caller-contained-state", "ancestor-state",
    "mutable-image", "unbound-network", "boolean-timeout", "changed-timeout",
    "empty-hook-result", "multiline-hook-result", "oversize-hook-result",
    "short-helper-hash", "device-client-path",
])
def test_profile_refuses_unreviewed_or_ambiguous_contract(field, value):
    profile = profile_value()
    target = profile
    for part in field[:-1]:
        target = target[part]
    target[field[-1]] = value
    raw = install.packed(profile)
    with pytest.raises(ValueError):
        caller.checked_profile(raw, install.digest(raw), PROFILE_ROOT)


def explicit_arguments(phase):
    arguments = {
        "--configuration": "C:/Private/managed.json",
        "--expired-current": phase,
    }
    if phase != "inspect":
        arguments["--attempt-directory"] = "C:/Private/attempt"
    if phase in {"select", "retire-helpers", "finalize"}:
        arguments["--source-journal"] = "C:/Private/original-journal"
    if phase in {"prepare-selected", "stage"}:
        arguments["--logical-project"] = LOGICAL_PROJECT
    return arguments


def argv_for(arguments):
    return [item for pair in arguments.items() for item in pair]


def test_no_arguments_and_readonly_check_are_separate_modes():
    assert caller.parse_arguments([]) == {"mode": "renew", "arguments": {}}
    assert caller.parse_arguments(["--check-only"]) == {"mode": "check", "arguments": {}}


@pytest.mark.parametrize("phase", [
    "inspect", "prepare-selected", "stage", "reconcile-stage", "retire-unused-stage",
    "publish", "activate", "select", "retire-helpers", "finalize",
])
def test_explicit_recovery_accepts_only_its_paired_phase_contract(phase):
    arguments = explicit_arguments(phase)
    assert caller.parse_arguments(argv_for(arguments)) == {"mode": "explicit", "arguments": arguments}


@pytest.mark.parametrize("arguments", [
    ["--renew-once"],
    ["--wait-for-engine"],
    ["--check-only", "--check-only"],
    ["--configuration"],
    ["--configuration=x", "--expired-current=inspect"],
    ["--configuration", "x"],
    ["--expired-current", "inspect"],
    ["--configuration", "x", "--expired-current", "unknown"],
    ["--configuration", "x", "--expired-current", "inspect", "--configuration", "x"],
    ["--configuration", "x", "--expired-current", "inspect", "--check-only"],
    ["--configuration", "x", "--expired-current", "inspect", "--attempt-directory", "x"],
    ["--configuration", "x", "--expired-current", "stage", "--attempt-directory", "x"],
    ["--configuration", "x", "--expired-current", "select", "--attempt-directory", "x"],
    ["--configuration", "x", "--expired-current", "prepare-selected", "--attempt-directory", "x",
     "--logical-project", LOGICAL_PROJECT, "--operator-successor-file", "x"],
    ["--configuration", "x", "--expired-current", "activate", "--attempt-directory", "x",
     "--logical-project", LOGICAL_PROJECT],
    ["--configuration", "x", "--expired-current", "publish", "--attempt-directory", "x",
     "--source-journal", "x"],
], ids=[
    "renew-option", "engine-wait", "duplicate-check", "odd-tokens", "equals-syntax",
    "missing-phase", "missing-configuration", "unknown-phase", "duplicate-pair", "mixed-mode",
    "inspect-attempt", "stage-missing-logical", "select-missing-source", "prepare-successor",
    "activate-logical", "publish-source",
])
def test_malformed_arguments_cannot_fall_through_to_renewal(arguments):
    arguments = ["C:/Private/input" if value == "x" else value for value in arguments]
    with pytest.raises(ValueError):
        caller.parse_arguments(arguments)


class SyntheticInputs:
    """In-memory custody adapter; it supplies no actual NTFS/ACL evidence."""
    def __init__(self):
        self.files = {}
        self.active = []
        self.events = []
        self.fail_exit = None

    @staticmethod
    def key(path):
        return Path(path).as_posix().replace("\\", "/")

    @contextmanager
    def hold_private_input(self, path, *, max_bytes=65536):
        key = self.key(path)
        raw = self.files[key]
        assert len(raw) <= max_bytes
        self.active.append(key)
        self.events.append(("enter", key))
        try:
            yield raw
            if self.fail_exit == key:
                raise ValueError("PUBLIC_LATE_INPUT_REFUSAL")
            if self.files[key] != raw:
                raise ValueError("PUBLIC_CHANGED_HELD_INPUT")
        finally:
            self.active.remove(key)
            self.events.append(("exit", key))


@pytest.fixture
def operation():
    windows = SyntheticInputs()
    profile = profile_value()
    anchor = Path("C:/Private/original-anchor.json")
    journal = Path("C:/Private/continued-journal")
    staging_root = Path("C:/Private/windows-renewal-" + "5" * 32)
    config_path = staging_root / "activation/config.private.json"
    record = {
        "project": PROJECT, "anchor": {"path": str(anchor), "sha256": "6" * 64},
        "source": {"source_commit": "a" * 40},
    }
    events = []
    state = SimpleNamespace(selected=False, renew_error=None, hook_error=None,
                            hook_stdout=(SUCCESS + "\n").encode(), hook_code=0,
                            engine_stdout=b"PUBLIC_SYNTHETIC_ENGINE\n", engine_code=0, engine_error=None,
                            late_selection=False,
                            explicit_code=0, explicit_output=install.packed({"result": "PUBLIC_EXPLICIT_OK"}))
    guard = SimpleNamespace(pending=False, completed=0)

    def begin(selected):
        assert selected is lease and state.selected and not guard.pending
        events.append("intent")
        guard.pending = True

    guard.begin = begin

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Read-only caller invoked a runtime callback")

    lease = SimpleNamespace(
        project=PROJECT, sequence=7, generation_sequence=31, selected_sha256="7" * 64,
        journal_path=journal, secrets_dir=staging_root / "secrets", env_file=staging_root / "selected.env",
        compose_file=Path("C:/Private/compose.json"), compose_sha256="8" * 64,
        docker_host="npipe:////./pipe/dockerDesktopLinuxEngine", engine_id="PUBLIC_SYNTHETIC_ENGINE",
        check_current=forbidden, check_configuration=forbidden, recover_existing=forbidden,
        stage_renewal=forbidden, continue_journal=forbidden, prepare_expired_current=forbidden,
    )
    config = {
        "project": lease.project, "engine_id": lease.engine_id, "docker_host": lease.docker_host,
        "renewed_secrets": str(lease.secrets_dir), "renewed_env": str(lease.env_file),
        "compose_file": str(lease.compose_file), "compose_sha256": lease.compose_sha256,
    }
    config_raw = install.packed(config)
    intent_path = journal / f"{lease.sequence:06}.intent.json"
    intent = {"config_path": str(config_path), "config_file_sha256": install.digest(config_raw),
              "config_sha256": install.digest(config_raw)}
    windows.files[windows.key(config_path)] = config_raw
    windows.files[windows.key(intent_path)] = install.packed(intent)
    helper = b"# PUBLIC_SYNTHETIC_INERT_GOOGLE_HELPER\n"
    windows.files[profile["hook"]["helper"]] = helper
    profile["hook"]["helper_sha256"] = install.digest(helper)
    windows.files[profile["hook"]["client_id"]] = b"PUBLIC_CLIENT_ID"
    windows.files[profile["hook"]["client_secret"]] = b"PUBLIC_CLIENT_SECRET"
    windows.files[windows.key(lease.secrets_dir / "keycloak_admin_password")] = b"PUBLIC_SELECTED_PASSWORD"
    managed_path = "C:/Private/managed.json"
    windows.files[managed_path] = install.packed({
        "schema": "marty.windows-managed-recovery/v1", "selection_file": str(anchor),
    })
    outcome = {
        "schema": "marty.windows-renewal-staging/v1", "project": PROJECT,
        "result": "renewed-and-selected", "sequence": lease.sequence,
        "generation_sequence": lease.generation_sequence, "journal": str(journal),
        "config_path": str(config_path), "staging_root": str(staging_root),
        "production_admission": False, "automatic_lifecycle": False,
    }

    def renew_once(path, logical_project):
        assert path == anchor and logical_project == LOGICAL_PROJECT and not state.selected
        events.append("renew")
        if state.renew_error:
            raise state.renew_error
        return copy.deepcopy(outcome)

    @contextmanager
    def selected_inputs(path):
        assert path == anchor and not state.selected
        events.append("selection-enter")
        state.selected = True
        try:
            yield lease
        finally:
            state.selected = False
            events.append("selection-exit")
            if state.late_selection:
                raise ValueError("PUBLIC_LATE_SELECTION_REFUSAL")

    def owned_mutation(arguments, *, timeout):
        assert state.selected and timeout == 90
        engine_probe = [profile["hook"]["docker"], "--host", lease.docker_host, "info", "--format", "{{.ID}}"]
        if arguments == engine_probe:
            events.append("engine-probe")
            if state.engine_error:
                raise state.engine_error
            return subprocess.CompletedProcess(arguments, state.engine_code, state.engine_stdout, b"")
        assert guard.pending
        password = lease.secrets_dir / "keycloak_admin_password"
        assert all(windows.key(path) in windows.active for path in (
            password, profile["hook"]["helper"], profile["hook"]["client_id"], profile["hook"]["client_secret"],
        ))
        assert arguments == [
            profile["hook"]["docker"], "--host", lease.docker_host, "run", "--rm", "--pull", "never",
            "--network", PROJECT + "_default",
            "--mount", f"type=bind,src={password},dst=/run/secrets/keycloak_admin_password,readonly",
            "--mount", "type=bind,src=C:/Private/google_client_id,dst=/run/secrets/google_client_id,readonly",
            "--mount", "type=bind,src=C:/Private/google_client_secret,dst=/run/secrets/google_client_secret,readonly",
            "--mount", "type=bind,src=C:/Private/google_helper.py,dst=/run/secrets/google_helper.py,readonly",
            "--entrypoint", "python", IMAGE, "/run/secrets/google_helper.py",
        ]
        events.append("hook")
        if state.hook_error:
            raise state.hook_error
        return subprocess.CompletedProcess(arguments, state.hook_code, state.hook_stdout, b"")

    def recovery_main(arguments):
        assert not state.selected and managed_path in windows.active
        events.append(("explicit", arguments))
        sys.stdout.write(state.explicit_output.decode("utf-8"))
        return state.explicit_code

    return SimpleNamespace(
        profile=profile, record=record, state=state, guard=guard, windows=windows, events=events,
        lease=lease, config=config, config_path=config_path, intent=intent, intent_path=intent_path,
        outcome=outcome, managed_path=managed_path,
        selection=SimpleNamespace(renew_once=renew_once, selected_inputs=selected_inputs,
                                  STAGE_SCHEMA=outcome["schema"], config_digest=lambda value: install.digest(install.packed(value))),
        renewal=SimpleNamespace(run_owned_mutation=owned_mutation), recovery=SimpleNamespace(main=recovery_main),
    )


def perform(fixture, options=None):
    return caller.perform_operation(
        fixture.profile, fixture.record, options or {"mode": "renew", "arguments": {}},
        fixture.selection, fixture.renewal, fixture.recovery, fixture.windows,
        state=fixture.guard,
    )


def test_renewal_reacquires_original_anchor_and_runs_exact_hook_inside_matching_lease(operation):
    result, explicit = perform(operation)
    assert operation.events == ["renew", "selection-enter", "engine-probe", "intent", "hook", "selection-exit"]
    assert result["result"] == "renewed-and-selected"
    assert (result["sequence"], result["generation_sequence"], result["selected_sha256"]) == (7, 31, "7" * 64)
    assert result["google_idp_verified"] is True and explicit is None
    assert operation.guard.pending is True
    assert operation.windows.active == []


def test_check_only_reads_history_without_renewal_hook_or_runtime_callbacks(operation):
    operation.lease.sequence = 1
    operation.lease.generation_sequence = 2
    result, explicit = perform(operation, {"mode": "check", "arguments": {}})
    assert operation.events == ["selection-enter", "selection-exit"]
    assert (result["sequence"], result["generation_sequence"]) == (1, 2)
    assert result["result"] == "bindings-and-history-verified" and explicit is None
    assert operation.windows.events == []


def test_failed_renewal_never_acquires_postrenewal_lease_or_runs_hook(operation):
    failure = RuntimeError("PUBLIC_RENEWAL_FAILED")
    operation.state.renew_error = failure
    with pytest.raises(RuntimeError) as caught:
        perform(operation)
    assert caught.value is failure
    assert operation.events == ["renew"]


@pytest.mark.parametrize("field,value", [
    ("result", "rolled_back"), ("project", "marty-production-other"),
    ("sequence", 1), ("sequence", True), ("generation_sequence", 6),
    ("generation_sequence", True), ("journal", "C:/Private/different-journal"),
    ("production_admission", True), ("automatic_lifecycle", True),
    ("staging_root", "C:/Private/different-attempt"),
], ids=["not-selected", "wrong-project", "initial-sequence", "boolean-sequence", "old-generation",
        "boolean-generation", "other-journal", "production-claim", "automatic-claim", "other-attempt"])
def test_invalid_renewal_result_cannot_authorize_hook(operation, field, value):
    operation.outcome[field] = value
    with pytest.raises(ValueError):
        perform(operation)
    assert operation.events == ["renew", "selection-enter", "selection-exit"]


@pytest.mark.parametrize("field,value", [
    ("project", "marty-production-other"), ("sequence", 8), ("generation_sequence", 32),
    ("journal_path", Path("C:/Private/later-journal")),
    ("engine_id", "PUBLIC_OTHER_ENGINE"), ("docker_host", "npipe:////./pipe/otherEngine"),
    ("secrets_dir", Path("C:/Private/other-secrets")), ("env_file", Path("C:/Private/other.env")),
    ("compose_file", Path("C:/Private/other-compose.json")), ("compose_sha256", "9" * 64),
], ids=["project", "local-sequence", "global-generation", "journal", "engine", "docker-host",
        "selected-secrets", "selected-env", "compose-file", "compose-digest"])
def test_different_selected_generation_cannot_borrow_completed_renewal_authority(operation, field, value):
    setattr(operation.lease, field, value)
    with pytest.raises(ValueError):
        perform(operation)
    assert operation.events == ["renew", "selection-enter", "selection-exit"]


@pytest.mark.parametrize("change", ["config-path", "raw-config-hash", "config-binding-hash", "config-bytes"])
def test_selected_intent_and_exact_config_bytes_must_bind_the_completed_attempt(operation, change):
    if change == "config-bytes":
        operation.windows.files[operation.windows.key(operation.config_path)] += b" "
    else:
        field = {"config-path": "config_path", "raw-config-hash": "config_file_sha256",
                 "config-binding-hash": "config_sha256"}[change]
        operation.intent[field] = "C:/Private/unrelated.json" if field == "config_path" else "0" * 64
        operation.windows.files[operation.windows.key(operation.intent_path)] = install.packed(operation.intent)
    with pytest.raises(ValueError):
        perform(operation)
    assert "hook" not in operation.events


@pytest.mark.parametrize("failure", ["exit-code", "timeout", "owned-uncertainty", "wrong-output", "extra-output", "invalid-utf8"])
def test_hook_failure_has_no_retry_and_cannot_report_renewal_success(operation, failure):
    if failure == "exit-code":
        operation.state.hook_code = 1
    elif failure == "timeout":
        operation.state.hook_error = subprocess.TimeoutExpired("PUBLIC_OWNED_HOOK", 90)
    elif failure == "owned-uncertainty":
        operation.state.hook_error = RuntimeError("PUBLIC_OWNED_PROCESS_UNCERTAIN")
    else:
        operation.state.hook_stdout = {
            "wrong-output": b"PUBLIC_WRONG_RESULT\n",
            "extra-output": (SUCCESS + "\nPUBLIC_EXTRA_OUTPUT\n").encode(),
            "invalid-utf8": b"\xff",
        }[failure]
    with pytest.raises((ValueError, RuntimeError, subprocess.TimeoutExpired, UnicodeError)):
        perform(operation)
    assert operation.events == ["renew", "selection-enter", "engine-probe", "intent", "hook", "selection-exit"]
    assert operation.guard.pending is True


@pytest.mark.parametrize("change", ["helper-pin", "helper-bytes", "client-id-empty", "client-secret-empty", "network"])
def test_hook_input_refusal_never_starts_helper_or_clears_pending_intent(operation, change):
    hook = operation.profile["hook"]
    if change == "helper-pin":
        hook["helper_sha256"] = "0" * 64
    elif change == "helper-bytes":
        operation.windows.files[hook["helper"]] += b"# PUBLIC_CHANGED\n"
    elif change == "network":
        hook["network"] = "marty-production-other_default"
    else:
        operation.windows.files[hook["client_id" if change == "client-id-empty" else "client_secret"]] = b""
    with pytest.raises(ValueError):
        perform(operation)
    assert operation.events == ["renew", "selection-enter", "engine-probe", "intent", "selection-exit"]
    assert operation.guard.pending is True


@pytest.mark.parametrize("phase", ["inspect", "prepare-selected", "stage", "finalize"])
def test_explicit_owner_phase_never_runs_ordinary_renewal_or_google_hook(operation, phase):
    arguments = explicit_arguments(phase)
    result, output = perform(operation, caller.parse_arguments(argv_for(arguments)))
    assert result == {"result": "PUBLIC_EXPLICIT_OK"}
    assert output == operation.state.explicit_output
    assert operation.events == [("explicit", argv_for(arguments))]
    assert operation.windows.active == []


def test_explicit_native_windows_paths_are_accepted_and_forwarded_without_rewriting(operation):
    arguments = explicit_arguments("stage")
    arguments["--configuration"] = r"C:\Private\managed.json"
    arguments["--attempt-directory"] = r"C:\Private\attempt"
    parsed = caller.parse_arguments(argv_for(arguments))
    assert parsed["arguments"] == arguments
    result, output = perform(operation, parsed)
    assert result == {"result": "PUBLIC_EXPLICIT_OK"} and output == operation.state.explicit_output
    assert operation.events == [("explicit", argv_for(arguments))]


@pytest.mark.parametrize("path", [
    "managed.json", r"\\server\share\managed.json", r"C:\Private\managed.json:stream",
    r"C:\Private\..\managed.json", r"C:\Private\managed,readonly.json",
])
def test_explicit_native_path_compatibility_does_not_allow_ambiguous_sources(path):
    arguments = explicit_arguments("inspect")
    arguments["--configuration"] = path
    with pytest.raises(ValueError):
        caller.parse_arguments(argv_for(arguments))


@pytest.mark.parametrize("phase", ["prepare-selected", "stage"])
def test_explicit_staging_namespace_must_match_enrollment_before_recovery(operation, phase):
    arguments = explicit_arguments(phase)
    arguments["--logical-project"] = "marty-selfhost-other"
    with pytest.raises(ValueError):
        perform(operation, caller.parse_arguments(argv_for(arguments)))
    assert operation.events == []


@pytest.mark.parametrize("change", ["other-anchor", "schema", "extra-field"])
def test_explicit_managed_configuration_cannot_redirect_the_original_owner(operation, change):
    value = install.decode(operation.windows.files[operation.managed_path])
    if change == "other-anchor":
        value["selection_file"] = "C:/Private/later-configuration.json"
    elif change == "schema":
        value["schema"] = "unreviewed"
    else:
        value["renew_once"] = True
    operation.windows.files[operation.managed_path] = install.packed(value)
    with pytest.raises(ValueError):
        perform(operation, caller.parse_arguments(argv_for(explicit_arguments("inspect"))))
    assert operation.events == []


@pytest.mark.parametrize("failure", ["exit-code", "boolean-code", "empty", "oversize", "not-object", "duplicate-key", "trailing-data"])
def test_explicit_owner_output_is_bounded_and_not_forwarded_on_failure(operation, failure):
    if failure in {"exit-code", "boolean-code"}:
        operation.state.explicit_code = 1 if failure == "exit-code" else False
    else:
        operation.state.explicit_output = {
            "empty": b"", "oversize": b"x" * 65537, "not-object": b"[]\n",
            "duplicate-key": b'{"result":"first","result":"second"}\n',
            "trailing-data": b'{"result":"PUBLIC_OK"}\nPUBLIC_EXTRA\n',
        }[failure]
    with pytest.raises(ValueError):
        perform(operation, caller.parse_arguments(argv_for(explicit_arguments("inspect"))))
    assert operation.events == [("explicit", argv_for(explicit_arguments("inspect")))]


@pytest.mark.parametrize("failure", ["wrong-engine", "exit-code", "timeout", "invalid-utf8"])
def test_engine_probe_refusal_never_publishes_hook_intent_or_starts_helper(operation, failure):
    if failure == "wrong-engine":
        operation.state.engine_stdout = b"PUBLIC_DIFFERENT_ENGINE\n"
    elif failure == "exit-code":
        operation.state.engine_code = 1
    elif failure == "timeout":
        operation.state.engine_error = subprocess.TimeoutExpired("PUBLIC_ENGINE_PROBE", 90)
    else:
        operation.state.engine_stdout = b"\xff"
    with pytest.raises((ValueError, UnicodeError, subprocess.TimeoutExpired)):
        perform(operation)
    assert operation.events == ["renew", "selection-enter", "engine-probe", "selection-exit"]
    assert operation.guard.pending is False


@pytest.mark.parametrize("mode", ["renew", "explicit", "check"])
def test_pending_hook_blocks_every_caller_mode_before_owner_callbacks(operation, mode):
    operation.guard.pending = True
    options = (caller.parse_arguments(argv_for(explicit_arguments("inspect"))) if mode == "explicit"
               else {"mode": mode, "arguments": {}})
    with pytest.raises(ValueError):
        perform(operation, options)
    assert operation.events == [] and operation.windows.events == []
    assert operation.guard.pending is True


def test_exhausted_hook_history_refuses_before_starting_another_renewal(operation):
    operation.guard.completed = caller.MAX_HOOK_ATTEMPTS
    with pytest.raises(ValueError):
        perform(operation)
    assert operation.events == []


@pytest.fixture
def invocation(operation, monkeypatch):
    fixture = operation
    fixture.state.late_source = False
    fixture.state.late_state = False
    fixture.state.fail_log = False
    fixture.logs = []

    @contextmanager
    def held_caller(_path, _expected):
        fixture.events.append("source-enter")
        try:
            yield (fixture.profile, fixture.record, fixture.selection, fixture.renewal,
                   fixture.recovery, fixture.windows, install)
        finally:
            fixture.events.append("source-exit")
            if fixture.state.late_source:
                raise ValueError("PUBLIC_SECRET_DETAIL_MUST_NOT_REACH_LOG")

    @contextmanager
    def held_state(_profile, _expected, _record, _windows, _installer):
        fixture.events.append("state-enter")
        try:
            yield fixture.guard
        finally:
            fixture.events.append("state-exit")
            if fixture.state.late_state:
                raise ValueError("PUBLIC_LATE_STATE_REFUSAL")

    def complete():
        assert fixture.guard.pending and not fixture.state.selected
        assert "source-exit" in fixture.events
        fixture.events.append("complete")
        fixture.guard.pending = False
        fixture.guard.completed += 1

    def log(path, line, windows):
        assert path == Path(fixture.profile["log"]) and windows is fixture.windows
        assert fixture.events[-1] == "state-exit"
        fixture.events.append("log")
        fixture.logs.append(line)
        if fixture.state.fail_log:
            raise ValueError("PUBLIC_PARTIAL_LOG_WRITE")

    fixture.guard.complete = complete
    monkeypatch.setattr(caller, "held_caller", held_caller)
    monkeypatch.setattr(caller, "held_hook_state", held_state)
    monkeypatch.setattr(caller, "append_log", log)
    fixture.invoke = lambda *args: caller.run(Path("C:/Private/owner-caller/caller.json"), "f" * 64, args)
    return fixture


def test_hook_completion_and_success_log_wait_for_all_owner_and_source_exits(invocation):
    result, _explicit = invocation.invoke()
    events = invocation.events
    assert events.index("selection-exit") < events.index("source-exit") < events.index("complete")
    assert events.index("complete") < events.index("state-exit") < events.index("log")
    summary = install.decode(invocation.logs[0])
    assert set(summary) == {"utc", "result", "sequence", "generation_sequence", "google_idp_verified"}
    assert summary["result"] == result["result"] == "renewed-and-selected"
    assert invocation.guard.pending is False and invocation.guard.completed == 1


@pytest.mark.parametrize("failure", ["source-exit", "selection-exit", "hook-timeout", "helper-exit"])
def test_late_or_uncertain_hook_failure_leaves_pending_and_blocks_next_invocation(invocation, failure):
    if failure == "source-exit":
        invocation.state.late_source = True
    elif failure == "selection-exit":
        invocation.state.late_selection = True
    elif failure == "hook-timeout":
        invocation.state.hook_error = subprocess.TimeoutExpired("PUBLIC_HOOK", 90)
    else:
        invocation.state.hook_code = 1
    with pytest.raises((ValueError, subprocess.TimeoutExpired)):
        invocation.invoke()
    assert "complete" not in invocation.events
    assert invocation.guard.pending is True and invocation.guard.completed == 0
    assert [install.decode(line)["result"] for line in invocation.logs] == ["operator-reconciliation-required"]
    assert b"PUBLIC_SECRET_DETAIL" not in b"".join(invocation.logs)
    invocation.state.late_source = invocation.state.late_selection = False
    invocation.events.clear()
    invocation.logs.clear()
    with pytest.raises(ValueError):
        invocation.invoke()
    assert "renew" not in invocation.events and "hook" not in invocation.events and "complete" not in invocation.events
    assert invocation.guard.pending is True


def test_check_only_never_writes_log_or_hook_records_even_after_late_failure(invocation):
    result, explicit = invocation.invoke("--check-only")
    assert result["result"] == "bindings-and-history-verified" and explicit is None
    assert invocation.logs == [] and not invocation.guard.pending and invocation.guard.completed == 0
    assert "intent" not in invocation.events and "complete" not in invocation.events
    invocation.state.late_source = True
    with pytest.raises(ValueError):
        invocation.invoke("--check-only")
    assert invocation.logs == []


def test_log_failure_is_not_retried_or_replaced_with_a_second_log_write(invocation):
    invocation.state.fail_log = True
    with pytest.raises(ValueError):
        invocation.invoke()
    assert invocation.events[-1] == "log"
    assert len(invocation.logs) == 1
    assert invocation.guard.completed == 1 and invocation.guard.pending is False


@pytest.mark.parametrize("phase", ["inspect", "prepare-selected"])
def test_explicit_output_is_withheld_until_source_exit_without_hook_records(invocation, phase):
    invocation.state.late_source = True
    with pytest.raises(ValueError):
        invocation.invoke(*argv_for(explicit_arguments(phase)))
    assert "intent" not in invocation.events and "complete" not in invocation.events
    assert invocation.guard.pending is False
    assert [install.decode(line)["result"] for line in invocation.logs] == ["operator-reconciliation-required"]


def test_late_hook_state_exit_suppresses_success_output_and_success_log(invocation):
    invocation.state.late_state = True
    with pytest.raises(ValueError):
        invocation.invoke()
    assert invocation.events.index("complete") < invocation.events.index("state-exit")
    assert [install.decode(line)["result"] for line in invocation.logs] == ["operator-reconciliation-required"]


@pytest.fixture
def journal(operation, tmp_path):
    root = tmp_path / "public-synthetic-hook-state"
    root.mkdir()
    profile = copy.deepcopy(operation.profile)
    # Only the filesystem adapter is portable. The profile spelling contract is
    # tested independently with real Windows paths above and actual NTFS below.
    profile["hook_state"] = str(root)
    profile_sha = install.digest(install.packed(profile))
    owner = install.packed(caller.hook_state_owner(profile_sha, profile["installation"]["sha256"]))
    (root / "owner.json").write_bytes(owner)
    (root / "lock").write_bytes(b"")
    windows = SyntheticWindows()
    return SimpleNamespace(
        root=root, profile=profile, profile_sha=profile_sha, record=operation.record,
        lease=operation.lease, windows=windows, owner=owner,
        hold=lambda: caller.held_hook_state(profile, profile_sha, operation.record, windows, install),
    )


def journal_bytes(root):
    return {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()}


def complete_attempt(journal, *, next_generation=False):
    if next_generation:
        journal.lease = copy.copy(journal.lease)
        journal.lease.sequence += 1
        journal.lease.generation_sequence += 1
        journal.lease.selected_sha256 = "9" * 64
    with journal.hold() as state:
        state.begin(journal.lease)
        state.complete()


def test_hook_journal_preserves_completed_history_and_binds_each_new_attempt(journal):
    complete_attempt(journal)
    first = journal_bytes(journal.root)
    assert set(first) == {"owner.json", "lock", "000001.intent.json", "000001.complete.json"}
    first_intent = install.decode(first["000001.intent.json"])
    first_complete = install.decode(first["000001.complete.json"])
    assert first_intent["previous_completion_sha256"] is None
    assert first_intent["anchor_sha256"] == journal.record["anchor"]["sha256"]
    assert first_intent["selected_sha256"] == journal.lease.selected_sha256
    assert first_intent["engine_id"] == journal.lease.engine_id and first_intent["docker_host"] == journal.lease.docker_host
    assert first_complete["intent_sha256"] == install.digest(first["000001.intent.json"])
    complete_attempt(journal, next_generation=True)
    current = journal_bytes(journal.root)
    assert {name: current[name] for name in first} == first
    second = install.decode(current["000002.intent.json"])
    assert second["previous_completion_sha256"] == install.digest(first["000001.complete.json"])
    assert second["generation_sequence"] == first_intent["generation_sequence"] + 1
    with journal.hold() as state:
        assert state.completed == 2 and state.pending is False
        with pytest.raises(ValueError):
            state.begin(journal.lease)
    assert journal_bytes(journal.root) == current


def test_pending_hook_journal_cannot_be_cleared_or_reused_by_a_later_invocation(journal):
    with journal.hold() as state:
        state.begin(journal.lease)
        assert state.pending and state.completed == 0
    pending = journal_bytes(journal.root)
    with journal.hold() as state:
        assert state.pending and state.completed == 0
        with pytest.raises(ValueError):
            state.begin(journal.lease)
        with pytest.raises(ValueError):
            state.complete()
    assert journal_bytes(journal.root) == pending
    assert "000001.complete.json" not in pending


@pytest.mark.parametrize("change", [
    "boolean-completion-attempt", "orphan-completion", "missing-first-attempt", "changed-prior-intent",
    "wrong-previous-completion", "repeated-generation", "wrong-owner", "noncanonical-record",
    "empty-intent", "empty-completion", "pending-before-later-attempt", "unexpected-entry",
])
def test_corrupt_hook_history_refuses_without_repair_or_fallback(journal, change):
    complete_attempt(journal)
    complete_attempt(journal, next_generation=True)
    root = journal.root
    first_intent = root / "000001.intent.json"
    first_complete = root / "000001.complete.json"
    second_intent = root / "000002.intent.json"
    if change == "boolean-completion-attempt":
        value = install.decode(first_complete.read_bytes())
        value["attempt"] = True
        first_complete.write_bytes(install.packed(value))
    elif change == "orphan-completion":
        first_intent.unlink()
    elif change == "missing-first-attempt":
        first_intent.unlink()
        first_complete.unlink()
    elif change == "changed-prior-intent":
        value = install.decode(first_intent.read_bytes())
        value["selected_sha256"] = "0" * 64
        first_intent.write_bytes(install.packed(value))
    elif change in {"wrong-previous-completion", "repeated-generation"}:
        value = install.decode(second_intent.read_bytes())
        if change == "wrong-previous-completion":
            value["previous_completion_sha256"] = "0" * 64
        else:
            value["generation_sequence"] -= 1
        raw = install.packed(value)
        second_intent.write_bytes(raw)
        completion = root / "000002.complete.json"
        completed = install.decode(completion.read_bytes())
        completed["intent_sha256"] = install.digest(raw)
        completion.write_bytes(install.packed(completed))
    elif change == "wrong-owner":
        (root / "owner.json").write_bytes(install.packed(caller.hook_state_owner("0" * 64, "2" * 64)))
    elif change == "noncanonical-record":
        first_intent.write_bytes(json.dumps(install.decode(first_intent.read_bytes()), indent=2).encode())
    elif change == "empty-intent":
        first_intent.write_bytes(b"")
    elif change == "empty-completion":
        first_complete.write_bytes(b"")
    elif change == "pending-before-later-attempt":
        first_complete.unlink()
    else:
        (root / "unreviewed.json").write_bytes(b"{}\n")
    damaged = journal_bytes(root)
    with pytest.raises(ValueError):
        with journal.hold():
            pytest.fail("Untrusted hook history admitted")
    assert journal_bytes(root) == damaged


@pytest.mark.parametrize("phase", ["intent", "complete"])
def test_hook_record_allocation_replacement_remains_failed_evidence(journal, phase):
    with pytest.raises(ValueError):
        with journal.hold() as state:
            if phase == "complete":
                state.begin(journal.lease)
            journal.windows.replace_before_write = True
            (state.begin(journal.lease) if phase == "intent" else state.complete())
    allocated = journal.root / f"000001.{phase}.json"
    assert allocated.read_bytes() == b""
    assert allocated.with_name(allocated.name + ".replaced").read_bytes() == b""
    damaged = journal_bytes(journal.root)
    with pytest.raises(ValueError):
        with journal.hold():
            pytest.fail("Partial record allocation admitted")
    assert journal_bytes(journal.root) == damaged


def test_late_intent_creation_failure_retains_pending_evidence(journal):
    def fail(path, write_value, _directory, _rename):
        if path.name == "000001.intent.json" and write_value is not None:
            raise ValueError("PUBLIC_LATE_INTENT_WRITE_REFUSAL")
    journal.windows.fail = fail
    with pytest.raises(ValueError):
        with journal.hold() as state:
            state.begin(journal.lease)
    journal.windows.fail = None
    pending = journal_bytes(journal.root)
    assert install.decode(pending["000001.intent.json"])["selected_sha256"] == journal.lease.selected_sha256
    assert "000001.complete.json" not in pending
    with journal.hold() as state:
        assert state.pending and state.completed == 0
    assert journal_bytes(journal.root) == pending
