#!/usr/bin/env python3
"""Call an installed Windows owner through independently pinned private inputs.

Deploy these reviewed bytes as run-owner.py beside a canonical caller.json.
This program does not install, register, replace, enable or migrate any task.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import ctypes
import hashlib
import importlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import re
import sys
import types

SCHEMA = "marty.windows-owner-source-caller/v1"
RESULT_SCHEMA = "marty.windows-owner-source-caller-result/v1"
PROFILE = "caller.json"
RUNNER = "run-owner.py"
MAX_RECORD = 65536
MAX_SOURCE = 4 * 1024 * 1024
MAX_LOG = 8 * 1024 * 1024
MAX_LOG_ENTRY = 2048
MAX_HOOK_RECORD = 4096
MAX_HOOK_ATTEMPTS = 4096
HOOK_SCHEMA = "marty.windows-owner-source-hook-state/v1"
INTENT_SCHEMA = "marty.windows-owner-source-hook-intent/v1"
COMPLETE_SCHEMA = "marty.windows-owner-source-hook-complete/v1"
BOOTSTRAP = ("package_windows_owner_source.py", "selfhost_windows_inputs.py",
             "selfhost_windows_source_install.py")
PHASES = frozenset(("prepare-selected", "inspect", "stage", "reconcile-stage",
                   "retire-unused-stage", "publish", "activate", "select",
                   "retire-helpers", "finalize"))
OPTIONS = frozenset(("--configuration", "--expired-current", "--attempt-directory",
                    "--source-journal", "--operator-successor-file", "--logical-project"))
REFUSAL = "Windows source caller requires operator reconciliation; preserve its inputs and operation evidence"


def require(value):
    if not value:
        raise ValueError(REFUSAL)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def packed(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def decode(raw):
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result)
            result[name] = value
        return result
    def constant(_value):
        raise ValueError(REFUSAL)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def exact_sha(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value))
    return value


def windows_path(value):
    """Validate spelling only; NTFS identity and privacy are proved separately."""
    require(type(value) is str and 3 < len(value) <= 1024
            and not any(ord(char) < 32 for char in value)
            and not any(char in value for char in '\\,"<>|?*'))
    path = PureWindowsPath(value)
    require(re.fullmatch(r"[A-Za-z]:", path.drive) and path.is_absolute()
            and path.as_posix() == value and len(path.parts) >= 2)
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}
    require(all(part not in {".", ".."} and ":" not in part
                and part.rstrip(" .") == part and part.split(".", 1)[0].upper() not in reserved
                for part in path.parts[1:]))
    return path


def checked_profile(raw, expected_sha, root):
    exact_sha(expected_sha)
    require(type(raw) is bytes and 0 < len(raw) <= MAX_RECORD and digest(raw) == expected_sha)
    value = decode(raw)
    require(type(value) is dict and set(value) == {
        "schema", "script_sha256", "python", "installation", "logical_project", "log", "hook", "hook_state"}
        and value["schema"] == SCHEMA and raw == packed(value))
    exact_sha(value["script_sha256"])
    root = windows_path(str(root).replace("\\", "/"))
    windows_path(value["python"]); log = windows_path(value["log"])
    state = windows_path(value["hook_state"])
    installation = value["installation"]
    require(type(installation) is dict and set(installation) == {"root", "sha256"})
    installed = windows_path(installation["root"]); exact_sha(installation["sha256"])
    require(type(value["logical_project"]) is str
            and re.fullmatch(r"marty-selfhost-[a-z0-9][a-z0-9-]{0,59}", value["logical_project"]))
    hook = value["hook"]
    require(type(hook) is dict and set(hook) == {
        "helper", "helper_sha256", "client_id", "client_secret", "docker", "image",
        "network", "timeout_seconds", "success_stdout"})
    paths = [windows_path(hook[key]) for key in ("helper", "client_id", "client_secret", "docker")]
    exact_sha(hook["helper_sha256"])
    require(type(hook["image"]) is str and re.fullmatch(r"python@sha256:[0-9a-f]{64}", hook["image"])
            and type(hook["network"]) is str
            and re.fullmatch(r"marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}_default", hook["network"])
            and type(hook["timeout_seconds"]) is int and hook["timeout_seconds"] == 90
            and type(hook["success_stdout"]) is str and 0 < len(hook["success_stdout"]) <= 256
            and hook["success_stdout"].strip() == hook["success_stdout"]
            and all(32 <= ord(char) <= 126 for char in hook["success_stdout"]))
    require(root != installed and root not in installed.parents and installed not in root.parents
            and len(set(paths + [log, windows_path(value["python"])])) == 6)
    require(all(path != root and root not in path.parents and path != installed
                and installed not in path.parents for path in paths + [log]))
    require(all(state != path and state not in path.parents and path not in state.parents
                for path in paths + [log, root, installed, windows_path(value["python"])]))
    return value


def parse_arguments(argv):
    require(type(argv) in (tuple, list) and all(type(item) is str for item in argv))
    if not argv:
        return {"mode": "renew", "arguments": {}}
    if list(argv) == ["--check-only"]:
        return {"mode": "check", "arguments": {}}
    require(0 < len(argv) <= 12 and len(argv) % 2 == 0)
    arguments = {}
    for name, value in zip(argv[::2], argv[1::2]):
        require(name in OPTIONS and name not in arguments and value and not value.startswith("-"))
        arguments[name] = value
    require({"--configuration", "--expired-current"} <= set(arguments))
    phase = arguments["--expired-current"]
    require(phase in PHASES)
    require(("--attempt-directory" in arguments) == (phase != "inspect")
            and ("--source-journal" in arguments) == (phase in {"select", "retire-helpers", "finalize"})
            and ("--logical-project" in arguments) == (phase in {"prepare-selected", "stage"})
            and (phase not in {"inspect", "prepare-selected"} or "--operator-successor-file" not in arguments))
    for name, value in arguments.items():
        if name not in {"--expired-current", "--logical-project"}:
            windows_path(value.replace("\\", "/"))
    if "--logical-project" in arguments:
        require(re.fullmatch(r"marty-selfhost-[a-z0-9][a-z0-9-]{0,59}", arguments["--logical-project"]))
    return {"mode": "explicit", "arguments": arguments}


def read_bounded(path, limit):
    with Path(path).open("rb") as source:
        raw = source.read(limit + 1)
    require(len(raw) <= limit)
    return raw


def directory_names(root, maximum):
    names = set()
    for path in root.iterdir():
        names.add(path.name)
        require(len(names) <= maximum)
    return names


def load_bootstrap(name, raw, path):
    require(name not in sys.modules)
    module = types.ModuleType(name); module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


@contextmanager
def held_caller(profile_path, expected_sha):
    """Hold the externally pinned caller, installation and original anchor."""
    require(os.name == "nt" and sys.platform == "win32" and sys.flags.isolated
            and sys.dont_write_bytecode and not sys.flags.optimize
            and sys.implementation.name == "cpython" and sys.version_info >= (3, 12))
    profile_path = Path(profile_path)
    require(profile_path.is_absolute() and profile_path.name == PROFILE)
    root = profile_path.parent; script = root / RUNNER
    require(Path(__file__).absolute() == script)
    profile_raw = read_bounded(profile_path, MAX_RECORD)
    profile = checked_profile(profile_raw, expected_sha, root)
    script_raw = read_bounded(script, MAX_SOURCE)
    require(digest(script_raw) == profile["script_sha256"]
            and PureWindowsPath(sys.executable) == PureWindowsPath(profile["python"]))
    installed = Path(profile["installation"]["root"])
    record_raw = read_bounded(installed / "installation.json", MAX_RECORD)
    require(digest(record_raw) == profile["installation"]["sha256"])
    initial = decode(record_raw)
    require(type(initial) is dict and type(initial.get("tooling")) is dict
            and type(initial["tooling"].get("files")) is dict
            and set(initial["tooling"]["files"]) == set(BOOTSTRAP))
    bodies = {}
    for name in BOOTSTRAP:
        reference = initial["tooling"]["files"][name]
        require(type(reference) is dict and set(reference) == {"sha256", "bytes"}
                and type(reference["bytes"]) is int and 0 < reference["bytes"] <= MAX_SOURCE)
        exact_sha(reference["sha256"])
        body = read_bounded(installed / "bootstrap" / name, MAX_SOURCE)
        require(len(body) == reference["bytes"] and digest(body) == reference["sha256"])
        bodies[name] = body
    # Only bytes bound by the independent profile -> installation -> bootstrap
    # chain may execute, even before the unchanged NTFS verifier can be loaded.
    modules = {}
    try:
        for name in BOOTSTRAP:
            module_name = "_marty_source_caller_bootstrap_" + name[:-3]
            modules[name] = load_bootstrap(module_name, bodies[name], installed / "bootstrap" / name)
        windows = modules["selfhost_windows_inputs.py"]
        package = modules["package_windows_owner_source.py"]
        installer = modules["selfhost_windows_source_install.py"]
        record = installer.checked_installation(record_raw, profile["installation"]["sha256"], installed)
        require(profile["hook"]["network"] == record["project"] + "_default")
        with ExitStack() as held:
            held.enter_context(windows.hold_storage_namespace(root.parent))
            held.enter_context(windows._held_private_input(root, directory=True))
            require(directory_names(root, 2) == {PROFILE, RUNNER})
            require(held.enter_context(windows.hold_private_input(profile_path)) == profile_raw)
            require(held.enter_context(windows.hold_private_input(script, max_bytes=MAX_SOURCE)) == script_raw)
            held.enter_context(windows.hold_storage_namespace(installed.parent))
            require(held.enter_context(windows.hold_private_input(installed / "installation.json")) == record_raw)
            archive = held.enter_context(windows.hold_private_input(installed / "source.zip", max_bytes=package.MAX_ARCHIVE_BYTES))
            require(package.inspect_archive(archive, record["source"]["archive_sha256"],
                                             record["source"]["source_commit"]) == record["source"])
            source = installer.archive_files(archive, record["source"]["source_commit"], package)
            files = installer.installation_files(record, archive, source, bodies, ready=True)
            held.enter_context(installer.hold_files(installed, files, windows))
            anchor = Path(record["anchor"]["path"])
            anchor_raw = held.enter_context(windows.hold_private_input(anchor))
            require(digest(anchor_raw) == record["anchor"]["sha256"]
                    and decode(anchor_raw).get("project") == record["project"])
            helper = held.enter_context(windows.hold_private_input(Path(profile["hook"]["helper"]), max_bytes=MAX_SOURCE))
            require(digest(helper) == profile["hook"]["helper_sha256"])
            for key in ("client_id", "client_secret"):
                require(held.enter_context(windows.hold_private_input(Path(profile["hook"][key]))))
            # These qualified system tools are public executable inputs, not
            # secret files; retain their identities/bytes without changing ACLs.
            require(held.enter_context(windows.hold_public_input(Path(profile["python"]), max_bytes=16 * 1024 * 1024)))
            require(held.enter_context(windows.hold_public_input(Path(profile["hook"]["docker"]), max_bytes=256 * 1024 * 1024)))
            # Check the existing private diagnostic log without writing it.
            with windows.hold_private_input(Path(profile["log"]), max_bytes=MAX_LOG) as log:
                require(len(log) <= MAX_LOG - MAX_LOG_ENTRY and (not log or log.endswith(b"\n")))
            finder = installer.VerifiedFinder(installed / "source", source)
            require(not (set(finder.modules) & set(sys.modules)))
            sys.meta_path.insert(0, finder)
            try:
                selection = importlib.import_module("selfhost_windows_selection")
                renewal = importlib.import_module("selfhost_windows_renewal")
                recovery = importlib.import_module("selfhost_windows_recovery")
                yield profile, record, selection, renewal, recovery, windows, installer
                imported = {name for name in finder.modules if name in sys.modules}
                require(imported and all(Path(sys.modules[name].__file__) == finder.root / finder.modules[name][0]
                                         for name in imported))
            finally:
                sys.meta_path.remove(finder)
                require(directory_names(root, 2) == {PROFILE, RUNNER})
    finally:
        for name in modules:
            sys.modules.pop("_marty_source_caller_bootstrap_" + name[:-3], None)


def docker_host(value):
    require(type(value) is str and re.fullmatch(r"npipe:/{4}\./pipe/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value))
    return value


def hook_arguments(profile, selected_password, lease):
    hook = profile["hook"]
    arguments = [hook["docker"], "--host", docker_host(lease.docker_host), "run", "--rm",
                 "--pull", "never", "--network", hook["network"]]
    for path, name in ((str(selected_password), "keycloak_admin_password"),
                       (hook["client_id"], "google_client_id"),
                       (hook["client_secret"], "google_client_secret"),
                       (hook["helper"], "google_helper.py")):
        # Docker --mount has a comma-delimited grammar; profile path checks and
        # this selected-path check prohibit delimiter injection before dispatch.
        windows_path(path.replace("\\", "/"))
        arguments.extend(("--mount", f"type=bind,src={path},dst=/run/secrets/{name},readonly"))
    return arguments + ["--entrypoint", "python", hook["image"], "/run/secrets/google_helper.py"]


def verify_hook_engine(profile, lease, renewal):
    require(type(lease.engine_id) is str and 0 < len(lease.engine_id) <= 256
            and all(33 <= ord(char) <= 126 for char in lease.engine_id))
    outcome = renewal.run_owned_mutation([profile["hook"]["docker"], "--host", docker_host(lease.docker_host),
                                         "info", "--format", "{{.ID}}"], timeout=90)
    require(outcome.returncode == 0 and type(outcome.stdout) is bytes
            and outcome.stdout.decode("utf-8").strip() == lease.engine_id)


def run_hook(profile, lease, renewal, windows):
    hook = profile["hook"]
    require(hook["network"] == lease.project + "_default")
    password = lease.secrets_dir / "keycloak_admin_password"
    with ExitStack() as held:
        helper = held.enter_context(windows.hold_private_input(Path(hook["helper"]), max_bytes=MAX_SOURCE))
        require(digest(helper) == hook["helper_sha256"])
        for path in (password, Path(hook["client_id"]), Path(hook["client_secret"])):
            require(held.enter_context(windows.hold_private_input(path)))
        outcome = renewal.run_owned_mutation(hook_arguments(profile, password, lease), timeout=hook["timeout_seconds"])
        # The existing owner bounds and contains the CLI process tree. A failed
        # or timed-out CLI cannot prove daemon-side quiescence; never retry it.
        require(outcome.returncode == 0 and type(outcome.stdout) is bytes
                and outcome.stdout.decode("utf-8").strip() == hook["success_stdout"])


def checked_renewed_selection(result, lease, record, selection, windows):
    require(type(result) is dict and set(result) == {
        "schema", "project", "result", "sequence", "generation_sequence", "journal", "config_path",
        "staging_root", "production_admission", "automatic_lifecycle"}
        and result["schema"] == selection.STAGE_SCHEMA and result["result"] == "renewed-and-selected"
        and result["project"] == record["project"] == lease.project
        and type(result["sequence"]) is int and type(result["generation_sequence"]) is int
        and 2 <= result["sequence"] <= result["generation_sequence"]
        and result["sequence"] == lease.sequence and result["generation_sequence"] == lease.generation_sequence
        and result["production_admission"] is False and result["automatic_lifecycle"] is False
        and Path(result["journal"]) == lease.journal_path)
    with ExitStack() as held:
        intent = decode(held.enter_context(windows.hold_private_input(
            lease.journal_path / f"{lease.sequence:06}.intent.json")))
        require(intent["config_path"] == result["config_path"])
        raw = held.enter_context(windows.hold_private_input(Path(result["config_path"])))
        config = decode(raw)
        require(digest(raw) == intent["config_file_sha256"]
                and selection.config_digest(config) == intent["config_sha256"]
                and config["project"] == lease.project and config["engine_id"] == lease.engine_id
                and config["docker_host"] == lease.docker_host
                and Path(config["renewed_secrets"]) == lease.secrets_dir
                and Path(config["renewed_env"]) == lease.env_file
                and Path(config["compose_file"]) == lease.compose_file
                and config["compose_sha256"] == lease.compose_sha256
                and Path(result["config_path"]) == Path(result["staging_root"]) / "activation" / "config.private.json")


class BoundedCapture(io.TextIOBase):
    def __init__(self):
        self.body = bytearray()

    def write(self, value):
        require(type(value) is str)
        raw = value.encode("utf-8")
        require(len(self.body) + len(raw) <= MAX_RECORD)
        self.body.extend(raw)
        return len(value)


def hook_state_owner(profile_sha, installation_sha):
    exact_sha(profile_sha); exact_sha(installation_sha)
    return {"schema": HOOK_SCHEMA, "profile_sha256": profile_sha, "installation_sha256": installation_sha}


class HookState:
    """One separately enrolled create-only hook journal under an exclusive lock."""
    def __init__(self, profile, profile_sha, record, windows, installer, held):
        self.profile, self.profile_sha, self.record = profile, profile_sha, record
        self.windows, self.installer, self.held = windows, installer, held
        self.root = Path(profile["hook_state"])
        self.names = {"owner.json", "lock"}
        self.completed = 0; self.pending = False; self.started = None
        self.previous = None

    def _record(self, name):
        raw = self.held.enter_context(self.windows.hold_private_input(self.root / name, max_bytes=MAX_HOOK_RECORD))
        require(0 < len(raw) <= MAX_HOOK_RECORD)
        value = decode(raw); require(type(value) is dict and packed(value) == raw)
        return value, raw

    def _intent(self, value, attempt, previous):
        require(set(value) == {"schema", "attempt", "profile_sha256", "installation_sha256", "anchor_sha256",
            "project", "sequence", "generation_sequence", "journal", "selected_sha256", "helper_sha256",
            "engine_id", "docker_host", "previous_completion_sha256"}
            and value["schema"] == INTENT_SCHEMA and type(value["attempt"]) is int and value["attempt"] == attempt
            and value["profile_sha256"] == self.profile_sha
            and value["installation_sha256"] == self.profile["installation"]["sha256"]
            and value["anchor_sha256"] == self.record["anchor"]["sha256"]
            and value["project"] == self.record["project"]
            and value["helper_sha256"] == self.profile["hook"]["helper_sha256"]
            and value["previous_completion_sha256"] == previous
            and type(value["sequence"]) is int and type(value["generation_sequence"]) is int
            and 2 <= value["sequence"] <= value["generation_sequence"]
            and type(value["engine_id"]) is str and 0 < len(value["engine_id"]) <= 256
            and all(33 <= ord(char) <= 126 for char in value["engine_id"]))
        exact_sha(value["selected_sha256"]); windows_path(value["journal"])
        docker_host(value["docker_host"])

    def inspect(self):
        self.held.enter_context(self.windows.hold_storage_namespace(self.root.parent))
        self.held.enter_context(self.windows._held_private_input(self.root, directory=True, mutable_directory=True))
        require(self.held.enter_context(self.windows.hold_private_input(self.root / "lock", exclusive=True)) == b"")
        owner = packed(hook_state_owner(self.profile_sha, self.profile["installation"]["sha256"]))
        require(self.held.enter_context(self.windows.hold_private_input(self.root / "owner.json")) == owner)
        names = directory_names(self.root, 2 + 2 * MAX_HOOK_ATTEMPTS)
        require(self.names <= names and len(names) <= 2 + 2 * MAX_HOOK_ATTEMPTS)
        records = names - self.names
        require(all(re.fullmatch(r"[0-9]{6}\.(?:intent|complete)\.json", name) for name in records))
        attempts = {int(name[:6]) for name in records}
        require(not attempts or 1 <= max(attempts) <= MAX_HOOK_ATTEMPTS
                and attempts == set(range(1, max(attempts) + 1)))
        previous_generation = 0
        for attempt in range(1, len(attempts) + 1):
            intent_name, complete_name = f"{attempt:06}.intent.json", f"{attempt:06}.complete.json"
            require(intent_name in records)
            intent, raw = self._record(intent_name)
            self._intent(intent, attempt, self.previous)
            require(intent["generation_sequence"] > previous_generation)
            previous_generation = intent["generation_sequence"]
            if complete_name not in records:
                require(attempt == len(attempts)); self.pending = True
                continue
            complete, completed_raw = self._record(complete_name)
            require(type(complete.get("attempt")) is int
                    and complete == {"schema": COMPLETE_SCHEMA, "attempt": attempt,
                    "profile_sha256": self.profile_sha, "installation_sha256": self.profile["installation"]["sha256"],
                    "intent_sha256": digest(raw), "result": "google-idp-verified"})
            self.previous = digest(completed_raw); self.completed += 1
        self.names = names
        self.last_generation = previous_generation

    def _create(self, name, value):
        require(name not in self.names and directory_names(self.root, 2 + 2 * MAX_HOOK_ATTEMPTS) == self.names)
        raw = packed(value); require(len(raw) <= MAX_HOOK_RECORD)
        self.installer.private_write(self.root / name, raw, self.windows, MAX_HOOK_RECORD)
        require(self.held.enter_context(self.windows.hold_private_input(
            self.root / name, max_bytes=MAX_HOOK_RECORD)) == raw)
        self.names.add(name)
        require(directory_names(self.root, 2 + 2 * MAX_HOOK_ATTEMPTS) == self.names)
        return raw

    def begin(self, lease):
        require(not self.pending and self.started is None and self.completed < MAX_HOOK_ATTEMPTS
                and lease.generation_sequence > self.last_generation)
        attempt = self.completed + 1
        value = {"schema": INTENT_SCHEMA, "attempt": attempt, "profile_sha256": self.profile_sha,
                 "installation_sha256": self.profile["installation"]["sha256"],
                 "anchor_sha256": self.record["anchor"]["sha256"], "project": lease.project,
                 "sequence": lease.sequence, "generation_sequence": lease.generation_sequence,
                 "journal": str(lease.journal_path).replace("\\", "/"), "selected_sha256": lease.selected_sha256,
                 "helper_sha256": self.profile["hook"]["helper_sha256"], "engine_id": lease.engine_id,
                 "docker_host": lease.docker_host, "previous_completion_sha256": self.previous}
        self._intent(value, attempt, self.previous)
        self.started = self._create(f"{attempt:06}.intent.json", value)
        self.pending = True

    def complete(self):
        require(self.pending and self.started is not None)
        attempt = self.completed + 1
        value = {"schema": COMPLETE_SCHEMA, "attempt": attempt, "profile_sha256": self.profile_sha,
                 "installation_sha256": self.profile["installation"]["sha256"],
                 "intent_sha256": digest(self.started), "result": "google-idp-verified"}
        raw = self._create(f"{attempt:06}.complete.json", value)
        self.previous = digest(raw); self.completed += 1; self.pending = False


@contextmanager
def held_hook_state(profile, profile_sha, record, windows, installer):
    with ExitStack() as held:
        state = HookState(profile, profile_sha, record, windows, installer, held)
        state.inspect()
        try:
            yield state
        finally:
            require(directory_names(state.root, 2 + 2 * MAX_HOOK_ATTEMPTS) == state.names)


def perform_operation(profile, record, options, selection, renewal, recovery, windows, *, state):
    anchor = Path(record["anchor"]["path"])
    mode = options["mode"]
    # Check-only is also an enrollment gate, so a pending hook cannot produce
    # an apparently ready zero status. No owner/Docker callback runs here.
    require(not state.pending)
    if mode == "check":
        with selection.selected_inputs(anchor) as lease:
            require(lease.project == record["project"] and type(lease.sequence) is int
                    and type(lease.generation_sequence) is int and 1 <= lease.sequence <= lease.generation_sequence)
            exact_sha(lease.selected_sha256)
            result = {"schema": RESULT_SCHEMA, "result": "bindings-and-history-verified",
                      "project": lease.project, "sequence": lease.sequence,
                      "generation_sequence": lease.generation_sequence, "selected_sha256": lease.selected_sha256,
                      "source_commit": record["source"]["source_commit"],
                      "active_callers_migrated": False, "credential_admission": False, "runtime_admission": False}
        return result, None
    if mode == "explicit":
        arguments = options["arguments"]
        if "--logical-project" in arguments:
            require(arguments["--logical-project"] == profile["logical_project"])
        with windows.hold_private_input(Path(arguments["--configuration"])) as raw:
            config = decode(raw)
            require(type(config) is dict and set(config) == {"schema", "selection_file"}
                    and config["schema"] == "marty.windows-managed-recovery/v1"
                    and Path(config["selection_file"]) == anchor)
            output, errors = BoundedCapture(), BoundedCapture()
            argv = [part for pair in arguments.items() for part in pair]
            with redirect_stdout(output), redirect_stderr(errors):
                code = recovery.main(argv)
            require(type(code) is int and code == 0 and output.body)
            result = decode(bytes(output.body))
            require(type(result) is dict and packed(result) == bytes(output.body))
        return result, bytes(output.body)
    require(mode == "renew")
    require(state.completed < MAX_HOOK_ATTEMPTS)
    outcome = selection.renew_once(anchor, profile["logical_project"])
    # A later or different generation must not borrow this renewal's authority
    # to run the follow-up hook. Reacquire the same owner and compare its exact
    # journal/configuration binding while that lease remains held.
    with selection.selected_inputs(anchor) as lease:
        checked_renewed_selection(outcome, lease, record, selection, windows)
        verify_hook_engine(profile, lease, renewal)
        state.begin(lease)
        run_hook(profile, lease, renewal, windows)
        result = {"schema": RESULT_SCHEMA, "result": "renewed-and-selected",
                  "project": lease.project, "sequence": lease.sequence,
                  "generation_sequence": lease.generation_sequence, "selected_sha256": lease.selected_sha256,
                  "google_idp_verified": True, "active_callers_migrated": False,
                  "credential_admission": False, "runtime_admission": False}
    return result, None


def append_log(path, line, windows):
    """Append one bounded nonsecret summary to an existing private NTFS file.

    This deliberately does not reuse the empty-file initializer as an appender.
    A verified no-write-sharing handle owns the complete append and readback.
    Partial writes/flush/exit errors are uncertain and are never retried.
    """
    require(os.name == "nt" and type(line) is bytes and 0 < len(line) <= MAX_LOG_ENTRY
            and line.endswith(b"\n") and line.count(b"\n") == 1)
    from ctypes import wintypes as w
    path = Path(path)
    with windows.hold_storage_namespace(path.parent):
        before = windows._path_identities(path)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        security = ctypes.WinDLL("advapi32", use_last_error=True)
        pointer = ctypes.c_void_p
        def bind(dll, name, args, result):
            function = getattr(dll, name); function.argtypes = args; function.restype = result
            return function
        create = bind(kernel, "CreateFileW", [w.LPCWSTR, w.DWORD, w.DWORD, pointer, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE)
        close = bind(kernel, "CloseHandle", [w.HANDLE], w.BOOL)
        info = bind(kernel, "GetFileInformationByHandleEx", [w.HANDLE, ctypes.c_int, pointer, w.DWORD], w.BOOL)
        volume = bind(kernel, "GetVolumeInformationByHandleW", [w.HANDLE, w.LPWSTR, w.DWORD, pointer, pointer, pointer, w.LPWSTR, w.DWORD], w.BOOL)
        read = bind(kernel, "ReadFile", [w.HANDLE, pointer, w.DWORD, ctypes.POINTER(w.DWORD), pointer], w.BOOL)
        write = bind(kernel, "WriteFile", [w.HANDLE, pointer, w.DWORD, ctypes.POINTER(w.DWORD), pointer], w.BOOL)
        seek = bind(kernel, "SetFilePointerEx", [w.HANDLE, ctypes.c_longlong, pointer, w.DWORD], w.BOOL)
        flush = bind(kernel, "FlushFileBuffers", [w.HANDLE], w.BOOL)
        descriptor = bind(security, "GetSecurityInfo", [w.HANDLE, w.DWORD, w.DWORD, pointer, pointer, pointer, pointer, ctypes.POINTER(pointer)], w.DWORD)
        descriptor_length = bind(security, "GetSecurityDescriptorLength", [pointer], w.DWORD)
        free = bind(kernel, "LocalFree", [pointer], pointer)
        # GENERIC_WRITE is required by the documented FlushFileBuffers contract.
        # OPEN_EXISTING and exactly READ sharing; the only write below follows
        # a checked EOF seek, with complete old-prefix/appended-byte readback.
        handle = create(str(path), 0xC0020080, 1, None, 3, 0x80200000, None)
        require(handle not in (None, ctypes.c_void_p(-1).value))
        try:
            # Duplicate an already-open append handle for the existing unchanged
            # privacy checker would violate share-read. Prove ACL through this
            # same handle, using the exact universal checked_acl policy below.
            prove_log_acl(handle, windows, kernel, security)
            baseline_descriptor = pointer()
            require(descriptor(handle, 1, 5, None, None, None, None, ctypes.byref(baseline_descriptor)) == 0)
            try:
                size = descriptor_length(baseline_descriptor); require(0 < size <= 65535)
                baseline_acl = ctypes.string_at(baseline_descriptor, size)
            finally:
                free(baseline_descriptor)
            class FileId(ctypes.Structure):
                _fields_ = [("volume", ctypes.c_ulonglong), ("identifier", ctypes.c_ubyte * 16)]
            class Standard(ctypes.Structure):
                _fields_ = [("allocated", ctypes.c_longlong), ("size", ctypes.c_longlong),
                            ("links", w.DWORD), ("delete_pending", ctypes.c_byte), ("directory", ctypes.c_byte)]
            require(sys.implementation.name == "cpython" and sys.version_info >= (3, 12))
            def identity():
                value, standard = FileId(), Standard()
                require(info(handle, 18, ctypes.byref(value), ctypes.sizeof(value))
                        and info(handle, 1, ctypes.byref(standard), ctypes.sizeof(standard)))
                require((value.volume, int.from_bytes(bytes(value.identifier), "little")) == before[-1]
                        and standard.links == 1 and not standard.directory and not standard.delete_pending
                        and 0 <= standard.size <= MAX_LOG and windows._path_identities(path) == before)
                return standard.size
            filesystem = ctypes.create_unicode_buffer(32)
            require(volume(handle, None, 0, None, None, None, filesystem, len(filesystem)) and filesystem.value == "NTFS")
            old_size = identity(); require(old_size + len(line) <= MAX_LOG)
            def contents(length):
                require(seek(handle, 0, None, 0))
                buffer, count = ctypes.create_string_buffer(length + 1), w.DWORD()
                require(read(handle, buffer, length + 1, ctypes.byref(count), None) and count.value == length)
                return buffer.raw[:length]
            old = contents(old_size); require(not old or old.endswith(b"\n"))
            require(identity() == old_size)
            require(seek(handle, 0, None, 2))
            written = w.DWORD(); buffer = ctypes.create_string_buffer(line)
            require(write(handle, buffer, len(line), ctypes.byref(written), None)
                    and written.value == len(line) and flush(handle))
            require(identity() == old_size + len(line) and contents(old_size + len(line)) == old + line)
            prove_log_acl(handle, windows, kernel, security)
            final_descriptor = pointer()
            require(descriptor(handle, 1, 5, None, None, None, None, ctypes.byref(final_descriptor)) == 0)
            try:
                size = descriptor_length(final_descriptor)
                require(size == len(baseline_acl) and ctypes.string_at(final_descriptor, size) == baseline_acl)
            finally:
                free(final_descriptor)
            require(identity() == old_size + len(line))
        finally:
            require(close(handle))


def prove_log_acl(handle, windows, kernel, security):
    """Use the retained current-user/owner/DACL policy on the append handle."""
    from ctypes import wintypes as w
    pointer = ctypes.c_void_p; pp = ctypes.POINTER(pointer)
    def bind(dll, name, args, result):
        function = getattr(dll, name); function.argtypes = args; function.restype = result
        return function
    close = bind(kernel, "CloseHandle", [w.HANDLE], w.BOOL)
    free = bind(kernel, "LocalFree", [pointer], pointer)
    get_process = bind(kernel, "GetCurrentProcess", [], w.HANDLE)
    open_token = bind(security, "OpenProcessToken", [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL)
    token_info = bind(security, "GetTokenInformation", [w.HANDLE, w.DWORD, pointer, w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL)
    sid_valid = bind(security, "IsValidSid", [pointer], w.BOOL)
    sid_length = bind(security, "GetLengthSid", [pointer], w.DWORD)
    sid_string = bind(security, "ConvertSidToStringSidW", [pointer, ctypes.POINTER(w.LPWSTR)], w.BOOL)
    get_security = bind(security, "GetSecurityInfo", [w.HANDLE, w.DWORD, w.DWORD, pp, pp, pp, pp, pp], w.DWORD)
    get_acl = bind(security, "GetAclInformation", [pointer, pointer, w.DWORD, w.DWORD], w.BOOL)
    get_ace = bind(security, "GetAce", [pointer, w.DWORD, pp], w.BOOL)
    def sid_text(sid):
        require(sid and sid_valid(sid)); text = w.LPWSTR()
        require(sid_string(sid, ctypes.byref(text)))
        try:
            return text.value
        finally:
            require(not free(ctypes.cast(text, pointer)))
    token = w.HANDLE(); require(open_token(get_process(), 8, ctypes.byref(token)))
    try:
        needed = w.DWORD(); token_info(token, 1, None, 0, ctypes.byref(needed))
        require(0 < needed.value <= 4096); buffer = ctypes.create_string_buffer(needed.value)
        require(token_info(token, 1, buffer, len(buffer), ctypes.byref(needed)))
        user = sid_text(ctypes.cast(buffer, pp)[0])
    finally:
        require(close(token))
    owner, dacl, allocated = pointer(), pointer(), pointer()
    require(get_security(handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(allocated)) == 0)
    try:
        class AclSize(ctypes.Structure):
            _fields_ = [("count", w.DWORD), ("used", w.DWORD), ("free", w.DWORD)]
        size = AclSize(); require(dacl and get_acl(dacl, ctypes.byref(size), ctypes.sizeof(size), 2))
        require(1 <= size.count <= 3 and size.used <= 65535)
        entries = []
        for index in range(size.count):
            item = pointer(); require(get_ace(dacl, index, ctypes.byref(item)))
            header = ctypes.string_at(item, 8); length = int.from_bytes(header[2:4], "little")
            require(header[0] == 0 and length >= 16)
            sid = item.value + 8; require(sid_valid(sid) and sid_length(sid) <= length - 8)
            entries.append((sid_text(sid), header[0], header[1], int.from_bytes(header[4:8], "little")))
        windows.checked_acl(sid_text(owner), user, entries)
    finally:
        require(not free(allocated))


def summary_line(result, options):
    summary = {"utc": datetime.now(timezone.utc).isoformat(), "result": result["result"]}
    if options["mode"] == "renew":
        summary.update(sequence=result["sequence"], generation_sequence=result["generation_sequence"], google_idp_verified=True)
    else:
        summary["phase"] = options["arguments"]["--expired-current"]
    raw = packed(summary); require(len(raw) <= MAX_LOG_ENTRY)
    return raw


def run(profile_path, expected_sha, argv=()):
    options = parse_arguments(argv)
    profile = windows = None
    log_attempted = False
    try:
        with ExitStack() as coordination:
            with held_caller(profile_path, expected_sha) as (profile, record, selection, renewal, recovery, windows, installer):
                state = coordination.enter_context(held_hook_state(profile, expected_sha, record, windows, installer))
                result, explicit = perform_operation(profile, record, options, selection, renewal, recovery, windows, state=state)
            if options["mode"] == "renew":
                state.complete()
        # Every selected-owner and source/caller/private-input exit has completed
        # before summary logging or forwarding an explicit owner's JSON result.
        if options["mode"] != "check":
            logged = result if options["mode"] == "renew" else {"result": "explicit-recovery-phase-completed"}
            log_attempted = True
            append_log(Path(profile["log"]), summary_line(logged, options), windows)
        return result, explicit
    except BaseException as error:
        if profile is not None and windows is not None and options["mode"] != "check" and not log_attempted:
            try:
                kind = type(error).__name__
                require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", kind))
                append_log(Path(profile["log"]), packed({"utc": datetime.now(timezone.utc).isoformat(),
                           "result": "operator-reconciliation-required", "error_type": kind}), windows)
            except BaseException:
                pass
        raise


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        require(os.name == "nt" and sys.platform == "win32" and sys.flags.isolated
                and sys.dont_write_bytecode and not sys.flags.optimize
                and sys.implementation.name == "cpython" and sys.version_info >= (3, 12))
        require(len(argv) >= 2 and argv[0] == "--expected-profile-sha256")
        exact_sha(argv[1])
        result, explicit = run(Path(__file__).absolute().parent / PROFILE, argv[1], argv[2:])
        output = explicit if explicit is not None else packed(result)
        require(len(output) <= MAX_RECORD)
        sys.stdout.write(output.decode("utf-8"))
        return 0
    except BaseException:
        sys.stderr.write(REFUSAL + ".\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
