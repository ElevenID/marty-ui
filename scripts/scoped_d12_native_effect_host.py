"""Source-bound D12 host callbacks shared by the real cutover executor.

This supplies actual private persistence, fresh current-role observations,
quiescence and bounded health reads. It does not mint dispatch authority or
replace the full-resource and PostgreSQL catalog checks.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import time
from copy import deepcopy
from pathlib import Path

from scoped_d12_native_host import D12ReadOnlyHost
from scoped_native_database import bounded_run
from scoped_linux_journal import LinuxBuildJournal
from scoped_native_runtime import daemon_source, read_executable_ref, read_ref, ref, require, sha
from scoped_passport_maintenance import exact_roles, observed_role_state, same_full_role_snapshot
from scoped_passport_successor import CURRENT_PROFILE
from scoped_native_profiles import D12_PASSPORT_CURRENT, current_rollout_build

LOCK_OWNER_SHA = "c4531f96157232ea4adc2a28e8822e3daa364d394e609a734820610c45760d89"
COMPOSE_PLUGIN_SHA = "7ab786491f8445d22c0779678a562116f09a7efe3a7a1c56f157c1fd6c4085f0"

RESOURCE_VERIFY_JS = r"""const fs=require('node:fs'),cp=require('node:child_process'),crypto=require('node:crypto');
const [modulePath,moduleHash,profilePath,profileHash,dockerPath]=process.argv.slice(1);
const digest=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
if(digest(modulePath)!==moduleHash||digest(profilePath)!==profileHash)throw Error('D12_RESOURCE_SOURCE_CHANGED');
const runtime=require(modulePath),profile=JSON.parse(fs.readFileSync(profilePath));
const readDocker=argv=>cp.execFileSync(dockerPath,['--context','desktop-linux',...argv],
 {encoding:'utf8',env:process.env,timeout:150000,maxBuffer:1048576});
const result=runtime.verifyFunctionalRuntime(profile,{qualification:'FUNCTIONAL_ONLY',readDocker});
if(digest(modulePath)!==moduleHash||digest(profilePath)!==profileHash)throw Error('D12_RESOURCE_SOURCE_CHANGED');
process.stdout.write(JSON.stringify(result));"""


class D12HeldCanonicalLock:
    """Hold the existing beta_operation_lock owner on the canonical recorder lock.

    The owner opens O_EXCL and retains its fd for the entire context. Both
    executor lock predicates refer to this one held OS lock; no nested lock or
    caller-supplied boolean is accepted.
    """

    def __init__(self, owner_ref, lock_path, run_id):
        source = read_ref(owner_ref, 16_384)
        require(source.name == "beta_operation_lock.py" and sha(source) == LOCK_OWNER_SHA,
                "D12_EXISTING_LOCK_OWNER_REQUIRED")
        path = Path(lock_path).resolve()
        require(path.name == ".recording.lock" and path.parent.name == "artifacts"
                and path.parent.parent.name == "marty-demo-recorder"
                and path.parent.is_dir() and not path.parent.is_symlink(),
                "D12_CANONICAL_RECORDING_LOCK_REQUIRED")
        require(isinstance(run_id, str) and re.fullmatch(r"[a-f0-9-]{36}", run_id),
                "D12_RUN_ID_REQUIRED")
        spec = importlib.util.spec_from_file_location("reviewed_beta_operation_lock", source)
        require(spec is not None and spec.loader is not None, "D12_LOCK_OWNER_IMPORT_REQUIRED")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        require(callable(module.operation_lock), "D12_LOCK_OWNER_CONTRACT_REQUIRED")
        self._owner, self.path, self.action = module, path, "d12-current-" + run_id
        self._context, self._identity = None, None

    def __enter__(self):
        require(self._context is None, "D12_LOCK_LEASE_ALREADY_ENTERED")
        context = self._owner.operation_lock(self.path, self.action)
        context.__enter__()
        self._context = context
        try:
            stat = self.path.stat()
            value = json.loads(self.path.read_bytes())
            require(value == {"pid": os.getpid(), "action": self.action},
                    "D12_LOCK_OWNER_READBACK_CHANGED")
            self._identity = (stat.st_dev, stat.st_ino)
            require(self.held(), "D12_LOCK_NOT_HELD")
        except BaseException:
            context.__exit__(*__import__("sys").exc_info())
            self._context, self._identity = None, None
            raise
        return self

    def held(self):
        if self._context is None or self._identity is None:
            return False
        try:
            stat = self.path.stat()
            return (stat.st_dev, stat.st_ino) == self._identity and not self.path.is_symlink() \
                and json.loads(self.path.read_bytes()) == {"pid": os.getpid(), "action": self.action}
        except (OSError, ValueError, json.JSONDecodeError):
            return False

    def __exit__(self, kind, value, trace):
        context, self._context = self._context, None
        self._identity = None
        require(context is not None, "D12_LOCK_LEASE_NOT_ENTERED")
        return context.__exit__(kind, value, trace)


class D12CurrentEffectObserver:
    """Fresh exact-CID reads, with one durable selected-create transition."""

    def __init__(self, host, selection_ref, store, save, profile=CURRENT_PROFILE, *, native_preimage=None):
        self.native_preimage=native_preimage
        self.profile = profile
        self.build_profile = current_rollout_build(profile)
        require(type(host) is D12ReadOnlyHost and type(store) is LinuxBuildJournal,
                "D12_REVIEWED_OBSERVER_REQUIRED")
        self.host, self.selection_ref, self.store, self.save = host, selection_ref, store, save
        self.original = deepcopy(host.before)
        self.current = deepcopy(host.before)
        self.created_ref = None

    def _engine(self):
        self.host._recheck_source()
        engine = self.host._docker(["info", "--format", "{{.ID}}"])
        if isinstance(engine, bytes):
            engine = engine.decode("utf-8", "strict")
        require(isinstance(engine, str) and engine.strip() == self.host.engine_id,
                "D12_ENGINE_CHANGED")

    def _inspect(self, ids):
        self._engine()
        require(isinstance(ids, list) and ids and len(ids) == len(set(ids))
                and set(ids).issubset({row["containerId"] for row in self.current.values()}),
                "D12_EXACT_OWNED_INSPECT_IDS_REQUIRED")
        rows = json.loads(self.host._docker(["inspect", *ids]))
        require(isinstance(rows, list) and len(rows) == len(ids)
                and {row.get("Id") for row in rows} == set(ids),
                "D12_EXACT_OWNED_INSPECTION_REQUIRED")
        return {row["Id"]: row for row in rows}

    def _project(self, role, actual):
        bound = self.current[role]
        labels = actual.get("Config", {}).get("Labels", {})
        require(actual.get("Id") == bound["containerId"] and actual.get("Image") == bound["imageId"]
                and labels.get("com.docker.compose.project") == bound["project"]
                and labels.get("com.docker.compose.service") == role,
                "D12_OWNED_ROLE_IDENTITY_CHANGED:" + role)
        if self.profile=="d05-membership-current-functional" and role in dict(self.build_profile.roles) and bound["containerId"]!=self.original[role]["containerId"] and not self.original[role]["binaryMounts"]:
            from scoped_beta_binary_overlay import _overlaps_executable
            target="/usr/local/bin/"+dict(self.build_profile.roles)[role]
            affected=[m for m in actual["Mounts"] if _overlaps_executable(m["Destination"],target)]
            require(len(affected)==1 and affected[0]["Destination"]==target and affected[0]["Type"]=="bind" and affected[0]["RW"] is False,
                    "CURRENT10_CREATED_EXECUTABLE_MOUNT_AMBIGUOUS")
        return observed_role_state(bound, actual)

    def inspect_role(self, role):
        require(role in self.current, "D12_UNOWNED_ROLE_REFUSED")
        cid = self.current[role]["containerId"]
        return self._project(role, self._inspect([cid])[cid])

    def inspect_all22(self):
        ids = [self.current[role]["containerId"] for role in sorted(self.current)]
        actual = self._inspect(ids)
        rows = [self._project(role, actual[self.current[role]["containerId"]])
                for role in sorted(self.current)]
        snapshot = {"scope": "D12_STATE_PROJECTION_ONLY", "roles": rows,
                    "sourceFactsBoundToPriorReceiptNotNewElfProbe": True,
                    "releaseQualified": False, "recordingQualified": False}
        exact_roles(snapshot, self.profile)
        return snapshot

    def database_snapshot(self, database_ref):
        """Re-read the frozen beta PostgreSQL generation; this performs no SQL.

        PostgreSQL stays running during the application cutover. Its CID,
        image and process generation must remain the observed preimage.
        This identity read does not substitute for resource or catalog proof.
        """
        frozen = json.loads(read_ref(database_ref).read_bytes())
        require(isinstance(frozen, dict) and set(frozen) == {"databaseIdentity"},
                "D12_DATABASE_PREIMAGE_REQUIRED")
        bound = frozen["databaseIdentity"]
        require(isinstance(bound, dict) and set(bound) ==
                {"containerId", "imageId", "startedAt", "hostPid", "project", "service"}
                and re.fullmatch(r"[a-f0-9]{64}", bound.get("containerId", ""))
                and re.fullmatch(r"sha256:[a-f0-9]{64}", bound.get("imageId", ""))
                and isinstance(bound.get("startedAt"), str) and bool(bound["startedAt"])
                and type(bound.get("hostPid")) is int and bound["hostPid"] > 0
                and bound.get("project") == "elevenid-beta" and bound.get("service") == "postgres",
                "D12_BETA_DATABASE_IDENTITY_REQUIRED")
        self._engine()
        rows = json.loads(self.host._docker(["inspect", bound["containerId"]]))
        require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict),
                "D12_EXACT_DATABASE_INSPECTION_REQUIRED")
        actual = rows[0]
        state = actual.get("State", {})
        labels = actual.get("Config", {}).get("Labels", {})
        identity = {"containerId": actual.get("Id"), "imageId": actual.get("Image"),
                    "startedAt": state.get("StartedAt"), "hostPid": state.get("Pid"),
                    "project": labels.get("com.docker.compose.project"),
                    "service": labels.get("com.docker.compose.service")}
        require(identity == bound and state.get("Running") is True
                and state.get("Status") == "running" and state.get("Paused") is False
                and state.get("OOMKilled") is False
                and state.get("Health", {}).get("Status") == "healthy",
                "D12_DATABASE_GENERATION_OR_HEALTH_CHANGED")
        self._engine()
        return {"databaseIdentity": identity}

    def bind_created_after_ack(self, step, state):
        if step != "CREATE_SELECTED":
            return None
        require(self.created_ref is None and state.get("phase") == "EFFECT_ACKNOWLEDGED"
                and state.get("acknowledgedStep") == step,
                "D12_CREATED_ACK_REQUIRED")
        durable = self.store.read("build-state.json")
        require(durable.get("phase") == state["phase"] and durable.get("acknowledgedStep") == step
                and durable.get("runId") == state["runId"],
                "D12_DURABLE_CREATE_ACK_REQUIRED")
        selection = json.loads(read_ref(self.selection_ref).read_bytes())
        roles = dict(self.build_profile.roles)
        require(set(selection.get("binaries", {})) == set(roles)
                and selection.get("sourceRevision") == self.build_profile.ui_revision
                and selection.get("coreRevision") == self.build_profile.core_revision,
                "D12_EXACT_SELECTED_BUILD_REQUIRED")
        self._engine()
        newly = {}
        old_ids = {row["containerId"] for row in self.original.values()}
        for role in sorted(roles):
            raw = self.host._docker(["ps", "-aq", "--no-trunc",
                "--filter", "label=com.docker.compose.project=" + self.original[role]["project"],
                "--filter", "label=com.docker.compose.service=" + role])
            ids = raw.decode("utf-8", "strict").split() if isinstance(raw, bytes) else raw.split()
            require(len(ids) == 1 and re.fullmatch(r"[a-f0-9]{64}", ids[0]) and ids[0] not in old_ids
                    and ids[0] not in newly.values(), "D12_SELECTED_CREATE_CID_AMBIGUOUS:" + role)
            newly[role] = ids[0]
        proposed = deepcopy(self.original)
        for role, cid in newly.items():
            binary = selection["binaries"][role]
            require(Path(binary.get("path", "")).name == roles[role]
                    and re.fullmatch(r"[a-f0-9]{64}", binary.get("sha256", "")),
                    "D12_SELECTED_BINARY_CHANGED:" + role)
            read_executable_ref(binary)
            target = "/usr/local/bin/" + roles[role]
            mounts = proposed[role]["binaryMounts"]
            matches = [row for row in mounts if row["destination"] == target]
            if self.profile=="d05-membership-current-functional" and not matches:
                from scoped_beta_binary_overlay import image_owned_baseline
                image_owned_baseline(role,roles[role],self.native_preimage,self.original[role])
                mounts.append({"type":"bind","source":daemon_source(binary["path"]),"destination":target,"writable":False})
            else:
                require(len(matches) == 1 and matches[0]["type"] == "bind"
                        and matches[0]["writable"] is False and binary.get("path"),
                        "D12_SELECTED_MOUNT_SOURCE_REQUIRED:" + role)
                matches[0]["source"] = daemon_source(binary["path"])
            proposed[role]["containerId"] = cid
        # Inspect every role against the proposed immutable lineage before
        # switching the observer. A foreign same-image CID or mount is refused.
        current = self.current
        self.current = proposed
        try:
            snapshot = self.inspect_all22()
            by_role = exact_roles(snapshot, self.profile)
            require(all(by_role[role]["state"] == "created" and by_role[role]["hostPid"] == 0
                        and by_role[role]["oomKilled"] is False for role in roles),
                    "D12_SELECTED_CREATED_STATE_REQUIRED")
            require(all(by_role[role]["containerId"] == self.original[role]["containerId"]
                        for role in set(self.original) - set(roles)),
                    "D12_UNSELECTED_CID_CHANGED")
            proof = {"schema": "marty.d12-owned-created-cids/v1", "runId": state["runId"],
                     "durableCreateAck": {"phase": durable["phase"], "acknowledgedStep": step},
                     "selection": self.selection_ref, "selectedContainerIds": newly,
                     "runtimeWrites": True, "releaseQualified": False}
            self.created_ref = self.save("d12-created-cids-after-ack.private.json", proof)
            return self.created_ref
        except BaseException:
            self.current = current
            raise


class D12CurrentHostBindings:
    """Real shared callbacks. Effect dispatch stays false until Root binds the
    separate reviewed authority and fresh full resource28 proof.
    """

    def __init__(self, host, *, inputs_ref, private_root, operation_journal,
                 build_journal, node_executable, docker_executable, docker_config, docker_config_refs,
                 lock_lease=None, dispatch_permit_ref=None, compose_plugin_ref=None):
        require(type(host) is D12ReadOnlyHost and type(operation_journal) is LinuxBuildJournal
                and type(build_journal) is LinuxBuildJournal,
                "D12_REVIEWED_HOST_AND_JOURNALS_REQUIRED")
        effect_source = Path(__file__).resolve()
        require(effect_source == host._root / "scripts" / effect_source.name
                and sha(effect_source) == host._source_files.get(
                    "scripts/" + effect_source.name, {}).get("sha256"),
                "D12_EFFECT_HOST_SOURCE_CHANGED")
        self.effect_source_ref = ref(effect_source)
        self.inputs_ref = inputs_ref
        self.inputs = json.loads(read_ref(inputs_ref).read_bytes())
        self.profile = self.inputs.get("rolloutProfile", CURRENT_PROFILE)
        self.build_profile = current_rollout_build(self.profile)
        if self.profile == "d05-membership-current-functional":
            client_source=Path(LinuxBuildJournal.invoke.__code__.co_filename).resolve()
            require(client_source==host._root/"scripts/scoped_linux_journal.py"
                    and sha(client_source)==host._source_files.get("scripts/scoped_linux_journal.py",{}).get("sha256"),
                    "CURRENT_TEN_REVIEWED_JOURNAL_CLIENT_REQUIRED")
            frozen_refs=self.inputs.get("journalSourceFiles")
            require(isinstance(frozen_refs,dict) and set(frozen_refs)=={"operation","build"},"CURRENT_TEN_FROZEN_JOURNAL_REFS_REQUIRED")
            for role,store in (("operation",operation_journal),("build",build_journal)):
                require(store.source_files is not None and store.source_files==frozen_refs[role],"CURRENT_TEN_FROZEN_JOURNAL_REFS_REQUIRED")
                store.verified_source_files()
        self.root = Path(private_root).resolve()
        require(self.root.is_dir() and not self.root.is_symlink()
                and self.root.is_relative_to(Path.home() / ".codex/private")
                and self.root != Path(operation_journal.private).resolve()
                and self.root != Path(build_journal.private).resolve(),
                "D12_DISTINCT_PRIVATE_OPERATION_ROOT_REQUIRED")
        self.host, self.store, self.build_journal = host, operation_journal, build_journal
        selection_ref = self.inputs.get("selection")
        require(isinstance(selection_ref, dict), "D12_SELECTION_REF_REQUIRED")
        native_preimage=None
        if self.profile=="d05-membership-current-functional":
            abi_plan=json.loads(read_ref(self.inputs["compatibility"]["plan"]).read_bytes())
            require(abi_plan["beforeBinding"]["sha256"]==self.inputs["runtimeBefore"]["sha256"],"CURRENT10_IMAGE_PREIMAGE_BINDING_CHANGED")
            native_preimage={"binding":self.inputs["runtimeBefore"],"inspections":abi_plan["nativeInspections"]}
        self.observer = D12CurrentEffectObserver(host, selection_ref, operation_journal, self.save, self.profile,native_preimage=native_preimage)
        self.node = read_executable_ref(node_executable)
        self.docker = read_executable_ref(docker_executable)
        self.node_ref, self.docker_ref = node_executable, docker_executable
        config = Path(docker_config).resolve()
        require(config.is_dir() and not config.is_symlink(), "D12_PINNED_DOCKER_CONFIG_REQUIRED")
        self.config = config
        require(isinstance(docker_config_refs, dict) and docker_config_refs
                and all(Path(name).is_absolute() and Path(name).resolve().is_relative_to(config)
                        and read_ref(bound).resolve() == Path(name).resolve()
                        for name, bound in docker_config_refs.items()),
                "D12_PINNED_DOCKER_CONFIG_FILES_REQUIRED")
        self.config_refs = dict(docker_config_refs)
        self.lock = lock_lease
        require(lock_lease is None or type(lock_lease) is D12HeldCanonicalLock,
                "D12_REAL_LOCK_CAPABILITY_REQUIRED")
        self.environment = {k: v for k, v in os.environ.items() if k.upper() in
            {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "COMSPEC", "PATHEXT"}}
        self.environment.update(PATH=";".join((str(self.docker.parent), "C:/Windows/System32")),
                                DOCKER_CONFIG=str(config), DOCKER_CONTEXT="desktop-linux")
        self.compose_plugin_ref = compose_plugin_ref
        self.compose_plugin = None
        self.dispatch_permit_ref = dispatch_permit_ref
        self.dispatch_permit = None
        if dispatch_permit_ref is not None:
            require(isinstance(compose_plugin_ref, dict), "D12_PINNED_COMPOSE_PLUGIN_REQUIRED")
            self.compose_plugin = read_executable_ref(compose_plugin_ref)
            self._check_compose_config()
            permit = json.loads(read_ref(dispatch_permit_ref, 65536).read_bytes())
            require(permit.get("schema") == "marty.d12-current-dispatch-intent/v1"
                    and permit.get("dispatchAuthorized") is True
                    and permit.get("runId") == self.inputs.get("runId")
                    and permit.get("scope") == "FUNCTIONAL_ONLY"
                    and permit.get("releaseQualified") is False
                    and permit.get("recordingQualified") is False
                    and permit.get("inputs") == inputs_ref
                    and permit.get("authority") == self.inputs.get("d12Authority")
                    and permit.get("resourceProfile") == self.inputs.get("resourceProfile")
                    and Path(dispatch_permit_ref["path"]).resolve().is_relative_to(
                        Path.home() / ".codex/private"),
                    "D12_EXACT_ROOT_DISPATCH_INTENT_REQUIRED")
            self.dispatch_permit = permit

    def _check_compose_config(self):
        require(self.compose_plugin is not None
                and self.compose_plugin.name.lower() == "docker-compose.exe"
                and self.compose_plugin_ref["sha256"] == COMPOSE_PLUGIN_SHA
                and read_executable_ref(self.compose_plugin_ref) == self.compose_plugin,
                "D12_EXACT_OFFICIAL_COMPOSE_PLUGIN_REQUIRED")
        config_path = self.config / "config.json"
        require(str(config_path) in self.config_refs
                and read_ref(self.config_refs[str(config_path)]).resolve() == config_path,
                "D12_OWNED_COMPOSE_CONFIG_REQUIRED")
        config = json.loads(config_path.read_bytes())
        require(config == {"currentContext": "desktop-linux",
                           "cliPluginsExtraDirs": [str(self.compose_plugin.parent)]},
                "D12_PINNED_COMPOSE_DISCOVERY_REQUIRED")
        meta = [Path(name) for name in self.config_refs if Path(name) != config_path]
        require(len(meta) == 1 and meta[0].name == "meta.json"
                and meta[0].parent.parent.name == "meta"
                and meta[0].parent.parent.parent.name == "contexts",
                "D12_PINNED_DESKTOP_CONTEXT_META_REQUIRED")
        return True

    def _probe_compose_discovery(self, observation_prefix=""):
        self.assert_inputs()
        result = bounded_run([str(self.docker), "--context", "desktop-linux",
                              "compose", "version", "--short"], env=self.environment,
                             timeout=30, stdout_limit=1024, stderr_limit=8192)
        self.save_bytes(observation_prefix + "d12-compose-version-stdout.private", result.stdout)
        self.save_bytes(observation_prefix + "d12-compose-version-stderr.private", result.stderr)
        self.save(observation_prefix + "d12-compose-version-terminal.private.json", {"exitCode": result.returncode,
            "observation": result.observation})
        require(type(result.returncode) is int and result.returncode == 0
                and result.observation["timedOut"] is False
                and not result.observation["failures"]
                and bool(result.stdout.strip()),
                "D12_PINNED_COMPOSE_DISCOVERY_FAILED")
        self.assert_inputs()
        return True

    def assert_inputs(self, *, rollback=False):
        require(rollback is False and json.loads(read_ref(self.inputs_ref).read_bytes()) == self.inputs,
                "D12_FROZEN_INPUTS_CHANGED")
        self.host._recheck_source()
        require(read_ref(self.effect_source_ref).resolve() == Path(__file__).resolve(),
                "D12_EFFECT_HOST_SOURCE_CHANGED")
        read_executable_ref(self.node_ref)
        read_executable_ref(self.docker_ref)
        require(self.config.is_dir() and not self.config.is_symlink(),
                "D12_DOCKER_CONFIG_CHANGED")
        for name, bound in self.config_refs.items():
            require(read_ref(bound).resolve() == Path(name).resolve(), "D12_DOCKER_CONFIG_FILE_CHANGED")
        if self.dispatch_permit_ref is not None:
            self._check_compose_config()
            require(json.loads(read_ref(self.dispatch_permit_ref, 65536).read_bytes()) == self.dispatch_permit,
                    "D12_DISPATCH_INTENT_CHANGED")
        return True

    @staticmethod
    def _bind_resource_rows(result, frozen):
        require(isinstance(result, dict) and result.get("scope") == "FUNCTIONAL_ONLY"
                and result.get("releaseQualified") is False
                and result.get("recordingQualified") is False
                and isinstance(result.get("roles"), list),
                "D12_ACTUAL_RESOURCE_RESULT_REQUIRED")
        expected = exact_roles(frozen, CURRENT_PROFILE)
        observed = exact_roles(result, CURRENT_PROFILE)
        for role, old in expected.items():
            row = observed[role]
            require(all(row.get(key) == old.get(key) for key in
                        ("containerId", "imageId", "project", "startedAt", "hostPid"))
                    and row.get("health") == old.get("health"),
                    "D12_RESOURCE28_AND_NATIVE22_DIVERGED:" + role)
        return True

    def authorization_verified(self, authority_ref):
        if self.dispatch_permit is None:
            return False
        self.assert_inputs()
        require(self.lock is not None and self.lock.held()
                and authority_ref == self.inputs.get("d12Authority")
                and self.dispatch_permit["authority"] == authority_ref,
                "D12_ROOT_INTENT_AND_HELD_LOCK_REQUIRED")
        self._authorization_attempt = getattr(self, "_authorization_attempt", 0) + 1
        attempt = self._authorization_attempt
        observation_prefix = f"d12-authorization-{attempt:04d}-"
        self._probe_compose_discovery(observation_prefix)
        profile_ref = self.dispatch_permit["resourceProfile"]
        profile = json.loads(read_ref(profile_ref, 2 * 1024 * 1024).read_bytes())
        require(profile.get("schema") == "marty.functional-mixed-runtime/v2"
                and profile.get("scope") == "FUNCTIONAL_ONLY"
                and profile.get("releaseQualified") is False
                and profile.get("recordingQualified") is False
                and isinstance(profile.get("resourceRestart"), dict),
                "D12_EXACT_RESTART_RESOURCE_PROFILE_REQUIRED")
        source_ref = self.inputs.get("functionalRuntimeModule")
        require(isinstance(source_ref, dict) and
                read_ref(source_ref).resolve() == self.host._root / "tests/scripts/functional-debug-runtime.js"
                and source_ref["sha256"] == self.host._source_files.get(
                    "tests/scripts/functional-debug-runtime.js", {}).get("sha256"),
                "D12_RESOURCE_VERIFIER_SOURCE_REQUIRED")
        require(read_ref(authority_ref, 65536).is_file(), "D12_EXACT_REVIEWED_AUTHORITY_REQUIRED")
        frozen = json.loads(read_ref(self.inputs["runtimeBefore"]).read_bytes())
        self.save(observation_prefix + "d12-resource28-request.private.json", {"runId": self.inputs["runId"],
            "source": source_ref, "resourceProfile": profile_ref,
            "runtimeBefore": self.inputs["runtimeBefore"], "scope": "FUNCTIONAL_ONLY"})
        result = bounded_run([str(self.node), "-e", RESOURCE_VERIFY_JS,
            source_ref["path"], source_ref["sha256"], profile_ref["path"],
            profile_ref["sha256"], str(self.docker)], env=self.environment,
            timeout=600, stdout_limit=1024 * 1024, stderr_limit=65536)
        self.save_bytes(observation_prefix + "d12-resource28-stdout.private", result.stdout)
        self.save_bytes(observation_prefix + "d12-resource28-stderr.private", result.stderr)
        self.save(observation_prefix + "d12-resource28-terminal.private.json", {"exitCode": result.returncode,
            "observation": result.observation})
        require(type(result.returncode) is int and result.returncode == 0
                and result.observation["timedOut"] is False
                and not result.observation["failures"],
                "D12_ACTUAL_RESOURCE28_VERIFIER_FAILED")
        actual = json.loads(result.stdout)
        self._bind_resource_rows(actual, frozen)
        self.assert_inputs()
        require(self.lock.held(), "D12_CANONICAL_LOCK_LOST_DURING_RESOURCE_READ")
        read_ref(profile_ref, 2 * 1024 * 1024)
        self.save(observation_prefix + "d12-resource28-bound.private.json", {"runId": self.inputs["runId"],
            "source": source_ref, "resourceProfile": profile_ref,
            "runtimeBefore": self.inputs["runtimeBefore"],
            "full28AncillaryVerifiedByReviewedRuntime": True,
            "actualRoleCount": len(actual["roles"]), "releaseQualified": False,
            "authorizationAttempt": attempt,
            "observations": {name: ref(self.root / (observation_prefix + name)) for name in (
                "d12-compose-version-stdout.private", "d12-compose-version-stderr.private",
                "d12-compose-version-terminal.private.json", "d12-resource28-request.private.json",
                "d12-resource28-stdout.private", "d12-resource28-stderr.private",
                "d12-resource28-terminal.private.json")}})
        return True

    def save_bytes(self, name, data):
        require(isinstance(name, str) and Path(name).name == name and name not in ("", ".", "..")
                and isinstance(data, bytes) and len(data) <= 512 * 1024 * 1024,
                "D12_PRIVATE_OUTPUT_SCOPE_REQUIRED")
        target = self.root / name
        with target.open("xb") as stream:
            require(stream.write(data) == len(data), "D12_PRIVATE_SHORT_WRITE")
            stream.flush()
            os.fsync(stream.fileno())
        return ref(target)

    def save(self, name, value):
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        return self.save_bytes(name, raw)

    def verify_all22_quiescent(self, bound):
        self.assert_inputs()
        frozen = json.loads(read_ref(bound).read_bytes())
        rows = exact_roles(frozen, self.profile)
        state = self.store.read("build-state.json")
        require(state.get("phase") == "ALL22_QUIESCENT"
                and state.get("quiescenceSha256") == bound["sha256"],
                "D12_DURABLE_QUIESCENCE_NOT_BOUND")
        fresh = self.observer.inspect_all22()
        require(same_full_role_snapshot(fresh, frozen, self.profile),
                "D12_QUIESCENCE_CHANGED_BEFORE_DATABASE")
        require(all(row.get("state") == "exited" and row.get("running") is False
                    and row.get("paused") is False and row.get("oomKilled") is False
                    and row.get("hostPid") == 0 and type(row.get("containerExitCode")) is int
                    and row["containerExitCode"] == 0 for row in rows.values()),
                "D12_NOT_ALL22_CLEANLY_QUIESCENT")
        return True

    def wait_all22_healthy(self, seconds):
        require(type(seconds) is int and 0 < seconds <= 120, "D12_HEALTH_DEADLINE_REQUIRED")
        self.assert_inputs()
        expected = self.host.before
        deadline = time.monotonic() + seconds
        while True:
            rows = exact_roles(self.observer.inspect_all22(), self.profile)
            if all(row.get("running") is True and row.get("paused") is False
                   and row.get("oomKilled") is False and type(row.get("hostPid")) is int
                   and row["hostPid"] > 0 and row.get("state") == "running"
                   and row.get("health") == expected[role].get("health")
                   for role, row in rows.items()):
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(1.0, remaining))

    def context(self):
        # No caller-supplied booleans or forged database identity can promote
        # this source slice to an effect-capable D12 executor context.
        return {"dispatch_enabled": self.dispatch_permit is not None,
                "operation_lock_held": lambda: self.lock is not None and self.lock.held(),
                "recording_lock_held": lambda: self.lock is not None and self.lock.held(),
                "authorization_verified": self.authorization_verified,
                "observe22": self.observer.inspect_all22,
                "inspect_all22": self.observer.inspect_all22,
                "inspect_role": self.observer.inspect_role,
                "effect_acknowledged": self.observer.bind_created_after_ack,
                "compose_model": self.host.compose_model,
                "database_snapshot": self.database_snapshot,
                "verify_all22_quiescent": self.verify_all22_quiescent,
                "wait_all22_healthy": self.wait_all22_healthy,
                "save": self.save, "save_bytes": self.save_bytes, "ref": ref,
                "assert_inputs": self.assert_inputs, "root": self.root,
                "env": self.environment, "nodeExecutable": str(self.node),
                "build_journal": self.build_journal}

    def database_snapshot(self):
        self.assert_inputs()
        require(isinstance(self.inputs.get("databaseBefore"), dict),
                "D12_DATABASE_PREIMAGE_REQUIRED")
        return self.observer.database_snapshot(self.inputs["databaseBefore"])
