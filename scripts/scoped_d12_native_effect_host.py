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
from scoped_native_database import bounded_run, require_bound_quiescence, fence_install_recovery_checkpoint
from scoped_linux_journal import LinuxBuildJournal
from scoped_native_runtime import daemon_source, read_executable_ref, read_ref, ref, require, sha, selected_sources
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


MAINTENANCE_RESOURCE_VERIFY_JS = RESOURCE_VERIFY_JS.replace(
    "const [modulePath,moduleHash,profilePath,profileHash,dockerPath]=process.argv.slice(1);",
    "const [modulePath,moduleHash,profilePath,profileHash,dockerPath,recoveryJson]=process.argv.slice(1);"
).replace(
    "const result=runtime.verifyFunctionalRuntime(profile,{qualification:'FUNCTIONAL_ONLY',readDocker});",
    "const recoveryRef=JSON.parse(recoveryJson);"
    "if(digest(recoveryRef.path)!==recoveryRef.sha256)throw Error('RECOVERY_RESOURCE_CHANGED');"
    "const result=runtime.verifyMaintenanceRuntime(profile,{qualification:'MAINTENANCE_RECOVERY_ONLY',readDocker,recoveryRef});"
)


CREATED_TARGET_VERIFY_JS = RESOURCE_VERIFY_JS.replace(
    "const result=runtime.verifyFunctionalRuntime(profile,{qualification:'FUNCTIONAL_ONLY',readDocker});",
    "const result=runtime.verifyCreatedTargetModel(profile,{readDocker});"
)


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
        require(isinstance(frozen, dict) and set(frozen) in (
                    {"databaseIdentity"}, {"databaseIdentity", "engineId", "runtimeWrites"}),
                "D12_DATABASE_PREIMAGE_REQUIRED")
        if "engineId" in frozen:
            require(frozen["engineId"] == self.host.engine_id and frozen["runtimeWrites"] is False,
                    "D12_DATABASE_PREIMAGE_METADATA_CHANGED")
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
        return {**frozen, "databaseIdentity": identity}

    def prepare_credential_replacement(self,recovery_ref):
        recovery=json.loads(read_ref(recovery_ref).read_bytes())
        state=self.store.read("build-state.json")
        require(self.profile=="d05-membership-current-functional" and self.created_ref is not None and recovery.get("schema")=="marty.d12-created-recovery/v1"
                and recovery.get("operation") in ("REPLACE_CREATED_CREDENTIAL_GENERATION_AND_RESUME",
                    "REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME")
                and recovery.get("replaceCredentialGeneration") is True
                and recovery.get("dispatchAuthorized") is True and recovery.get("draftOnly") is False
                and state==json.loads(read_ref(recovery["originalOperationState"]).read_bytes()),
                "D12_CREATED_REPLACEMENT_AUTHORITY_REQUIRED")
        snapshot=self.inspect_all22();rows=exact_roles(snapshot,self.profile)
        selected=dict(self.build_profile.roles)
        require(all(row.get("state")==("created" if role in selected else "exited")
                and row.get("running") is False and row.get("hostPid")==0
                and row.get("paused") is False and row.get("oomKilled") is False
                and row.get("containerExitCode")==0 for role,row in rows.items()),
                "D12_CREATED_REPLACEMENT_PREIMAGE_REQUIRED")
        self._replacement_ready_authority=recovery_ref
        self._replacement_preimage_ids={row["containerId"] for row in rows.values()}
        return self.save("d12-created-credential-replacement-preimage.private.json",snapshot)

    def _created_projection(self,selection,newly):
        roles=dict(self.build_profile.roles)
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
        return proposed

    def bind_ob3_partial_created(self,recovery_ref):
        recovery=json.loads(read_ref(recovery_ref).read_bytes());state=self.store.read("build-state.json")
        require(state==json.loads(read_ref(recovery["originalOperationState"]).read_bytes())
                and state.get("phase")=="START_INSPECTION_PENDING","D12_OB3_PARTIAL_OBSERVER_STATE_CHANGED")
        created=json.loads(read_ref(state["created"]).read_bytes());rows=exact_roles(created,self.profile)
        selection=json.loads(read_ref(self.selection_ref).read_bytes());roles=dict(self.build_profile.roles)
        require(set(selection["binaries"])==set(roles) and selection["sourceRevision"]==self.build_profile.ui_revision
                and selection["coreRevision"]==self.build_profile.core_revision,"D12_OB3_SELECTED_SOURCE_CHANGED")
        newly={role:rows[role]["containerId"] for role in roles}
        require(len(set(newly.values()))==10 and not set(newly.values())&{row["containerId"] for row in self.original.values()},
                "D12_OB3_CREATED_CID_CHANGED")
        proposed=self._created_projection(selection,newly)
        for role,row in rows.items():
            require(row["containerId"]==proposed[role]["containerId"] and row["imageId"]==proposed[role]["imageId"],
                    "D12_OB3_CREATED_IDENTITY_CHANGED:"+role)
        for role in roles:
            proposed[role].update(source=selection["sourceRevision"],coreSource=selection["coreRevision"],
                sha256=selection["binaries"][role]["sha256"],kind="SCOPED_NATIVE_FUNCTIONAL_OVERLAY")
        self.current=proposed;self.created_ref=state["created"]
        return self.created_ref

    def bind_created_after_ack(self, step, state, *, reconciled_replacement=None):
        if step not in ("CREATE_SELECTED","REPLACE_CREATED_CREDENTIAL_GENERATION"):
            return None
        replacing=step=="REPLACE_CREATED_CREDENTIAL_GENERATION"
        resuming=reconciled_replacement is not None
        recovery=None
        if resuming:
            recovery=json.loads(read_ref(reconciled_replacement).read_bytes())
            require(replacing and recovery.get("schema")=="marty.d12-created-recovery/v1"
                    and recovery.get("operation") in ("RESUME_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT",
                        "REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME")
                    and recovery.get("dispatchAuthorized") is True and recovery.get("draftOnly") is False
                    and state==json.loads(read_ref(recovery["originalOperationState"]).read_bytes())
                    and state.get("replacementAuthority")==recovery["previousRecoveryAuthority"],
                    "D12_RECONCILED_REPLACEMENT_AUTHORITY_REQUIRED")
        require(not replacing or self.profile=="d05-membership-current-functional","D12_CREATED_REPLACEMENT_CURRENT10_ONLY")
        require((self.created_ref is None if resuming else self.created_ref is not None if replacing else self.created_ref is None)
                and state.get("phase") == "EFFECT_ACKNOWLEDGED"
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
        old_ids = {row["containerId"] for row in (self.current if replacing else self.original).values()}
        if resuming:
            previous=json.loads(read_ref(recovery["previousRecoveryAuthority"]).read_bytes())
            require(previous.get("operation") in ("REPLACE_CREATED_CREDENTIAL_GENERATION_AND_RESUME",
                    "REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME"),
                    "D12_RECONCILED_REPLACEMENT_AUTHORITY_REQUIRED")
            prior=json.loads(read_ref(previous["selected22"]).read_bytes())
            require(isinstance(prior,dict) and set(prior)==set(self.original)
                    and all(re.fullmatch(r"[a-f0-9]{64}",row.get("Id","")) for row in prior.values())
                    and len({row["Id"] for row in prior.values()})==len(prior),
                    "D12_RECONCILED_REPLACEMENT_PREIMAGE_REQUIRED")
            old_ids={row["Id"] for row in prior.values()} | {row["containerId"] for row in self.original.values()}
        elif replacing:
            require(getattr(self,"_replacement_ready_authority",None)==state.get("replacementAuthority")
                    and getattr(self,"_replacement_preimage_ids",None)==old_ids,
                    "D12_CREATED_REPLACEMENT_PREIMAGE_REQUIRED")
        for role in sorted(roles):
            raw = self.host._docker(["ps", "-aq", "--no-trunc",
                "--filter", "label=com.docker.compose.project=" + self.original[role]["project"],
                "--filter", "label=com.docker.compose.service=" + role])
            ids = raw.decode("utf-8", "strict").split() if isinstance(raw, bytes) else raw.split()
            require(len(ids) == 1 and re.fullmatch(r"[a-f0-9]{64}", ids[0]) and ids[0] not in old_ids
                    and ids[0] not in newly.values(), "D12_SELECTED_CREATE_CID_AMBIGUOUS:" + role)
            newly[role] = ids[0]
        if resuming:
            selected22=json.loads(read_ref(recovery["selected22"]).read_bytes())
            require(isinstance(selected22,dict) and set(selected22)==set(self.original)
                    and all(selected22[role].get("Id")==cid for role,cid in newly.items())
                    and all(selected22[role].get("Id")==self.original[role]["containerId"]
                        for role in set(self.original)-set(roles)),
                    "D12_RECONCILED_REPLACEMENT_CIDS_CHANGED")
        proposed=self._created_projection(selection,newly)
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
                     "runtimeWrites": not resuming, "releaseQualified": False}
            self.created_ref = self.save("d12-reconciled-replacement-cids.private.json" if resuming
                else "d12-credential-replacement-cids-after-ack.private.json" if replacing
                else "d12-created-cids-after-ack.private.json",proof)
            if replacing:
                self._replacement_ready_authority=None
                self._replacement_preimage_ids=None
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
                    and permit.get("scope") in ("FUNCTIONAL_ONLY","OB3_FUNCTIONAL_ONLY")
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
    def _bind_resource_rows(result, frozen, *, scope="FUNCTIONAL_ONLY"):
        require(isinstance(result, dict) and result.get("scope") == scope
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
        return self._authorization_verified(authority_ref)

    def _ob3_containment_read(self,recovery_ref,phase,outcomes):
        self.assert_inputs();require(self.lock is not None and self.lock.held(),"D12_OB3_CANONICAL_LOCK_REQUIRED")
        recovery=json.loads(read_ref(recovery_ref).read_bytes())
        source=self.inputs["functionalRuntimeModule"];profile=self.inputs["resourceProfile"]
        require(read_ref(source).resolve()==self.host._root/"tests/scripts/functional-debug-runtime.js"
                and source["sha256"]==self.host._source_files["tests/scripts/functional-debug-runtime.js"]["sha256"],
                "D12_OB3_CONTAINMENT_SOURCE_REQUIRED")
        script=RESOURCE_VERIFY_JS.replace("const result=runtime.verifyFunctionalRuntime(profile,{qualification:'FUNCTIONAL_ONLY',readDocker});",
            "const result=runtime.verifyOb3ContainmentRuntime(profile,{readDocker,recoveryRef:JSON.parse(process.argv[6]),phase:process.argv[7],outcomes:JSON.parse(process.argv[8])});")
        require("verifyOb3ContainmentRuntime" in script and "verifyFunctionalRuntime(profile" not in script,
                "D12_OB3_CONTAINMENT_ROUTING_REQUIRED")
        prefix="ob3-containment-"+phase.lower()
        result=bounded_run([str(self.node),"-e",script,source["path"],source["sha256"],profile["path"],profile["sha256"],
            str(self.docker),json.dumps(recovery_ref),phase,json.dumps(outcomes)],env=self.environment,
            timeout=420,stdout_limit=1024*1024,stderr_limit=65536)
        self.save_bytes(prefix+"-stdout.private",result.stdout);self.save_bytes(prefix+"-stderr.private",result.stderr)
        self.save(prefix+"-terminal.safe.json",{"exitCode":result.returncode,"observation":result.observation})
        require(result.returncode==0 and result.observation["timedOut"] is False and not result.observation["failures"],
                "D12_OB3_CURRENT28_CONTAINMENT_READ_FAILED")
        proof=json.loads(result.stdout)
        require(proof.get("schema")=="marty.ob3-containment-observation/v1" and proof.get("runId")==self.inputs["runId"]
                and proof.get("fullStackQualified") is False and len(proof.get("resources",[]))==28
                and len(proof.get("roles",[]))==22 and proof.get("phase")==("OB3_PARTIAL_STARTS_OWNED" if phase=="PARTIAL" else "OB3_PARTIAL_QUIESCENT"),
                "D12_OB3_CONTAINMENT_DTO_CHANGED")
        self.assert_inputs();require(self.lock.held(),"D12_OB3_LOCK_LOST_DURING_READ")
        return proof

    def ob3_quiesce_authorization_verified(self,authority_ref,recovery_ref):
        from scoped_d12_native_execution import partial_start_ob3_checkpoint,OB3_ALLOWED_SCENARIOS,D12CurrentExecution
        self.assert_inputs();selected_sources(self.inputs,self.profile)
        execution_source=Path(D12CurrentExecution.__init__.__code__.co_filename).resolve()
        require(self.profile=="d05-membership-current-functional" and self.inputs.get("dispatchEnabled") is True
                and self.inputs.get("applyAuthorized") is True
                and read_ref(self.inputs["executionSource"]).resolve()==execution_source
                and execution_source==self.host._root/"scripts/scoped_d12_native_execution.py"
                and self.inputs["executionSource"]["sha256"]==self.host._source_files.get(
                    "scripts/scoped_d12_native_execution.py",{}).get("sha256"),
                "D12_OB3_CURRENT_EXECUTION_AND_ENABLED_INPUTS_REQUIRED")
        authority=json.loads(read_ref(authority_ref).read_bytes());recovery=json.loads(read_ref(recovery_ref).read_bytes())
        require(self.dispatch_permit is not None and self.dispatch_permit["scope"]=="OB3_FUNCTIONAL_ONLY"
                and self.dispatch_permit["authority"]==authority_ref==self.inputs["d12Authority"]
                and authority.get("schema")=="marty.d12-current-native-authority/v1"
                and authority.get("scope")=="OB3_FUNCTIONAL_ONLY" and authority.get("dispatchAuthorized") is True
                and authority.get("draftOnly") is False and authority.get("runId")==self.inputs["runId"]
                and authority.get("approvedRecoveryAuthoritySha256")==recovery_ref["sha256"]
                and authority.get("approvedExecutionSourceSha256")==self.inputs["executionSource"]["sha256"]
                and authority.get("approvedFunctionalRuntimeSha256")==self.inputs["functionalRuntimeModule"]["sha256"]
                and authority.get("approvedRuntimeReaderSha256")==self.inputs["d12RuntimeModule"]["sha256"]
                and authority.get("approvedProfileSourceSha256")==sha(self.host._root/"scripts/scoped_native_profiles.py")
                and authority.get("approvedSelectionSha256")==self.inputs["selection"]["sha256"]
                and authority.get("allowedScenarios")==list(OB3_ALLOWED_SCENARIOS)
                and authority.get("deferredRoles")==["passport-beta-bureau"]
                and recovery.get("engineId")==self.host.engine_id,"D12_EXPLICIT_OB3_CONTAINMENT_AUTHORITY_REQUIRED")
        require(self.lock is not None and self.lock.held(),"D12_OB3_CANONICAL_LOCK_REQUIRED")
        partial_start_ob3_checkpoint(self.inputs,self.store.read("build-state.json"),self.store.read("build-apply-intent.json"),
            recovery,operation_backend=self.store.specification)
        self.observer.bind_ob3_partial_created(recovery_ref)
        # Only source ownership is established here. Expired SDK5 credentials
        # are not used or described as a valid lease by this containment path.
        self._ob3_quiesce_approval=recovery_ref
        self._ob3_containment_before=self._ob3_containment_read(recovery_ref,"PARTIAL",{})
        return True

    def ob3_quiesce_steps(self,recovery_ref):
        from scoped_passport_maintenance import _stop_contract
        require(getattr(self,"_ob3_quiesce_approval",None)==recovery_ref,"D12_OB3_CONTAINMENT_NOT_AUTHORIZED")
        recovery=json.loads(read_ref(recovery_ref).read_bytes());state=self.store.read("build-state.json")
        require(state==json.loads(read_ref(recovery["originalOperationState"]).read_bytes()),"D12_OB3_STOP_PREIMAGE_CHANGED")
        roles=set(state["startAcks"])|{"passport-beta-bureau"};require(set(recovery["stopContracts"])==set(state["startAcks"]),
            "D12_OB3_EXACT_SOURCE_STOP_CONTRACT_SET_REQUIRED")
        plan=json.loads(read_ref(self.inputs["maintenancePlan"]).read_bytes())
        before=json.loads(read_ref(self.inputs["runtimeBefore"]).read_bytes());models={k:json.loads(read_ref(v).read_bytes()) for k,v in plan["composeModels"].items()}
        from scoped_passport_maintenance import preview
        order=[step["role"] for step in preview(plan,before,models)["stopSteps"] if step["role"] in roles]
        result=[]
        for role in order:
            row=self.observer.inspect_role(role)
            if role=="passport-beta-bureau":
                policy=json.loads(read_ref(recovery["deferredStopContract"]).read_bytes())
                require(policy.get("containerId")==row["containerId"] and policy.get("imageId")==row["imageId"]
                        and policy.get("gracefulShutdownVerified") is False,"D12_OB3_FAILED_ROLE_STOP_IDENTITY_CHANGED")
            else:policy=_stop_contract(role,self.observer.current[role],recovery["stopContracts"][role])
            result.append({"role":role,"containerId":row["containerId"],"imageId":row["imageId"],
                "argv":["docker","stop","--signal",policy["signal"],"--time","-1",row["containerId"]]})
        self._ob3_stop_steps={step["role"]:step for step in result}
        return result

    def ob3_stop_owned_role(self,recovery_ref,step):
        self.assert_inputs();require(self.lock is not None and self.lock.held()
            and getattr(self,"_ob3_quiesce_approval",None)==recovery_ref
            and getattr(self,"_ob3_stop_steps",{}).get(step["role"])==step,"D12_OB3_EXACT_STOP_STEP_REQUIRED")
        state=self.store.read("build-state.json")
        require(state.get("phase")=="OB3_STOP_PENDING" and state.get("pendingStep")=="OB3_STOP_"+step["role"]
                and state.get("pendingArgv")==step["argv"] and state.get("recoveryAuthority")==recovery_ref,
                "D12_OB3_DURABLE_STOP_INTENT_REQUIRED")
        row=self.observer.inspect_role(step["role"])
        require(row["containerId"]==step["containerId"] and row["imageId"]==step["imageId"],"D12_OB3_STOP_CID_CHANGED")
        result=bounded_run([str(self.docker),"--context","desktop-linux",*step["argv"][1:]],env=self.environment,
            timeout=180,stdout_limit=65536,stderr_limit=65536)
        name="ob3-stop-"+step["role"]
        self.save_bytes(name+".stdout",result.stdout);self.save_bytes(name+".stderr",result.stderr)
        self.save(name+".terminal.json",{"exitCode":result.returncode,"observation":result.observation})
        require(result.returncode==0 and result.observation["timedOut"] is False and not result.observation["failures"],
                "D12_OB3_STOP_UNKNOWN_NO_RETRY")
        return self.observer.inspect_role(step["role"])

    def observe_ob3_quiescence(self,recovery_ref,outcomes):
        require(getattr(self,"_ob3_quiesce_approval",None)==recovery_ref,"D12_OB3_CONTAINMENT_NOT_AUTHORIZED")
        proof=self._ob3_containment_read(recovery_ref,"QUIESCENT",outcomes)
        require(all(not row["running"] and row["hostPid"]==0 for row in proof["roles"]),"D12_OB3_NOT_QUIESCENT")
        return self.save("ob3-owned22-quiescence.private.json",proof)

    def recovery_authorization_verified(self, authority_ref, recovery_ref):
        authority = json.loads(read_ref(authority_ref, 65536).read_bytes())
        recovery = json.loads(read_ref(recovery_ref, 2 * 1024 * 1024).read_bytes())
        require(authority.get("approvedRecoveryAuthoritySha256") == recovery_ref["sha256"]
                and (recovery.get("schema"), recovery.get("operation")) in (("marty.d12-fence-install-recovery/v1", "RESUME_AFTER_TERMINAL_FENCE_INSTALL"),
                    ("marty.d12-created-recovery/v1", "RESUME_AFTER_ACKNOWLEDGED_CREATE_SELECTED"),
                    ("marty.d12-created-recovery/v1", "REPLACE_CREATED_CREDENTIAL_GENERATION_AND_RESUME"),
                    ("marty.d12-created-recovery/v1", "RESUME_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT"),
                    ("marty.d12-created-recovery/v1", "REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME"))
                and recovery.get("dispatchAuthorized") is True and recovery.get("draftOnly") is False
                and recovery.get("runId") == self.inputs["runId"],
                "D12_EXPLICIT_RECOVERY_AUTHORITY_REQUIRED")
        return self._authorization_verified(authority_ref, recovery_ref)

    def _authorization_verified(self, authority_ref, recovery_ref=None):
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
        resource_recovery_ref = None
        created_recovery = False
        frozen_ref = self.inputs["runtimeBefore"]
        if recovery_ref is not None:
            recovery = json.loads(read_ref(recovery_ref).read_bytes())
            created_recovery = recovery.get("schema")=="marty.d12-created-recovery/v1"
            if created_recovery:
                from scoped_d12_native_execution import created_recovery_checkpoint
                created_recovery_checkpoint(self.inputs,self.store.read("build-state.json"),
                    self.store.read("build-apply-intent.json"),recovery,operation_backend=self.store.specification)
                if self.observer.created_ref is None:
                    state=self.store.read("build-state.json")
                    if recovery.get("operation") in ("RESUME_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT",
                        "REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME"):
                        created=self.observer.bind_created_after_ack("REPLACE_CREATED_CREDENTIAL_GENERATION",state,
                            reconciled_replacement=recovery_ref)
                        self._verify_created_target("REPLACE_CREATED_CREDENTIAL_GENERATION",state,created,
                            recovery_ref=recovery_ref,prefix=observation_prefix+"d12-reconciled-replacement-target",
                            use_installed_model=recovery.get("operation")=="REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME")
                    else:
                        self.observer.bind_created_after_ack("CREATE_SELECTED",state)
            frozen_ref = recovery["quiescence"]
            resource_recovery_ref = recovery["maintenanceResourceRecovery"]
            read_ref(resource_recovery_ref, 2 * 1024 * 1024)
        frozen = self.observer.inspect_all22() if created_recovery else json.loads(read_ref(frozen_ref).read_bytes())
        if created_recovery:
            resource_recovery=json.loads(read_ref(resource_recovery_ref).read_bytes())
            require(resource_recovery.get("postCreate")=={
                "selection":self.inputs["selection"],"selected22":recovery["selected22"],
                "selected22Job":recovery["selected22Job"],"plannedModels":json.loads(read_ref(recovery["originalInputs"]).read_bytes())["plannedModels"]},
                "D12_CREATED_RESOURCE_BINDING_CHANGED")
        self.save(observation_prefix + "d12-resource28-request.private.json", {"runId": self.inputs["runId"],
            "source": source_ref, "resourceProfile": profile_ref,
            "runtimeBefore": self.inputs["runtimeBefore"],
            "scope": "FUNCTIONAL_ONLY" if recovery_ref is None else "MAINTENANCE_RECOVERY_ONLY"})
        script = RESOURCE_VERIFY_JS if recovery_ref is None else MAINTENANCE_RESOURCE_VERIFY_JS
        arguments = [str(self.node), "-e", script, source_ref["path"], source_ref["sha256"],
                     profile_ref["path"], profile_ref["sha256"], str(self.docker)]
        if resource_recovery_ref is not None:
            arguments.append(json.dumps(resource_recovery_ref))
        result = bounded_run(arguments, env=self.environment,
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
        self._bind_resource_rows(actual, frozen, scope=("FUNCTIONAL_ONLY" if recovery_ref is None else "MAINTENANCE_RECOVERY_ONLY"))
        self.assert_inputs()
        require(self.lock.held(), "D12_CANONICAL_LOCK_LOST_DURING_RESOURCE_READ")
        read_ref(profile_ref, 2 * 1024 * 1024)
        self.save(observation_prefix + "d12-resource28-bound.private.json", {"runId": self.inputs["runId"],
            "source": source_ref, "resourceProfile": profile_ref,
            "runtimeBefore": self.inputs["runtimeBefore"],
            "full28AncillaryVerifiedByReviewedRuntime": True,
            "actualRoleCount": len(actual["roles"]), "releaseQualified": False,
            "authorizationAttempt": attempt,
            **({"scope": "MAINTENANCE_RECOVERY_ONLY", "recoveryAuthority": recovery_ref,
                "maintenanceResourceRecovery": resource_recovery_ref, "functionalQualification": False}
               if recovery_ref is not None else {}),
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
        require_bound_quiescence(state, self.inputs, bound)
        return self._verify_quiescent_snapshot(frozen, rows)

    def verify_recovery_quiescent(self, recovery_ref):
        self.assert_inputs()
        recovery = json.loads(read_ref(recovery_ref).read_bytes())
        if recovery.get("schema")=="marty.d12-created-recovery/v1":
            from scoped_d12_native_execution import created_recovery_checkpoint
            created_recovery_checkpoint(self.inputs,self.store.read("build-state.json"),
                self.store.read("build-apply-intent.json"),recovery,operation_backend=self.store.specification)
            require(self.observer.created_ref is not None,"D12_CREATED_OBSERVER_NOT_BOUND")
            fresh=exact_roles(self.observer.inspect_all22(),self.profile)
            selected=dict(self.observer.build_profile.roles)
            require(all(row.get("state")==("created" if role in selected else "exited")
                    and row.get("running") is False and row.get("hostPid")==0
                    and row.get("paused") is False and row.get("oomKilled") is False
                    and row.get("containerExitCode")==0 for role,row in fresh.items()),
                    "D12_CREATED_RECOVERY_STATE_CHANGED")
            return True
        bound = recovery["quiescence"]
        inputs = {**self.inputs, "quiescence": bound}
        fence_install_recovery_checkpoint(inputs, self.store.read("build-state.json"),
            self.store.read("build-apply-intent.json"), recovery)
        frozen = json.loads(read_ref(bound).read_bytes())
        return self._verify_quiescent_snapshot(frozen, exact_roles(frozen, self.profile))

    def _verify_quiescent_snapshot(self, frozen, rows):
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

    def effect_acknowledged(self,step,state):
        created=self.observer.bind_created_after_ack(step,state)
        return self._verify_created_target(step,state,created)

    def _verify_created_target(self,step,state,created,*,recovery_ref=None,prefix=None,use_installed_model=False):
        if created is None or self.profile!="d05-membership-current-functional":
            return created
        # The current owned Job has not closed yet: this binds the actual
        # acknowledged create and source model, never a normal-Job claim.
        self.assert_inputs()
        durable=self.store.read("build-state.json")
        require(durable==state and durable.get("phase")=="EFFECT_ACKNOWLEDGED"
                and durable.get("acknowledgedStep")==step,"D12_CREATED_TARGET_ACK_CHANGED")
        recovery_ref=recovery_ref or state.get("replacementAuthority") or state.get("recoveryAuthority")
        if recovery_ref is None:
            return created  # Existing non-recovery entry retains its behavior.
        recovery=json.loads(read_ref(recovery_ref).read_bytes())
        require(type(use_installed_model) is bool,"D12_CREATED_TARGET_MODEL_MODE_REQUIRED")
        target_inputs=self.inputs
        if use_installed_model:
            require(recovery.get("operation")=="REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME"
                    and recovery.get("dispatchAuthorized") is True and recovery.get("draftOnly") is False
                    and state==json.loads(read_ref(recovery["originalOperationState"]).read_bytes()),
                    "D12_CREATED_INSTALLED_MODEL_AUTHORITY_REQUIRED")
            target_inputs=json.loads(read_ref(recovery["originalInputs"]).read_bytes())
            require(target_inputs["runId"]==self.inputs["runId"] and target_inputs["selection"]==self.inputs["selection"],
                    "D12_CREATED_INSTALLED_MODEL_BINDING_CHANGED")
        resource=json.loads(read_ref(recovery["maintenanceResourceRecovery"]).read_bytes())
        prefix=prefix or ("d12-created-replacement-target" if step=="REPLACE_CREATED_CREDENTIAL_GENERATION" else "d12-created-target")
        acknowledgement=self.save(prefix+"-ack.private.json",durable)
        request=self.save(prefix+"-request.private.json",{"runId":self.inputs["runId"],"engineId":self.host.engine_id,
            "selection":self.inputs["selection"],"plannedModels":target_inputs["plannedModels"],
            "composeArguments":target_inputs["composeArguments"],
            "runtimeBefore":self.inputs["runtimeBefore"],"resourceBefore":resource["resourceBefore"],
            "createdCids":created,"acknowledgedState":acknowledgement})
        source=self.inputs["functionalRuntimeModule"]
        result=bounded_run([str(self.node),"-e",CREATED_TARGET_VERIFY_JS,source["path"],source["sha256"],
            request["path"],request["sha256"],str(self.docker)],env=self.environment,
            timeout=180,stdout_limit=1024*1024,stderr_limit=65536)
        self.save_bytes(prefix+"-stdout.private",result.stdout)
        self.save_bytes(prefix+"-stderr.private",result.stderr)
        self.save(prefix+"-terminal.private.json",{"exitCode":result.returncode,"observation":result.observation})
        require(result.returncode==0 and result.observation["timedOut"] is False and not result.observation["failures"],
                "D12_ACTUAL_CREATED_TARGET_MODEL_FAILED")
        observed=json.loads(result.stdout)
        require(observed.get("state")=="ACTUAL_CREATED_TARGET_MODEL_BOUND_BY_CURRENT_OWNER"
                and observed.get("runId")==self.inputs["runId"] and observed.get("acknowledgedStep")==step
                and observed.get("currentJobNormalClosureNotYetQualified") is True,
                "D12_ACTUAL_CREATED_TARGET_MODEL_REQUIRED")
        self.assert_inputs()
        return created

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
                "effect_acknowledged": self.effect_acknowledged,
                "prepare_created_credential_replacement": self.observer.prepare_credential_replacement,
                "compose_model": self.host.compose_model,
                "database_snapshot": self.database_snapshot,
                "verify_all22_quiescent": self.verify_all22_quiescent,
                "verify_recovery_quiescent": self.verify_recovery_quiescent,
                "recovery_authorization_verified": self.recovery_authorization_verified,
                "wait_all22_healthy": self.wait_all22_healthy,
                "ob3_quiesce_authorization_verified": self.ob3_quiesce_authorization_verified,
                "ob3_quiesce_steps": self.ob3_quiesce_steps,
                "ob3_stop_owned_role": self.ob3_stop_owned_role,
                "observe_ob3_quiescence": self.observe_ob3_quiescence,
                "save": self.save, "save_bytes": self.save_bytes, "ref": ref,
                "assert_inputs": self.assert_inputs, "root": self.root,
                "env": self.environment, "nodeExecutable": str(self.node),
                "build_journal": self.build_journal}

    def database_snapshot(self):
        self.assert_inputs()
        require(isinstance(self.inputs.get("databaseBefore"), dict),
                "D12_DATABASE_PREIMAGE_REQUIRED")
        return self.observer.database_snapshot(self.inputs["databaseBefore"])
