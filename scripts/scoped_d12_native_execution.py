"""Closed current-source D12 native cutover using existing journal, SQL and Rust CLIs.

The caller is the reviewed beta host and supplies its existing operation lock,
actual22 reader and frozen Compose model. Import and construction make no effects.
An uncertain command leaves a durable pending state for explicit reconciliation.
"""
from __future__ import annotations

import json
from pathlib import Path

from scoped_native_runtime import D12_CURRENT_RUNTIME_ROLES, daemon_source, durable_barrier, read_ref, require, selected_sources, sha, started_later
from scoped_native_profiles import D12_PASSPORT_CURRENT
from scoped_passport_successor import CURRENT_PROFILE, select_current_binaries
from scoped_native_database import D12CurrentDatabasePhase
import scoped_beta_binary_overlay as overlay
import scoped_passport_maintenance as maintenance

MIGRATION_SHA256 = {
    "rust/services/flow/migrations/0003_physical_start_intents.sql":
        "fd86a211a4b799b53827456ac1d5b8887ae3264c26ae889fb7714a1fa62e4edd",
    "rust/services/issuance/migrations/0010_passport_start_idempotency.sql":
        "05b3aafe03b9aa258c8061db2d9ac1adb35f17f0d513b9995d48ee2ef2305801",
    "rust/services/issuance/migrations/0011_passport_administrative_cancellation.sql":
        "9842f5ea39aab254d41cf7bc936411b813b853352a1e2de668594926dd08f682",
}
D05_MIGRATION_SHA256 = {**MIGRATION_SHA256,
    'rust/services/credential-template/migrations/0003_membership_achievement_criteria.sql': '8d4a006db83610c3253bf00504f779939e43069b9e45dde2074694891d9a0987',
    'rust/services/issuance/migrations/0012_membership_achievement_criteria.sql': '2becfb8d83bfe775f75a95d6b1aa17b317cdcec825f1350e181e93347d67bb7e',
}



def exact_exported_sql(prepared, inputs, profile=CURRENT_PROFILE):
    from scoped_native_profiles import current_rollout_build
    build = current_rollout_build(profile)
    """Use LF Git-exported source bytes, never a Windows checkout conversion."""
    from scoped_native_maintenance import operational_sql_sources
    from scoped_native_runtime import migration_names
    source = prepared["sources"]["ui"]
    require(source["revision"] == build.ui_revision,
            "D12_EXACT_SQL_SOURCE_REVISION_REQUIRED")
    root = Path(source["directory"]).resolve()
    expected = operational_sql_sources()
    require(set(inputs["sqlSources"]) == set(expected), "D12_EXACT_OPERATIONAL_SQL_SET_REQUIRED")
    for name, digest in expected.items():
        bound = inputs["sqlSources"][name]
        require(bound["sha256"] == digest
                and read_ref(bound).resolve() == root / "scripts" / "sql" / name,
                "D12_EXACT_GIT_EXPORTED_SQL_REQUIRED:" + name)
    from scoped_native_maintenance import migration_requirements
    required = migration_requirements()["catalogSqlSha256"]
    require(inputs["catalogSql"]["sha256"] == required
            and read_ref(inputs["catalogSql"]).resolve()
                == root / "scripts" / "sql" / "passport-beta-maintenance-catalog.sql",
            "D12_EXACT_GIT_EXPORTED_CATALOG_REQUIRED")
    required_migrations = D05_MIGRATION_SHA256 if profile == "d05-membership-current-functional" else MIGRATION_SHA256
    migration_paths = {"rust/services/" + item.replace("/", "/migrations/", 1) + ".sql"
                       for item in migration_names(profile)}
    require(set(inputs["migrationSources"]) == migration_paths == set(required_migrations),
            "D12_EXACT_RUST_MIGRATION_SET_REQUIRED")
    for name, bound in inputs["migrationSources"].items():
        require(bound["sha256"] == required_migrations[name]
                and read_ref(bound).resolve() == root / name,
                "D12_EXACT_GIT_EXPORTED_MIGRATION_REQUIRED")


class D12CurrentExecution:
    def __init__(self, context, inputs, journal, *, read_only_preflight=False):
        self.g, self.i, self.store = context, inputs, journal
        require(type(read_only_preflight) is bool, "D12_PREFLIGHT_MODE_REQUIRED")
        self.read_only_preflight = read_only_preflight
        require(not read_only_preflight or getattr(journal, "read_only", False) is True,
                "D12_READ_ONLY_OPERATION_JOURNAL_REQUIRED")
        from scoped_native_profiles import current_rollout_build
        self.profile = inputs.get("rolloutProfile", CURRENT_PROFILE)
        self.build_profile = current_rollout_build(self.profile)
        self.roles = dict(self.build_profile.roles)
        self.native_preimage = None
        self.state = {"schema": "marty.d12-current-native-operation/v1", "phase": "NOT_STARTED",
                      "runId": inputs["runId"], "scope": "FUNCTIONAL_ONLY",
                      "sourceRevision": self.build_profile.ui_revision,
                      "coreRevision": self.build_profile.core_revision,
                      "releaseQualified": False, "recordingQualified": False, "steps": []}

    def record(self, phase, **fields):
        require(not self.read_only_preflight, "D12_READ_ONLY_PREFLIGHT_NO_INTENT")
        self.state.update(phase=phase, **fields)
        require(durable_barrier(self.store.state(self.state)), "D12_DURABLE_STATE_REQUIRED")

    def command(self, database, step, args):
        # The shared database transport inserts its pinned Desktop context.
        # Stop contracts already spell that context explicitly.
        if args[:3] == ["docker", "--context", "desktop-linux"]:
            args = ["docker", *args[3:]]
        require(args and args[0] == "docker", "D12_EXACT_DOCKER_TRANSPORT_REQUIRED")
        self.record("PENDING_EFFECT", pendingStep=step,
                    pendingArgv=["docker", "--context", "desktop-linux", *args[1:]])
        result = database.command(args)
        self.record("EFFECT_ACKNOWLEDGED", pendingStep=None, pendingArgv=None, acknowledgedStep=step)
        if "effect_acknowledged" in self.g:
            self.g["effect_acknowledged"](step, self.state)
        return result

    def inspect_all22(self):
        # The functional Docker observer requires running PID 1. During a
        # maintenance stop/create window use a fresh exact-22 batch when the
        # reviewed host provides one. The historical individual reader stays
        # available for existing callers and tests.
        if "inspect_all22" in self.g:
            snapshot = self.g["inspect_all22"]()
        else:
            snapshot = {"roles": [self.g["inspect_role"](role) for role in sorted(D12_CURRENT_RUNTIME_ROLES)]}
        maintenance.exact_roles(snapshot, self.profile)
        return snapshot

    def preflight(self):
        i, g = self.i, self.g
        require(g["dispatch_enabled"] is True and g["operation_lock_held"]() is True
                and g["recording_lock_held"]() is True,
                "D12_EXCLUSIVE_AUTHORITY_REQUIRED")
        selected_sources(i, self.profile)
        require(i["roleBinaries"] == self.roles and i["scope"] == "FUNCTIONAL_ONLY"
                and i["releaseQualified"] is False and i["recordingQualified"] is False,
                "D12_CURRENT_FUNCTIONAL_SCOPE_REQUIRED")
        require("quiescence" not in i, "D12_PREEXISTING_QUIESCENCE_FORBIDDEN")
        authority = json.loads(read_ref(i["d12Authority"], 65536).read_bytes())
        require(g["authorization_verified"](i["d12Authority"]) is True
                and authority.get("dispatchAuthorized") is True
                and authority.get("runId") == i["runId"]
                and read_ref(i["executionSource"]).resolve() == Path(__file__).resolve()
                and authority.get("approvedExecutionSourceSha256") == i["executionSource"]["sha256"]
                and sha(Path(__file__)) == i["executionSource"]["sha256"]
                and authority.get("approvedMetadataModuleSha256") == i["metadataModule"]["sha256"]
                and read_ref(i["metadataModule"]).name == "native-maintenance-metadata.js"
                and authority.get("approvedFunctionalRuntimeSha256") == i["functionalRuntimeModule"]["sha256"]
                and read_ref(i["functionalRuntimeModule"]).name == "functional-debug-runtime.js"
                and read_ref(i["functionalRuntimeModule"]).parent
                    == read_ref(i["metadataModule"]).parent
                and authority.get("approvedRuntimeReaderSha256") == i["d12RuntimeModule"]["sha256"]
                and read_ref(i["d12RuntimeModule"]).name == "d12-current-native-runtime.js"
                and authority.get("approvedProfileSourceSha256")
                    == sha(Path(__file__).with_name("scoped_native_profiles.py")),
                "D12_REVIEWED_AUTHORIZATION_REQUIRED")
        selection = (select_current_binaries(i["preparedSource"], i["canonicalBuildReceipt"], g["build_journal"])
                     if self.profile == CURRENT_PROFILE else select_current_binaries(i["preparedSource"], i["canonicalBuildReceipt"], g["build_journal"], self.profile))
        exact_exported_sql(json.loads(read_ref(i["preparedSource"]).read_bytes()), i, self.profile)
        require(selection == json.loads(read_ref(i["selection"]).read_bytes())
                and authority.get("approvedSelectionSha256") == i["selection"]["sha256"],
                "D12_EXACT_SELECTED_BUILD_REQUIRED")
        if self.profile == "d05-membership-current-functional":
            abi_plan=json.loads(read_ref(i["compatibility"]["plan"]).read_bytes())
            require(abi_plan["beforeBinding"]["sha256"]==i["runtimeBefore"]["sha256"],"CURRENT10_IMAGE_PREIMAGE_BINDING_CHANGED")
            self.native_preimage={"binding":i["runtimeBefore"],"inspections":abi_plan["nativeInspections"]}
        before = g["observe22"]()
        require(maintenance.same_full_role_snapshot(
                    before, json.loads(read_ref(i["runtimeBefore"]).read_bytes()), self.profile)
                and authority.get("approvedRuntimeBeforeSha256") == i["runtimeBefore"]["sha256"],
                "D12_FRESH_ACTUAL22_PREIMAGE_REQUIRED")
        require(g["database_snapshot"]() == json.loads(read_ref(i["databaseBefore"]).read_bytes())
                and authority.get("approvedDatabaseBeforeSha256") == i["databaseBefore"]["sha256"],
                "D12_FRESH_DATABASE_PREIMAGE_REQUIRED")
        plan = json.loads(read_ref(i["maintenancePlan"]).read_bytes())
        models = {name: json.loads(read_ref(bound).read_bytes())
                  for name, bound in plan["composeModels"].items()}
        preview = maintenance.preview(plan, before, models)
        require(preview["noApplyAuthority"] is True and preview["allStopRoles"]
                and set(preview["allStopRoles"]) == D12_CURRENT_RUNTIME_ROLES,
                "D12_ALL22_MAINTENANCE_REQUIRED")
        base = models["elevenid-beta"]
        if self.profile == "d05-membership-current-functional":
            from scoped_native_database import current_tenant
            tenant = current_tenant(i, authority)
            mixed_ref=i["composeProductBinding"]
            mixed=json.loads(read_ref(mixed_ref,65536).read_bytes())
            require(authority.get("approvedComposeProductBindingSha256")==mixed_ref["sha256"]
                    and set(mixed)=={"binaryUiRevision","binaryCoreRevision","composeRevision","composeSource","modelSources"}
                    and mixed["binaryUiRevision"]==self.build_profile.ui_revision
                    and mixed["binaryCoreRevision"]==self.build_profile.core_revision
                    and mixed["composeRevision"]=="82862f78876f2885a32353ba99a34ccba284faac"
                    and mixed["composeSource"]["sha256"]=="8a5d929fc657dc0f80582ad140d10fbcc05eb90cc6a39e68fe85a4d4962231ab"
                    and read_ref(mixed["composeSource"]).name=="docker-compose.beta.yml"
                    and mixed["modelSources"]==i["composeSources"],
                    "CURRENT_TEN_EXPLICIT_MIXED_COMPOSE_BINDING_REQUIRED")
            for role,key in (("flow","MARTY_ORG_ID"),("issuance-native","MARTY_ORG_ID"),("organization","MARTY_ORG_ID"),("auth","CREDENTIAL_LOGIN_ORGANIZATION_ID")):
                require(base["services"][role].get("environment",{}).get(key)==tenant,"CURRENT_TEN_COMPOSE_TENANT_CHANGED:"+role)
        require(g["compose_model"](i["composeArguments"], None) == base,
                "D12_FRESH_COMPOSE_MODEL_REQUIRED")
        replacement = overlay.binary_overlay(selection["binaries"], self.profile, before=base,native_preimage=self.native_preimage)
        overlay_ref = g["save"]("d12-current-overlay.private.json", replacement)
        after_model = g["compose_model"](i["composeArguments"], overlay_ref)
        overlay.validate_delta(base, after_model, selection["binaries"], self.profile,native_preimage=self.native_preimage)
        overlay.compose_recreate_arguments(i["composeArguments"], overlay_ref["path"],
                                           self.profile, list(self.roles), no_start=True)
        database = (D12CurrentDatabasePhase(g, i, self.store, read_only_preflight=True)
                    if self.read_only_preflight else D12CurrentDatabasePhase(g, i, self.store))
        database._check_current_compatibility(selection, i["compatibility"]["plan"],
                                               i["compatibility"]["result"])
        if self.profile == "d05-membership-current-functional":
            from scoped_native_database import current_ten_tenant_observation
            tenant_observation = g["save"]("current-ten-tenant-preflight.json",current_ten_tenant_observation(database))
            self.state["tenantPreflight"] = tenant_observation
        return database, before, preview, overlay_ref

    def run(self):
        require(not self.read_only_preflight, "D12_READ_ONLY_PREFLIGHT_NO_APPLY")
        database, before, preview, overlay_ref = self.preflight()
        i, g = self.i, self.g
        intent = {"schema": "marty.d12-current-apply-intent/v1", "runId": i["runId"],
                  "selectionSha256": i["selection"]["sha256"], "executorSource": i["executorSource"],
                  "runtimeBefore": i["runtimeBefore"], "databaseBefore": i["databaseBefore"],
                  "authority": i["d12Authority"], "automaticRetry": False}
        require(durable_barrier(self.store.exclusive("build-apply-intent.json", intent)),
                "D12_DURABLE_ONE_SHOT_INTENT_REQUIRED")
        self.record("APPLY_INTENT_DURABLE")
        outcomes = {}
        for step in preview["stopSteps"]:
            role = step["role"]
            self.command(database, "STOP_" + role, step["argv"])
            row = g["inspect_role"](role)
            require(row["containerId"] == step["containerId"] and row["state"] == "exited"
                    and row["hostPid"] == 0 and row["containerExitCode"] == 0
                    and row["oomKilled"] is False, "D12_STOP_NOT_TERMINAL:" + role)
            outcomes[role] = {"terminal": True, "exitCode": 0, "stopAcknowledged": True}
            self.state["steps"].append("STOP_" + role)
            self.record("STOP_TERMINAL")
        stopped = self.inspect_all22()
        maintenance.validate_quiescent(before, stopped, outcomes, self.profile)
        quiescence = g["save"]("d12-all22-quiescent.private.json", stopped)
        # This actual receipt cannot exist before the 22 stop outcomes. Keep
        # the frozen caller input immutable and pass a derived phase input to
        # the existing database executor only after durable observation.
        require(read_ref(quiescence).is_file(), "D12_FRESH_QUIESCENCE_REQUIRED")
        require(durable_barrier(self.store.state({"phase": "ALL22_QUIESCENT", "runId": i["runId"],
                "quiescenceSha256": quiescence["sha256"]})), "D12_DURABLE_QUIESCENCE_REQUIRED")
        database.i = {**i, "quiescence": quiescence}
        database_proof = database.run()
        verified_database = database.node("verify", proof=database_proof,
            commands=database.commands, context={"runId": i["runId"],
                "selectionSha256": i["selection"]["sha256"],
                "executorSource": i["executorSource"], "rolloutProfile": self.profile,
                "sourceRevision": self.build_profile.ui_revision,
                "coreRevision": self.build_profile.core_revision,
                "baseline": database.baseline_refs,
                "approvedDatabaseBeforeSha256": i["databaseBefore"]["sha256"],
                "approvedEngineId": database.engine_id,
                **({"tenantId":database.tenant_id} if self.profile == "d05-membership-current-functional" else {})})
        require(verified_database["sourceCommit"] == self.build_profile.ui_revision
                and verified_database["databaseIdentity"] == database.identity,
                "D12_ACTUAL_DATABASE_PROOF_REQUIRED")
        self.record("DATABASE_MAINTENANCE_TERMINAL", databaseProof=g["save"]("d12-database-proof.private.json", database_proof),
                    verifiedDatabase=g["save"]("d12-database-verified.private.json", verified_database))
        recreate = overlay.compose_recreate_arguments(i["composeArguments"], overlay_ref["path"],
                    self.profile, list(self.roles), no_start=True)
        self.command(database, "CREATE_SELECTED", recreate)
        self.record("CREATE_INSPECTION_PENDING", pendingStep="INSPECT_CREATED")
        created = self.inspect_all22()
        old_rows = maintenance.exact_roles(before, self.profile)
        new_rows = maintenance.exact_roles(created, self.profile)
        for role in self.roles:
            old, new = old_rows[role], new_rows[role]
            require(new["containerId"] != old["containerId"] and new["state"] == "created"
                    and new["hostPid"] == 0 and new["imageId"] == old["imageId"]
                    and new["oomKilled"] is False, "D12_SELECTED_CREATE_NOT_PROVEN:" + role)
            target = "/usr/local/bin/" + self.roles[role]
            prior_mounts = {row["destination"]: row for row in old["binaryMounts"]}
            mounts = {row["destination"]: row for row in new["binaryMounts"]}
            image_owned=self.profile=="d05-membership-current-functional" and target not in prior_mounts
            if image_owned:
                overlay.image_owned_baseline(role,self.roles[role],self.native_preimage,old)
            require(len(prior_mounts) == len(old["binaryMounts"])
                    and len(mounts) == len(new["binaryMounts"])
                    and set(mounts) == (set(prior_mounts)|{target} if image_owned else set(prior_mounts)) and target in mounts
                    and all(mounts[key] == prior_mounts[key] for key in mounts if key != target)
                    and mounts[target]["type"] == "bind" and mounts[target]["writable"] is False
                    and daemon_source(mounts[target]["source"])
                    == daemon_source(database.selection["binaries"][role]["path"]),
                    "D12_CREATED_EXECUTABLE_BIND_CHANGED:" + role)
        for role in D12_CURRENT_RUNTIME_ROLES - set(self.roles):
            require(new_rows[role] == maintenance.exact_roles(stopped, self.profile)[role],
                    "D12_UNSELECTED_CREATE_CHANGED:" + role)
        created_ref = g["save"]("d12-created.private.json", {"runId": i["runId"], "roles": created["roles"]})
        self.record("SELECTED_CREATED", pendingStep=None, created=created_ref)
        start_acks = {}
        for role in preview["restoreOrder"]:
            cid = new_rows[role]["containerId"]
            self.command(database, "START_" + role, ["docker", "start", cid])
            self.record("START_INSPECTION_PENDING", pendingStep="INSPECT_START_" + role,
                        pendingContainerId=cid)
            observed = json.loads(database.command(["docker", "inspect", cid]))[0]
            state = observed["State"]
            labels = observed["Config"]["Labels"]
            require(observed["Id"] == cid and observed["Image"] == old_rows[role]["imageId"]
                    and labels.get("com.docker.compose.project") == old_rows[role]["project"]
                    and labels.get("com.docker.compose.service") == role
                    and state["Status"] == "running" and state["Running"] is True
                    and state["OOMKilled"] is False
                    and type(state["Pid"]) is int and state["Pid"] > 0
                    and started_later(state["StartedAt"], old_rows[role]["startedAt"]),
                    "D12_START_GENERATION_NOT_OWNED:" + role)
            start_acks[role] = {"containerId": cid, "startedAt": state["StartedAt"],
                                "hostPid": state["Pid"], "imageId": observed["Image"]}
            self.state["steps"].append("START_" + role)
            self.record("START_OBSERVED", pendingStep=None, pendingContainerId=None,
                        startAcks=dict(start_acks))
        require(set(start_acks) == D12_CURRENT_RUNTIME_ROLES, "D12_ALL22_START_ACKS_REQUIRED")
        acks_ref = g["save"]("d12-start-acks.private.json", {"runId": i["runId"], "acks": start_acks})
        self.record("ALL22_STARTS_OBSERVED", startAcksRef=acks_ref)
        require(g["wait_all22_healthy"](120) is True, "D12_ALL22_HEALTH_DEADLINE_REQUIRED")
        after = database.node("runtime", module=i["d12RuntimeModule"],
            inputs={"before": i["runtimeBefore"], "selection": i["selection"],
                    "created": created_ref, "startAcks": acks_ref,
                    "runId": i["runId"], "engineId": database.engine_id})
        proof = overlay.validate_runtime_after(before, after, database.selection["binaries"],
                   D12_CURRENT_RUNTIME_ROLES - set(self.roles), self.profile,native_preimage=self.native_preimage)
        require(g["database_snapshot"]()["databaseIdentity"] == database.identity,
                "D12_DATABASE_POSTFLIGHT_REQUIRED")
        startup_schema = None
        runtime_ref = None
        if self.profile == "d05-membership-current-functional":
            from scoped_native_database import current_ten_startup_schema_observation
            self.record("NATIVE_STARTUP_SCHEMA_INSPECTION_PENDING")
            runtime_ref = g["save"]("d12-runtime-after.private.json",proof)
            observed_schema=current_ten_startup_schema_observation(database)
            auth=next(row for row in proof["roles"] if row["role"]=="auth")
            fresh_auth=g["inspect_role"]("auth")
            require(all(fresh_auth[key]==auth[key] for key in ("containerId","startedAt","hostPid","imageId"))
                    and fresh_auth.get("running") is True and fresh_auth.get("health")=="healthy",
                    "CURRENT_TEN_AUTH_STARTUP_GENERATION_CHANGED")
            observed_schema.update(nativeRuntime=runtime_ref,startupOwner={"role":"auth","containerId":auth["containerId"],"startedAt":auth["startedAt"],"sourceRevision":auth["source"],"elfSha256":auth["sha256"]})
            startup_schema = g["save"]("current-ten-startup-schema-observation.json",observed_schema)
            self.record("NATIVE_STARTUP_SCHEMA_OBSERVED",startupSchema=startup_schema)
        result = {"schema": "marty.d12-current-native-functional/v1", "runId": i["runId"],
                  "sourceRevision": self.build_profile.ui_revision,
                  "coreRevision": self.build_profile.core_revision,
                  "selection": i["selection"], "database": database_proof,
                  "runtime": runtime_ref if runtime_ref is not None else g["save"]("d12-runtime-after.private.json", proof),
                  "nativeRuntimeReady": True, "functionalReady": False,
                  "passportScenarioVerified": False, "physicalBookletVerified": False,
                  "releaseQualified": False, "recordingQualified": False}
        if startup_schema is not None:
            result["startupSchema"] = startup_schema
            result["tenantId"] = database.tenant_id
        self.record("FUNCTIONAL_NATIVE_TERMINAL", result=g["save"]("d12-native-result.private.json", result))
        return result
