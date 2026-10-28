"""One issuer-native cutover using the existing reviewed production helpers.

The frozen host launcher supplies the existing Compose, actual Docker reader,
private journal, scoped API reader and source-bound verifier. No SQL mutation,
image build, provider configuration edit or implicit recovery is implemented.
"""
from __future__ import annotations
from pathlib import Path
import json
import time
from scoped_native_runtime import durable_barrier, read_ref, require, sha
from scoped_signing_successor import environment, effective_environment, live_compose_arguments

ROLE = "issuance-native"
BINARY = "marty-issuance-service"
TARGET = "/usr/local/bin/" + BINARY
PROFILE = "canvas-issuer-scoped-jobs"
BEFORE = "75a9e465fbbf139a528739f36a71121a63860f17e9aca45c612d5f49532b7f60"
PROXY = "fa3eeb5612515340cd0100d8b7e0cd7fff7c97f30f0e9ce31f1498896712fd89"


class IssuerSuccessor:
    """Callbacks are frozen production code, never JSON-provided commands."""

    def __init__(self, context, inputs):
        self.g, self.i = context, inputs
        self.root = Path(inputs["privateRoot"])
        self.legacy = context["issuer_helpers"]
        require(self.legacy.validate_delta.__globals__ is vars(self.legacy), "REAL_HELPER_GLOBALS_REQUIRED")
        self.legacy.ROLES = (ROLE,)
        self.store = context["journal_factory"](inputs)
        self.rolling_back = False
        self.state = {"operation": "CANVAS_ISSUER_SCOPED_JOBS", "runId": inputs["runId"],
                      "phase": "PRECHECK", "new": {}, "releaseQualified": False, "recordingQualified": False}
        self.state["controllerIdentity"] = context["controller_identity"]()

    def record(self, phase, **fields):
        self.state.update(phase=phase, **fields)
        require(durable_barrier(self.store.state(self.state)), "DURABLE_STATE_BARRIER_REQUIRED")

    def command(self, arguments):
        self.g["assert_inputs"](rollback=self.rolling_back)
        return self.g["command"](arguments)

    def inspect(self, cid):
        return json.loads(self.command(["docker", "inspect", cid]))[0]

    def candidate(self):
        output = self.i["candidate"]
        path = read_ref(output, 512 * 1024 * 1024)
        require(path.stat().st_size == output["bytes"], "CANDIDATE_SIZE_CHANGED")
        return path

    def old_binary(self):
        output = self.i["oldBinary"]
        require(output["sha256"] == "81749432b2d86dd2e8ea83176a824bf8075254860858b6552e76b0e5cdd3ee0c",
                "ORIGINAL_ELF_LINEAGE_CHANGED")
        path = read_ref(output, 512 * 1024 * 1024)
        require(path.stat().st_size == output["bytes"], "ORIGINAL_ELF_SIZE_CHANGED")
        return path

    def preflight(self):
        self.g["assert_inputs"](rollback=False)
        binary = self.candidate()
        # Cheap current-role and own-chain checks precede the full22 observation.
        old = self.inspect(BEFORE)
        require(old["Config"]["Labels"]["com.docker.compose.service"] == ROLE
                and old["State"]["Running"] and not old["State"]["Paused"], "CURRENT_NATIVE_ROLE_CHANGED")
        labels = old["Config"]["Labels"]
        files = labels["com.docker.compose.project.config_files"].split(",")
        # This role already runs from a frozen chain. Do not silently prepend
        # today's primary environment files to that historical exact chain.
        env_files = labels["com.docker.compose.project.environment_file"].split(",")
        require(env_files == self.i["runtimeEnvironmentFiles"], "OWN_ENVIRONMENT_CHAIN_CHANGED")
        require(all(Path(p).is_file() and not Path(p).is_symlink() for p in files + env_files), "OWN_COMPOSE_INPUT_MISSING")
        raw = ["docker", "compose", "--project-name", "elevenid-beta"]
        for flag, paths in (("--env-file", env_files), ("-f", files)):
            for path in paths:
                raw.extend((flag, path))
        argv = live_compose_arguments(raw, labels["com.docker.compose.project.working_dir"])
        before = self.legacy.base.validate_compose(argv)
        image = json.loads(self.command(["docker", "image", "inspect", old["Image"]]))[0]
        expected_env = effective_environment(image["Config"].get("Env") or [], before["services"][ROLE].get("environment", {}))
        require(environment(old["Config"]["Env"]) == expected_env, "EFFECTIVE_ENVIRONMENT_CHANGED")
        digest = self.command(argv + ["config", "--hash", ROLE]).decode().split()[-1]
        require(digest == labels["com.docker.compose.config-hash"], "CURRENT_COMPOSE_HASH_CHANGED")
        # Existing source-only renderer changes exactly the existing RO mount source.
        overlay = self.g["overlay"].binary_overlay({ROLE: self.i["candidate"]}, PROFILE, before=before)
        overlay_ref = self.g["save"]("candidate-overlay.private.json", overlay)
        after = self.legacy.base.validate_compose(argv, overlay=Path(overlay_ref["path"]))
        self.legacy.validate_delta(before, after, binary)
        frozen, hashes = self.g["freeze_compose"](raw, before, old)
        observed = self.g["node"]("before", {})
        rows = observed["binding"]["roles"]
        require(len(rows) == 22 and len({row["role"] for row in rows}) == 22, "BASE_ROLE_SET_CHANGED")
        require(next(row for row in rows if row["role"] == ROLE)["containerId"] == BEFORE
                and next(row for row in rows if row["role"] == "issuance")["containerId"] == PROXY,
                "ISSUER_OR_PROXY_CHANGED")
        database = self.g["database_snapshot"]()
        preview = {"state": "READ_ONLY_PREVIEW_READY", "runId": self.i["runId"], "before": observed,
                   "beforeConfig": self.g["save"]("preflight-native-config.private.json", old),
                   "beforeModel": self.g["save"]("before-compose.private.json", before),
                   "composeArguments": frozen, "frozenInputHashes": hashes,
                   "overlay": overlay_ref, "database": database, "candidate": self.i["candidate"],
                   "productionTouched": False, "imagesBuilt": False, "releaseQualified": False, "recordingQualified": False}
        return self.g["save"]("read-only-preview.private.json", preview)

    def prepare_model(self, preview, *, rollback=False):
        self.g["assert_inputs"](rollback=rollback)
        require(all(sha(Path(path)) == value for path, value in preview["frozenInputHashes"].items()), "FROZEN_COMPOSE_CHANGED")
        argv = preview["composeArguments"]
        model = json.loads(read_ref(preview["beforeModel"]).read_bytes())
        require(self.legacy.base.validate_compose(argv) == model, "FROZEN_MODEL_CHANGED")
        if rollback:
            old = json.loads(read_ref(preview["beforeConfig"]).read_bytes())
            path = next(mount["Source"] for mount in old["Mounts"] if mount["Destination"] == TARGET)
            self.g["verify_old_binary"](path)
            return argv, old, str(self.old_binary())
        self.candidate()
        overlay = read_ref(preview["overlay"])
        self.legacy.validate_delta(model, self.legacy.base.validate_compose(argv, overlay=overlay), self.candidate())
        return argv + ["-f", str(overlay)], json.loads(read_ref(preview["beforeConfig"]).read_bytes()), str(self.candidate())

    def replace(self, preview, *, rollback=False):
        argv, old, binary = self.prepare_model(preview, rollback=rollback)
        active = self.state["new"].get("containerId") if rollback else BEFORE
        require(active, "KNOWN_OWNED_CONTAINER_REQUIRED")
        self.g["node"]("untouched", {"before": preview["before"]})
        current = self.inspect(active)
        if rollback and not current["State"]["Running"]:
            require(current["State"]["Status"] in ("created", "exited") and current["State"]["Pid"] == 0
                    and not current["State"]["OOMKilled"], "RECOVERY_TERMINAL_STATE_NOT_RECONCILED")
            self.record("ROLLBACK_KNOWN_TERMINAL", activeContainerId=active)
        else:
            self.record("ROLLBACK_STOP_INTENT" if rollback else "STOP_INTENT", activeContainerId=active)
            self.command(["docker", "stop", "--timeout", "60", active])
            stopped = self.inspect(active)
            require(stopped["State"]["Status"] == "exited" and stopped["State"]["Pid"] == 0
                    and stopped["State"]["ExitCode"] == 0 and not stopped["State"]["OOMKilled"], "ISSUER_NOT_CLEANLY_STOPPED")
            self.record("STOP_ACK", activeContainerId=active)
        self.record("ROLLBACK_CREATE_INTENT" if rollback else "CREATE_INTENT")
        self.command(argv + ["create", "--no-build", "--no-deps", "--pull", "never", "--force-recreate", ROLE])
        ids = self.command(["docker", "ps", "-aq", "--no-trunc", "--filter", "label=com.docker.compose.project=elevenid-beta",
                            "--filter", "label=com.docker.compose.service=" + ROLE]).decode().split()
        require(len(ids) == 1, "CREATE_OUTCOME_UNKNOWN")
        created = self.inspect(ids[0])
        self.state["new"] = {"containerId": created["Id"],
                             "createdConfig": self.g["save"]("created-native-config-" + created["Id"] + ".private.json", created)}
        self.record("ROLLBACK_CREATED" if rollback else "CREATED")
        self.g["created_matches"](old, created, binary, argv)
        self.g["node"]("untouched", {"before": preview["before"]})
        self.record("ROLLBACK_START_INTENT" if rollback else "START_INTENT")
        self.command(["docker", "start", created["Id"]])
        self.record("START_ACK", activeContainerId=created["Id"])
        until = time.monotonic() + 120
        while True:
            current = self.inspect(created["Id"])
            if current["State"].get("Health", {}).get("Status") == "healthy":
                break
            require(current["State"]["Running"] and time.monotonic() < until, "ISSUER_HEALTH_NOT_ESTABLISHED")
            time.sleep(2)
        return self.g["observe_replacement"](current, binary, rollback)

    def apply(self, preview_ref):
        require(self.g["dispatch_enabled"] is True, "DISPATCH_DISABLED")
        preview = json.loads(read_ref(preview_ref).read_bytes())
        require(preview["state"] == "READ_ONLY_PREVIEW_READY" and preview["runId"] == self.i["runId"], "PREVIEW_CHANGED")
        require(self.g["node"]("before", {}) == preview["before"], "FRESH_ACTUAL22_CHANGED")
        require(self.g["database_snapshot"]() == preview["database"], "DATABASE_BASELINE_CHANGED")
        proof = self.store.exclusive("build-apply-intent.json", {"operation": self.state["operation"], "runId": self.i["runId"],
                                     "preview": preview_ref, "automaticRetry": False})
        require(durable_barrier(proof), "DURABLE_INTENT_BARRIER_REQUIRED")
        self.record("APPLY_CONSUMED")
        try:
            row = self.replace(preview)
            self.record("CANDIDATE_RUNNING", actualRole=row)
            readback = self.g["node"]("after", {"before": preview["before"], "role": row})
            auth = self.g["scoped_inventory_read"]()
            require(auth["httpStatus"] == 200 and auth["scopeVerified"] is True and auth["authCleanupComplete"] is True,
                    "SCOPED_INVENTORY_READ_FAILED")
            require(self.g["database_snapshot"]() == preview["database"], "DATABASE_CHANGED_DURING_REPLACEMENT")
            published = self.g["publish_profile"](preview, row, readback, auth)
            self.record("APPLIED_FUNCTIONAL_ONLY", actual22Readback=True, profile=published)
            return self.state
        except BaseException as error:
            self.record("FAILED_OR_UNKNOWN", failureAt=self.state["phase"], errorType=type(error).__name__, automaticRetry=False)
            raise

    def rollback(self, preview_ref, reconciled_state):
        require(self.g["dispatch_enabled"] is True, "DISPATCH_DISABLED")
        require(reconciled_state == self.store.read("build-state.json"), "AUTHORITATIVE_RECOVERY_STATE_CHANGED")
        require(self.g["reconcile_owned"](reconciled_state) is True, "OWNED_OUTCOME_NOT_RECONCILED")
        self.state = reconciled_state
        self.rolling_back = True
        # A new explicit recovery authority preserves the failed apply journal.
        self.store = self.g["rollback_journal_factory"](self.i)
        preview = json.loads(read_ref(preview_ref).read_bytes())
        proof = self.store.exclusive("build-apply-intent.json", {"operation": "CANVAS_ISSUER_ROLLBACK_ONLY", "runId": self.i["runId"]})
        require(durable_barrier(proof), "DURABLE_RECOVERY_INTENT_BARRIER_REQUIRED")
        if not self.state["new"].get("containerId"):
            self.old_binary()
            stopped = self.inspect(BEFORE)
            original = json.loads(read_ref(preview["beforeConfig"]).read_bytes())
            require(all(stopped[key] == original[key] for key in ("Id", "Name", "Image", "Config", "HostConfig", "Mounts")),
                    "ORIGINAL_OWNED_CONFIG_CHANGED")
            require(stopped["State"]["Status"] == "exited" and stopped["State"]["Pid"] == 0
                    and not stopped["State"]["OOMKilled"], "ORIGINAL_STOP_NOT_RECONCILED")
            self.g["node"]("untouched", {"before": preview["before"]})
            self.record("RESTORE_ORIGINAL_START_INTENT")
            self.command(["docker", "start", BEFORE])
            row = self.g["observe_original_restored"](BEFORE)
        else:
            row = self.replace(preview, rollback=True)
        self.g["node"]("after-rollback", {"before": preview["before"], "role": row})
        self.record("ROLLED_BACK_UNQUALIFIED_NEW_GENERATION", actualRole=row, originalProfileReused=False)
        return self.state
