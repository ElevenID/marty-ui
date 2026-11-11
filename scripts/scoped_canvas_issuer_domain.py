"""Read-only domain/provenance callbacks for the existing issuer host operator."""
import ctypes
from ctypes import wintypes
import json
import os
import subprocess
import time
import uuid

SQL = """SELECT json_build_object(
 'database',current_database(),
 'versions',(SELECT json_agg(version ORDER BY version) FROM issuance_service.rust_schema_migrations),
 'transactions',(SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text,'[]'),'UTF8')),'hex') FROM issuance_service.issuance_transactions t),
 'credentials',(SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text,'[]'),'UTF8')),'hex') FROM issuance_service.issued_credentials t),
 'jobs',(SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text,'[]'),'UTF8')),'hex') FROM issuance_service.canvas_evidence_sync_jobs t),
 'targets',(SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text,'[]'),'UTF8')),'hex') FROM issuance_service.canvas_evidence_sync_targets t),
 'bindings',(SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id)::text,'[]'),'UTF8')),'hex') FROM issuance_service.canvas_program_bindings t),
 'activeJobs',(SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs WHERE status IN ('queued','leased','retry')),
 'unknownJobs',(SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs WHERE status NOT IN ('queued','leased','retry','succeeded','dead_letter','cancelled')))
"""


def attach_context(context, inputs):
    """Only install callbacks here; check/bootstrap must perform no operations."""
    require, command = context["require"], context["command"]

    def process_identity(pid=None):
        require(os.name == "nt", "WINDOWS_CONTROLLER_IDENTITY_REQUIRED")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        pid = os.getpid() if pid is None else pid
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            require(ctypes.get_last_error() == 87, "CONTROLLER_PROCESS_UNIDENTIFIED")
            return None
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            require(kernel.GetProcessTimes(handle, *[ctypes.byref(value) for value in times]), "CONTROLLER_BIRTH_UNKNOWN")
            code = wintypes.DWORD()
            require(kernel.GetExitCodeProcess(handle, ctypes.byref(code)), "CONTROLLER_EXIT_UNKNOWN")
            return {"pid": pid, "creationFileTime": (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime,
                    "running": code.value == 259}
        finally:
            kernel.CloseHandle(handle)

    last = {}

    def node(mode, payload):
        # The scoped API client imports the real driver and its sibling modules.
        # Bind that checkout as well as the standalone reader before launching it.
        git = inputs["executables"]["git"]["path"]
        source = subprocess.run([git, "-C", inputs["driverRepository"], "rev-parse", "HEAD"],
                                env=context["env"], capture_output=True, timeout=20)
        require(source.returncode == 0 and source.stdout.decode().strip() == inputs["driverRevision"], "DRIVER_SOURCE_REVISION_CHANGED")
        clean = subprocess.run([git, "-C", inputs["driverRepository"], "status", "--porcelain"],
                               env=context["env"], capture_output=True, timeout=20)
        require(clean.returncode == 0 and not clean.stdout.strip(), "DRIVER_SOURCE_DIRTY")
        arguments = [context["nodeExecutable"], inputs["nodeReader"]["path"], "--inputs", context["inputRef"]["path"],
                     "--inputs-sha256", context["inputRef"]["sha256"], "--mode", mode]
        nonce = str(uuid.uuid4())
        if payload:
            request = context["save"]("node-" + mode + "-" + nonce + ".request.private.json", payload)
            arguments += ["--payload", request["path"], "--payload-sha256", request["sha256"]]
        env = dict(context["env"])
        env["NODE_PATH"] = inputs["nodePath"]
        result = subprocess.run(arguments, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=600, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        context["save"]("node-" + mode + "-" + nonce + ".result.private.json", {
            "mode": mode, "exitCode": result.returncode, "stdout": result.stdout[-1024 * 1024:].decode("utf8", "replace"),
            "stderr": result.stderr[-65536:].decode("utf8", "replace")})
        require(result.returncode == 0, "SOURCE_BOUND_NODE_READ_FAILED")
        value = json.loads(result.stdout)
        if mode == "after":
            require(value["state"] == "ACTUAL22_READBACK_VERIFIED" and len(value["roles"]) == 22, "ACTUAL22_READBACK_REQUIRED")
            last.update(before=payload["before"], role=payload["role"])
        return value

    def database_snapshot():
        wanted = inputs["databaseIdentity"]
        actual = json.loads(command(["docker", "inspect", wanted["containerId"]]))[0]
        require(actual["Id"] == wanted["containerId"] and actual["Image"] == wanted["imageId"]
                and actual["State"]["Running"] and actual["State"]["StartedAt"] == wanted["startedAt"]
                and actual["State"]["Pid"] == wanted["hostPid"]
                and actual["Config"]["Labels"]["com.docker.compose.project"] == "elevenid-beta"
                and actual["Config"]["Labels"]["com.docker.compose.service"] == "postgres", "DATABASE_IDENTITY_CHANGED")
        # Reuse the existing PGOPTIONS read-only operator, including its tenant service guard.
        data = context["issuer_helpers"].postgres_json(SQL)
        require(data["database"] == "marty" and data["activeJobs"] == 0 and data["unknownJobs"] == 0,
                "CANVAS_DATABASE_NOT_QUIESCENT")
        return {"identity": wanted, "data": data, "scope": "ISSUANCE_TRANSACTIONS_CREDENTIALS_CANVAS_JOBS_TARGETS_BINDINGS_AND_MIGRATION_LEDGER"}

    def inventory():
        require("role" in last, "ACTUAL_CANDIDATE_READBACK_REQUIRED")
        return node("inventory", {"before": last["before"], "role": last["role"]})

    def wait_dependents_healthy(before):
        gateway = next(row for row in before["binding"]["roles"] if row["role"] == "gateway")
        deadline = time.monotonic() + 120
        while True:
            actual = json.loads(command(["docker", "inspect", gateway["containerId"]]))[0]
            require(actual["Id"] == gateway["containerId"] and actual["Image"] == gateway["imageId"]
                    and actual["State"]["StartedAt"] == gateway["startedAt"] and actual["State"]["Pid"] == gateway["hostPid"]
                    and actual["State"]["Running"] and not actual["State"]["Paused"], "DEPENDENT_GATEWAY_IDENTITY_CHANGED")
            status = actual["State"].get("Health", {}).get("Status")
            if status == "healthy":
                return
            require(status in ("starting", "unhealthy") and time.monotonic() < deadline, "DEPENDENT_GATEWAY_READINESS_NOT_RECOVERED")
            time.sleep(2)

    def publish(preview, row, readback, auth):
        require(readback["state"] == "ACTUAL22_READBACK_VERIFIED" and len(readback["roles"]) == 22, "ACTUAL22_READBACK_REQUIRED")
        before = context["save"]("before-runtime-binding.private.json", {
            "baseProfileSha256": inputs["baseProfile"]["sha256"], "binding": preview["before"]["binding"]})
        auth_ref = context["save"]("scoped-inventory-read.private.json", auth)
        deployment = {"schema": "marty.scoped-native-overlay-deployment/v1", "profile": "canvas-issuer-scoped-jobs",
                      "state": "APPLIED_FUNCTIONAL_ONLY", "actualReadbackVerified": True,
                      "baseProfileSha256": inputs["baseProfile"]["sha256"],
                      "buildReceiptSha256": inputs["evidence"]["buildReceipt"]["sha256"],
                      "compatibilityResultSha256": inputs["evidence"]["compatibilityResult"]["sha256"],
                      "sourceRevision": "fce109daf47a7712c1ff5779b0e33def57bbce20",
                      "coreRevision": "44040270000f93b7e7499cbec31b3bb3dd7e3df1", "engineId": inputs["engineId"],
                      "beforeRuntimeBinding": before, "roles": {"issuance-native": row}, "scopedInventoryReadback": auth_ref,
                      "productionTouched": False, "imagesBuilt": False, "releaseQualified": False, "recordingQualified": False}
        receipt = context["save"]("issuer-deployment.private.json", deployment)
        profile = context["save"]("functional-runtime-profile.json", {"schema": "marty.functional-mixed-runtime/v2",
            "scope": "FUNCTIONAL_ONLY", "releaseQualified": False, "recordingQualified": False,
            "baseProfile": inputs["baseProfile"], "nativeOverlay": {**inputs["evidence"], "deploymentReceipt": receipt}})
        verified = node("verify-profile", {"profile": profile})
        context["save"]("actual-postapply-runtime-binding.json", verified["binding"])
        return profile

    def reconcile_owned(state):
        old = state["controllerIdentity"]
        current = process_identity(old["pid"])
        require(current is None or current["creationFileTime"] != old["creationFileTime"] or not current["running"], "ORIGINAL_CONTROLLER_STILL_LIVE")
        # An intent-only daemon outcome needs a separate Root-reviewed disposition.
        require(state.get("failureAt") not in ("STOP_INTENT", "CREATE_INTENT", "START_INTENT", "ROLLBACK_CREATE_INTENT", "ROLLBACK_START_INTENT"),
                "UNKNOWN_DAEMON_OUTCOME_REQUIRES_ROOT_RECONCILIATION")
        preview = context["document"](inputs["preview"])
        node("untouched", {"before": preview["before"], **({"nativeTransition": state["new"]} if state["new"].get("containerId") else {
            "nativeTransition": {"containerId": "75a9e465fbbf139a528739f36a71121a63860f17e9aca45c612d5f49532b7f60", "originalConfig": preview["beforeConfig"]}})})
        cid = state["new"].get("containerId")
        if cid:
            saved = context["document"](state["new"]["createdConfig"])
            actual = json.loads(command(["docker", "inspect", cid]))[0]
            require(all(actual[key] == saved[key] for key in ("Id", "Name", "Image", "Config", "HostConfig", "Mounts")), "KNOWN_CREATED_OWNER_CHANGED")
            require(actual["Config"]["Labels"]["com.docker.compose.service"] == "issuance-native"
                    and actual["Config"]["Labels"]["com.docker.compose.project"] == "elevenid-beta", "KNOWN_CREATED_ROLE_CHANGED")
        else:
            require(state.get("failureAt") in ("STOP_ACK", "APPLY_CONSUMED"), "CREATE_ABSENCE_NOT_PROVEN")
        return True

    context.update(node=node, database_snapshot=database_snapshot, scoped_inventory_read=inventory,
                   publish_profile=publish, reconcile_owned=reconcile_owned, controller_identity=process_identity,
                   wait_dependents_healthy=wait_dependents_healthy)
