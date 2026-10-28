"""Preview-only all22-role maintenance wrapper for the scoped D12 overlay.

It renders bounded, no-SIGKILL graceful stop/start commands and validates
observations. It never executes Docker, SQL, backup, credential operations or
recovery. A separately reviewed execution wrapper must hold existing host locks,
consume a durable private intent, and authenticate every actual observation.
"""
from __future__ import annotations
from copy import deepcopy
import re
from scoped_native_runtime import RUNTIME_ROLES, ROLE_BINARIES, read_ref, require, selected_sources


def exact_roles(observed):
    rows = observed["roles"]
    require(len(rows) == 22 and {row["role"] for row in rows} == RUNTIME_ROLES, "EXACT_22_ROLE_SET_REQUIRED")
    require(len({row["containerId"] for row in rows}) == 22 and all(re.fullmatch(r"[a-f0-9]{64}", row["containerId"]) for row in rows),
            "UNIQUE_BOUND_CONTAINER_IDS_REQUIRED")
    return {row["role"]: row for row in rows}


def _stop_contract(role, row, bound):
    import json
    policy = json.loads(read_ref(bound).read_bytes())
    require(policy.get("schema") == "marty.reviewed-graceful-stop/v1" and policy.get("role") == role
            and policy.get("containerId") == row["containerId"] and policy.get("elfSha256") == row["sha256"]
            and policy.get("sourceRevision") == row["source"], "EXACT_STOP_CONTRACT_REQUIRED:" + role)
    require(policy.get("signal") in ("SIGTERM", "SIGINT") and policy.get("allowedExitCodes") == [0] and type(policy["allowedExitCodes"][0]) is int
            and policy.get("noAutomaticSigkill") is True, "SOURCE_BACKED_GRACEFUL_STOP_REQUIRED:" + role)
    # A hash-bound source proof is required. Existing crash-stop exceptions do
    # not become blanket permission; unresolved handlers block preview readiness.
    proof = json.loads(read_ref(policy["sourceProof"], 65536).read_bytes())
    require(proof.get("schema") == "marty.graceful-shutdown-source-proof/v1" and proof.get("role") == role
            and proof.get("sourceRevision") == row["source"] and proof.get("elfSha256") == row["sha256"]
            and policy["signal"] in proof.get("supportedSignals", []), "GRACEFUL_SOURCE_PROOF_MISMATCH:" + role)
    return policy


PROJECTS = frozenset(("elevenid-beta", "elevenid-beta-ui"))
ROLE_PROJECTS = {role: "elevenid-beta-ui" if role == "ui-prod" else "elevenid-beta" for role in RUNTIME_ROLES}


def _restore_order(models, rows, reviewed_cross_edges):
    require(set(models) == PROJECTS, "EXACT_TWO_COMPOSE_PROJECTS_REQUIRED")
    dependencies = {role: set() for role in RUNTIME_ROLES}
    for project, model in models.items():
        require(model.get("name") == project, "COMPOSE_PROJECT_NAME_CHANGED")
        for role in set(model["services"]) & RUNTIME_ROLES:
            require(rows[role].get("project") == ROLE_PROJECTS[role] == project, "COMPOSE_ROLE_PROJECT_MISASSOCIATED")
    for role in RUNTIME_ROLES:
        project = rows[role].get("project")
        require(project == ROLE_PROJECTS[role] and role in models[project]["services"], "BASELINE_ROLE_PROJECT_MISSING")
        dep = models[project]["services"][role].get("depends_on", {})
        require(isinstance(dep, (dict, list)), "UNKNOWN_COMPOSE_DEPENDENCY_SHAPE")
        for name in dep:
            if name not in models[project]["services"]:
                require(name in RUNTIME_ROLES and (role, name) in reviewed_cross_edges, "UNREVIEWED_CROSS_PROJECT_DEPENDENCY")
            if name in RUNTIME_ROLES:
                if ROLE_PROJECTS[name] != project:
                    require((role, name) in reviewed_cross_edges, "UNREVIEWED_CROSS_PROJECT_DEPENDENCY")
                dependencies[role].add(name)
    for role, dependency in reviewed_cross_edges:
        dependencies[role].add(dependency)
    order = []
    while len(order) != 22:
        ready = sorted(role for role in RUNTIME_ROLES - set(order) if dependencies[role].issubset(order))
        require(ready, "MAINTENANCE_DEPENDENCY_CYCLE_REQUIRES_REVIEW")
        order.extend(ready)
    return order


def _reviewed_cross_edges(plan):
    import json
    edges = set()
    for edge in plan.get("reviewedCrossProjectDependencies", []):
        role, dependency = edge["fromRole"], edge["toRole"]
        require(role in RUNTIME_ROLES and dependency in RUNTIME_ROLES and ROLE_PROJECTS[role] != ROLE_PROJECTS[dependency],
                "CROSS_PROJECT_EDGE_SCOPE_CHANGED")
        expected = {"schema": "marty.reviewed-cross-project-dependency/v1", "fromRole": role, "toRole": dependency,
                    "fromProject": ROLE_PROJECTS[role], "toProject": ROLE_PROJECTS[dependency]}
        require(json.loads(read_ref(edge["proof"], 65536).read_bytes()) == expected, "CROSS_PROJECT_PROOF_CHANGED")
        require((role, dependency) not in edges, "DUPLICATE_CROSS_PROJECT_EDGE")
        edges.add((role, dependency))
    return edges


def preview(plan, before, compose_models):
    selected_sources(plan)
    rows = exact_roles(before)
    require(set(plan["stopContracts"]) == RUNTIME_ROLES, "ALL_22_STOP_CONTRACTS_REQUIRED")
    for row in rows.values():
        require(row.get("running") is True and row.get("paused") is False and type(row.get("hostPid")) is int
                and row["hostPid"] > 0, "RUNNING_UNPAUSED_BASELINE_REQUIRED")
    import json
    require(set(plan["composeModels"]) == PROJECTS and set(compose_models) == PROJECTS, "EXACT_TWO_COMPOSE_PROJECTS_REQUIRED")
    for project, bound in plan["composeModels"].items():
        frozen = json.loads(read_ref(bound).read_bytes())
        require(frozen == compose_models[project], "FROZEN_COMPOSE_MODEL_CHANGED:" + project)
    restore = _restore_order(compose_models, rows, _reviewed_cross_edges(plan))
    # Fence public ingress first, then reverse dependency order. All22 must be
    # terminal before any privileged SQL, not merely the three replaced roles.
    order = ["gateway", *[role for role in reversed(restore) if role != "gateway"]]
    stops = []
    for role in order:
        policy = _stop_contract(role, rows[role], plan["stopContracts"][role])
        stops.append({"role": role, "project": rows[role]["project"], "containerId": rows[role]["containerId"], "signal": policy["signal"],
            "argv": ["docker", "--context", "desktop-linux", "stop", "--signal", policy["signal"], "--timeout", "-1", rows[role]["containerId"]],
            "timeoutOutcome": "UNKNOWN_RECONCILE_NO_RETRY_OR_AUTOMATIC_START", "requireExitCode": 0,
            "noOom": True, "requirePidZero": True})
    return {"schema": "marty.passport-maintenance-preview/v1", "state": "PREVIEW_ONLY_NOT_QUIESCED",
        "allStopRoles": order, "composeProjects": sorted(PROJECTS), "stopSteps": stops, "restoreOrder": restore,
        "additionalUnselectedRestartRoles": sorted(RUNTIME_ROLES - set(ROLE_BINARIES)),
        "existingLocksRequired": ["beta_operation_lock", "canonical_recording_lock_without_nested_acquire"],
        "durableOneShotIntentRequiredBeforeFirstStop": True,
        "phaseGates": ["actual22_and_retained_D12_D05_readonly_baseline", "all22_owned_stops_terminal_pid0_noOom",
            "consistent_current_database_backup", "existing_fully_fenced_source_bound_SQL_and_zero_app_connections",
            "version_checked_additive_migrations_and_0009_ledger", "existing_ACL_finalizer_denials_and_owner_receipt",
            "reviewed_exact3_binary_overlay", "all22_start_pass_before_any_health_wait",
            "all22_health_source_uid_mounts_and_retained_data_proof", "new_explicit_runtime_generation_profile"],
        "noHistoricalJobMutation": True, "noAutomaticRollback": True, "noApplyAuthority": True,
        "releaseQualified": False, "recordingQualified": False}


def validate_quiescent(before, stopped, outcomes):
    original, current = exact_roles(before), exact_roles(stopped)
    require(set(outcomes) == RUNTIME_ROLES, "ALL_STOP_OUTCOMES_REQUIRED")
    for role, prior in original.items():
        row, outcome = current[role], outcomes[role]
        require(row["containerId"] == prior["containerId"] and row["imageId"] == prior["imageId"]
                and row["sha256"] == prior["sha256"] and row["binaryMounts"] == prior["binaryMounts"]
                and row["startedAt"] == prior["startedAt"],
                "STOPPED_ROLE_CUSTODY_CHANGED:" + role)
        require(outcome.get("terminal") is True and type(outcome.get("exitCode")) is int and outcome["exitCode"] == 0
                and outcome.get("stopAcknowledged") is True, "UNKNOWN_STOP_OUTCOME_NO_SQL:" + role)
        require(row.get("running") is False and row.get("paused") is False and type(row.get("hostPid")) is int and row["hostPid"] == 0
                and type(row.get("containerExitCode")) is int and row["containerExitCode"] == 0
                and row.get("oomKilled") is False and row.get("state") == "exited", "ROLE_NOT_CLEANLY_QUIESCENT:" + role)
    return {"all22Quiescent": True, "databaseConnectionsStillRequireIndependentFencedSQLCheck": True,
            "noApplyAuthority": True}


def restore_commands(before, current, outcomes, restore_order):
    """Return owned start pass only after every prior command is terminal.

    A timeout, unresolved paused state or missing generation blocks this path;
    Root must first authorize a separate exact reconciliation, never blind start.
    """
    original, now = exact_roles(before), exact_roles(current)
    require(set(outcomes) == RUNTIME_ROLES and all(outcomes[r].get("terminal") is True for r in RUNTIME_ROLES),
            "UNRESOLVED_STOP_REFUSES_AUTOMATIC_RESTORE")
    require(len(restore_order) == 22 and set(restore_order) == RUNTIME_ROLES, "FROZEN_RESTORE_ORDER_REQUIRED")
    result = []
    for role in restore_order:
        prior = original[role]
        actual = now[role]
        require(actual["containerId"] == prior["containerId"] and actual["imageId"] == prior["imageId"]
                and actual["sha256"] == prior["sha256"] and actual["binaryMounts"] == prior["binaryMounts"]
                and actual.get("paused") is False, "RESTORE_IDENTITY_OR_PAUSED_STATE_UNKNOWN")
        require(actual.get("state") in ("running", "exited") and actual.get("running") == (actual["state"] == "running"),
                "RESTORE_RUNTIME_STATE_UNKNOWN")
        if not actual["running"]:
            require(type(actual.get("hostPid")) is int and actual["hostPid"] == 0 and actual.get("containerExitCode") == 0
                    and actual.get("oomKilled") is False and outcomes[role].get("exitCode") == 0
                    and outcomes[role].get("stopAcknowledged") is True, "RESTORE_STOP_NOT_POSITIVELY_RECONCILED")
            result.append({"role": role, "argv": ["docker", "--context", "desktop-linux", "start", prior["containerId"]]})
    return {"startPass": result, "healthWaitAfterEntirePass": True, "noDesktopCommand": True,
            "noRecreateResetPruneOrMigration": True, "noApplyAuthority": True}


def with_observed_state(binding, inspections):
    """Project only allowlisted Docker State metadata; never Env or arguments."""
    allowed = {"role", "binary", "source", "sha256", "kind", "imageId", "project", "containerId", "health",
               "startedAt", "hostPid", "executablePath", "processExecutableSha256", "binaryMounts", "effectiveUid", "configuredRuntimeUid"}
    rows = [{key: deepcopy(value) for key, value in row.items() if key in allowed} for row in binding["roles"]]
    by_id = {item["Id"]: item for item in inspections}
    require(len(by_id) == len(inspections) == 22, "EXACT_22_INSPECTIONS_REQUIRED")
    for row in rows:
        actual = by_id[row["containerId"]]
        require(actual["Image"] == row["imageId"], "BASELINE_IMAGE_CHANGED")
        for mount in row["binaryMounts"]:
            matches = [item for item in actual["Mounts"] if item["Destination"] == mount["destination"]]
            require(len(matches) == 1 and matches[0]["Type"] == mount["type"] and matches[0]["Source"] == mount["source"]
                    and matches[0]["RW"] == mount["writable"], "OBSERVED_EXECUTABLE_MOUNT_CHANGED")
        state = actual["State"]
        row.update(startedAt=state["StartedAt"], health=state.get("Health", {}).get("Status"), running=state["Running"], paused=state["Paused"], hostPid=state["Pid"], state=state["Status"],
                   containerExitCode=state["ExitCode"], oomKilled=state.get("OOMKilled", False))
    return {"scope": "D12_STATE_PROJECTION_ONLY", "roles": rows, "sourceFactsBoundToPriorReceiptNotNewElfProbe": True,
            "releaseQualified": False, "recordingQualified": False}
