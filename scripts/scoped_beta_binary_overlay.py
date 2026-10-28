"""Strict three-role preview adapter over existing Compose/runtime observations.

This module never executes Compose, SQL, stop/start or rollback. The reviewed
beta operator retains execution authority and its operation lock. A preview is
not a migration receipt or a functional-runtime/v2 qualification.
"""
from __future__ import annotations
from copy import deepcopy
import re
from scoped_native_runtime import (CORE_REVISION, UI_REVISION, ROLE_BINARIES,
    MARTY_CLIENTS, RUNTIME_ROLES, MIGRATIONS, daemon_source, read_ref, require, selected_sources, started_later)

SQL_FILES = ("passport-beta-db-maintenance-start.sql", "passport-beta-batch-acl-finalize.sql",
    "passport-beta-db-enable-app-login.sql", "passport-beta-rust-owner-transition.sql", "passport-beta-rust-owner-verify.sql")
SQL_SHA256 = {'passport-beta-db-maintenance-start.sql': '0129b6047f8ad3db2fa271f4b275bca6160b68c3bb6625dcc3937aba6f241608', 'passport-beta-batch-acl-finalize.sql': '5cca0125986da948eb5a684fc1ea24e349e680c967a6ff1e837659f4b22ee2ff', 'passport-beta-db-enable-app-login.sql': '4f30d51de9978ce1c9c62c41fc4a8fb600b4b275d1c82535ffcf0f67a1001720', 'passport-beta-rust-owner-transition.sql': '2cc812c71a6abc7db72f701ef83f51514ba620cfcba9af1f62025b3164bbe01a', 'passport-beta-rust-owner-verify.sql': '3c098a5d6b13f95a63bdabdf5a029b119563ea7045ffe3cbb870f12d97386f0d'}
FLOW_MUTABLE_COLUMNS = frozenset(("status", "claim_token", "claim_expires_at", "updated_at"))

def binary_overlay(binaries):
    require(set(binaries) == set(ROLE_BINARIES), "EXACT_THREE_ROLE_BINARIES_REQUIRED")
    return {"services": {role: {"volumes": [{"type": "bind", "source": str(read_ref(binaries[role], 512 * 1024 * 1024)),
        "target": "/usr/local/bin/" + binary, "read_only": True, "bind": {"create_host_path": False}}]}
        for role, binary in ROLE_BINARIES.items()}}

def validate_delta(before, after, binaries):
    require(set(binaries) == set(ROLE_BINARIES), "EXACT_THREE_ROLE_BINARIES_REQUIRED")
    require({k: v for k, v in before.items() if k != "services"} == {k: v for k, v in after.items() if k != "services"}, "PROJECT_SETTINGS_CHANGED")
    require(set(before["services"]) == set(after["services"]), "SERVICE_SET_CHANGED")
    for role, service in before["services"].items():
        old, new = deepcopy(service), deepcopy(after["services"][role])
        if role in ROLE_BINARIES:
            target = "/usr/local/bin/" + ROLE_BINARIES[role]
            a, b = old.pop("volumes", []), new.pop("volumes", [])
            require(len({v["target"] for v in a}) == len(a) and len({v["target"] for v in b}) == len(b), "DUPLICATE_MOUNT_TARGET")
            a, b = {v["target"]: v for v in a}, {v["target"]: v for v in b}
            require(set(a) == set(b) and target in a, "EXISTING_EXECUTABLE_BIND_REQUIRED")
            require(all(a[k] == b[k] for k in a if k != target), "UNRELATED_MOUNT_CHANGED")
            x, y = dict(a[target]), dict(b[target])
            require(x["type"] == y["type"] == "bind" and x.get("read_only") is True and y.get("read_only") is True, "READ_ONLY_EXECUTABLE_REQUIRED")
            x.pop("source")
            source = y.pop("source")
            require(daemon_source(source) == daemon_source(binaries[role]["path"]) and x == y, "EXECUTABLE_BIND_CHANGED_OUTSIDE_SOURCE")
        require(old == new, "UNRELATED_SERVICE_SETTINGS_CHANGED:" + role)

def maintenance_contract(plan):
    selected_sources(plan)
    require(set(plan.get("databaseClientRoles", [])) == MARTY_CLIENTS, "EXACT_BROADER_DATABASE_CLIENT_SCOPE_REQUIRED")
    require(plan.get("requiresSeparateMaintenanceReview") is True, "BROAD_MAINTENANCE_NOT_ACKNOWLEDGED")
    require(set(plan.get("migrationNames", [])) == set(MIGRATIONS), "EXACT_MIGRATION_SET_REQUIRED")
    require(plan.get("issuance0009LedgerCheckRequired") is True, "MDOC_PREREQUISITE_LEDGER_CHECK_REQUIRED")
    require(set(plan.get("sqlFiles", {})) == set(SQL_FILES), "EXISTING_FENCED_SQL_SEQUENCE_REQUIRED")
    for name, bound in plan["sqlFiles"].items():
        require(bound["sha256"] == SQL_SHA256[name], "SOURCE_BOUND_FENCED_SQL_CHANGED")
        file = read_ref(bound)
        require(file.name == name, "SQL_ALIAS_CHANGED")
    require(plan.get("noHistoricalJobMutation") is True and plan.get("noAutomaticRollback") is True, "RETAINED_DATA_AND_ROLLBACK_CUSTODY_REQUIRED")

def validate_fenced_observation(observed, expected):
    # These facts must come from the existing privileged source-bound SQL reader,
    # not an operator setting flags. The wrapper pins that reader and receipt.
    require(observed["databaseIdentity"] == expected["databaseIdentity"], "DATABASE_IDENTITY_CHANGED")
    require(observed.get("phase") == "fully_fenced" and observed.get("fenceEpoch") == expected["fenceEpoch"] and type(observed.get("fenceEpoch")) is int and observed["fenceEpoch"] > 0, "FENCED_EPOCH_REQUIRED")
    require(type(observed.get("activeMartyConnections")) is int and type(observed.get("activeMigratorConnections")) is int, "EXACT_CONNECTION_COUNTS_REQUIRED")
    require(observed.get("martyCanLogin") is False and observed.get("migratorCanLogin") is False and observed.get("activeMartyConnections") == 0 and observed.get("activeMigratorConnections") == 0, "APPLICATION_CONNECTIONS_NOT_FENCED")
    require(set(observed.get("flowIntentUpdateColumns", [])) == FLOW_MUTABLE_COLUMNS, "FLOW_IMMUTABLE_FIELDS_NOT_PROTECTED")
    require(observed.get("appSchemaCreateDenied") is True and observed.get("cancellationHistoryMutationsDenied") is True, "REQUIRED_ACL_DENIALS_UNPROVEN")

def validate_runtime_after(before, after, binaries, maintenance_restart_roles):
    old = {row["role"]: row for row in before["roles"]}
    new = {row["role"]: row for row in after["roles"]}
    require(len(before["roles"]) == len(after["roles"]) == len(old) == len(new) == 22 and set(old) == set(new) == RUNTIME_ROLES, "EXACT_22_ROLE_SET_REQUIRED")
    require(len({row["containerId"] for row in new.values()}) == 22 and all(re.fullmatch(r"[a-f0-9]{64}", row["containerId"]) for row in new.values()), "UNIQUE_CONTAINER_IDENTITIES_REQUIRED")
    require(set(maintenance_restart_roles).issubset(RUNTIME_ROLES - set(ROLE_BINARIES)), "UNREVIEWED_RESTART_ROLE")
    changes = []
    for role, prior in old.items():
        actual = new[role]
        require(actual["imageId"] == prior["imageId"] and actual["effectiveUid"] == prior["effectiveUid"] and actual["configuredRuntimeUid"] == prior["configuredRuntimeUid"], "IMAGE_OR_UID_CHANGED")
        if role not in ROLE_BINARIES:
            expected = deepcopy(prior)
            if role in maintenance_restart_roles:
                require(actual["containerId"] == prior["containerId"] and started_later(actual["startedAt"], prior["startedAt"]) and type(actual["hostPid"]) is int and actual["hostPid"] > 0, "RESTART_GENERATION_NOT_PROVEN")
                expected.update(startedAt=actual["startedAt"], hostPid=actual["hostPid"])
                changes.append(role)
            require(actual == expected, "UNSELECTED_RUNTIME_CHANGED:" + role)
            continue
        changed_fields = {"containerId", "startedAt", "hostPid", "source", "coreSource", "kind", "sha256", "processExecutableSha256", "binaryMounts", "requiredObservation"}
        require({k: v for k, v in actual.items() if k not in changed_fields} == {k: v for k, v in prior.items() if k not in changed_fields}, "UNRELATED_SELECTED_RUNTIME_CHANGED")
        require("requiredObservation" not in actual, "LEGACY_EXPECTATION_CANNOT_BECOME_NEW_D12_OBSERVATION")
        require(actual["containerId"] not in {row["containerId"] for row in old.values()} and actual["source"] == UI_REVISION, "FRESH_SELECTED_SOURCE_REQUIRED")
        require(actual.get("coreSource") == CORE_REVISION and actual.get("kind") == "SCOPED_NATIVE_FUNCTIONAL_OVERLAY", "SELECTED_RUNTIME_LINEAGE_CHANGED")
        require(actual["sha256"] == actual["processExecutableSha256"] == binaries[role]["sha256"], "RUNNING_ELF_HASH_CHANGED")
        require(actual["health"] == "healthy" and started_later(actual["startedAt"], prior["startedAt"]) and type(actual["hostPid"]) is int and actual["hostPid"] > 0, "SELECTED_RUNTIME_NOT_READY")
        target = "/usr/local/bin/" + ROLE_BINARIES[role]
        a = {m["destination"]: m for m in prior["binaryMounts"]}
        b = {m["destination"]: m for m in actual["binaryMounts"]}
        require(len(a) == len(prior["binaryMounts"]) and len(b) == len(actual["binaryMounts"]) and set(a) == set(b) and target in a, "RUNTIME_MOUNT_SET_CHANGED")
        require(all(a[k] == b[k] for k in a if k != target), "UNRELATED_RUNTIME_MOUNT_CHANGED")
        require(b[target]["type"] == "bind" and b[target]["writable"] is False and daemon_source(b[target]["source"]) == daemon_source(binaries[role]["path"]), "RUNTIME_EXECUTABLE_BIND_CHANGED")
        require(actual["executablePath"] == target, "RUNNING_EXECUTABLE_PATH_CHANGED")
    return {"schema": "marty.passport-scoped-native-runtime/v1", "uiRevision": UI_REVISION, "coreRevision": CORE_REVISION,
        "roleBinaries": ROLE_BINARIES, "maintenanceRestartRoles": changes, "roles": list(new.values()),
        "scope": "FUNCTIONAL_ONLY", "releaseQualified": False, "recordingQualified": False,
        "acceptedByExistingFunctionalRuntimeV2": False}

def compose_recreate_arguments(frozen_arguments, overlay_path):
    # Existing operator invokes this only AFTER reviewed maintenance/SQL/backup
    # gates, while holding the host operation lock. It is not an apply function.
    require(frozen_arguments[:4] == ["docker", "compose", "-p", "elevenid-beta"], "FROZEN_BETA_COMPOSE_ARGUMENTS_REQUIRED")
    require(len(frozen_arguments) >= 8 and len(frozen_arguments[4:]) % 2 == 0, "EXACT_BASE_COMPOSE_GRAMMAR_REQUIRED")
    counts = {"--project-directory": 0, "--env-file": 0, "-f": 0}
    for flag, value in zip(frozen_arguments[4::2], frozen_arguments[5::2]):
        require(flag in counts and isinstance(value, str) and value and not value.startswith("-"), "UNEXPECTED_BASE_COMPOSE_ARGUMENT")
        require(not re.search(r"[\x00-\x1f\x7f]", value), "INVALID_COMPOSE_INPUT_PATH")
        normalized = value.replace("\\", "/")
        require(normalized.startswith("/") or re.match(r"^[cCdD]:/", normalized), "ABSOLUTE_COMPOSE_INPUT_REQUIRED")
        require(all(part not in (".", "..") for part in normalized.split("/")), "TRAVERSING_COMPOSE_INPUT")
        counts[flag] += 1
    require(counts["--project-directory"] == 1 and counts["-f"] >= 1, "EXACT_COMPOSE_PROJECT_DIRECTORY_REQUIRED")
    return [*frozen_arguments, "-f", str(overlay_path), "up", "--detach", "--no-build", "--no-deps", "--pull", "never", "--force-recreate", "flow", "issuance-native", "gateway"]
