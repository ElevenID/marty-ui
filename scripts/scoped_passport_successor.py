"""D12 selection from the canonical all-service build, never a new build scope.

Read the original durable journal with its original frozen worker. A local
receipt, provisional build, or a successful compile without loader/UID evidence
cannot authorize a rollout. This module executes no deployment or migration.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

from scoped_native_profiles import OFFICIAL_ALL_SERVICES
from scoped_native_runtime import ROLE_BINARIES, read_ref, require, sha

PROFILE = "d12-passport-canonical-subset"
BASE_PROFILE_SHA256 = "6877251e868d692b43825761a4ac99fecf133b519f295a347d12221970b5a7f3"
BASE_BINDING_SHA256 = "09b2a8c03ff1907b6444baa91517c8a22ccaeabdbf82992e4198b76c92017fdc"
PREPARED_SHA256 = "c9b77a332139e5d7eb0e2684b5b54514ecad262531873e2f4c36dcd599da4c1a"
SOURCE = OFFICIAL_ALL_SERVICES.ui_revision
CORE = OFFICIAL_ALL_SERVICES.core_revision


def _terminal_build(receipt, prepared, prepared_sha, build_profile, exact_prepared):
    """Semantic checks are separate from the mandatory authoritative read."""
    require(exact_prepared is None or prepared_sha == exact_prepared, "EXACT_CANONICAL_BUILD_PREPARATION_REQUIRED")
    require(prepared.get("buildProfile") == build_profile.name
            and prepared.get("uiRevision") == build_profile.ui_revision and prepared.get("coreRevision") == build_profile.core_revision
            and prepared.get("roleBinaries") == dict(build_profile.roles),
            "EXACT_ALL29_PREPARATION_REQUIRED")
    require(receipt.get("state") == "PASSED" and type(receipt.get("exitCode")) is int
            and receipt["exitCode"] == 0 and receipt.get("oomKilled") is False
            and receipt.get("canonicalAllServices") is True
            and receipt.get("source") == receipt.get("uiRevision") == build_profile.ui_revision
            and receipt.get("coreRevision") == build_profile.core_revision
            and receipt.get("buildProfile") == build_profile.name
            and receipt.get("roleBinaries") == dict(build_profile.roles)
            and receipt.get("preparationSha256") == prepared_sha
            and receipt.get("runId") == prepared["runId"], "TERMINAL_CANONICAL_ALL29_REQUIRED")
    require(all(receipt.get(key) is False for key in
                ("imagesBuilt", "releaseQualified", "recordingQualified")), "FUNCTIONAL_BUILD_ONLY")
    require(set(receipt.get("binaries", {})) == set(dict(build_profile.roles)),
            "COMPLETE_CANONICAL_ALL29_RECEIPT_REQUIRED")


def terminal_build(receipt, prepared, prepared_sha):
    return _terminal_build(receipt, prepared, prepared_sha, OFFICIAL_ALL_SERVICES, PREPARED_SHA256)


def _select_canonical_binaries(prepared_ref, receipt_ref, journal, build_profile, roles, rollout_profile, exact_prepared):
    """Use an original shared LinuxBuildJournal, not a caller-authored mirror.

    The private binder loads its worker/shared/transport from exact Git blobs and
    the existing prepared specification. The method source, specification and
    actual read SHA/root are checked here; no current-source worker substitutes
    for the old journal backend and no new journal is initialized.
    """
    require(exact_prepared is None or prepared_ref["sha256"] == exact_prepared,
            "EXACT_CANONICAL_BUILD_PREPARATION_REQUIRED")
    prepared = json.loads(read_ref(prepared_ref).read_bytes())
    receipt = json.loads(read_ref(receipt_ref, 256 * 1024).read_bytes())
    spec = prepared["journalBackend"]
    require(type(journal).__name__ == "LinuxBuildJournal"
            and journal.run_id == prepared["runId"] and journal.specification == spec,
            "ORIGINAL_SHARED_BUILD_JOURNAL_REQUIRED")
    method = type(journal).invoke
    worker = Path(method.__code__.co_filename)
    require(sha(worker) == spec["workerSha256"]
            and sha(worker.with_name("scoped_native_runtime.py")) == spec["sharedSha256"],
            "ORIGINAL_JOURNAL_SOURCE_CHANGED")
    actual = journal.invoke("read", "build-receipt.json")
    require(actual.get("ok") is True and actual.get("name") == "build-receipt.json"
            and actual.get("rootProof") == spec["rootProof"]
            and actual.get("sha256") == receipt_ref["sha256"]
            and actual.get("value") == receipt, "ACTUAL_CANONICAL_JOURNAL_RECEIPT_REQUIRED")
    require(sha(worker) == spec["workerSha256"], "ORIGINAL_JOURNAL_SOURCE_CHANGED")
    _terminal_build(receipt, prepared, prepared_ref["sha256"], build_profile, exact_prepared)
    # Preserve every original evidence ref. Do not manufacture a smaller build
    # receipt or claim this subset was independently compiled.
    for key in ("originalCargoLock", "localizedCargoLock", "localizedLockProof",
                "lockedLocalizedMetadata", "coreFeatureResolution",
                "productionFeatureTree", "canonicalCompilerLog", "coreCompilerArtifacts"):
        read_ref(receipt[key], 64 * 1024 * 1024)
    binaries = {role: receipt["binaries"][binary] for role, binary in roles.items()}
    for bound in binaries.values():
        with read_ref(bound, 512 * 1024 * 1024).open("rb") as stream:
            header = stream.read(20)
        require(header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00",
                "SELECTED_AMD64_ELF_REQUIRED")
    return {"schema": "marty.passport-canonical-subset/v1", "profile": rollout_profile,
            "state": "SELECTED_NOT_DEPLOYED", "sourceRevision": build_profile.ui_revision, "coreRevision": build_profile.core_revision,
            "roleBinaries": dict(roles), "binaries": binaries,
            "canonicalBuildReceipt": receipt_ref, "preparedSource": prepared_ref,
            "journal": {"runId": prepared["runId"], "specification": spec},
            "scope": "FUNCTIONAL_ONLY", "releaseQualified": False, "recordingQualified": False}


def select_canonical_binaries(prepared_ref, receipt_ref, journal):
    return _select_canonical_binaries(prepared_ref, receipt_ref, journal, OFFICIAL_ALL_SERVICES,
                                      ROLE_BINARIES, PROFILE, PREPARED_SHA256)


def _validate_compatibility(selection, plan_ref, result_ref, roles, required_gid=None):
    """Require real loader/UID receipts; compile finish explicitly lacks these."""
    plan = json.loads(read_ref(plan_ref).read_bytes())
    result = json.loads(read_ref(result_ref).read_bytes())
    require(plan.get("scope") == "ELF_LOADER_UID_COMPATIBILITY_ONLY"
            and plan.get("buildReceiptAuthoritativeSha256") == selection["canonicalBuildReceipt"]["sha256"]
            and result.get("schema") == 1
            and result.get("state") == "ELF_LOADER_UID_COMPATIBILITY_PASS"
            and result.get("planSha256") == plan_ref["sha256"], "ACTUAL_COMPATIBILITY_REQUIRED")
    require(all(result.get(key) is False for key in
                ("candidateServiceEntrypointExecuted", "signingOrApi", "runtimeDeployed")),
            "LOADER_ONLY_COMPATIBILITY_REQUIRED")
    rows = result.get("rows", [])
    require(len(rows) == len({row["binary"] for row in rows}) == len(roles)
            and {row["binary"] for row in rows} == set(roles.values()),
            "EXACT_THREE_COMPATIBILITY_ROWS_REQUIRED" if len(roles) == 3 else "EXACT_FOUR_COMPATIBILITY_ROWS_REQUIRED")
    require(len({row.get("containerId") for row in rows}) == len(roles)
            and all(isinstance(row.get("containerId"), str)
                    and re.fullmatch(r"[a-f0-9]{64}", row["containerId"]) for row in rows),
            "EXACT_OWNED_COMPATIBILITY_CONTAINERS_REQUIRED")
    for role, binary in roles.items():
        row = next(row for row in rows if row["binary"] == binary)
        require(row["sha256"] == selection["binaries"][role]["sha256"]
                and type(row.get("uid")) is int and row["uid"] == 10001
                and (required_gid is None or type(row.get("gid")) is int and row["gid"] == required_gid)
                and type(row.get("exitCode")) is int and row["exitCode"] == 0
                and all(row.get(key) is True for key in
                        ("candidateReadableExecutable", "loaderListSucceeded", "ownedContainerRemoved")),
                "SELECTED_ELF_COMPATIBILITY_NOT_PROVEN")
    return {"plan": plan_ref, "result": result_ref}


def validate_compatibility(selection, plan_ref, result_ref):
    return _validate_compatibility(selection, plan_ref, result_ref, ROLE_BINARIES)


def migration_requirements():
    """Existing mechanisms only, with the unresolved Flow execution seam explicit."""
    from scoped_beta_binary_overlay import MIGRATIONS, SQL_SHA256
    return {"scope": "D12_MAINTENANCE_PLAN_ONLY", "migrationNames": list(MIGRATIONS),
            "fencedSqlSha256": dict(SQL_SHA256),
            "issuanceArgv": [["marty-issuance-service", "migrate"],
                             ["marty-issuance-service", "verify-owned-schema"]],
            "flowSource": "rust/services/flow/src/migration.rs::migrate_flow_schema",
            "flowValidation": "rust/services/flow/src/migration.rs::validate_flow_schema",
            "flowCliAvailableInD2de": False,
            "currentSourceFlowCli": ["migrate", "verify-owned-schema"],
            "separateSourceBoundMigrationToolBuildRequired": True,
            "matchingMigrationSqlAndSchemaHashesRequired": True,
            "flowExecutionDisposition": "REQUIRES_SEPARATELY_BUILT_REVIEWED_FLOW_SCHEMA_TOOL",
            "all22QuiescenceRequired": True, "issuance0009LedgerCheckRequired": True,
            "applyEnabled": False, "historicalSqlHandoffPermitted": False,
            "automaticRollbackPermitted": False}
