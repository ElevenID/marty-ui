"""Closed latest-main four-role selection; executes no build or deployment.

The original d2de/three-role preparation remains a separate closed contract.
Latest input SHA is supplied by the reviewed one-run preparation, and MUST also
match the receipt actually read from its original durable build journal.
"""
import json
from scoped_native_profiles import LATEST_ALL_SERVICES
from scoped_native_runtime import read_ref, require
import scoped_passport_successor as passport

PROFILE = "native-devtest-passport-four-role"
SOURCE = LATEST_ALL_SERVICES.ui_revision
CORE = LATEST_ALL_SERVICES.core_revision
ROLE_BINARIES = {"applicant": "marty-applicant", **passport.ROLE_BINARIES}
BASE_PROFILE_SHA256 = passport.BASE_PROFILE_SHA256
BASE_BINDING_SHA256 = passport.BASE_BINDING_SHA256
FREEZE_SHA256 = "075a9bafaf27bd31acfe8372c3172e04cf584120882018ff327e71044b69a5c1"


def terminal_build(receipt, prepared, prepared_sha):
    return passport._terminal_build(receipt, prepared, prepared_sha, LATEST_ALL_SERVICES, None)


def select_canonical_binaries(prepared_ref, receipt_ref, journal):
    prepared = json.loads(read_ref(prepared_ref).read_bytes())
    require(prepared.get("sourceFreezeReceipt", {}).get("sha256") == FREEZE_SHA256,
            "EXACT_LATEST_SOURCE_FREEZE_REQUIRED")
    freeze = json.loads(read_ref(prepared["sourceFreezeReceipt"]).read_bytes())
    require(freeze.get("productRevision") == SOURCE and freeze.get("coreRevision") == CORE
            and freeze.get("imagesBuilt") is False and freeze.get("releaseQualified") is False,
            "EXACT_LATEST_SOURCE_FREEZE_REQUIRED")
    return passport._select_canonical_binaries(prepared_ref, receipt_ref, journal,
        LATEST_ALL_SERVICES, ROLE_BINARIES, PROFILE, None)


def validate_compatibility(selection, plan_ref, result_ref):
    validated = passport._validate_compatibility(selection, plan_ref, result_ref, ROLE_BINARIES, 10001)
    plan = json.loads(read_ref(plan_ref).read_bytes())
    require(plan.get("beforeBinding", {}).get("sha256") == BASE_BINDING_SHA256,
            "EXACT_CURRENT_PREIMAGE_FOR_COMPATIBILITY_REQUIRED")
    before = json.loads(read_ref(plan["beforeBinding"]).read_bytes())
    result = json.loads(read_ref(result_ref).read_bytes())
    for role, binary in ROLE_BINARIES.items():
        prior = next(row for row in before["roles"] if row["role"] == role)
        row = next(row for row in result["rows"] if row["binary"] == binary)
        require(row.get("imageId") == prior["imageId"], "ACTUAL_RUNTIME_IMAGE_COMPATIBILITY_REQUIRED")
    return validated


def operational_sql_sources():
    """Closed operational sources; business migrations remain in Rust."""
    from scoped_beta_binary_overlay import SQL_SHA256
    return {**SQL_SHA256,
        "passport-beta-fence-install.sql": "070d05156230ffc86658857ac8f7c7301d935cad772760942e40155030e6244f",
        "passport-beta-fence-drain.sql": "c1728e56e456a5e1a4d043d911fe6f16cb53addea60a00eed65724000bc0d2bc",
        "passport-beta-fence-verify.sql": "ff05feb0d08fc943ccbc7a1f85af9e87703563392a80667bbebfd66da7921db2",
        "passport-beta-rust-owner-verify.sql": "ce0f770268d1043248cfa8a5fd039fa8db4b9e6a367804870670378684e73047",
        "passport-beta-issuer-trigger-verify.sql": "584b2f9fade26bf8ec7744328bb3566fe4692d026f0cbefc5245d78c7f6834de",
        "passport-beta-native-attestation.sql": "9fea7b48ada94accad6920a51479b3dfeb2aea87603cba964a48041a2c2689eb"}


def migration_requirements():
    required = passport.migration_requirements()
    required.update(fencedSqlSha256=operational_sql_sources(),
        catalogSqlSha256="e7972f5d018100c5288dbe4eca0df2dbaa61ce21f8a34991789a3a173ad8110c",
        outcomeVerifier="tests/scripts/native-maintenance-runtime.js::produceLatestProfile",
        operationEvidence="ORIGINAL_JOURNAL_RUST_PSQL_CATALOG_RECEIPTS_NOT_LEGACY_FENCE_DTO",
        scope="LATEST_NATIVE_MAINTENANCE_PLAN_ONLY",
        flowSchemaToolSourceRevision=SOURCE, flowCliAvailableInSelectedBuild=True,
        separateSourceBoundMigrationToolBuildRequired=False,
        flowExecutionDisposition="USE_SAME_SOURCE_BOUND_SELECTED_FLOW_ELF",
        selectedRoleBinaries=ROLE_BINARIES,
        applicantStateHelper="scripts/beta-state-volume-plan.ps1::Set-BetaApplicantNonrootState",
        applicantUserBefore="0:0", applicantUserAfter="10001:10001",
        applicantDirectoryAfter={"uid": 10001, "gid": 10001, "mode": "0700"},
        applicantFileAfter={"uid": 10001, "gid": 10001, "mode": "0660"})
    return required
