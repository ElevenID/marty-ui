"""Synthetic source controls. No build, data migration, beta or qualification."""
from copy import deepcopy
import hashlib
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_native_maintenance as latest
import scoped_native_profiles as profiles
import scoped_native_build as build
import scoped_beta_binary_overlay as overlay
from scoped_native_runtime import selected_sources


def test_closed_latest_all29_scope_preserves_historical_recipe_and_cache():
    old, new = profiles.OFFICIAL_ALL_SERVICES, profiles.LATEST_ALL_SERVICES
    assert old.ui_revision == "d2debf0fde2a0c826f8925aca648c9d3dabfbc9f"
    assert old.roles == new.roles and len(new.roles) == 29
    assert new.ui_revision == latest.SOURCE and new.core_revision == latest.CORE
    assert old.volumes == new.volumes and old.cargo_profile == new.cargo_profile == "release"
    assert build.render_recipe(old.name) == build.render_recipe(new.name)
    assert build.LATEST_FREEZE_SHA256 == latest.FREEZE_SHA256
    assert set(build.build_scope(new.name)["roles"]) == set(dict(new.roles))
    with pytest.raises(ValueError):
        build.build_scope(latest.PROFILE)
    plan = dict(rolloutProfile=latest.PROFILE, uiRevision=latest.SOURCE,
                coreRevision=latest.CORE, roleBinaries=latest.ROLE_BINARIES,
                releaseQualified=False, recordingQualified=False)
    selected_sources(plan, latest.PROFILE)
    for change in (dict(uiRevision=old.ui_revision), dict(buildProfile=new.name), dict(roleBinaries=overlay.ROLE_BINARIES)):
        with pytest.raises(ValueError):
            selected_sources(plan | change, latest.PROFILE)


def test_latest_terminal_requires_exact_all29_and_same_source_run():
    prepared = dict(buildProfile=profiles.LATEST_ALL_SERVICES.name, uiRevision=latest.SOURCE,
        coreRevision=latest.CORE, runId="synthetic-only", roleBinaries=dict(profiles.LATEST_ALL_SERVICES.roles))
    receipt = prepared | dict(state="PASSED", exitCode=0, oomKilled=False, canonicalAllServices=True,
        source=latest.SOURCE, preparationSha256="a" * 64, imagesBuilt=False, releaseQualified=False,
        recordingQualified=False, binaries={binary: {} for binary in prepared["roleBinaries"]})
    latest.terminal_build(receipt, prepared, "a" * 64)
    for change in (dict(state="BUILD_RUNNING"), dict(exitCode=False), dict(oomKilled=True),
                   dict(source=profiles.OFFICIAL_ALL_SERVICES.ui_revision), dict(runId="foreign"),
                   dict(binaries={binary: {} for binary in latest.ROLE_BINARIES.values()})):
        with pytest.raises(ValueError):
            latest.terminal_build(receipt | change, prepared, "a" * 64)


def test_four_role_compose_changes_only_binary_sources_and_applicant_user(tmp_path):
    binaries = {}
    before = {"name": "elevenid-beta", "services": {}}
    for role, binary in latest.ROLE_BINARIES.items():
        file = tmp_path / binary
        file.write_bytes(b"synthetic-not-ELF")
        binaries[role] = dict(path=str(file), sha256=hashlib.sha256(file.read_bytes()).hexdigest())
        before["services"][role] = dict(user="0:0" if role == "applicant" else "10001:10001",
            environment={"UNCHANGED": "synthetic"}, labels={"keep": "label"},
            volumes=[dict(type="bind", source="/old/" + binary, target="/usr/local/bin/" + binary,
                          read_only=True, bind={"create_host_path": False})])
    before["services"]["signing-keys"] = dict(user="10001:10001", environment={"keep": "yes"})
    rendered = overlay.binary_overlay(binaries, latest.PROFILE, before=before)
    after = deepcopy(before)
    for role, patch in rendered["services"].items():
        after["services"][role].update(patch)
    overlay.validate_delta(before, after, binaries, latest.PROFILE)
    for mutate in (lambda a: a["services"]["applicant"].update(user="10001:0"),
                   lambda a: a["services"]["flow"]["environment"].update(UNCHANGED="changed"),
                   lambda a: a["services"]["signing-keys"].update(user="0:0"),
                   lambda a: a["services"]["gateway"]["volumes"][0].update(read_only=False)):
        bad = deepcopy(after)
        mutate(bad)
        with pytest.raises(ValueError):
            overlay.validate_delta(before, bad, binaries, latest.PROFILE)
    for roles in (["applicant"], list(latest.ROLE_BINARIES) + ["issuance"], ["applicant"] * 4):
        with pytest.raises(ValueError):
            overlay.overlay_roles(latest.PROFILE, roles)
    args = ["docker", "compose", "-p", "elevenid-beta", "--project-directory", "/owned", "-f", "/owned/base.yml"]
    vector = overlay.compose_recreate_arguments(args, "/owned/overlay.yml", latest.PROFILE, no_start=True)
    assert set(vector[-4:]) == set(latest.ROLE_BINARIES) and "--no-start" in vector
    with pytest.raises(ValueError):
        overlay.compose_recreate_arguments(args, "/owned/overlay.yml", latest.PROFILE)


def test_latest_uses_selected_flow_cli_without_duplicate_tool_build():
    required = latest.migration_requirements()
    assert required["flowSchemaToolSourceRevision"] == latest.SOURCE
    assert required["flowCliAvailableInSelectedBuild"] is True
    assert required["separateSourceBoundMigrationToolBuildRequired"] is False
    assert required["all22QuiescenceRequired"] is True and required["historicalSqlHandoffPermitted"] is False
    assert required["applicantUserBefore"] == "0:0" and required["applicantUserAfter"] == "10001:10001"
    assert required["applyEnabled"] is False


def test_latest_contract_binds_initial_fence_and_metadata_sources():
    from scoped_native_runtime import MARTY_CLIENTS, MIGRATIONS
    root = Path(__file__).resolve().parents[1]
    plan = dict(rolloutProfile=latest.PROFILE, uiRevision=latest.SOURCE,
        coreRevision=latest.CORE, roleBinaries=latest.ROLE_BINARIES,
        releaseQualified=False, recordingQualified=False,
        databaseClientRoles=list(MARTY_CLIENTS), requiresSeparateMaintenanceReview=True,
        migrationNames=list(MIGRATIONS), issuance0009LedgerCheckRequired=True,
        noHistoricalJobMutation=True, noAutomaticRollback=True,
        sqlFiles={name: dict(path=str(root / "scripts/sql" / name), sha256=digest)
                  for name, digest in latest.operational_sql_sources().items()})
    overlay.maintenance_contract(plan, latest.PROFILE)
    bad = deepcopy(plan)
    del bad["sqlFiles"]["passport-beta-fence-install.sql"]
    with pytest.raises(ValueError, match="EXISTING_FENCED_SQL_SEQUENCE_REQUIRED"):
        overlay.maintenance_contract(bad, latest.PROFILE)
    required = latest.migration_requirements()
    assert required["fencedSqlSha256"] == latest.operational_sql_sources()
    assert required["operationEvidence"] == "ORIGINAL_JOURNAL_RUST_PSQL_CATALOG_RECEIPTS_NOT_LEGACY_FENCE_DTO"
    assert required["applyEnabled"] is False
