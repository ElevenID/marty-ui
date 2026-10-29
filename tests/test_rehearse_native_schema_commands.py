"""Synthetic orchestration controls; no Docker, PG or beta qualification."""
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlsplit
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rehearse_native_schema_commands as rehearsal


def fixture(tmp_path):
    admin = tmp_path / "admin.url"
    admin.write_text("postgres://postgres:SYNTHETIC_PASSWORD@postgres/marty")
    from scoped_native_runtime import ref
    inputs = {"runId": "11111111-1111-4111-8111-111111111111", "binaries": {"flow": {}, "issuance-native": {}},
              "databaseAdminUrl": ref(admin)}
    return rehearsal.Rehearsal({"root": tmp_path}, inputs)


def test_fixture_never_claims_authoritative_journal_or_beta_profile(tmp_path):
    value = fixture(tmp_path)
    value.persist()
    assert value.state["schema"] == "marty.synthetic-native-schema-rehearsal/v1"
    assert value.state["betaDatabaseAccessed"] is False
    assert value.state["durableAuthorityClaimed"] is False
    assert value.state["sourceSqlBetaGuardSettingsAreSynthetic"] is True
    assert json.loads((tmp_path / "rehearsal-state.json").read_text())["durableAuthorityClaimed"] is False


def test_fixture_bootstrap_uses_same_cli_with_owned_app_role(tmp_path):
    value = fixture(tmp_path)
    value.bootstrap = True
    assert parse_qs(urlsplit(value.database_url("migrate")).query) == {"options[role]": ["marty"]}
    value.bootstrap = False
    assert parse_qs(urlsplit(value.database_url("migrate")).query) == {"options[role]": ["postgres"]}
    assert parse_qs(urlsplit(value.database_url("verify-owned-schema")).query) == {"options[role]": ["marty"]}


def test_beta_postgres_is_refused_before_container_inspection(tmp_path):
    value = fixture(tmp_path)
    value.pg_cid = "f37ec29f5810b5ec0564ed47658c092eb73ed68496044d155ea75549a375745d"
    value.i["databaseNetwork"] = "marty-schema-rehearsal-" + value.fixture_run
    calls = []
    value.command = lambda args: calls.append(args) or (rehearsal.ENGINE + "\n").encode()
    with pytest.raises(ValueError, match="OWNED_FIXTURE_NOT_STARTED"):
        value.guard()
    assert len(calls) == 1 and calls[0][1] == "info"


def test_expected_negative_requires_actual_acl_reason_not_generic_exit1(tmp_path):
    value = fixture(tmp_path)
    value.state["pendingContainerId"] = "a" * 64
    value.command_index = 7
    value.stage_intent = lambda name: setattr(value, "stage", name)
    (tmp_path / "negative-database-command-7.stderr").write_text("password authentication failed")
    def failure(*args):
        raise ValueError("DATABASE_COMMAND_NONZERO_RECONCILE")
    value.schema = failure
    value.validate_schema = lambda *args, **kwargs: pytest.fail("Wrong-cause failure must not be relabeled/retired as an expected rejection")
    with pytest.raises(ValueError, match="EXPECTED_ACL_OR_ROLE_DENIAL_NOT_OBSERVED"):
        value.schema_stage("negative", "issuance-native", "verify-owned-schema", expect_failure=True)


def test_rehearsal_is_not_armed_and_stages_are_exact():
    assert rehearsal.DISPATCH_ENABLED is False
    assert len(set(rehearsal.STAGES)) == len(rehearsal.STAGES) == 17
    assert "reject-flow-before-acl" in rehearsal.STAGES and "reject-admin-issuer" in rehearsal.STAGES


def test_rehearsal_business_sql_asset_paths_exist_in_actual_source():
    root = Path(__file__).resolve().parents[1]
    assert len(rehearsal.MIGRATION_FILES) == 3
    assert all((root / name).is_file() for name in rehearsal.MIGRATION_FILES)
