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


def test_closed_python_export_resolves_lazy_operational_sql_import(tmp_path):
    import subprocess
    root = Path(__file__).resolve().parents[1]
    for name in rehearsal.OPERATOR_FILES:
        if name.endswith(".py"):
            target = tmp_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((root / name).read_bytes())
    code = "import sys;sys.path.insert(0,sys.argv[1]);from rehearse_native_schema_commands import operational_sql_sources;assert len(operational_sql_sources())==9"
    subprocess.run([sys.executable, "-I", "-c", code, str(tmp_path / "scripts")], check=True)


def test_cleanup_refuses_same_live_controller_before_any_command(tmp_path, monkeypatch):
    value = fixture(tmp_path)
    value.g["inputSha256"] = "a" * 64
    identity = {"pid": 123, "creationFileTime": 456, "running": True}
    monkeypatch.setattr(rehearsal, "process_identity", lambda pid: identity)
    value.command = lambda *args: pytest.fail("Live controller must block all Docker operations")
    with pytest.raises(ValueError, match="ORIGINAL_REHEARSAL_CONTROLLER_STILL_LIVE"):
        value.cleanup({"inputsSha256": "a" * 64, "controllerIdentity": identity}, "22222222-2222-4222-8222-222222222222")


def test_cleanup_effect_requires_fresh_exact_engine(tmp_path):
    value = fixture(tmp_path)
    calls = []
    value.command = lambda args: calls.append(args) or b"FOREIGN_ENGINE"
    with pytest.raises(ValueError, match="ENGINE_CHANGED"):
        value.cleanup_effect(["docker", "rm", "owned"])
    assert len(calls) == 1 and calls[0][1] == "info"


def test_cleanup_refuses_foreign_network_before_container_actions(tmp_path, monkeypatch):
    value = fixture(tmp_path)
    value.i["databaseNetwork"] = "marty-schema-rehearsal-" + value.fixture_run
    value.g.update(inputSha256="a" * 64, save=lambda *args: {})
    monkeypatch.setattr(rehearsal, "process_identity", lambda pid: None)
    calls = []
    def command(args):
        calls.append(args)
        if args[1] == "info":
            return rehearsal.ENGINE.encode()
        if args[1:3] == ["network", "ls"]:
            return b"a" * 64
        if args[1:3] == ["network", "inspect"]:
            return json.dumps([{"Name": value.i["databaseNetwork"], "Internal": True, "Labels": {"elevenid.owner": "foreign"}}]).encode()
        pytest.fail("Foreign network must block container actions")
    value.command = command
    with pytest.raises(ValueError, match="OWNED_NETWORK_RECONCILIATION_REFUSED"):
        value.cleanup({"inputsSha256": "a" * 64, "controllerIdentity": {"pid": 123, "creationFileTime": 456}, "state": {}}, "22222222-2222-4222-8222-222222222222")
    assert not any(args[1] in ("stop", "rm", "create", "start") for args in calls)


def test_actual_operator_arming_normalizes_only_unique_assignment():
    raw = Path(rehearsal.__file__).read_bytes()
    enabled = raw.replace(b"\nDISPATCH_ENABLED = False\n", b"\nDISPATCH_ENABLED = True\n", 1)
    assert enabled != raw and rehearsal.disabled_operator_source(enabled) == raw
    with pytest.raises(ValueError, match="ONLY_DISPATCH_FLAG_MAY_CHANGE"):
        rehearsal.disabled_operator_source(enabled + b"\nDISPATCH_ENABLED = True\n")


def test_cleanup_refuses_recreated_known_helper_generation(tmp_path):
    value = fixture(tmp_path)
    failure = {"state": {"pendingStage": "migrate-flow", "pendingContainerId": "a" * 64}}
    with pytest.raises(ValueError, match="KNOWN_HELPER_CID_CHANGED"):
        value.cleanup_generation("migrate-flow", "b" * 64, failure)
    value.cleanup_generation("migrate-flow", "a" * 64, failure)
    with pytest.raises(ValueError, match="NON_PENDING_HELPER"):
        value.cleanup_generation("bootstrap-flow", "a" * 64, failure)


def test_cleanup_refuses_extra_network_and_binds_created_default(tmp_path):
    value = fixture(tmp_path)
    value.i["databaseNetwork"] = "owned"
    value.network_id = "a" * 64
    row = {"NetworkSettings": {"Networks": {"owned": {"NetworkID": value.network_id}, "beta": {"NetworkID": "b" * 64}}},
           "State": {"Status": "running", "Running": True, "Pid": 123}}
    value.command = lambda *args: pytest.fail("Extra network must fail before network read/effect")
    with pytest.raises(ValueError, match="CLEANUP_EXTRA_OR_MISSING_NETWORK"):
        value.cleanup_network(row)
    del row["NetworkSettings"]["Networks"]["beta"]
    row["NetworkSettings"]["Networks"]["owned"]["NetworkID"] = ""
    with pytest.raises(ValueError, match="CLEANUP_NETWORK_ID_CHANGED"):
        value.cleanup_network(row)
    row["State"] = {"Status": "created", "Running": False, "Pid": 0}
    value.command = lambda args: json.dumps([{"Id": value.network_id, "Name": "owned", "Internal": True,
        "Labels": {"elevenid.owner": rehearsal.OWNER, "elevenid.run": value.fixture_run}}]).encode()
    value.cleanup_network(row)


@pytest.mark.parametrize("stdout,code,expected", [(b"4000000000", 0, "PHYSICAL_4GIB_REQUIRED"), (b"unknown", 1, "PHYSICAL_CAPACITY_UNKNOWN")])
def test_capacity_persists_actual_sample_before_refusal(monkeypatch, stdout, code, expected):
    from types import SimpleNamespace
    result = SimpleNamespace(stdout=stdout, stderr=b"bounded diagnostic", returncode=code,
        observation={"failures": [], "timedOut": False})
    monkeypatch.setattr(rehearsal, "bounded_run", lambda *args, **kwargs: result)
    saved = []
    context = {"env": {}, "save": lambda name, value: saved.append((name, value)) or {"sha256": "actual"}}
    with pytest.raises(ValueError, match=expected):
        rehearsal.capacity(context, {"executables": {"powershell": {"path": "not-executed"}}})
    assert len(saved) == 1 and saved[0][1]["stdout"] == stdout.decode()
    assert saved[0][1]["exitCode"] == code and saved[0][1]["requiredPhysicalBytes"] == 4294967296
    assert context["capacityObservation"] == {"sha256": "actual"}


def test_private_failure_diagnostic_retains_bounded_cause_without_locals():
    try:
        try:
            raise ValueError("EXACT_PRIVATE_REASON" + "x" * 5000)
        except ValueError as cause:
            raise RuntimeError("OUTER_REASON") from cause
    except RuntimeError as error:
        diagnostic = rehearsal.private_failure_diagnostic(error)
    assert diagnostic["privateOnly"] is True
    assert [row["errorClass"] for row in diagnostic["causes"]] == ["RuntimeError", "ValueError"]
    assert diagnostic["causes"][1]["message"].startswith("EXACT_PRIVATE_REASON")
    assert len(diagnostic["causes"][1]["message"]) == 2048
    assert all(set(frame) == {"file", "line", "function"} for row in diagnostic["causes"] for frame in row["frames"])


def test_private_exclusive_file_roundtrip_beyond_windows_max_path(tmp_path):
    import os
    parent = tmp_path
    while len(str(parent)) < 280:
        parent = parent / ("owned-private-" + "x" * 24)
    native = Path("\\\\?\\" + str(parent.absolute())) if os.name == "nt" else parent
    native.mkdir(parents=True)
    target = parent / "owned-receipt.json"
    bound = rehearsal.write_private_bytes(target, b"PRIVATE_SYNTHETIC_CONTROL")
    assert len(str(target)) > 260
    assert rehearsal.read_ref(bound).read_bytes() == b"PRIVATE_SYNTHETIC_CONTROL"
    with pytest.raises(FileExistsError):
        rehearsal.write_private_bytes(target, b"MUST_NOT_OVERWRITE")
    assert rehearsal.read_ref(bound).read_bytes() == b"PRIVATE_SYNTHETIC_CONTROL"


def test_explicit_recovery_preserves_resource_scope_and_sql_assets():
    from copy import deepcopy
    keys = ("schema", "runId", "privateRoot", "sourceRevision", "coreRevision", "postgresName", "databaseNetwork",
        "stageIds", "buildReceipt", "binaries", "executables", "dockerConfig", "dockerConfigFiles", "guardModules", "guardFiles", "migrationSetSha256")
    prior = {key: key for key in keys}
    prior.update(sqlSources={"fixed.sql": {"sha256": "a" * 64}}, migrationSources={"fixed.rs": {"sha256": "b" * 64}})
    inputs = deepcopy(prior)
    inputs["recoveryFrom"] = {"sha256": "old-input"}
    rehearsal.validate_recovery_scope(inputs, prior)
    inputs["runId"] = "different-resource-generation"
    with pytest.raises(ValueError, match="EXACT_FAILED_RESOURCE_SCOPE_REQUIRED"):
        rehearsal.validate_recovery_scope(inputs, prior)
    inputs["runId"] = prior["runId"]
    inputs["sqlSources"]["fixed.sql"]["sha256"] = "c" * 64
    with pytest.raises(ValueError, match="RECOVERY_SOURCE_ASSETS_CHANGED"):
        rehearsal.validate_recovery_scope(inputs, prior)
