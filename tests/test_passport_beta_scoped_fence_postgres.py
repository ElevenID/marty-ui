"""Exercise the beta passport fence in an isolated, throwaway PostgreSQL container."""

from __future__ import annotations

import os
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid

import pytest

from scripts.probe_passport_beta_fence_direct_writes import (
    FenceProbeError, candidate_sql, probe_direct_writes, unrelated_sql,
)
from scripts.prepare_passport_beta_native_migrations import (
    build_sql, migration_set_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "tests/fixtures/passport-beta-fence-schema.sql"
INSTALL = ROOT / "scripts/sql/passport-beta-fence-install.sql"
DRAIN = ROOT / "scripts/sql/passport-beta-fence-drain.sql"
VERIFY = ROOT / "scripts/sql/passport-beta-fence-verify.sql"
FINALIZE_BATCH_ACL = ROOT / "scripts/sql/passport-beta-batch-acl-finalize.sql"
START_MAINTENANCE = ROOT / "scripts/sql/passport-beta-db-maintenance-start.sql"
ENABLE_APP_LOGIN = ROOT / "scripts/sql/passport-beta-db-enable-app-login.sql"
RUST_OWNER_TRANSITION = ROOT / "scripts/sql/passport-beta-rust-owner-transition.sql"
RUST_OWNER_VERIFY = ROOT / "scripts/sql/passport-beta-rust-owner-verify.sql"
SUBMISSION_INTENT_MIGRATION = ROOT / "rust/services/issuance/migrations/0004_passport_submission_intent.sql"
POSTGRES_IMAGE = "postgres:15-alpine@sha256:fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c"


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=90
    )


def sql(container: str, query: str, *, allowed: bool = True) -> str:
    result = docker(
        "exec", container, "psql", "-U", "postgres", "-d", "marty",
        "-v", "ON_ERROR_STOP=1", "-At", "-c", query, check=False,
    )
    if allowed and result.returncode != 0:
        pytest.fail(f"SQL unexpectedly failed: {result.stderr}")
    if not allowed and result.returncode == 0:
        pytest.fail(f"SQL unexpectedly succeeded: {query}")
    return result.stdout if allowed else result.stderr


def script_args(
    container: str, path: Path, *, attested: bool = True,
    migration_digest: str | None = None,
) -> list[str]:
    docker("cp", str(path), f"{container}:/tmp/{path.name}")
    if path == INSTALL:
        docker("cp", str(DRAIN), f"{container}:/tmp/{DRAIN.name}")
    if path == RUST_OWNER_TRANSITION:
        docker("cp", str(DRAIN), f"{container}:/tmp/{DRAIN.name}")
        docker("cp", str(VERIFY), f"{container}:/tmp/{VERIFY.name}")
        docker("cp", str(RUST_OWNER_VERIFY), f"{container}:/tmp/{RUST_OWNER_VERIFY.name}")
    target = []
    if attested:
        system_id = sql(container, "SELECT system_identifier FROM pg_control_system()").strip()
        database_oid = sql(
            container, "SELECT oid FROM pg_database WHERE datname='marty'"
        ).strip()
        target = [
            "-c", "SET marty.passport_beta_verified_project = 'elevenid-beta'",
            "-c", f"SET marty.passport_beta_expected_system_identifier = '{system_id}'",
            "-c", f"SET marty.passport_beta_expected_database_oid = '{database_oid}'",
        ]
        if path in (FINALIZE_BATCH_ACL, START_MAINTENANCE, ENABLE_APP_LOGIN,
                    RUST_OWNER_TRANSITION, RUST_OWNER_VERIFY):
            epoch = sql(container, "SELECT epoch FROM passport_cutover.state").strip()
            target += [
                "-c", f"SET marty.passport_beta_expected_fence_epoch = '{epoch}'",
            ]
        if path in (ENABLE_APP_LOGIN, RUST_OWNER_TRANSITION):
            target += [
                "-c", "SET marty.passport_beta_expected_source_commit = '" + "b" * 40 + "'",
                "-c", "SET marty.passport_beta_expected_native_migration_sha256 = '"
                      + (migration_digest or migration_set_sha256((("disposable.sql", b"SELECT 1;\n"),))) + "'",
            ]
        if path == RUST_OWNER_VERIFY:
            marker = sql(container, "SELECT transition_txid FROM passport_cutover.state").strip()
            target += [
                "-c", f"SET marty.passport_beta_expected_transition_txid = '{marker}'",
            ]
    return [
        "exec", container, "psql", "-U", "postgres", "-d", "marty",
        "-qAt", "-v", "ON_ERROR_STOP=1", *target,
        "-f", f"/tmp/{path.name}",
    ]


def script(
    container: str, path: Path, *, attested: bool = True,
    migration_digest: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return docker(*script_args(container, path, attested=attested,
                               migration_digest=migration_digest), check=False)


@pytest.fixture
def database():
    if os.getenv("BETA_FENCE_DISPOSABLE_DOCKER") != "1":
        pytest.skip("set BETA_FENCE_DISPOSABLE_DOCKER=1 for isolated PostgreSQL checks")
    name = f"marty-passport-fence-test-{uuid.uuid4().hex[:12]}"
    docker(
        "run", "--rm", "-d", "--name", name, "--network", "none",
        "-e", "POSTGRES_PASSWORD=disposable-only", POSTGRES_IMAGE,
    )
    try:
        for _ in range(60):
            if docker(
                "exec", name, "psql", "-U", "postgres", "-d", "postgres",
                "-At", "-c", "SELECT 1", check=False,
            ).returncode == 0:
                break
            time.sleep(0.25)
        else:
            pytest.fail("disposable PostgreSQL did not become ready")
        # The image briefly runs a bootstrap postmaster before starting the
        # durable server. A successful SELECT during bootstrap is not enough.
        for _ in range(60):
            created = docker(
                "exec", name, "psql", "-U", "postgres", "-d", "postgres",
                "-v", "ON_ERROR_STOP=1", "-c", "CREATE ROLE marty LOGIN;",
                check=False,
            )
            if created.returncode == 0:
                break
            if created.returncode != 2:
                pytest.fail(f"could not create disposable role: {created.stderr}")
            time.sleep(0.25)
        else:
            pytest.fail("disposable PostgreSQL did not finish bootstrap")
        for _ in range(60):
            created_db = docker(
                "exec", name, "createdb", "-U", "postgres", "-O", "marty", "marty",
                check=False,
            )
            if created_db.returncode == 0:
                break
            if "could not connect" not in created_db.stderr and "connection" not in created_db.stderr:
                pytest.fail(f"could not create disposable database: {created_db.stderr}")
            time.sleep(0.25)
        else:
            pytest.fail("disposable PostgreSQL did not finish startup")
        assert script(name, SCHEMA).returncode == 0
        yield name
    finally:
        docker("stop", name, check=False)


def test_batch_acl_finalizer_requires_exact_fence_and_grants_app_access(database: str):
    installed = script(database, INSTALL)
    assert installed.returncode == 0, installed.stderr
    sql(database, """
        CREATE TABLE issuance_service.passport_beta_batch_intents (
            batch_id uuid PRIMARY KEY
        )
    """)
    missing_target = script(database, FINALIZE_BATCH_ACL, attested=False)
    assert missing_target.returncode != 0
    assert "lacks exact fenced beta target" in missing_target.stderr
    assert sql(database, """
        SELECT pg_get_userbyid(relowner)
        FROM pg_class
        WHERE oid='issuance_service.passport_beta_batch_intents'::regclass
    """).strip() == "postgres"

    wrong_epoch = script_args(database, FINALIZE_BATCH_ACL)
    wrong_epoch = [
        arg.replace("SET marty.passport_beta_expected_fence_epoch = '",
                    "SET marty.passport_beta_expected_fence_epoch = '0")
        if arg.startswith("SET marty.passport_beta_expected_fence_epoch = '") else arg
        for arg in wrong_epoch
    ]
    refused = docker(*wrong_epoch, check=False)
    assert refused.returncode != 0
    assert "lacks exact fenced beta target" in refused.stderr

    active_login = script(database, FINALIZE_BATCH_ACL)
    assert active_login.returncode != 0
    assert "lacks exact fenced beta target" in active_login.stderr
    sql(database, "ALTER ROLE marty NOLOGIN")
    finalized = script(database, FINALIZE_BATCH_ACL)
    assert finalized.returncode == 0, finalized.stderr
    assert sql(database, """
        SELECT pg_get_userbyid(relowner) || ':' ||
               has_table_privilege('marty',oid,'SELECT') || ':' ||
               has_table_privilege('marty',oid,'INSERT') || ':' ||
               has_table_privilege('marty',oid,'UPDATE') || ':' ||
               has_table_privilege('marty',oid,'DELETE') || ':' ||
               has_table_privilege('marty',oid,'TRUNCATE,TRIGGER')
        FROM pg_class
        WHERE oid='issuance_service.passport_beta_batch_intents'::regclass
    """).strip() == "marty_passport_fence_owner:true:true:true:true:false"
    assert script(database, VERIFY).returncode == 0


def test_maintenance_start_requires_fence_and_drains_existing_login(database: str):
    unfenced = script(database, START_MAINTENANCE, attested=False)
    assert unfenced.returncode != 0
    assert sql(database, "SELECT rolcanlogin FROM pg_roles WHERE rolname='marty'").strip() == "t"

    installed = script(database, INSTALL)
    assert installed.returncode == 0, installed.stderr
    missing_target = script(database, START_MAINTENANCE, attested=False)
    assert missing_target.returncode != 0
    assert "lacks exact fenced beta target" in missing_target.stderr
    assert sql(database, "SELECT rolcanlogin FROM pg_roles WHERE rolname='marty'").strip() == "t"

    idle_client = subprocess.Popen(
        ["docker", "exec", "-i", database, "psql", "-U", "marty", "-d", "marty",
         "-v", "ON_ERROR_STOP=1", "-At"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )
    try:
        for _ in range(40):
            if sql(database, "SELECT count(*) FROM pg_stat_activity "
                             "WHERE usename='marty' AND state='idle'").strip() == "1":
                break
            time.sleep(0.1)
        else:
            pytest.fail("disposable marty session did not open")
        started = script(database, START_MAINTENANCE)
        assert started.returncode == 0, started.stderr
        assert sql(database, "SELECT rolcanlogin FROM pg_roles WHERE rolname='marty'").strip() == "f"
        assert sql(database, "SELECT count(*) FROM pg_stat_activity "
                             "WHERE usename='marty'").strip() == "0"
        assert script(database, VERIFY).returncode == 0
        _out, err = idle_client.communicate("SELECT 1;\n", timeout=10)
        assert idle_client.returncode != 0
        assert "server closed the connection" in err
        retried = script(database, START_MAINTENANCE)
        assert retried.returncode == 0, retried.stderr
    finally:
        if idle_client.poll() is None:
            idle_client.terminate()
        idle_client.communicate(timeout=10)


def test_maintenance_start_refuses_active_session_without_disabling_login(database: str):
    installed = script(database, INSTALL)
    assert installed.returncode == 0, installed.stderr
    sleeper = subprocess.Popen(
        ["docker", "exec", database, "psql", "-U", "marty", "-d", "marty",
         "-v", "ON_ERROR_STOP=1", "-c", "SELECT pg_sleep(30)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        for _ in range(40):
            if sql(database, "SELECT count(*) FROM pg_stat_activity "
                             "WHERE usename='marty' AND state='active'").strip() == "1":
                break
            time.sleep(0.1)
        else:
            pytest.fail("disposable active marty session did not open")
        refused = script(database, START_MAINTENANCE)
        assert refused.returncode != 0
        assert "lacks exact fenced beta target" in refused.stderr
        assert sql(database, "SELECT rolcanlogin FROM pg_roles WHERE rolname='marty'").strip() == "t"
    finally:
        if sleeper.poll() is None:
            sleeper.terminate()
        sleeper.communicate(timeout=10)


def test_maintenance_start_rejects_role_membership_without_disabling_login(database: str):
    installed = script(database, INSTALL)
    assert installed.returncode == 0, installed.stderr
    sql(database, "CREATE ROLE disposable_member LOGIN")
    sql(database, "GRANT marty TO disposable_member")
    refused = script(database, START_MAINTENANCE)
    assert refused.returncode != 0
    assert "lacks exact fenced beta target" in refused.stderr
    assert sql(database, "SELECT rolcanlogin FROM pg_roles WHERE rolname='marty'").strip() == "t"


def test_app_login_requires_finalized_batch_access_and_drained_sessions(
    database: str, tmp_path: Path,
):
    assert script(database, INSTALL).returncode == 0
    assert script(database, START_MAINTENANCE).returncode == 0
    sql(database, """
        CREATE TABLE issuance_service.passport_beta_batch_intents (
            batch_id uuid PRIMARY KEY
        )
    """)
    premature = script(database, ENABLE_APP_LOGIN)
    assert premature.returncode != 0
    assert "lacks committed native migrations" in premature.stderr
    assert sql(database, "SELECT rolcanlogin FROM pg_roles WHERE rolname='marty'").strip() == "f"
    assert script(database, FINALIZE_BATCH_ACL).returncode == 0
    missing_native = script(database, ENABLE_APP_LOGIN)
    assert missing_native.returncode != 0
    assert "lacks committed native migrations" in missing_native.stderr
    target = {
        "system_id": sql(database, "SELECT system_identifier FROM pg_control_system()").strip(),
        "database_oid": sql(database, "SELECT oid FROM pg_database WHERE datname='marty'").strip(),
        "fence_epoch": sql(database, "SELECT epoch FROM passport_cutover.state").strip(),
    }
    disposable_bundle = build_sql(target, (("disposable.sql", b"SELECT 1;\n"),), "b" * 40)
    payload = tmp_path / "passport-beta-disposable-native-marker.sql"
    payload.write_bytes(disposable_bundle)
    native = script(database, payload)
    assert native.returncode == 0, native.stderr
    missing_target = script(database, ENABLE_APP_LOGIN, attested=False)
    assert missing_target.returncode != 0
    assert "lacks exact drained beta target" in missing_target.stderr
    opened = script(database, ENABLE_APP_LOGIN)
    assert opened.returncode == 0, opened.stderr
    assert sql(database, "SELECT rolcanlogin FROM pg_roles WHERE rolname='marty'").strip() == "t"
    assert script(database, VERIFY).returncode == 0
    repeated = script(database, ENABLE_APP_LOGIN)
    assert repeated.returncode == 0, repeated.stderr


def test_rust_owner_transition_preserves_fence_epoch_and_guarded_ddl(
    database: str, tmp_path: Path,
):
    sql(database, """
        SET ROLE marty;
        CREATE FUNCTION issuance_service.guard_physical_document_submission_intent()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$
    """)
    assert script(database, INSTALL).returncode == 0
    assert script(database, START_MAINTENANCE).returncode == 0
    sql(database, "CREATE TABLE issuance_service.passport_beta_batch_intents (batch_id uuid PRIMARY KEY)")
    assert script(database, FINALIZE_BATCH_ACL).returncode == 0
    target = {
        "system_id": sql(database, "SELECT system_identifier FROM pg_control_system()").strip(),
        "database_oid": sql(database, "SELECT oid FROM pg_database WHERE datname='marty'").strip(),
        "fence_epoch": sql(database, "SELECT epoch FROM passport_cutover.state").strip(),
    }
    migrations = (("0004_passport_submission_intent.sql", SUBMISSION_INTENT_MIGRATION.read_bytes()),)
    digest = migration_set_sha256(migrations)
    marker = tmp_path / "rust-owner-native-marker.sql"
    marker.write_bytes(build_sql(target, migrations, "b" * 40))
    assert script(database, marker).returncode == 0
    assert sql(database, """
        SELECT pg_get_userbyid(proowner) FROM pg_proc
        WHERE oid='issuance_service.guard_physical_document_submission_intent()'::regprocedure
    """) == "marty\n"
    assert script(database, ENABLE_APP_LOGIN, migration_digest=digest).returncode == 0
    sql(database, """
        CREATE OR REPLACE FUNCTION issuance_service.guard_physical_document_submission_intent()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$
    """)
    weak_guard = script(database, RUST_OWNER_TRANSITION, migration_digest=digest)
    assert weak_guard.returncode != 0
    assert "trigger inventory changed" in weak_guard.stderr
    assert sql(database, "SELECT phase FROM passport_cutover.state") == "fully_fenced\n"
    assert sql(database, """
        SELECT pg_get_userbyid(proowner) FROM pg_proc
        WHERE oid='issuance_service.guard_physical_document_submission_intent()'::regprocedure
    """) == "marty\n"
    assert script(database, SUBMISSION_INTENT_MIGRATION).returncode == 0
    candidate = candidate_sql("d" * 32)
    for statement in candidate.values():
        sql(database, f"SET ROLE marty; BEGIN; {statement}; ROLLBACK;", allowed=False)
    missing_target = script(database, RUST_OWNER_TRANSITION, attested=False,
                            migration_digest=digest)
    assert missing_target.returncode != 0
    assert "lacks exact beta target" in missing_target.stderr
    assert sql(database, "SELECT phase FROM passport_cutover.state") == "fully_fenced\n"
    transitioned = script(database, RUST_OWNER_TRANSITION, migration_digest=digest)
    assert transitioned.returncode == 0, transitioned.stderr
    receipt = json.loads(transitioned.stdout.splitlines()[-1])
    assert receipt["schema"] == "marty.passport-beta-rust-owner-transition/v1"
    assert receipt["phase"] == "rust_owner"
    assert receipt["fence_epoch"] == int(target["fence_epoch"])
    assert receipt["transition_txid"] > receipt["fence_epoch"]
    assert sql(database, """
        SELECT pg_get_userbyid(proowner) FROM pg_proc
        WHERE oid='issuance_service.guard_physical_document_submission_intent()'::regprocedure
    """) == "marty_passport_fence_owner\n"
    assert sql(database, "SELECT epoch FROM passport_cutover.state").strip() == target["fence_epoch"]
    assert script(database, RUST_OWNER_VERIFY).returncode == 0
    assert script(database, RUST_OWNER_VERIFY, attested=False).returncode != 0
    sql(database, "DROP TRIGGER trg_physical_document_submission_intent ON issuance_service.physical_document_jobs")
    missing_intent = script(database, RUST_OWNER_VERIFY)
    assert missing_intent.returncode != 0
    assert "trigger inventory changed" in missing_intent.stderr
    sql(database, """
        CREATE TRIGGER trg_physical_document_submission_intent
        BEFORE UPDATE ON issuance_service.physical_document_jobs
        FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_physical_document_submission_intent()
    """)
    assert script(database, RUST_OWNER_VERIFY).returncode == 0
    for statement in candidate.values():
        sql(database, f"SET ROLE marty; BEGIN; {statement}; ROLLBACK;")
    sql(database, "SET ROLE marty; TRUNCATE issuance_service.physical_document_jobs CASCADE", allowed=False)
    sql(database, "SET ROLE marty; ALTER TABLE issuance_service.physical_document_jobs DISABLE TRIGGER passport_fence_job", allowed=False)
    assert script(database, RUST_OWNER_TRANSITION, migration_digest=digest).returncode != 0
    assert sql(database, "SELECT phase FROM passport_cutover.state") == "rust_owner\n"
    sql(database, "ALTER TABLE passport_cutover.state DROP CONSTRAINT state_transition_shape_check")
    drifted = script(database, RUST_OWNER_VERIFY)
    assert drifted.returncode != 0
    assert "state constraint changed" in drifted.stderr


def test_scoped_fence_and_drain(database: str):
    # In-flight passport work must finish before the atomic full fence installs.
    sql(database, """
        INSERT INTO issuance_service.physical_document_jobs
            (id, organization_id, flow_execution_id, application_id,
             application_template_id, credential_template_id,
             delivery_destination_profile_id, document_type, country_code,
             status, secure_artifact_ciphertext, secure_artifact_reference,
             created_at, updated_at)
        VALUES ('job', 'org', 'flow', 'application', 'application-template',
            'credential-template', 'destination', 'P', 'USA', 'SUBMITTED',
            '{"schema":"marty.passport-artifact-manifest/v1","chunks":["vault:v1:chunk"]}',
            'physical-artifact://job', clock_timestamp(), clock_timestamp());
        INSERT INTO flow_service.flow_definitions (id, flow_type)
        VALUES ('physical', 'physical_document_issuance');
        INSERT INTO flow_service.flow_instances
            (id, flow_definition_id, organization_id, context, status)
        VALUES ('physical-instance', 'physical', 'org', '{}', 'in_progress');
    """)
    unverified = script(database, INSTALL, attested=False)
    assert unverified.returncode != 0 and "exact beta target attestation" in unverified.stderr
    pending = script(database, INSTALL)
    assert pending.returncode != 0 and "drain is not empty" in pending.stderr
    assert sql(database, "SELECT to_regnamespace('passport_cutover') IS NULL") == "t\n"

    sql(database, """
        UPDATE issuance_service.physical_document_jobs
        SET status='ACTIVE', sod_sha256=repeat('a',64), bureau_job_id='bureau-1',
            tracking_number='track-1', quality_result='{"passed":true}',
            completed_at=clock_timestamp() WHERE id='job';
        UPDATE flow_service.flow_instances
        SET status='completed', completed_at=clock_timestamp(),
            state_history='[{"event":"completed"}]'
        WHERE id='physical-instance';
    """)
    sql(database, "UPDATE issuance_service.physical_document_jobs SET secure_artifact_ciphertext='legacy' WHERE id='job'")
    legacy = script(database, INSTALL)
    assert legacy.returncode != 0 and "artifacts 1" in legacy.stderr
    sql(database, """
        UPDATE issuance_service.physical_document_jobs
        SET secure_artifact_ciphertext=
            '{"schema":"marty.passport-artifact-manifest/v1","chunks":["vault:v1:chunk"]}'
        WHERE id='job';
        INSERT INTO flow_service.flow_instances
            (id, flow_definition_id, organization_id, context, status)
        VALUES ('orphan', 'missing-definition', 'org', '{}', 'in_progress');
    """)
    orphan = script(database, INSTALL)
    assert orphan.returncode != 0 and "flows 1" in orphan.stderr
    sql(database, "UPDATE flow_service.flow_instances SET status='cancelled' WHERE id='orphan'")
    installed = script(database, INSTALL)
    assert installed.returncode == 0, installed.stderr
    assert sql(database, "SELECT phase FROM passport_cutover.state") == "fully_fenced\n"
    assert sql(database, """
        SELECT rolcanlogin::text || '|' || rolinherit::text || '|' ||
               rolsuper::text || '|' || rolcreaterole::text || '|' ||
               rolcreatedb::text || '|' || rolbypassrls::text
        FROM pg_roles WHERE rolname='marty_beta_migrator'
    """) == "false|false|false|false|false|false\n"
    assert sql(database, """
        SELECT count(*) FROM pg_auth_members
        WHERE roleid='marty_beta_migrator'::regrole
           OR member='marty_beta_migrator'::regrole
    """) == "0\n"

    for statement in (
        "INSERT INTO issuance_service.physical_document_jobs (id,organization_id,flow_execution_id,application_id,application_template_id,credential_template_id,delivery_destination_profile_id,document_type,country_code,status,secure_artifact_ciphertext,secure_artifact_reference,created_at,updated_at) VALUES ('new','org','flow-new','application-new','app-template','credential-template','destination','P','USA','DRAFT','{}','physical-artifact://new',clock_timestamp(),clock_timestamp())",
        "INSERT INTO flow_service.flow_definitions (id,flow_type) VALUES ('new-physical','physical_document_issuance')",
        "INSERT INTO flow_service.flow_instances (id,flow_definition_id,organization_id,context,status) VALUES ('new-physical','physical','org','{}','created')",
        "UPDATE flow_service.flow_definitions SET flow_type='physical_document_issuance' WHERE id='ordinary'",
        "TRUNCATE issuance_service.physical_document_jobs CASCADE",
        "ALTER TABLE issuance_service.physical_document_jobs DISABLE TRIGGER passport_fence_job",
        "DROP SCHEMA flow_service CASCADE",
        "UPDATE passport_cutover.state SET phase='fully_fenced'",
    ):
        if "WHERE id='ordinary'" in statement:
            sql(database, "INSERT INTO flow_service.flow_definitions (id,flow_type) VALUES ('ordinary','verification')")
        sql(database, f"SET ROLE marty; {statement}", allowed=False)

    # Existing evidence is immutable after the full fence.
    sql(database, "SET ROLE marty; UPDATE issuance_service.physical_document_jobs SET secure_artifact_ciphertext='{}' WHERE id='job'", allowed=False)
    sql(database, "SET ROLE marty; UPDATE issuance_service.physical_document_jobs SET status='FAILED' WHERE id='job'", allowed=False)
    sql(database, "SET ROLE marty; UPDATE flow_service.flow_instances SET status='completed', context='{}', step_history='[]', state_history='[]' WHERE id='physical-instance'", allowed=False)
    second_install = script(database, INSTALL)
    assert second_install.returncode != 0
    sql(database, "SET ROLE marty; INSERT INTO issuance_service.other_issuance VALUES ('unrelated','ready')")
    sql(database, "SET ROLE marty; INSERT INTO flow_service.flow_instances (id,flow_definition_id,organization_id,context,status) VALUES ('unrelated','ordinary','org','{}','in_progress')")
    assert sql(database, "SELECT count(*) FROM issuance_service.physical_document_jobs") == "1\n"
    assert sql(database, "SELECT count(*) FROM flow_service.flow_instances") == "3\n"
    unbound_verify = script(database, VERIFY, attested=False)
    assert unbound_verify.returncode != 0 and "target attestation" in unbound_verify.stderr
    verified = script(database, VERIFY)
    assert verified.returncode == 0, verified.stderr
    receipt = json.loads(verified.stdout.splitlines()[-1])
    assert receipt["schema"] == "marty.passport-beta-fence-verification/v1"
    assert receipt["phase"] == "fully_fenced"
    assert receipt["epoch"] > 0
    assert len(receipt["functions_md5"]) == 7
    sql(database, "ALTER TABLE issuance_service.physical_document_jobs DISABLE TRIGGER passport_fence_job")
    drifted = script(database, VERIFY)
    assert drifted.returncode != 0 and "trigger changed" in drifted.stderr
    sql(database, """
        DROP TRIGGER passport_fence_job ON issuance_service.physical_document_jobs;
        CREATE TRIGGER passport_fence_job BEFORE DELETE
            ON issuance_service.physical_document_jobs FOR EACH ROW
            EXECUTE FUNCTION passport_cutover.guard_job();
        ALTER TABLE issuance_service.physical_document_jobs
            ENABLE ALWAYS TRIGGER passport_fence_job;
    """)
    narrowed = script(database, VERIFY)
    assert narrowed.returncode != 0 and "trigger changed" in narrowed.stderr


def test_verifier_rejects_replaced_guard_body(database: str):
    assert script(database, INSTALL).returncode == 0
    assert script(database, VERIFY).returncode == 0
    sql(database, """
        CREATE OR REPLACE FUNCTION passport_cutover.guard_job()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog AS $body$
        BEGIN RETURN NEW; END
        $body$;
    """)
    changed = script(database, VERIFY)
    assert changed.returncode != 0 and "function owner or security mode changed" in changed.stderr


def test_verifier_rejects_companion_and_column_limited_triggers(database: str):
    assert script(database, INSTALL).returncode == 0
    sql(database, """
        CREATE FUNCTION flow_service.test_mutate_context()
        RETURNS trigger LANGUAGE plpgsql AS $body$
        BEGIN NEW.context = '{"physical_document_job":{}}'; RETURN NEW; END
        $body$;
        CREATE TRIGGER zzz_mark_physical BEFORE INSERT OR UPDATE
            ON flow_service.flow_instances FOR EACH ROW
            EXECUTE FUNCTION flow_service.test_mutate_context();
    """)
    extra = script(database, VERIFY)
    assert extra.returncode != 0 and "trigger inventory changed" in extra.stderr
    sql(database, """
        DROP TRIGGER zzz_mark_physical ON flow_service.flow_instances;
        DROP TRIGGER passport_fence_instance ON flow_service.flow_instances;
        CREATE TRIGGER passport_fence_instance
            BEFORE INSERT OR UPDATE OF context OR DELETE
            ON flow_service.flow_instances FOR EACH ROW
            EXECUTE FUNCTION passport_cutover.guard_instance();
        ALTER TABLE flow_service.flow_instances
            ENABLE ALWAYS TRIGGER passport_fence_instance;
    """)
    narrowed = script(database, VERIFY)
    assert narrowed.returncode != 0 and "trigger changed" in narrowed.stderr


def test_verifier_rejects_app_role_escalation(database: str):
    assert script(database, INSTALL).returncode == 0
    sql(database, "ALTER ROLE marty CREATEROLE")
    privileged = script(database, VERIFY)
    assert privileged.returncode != 0 and "ownership or app ACL changed" in privileged.stderr


def test_verifier_rejects_rogue_superuser(database: str):
    assert script(database, INSTALL).returncode == 0
    sql(database, "CREATE ROLE rogue_beta_writer LOGIN SUPERUSER")
    result = script(database, VERIFY)
    assert result.returncode != 0 and "unexpected passport writer role" in result.stderr


def test_verifier_rejects_noinherit_writer_membership(database: str):
    assert script(database, INSTALL).returncode == 0
    sql(database, """
        CREATE ROLE hidden_writer NOLOGIN;
        ALTER ROLE marty NOINHERIT;
        GRANT TRIGGER ON flow_service.flow_instances TO hidden_writer;
        GRANT hidden_writer TO marty;
    """)
    assert sql(database, """
        SELECT has_table_privilege('marty', 'flow_service.flow_instances', 'TRIGGER')
    """) == "f\n"
    result = script(database, VERIFY)
    assert result.returncode != 0 and "role attributes or memberships changed" in result.stderr


def test_one_shot_migration_role_preserves_fence_at_rest(
    database: str, tmp_path: Path,
):
    assert script(database, INSTALL).returncode == 0
    sql(database, """
        SET ROLE marty;
        ALTER TABLE flow_service.flow_instances ADD COLUMN migration_probe text;
    """, allowed=False)
    container_id = docker("inspect", database, "--format", "{{.Id}}").stdout.strip()
    system_id = sql(database, "SELECT system_identifier FROM pg_control_system()").strip()
    database_oid = sql(database, "SELECT oid FROM pg_database WHERE datname='marty'").strip()
    mutation_marker = tmp_path / "beta-mutation.pending"
    fence_marker = tmp_path / "passport-fence.pending"
    mutation_marker.write_text("test", encoding="utf-8")
    fence_marker.write_text("test", encoding="utf-8")
    lease_file = ROOT / "scripts/beta-passport-migration-lease.ps1"
    escaped_lease_file = str(lease_file).replace("'", "''")
    def lease(verb: str) -> None:
        code = f"""
            $ErrorActionPreference = 'Stop'
            . '{escaped_lease_file}'
            function Get-BetaMutationMarkerPath {{ return $env:BETA_TEST_MUTATION_MARKER }}
            function Get-BetaPassportFenceMarkerPath {{ return $env:BETA_TEST_FENCE_MARKER }}
            {verb}-BetaPassportMigrationLease `
                -PostgresContainer $env:BETA_TEST_CONTAINER `
                -SystemIdentifier $env:BETA_TEST_SYSTEM_ID `
                -DatabaseOid $env:BETA_TEST_DATABASE_OID `
                -TemporaryPassword $env:BETA_TEST_PASSWORD
        """
        # Stop does not take a password; PowerShell parameter binding must not
        # quietly accept one the cleanup function did not request.
        if verb == "Stop":
            code = code.replace("`\n                -TemporaryPassword $env:BETA_TEST_PASSWORD", "")
        env = {**os.environ,
               "BETA_TEST_MUTATION_MARKER": str(mutation_marker),
               "BETA_TEST_FENCE_MARKER": str(fence_marker),
               "BETA_TEST_CONTAINER": container_id,
               "BETA_TEST_SYSTEM_ID": system_id,
               "BETA_TEST_DATABASE_OID": database_oid,
               "BETA_TEST_PASSWORD": "a" * 64}
        shell = shutil.which("pwsh") or shutil.which("powershell")
        assert shell is not None, "PowerShell is required for migration lease proof"
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", code],
            capture_output=True, text=True, timeout=30, env=env,
        )
        assert result.returncode == 0, result.stderr

    lease("Start")
    active = script(database, VERIFY)
    assert active.returncode != 0 and "role attributes or memberships changed" in active.stderr
    migration = docker(
        "exec", database, "psql", "-U", "marty_beta_migrator", "-d", "marty",
        "-v", "ON_ERROR_STOP=1", "-c", """
            CREATE SCHEMA IF NOT EXISTS issuance_service;
            CREATE TABLE public.migration_probe (id text PRIMARY KEY);
            GRANT SELECT, INSERT, UPDATE, DELETE ON public.migration_probe TO marty;
        """, check=False,
    )
    assert migration.returncode == 0, migration.stderr
    denied_guarded_ddl = docker(
        "exec", database, "psql", "-U", "marty_beta_migrator", "-d", "marty",
        "-v", "ON_ERROR_STOP=1", "-c", """
            ALTER TABLE flow_service.flow_instances ADD COLUMN migration_probe text;
        """, check=False,
    )
    assert denied_guarded_ddl.returncode != 0
    denied_guard_role = docker(
        "exec", database, "psql", "-U", "marty_beta_migrator", "-d", "marty",
        "-v", "ON_ERROR_STOP=1", "-c", "SET ROLE marty_passport_fence_owner",
        check=False,
    )
    assert denied_guard_role.returncode != 0
    lingering = subprocess.Popen(
        ["docker", "exec", database, "psql", "-U", "marty_beta_migrator",
         "-d", "marty", "-c", "SELECT pg_sleep(30)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        for _ in range(80):
            if sql(database, """
                SELECT count(*) FROM pg_stat_activity
                WHERE usename='marty_beta_migrator' AND wait_event='PgSleep'
            """).strip() == "1":
                break
            time.sleep(0.025)
        else:
            pytest.fail("migration role session did not become active")
        lease("Stop")
        lingering.communicate(timeout=5)
        assert lingering.returncode != 0
    finally:
        if lingering.poll() is None:
            lingering.terminate()
            lingering.communicate(timeout=5)
    verified = script(database, VERIFY)
    assert verified.returncode == 0, verified.stderr
    sql(database, "SET ROLE marty; INSERT INTO public.migration_probe VALUES ('available')")
    assert sql(database, """
        SELECT rolcanlogin::text || '|' || rolinherit::text
        FROM pg_roles WHERE rolname='marty_beta_migrator'
    """) == "false|false\n"


def test_direct_writer_probe_uses_valid_candidates_and_fence_errors(database: str):
    container_id = docker("inspect", database, "--format", "{{.Id}}").stdout.strip()
    system_id = sql(database, "SELECT system_identifier FROM pg_control_system()").strip()
    database_oid = sql(database, "SELECT oid FROM pg_database WHERE datname='marty'").strip()
    context = docker("context", "show").stdout.strip()
    daemon_id = docker("info", "--format", "{{.ID}}").stdout.strip()
    target = {
        "expected_docker_context": context,
        "expected_daemon_id": daemon_id,
        "expected_system_identifier": system_id,
        "expected_database_oid": database_oid,
        "expected_fence_epoch": 1,
    }
    for statement in candidate_sql("a" * 32).values():
        sql(database, f"BEGIN; {statement}; ROLLBACK;")
    for statement in unrelated_sql("a" * 32).values():
        assert sql(database, f"BEGIN; {statement}; ROLLBACK;").splitlines() == [
            "BEGIN", "1", "ROLLBACK",
        ]
    with pytest.raises(FenceProbeError):
        probe_direct_writes(container_id, **target)
    assert script(database, INSTALL).returncode == 0
    target["expected_fence_epoch"] = int(sql(database, "SELECT epoch FROM passport_cutover.state"))
    first = probe_direct_writes(container_id, **target)
    second = probe_direct_writes(container_id, **target)
    installed_at = sql(database, """
        SELECT to_char(installed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') || 'T' ||
               to_char(installed_at AT TIME ZONE 'UTC', 'HH24:MI:SS.MS') || 'Z'
        FROM passport_cutover.state WHERE singleton
    """).strip()
    assert installed_at < first["observed_at_utc"]
    assert set(first["rejections"]) == {
        "physical_document_jobs", "physical_flow_definitions",
        "physical_flow_instances",
    }
    assert first["unrelated_writes"] == {
        "issuance_transactions": {"verified": True, "rolled_back": True},
        "non_passport_flow_definitions": {"verified": True, "rolled_back": True},
    }
    assert sql(database, "SELECT count(*) FROM issuance_service.issuance_transactions").strip() == "0"
    assert sql(database, "SELECT count(*) FROM flow_service.flow_definitions").strip() == "0"
    assert first["session_user"] == first["current_user"] == "marty"
    assert first["database_uid"] == f"postgresql:{system_id}:{database_oid}"
    assert first["fence_epoch"] == target["expected_fence_epoch"]
    assert first["observation_watermark"] > target["expected_fence_epoch"]
    assert second["observation_watermark"] > first["observation_watermark"]
    assert first["observed_at_utc"].endswith("Z")
    assert first["receipt_sha256"] != second["receipt_sha256"]
    with pytest.raises(FenceProbeError):
        probe_direct_writes(container_id, **{**target, "expected_fence_epoch": 1})
    assert script(database, VERIFY).returncode == 0


def test_install_waits_for_prior_writer_and_rechecks_drain(database: str):
    writer = subprocess.Popen(
        [
            "docker", "exec", database, "psql", "-U", "postgres", "-d", "marty",
            "-v", "ON_ERROR_STOP=1", "-c", """
                BEGIN;
                SET ROLE marty;
                INSERT INTO issuance_service.physical_document_jobs
                    (id, organization_id, flow_execution_id, application_id,
                     application_template_id, credential_template_id,
                     delivery_destination_profile_id, document_type, country_code,
                     status, secure_artifact_ciphertext, secure_artifact_reference,
                     created_at, updated_at)
                VALUES ('racing-job', 'org', 'flow', 'application', 'app-template',
                    'credential-template', 'destination', 'P', 'USA', 'DRAFT',
                    '{"schema":"marty.passport-artifact-manifest/v1","chunks":["vault:v1:chunk"]}',
                    'physical-artifact://racing-job', clock_timestamp(), clock_timestamp());
                SELECT pg_sleep(2);
                COMMIT;
            """,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        for _ in range(60):
            sleeping = sql(database, """
                SELECT count(*) FROM pg_stat_activity
                WHERE pid <> pg_backend_pid()
                  AND wait_event_type='Timeout' AND wait_event='PgSleep'
            """).strip()
            if sleeping == "1":
                break
            time.sleep(0.025)
        else:
            pytest.fail("competing writer did not reach its open transaction")
        install = script(database, INSTALL)
        assert install.returncode != 0 and "drain is not empty" in install.stderr
        stdout, stderr = writer.communicate(timeout=15)
        assert writer.returncode == 0, (stdout, stderr)
        assert sql(database, "SELECT count(*) FROM issuance_service.physical_document_jobs") == "1\n"
        assert sql(database, "SELECT to_regnamespace('passport_cutover') IS NULL") == "t\n"
        assert sql(database, "SELECT count(*) FROM pg_roles WHERE rolname='marty_passport_fence_owner'") == "0\n"
        assert sql(database, "SELECT count(*) FROM pg_roles WHERE rolname='marty_beta_migrator'") == "0\n"
    finally:
        if writer.poll() is None:
            writer.terminate()
            writer.communicate(timeout=5)


def test_crashed_prior_writer_rolls_back_before_install(database: str):
    writer = subprocess.Popen(
        [
            "docker", "exec", database, "psql", "-U", "postgres", "-d", "marty",
            "-v", "ON_ERROR_STOP=1", "-c", """
                BEGIN;
                INSERT INTO issuance_service.physical_document_jobs
                    (id, organization_id, flow_execution_id, application_id,
                     application_template_id, credential_template_id,
                     delivery_destination_profile_id, document_type, country_code,
                     status, secure_artifact_ciphertext, secure_artifact_reference,
                     created_at, updated_at)
                VALUES ('crashed-job', 'org', 'flow', 'application', 'app-template',
                    'credential-template', 'destination', 'P', 'USA', 'DRAFT',
                    '{"schema":"marty.passport-artifact-manifest/v1","chunks":["vault:v1:chunk"]}',
                    'physical-artifact://crashed-job', clock_timestamp(), clock_timestamp());
                SELECT pg_sleep(30);
                COMMIT;
            """,
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    installer = None
    try:
        for _ in range(80):
            if sql(database, """
                SELECT count(*) FROM pg_stat_activity
                WHERE pid <> pg_backend_pid()
                  AND wait_event_type='Timeout' AND wait_event='PgSleep'
            """).strip() == "1":
                break
            time.sleep(0.025)
        else:
            pytest.fail("crash fixture did not enter its transaction")
        installer = subprocess.Popen(
            ["docker", *script_args(database, INSTALL)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(80):
            if sql(database, """
                SELECT count(*) FROM pg_stat_activity
                WHERE pid <> pg_backend_pid() AND wait_event_type='Lock'
                  AND query LIKE 'LOCK TABLE issuance_service.physical_document_jobs%'
            """).strip() == "1":
                break
            time.sleep(0.025)
        else:
            pytest.fail("installer did not wait on the prior writer")
        writer_pid = sql(database, """
            SELECT pid FROM pg_stat_activity
            WHERE pid <> pg_backend_pid()
              AND wait_event_type='Timeout' AND wait_event='PgSleep'
        """).strip()
        assert writer_pid.isdigit()
        assert sql(database, f"SELECT pg_terminate_backend({writer_pid})") == "t\n"
        output, error = installer.communicate(timeout=15)
        assert installer.returncode == 0, (output, error)
        writer.communicate(timeout=5)
        assert writer.returncode != 0
        assert sql(database, "SELECT count(*) FROM issuance_service.physical_document_jobs") == "0\n"
        assert sql(database, "SELECT phase FROM passport_cutover.state") == "fully_fenced\n"
    finally:
        for process in (writer, installer):
            if process is not None and process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)
