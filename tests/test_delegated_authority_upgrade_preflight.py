"""Execute the read-only preflight against disposable PostgreSQL databases.

Set MARTY_PREFLIGHT_TEST_DATABASE_URL to an explicitly disposable loopback admin
database. Only test-created databases/roles are removed. Corruption cases below
alter synthetic test records; none is an operational repair/import procedure.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from urllib.parse import urlsplit
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "rust/services/delegated-authority"
PREFLIGHT = SERVICE / "operations/preflight.sql"
DATABASE_URL = os.environ.get("MARTY_PREFLIGHT_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="requires an explicitly disposable local PostgreSQL admin database")


def identifier(value):
    return '"' + value.replace('"', '""') + '"'


def literal(value):
    return "'" + value.replace("'", "''") + "'"


@pytest.fixture(scope="module")
def postgres():
    parsed = urlsplit(DATABASE_URL)
    assert parsed.scheme in ("postgresql", "postgres")
    assert parsed.hostname in ("127.0.0.1", "::1"), "these destructive fixture tests require loopback"
    assert parsed.password is None and not parsed.query and not parsed.fragment
    binary = Path(os.environ.get("PG_BINDIR", "")) / "psql"
    executable = str(binary) if binary.is_file() else shutil.which("psql")
    assert executable, "psql must be installed"
    assert parsed.username and parsed.path.strip("/")

    def run(sql=None, *, database=None, variables=None, file=None, check=True):
        args = [executable, "-X", "--no-password", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                "-h", parsed.hostname, "-p", str(parsed.port or 5432), "-U", parsed.username,
                "-d", database or parsed.path.strip("/")]
        for key, value in (variables or {}).items():
            args.extend(["-v", f"{key}={value}"])
        if file:
            args.extend(["-f", str(file)])
        result = subprocess.run(args, input=sql, text=True, capture_output=True, timeout=45, check=False)
        if check:
            assert result.returncode == 0, result.stderr
        return result

    assert int(run("SHOW server_version_num;").stdout.strip()) >= 150000
    return run


@pytest.fixture
def database_factory(postgres):
    @contextmanager
    def create(*, unusual_names=False):
        token = uuid4().hex[:16]
        name = f"da_preflight_{token}"
        roles = {"migration_owner": f"da_owner_{token}", "request_role": f"da_request_{token}",
                 "confirmation_role": f"da_confirm_{token}", "authority_role": f"da_authority_{token}"}
        if unusual_names:
            roles = {key: value + " '\";--" for key, value in roles.items()}
        for role in roles.values():
            postgres(f"CREATE ROLE {identifier(role)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;")
        postgres(f"CREATE DATABASE {identifier(name)} OWNER {identifier(roles['migration_owner'])};")
        extra_roles = []

        def sql(statement, *, check=True):
            return postgres(statement, database=name, check=check)

        def migrate(count=None):
            migrations = sorted((SERVICE / "migrations").glob("*.sql"))
            selected = migrations if count is None else migrations[:count]
            statements = [f"SET ROLE {identifier(roles['migration_owner'])}; BEGIN;",
                "CREATE SCHEMA IF NOT EXISTS delegated_authority_service;",
                "CREATE TABLE IF NOT EXISTS delegated_authority_service.schema_migrations ("
                "version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP);"]
            for path in selected:
                raw = path.read_bytes()
                statements.append(raw.decode())
                statements.append("INSERT INTO delegated_authority_service.schema_migrations(version,checksum) VALUES ("
                                  f"{int(path.name[:4])},{literal('sha256:' + hashlib.sha256(raw).hexdigest())});")
            statements.append("COMMIT;")
            sql("\n".join(statements))

        def privileges():
            request = identifier(roles["request_role"])
            confirmation = identifier(roles["confirmation_role"])
            authority = identifier(roles["authority_role"])
            sql(f"""
                GRANT USAGE ON SCHEMA delegated_authority_service TO {request},{confirmation},{authority};
                GRANT SELECT,INSERT,UPDATE ON delegated_authority_service.delegation_grants TO {request};
                GRANT SELECT ON delegated_authority_service.grant_lifecycle_events,
                    delegated_authority_service.schema_migrations,
                    delegated_authority_service.consent_confirmations,
                    delegated_authority_service.consent_withdrawals,
                    delegated_authority_service.representation_authority_sources,
                    delegated_authority_service.representation_authority_assertions TO {request};
                GRANT SELECT,INSERT ON delegated_authority_service.consent_confirmations,
                    delegated_authority_service.consent_withdrawals TO {confirmation};
                GRANT SELECT,INSERT ON delegated_authority_service.representation_authority_sources,
                    delegated_authority_service.representation_authority_assertions TO {authority};
                GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(TEXT) TO {request},{confirmation};
            """)
            if sql("SELECT to_regclass('delegated_authority_service.command_results') IS NOT NULL;").stdout.strip() == "t":
                sql(f"GRANT SELECT,INSERT ON delegated_authority_service.command_results TO {request};")

        def inspect(phase="pre-migration", *, overrides=None):
            variables = {"phase": phase, **roles, **(overrides or {})}
            return postgres(database=name, variables=variables, file=PREFLIGHT, check=False)

        def snapshot():
            tables = sql("SELECT tablename FROM pg_tables WHERE schemaname='delegated_authority_service' ORDER BY tablename;").stdout.splitlines()
            return {table: sql(f"SELECT COALESCE(jsonb_agg(v ORDER BY v::TEXT),'[]'::jsonb) FROM "
                              f"(SELECT to_jsonb(t) AS v FROM delegated_authority_service.{identifier(table)} t) records;").stdout
                    for table in tables}

        class Database:
            pass
        database = Database()
        database.name, database.roles, database.extra_roles = name, roles, extra_roles
        database.sql, database.migrate, database.privileges = sql, migrate, privileges
        database.inspect, database.snapshot = inspect, snapshot
        try:
            yield database
        finally:
            postgres(f"DROP DATABASE {identifier(name)} WITH (FORCE);")
            for role in [*extra_roles, *roles.values()]:
                postgres(f"DROP ROLE {identifier(role)};")
    return create


@pytest.fixture
def database(database_factory):
    with database_factory() as database:
        yield database


def pending_grant():
    return {"profile": "urn:marty:delegation-grant:v1", "id": str(uuid4()), "organization_id": str(uuid4()),
            "authority": {"mode": "MANAGED", "issuer": {"type": "SERVICE_ACCOUNT", "id": "urn:example:issuer"}},
            "terms": {"grantor": {"type": "USER", "id": "urn:example:grantor"},
                      "subject": {"type": "USER", "id": "urn:example:subject"},
                      "delegate": {"type": "SERVICE_ACCOUNT", "id": "urn:example:agent"},
                      "binding": {"method": "KEY", "key_thumbprint": "sha256:" + "a" * 64},
                      "actions": ["urn:example:read"], "audiences": ["https://example.invalid"],
                      "resources": ["urn:example:resource"], "valid_from": "2000-01-01T00:00:00Z",
                      "valid_until": "2099-01-01T00:00:00Z", "constraints": {"mode": "NONE"}},
            "terms_digest": "sha256:" + "b" * 64, "status": "PENDING", "revision": 1,
            "created_at": "2000-01-01T00:00:00Z", "updated_at": "2000-01-01T00:00:00Z"}


def insert_grant(database, grant=None):
    grant = grant or pending_grant()
    document = literal(json.dumps(grant))
    database.sql(f"""INSERT INTO delegated_authority_service.delegation_grants
        (id,organization_id,status,revision,terms_digest,grant_document,created_at,updated_at)
        VALUES ({literal(grant['id'])},{literal(grant['organization_id'])},{literal(grant['status'])},
        {grant['revision']},{literal(grant['terms_digest'])},{document}::jsonb,
        {literal(grant['created_at'])},{literal(grant['updated_at'])});""")
    return grant


def revoke_grant(database, grant):
    grant = {**grant, "revision": 2, "status": "REVOKED", "updated_at": "2000-01-01T00:00:01Z"}
    database.sql(f"""UPDATE delegated_authority_service.delegation_grants
        SET revision=2,status='REVOKED',updated_at={literal(grant['updated_at'])},
            grant_document={literal(json.dumps(grant))}::jsonb WHERE id={literal(grant['id'])};""")
    return grant


def insert_create_result(database, grant):
    command = {"profile": "urn:marty:delegation-command:v1", "command": "CREATE_GRANT",
               "command_id": str(uuid4()), "terms": grant["terms"]}
    # Deliberately synthetic: the SQL preflight verifies historical binding,
    # not canonical hashing or the authenticated provenance of this actor.
    database.sql(f"""INSERT INTO delegated_authority_service.command_results
        (organization_id,actor_type,actor_id,command_id,command_digest,command_document,
         grant_id,grant_revision,result_document)
        VALUES ({literal(grant['organization_id'])},'USER','urn:example:grantor',
                {literal(command['command_id'])},{literal('sha256:' + 'c' * 64)},
                {literal(json.dumps(command))}::jsonb,{literal(grant['id'])},1,
                {literal(json.dumps(grant))}::jsonb);""")
    return command


def assert_passed(result, *, version, grants=0, events=0, results=0):
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout.strip())
    assert report["schema_version"] == version
    assert report["grant_count"] == grants and report["event_count"] == events
    assert report["command_result_count"] == results
    assert report["runtime_qualification"] == "NOT_ASSESSED"
    assert report["execution_authorized"] is False


def assert_rejected_without_changes(database, code, *, phase="pre-migration", overrides=None):
    before = database.snapshot()
    result = database.inspect(phase, overrides=overrides)
    assert result.returncode != 0
    assert code in result.stderr, result.stderr
    assert database.snapshot() == before


def test_clean_install_preflight_creates_no_service_schema(database):
    assert_passed(database.inspect(), version=0)
    assert database.snapshot() == {}
    assert_rejected_without_changes(database, "DA_PREFLIGHT_SCHEMA_STATE", phase="post-migration")


def test_empty_initial_migration_can_proceed_without_synthesizing_history(database):
    database.migrate(1)
    before = database.snapshot()
    assert_passed(database.inspect(), version=1)
    assert database.snapshot() == before


def test_nonempty_initial_table_blocks_before_0002_and_retains_every_record(database):
    database.migrate(1)
    grant = insert_grant(database)
    assert_rejected_without_changes(database, "DA_PREFLIGHT_UNJOURNALED_GRANTS")
    remaining = database.sql(f"SELECT grant_document FROM delegated_authority_service.delegation_grants WHERE id={literal(grant['id'])};")
    assert json.loads(remaining.stdout) == grant


def test_current_schema_and_valid_history_remain_unchanged(database):
    database.migrate()
    database.privileges()
    grant = insert_grant(database)
    revoke_grant(database, grant)
    before = database.snapshot()
    version = len(list((SERVICE / "migrations").glob("*.sql")))
    assert_passed(database.inspect("post-migration"), version=version, grants=1, events=2)
    assert database.snapshot() == before


def test_historical_result_survives_later_lifecycle_change(database):
    database.migrate()
    database.privileges()
    grant = insert_grant(database)
    insert_create_result(database, grant)
    revoke_grant(database, grant)
    before = database.snapshot()
    version = len(list((SERVICE / "migrations").glob("*.sql")))
    assert_passed(database.inspect("post-migration"), version=version, grants=1, events=2, results=1)
    assert database.snapshot() == before


@pytest.mark.parametrize("mutation", ["result-time", "command-identity", "immutable-terms", "latest-snapshot", "unknown-command"])
def test_original_command_result_binding_is_audited_without_rewriting_it(database, mutation):
    database.migrate()
    database.privileges()
    grant = insert_grant(database)
    insert_create_result(database, grant)
    latest = revoke_grant(database, grant)
    database.sql("ALTER TABLE delegated_authority_service.command_results DISABLE TRIGGER command_results_immutable;")
    if mutation == "result-time":
        database.sql("""UPDATE delegated_authority_service.command_results
            SET result_document=jsonb_set(result_document,'{updated_at}','"2000-01-01T00:00:02Z"');""")
    elif mutation == "command-identity":
        database.sql(f"""UPDATE delegated_authority_service.command_results
            SET command_document=jsonb_set(command_document,'{{command_id}}',{literal(json.dumps(str(uuid4())))}::jsonb);""")
    elif mutation == "immutable-terms":
        database.sql("""UPDATE delegated_authority_service.command_results
            SET result_document=jsonb_set(result_document,'{terms,delegate,id}','"urn:example:substituted"');""")
    elif mutation == "latest-snapshot":
        database.sql(f"UPDATE delegated_authority_service.command_results SET result_document={literal(json.dumps(latest))}::jsonb;")
    else:
        database.sql("""UPDATE delegated_authority_service.command_results
            SET command_document=jsonb_set(command_document,'{command}','"START_USE"');""")
    database.sql("ALTER TABLE delegated_authority_service.command_results ENABLE TRIGGER command_results_immutable;")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_COMMAND_RESULTS", phase="post-migration")


@pytest.mark.parametrize("mutation", ["missing-event", "previous-state", "event-time", "current-document"])
def test_corrupt_synthetic_history_is_detected_without_attempting_repair(database, mutation):
    database.migrate()
    database.privileges()
    grant = revoke_grant(database, insert_grant(database))
    # Deliberate corruption of isolated synthetic fixtures only. Re-enable all
    # guards before inspection so the journal check, not a disabled trigger, fails.
    database.sql("ALTER TABLE delegated_authority_service.grant_lifecycle_events DISABLE TRIGGER grant_lifecycle_events_append_only;")
    if mutation == "missing-event":
        database.sql("DELETE FROM delegated_authority_service.grant_lifecycle_events WHERE revision=1;")
    elif mutation == "previous-state":
        database.sql("UPDATE delegated_authority_service.grant_lifecycle_events SET previous_status='ACTIVE' WHERE revision=2;")
    elif mutation == "event-time":
        database.sql("UPDATE delegated_authority_service.grant_lifecycle_events SET occurred_at='1999-01-01T00:00:00Z' WHERE revision=1;")
    else:
        database.sql("""ALTER TABLE delegated_authority_service.delegation_grants DROP CONSTRAINT delegation_grants_document_columns;
            ALTER TABLE delegated_authority_service.delegation_grants DISABLE TRIGGER delegation_grants_guard;
            ALTER TABLE delegated_authority_service.delegation_grants DISABLE TRIGGER delegation_grants_journal;
            UPDATE delegated_authority_service.delegation_grants SET grant_document=jsonb_set(grant_document,'{status}','"ACTIVE"');
            ALTER TABLE delegated_authority_service.delegation_grants ENABLE TRIGGER delegation_grants_guard;
            ALTER TABLE delegated_authority_service.delegation_grants ENABLE TRIGGER delegation_grants_journal;""")
    database.sql("ALTER TABLE delegated_authority_service.grant_lifecycle_events ENABLE TRIGGER grant_lifecycle_events_append_only;")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_JOURNAL", phase="post-migration")


@pytest.mark.parametrize("mutation", ["checksum", "bare-checksum", "missing-version", "future-version", "disabled-trigger", "conditional-trigger", "wrong-owner", "wrong-function-search-path", "wrong-function-security"])
def test_migration_and_schema_drift_fail_closed(database, mutation):
    database.migrate()
    database.privileges()
    if mutation == "checksum":
        database.sql("UPDATE delegated_authority_service.schema_migrations SET checksum='changed' WHERE version=1;")
        code = "DA_PREFLIGHT_MIGRATION_HISTORY"
    elif mutation == "bare-checksum":
        database.sql("UPDATE delegated_authority_service.schema_migrations SET checksum=substring(checksum FROM 8) WHERE version=1;")
        code = "DA_PREFLIGHT_MIGRATION_HISTORY"
    elif mutation == "missing-version":
        database.sql("DELETE FROM delegated_authority_service.schema_migrations WHERE version=2;")
        code = "DA_PREFLIGHT_MIGRATION_HISTORY"
    elif mutation == "future-version":
        database.sql("INSERT INTO delegated_authority_service.schema_migrations(version,checksum) VALUES(999,'unknown');")
        code = "DA_PREFLIGHT_MIGRATION_HISTORY"
    elif mutation == "disabled-trigger":
        database.sql("ALTER TABLE delegated_authority_service.delegation_grants DISABLE TRIGGER delegation_grants_journal;")
        code = "DA_PREFLIGHT_TRIGGER"
    elif mutation == "conditional-trigger":
        database.sql("""DROP TRIGGER command_results_binding ON delegated_authority_service.command_results;
            CREATE TRIGGER command_results_binding BEFORE INSERT ON delegated_authority_service.command_results
            FOR EACH ROW WHEN (false) EXECUTE FUNCTION delegated_authority_service.guard_command_result();""")
        code = "DA_PREFLIGHT_TRIGGER"
    elif mutation == "wrong-owner":
        database.sql(f"ALTER TABLE delegated_authority_service.consent_confirmations OWNER TO {identifier(database.roles['request_role'])};")
        code = "DA_PREFLIGHT_OBJECT_OWNER"
    elif mutation == "wrong-function-search-path":
        database.sql("ALTER FUNCTION delegated_authority_service.journal_grant_lifecycle() SET search_path=public;")
        code = "DA_PREFLIGHT_FUNCTION_OWNER"
    else:
        database.sql("ALTER FUNCTION delegated_authority_service.journal_grant_lifecycle() SECURITY INVOKER;")
        code = "DA_PREFLIGHT_FUNCTION_OWNER"
    assert_rejected_without_changes(database, code, phase="post-migration")


@pytest.mark.parametrize("mutation", ["source-write", "journal-write", "result-update", "producer-result-read", "column-write", "grant-option", "cross-producer", "function-execute", "owner-membership", "indirect-owner-membership", "missing-read", "schema-create"])
def test_actual_database_privilege_paths_are_audited(database, postgres, mutation):
    database.migrate()
    database.privileges()
    request = identifier(database.roles["request_role"])
    confirmation = identifier(database.roles["confirmation_role"])
    owner = identifier(database.roles["migration_owner"])
    code = "DA_PREFLIGHT_TABLE_PRIVILEGE"
    if mutation == "source-write":
        database.sql(f"GRANT INSERT ON delegated_authority_service.consent_confirmations TO {request};")
    elif mutation == "journal-write":
        database.sql(f"GRANT INSERT ON delegated_authority_service.grant_lifecycle_events TO {request};")
    elif mutation == "result-update":
        database.sql(f"GRANT UPDATE ON delegated_authority_service.command_results TO {request};")
    elif mutation == "producer-result-read":
        database.sql(f"GRANT SELECT ON delegated_authority_service.command_results TO {confirmation};")
    elif mutation == "column-write":
        database.sql(f"GRANT UPDATE(evidence_ref) ON delegated_authority_service.consent_confirmations TO {request};")
    elif mutation == "grant-option":
        database.sql(f"GRANT SELECT ON delegated_authority_service.delegation_grants TO {request} WITH GRANT OPTION;")
    elif mutation == "cross-producer":
        database.sql(f"GRANT INSERT ON delegated_authority_service.representation_authority_assertions TO {confirmation};")
    elif mutation == "function-execute":
        database.sql(f"GRANT EXECUTE ON FUNCTION delegated_authority_service.guard_consent_source() TO {request};")
        code = "DA_PREFLIGHT_FUNCTION_PRIVILEGE"
    elif mutation == "owner-membership":
        database.sql(f"ALTER ROLE {request} NOINHERIT; GRANT {owner} TO {request};")
        code = "DA_PREFLIGHT_ROLE_ESCALATION"
    elif mutation == "indirect-owner-membership":
        name = "da_bridge_" + uuid4().hex[:16]
        postgres(f"CREATE ROLE {identifier(name)} NOLOGIN NOINHERIT;")
        database.extra_roles.append(name)
        database.sql(f"GRANT {owner} TO {identifier(name)}; GRANT {identifier(name)} TO {request};")
        code = "DA_PREFLIGHT_ROLE_ESCALATION"
    elif mutation == "missing-read":
        database.sql(f"REVOKE SELECT ON delegated_authority_service.consent_withdrawals FROM {request};")
        code = "DA_PREFLIGHT_MISSING_PRIVILEGE"
    else:
        database.sql(f"GRANT CREATE ON SCHEMA delegated_authority_service TO {request};")
        code = "DA_PREFLIGHT_SCHEMA_PRIVILEGE"
    assert_rejected_without_changes(database, code, phase="post-migration")


def test_psql_role_arguments_are_quoted_values_not_executable_sql(database_factory):
    with database_factory(unusual_names=True) as database:
        database.migrate()
        database.privileges()
        version = len(list((SERVICE / "migrations").glob("*.sql")))
        assert_passed(database.inspect("post-migration"), version=version)
        assert_rejected_without_changes(database, "DA_PREFLIGHT_ROLES",
            overrides={"request_role": "missing'; SELECT pg_sleep(40); --"})


def test_four_identities_and_explicit_phase_are_required(database):
    assert_rejected_without_changes(database, "DA_PREFLIGHT_ROLES",
        overrides={"confirmation_role": database.roles["request_role"]})
    assert_rejected_without_changes(database, "DA_PREFLIGHT_PHASE", overrides={"phase": "activate"})


@pytest.mark.parametrize("missing", ["phase", "migration_owner", "request_role", "confirmation_role", "authority_role"])
def test_missing_psql_variable_returns_failure_without_creating_objects(database, postgres, missing):
    variables = {"phase": "pre-migration", **database.roles}
    del variables[missing]
    result = postgres(database=database.name, variables=variables, file=PREFLIGHT, check=False)
    assert result.returncode != 0
    assert "DA_PREFLIGHT_REQUIRED_VARIABLE" in result.stderr
    assert database.snapshot() == {}
