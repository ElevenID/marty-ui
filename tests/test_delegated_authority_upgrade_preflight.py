"""Execute the read-only preflight against disposable PostgreSQL databases.

Set MARTY_PREFLIGHT_TEST_DATABASE_URL to an explicitly disposable loopback admin
database. Only test-created databases/roles are removed. Corruption cases below
alter synthetic test records; none is an operational repair/import procedure.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
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
            if sql("SELECT to_regclass('delegated_authority_service.command_identities') IS NOT NULL;").stdout.strip() == "t":
                sql(f"GRANT SELECT,INSERT ON delegated_authority_service.command_identities TO {request};")

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


def test_use_upgrade_backfills_existing_command_identity_without_rewriting_history(database):
    database.migrate(5)
    grant = insert_grant(database)
    command = insert_create_result(database, grant)
    original = database.sql("SELECT command_document::text || result_document::text FROM delegated_authority_service.command_results;").stdout
    migration = SERVICE / "migrations/0006_retained_use_commands.sql"
    raw = migration.read_bytes()
    database.sql(f"SET ROLE {identifier(database.roles['migration_owner'])}; BEGIN;\n" + raw.decode() +
        f"\nINSERT INTO delegated_authority_service.schema_migrations(version,checksum) VALUES (6,{literal('sha256:' + hashlib.sha256(raw).hexdigest())}); COMMIT; RESET ROLE;")
    database.privileges()
    assert_passed(database.inspect("pre-migration"), version=6, grants=1, events=1, results=1)
    assert database.sql("SELECT command_document::text || result_document::text FROM delegated_authority_service.command_results;").stdout == original
    assert database.sql("SELECT command_id::text FROM delegated_authority_service.command_identities;").stdout.strip() == command["command_id"]


@pytest.mark.parametrize("mutation", ["digest", "name", "orphan"])
def test_shared_command_identity_history_drift_is_rejected_without_repair(database, mutation):
    database.migrate()
    database.privileges()
    grant = insert_grant(database)
    insert_create_result(database, grant)
    if mutation == "orphan":
        database.sql(f"INSERT INTO delegated_authority_service.command_identities VALUES ({literal(str(uuid4()))},'USER','urn:example:orphan',{literal(str(uuid4()))},'START_USE',{literal('sha256:'+'d'*64)});")
    else:
        assignment = "command_digest='sha256:'||repeat('d',64)" if mutation == "digest" else "command_name='START_USE'"
        database.sql(f"ALTER TABLE delegated_authority_service.command_identities DISABLE TRIGGER command_identities_immutable; UPDATE delegated_authority_service.command_identities SET {assignment}; ALTER TABLE delegated_authority_service.command_identities ENABLE TRIGGER command_identities_immutable;")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_USE_HISTORY", phase="post-migration")


@pytest.mark.parametrize("table,trigger", [
    ("command_results", "command_results_identity"),
    ("use_command_claims", "use_command_claims_binding"),
    ("use_admissions", "use_admissions_binding"),
    ("use_receipts", "use_receipts_binding"),
    ("use_command_results", "use_command_results_binding"),
    ("use_command_results", "use_command_results_commit"),
    *[(name, name + suffix) for name in ("command_identities", "use_command_claims", "use_admissions", "use_receipts", "use_command_results")
      for suffix in ("_immutable", "_no_truncate")],
])
def test_every_retained_use_guard_is_required(database, table, trigger):
    database.migrate()
    database.privileges()
    database.sql(f"ALTER TABLE delegated_authority_service.{table} DISABLE TRIGGER {trigger};")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_TRIGGER", phase="post-migration")


def test_retained_use_deadline_guard_must_be_deferred(database):
    database.migrate()
    database.privileges()
    database.sql("DROP TRIGGER use_command_results_commit ON delegated_authority_service.use_command_results; CREATE TRIGGER use_command_results_commit AFTER INSERT ON delegated_authority_service.use_command_results FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.check_use_result_commit();")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_TRIGGER", phase="post-migration")


@pytest.mark.parametrize("privilege", ["SELECT", "INSERT"])
def test_lifecycle_writer_requires_only_registry_addition(database, privilege):
    database.migrate()
    database.privileges()
    database.sql(f"REVOKE {privilege} ON delegated_authority_service.command_identities FROM {identifier(database.roles['request_role'])};")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_MISSING_PRIVILEGE", phase="post-migration")


@pytest.mark.parametrize("table", ["use_command_claims", "use_admissions", "use_receipts", "use_command_results"])
def test_lifecycle_writer_is_not_granted_retained_use_evidence(database, table):
    database.migrate()
    database.privileges()
    database.sql(f"GRANT SELECT ON delegated_authority_service.{table} TO {identifier(database.roles['request_role'])};")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_TABLE_PRIVILEGE", phase="post-migration")


@pytest.mark.parametrize("mutation", ["table", "version"])
def test_retained_use_schema_must_match_recorded_version(database, mutation):
    database.migrate()
    database.privileges()
    if mutation == "table":
        database.sql("DROP TABLE delegated_authority_service.use_command_results;")
    else:
        database.sql("DELETE FROM delegated_authority_service.schema_migrations WHERE version>=6;")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_SCHEMA_STATE", phase="post-migration")


@pytest.mark.parametrize("mutation", ["missing-start", "missing-final", "wrong-predicate", "wrong-columns", "missing-nonce"])
def test_retained_use_unique_indexes_cannot_be_weakened(database, mutation):
    database.migrate()
    database.privileges()
    if mutation == "missing-nonce":
        database.sql("ALTER TABLE delegated_authority_service.use_admissions DROP CONSTRAINT use_admissions_organization_id_verifier_id_nonce_key;")
    elif mutation == "missing-final":
        database.sql("DROP INDEX delegated_authority_service.use_command_final_challenge;")
    else:
        database.sql("DROP INDEX delegated_authority_service.use_command_start_challenge;")
        if mutation == "wrong-predicate":
            database.sql("CREATE UNIQUE INDEX use_command_start_challenge ON delegated_authority_service.use_command_claims(organization_id,challenge_id) WHERE command_name='FINALIZE_USE';")
        elif mutation == "wrong-columns":
            database.sql("CREATE UNIQUE INDEX use_command_start_challenge ON delegated_authority_service.use_command_claims(organization_id,command_id) WHERE command_name='START_USE';")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_USE_INDEX", phase="post-migration")


def insert_retained_use(database, outcome="pending", *, delegate_type=None):
    """Synthetic owner-state evidence; this is not proof or signer qualification."""
    stamp = lambda value: value.isoformat().replace("+00:00", "Z")
    candidate = pending_grant()
    if delegate_type is not None:
        candidate["terms"]["delegate"]["type"] = delegate_type
    grant = insert_grant(database, candidate)
    approved_at = stamp(datetime.now(timezone.utc) - timedelta(seconds=2))
    grant = {**grant, "status": "ACTIVE", "revision": 2, "updated_at": approved_at,
             "approval": {"profile": "urn:example:approval", "grant_id": grant["id"],
                "approver": grant["terms"]["grantor"], "evidence_ref": "urn:example:consent",
                "authority_evidence_ref": "urn:example:authority", "terms_digest": grant["terms_digest"], "approved_at": approved_at}}
    database.sql(f"UPDATE delegated_authority_service.delegation_grants SET status='ACTIVE',revision=2,updated_at={literal(approved_at)},grant_document={literal(json.dumps(grant))}::jsonb WHERE id={literal(grant['id'])};")
    org, gid = map(literal, (grant["organization_id"], grant["id"]))
    actor = grant["terms"]["delegate"]
    start_id, challenge = str(uuid4()), str(uuid4())
    grant_ref = {key: grant[key] for key in ("id", "revision", "terms_digest")}
    operation = {"action": grant["terms"]["actions"][0], "resource_id": grant["terms"]["resources"][0],
                 "audience": grant["terms"]["audiences"][0], "request_profile": "urn:example:operation:v1", "request_digest": "sha256:" + "e" * 64}
    start = {"profile": "urn:marty:delegation-command:v1", "command": "START_USE", "command_id": start_id, "grant": grant_ref, "operation": operation}
    digest = "sha256:" + "c" * 64

    def claim(command):
        database.sql(f"""INSERT INTO delegated_authority_service.use_command_claims
            (organization_id,actor_type,actor_id,command_id,command_name,command_digest,command_document,challenge_id,grant_id,grant_revision,grant_document)
            VALUES ({org},{literal(actor['type'])},{literal(actor['id'])},{literal(command['command_id'])},{literal(command['command'])},{literal(digest)},{literal(json.dumps(command))}::jsonb,{literal(challenge)},{gid},2,{literal(json.dumps(grant))}::jsonb);""")

    claim(start)
    if outcome == "pending":
        return grant
    created = datetime.now(timezone.utc)
    expires = created + timedelta(minutes=2)
    snapshot = {"organization_id": grant["organization_id"], "challenge_id": challenge, "grant": grant, "operation": operation,
                "verifier_id": "urn:example:verifier", "nonce": "n" * 32, "created_at": stamp(created), "expires_at": stamp(expires)}
    challenge_result = {"kind": "CHALLENGE", "challenge_id": challenge, "grant": grant_ref, "operation": operation,
                        "created_at": stamp(created), "expires_at": stamp(expires)}
    response = {"profile": "urn:marty:delegation-command-response:v1", "original_command_id": start_id,
                "command_digest": digest, "recovered": False, "result": challenge_result}
    database.sql(f"""BEGIN;
        INSERT INTO delegated_authority_service.use_admissions (organization_id,challenge_id,actor_type,actor_id,command_id,verifier_id,nonce,challenge_document,created_at,expires_at)
        VALUES ({org},{literal(challenge)},{literal(actor['type'])},{literal(actor['id'])},{literal(start_id)},'urn:example:verifier',{literal('n'*32)},{literal(json.dumps(snapshot))}::jsonb,{literal(stamp(created))},{literal(stamp(expires))});
        INSERT INTO delegated_authority_service.use_command_results VALUES ({org},{literal(actor['type'])},{literal(actor['id'])},{literal(start_id)},{literal(json.dumps(response))}::jsonb,clock_timestamp(),clock_timestamp()+interval '20 seconds'); COMMIT;""")
    if outcome == "challenge":
        return grant
    command = {"profile": "urn:marty:delegation-command:v1", "command": "FINALIZE_USE", "command_id": str(uuid4()), "challenge_id": challenge, "proof_submission_id": str(uuid4())}
    claim(command)
    issued = datetime.now(timezone.utc)
    auth_expires = issued + timedelta(seconds=30)
    payload = {"profile": "urn:marty:delegated-decision-receipt:v1", "id": str(uuid4()), "decision": outcome,
               "issuer": grant["authority"]["issuer"], "evaluation": {"organization_id": grant["organization_id"],
                   "challenge": "n" * 32, "actor": actor, "grant": grant_ref, "operation": operation},
               "issued_at": stamp(issued), "expires_at": stamp(auth_expires)}
    # A valid transport-shaped synthetic JWS isolates structural history checks.
    # There is no assertion that this signature or simplified payload is qualified.
    import base64
    encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode()
    compact = encode(b'{"alg":"EdDSA","kid":"urn:example:key","typ":"mip-delegated-decision+jws"}') + "." + encode(json.dumps(payload).encode()) + "." + encode(bytes(64))
    receipt_ref = "urn:marty:delegated-receipt:" + payload["id"]
    receipt_digest = "sha256:" + hashlib.sha256(compact.encode()).hexdigest()
    final_result = {"kind": "FINAL_USE", "challenge_id": challenge, "decision": outcome, "receipt_ref": receipt_ref,
                    "receipt_digest": receipt_digest, "recorded_at": stamp(issued), "authorization_expires_at": stamp(auth_expires), "semantics": "EVIDENCE_ONLY"}
    response = {**response, "original_command_id": command["command_id"], "result": final_result}
    database.sql(f"""BEGIN;
        INSERT INTO delegated_authority_service.use_receipts VALUES ({org},{literal(challenge)},{literal(actor['type'])},{literal(actor['id'])},{literal(command['command_id'])},{literal(command['proof_submission_id'])},{literal('sha256:'+'a'*64)},{literal(receipt_ref)},{literal(receipt_digest)},{literal(compact)},{literal(json.dumps(payload))}::jsonb,{literal(stamp(issued))},{literal(stamp(auth_expires))});
        INSERT INTO delegated_authority_service.use_command_results VALUES ({org},{literal(actor['type'])},{literal(actor['id'])},{literal(command['command_id'])},{literal(json.dumps(response))}::jsonb,clock_timestamp(),clock_timestamp()+interval '20 seconds'); COMMIT;""")
    return grant


@pytest.mark.parametrize("outcome,claims,results", [("pending", 1, 0), ("challenge", 1, 1), ("PERMIT", 2, 2), ("DENY", 2, 2)])
def test_retained_use_history_survives_grant_revocation_without_recovery_side_effects(database, outcome, claims, results):
    database.migrate()
    database.privileges()
    grant = insert_retained_use(database, outcome)
    grant = {**grant, "status": "REVOKED", "revision": 3, "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    database.sql(f"UPDATE delegated_authority_service.delegation_grants SET status='REVOKED',revision=3,updated_at={literal(grant['updated_at'])},grant_document={literal(json.dumps(grant))}::jsonb WHERE id={literal(grant['id'])};")
    before = database.snapshot()
    report = database.inspect("post-migration")
    assert_passed(report, version=8, grants=1, events=3)
    data = json.loads(report.stdout)
    assert data["use_command_claim_count"] == claims and data["use_command_result_count"] == results
    assert database.snapshot() == before


@pytest.mark.parametrize("table,assignment", [
    ("use_command_claims", "command_digest='sha256:'||repeat('d',64)"),
    ("use_admissions", "nonce=repeat('x',32)"),
    ("use_receipts", "compact_jws=compact_jws||'x'"),
    ("use_receipts", "receipt_document=jsonb_set(receipt_document,'{decision}','\"DENY\"')"),
    ("use_command_results", "response_document=jsonb_set(response_document,'{result,semantics}','\"EXECUTE\"')"),
])
def test_retained_use_history_corruption_is_rejected_without_repair(database, table, assignment):
    database.migrate()
    database.privileges()
    insert_retained_use(database, "PERMIT")
    database.sql(f"ALTER TABLE delegated_authority_service.{table} DISABLE TRIGGER {table}_immutable; UPDATE delegated_authority_service.{table} SET {assignment}; ALTER TABLE delegated_authority_service.{table} ENABLE TRIGGER {table}_immutable;")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_USE_HISTORY", phase="post-migration")


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


def insert_organization_approval(database):
    """Independent synthetic evidence using actual guards, never a repair path."""
    grant = pending_grant()
    actor, review, confirmation, member = (str(uuid4()) for _ in range(4))
    grant["authority"]["issuer"] = {"type": "ORGANIZATION", "id": "urn:marty:organization:" + grant["organization_id"]}
    grant["terms"]["grantor"] = {"type": "USER", "id": "urn:marty:user:" + actor}
    grant["terms"]["subject"] = grant["authority"]["issuer"].copy()
    insert_grant(database, grant)
    now = datetime.now(timezone.utc)
    stamp = lambda value: value.isoformat().replace("+00:00", "Z")
    created, confirmed, expires, authority_until = (
        stamp(now - timedelta(seconds=2)), stamp(now - timedelta(seconds=1)),
        stamp(now + timedelta(seconds=120)), stamp(now + timedelta(seconds=10)),
    )
    org, gid, digest = map(literal, (grant["organization_id"], grant["id"], grant["terms_digest"]))
    evidence, authority = map(literal, ("urn:example:consent:" + confirmation, "urn:example:authority:" + confirmation))
    profile, version, artifact = map(literal, ("urn:example:organization-approval:v1", "1.0.0", "sha256:" + "c" * 64))
    session = literal("urn:marty:session:sha256:" + "d" * 64)
    grantor, subject, issuer = (literal(json.dumps(p)) + "::jsonb" for p in
        (grant["terms"]["grantor"], grant["terms"]["subject"], grant["authority"]["issuer"]))
    database.sql(f"""
        INSERT INTO delegated_authority_service.approval_reviews
            (organization_id,review_id,grant_id,grant_revision,terms_digest,grant_document,actor_id,session_ref,profile,adapter_version,artifact_digest,created_at,expires_at)
        VALUES ({org},{literal(review)},{gid},1,{digest},{literal(json.dumps(grant))}::jsonb,{literal(actor)},{session},{profile},{version},{artifact},{literal(created)},{literal(expires)});
        INSERT INTO delegated_authority_service.representation_authority_sources
            (organization_id,authority_evidence_ref,evidence_ref,grant_id,terms_digest,grantor,subject,issuer,profile,adapter_version,artifact_digest)
        VALUES ({org},{authority},{evidence},{gid},{digest},{grantor},{subject},{issuer},{profile},{version},{artifact});
        INSERT INTO delegated_authority_service.representation_authority_assertions
            (organization_id,authority_evidence_ref,revision,state,asserted_at,valid_until)
        VALUES ({org},{authority},1,'AUTHORIZED',{literal(confirmed)},{literal(authority_until)});
        INSERT INTO delegated_authority_service.organization_authority_observations
            (organization_id,authority_evidence_ref,revision,user_id,member_id,source,permission,authorized,observed_at,valid_until)
        VALUES ({org},{authority},1,{literal(actor)},{literal(member)},'urn:marty:organization-store:v1','delegation-grant:approve',true,{literal(confirmed)},{literal(authority_until)});
        INSERT INTO delegated_authority_service.consent_confirmations
            (organization_id,evidence_ref,authority_evidence_ref,grant_id,terms_digest,grantor,subject,issuer,profile,adapter_version,artifact_digest,confirmed_at,valid_until)
        VALUES ({org},{evidence},{authority},{gid},{digest},{grantor},{subject},{issuer},{profile},{version},{artifact},{literal(confirmed)},{literal(expires)});
        INSERT INTO delegated_authority_service.approval_confirmation_bindings
            (organization_id,actor_id,confirmation_id,review_id,grant_id,terms_digest,session_ref,evidence_ref,authority_evidence_ref,confirmed_at,valid_until)
        VALUES ({org},{literal(actor)},{literal(confirmation)},{literal(review)},{gid},{digest},{session},{evidence},{authority},{literal(confirmed)},{literal(expires)});
    """)
    return grant


def test_organization_approval_preflight_preserves_historical_evidence_after_revocation(database):
    database.migrate()
    database.privileges()
    grant = insert_organization_approval(database)
    revoke_grant(database, grant)
    before = database.snapshot()
    report = database.inspect("post-migration")
    assert_passed(report, version=8, grants=1, events=2)
    parsed = json.loads(report.stdout)
    assert parsed["approval_review_count"] == parsed["approval_confirmation_count"] == parsed["organization_authority_observation_count"] == 1
    assert database.snapshot() == before


@pytest.mark.parametrize("table,assignment,guard", [
    ("approval_reviews", "session_ref='urn:marty:session:sha256:' || repeat('e',64)", "approval_reviews_immutable"),
    ("approval_reviews", "grant_document=jsonb_set(grant_document,'{terms,delegate,id}','\"urn:example:changed-agent\"')", "approval_reviews_immutable"),
    ("approval_reviews", "grant_document=jsonb_set(grant_document,'{approval}','null'::jsonb)", "approval_reviews_immutable"),
    ("approval_confirmation_bindings", "terms_digest='sha256:' || repeat('e',64)", "approval_confirmation_bindings_immutable"),
    ("approval_confirmation_bindings", "actor_id=gen_random_uuid()", "approval_confirmation_bindings_immutable"),
    ("organization_authority_observations", "user_id=gen_random_uuid()", "organization_authority_observations_immutable"),
    ("organization_authority_observations", "authorized=false", "organization_authority_observations_immutable"),
])
def test_organization_approval_history_drift_is_reported_without_repair(database, table, assignment, guard):
    database.migrate()
    database.privileges()
    insert_organization_approval(database)
    database.sql(f"ALTER TABLE delegated_authority_service.{table} DISABLE TRIGGER {guard}; UPDATE delegated_authority_service.{table} SET {assignment}; ALTER TABLE delegated_authority_service.{table} ENABLE TRIGGER {guard};")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_APPROVAL_HISTORY", phase="post-migration")


def test_approval_producer_optional_privileges_do_not_require_lifecycle_result_access(database):
    database.migrate()
    database.privileges()
    request, consent, authority = (identifier(database.roles[key]) for key in ("request_role", "confirmation_role", "authority_role"))
    database.sql(f"""
        GRANT SELECT ON delegated_authority_service.approval_storage_identity,
            delegated_authority_service.approval_reviews,delegated_authority_service.approval_confirmation_bindings,
            delegated_authority_service.organization_authority_observations TO {request};
        GRANT SELECT,INSERT ON delegated_authority_service.approval_reviews,
            delegated_authority_service.approval_confirmation_bindings TO {consent};
        GRANT SELECT ON delegated_authority_service.approval_storage_identity TO {consent};
        GRANT SELECT,INSERT ON delegated_authority_service.organization_authority_observations TO {authority};
        GRANT SELECT ON delegated_authority_service.delegation_grants,
            delegated_authority_service.approval_storage_identity TO {authority};
        GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(TEXT) TO {authority};
    """)
    assert_passed(database.inspect("post-migration"), version=8)
    database.sql(f"GRANT INSERT ON delegated_authority_service.organization_authority_observations TO {consent};")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_TABLE_PRIVILEGE", phase="post-migration")


@pytest.mark.parametrize("remove_assertions", [False, True])
def test_bound_approval_authority_requires_its_original_observation(database, remove_assertions):
    database.migrate()
    database.privileges()
    insert_organization_approval(database)
    database.sql("ALTER TABLE delegated_authority_service.organization_authority_observations DISABLE TRIGGER organization_authority_observations_immutable; DELETE FROM delegated_authority_service.organization_authority_observations; ALTER TABLE delegated_authority_service.organization_authority_observations ENABLE TRIGGER organization_authority_observations_immutable;")
    if remove_assertions:
        database.sql("ALTER TABLE delegated_authority_service.representation_authority_assertions DISABLE TRIGGER representation_authority_assertions_immutable; DELETE FROM delegated_authority_service.representation_authority_assertions; ALTER TABLE delegated_authority_service.representation_authority_assertions ENABLE TRIGGER representation_authority_assertions_immutable;")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_APPROVAL_HISTORY", phase="post-migration")


@pytest.mark.parametrize("mutation", ["missing-table", "missing-ledger", "disabled-guard", "wrong-function", "empty-identity"])
def test_approval_schema_and_guard_drift_fail_closed(database, mutation):
    database.migrate()
    database.privileges()
    if mutation == "missing-table":
        database.sql("DROP TABLE delegated_authority_service.organization_authority_observations;")
        code = "DA_PREFLIGHT_SCHEMA_STATE"
    elif mutation == "missing-ledger":
        database.sql("DELETE FROM delegated_authority_service.schema_migrations WHERE version=5;")
        code = "DA_PREFLIGHT_MIGRATION_HISTORY"
    elif mutation == "disabled-guard":
        database.sql("ALTER TABLE delegated_authority_service.approval_reviews DISABLE TRIGGER approval_reviews_binding;")
        code = "DA_PREFLIGHT_TRIGGER"
    elif mutation == "wrong-function":
        database.sql("ALTER FUNCTION delegated_authority_service.guard_approval_review() SECURITY INVOKER;")
        code = "DA_PREFLIGHT_FUNCTION_OWNER"
    else:
        database.sql("ALTER TABLE delegated_authority_service.approval_storage_identity DISABLE TRIGGER approval_storage_identity_immutable; DELETE FROM delegated_authority_service.approval_storage_identity; ALTER TABLE delegated_authority_service.approval_storage_identity ENABLE TRIGGER approval_storage_identity_immutable;")
        code = "DA_PREFLIGHT_APPROVAL_HISTORY"
    assert_rejected_without_changes(database, code, phase="post-migration")


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


@pytest.mark.parametrize("mutation", ["source-write", "journal-write", "result-update", "producer-result-read", "column-write", "grant-option", "cross-producer", "function-execute", "owner-membership", "indirect-owner-membership", "predefined-role-membership", "replication", "missing-read", "schema-create"])
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
    elif mutation == "predefined-role-membership":
        database.sql(f"ALTER ROLE {request} NOINHERIT; GRANT pg_execute_server_program TO {request};")
        code = "DA_PREFLIGHT_ROLE_ESCALATION"
    elif mutation == "replication":
        database.sql(f"ALTER ROLE {request} REPLICATION;")
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


def insert_machine_audit(database, *, lifetime=30, with_machine_authorization=False):
    """Synthetic retained owner evidence, never crypto/source qualification."""
    now = datetime.now(timezone.utc)
    stamp = lambda value: value.isoformat().replace("+00:00", "Z")
    organization, machine, grant, challenge = [str(uuid4()) for _ in range(4)]
    completed, deadline = stamp(now), stamp(now + timedelta(seconds=lifetime))
    scope = {"organization_id": organization, "machine_identity_id": machine,
             "deployment_profile_id": str(uuid4()), "principal": {"type": "MACHINE_IDENTITY", "id": "urn:synthetic:machine"},
             "runtime_instance_ref": "urn:synthetic:runtime", "key_id": "synthetic-key",
             "key_thumbprint": "sha256:" + "a" * 64, "policy_id": str(uuid4()), "policy_digest": "sha256:" + "b" * 64,
             "grant_id": grant, "grant_revision": 2, "challenge_id": challenge,
             "challenge_digest": "sha256:" + "c" * 64, "proof_evidence_ref": "urn:synthetic:core-proof",
             "action": "urn:synthetic:action", "audience": "urn:synthetic:audience", "resource": "urn:synthetic:resource",
             "operation_profile": "urn:synthetic:operation:v1", "operation_digest": "sha256:" + "d" * 64}
    document = {"profile": "urn:marty:machine-authentication-evidence:v1", "scope": scope,
                "policy_document": {"synthetic_fixture_only": True},
                "state": {"evidence_ref": "urn:synthetic:state", "observed_at": completed, "valid_until": deadline},
                "proof": {"evidence_ref": scope["proof_evidence_ref"], "verified_at": completed, "valid_until": deadline},
                "credentials": {"trust_profile_id": str(uuid4()), "credentials": [], "observed_at": completed, "valid_until": deadline},
                "attestation": None, "machine_authorization": None, "completed_at": completed, "valid_until": deadline}
    if with_machine_authorization:
        document["machine_authorization"] = {"policy_set_id": str(uuid4()), "revision": 1,
            "policy_type": "MACHINE_AUTHORIZATION", "policy_digest": "sha256:" + "e" * 64,
            "evidence_ref": "urn:synthetic:original-machine-permit", "observed_at": completed, "valid_until": deadline}
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    reference = "urn:marty:machine-authentication:" + digest
    database.sql(f"""INSERT INTO delegated_authority_service.machine_authentication_evidence
        (organization_id,evidence_ref,evidence_digest,actor_type,actor_id,machine_identity_id,grant_id,grant_revision,
         challenge_id,audit_bytes,audit_document,completed_at,valid_until,retained_at)
        VALUES ({literal(organization)},{literal(reference)},{literal(digest)},'MACHINE_IDENTITY','urn:synthetic:machine',
            {literal(machine)},{literal(grant)},2,{literal(challenge)},convert_to({literal(raw)},'UTF8'),
            {literal(raw)}::JSONB,{literal(completed)},{literal(deadline)},clock_timestamp());""")
    return document, reference


@pytest.mark.parametrize("table,trigger", [
    ("machine_authentication_evidence", "machine_authentication_evidence_binding"),
    ("machine_authentication_evidence", "machine_authentication_evidence_commit"),
    ("machine_authentication_evidence", "machine_authentication_evidence_immutable"),
    ("machine_authentication_evidence", "machine_authentication_evidence_no_truncate"),
    ("use_receipts", "use_receipts_machine_evidence"),
])
def test_every_machine_audit_guard_is_required(database, table, trigger):
    database.migrate()
    database.privileges()
    database.sql(f"ALTER TABLE delegated_authority_service.{table} DISABLE TRIGGER {trigger};")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_TRIGGER", phase="post-migration")


def test_machine_audit_commit_guard_must_be_deferred(database):
    database.migrate()
    database.privileges()
    database.sql("DROP TRIGGER machine_authentication_evidence_commit ON delegated_authority_service.machine_authentication_evidence; CREATE TRIGGER machine_authentication_evidence_commit AFTER INSERT ON delegated_authority_service.machine_authentication_evidence FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.check_machine_authentication_evidence_commit();")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_TRIGGER", phase="post-migration")


@pytest.mark.parametrize("role", ["request_role", "confirmation_role", "authority_role"])
@pytest.mark.parametrize("privilege", ["SELECT", "INSERT"])
def test_existing_runtime_roles_cannot_read_or_write_private_machine_audit(database, role, privilege):
    database.migrate()
    database.privileges()
    database.sql(f"GRANT {privilege} ON delegated_authority_service.machine_authentication_evidence TO {identifier(database.roles[role])};")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_TABLE_PRIVILEGE", phase="post-migration")


@pytest.mark.parametrize("mutation", ["table", "version", "index"])
def test_machine_audit_schema_must_match_recorded_migration_and_exact_identity(database, mutation):
    database.migrate()
    database.privileges()
    if mutation == "table":
        database.sql("DROP TABLE delegated_authority_service.machine_authentication_evidence CASCADE;")
        code = "DA_PREFLIGHT_SCHEMA_STATE"
    elif mutation == "version":
        database.sql("DELETE FROM delegated_authority_service.schema_migrations WHERE version>=7;")
        code = "DA_PREFLIGHT_SCHEMA_STATE"
    else:
        database.sql("ALTER TABLE delegated_authority_service.machine_authentication_evidence DROP CONSTRAINT machine_authentication_evidence_pkey; CREATE UNIQUE INDEX weaker_machine_audit ON delegated_authority_service.machine_authentication_evidence(evidence_ref);")
        code = "DA_PREFLIGHT_MACHINE_INDEX"
    assert_rejected_without_changes(database, code, phase="post-migration")


def test_expired_machine_audit_is_preserved_history_without_runtime_qualification(database):
    database.migrate()
    database.privileges()
    insert_machine_audit(database, lifetime=1)
    database.sql("SELECT pg_sleep(1.1);")
    before = database.snapshot()
    result = database.inspect("post-migration")
    assert_passed(result, version=8)
    report = json.loads(result.stdout.strip())
    assert report["machine_authentication_evidence_count"] == 1
    assert report["legacy_machine_receipt_count"] == 0
    assert report["execution_authorized"] is False
    assert database.snapshot() == before


@pytest.mark.parametrize("mutation", ["actor", "grant", "challenge", "deadline", "retained-at", "bytes"])
def test_machine_audit_history_corruption_is_rejected_without_repair(database, mutation):
    database.migrate()
    database.privileges()
    insert_machine_audit(database)
    assignment = {"actor": "actor_id='urn:synthetic:wrong-actor'", "grant": "grant_id=gen_random_uuid()",
                  "challenge": "challenge_id=gen_random_uuid()", "deadline": "valid_until=valid_until+interval '1 second'",
                  "retained-at": "retained_at=valid_until", "bytes": "audit_bytes=convert_to(' '||convert_from(audit_bytes,'UTF8'),'UTF8')"}[mutation]
    if mutation == "bytes":
        # Owner-only synthetic corruption, solely to test inspection. Never a
        # runtime migration, recovery or evidence import procedure.
        database.sql("""DO $$ DECLARE item RECORD; BEGIN
            FOR item IN SELECT conname FROM pg_constraint WHERE conrelid='delegated_authority_service.machine_authentication_evidence'::regclass
              AND contype='c' AND pg_get_constraintdef(oid) LIKE '%sha256(audit_bytes)%' LOOP
              EXECUTE format('ALTER TABLE delegated_authority_service.machine_authentication_evidence DROP CONSTRAINT %I',item.conname);
            END LOOP; END $$;""")
    database.sql(f"ALTER TABLE delegated_authority_service.machine_authentication_evidence DISABLE TRIGGER machine_authentication_evidence_immutable; UPDATE delegated_authority_service.machine_authentication_evidence SET {assignment}; ALTER TABLE delegated_authority_service.machine_authentication_evidence ENABLE TRIGGER machine_authentication_evidence_immutable;")
    code = "DA_PREFLIGHT_MACHINE_CONSTRAINT" if mutation == "bytes" else "DA_PREFLIGHT_MACHINE_HISTORY"
    assert_rejected_without_changes(database, code, phase="post-migration")


@pytest.mark.parametrize("delegate_type", ["SERVICE_ACCOUNT", "MACHINE_IDENTITY"])
def test_additive_machine_audit_migration_preserves_preexisting_use_outcome(database, delegate_type):
    database.migrate(6)
    database.privileges()
    insert_retained_use(database, "PERMIT", delegate_type=delegate_type)
    before = database.snapshot()
    migration = SERVICE / "migrations/0007_machine_authentication_evidence.sql"
    raw = migration.read_bytes()
    database.sql(f"SET ROLE {identifier(database.roles['migration_owner'])}; BEGIN;\n" + raw.decode() +
        f"\nINSERT INTO delegated_authority_service.schema_migrations(version,checksum) VALUES (7,{literal('sha256:' + hashlib.sha256(raw).hexdigest())}); COMMIT; RESET ROLE;")
    next_migration = SERVICE / "migrations/0008_machine_authorization_evidence.sql"
    next_raw = next_migration.read_bytes()
    database.sql(f"SET ROLE {identifier(database.roles['migration_owner'])}; BEGIN;\n" + next_raw.decode() +
        f"\nINSERT INTO delegated_authority_service.schema_migrations(version,checksum) VALUES (8,{literal('sha256:' + hashlib.sha256(next_raw).hexdigest())}); COMMIT; RESET ROLE;")
    after = database.snapshot()
    for table, rows in before.items():
        if table != "schema_migrations":
            assert after[table] == rows
    result = database.inspect("post-migration")
    assert_passed(result, version=8, grants=1, events=2)
    report = json.loads(result.stdout.strip())
    assert report["machine_authentication_evidence_count"] == 0
    assert report["legacy_machine_receipt_count"] == int(delegate_type == "MACHINE_IDENTITY")


@pytest.mark.parametrize("constraint", ["machine_evidence_digest_matches_bytes", "machine_evidence_document_matches_bytes", "machine_evidence_reference_matches_digest"])
@pytest.mark.parametrize("mutation", ["missing", "weakened"])
def test_machine_audit_byte_binding_constraints_cannot_be_removed_or_weakened(database, constraint, mutation):
    database.migrate()
    database.privileges()
    database.sql(f"ALTER TABLE delegated_authority_service.machine_authentication_evidence DROP CONSTRAINT {constraint};")
    if mutation == "weakened":
        database.sql(f"ALTER TABLE delegated_authority_service.machine_authentication_evidence ADD CONSTRAINT {constraint} CHECK(true);")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_MACHINE_CONSTRAINT", phase="post-migration")


@pytest.mark.parametrize("table,trigger", [
    ("machine_authorization_evidence", "machine_authorization_evidence_binding"),
    ("machine_authorization_evidence", "machine_authorization_evidence_commit"),
    ("machine_authorization_evidence", "machine_authorization_evidence_immutable"),
    ("machine_authentication_evidence", "machine_authentication_authorization_binding"),
])
def test_machine_policy_required_trigger_cannot_be_disabled(database, table, trigger):
    database.migrate()
    database.privileges()
    database.sql(f"ALTER TABLE delegated_authority_service.{table} DISABLE TRIGGER {trigger};")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_TRIGGER", phase="post-migration")


@pytest.mark.parametrize("constraint", ["machine_authorization_evidence_bytes", "machine_authorization_evidence_digest", "machine_authorization_evidence_reference"])
@pytest.mark.parametrize("mutation", ["missing", "weakened"])
def test_machine_policy_exact_byte_checks_cannot_be_removed_or_weakened(database, constraint, mutation):
    database.migrate()
    database.privileges()
    database.sql(f"ALTER TABLE delegated_authority_service.machine_authorization_evidence DROP CONSTRAINT {constraint};")
    if mutation == "weakened":
        database.sql(f"ALTER TABLE delegated_authority_service.machine_authorization_evidence ADD CONSTRAINT {constraint} CHECK(true);")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_MACHINE_POLICY_CONSTRAINT", phase="post-migration")


@pytest.mark.parametrize("function", ["guard_machine_authorization_evidence", "check_machine_authorization_evidence_commit", "guard_machine_authentication_authorization"])
def test_machine_policy_guard_body_cannot_be_replaced_with_a_success_stub(database, function):
    database.migrate()
    database.privileges()
    database.sql(f"CREATE OR REPLACE FUNCTION delegated_authority_service.{function}() RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN RETURN NEW; END $$;")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_MACHINE_POLICY_GUARD", phase="post-migration")


@pytest.mark.parametrize("role", ["request_role", "confirmation_role", "authority_role"])
@pytest.mark.parametrize("privilege", ["SELECT", "INSERT"])
def test_existing_serving_roles_cannot_acquire_machine_policy_source_access(database, role, privilege):
    database.migrate()
    database.privileges()
    database.sql(f"GRANT {privilege} ON delegated_authority_service.machine_authorization_evidence TO {identifier(database.roles[role])};")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_TABLE_PRIVILEGE", phase="post-migration")


def test_machine_policy_identity_requires_exact_primary_key(database):
    database.migrate()
    database.privileges()
    database.sql("ALTER TABLE delegated_authority_service.machine_authorization_evidence DROP CONSTRAINT machine_authorization_evidence_pkey; CREATE UNIQUE INDEX weaker_machine_policy_identity ON delegated_authority_service.machine_authorization_evidence(evidence_ref);")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_MACHINE_POLICY_INDEX", phase="post-migration")


def insert_machine_policy_pair(database):
    """Synthetic source history for inspection, never a qualified MMF decision."""
    audit, _ = insert_machine_audit(database)
    scope = audit["scope"]
    organization = scope["organization_id"]
    policy = str(uuid4())
    stamp = lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    observed = stamp()
    deadline = audit["valid_until"]
    schema = "synthetic schema for stored byte-binding only"
    source = {"profile": "urn:marty:machine-policy-source-evidence:v1", "scope": scope,
              "policy_set_id": policy, "policy_revision": 1, "policy_digest": "sha256:" + "f" * 64,
              "observed_at": observed, "completed_at": observed, "valid_until": deadline,
              "schema": schema, "entities": [], "history_ref": "urn:synthetic:policy:history:1",
              "policy_snapshot": {"organization_id": organization, "policy_set_id": policy, "revision": 1,
                "policy_type": "MACHINE_AUTHORIZATION", "status": "ACTIVE", "schema_version": "MartyMachine/1.0",
                "schema_digest": "sha256:" + hashlib.sha256(schema.encode()).hexdigest(), "updated_at": observed}}
    def insert(kind, doc, completed):
        raw = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        digest = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
        reference = ("urn:marty:machine-policy-source:" if kind == "SOURCE" else "urn:marty:machine-authorization:") + digest
        database.sql(f"""INSERT INTO delegated_authority_service.machine_authorization_evidence
            (organization_id,evidence_ref,kind,evidence_bytes,evidence_document,evidence_digest,observed_at,completed_at,valid_until,retained_at)
            VALUES ({literal(organization)},{literal(reference)},{literal(kind)},convert_to({literal(raw)},'UTF8'),
                {literal(raw)}::JSONB,{literal(digest)},{literal(observed)},{literal(completed)},{literal(deadline)},clock_timestamp());""")
        return reference
    reference = insert("SOURCE", source, observed)
    completed = stamp()
    evaluation = {"profile": "urn:marty:machine-authorization-evidence:v1", "scope": scope,
                  "policy_set_id": policy, "policy_revision": 1, "policy_digest": source["policy_digest"],
                  "source_evidence_ref": reference, "observed_at": observed, "evaluated_at": completed,
                  "valid_until": deadline, "decision": "PERMIT"}
    return insert("EVALUATION", evaluation, completed)


def test_machine_policy_retained_source_and_evaluation_are_inspected_without_authorizing_use(database):
    database.migrate()
    database.privileges()
    insert_machine_policy_pair(database)
    before = database.snapshot()
    result = database.inspect("post-migration")
    assert_passed(result, version=8)
    report = json.loads(result.stdout.strip())
    assert report["machine_authorization_evidence_count"] == 2
    assert report["legacy_machine_authorization_audit_count"] == 0
    assert report["execution_authorized"] is False
    assert database.snapshot() == before


def test_machine_policy_history_detects_a_deleted_source_without_repair(database):
    database.migrate()
    database.privileges()
    insert_machine_policy_pair(database)
    database.sql("ALTER TABLE delegated_authority_service.machine_authorization_evidence DISABLE TRIGGER machine_authorization_evidence_immutable; DELETE FROM delegated_authority_service.machine_authorization_evidence WHERE kind='SOURCE'; ALTER TABLE delegated_authority_service.machine_authorization_evidence ENABLE TRIGGER machine_authorization_evidence_immutable;")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_MACHINE_POLICY_HISTORY", phase="post-migration")


def test_machine_policy_missing_new_retained_permit_is_detected_without_fabrication(database):
    database.migrate()
    database.privileges()
    database.sql("ALTER TABLE delegated_authority_service.machine_authentication_evidence DISABLE TRIGGER machine_authentication_authorization_binding;")
    insert_machine_audit(database, with_machine_authorization=True)
    database.sql("ALTER TABLE delegated_authority_service.machine_authentication_evidence ENABLE TRIGGER machine_authentication_authorization_binding;")
    assert_rejected_without_changes(database, "DA_PREFLIGHT_MACHINE_POLICY_HISTORY", phase="post-migration")


def test_machine_policy_upgrade_preserves_unqualified_original_authorization_history(database):
    database.migrate(7)
    database.privileges()
    insert_machine_audit(database, with_machine_authorization=True)
    before = database.snapshot()
    raw = (SERVICE / "migrations/0008_machine_authorization_evidence.sql").read_bytes()
    database.sql(f"SET ROLE {identifier(database.roles['migration_owner'])}; BEGIN;\n" + raw.decode() +
        f"\nINSERT INTO delegated_authority_service.schema_migrations(version,checksum) VALUES (8,{literal('sha256:' + hashlib.sha256(raw).hexdigest())}); COMMIT; RESET ROLE;")
    after = database.snapshot()
    for table, rows in before.items():
        if table != "schema_migrations":
            assert after[table] == rows
    result = database.inspect("post-migration")
    assert_passed(result, version=8)
    report = json.loads(result.stdout.strip())
    assert report["legacy_machine_authorization_audit_count"] == 1
    assert report["machine_authorization_evidence_count"] == 0
    assert report["execution_authorized"] is False
