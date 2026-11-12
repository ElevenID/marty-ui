"""Read-only compatibility witnesses for an owned Windows product transition.

These probes neither authorize a deployment nor replace native signer/token
custody admission. No password, token, row data or private key is returned.
Postgres computes catalog/ledger hashes inside read-only sessions; its ordinary
application rows are not copied, backed up or migrated by these probes.
"""
import hashlib
import datetime
import json
from dataclasses import dataclass
from pathlib import Path
import re
import ssl
import subprocess
import time
import urllib.request

import selfhost_windows_renewal as renewal

NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,62}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
PG_OPTIONS = 'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c search_path=pg_catalog'
DATABASES_SQL = """SELECT COALESCE(jsonb_agg(datname ORDER BY datname),'[]'::jsonb)
FROM pg_database WHERE datallowconn AND NOT datistemplate AND datname <> 'postgres'"""
LEDGERS_SQL = """SELECT COALESCE(jsonb_agg(jsonb_build_object('schema',n.nspname,'name',c.relname)
ORDER BY n.nspname,c.relname),'[]'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE c.relkind IN ('r','p') AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
AND c.relname ~* '(migrat|changelog|schema_version)' AND lower(c.relname) <> 'databasechangeloglock'"""
LEDGERS_SQL = LEDGERS_SQL.replace("'(migrat|changelog|schema_version)'",
                                "'(migrat|changelog|schema_version|^alembic_version$|^flyway_schema_history$)'")
# One statement observes one MVCC catalog snapshot. OIDs deliberately detect
# drop/recreate events with otherwise identical definitions. Sequence values,
# statistics, ordinary rows and credentials are excluded.
CATALOG_SQL = """WITH n AS (SELECT oid,nspname,nspowner,nspacl FROM pg_namespace
WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'),
c AS (SELECT * FROM pg_class WHERE relnamespace IN (SELECT oid FROM n)),
p AS (SELECT * FROM pg_proc WHERE pronamespace IN (SELECT oid FROM n))
SELECT to_json(encode(sha256(convert_to(jsonb_build_object(
'namespaces',(SELECT jsonb_agg(to_jsonb(n) ORDER BY oid) FROM n),
'relations',(SELECT jsonb_agg(jsonb_build_object('oid',oid,'name',relname,'namespace',relnamespace,
'kind',relkind,'owner',relowner,'persistence',relpersistence,'acl',relacl,'options',reloptions,
'metadata',to_jsonb(c)-ARRAY['relpages','reltuples','relallvisible','relallfrozen','relfrozenxid','relminmxid'],
'rowsecurity',relrowsecurity,'forcerowsecurity',relforcerowsecurity,'tablespace',reltablespace,
'view',CASE WHEN relkind IN ('v','m') THEN pg_get_viewdef(oid,true) ELSE NULL END) ORDER BY oid) FROM c),
'attributes',(SELECT jsonb_agg(to_jsonb(a) ORDER BY attrelid,attnum) FROM pg_attribute a WHERE attrelid IN (SELECT oid FROM c) AND attnum>0),
'defaults',(SELECT jsonb_agg(jsonb_build_object('relation',adrelid,'column',adnum,'expression',pg_get_expr(adbin,adrelid)) ORDER BY adrelid,adnum)
FROM pg_attrdef WHERE adrelid IN (SELECT oid FROM c)),
'constraints',(SELECT jsonb_agg(jsonb_build_object('oid',oid,'relation',conrelid,'name',conname,'definition',pg_get_constraintdef(oid,true),
'validated',convalidated,'deferred',condeferred,'deferrable',condeferrable) ORDER BY oid) FROM pg_constraint WHERE connamespace IN (SELECT oid FROM n)),
'indexes',(SELECT jsonb_agg(jsonb_build_object('oid',indexrelid,'definition',pg_get_indexdef(indexrelid),'valid',indisvalid,'ready',indisready)
ORDER BY indexrelid) FROM pg_index WHERE indrelid IN (SELECT oid FROM c)),
'functions',(SELECT jsonb_agg(jsonb_build_object('metadata',to_jsonb(p),'definition',CASE WHEN prokind IN ('f','p','w')
THEN pg_get_functiondef(oid) ELSE NULL END) ORDER BY oid) FROM p),
'aggregates',(SELECT jsonb_agg(to_jsonb(a) ORDER BY aggfnoid) FROM pg_aggregate a WHERE aggfnoid IN (SELECT oid FROM p)),
'triggers',(SELECT jsonb_agg(jsonb_build_object('oid',oid,'definition',pg_get_triggerdef(oid,true),'enabled',tgenabled)
ORDER BY oid) FROM pg_trigger WHERE tgrelid IN (SELECT oid FROM c) AND NOT tgisinternal),
'policies',(SELECT jsonb_agg(to_jsonb(a) ORDER BY oid) FROM pg_policy a WHERE polrelid IN (SELECT oid FROM c)),
'types',(SELECT jsonb_agg(to_jsonb(a) ORDER BY oid) FROM pg_type a WHERE typnamespace IN (SELECT oid FROM n)),
'enums',(SELECT jsonb_agg(to_jsonb(a) ORDER BY enumtypid,enumsortorder) FROM pg_enum a WHERE enumtypid IN (SELECT oid FROM pg_type WHERE typnamespace IN (SELECT oid FROM n))),
'sequences',(SELECT jsonb_agg(to_jsonb(a) ORDER BY seqrelid) FROM pg_sequence a WHERE seqrelid IN (SELECT oid FROM c)),
'extensions',(SELECT jsonb_agg(to_jsonb(a) ORDER BY oid) FROM pg_extension a),
'collations',(SELECT jsonb_agg(to_jsonb(a) ORDER BY oid) FROM pg_collation a WHERE collnamespace IN (SELECT oid FROM n))
,'inheritance',(SELECT jsonb_agg(to_jsonb(a) ORDER BY inhrelid,inhseqno) FROM pg_inherits a WHERE inhrelid IN (SELECT oid FROM c) OR inhparent IN (SELECT oid FROM c))
,'partitions',(SELECT jsonb_agg(to_jsonb(a) ORDER BY partrelid) FROM pg_partitioned_table a WHERE partrelid IN (SELECT oid FROM c))
,'rules',(SELECT jsonb_agg(to_jsonb(a) ORDER BY oid) FROM pg_rewrite a WHERE ev_class IN (SELECT oid FROM c))
,'default_acl',(SELECT jsonb_agg(to_jsonb(a) ORDER BY oid) FROM pg_default_acl a)
)::text,'UTF8')),'hex'))"""
SCHEMA = 'marty.windows-postgres-schema/v2'
PROBE = 'catalog-and-source-ledger-profile/v2'
PROFILE_ID = 'marty-selfhost-ledgers/v1'
CONSISTENCY = 'per-database-repeatable-read;two-equal-observations'
QUIESCENCE_SQL = """SELECT jsonb_build_object(
'database_clock',clock_timestamp(),'primary',NOT pg_is_in_recovery(),
'databases',("""+DATABASES_SQL+"""),
'client_backends',(SELECT count(*) FROM pg_stat_activity
WHERE pid <> pg_backend_pid() AND backend_type='client backend'),
'prepared_transactions',(SELECT count(*) FROM pg_prepared_xacts),
'subscriptions',(SELECT count(*) FROM pg_subscription),
'replication_backends',(SELECT count(*) FROM pg_stat_activity
WHERE backend_type IN ('walsender','walreceiver')),
'unqualified_backends',(SELECT count(*) FROM pg_stat_activity
WHERE pid <> pg_backend_pid() AND (backend_type IS NULL OR backend_type NOT IN (
'client backend','walsender','walreceiver','autovacuum launcher','autovacuum worker',
'background writer','checkpointer','archiver','walwriter','walsummarizer','logical replication launcher'))))"""
APPLICATION_LEDGERS = frozenset({
    ('auth_service', 'rust_schema_versions'), ('compliance_profile_service', 'native_migrations'),
    ('credential_template_service', 'rust_schema_versions'), ('deployment_profile_service', 'native_migrations'),
    ('flow_service', 'rust_schema_versions'), ('issuance_service', 'rust_schema_migrations'),
    ('organization_service', 'rust_schema_versions'), ('revocation_profile_service', 'rust_schema_migrations'),
    ('trust_profile_service', 'native_migrations'),
    # Explicit compatibility ledgers owned by the native device/notification
    # migrations; arbitrary Alembic/Flyway inventories remain unsupported.
    ('device_registration_service', 'alembic_version'), ('notification_service', 'alembic_version')})
KEYCLOAK_LEDGERS = frozenset({('public', 'databasechangelog'), ('public', 'migration_model')})
BINARY_PATHS = {'plugin_sha256': '/plugins/openbao-didcomm-authcrypt',
                'unseal_sha256': '/usr/local/bin/selfhost-unseal',
                'ready_sha256': '/usr/local/bin/selfhost-openbao-ready', 'bao_sha256': '/bin/bao'}


def require(value, message='Product compatibility probe refused'):
    renewal.require(value, message)


def owned_role(items, project, role):
    require(isinstance(project, str) and re.fullmatch(r'marty-(?:production|selfhost)-[a-z0-9][a-z0-9-]{0,59}', project))
    require(isinstance(items, list) and all(renewal._project(item) == project for item in items))
    rows = [item for item in items if renewal._service(item) == role]
    require(len(rows) == 1 and re.fullmatch(r'[0-9a-f]{64}', rows[0]['Id']))
    return rows[0]


@dataclass(frozen=True)
class LedgerProfile:
    """Known runtime schemas, not an artifact-supplied migration guess.

    Database names may be mapped from held installation settings. Ledger names
    come from this reviewed runtime profile; unsupported/missing inventories
    refuse. Applicants' idempotent schema has explicitly no migration ledger.
    """
    application: str = 'marty'
    keycloak: str = 'keycloak'
    applicants: str = 'marty_applicants'

    def __post_init__(self):
        names = (self.application, self.keycloak, self.applicants)
        require(all(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9_]{0,62}', name) for name in names)
                and len(set(names)) == 3)

    @property
    def tables(self):
        return {self.application: APPLICATION_LEDGERS, self.keycloak: KEYCLOAK_LEDGERS, self.applicants: frozenset()}


def validate_row_inventory(value, expected):
    require(type(value) is dict and len(value) <= RELATION_LIMIT
            and {schema+'.'+name for schema, name in expected} <= set(value))
    for table, columns in value.items():
        require(type(table) is str and len(table.split('.')) == 2
                and all(NAME.fullmatch(part) for part in table.split('.'))
                and type(columns) is list and len(columns) <= 1600
                and all(type(column) is str and column and '\0' not in column
                        and len(column.encode('utf-8')) <= 63 for column in columns)
                and len(columns) == len(set(columns)))


def _database_script(expected, *, detailed=False):
    fields = "'kind','catalog','sha256',witness,'supported',NOT(EXISTS(SELECT 1 FROM pg_foreign_table) OR EXISTS(SELECT 1 FROM pg_event_trigger))"
    if detailed:
        fields += ", 'row_inventory',(SELECT coalesce(jsonb_object_agg(r.nspname||'.'||r.relname,"
        fields += "(SELECT coalesce(jsonb_agg(attname ORDER BY attnum),'[]'::jsonb) FROM pg_attribute "
        fields += "WHERE attrelid=r.oid AND attnum>0 AND NOT attisdropped)),'{}'::jsonb) FROM ("
        fields += "SELECT c.oid,n.nspname,c.relname "+ROW_RELATIONS+" ORDER BY n.nspname,c.relname LIMIT "+str(RELATION_LIMIT+1)+") r)"
    statements = [r'\set ON_ERROR_STOP on', 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;',
        "SELECT jsonb_build_object("+fields+") FROM ("+CATALOG_SQL+") AS c(witness);",
        "SELECT jsonb_build_object('kind','inventory','tables',witness) FROM ("+LEDGERS_SQL+") AS i(witness);"]
    for schema, name in sorted(expected):
        require(NAME.fullmatch(schema) and NAME.fullmatch(name))
        statements.append("SELECT jsonb_build_object('kind','ledger','schema','"+schema+"','name','"+name+
            "','sha256',encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)::text),'[]'::jsonb)::text,'UTF8')),'hex')) FROM \""+
            schema+'"."'+name+'" m;')
    statements.append('COMMIT;')
    return ('\n'.join(statements)+'\n').encode()


def _database_snapshot(docker, base, database, expected, *, detailed=False):
    args = ['exec', '--interactive', *base[1:], '--dbname', database, '--file=-']
    output = _text(docker, args, stdin_bytes=_database_script(expected, detailed=detailed))
    records = [json.loads(line) for line in output.splitlines()]
    require(len(records) == 2+len(expected) and all(type(row) is dict for row in records))
    catalog, inventory, *ledgers = records
    require(set(catalog) == {'kind', 'sha256', 'supported'} | ({'row_inventory'} if detailed else set())
            and catalog['kind'] == 'catalog' and catalog['supported'] is True
            and isinstance(catalog['sha256'], str) and SHA.fullmatch(catalog['sha256']))
    require(set(inventory) == {'kind', 'tables'} and inventory['kind'] == 'inventory' and type(inventory['tables']) is list)
    names = []
    for row in inventory['tables']:
        require(type(row) is dict and set(row) == {'schema', 'name'}
                and all(isinstance(value, str) and NAME.fullmatch(value) for value in row.values()))
        names.append((row['schema'], row['name']))
    require(len(names) == len(set(names)) and set(names) == expected, 'Migration ledger inventory differs from reviewed profile')
    values = {}
    for row in ledgers:
        require(set(row) == {'kind', 'schema', 'name', 'sha256'} and row['kind'] == 'ledger'
                and (row['schema'], row['name']) in expected and isinstance(row['sha256'], str) and SHA.fullmatch(row['sha256']))
        key = row['schema']+'.'+row['name'];require(key not in values);values[key] = row['sha256']
    require(len(values) == len(expected))
    raw = json.dumps(values, sort_keys=True, separators=(',', ':')).encode()
    result = {'catalog_sha256': catalog['sha256'], 'migration_sha256': hashlib.sha256(raw).hexdigest()}
    if detailed:
        validate_row_inventory(catalog['row_inventory'], expected)
        result.update(migration_ledgers=values, row_inventory=catalog['row_inventory'])
    return result


def _postgres_base(items, project):
    postgres = owned_role(items, project, 'postgres')
    environment = postgres['Config'].get('Env', [])
    require(type(environment) is list and all(isinstance(row, str) for row in environment))
    users = [row[len('POSTGRES_USER='):] for row in environment if row.startswith('POSTGRES_USER=')]
    require(len(users) == 1 and NAME.fullmatch(users[0]))
    return ['exec', '--user', 'postgres', '--env', PG_OPTIONS, postgres['Id'], 'psql', '--no-psqlrc',
            '--no-password', '--quiet', '--tuples-only', '--no-align', '--username', users[0]]


ROW_LIMIT = 2048
RELATION_LIMIT = 256
ROW_RELATIONS = """FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
AND c.relkind IN ('r','p','m','S')"""
ROW_UNSUPPORTED = """EXISTS(SELECT 1 FROM pg_foreign_table)
OR EXISTS(SELECT 1 FROM pg_largeobject_metadata)
OR EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid
JOIN pg_namespace tn ON tn.oid=t.typnamespace WHERE a.attnum>0 AND NOT a.attisdropped
AND a.attrelid IN (SELECT c.oid """ + ROW_RELATIONS + ") AND tn.nspname <> 'pg_catalog')"


def _retained_rows_script():
    # PostgreSQL quotes catalog identifiers with %I and values with %L. No
    # caller/artifact text becomes SQL. One read-only MVCC transaction retains
    # every SQL column. Composite text preserves array bounds and raw JSON text
    # that to_jsonb(row) loses. Custom output types and large objects are refused;
    # canonical session settings bind built-in output. Values stay in PostgreSQL.
    inventory = "SELECT n.nspname AS schema,c.relname AS name " + ROW_RELATIONS
    return (r'\set ON_ERROR_STOP on' + '\n'
        'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n'
        "SET LOCAL TimeZone='UTC'; SET LOCAL DateStyle='ISO,YMD'; SET LOCAL IntervalStyle='postgres';\n"
        "SET LOCAL bytea_output='hex'; SET LOCAL extra_float_digits=3; SET LOCAL lc_monetary='C';\n"
        "SELECT jsonb_build_object('kind','inventory','supported',NOT(" + ROW_UNSUPPORTED + "),"
        "'tables',coalesce(jsonb_agg(to_jsonb(t) ORDER BY schema,name),'[]'::jsonb)) FROM ("
        + inventory + ' LIMIT ' + str(RELATION_LIMIT+1) + ') t;\n'
        "SELECT format($owned$SELECT jsonb_build_object('kind','rows','schema',%L,'name',%L,"
        "'rows',count(*),'sha256',encode(sha256(convert_to(coalesce("
        "jsonb_agg(t::text ORDER BY t::text COLLATE \"C\"),'[]'::jsonb)::text,'UTF8')),'hex')) "
        'FROM (SELECT * FROM %I.%I LIMIT ' + str(ROW_LIMIT+1) + ') t;$owned$,'
        'n.nspname,c.relname,n.nspname,c.relname) ' + ROW_RELATIONS + ' AND NOT(' + ROW_UNSUPPORTED + ')'
        + ' ORDER BY n.nspname,c.relname LIMIT ' + str(RELATION_LIMIT+1)
        + '\n' + r'\gexec' + '\nCOMMIT;\n').encode()


def retained_rows_snapshot(docker, items, project, *, profile=LedgerProfile()):
    """Bounded application rows/sequences, not permission to change any row.

    Full transition admission must compare this complete inventory alongside
    the separately qualified narrow migration/startup witnesses and catalog.
    This probe cannot choose exclusions or execute migrations.
    """
    require(type(profile) is LedgerProfile)
    base = _postgres_base(items, project)
    output = _text(docker, [base[0], '--interactive', *base[1:], '--dbname',
        profile.application, '--file=-'], stdin_bytes=_retained_rows_script())
    records = [json.loads(line) for line in output.splitlines()]
    require(2 <= len(records) <= RELATION_LIMIT+1 and all(type(row) is dict for row in records))
    inventory, *rows = records
    require(set(inventory) == {'kind', 'supported', 'tables'} and inventory['kind'] == 'inventory'
            and inventory['supported'] is True and type(inventory['tables']) is list)
    names = []
    for entry in inventory['tables']:
        require(type(entry) is dict and set(entry) == {'schema', 'name'}
                and all(type(value) is str and NAME.fullmatch(value) for value in entry.values()))
        names.append((entry['schema'], entry['name']))
    require(0 < len(names) <= RELATION_LIMIT and names == sorted(set(names)) and len(rows) == len(names))
    result = {}
    for row, expected in zip(rows, names):
        require(set(row) == {'kind', 'schema', 'name', 'rows', 'sha256'} and row['kind'] == 'rows'
                and (row['schema'], row['name']) == expected and type(row['rows']) is int
                and 0 <= row['rows'] <= ROW_LIMIT and type(row['sha256']) is str and SHA.fullmatch(row['sha256']))
        result['.'.join(expected)] = {key: row[key] for key in ('rows', 'sha256')}
    return {'schema': 'marty.windows-retained-application-rows/v1',
            'database': profile.application, 'tables': result}


MUTABLE_TABLES = {
    'credential_template': ('credential_template_service.credential_templates', ('claims', 'version', 'updated_at')),
    'issuance_application': ('issuance_service.application_templates', ('claim_collection_rules', 'management_version', 'updated_at')),
    'wallets': ('credential_template_service.wallet_registry', ('updated_at',)),
    'destinations': ('credential_template_service.delivery_destinations', ('updated_at',)),
    'issuer': ('trust_profile_service.issuer_entities', ('updated_at',)),
    'roles': ('organization_service.roles', ('updated_at',)),
    'deployment': ('deployment_profile_service.deployment_profiles', ('updated_at',)),
}


def _mutable_scope(membership_before, startup_before):
    import selfhost_windows_product_schema as membership
    import selfhost_windows_product_startup as startup
    membership.validate_before(membership_before);startup.validate_before(startup_before)
    return {name: {'table': table, 'excluded': list(excluded),
            'keys': (membership_before if name in membership.TABLES else startup_before)[name]['eligible_id_sha256'],
            'rows': (membership_before if name in membership.TABLES else startup_before)[name]['row_count']}
            for name, (table, excluded) in MUTABLE_TABLES.items()}


def _mutable_rows_script(scope):
    # Catalog identifiers are quoted by PostgreSQL, including unknown columns.
    # Only validated fixed-length hashes become values. Unsupported custom
    # output types prevent command generation, before evaluating physical rows.
    statements = [r'\set ON_ERROR_STOP on', 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;',
        "SET LOCAL TimeZone='UTC'; SET LOCAL DateStyle='ISO,YMD'; SET LOCAL IntervalStyle='postgres';",
        "SET LOCAL bytea_output='hex'; SET LOCAL extra_float_digits=3; SET LOCAL lc_monetary='C';",
        "SELECT jsonb_build_object('kind','support','supported',NOT("+ROW_UNSUPPORTED+"));"]
    for name, entry in sorted(scope.items()):
        schema, table = entry['table'].split('.')
        excluded = 'ARRAY['+','.join("'"+key+"'" for key in entry['excluded'])+']::text[]'
        keys = '{'+','.join(entry['keys'])+'}'
        statements.append("SELECT format($owned$SELECT jsonb_build_object('kind','rows','table',%L,"
            "'rows',count(*),'masked',count(*) FILTER(WHERE selected),'columns',%L::jsonb,'excluded',%L::jsonb,"
            "'sha256',encode(sha256(convert_to(coalesce(jsonb_agg(payload ORDER BY payload COLLATE \"C\"),"
            "'[]'::jsonb)::text,'UTF8')),'hex')) FROM (SELECT "
            "encode(sha256(convert_to(t.id::text,'UTF8')),'hex')=ANY(%L::text[]) AS selected,"
            "CASE WHEN encode(sha256(convert_to(t.id::text,'UTF8')),'hex')=ANY(%L::text[]) "
            "THEN ROW(%s)::text ELSE t::text END AS payload FROM (SELECT * FROM %I.%I LIMIT "
            +str(ROW_LIMIT+1)+") t) physical;$owned$,'"+entry['table']+"',"
            "coalesce(jsonb_agg(attname ORDER BY attnum) FILTER(WHERE NOT(attname=ANY("+excluded+"))),'[]'::jsonb)::text,"
            "coalesce(jsonb_agg(attname ORDER BY attname) FILTER(WHERE attname=ANY("+excluded+")),'[]'::jsonb)::text,"
            "'"+keys+"','"+keys+"',string_agg(format('t.%I',attname),',' ORDER BY attnum) "
            "FILTER(WHERE NOT(attname=ANY("+excluded+"))),'"+schema+"','"+table+"') "
            "FROM pg_attribute WHERE attrelid=to_regclass('"+entry['table']+"') AND attnum>0 AND NOT attisdropped "
            "HAVING count(*)>0 AND NOT("+ROW_UNSUPPORTED+")\n"+r'\gexec')
    statements.append('COMMIT;')
    return ('\n'.join(statements)+'\n').encode()


def retained_mutable_rows_snapshot(docker, items, project, membership_before, startup_before, *, profile=LedgerProfile()):
    """Physical retention outside exactly qualified mutable fields/cohorts.

    This supplements, never replaces, the semantic migration/startup witnesses.
    Selected rows omit only the fixed modified fields; every other physical
    column remains typed SQL text. Unselected rows retain the whole SQL row.
    Values never leave PostgreSQL. Catalog/type equality and quiescence are
    separate requirements, and this fingerprint grants no mutation authority.
    """
    require(type(profile) is LedgerProfile)
    scope = _mutable_scope(membership_before, startup_before)
    base = _postgres_base(items, project)
    output = _text(docker, [base[0], '--interactive', *base[1:], '--dbname', profile.application,
                           '--file=-'], stdin_bytes=_mutable_rows_script(scope))
    records = [json.loads(line) for line in output.splitlines()]
    require(len(records) == len(scope)+1 and all(type(row) is dict for row in records))
    supported, *rows = records
    require(supported == {'kind': 'support', 'supported': True} and supported['supported'] is True)
    values = {}
    for row, (name, entry) in zip(rows, sorted(scope.items())):
        require(set(row) == {'kind', 'table', 'rows', 'masked', 'columns', 'excluded', 'sha256'}
                and row['kind'] == 'rows' and row['table'] == entry['table']
                and type(row['rows']) is int and row['rows'] == entry['rows']
                and type(row['masked']) is int and row['masked'] == len(entry['keys'])
                and type(row['columns']) is list and row['columns'] and 'id' in row['columns']
                and all(type(column) is str and column for column in row['columns'])
                and len(row['columns']) == len(set(row['columns']))
                and not set(row['columns']) & set(entry['excluded'])
                and row['excluded'] == sorted(entry['excluded'])
                and type(row['sha256']) is str and SHA.fullmatch(row['sha256']))
        values[entry['table']] = {key: row[key] for key in ('rows', 'masked', 'columns', 'sha256')}
    return {'schema': 'marty.windows-retained-mutable-rows/v1', 'database': profile.application,
            'scope_sha256': hashlib.sha256(json.dumps(scope, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'tables': values}


def refuse_pending_product_migrations(docker, items, project, admitted, *, profile=LedgerProfile()):
    """Require the reviewed image-only baseline before any product intent/write.

    Presence is not migration qualification: the full catalog/ledger equality,
    native custody and runtime checks remain mandatory. This is an early
    negative check, not a migration executor or an authorization to preapply SQL.
    """
    # A source SHA is not a schema contract. Later descendants carry these
    # migrations too; a new SHA must never bypass this baseline. Until the full
    # schema owner is qualified, even an older candidate cannot use this tool to
    # transition a pre-baseline database. Never preapply SQL to satisfy the gate.
    require(type(admitted) is dict and type(admitted.get('backend')) is dict
            and type(admitted['backend'].get('source_sha')) is str
            and re.fullmatch(r'[0-9a-f]{40}', admitted['backend']['source_sha']))
    require(type(profile) is LedgerProfile)
    sql = """SELECT jsonb_build_object(
        'credential_template', EXISTS (SELECT 1 FROM credential_template_service.rust_schema_versions
            WHERE version='rust_credential_template_0003'),
        'issuance', EXISTS (SELECT 1 FROM issuance_service.rust_schema_migrations
            WHERE version='0012_membership_achievement_criteria'),
        'trust_profile', EXISTS (SELECT 1 FROM trust_profile_service.native_migrations
            WHERE version='trust-profile-credential-authority-v1'),
        'authority_relation', to_regclass('trust_profile_service.credential_authority_revisions') IS NOT NULL
    )"""
    observed = docker.json([*_postgres_base(items, project), '--dbname', profile.application, '--command', sql])
    require(type(observed) is dict and set(observed) == {
        'credential_template', 'issuance', 'trust_profile', 'authority_relation'}
        and all(type(value) is bool for value in observed.values()), 'Migration presence observation malformed')
    require(all(observed.values()),
            'Product requires unapplied schema migrations; qualify a schema transition before recreation')


def schema_snapshot(docker, items, project, *, profile=LedgerProfile()):
    return _schema_snapshot(docker, items, project, profile=profile, detailed=False)


def detailed_schema_snapshot(docker, items, project, *, profile=LedgerProfile()):
    """Retain each ledger's digest alongside its existing aggregate.

    This v4 witness is for a full schema owner, not the v1 image-only journal.
    Its same-transaction ordered relation/column inventory must bind retained
    row proofs. Older v3 receipts lack that inventory and are not reinterpreted.
    Both forms use the same transactions and drift refusal. Legacy snapshots
    keep exactly their former shape and meaning.
    """
    return _schema_snapshot(docker, items, project, profile=profile, detailed=True)


def quiescence_snapshot(docker, items, project, *, profile=LedgerProfile()):
    """Refuse remaining PostgreSQL writers; never stop or disconnect anyone.

    The execution owner must also keep its exact runtime writer cohort stopped
    and repeat this check at write boundaries. Zero observations do not prevent
    future connections by an external administrator, nor grant SQL admission.
    Client counts cover the whole cluster, including idle/default-DB clients.
    Prepared transactions, subscriptions, replication sessions and unreviewed
    background workers must also be absent. Only built-in maintenance types
    are exempt; logical/parallel apply and extension workers are not exempt.
    """
    require(type(profile) is LedgerProfile)
    postgres = owned_role(items, project, 'postgres')
    base = _postgres_base(items, project)
    observations = []
    deadline = time.monotonic()+65
    for _index in range(2):
        require(time.monotonic() < deadline)
        value = json.loads(_text(docker, [*base, '--dbname', 'postgres', '--command', QUIESCENCE_SQL]))
        require(type(value) is dict and set(value) == {'database_clock', 'primary', 'databases',
            'client_backends', 'prepared_transactions', 'replication_backends', 'subscriptions', 'unqualified_backends'})
        require(value['primary'] is True and type(value['databases']) is list
                and all(type(name) is str for name in value['databases'])
                and len(value['databases']) == len(set(value['databases']))
                and set(value['databases']) == set(profile.tables))
        require(all(type(value[key]) is int and value[key] == 0
                    for key in ('client_backends', 'prepared_transactions', 'replication_backends',
                                'subscriptions', 'unqualified_backends')),
                'Database is not quiescent; retain the guarded attempt')
        require(type(value['database_clock']) is str)
        clock = datetime.datetime.fromisoformat(value['database_clock'].replace('Z', '+00:00'))
        require(clock.year > 1 and clock.tzinfo is not None)
        require(not observations or clock >= datetime.datetime.fromisoformat(
            observations[-1]['database_clock'].replace('Z', '+00:00')))
        observations.append(value)
    require(time.monotonic() < deadline)
    return {'schema': 'marty.windows-postgres-quiescence/v1', 'project': project,
            'postgres_id': postgres['Id'], 'observations': observations,
            'product_transition_admission': False, 'native_admission': False}


def _schema_snapshot(docker, items, project, *, profile, detailed):
    """Coherent per-DB transactions, bracketed by equal full observations.

    PostgreSQL has no shared snapshot across databases. The owning transition
    must hold its project lock/quiesce its own DDL writers; these observations
    refuse drift but do not prevent an external administrator's future DDL.
    """
    require(type(profile) is LedgerProfile)
    deadline = time.monotonic()+60
    base = _postgres_base(items, project)
    def observe():
        require(time.monotonic() < deadline)
        databases = docker.json([*base, '--dbname', 'postgres', '--command', DATABASES_SQL])
        require(type(databases) is list and all(isinstance(name, str) for name in databases)
                and len(databases) == len(set(databases)) and set(databases) == set(profile.tables))
        result = {}
        for database, expected in sorted(profile.tables.items()):
            require(time.monotonic() < deadline)
            result[database] = _database_snapshot(docker, base, database, expected, detailed=detailed)
        require(time.monotonic() < deadline)
        return result
    first = observe();second = observe()
    require(first == second, 'Schema changed during compatibility observation')
    return {'schema': 'marty.windows-postgres-schema/v4' if detailed else SCHEMA,
            'probe': 'catalog-and-source-ledger-profile/v4' if detailed else PROBE,
            'profile': PROFILE_ID, 'consistency': CONSISTENCY,
            'database_roles': {'application': profile.application, 'keycloak': profile.keycloak, 'applicants': profile.applicants},
            'databases': second}


def _text(docker, args, *, stdin_bytes=None):
    pipe = {'stdin': subprocess.DEVNULL} if stdin_bytes is None else {'input': stdin_bytes}
    result = subprocess.run([*docker.prefix, *args], capture_output=True, timeout=30, **pipe)
    require(result.returncode == 0 and len(result.stdout) <= 65536)
    return result.stdout.decode('utf-8').strip()


def provider_snapshot(docker, items, project, ca_file):
    """Public TLS health and immutable binary fingerprints; not native admission."""
    from selfhost_windows_inputs import hold_private_input
    bao = owned_role(items, project, 'openbao')
    ports = bao.get('NetworkSettings', {}).get('Ports', {}).get('8200/tcp')
    require(type(ports) is list and len(ports) == 1 and ports[0].get('HostIp') == '127.0.0.1'
            and isinstance(ports[0].get('HostPort'), str) and ports[0]['HostPort'].isdigit()
            and 1 <= int(ports[0]['HostPort']) <= 65535)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):return None
    with hold_private_input(Path(ca_file)) as ca:
        context = ssl.create_default_context(cadata=ca.decode('ascii'))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
        with opener.open('https://127.0.0.1:'+ports[0]['HostPort']+'/v1/sys/health', timeout=15) as response:
            require(response.status == 200)
            raw = response.read(65537);require(len(raw) <= 65536)
    status = json.loads(raw)
    require(type(status) is dict and status.get('initialized') is True and status.get('sealed') is False and status.get('version') == '2.5.5'
            and isinstance(status.get('cluster_id'), str)
            and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', status['cluster_id']))
    text = _text(docker, ['exec', '--user', '65534:65534', bao['Id'], 'sha256sum', *BINARY_PATHS.values()])
    hashes = {}
    for line in text.splitlines():
        fields = line.split()
        require(len(fields) == 2 and SHA.fullmatch(fields[0]) and fields[1] in BINARY_PATHS.values() and fields[1] not in hashes)
        hashes[fields[1]] = fields[0]
    require(set(hashes) == set(BINARY_PATHS.values()))
    version = _text(docker, ['exec', '--user', '65534:65534', bao['Id'], '/bin/bao', 'version'])
    require(version.startswith('OpenBao v2.5.5 ') and '\n' not in version)
    return {'schema': 'marty.windows-provider-custody/v1', 'cluster_id': status['cluster_id'],
            'ca_sha256': hashlib.sha256(ca).hexdigest(), 'bao_version': version,
            **{key: hashes[path] for key, path in BINARY_PATHS.items()}}
