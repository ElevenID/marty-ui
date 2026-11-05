"""Read-only compatibility witnesses for an owned Windows product transition.

These probes neither authorize a deployment nor replace native signer/token
custody admission. No password, token, row data or private key is returned.
Postgres computes catalog/ledger hashes inside read-only sessions; its ordinary
application rows are not copied, backed up or migrated by these probes.
"""
import hashlib
import json
from pathlib import Path
import re
import ssl
import subprocess
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
)::text,'UTF8')),'hex'))"""
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


def schema_snapshot(docker, items, project):
    postgres = owned_role(items, project, 'postgres')
    environment = postgres['Config'].get('Env', [])
    require(type(environment) is list and all(isinstance(row, str) for row in environment))
    users = [row[len('POSTGRES_USER='):] for row in environment if row.startswith('POSTGRES_USER=')]
    require(len(users) == 1 and NAME.fullmatch(users[0]))
    base = ['exec', '--user', 'postgres', '--env', PG_OPTIONS, postgres['Id'], 'psql', '--no-psqlrc',
            '--no-password', '--quiet', '--tuples-only', '--no-align', '--username', users[0]]
    def query(database, sql):
        require(isinstance(database, str) and NAME.fullmatch(database))
        return docker.json([*base, '--dbname', database, '--command', sql])
    databases = query('postgres', DATABASES_SQL)
    require(type(databases) is list and 1 <= len(databases) <= 32
            and all(isinstance(name, str) and NAME.fullmatch(name) for name in databases)
            and len(set(databases)) == len(databases))
    result = {};observed_ledger = False
    for database in sorted(databases):
        catalog = query(database, CATALOG_SQL)
        require(isinstance(catalog, str) and SHA.fullmatch(catalog))
        ledgers = query(database, LEDGERS_SQL)
        require(type(ledgers) is list and len(ledgers) <= 64)
        values = {}
        for ledger in ledgers:
            require(type(ledger) is dict and set(ledger) == {'schema', 'name'}
                    and all(isinstance(value, str) and NAME.fullmatch(value) for value in ledger.values()))
            # Names come from the read-only catalog query, never shell text.
            table = '"'+ledger['schema']+'"."'+ledger['name']+'"'
            require(table not in values)
            sql = "SELECT to_json(encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)::text),'[]'::jsonb)::text,'UTF8')),'hex')) FROM "+table+' m'
            value = query(database, sql)
            require(isinstance(value, str) and SHA.fullmatch(value))
            values[table] = value
        observed_ledger |= bool(values)
        raw = json.dumps(values, sort_keys=True, separators=(',', ':')).encode()
        result[database] = {'catalog_sha256': catalog, 'migration_sha256': hashlib.sha256(raw).hexdigest()}
    require(observed_ledger, 'No migration ledger was witnessed')
    return {'schema': 'marty.windows-postgres-schema/v1', 'probe': 'catalog-and-migration-ledger/v1', 'databases': result}


def _text(docker, args):
    result = subprocess.run([*docker.prefix, *args], capture_output=True, timeout=30)
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
