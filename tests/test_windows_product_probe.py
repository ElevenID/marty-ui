"""Compatibility probes return only fingerprints and cannot issue SQL writes."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import selfhost_windows_product_probe as probe
import selfhost_windows_inputs as inputs

PROJECT = 'marty-production-synthetic'


def item(role):
    return {'Id': 'a'*64, 'Config': {'Env': ['POSTGRES_USER=marty'], 'Labels': {
        'com.docker.compose.project': PROJECT, 'com.docker.compose.service': role}},
        'NetworkSettings': {'Ports': {'8200/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '29200'}]}}}


class Postgres:
    def __init__(self, fault=None):self.calls = [];self.fault = fault;self.rounds = {}
    def json(self, args):
        self.calls.append(args)
        assert args[:5] == ['exec', '--user', 'postgres', '--env', probe.PG_OPTIONS]
        assert '--no-password' in args and '--no-psqlrc' in args
        assert 'default_transaction_read_only=on' in args[4] and 'search_path=pg_catalog' in args[4]
        assert args[-1] == probe.DATABASES_SQL
        if self.fault == 'duplicate-database':return ['marty', 'marty']
        if self.fault == 'database-shape':return [{}]
        if self.fault == 'database-injection':return ['marty; DELETE FROM x']
        return ['keycloak', 'marty', 'marty_applicants']
    def text(self, docker, args, *, stdin_bytes):
        assert docker is self
        self.calls.append(args)
        assert args[:4] == ['exec', '--interactive', '--user', 'postgres']
        assert args[args.index('--env')+1] == probe.PG_OPTIONS and args[-1] == '--file=-'
        database = args[args.index('--dbname')+1]
        expected = probe.LedgerProfile().tables[database]
        script = stdin_bytes.decode()
        assert script.startswith('\\set ON_ERROR_STOP on\nBEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;')
        assert script.endswith('COMMIT;\n') and probe.CATALOG_SQL in script and probe.LEDGERS_SQL in script
        self.rounds[database] = self.rounds.get(database, 0)+1
        catalog = 'unexpected private data' if self.fault == 'raw-catalog' else 'b'*64
        if self.fault == 'snapshot-drift' and self.rounds[database] == 2:catalog = 'd'*64
        inventory = [{'schema': schema, 'name': name} for schema, name in sorted(expected)]
        if self.fault == 'no-ledger':inventory = []
        elif self.fault == 'ledger-injection':inventory.append({'schema': 'public', 'name': 'bad;DELETE'})
        elif self.fault in {'alembic', 'flyway'}:
            inventory.append({'schema': 'public', 'name': 'alembic_version' if self.fault == 'alembic' else 'flyway_schema_history'})
        rows = [{'kind': 'catalog', 'sha256': catalog, 'supported': self.fault not in {'foreign-table', 'event-trigger'}},
                {'kind': 'inventory', 'tables': inventory}]
        for schema, name in sorted(expected):
            assert 'FROM "'+schema+'"."'+name+'" m;' in script
            rows.append({'kind': 'ledger', 'schema': schema, 'name': name,
                         'sha256': 'unexpected private data' if self.fault == 'raw-ledger' else 'c'*64})
        return '\n'.join(json.dumps(row) for row in rows)


def test_catalog_and_ledger_rows_are_hashed_in_repeatable_read_observations(monkeypatch):
    docker = Postgres()
    monkeypatch.setattr(probe, '_text', docker.text)
    result = probe.schema_snapshot(docker, [item('postgres')], PROJECT)
    assert set(result['databases']) == {'keycloak', 'marty', 'marty_applicants'}
    assert all(probe.SHA.fullmatch(value) for row in result['databases'].values() for value in row.values())
    assert len(docker.calls) == 8 and set(docker.rounds.values()) == {2}
    assert result['consistency'] == probe.CONSISTENCY and 'unexpected private data' not in json.dumps(result)
    assert 'pg_authid' not in probe.CATALOG_SQL and 'pg_statistic' not in probe.CATALOG_SQL


@pytest.mark.parametrize('fault', ['duplicate-database', 'database-shape', 'database-injection', 'raw-catalog',
                                  'no-ledger', 'ledger-injection', 'raw-ledger', 'alembic', 'flyway', 'snapshot-drift',
                                  'foreign-table', 'event-trigger'])
def test_invalid_inventory_or_unhashed_values_never_become_schema_witness(monkeypatch, fault):
    docker = Postgres(fault);monkeypatch.setattr(probe, '_text', docker.text)
    with pytest.raises(ValueError):probe.schema_snapshot(docker, [item('postgres')], PROJECT)


@pytest.mark.parametrize('fault', ['foreign', 'duplicate', 'bad-id', 'missing-user', 'duplicate-user'])
def test_wrong_container_or_database_identity_refuses_before_exec(fault):
    rows = [item('postgres')]
    if fault == 'foreign':rows[0]['Config']['Labels']['com.docker.compose.project'] = 'other'
    elif fault == 'duplicate':rows.append(deepcopy(rows[0]))
    elif fault == 'bad-id':rows[0]['Id'] = 'unqualified'
    elif fault == 'missing-user':rows[0]['Config']['Env'] = []
    else:rows[0]['Config']['Env'].append('POSTGRES_USER=other')
    docker = Postgres()
    with pytest.raises(ValueError):probe.schema_snapshot(docker, rows, PROJECT)
    assert not docker.calls


@pytest.mark.parametrize('missing', ['credential_template', 'issuance', 'trust_profile', 'authority_relation'])
def test_known_product_source_refuses_each_missing_migration_before_admission(missing):
    class Presence:
        def json(self, args):
            assert args[:5] == ['exec', '--user', 'postgres', '--env', probe.PG_OPTIONS]
            assert args[args.index('--dbname')+1] == 'marty'
            assert '--no-password' in args and '--no-psqlrc' in args
            assert args[-1].lstrip().startswith('SELECT jsonb_build_object(')
            return {name: name != missing for name in (
                'credential_template', 'issuance', 'trust_profile', 'authority_relation')}
    with pytest.raises(ValueError, match='qualify a schema transition before recreation'):
        probe.refuse_pending_product_migrations(Presence(), [item('postgres')], PROJECT,
            {'backend': {'source_sha': 'b1723c527c1df9c2d2d8d7ed5ac02d362a96cd34'}})


@pytest.mark.parametrize('observation', [None, [], {}, {'unexpected': True},
    dict(credential_template=1, issuance=True, trust_profile=True, authority_relation=True)])
def test_migration_presence_never_accepts_missing_or_nonboolean_evidence(observation):
    class Presence:
        def json(self, _args):return observation
    with pytest.raises(ValueError):
        probe.refuse_pending_product_migrations(Presence(), [item('postgres')], PROJECT,
            {'backend': {'source_sha': 'b1723c527c1df9c2d2d8d7ed5ac02d362a96cd34'}})


def test_present_migrations_return_no_admission_and_other_sources_keep_existing_schema_checks():
    class Presence:
        def json(self, _args):
            return dict(credential_template=True, issuance=True, trust_profile=True, authority_relation=True)
    assert probe.refuse_pending_product_migrations(Presence(), [item('postgres')], PROJECT,
        {'backend': {'source_sha': 'b1723c527c1df9c2d2d8d7ed5ac02d362a96cd34'}}) is None
    # No source outside this reviewed negative check gains a migration permit.
    assert probe.refuse_pending_product_migrations(None, [], PROJECT,
        {'backend': {'source_sha': 'a'*40}}) is None


def provider(monkeypatch, fault=None):
    calls = [];ca = b'PUBLIC_SYNTHETIC_CA'
    @contextmanager
    def held(path):
        assert path == Path('synthetic-ca.pem')
        yield ca
    monkeypatch.setattr(inputs, 'hold_private_input', held)
    def context(**kwargs):
        assert kwargs == {'cadata': ca.decode()}
        return object()
    monkeypatch.setattr(probe.ssl, 'create_default_context', context)
    status = {'initialized': True, 'sealed': False, 'version': '2.5.5',
              'cluster_id': '00000000-0000-0000-0000-000000000001'}
    if fault == 'sealed':status['sealed'] = True
    elif fault == 'uninitialized':status['initialized'] = False
    elif fault == 'version':status['version'] = '3.0.0'
    elif fault == 'cluster':status['cluster_id'] = 'unknown'
    class Response:
        status = 200
        def __enter__(self):return self
        def __exit__(self, *_args):pass
        def read(self, maximum):
            assert maximum == 65537
            return b'x'*maximum if fault == 'oversize' else json.dumps(status).encode()
    class Opener:
        def open(self, url, *, timeout):
            assert url == 'https://127.0.0.1:29200/v1/sys/health' and timeout == 15
            return Response()
    def opener(*handlers):
        assert any(isinstance(handler, probe.urllib.request.ProxyHandler) and handler.proxies == {} for handler in handlers)
        redirects = [handler for handler in handlers if isinstance(handler, probe.urllib.request.HTTPRedirectHandler)]
        assert len(redirects) == 1 and redirects[0].redirect_request() is None
        return Opener()
    monkeypatch.setattr(probe.urllib.request, 'build_opener', opener)
    def text(_docker, args):
        calls.append(args)
        assert args[:4] == ['exec', '--user', '65534:65534', 'a'*64]
        if args[4] == 'sha256sum':
            value = '\n'.join('b'*64+'  '+path for path in probe.BINARY_PATHS.values())
            if fault == 'missing-binary':value = value.splitlines()[0]
            return value
        assert args[4:] == ['/bin/bao', 'version']
        return 'OpenBao v2.5.5 synthetic'
    monkeypatch.setattr(probe, '_text', text)
    return calls, ca


def test_provider_uses_verified_ca_no_proxy_or_redirect_and_only_public_probes(monkeypatch):
    calls, ca = provider(monkeypatch)
    result = probe.provider_snapshot(object(), [item('openbao')], PROJECT, 'synthetic-ca.pem')
    assert result['ca_sha256'] == hashlib.sha256(ca).hexdigest()
    assert len(calls) == 2 and all(key not in result for key in ('token', 'private_key', 'unseal_key'))


@pytest.mark.parametrize('fault', ['sealed', 'uninitialized', 'version', 'cluster', 'oversize', 'missing-binary'])
def test_bad_tls_health_or_binary_evidence_refuses(monkeypatch, fault):
    provider(monkeypatch, fault)
    with pytest.raises(ValueError):probe.provider_snapshot(object(), [item('openbao')], PROJECT, 'synthetic-ca.pem')


@pytest.mark.parametrize('ip', ['0.0.0.0', '192.0.2.1', '::'])
def test_provider_probe_never_follows_nonloopback_publication(monkeypatch, ip):
    calls, _ca = provider(monkeypatch)
    bao = item('openbao');bao['NetworkSettings']['Ports']['8200/tcp'][0]['HostIp'] = ip
    with pytest.raises(ValueError):probe.provider_snapshot(object(), [bao], PROJECT, 'synthetic-ca.pem')
    assert not calls
