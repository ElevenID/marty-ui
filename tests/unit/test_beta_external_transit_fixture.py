"""Hermetic risk controls; no provider, native-runtime or browser calls."""
import hashlib
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parents[2]/'scripts/beta_external_transit_fixture.py'
spec = importlib.util.spec_from_file_location('transit_fixture', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Provider:
    def __init__(self, scenario='D02'):
        self.calls = []
        self.exists = False
        self.policy = False
        self.revoked = False
        self.scenario = scenario
        self.bad_caps = False
        self.mint_unknown = False
        self.key_flags = {}
        self.absence_status = 404
        self.lookup_changes = {}
        self.lookup_status = 200
        self.lookup_unknown = False

    def api(self, ca, token, method, path, body=None):
        self.calls.append((method, path, body))
        if path == '/v1/sys/seal-status':
            return 200, {'sealed': False, 'cluster_id': 'actual-cluster'}
        if path == '/v1/sys/mounts':
            return 200, {'data': {'transit/': {'type': 'transit'}}}
        if path == '/v1/auth/token/create-orphan':
            if self.mint_unknown:
                raise TimeoutError('PRIVATE_PROVIDER_SECRET')
            return 200, {'auth': {'client_token': 'private-test-leaf-123456', 'accessor': 'private-accessor',
                                'policies': body['policies'], 'renewable': False, 'lease_duration': 3600}}
        if path == '/v1/auth/token/lookup-accessor':
            if self.lookup_unknown:
                raise TimeoutError('PRIVATE_PROVIDER_SECRET')
            key = self.scenario.lower()+'-external-13da81b5-e0b2-4dfd-8b28-9a38da899cba'
            return self.lookup_status, {'data': {'accessor': body['accessor'], 'policies': [key],
                                                'orphan': True, 'renewable': False, 'ttl': 3500,
                                                **self.lookup_changes}}
        if path == '/v1/auth/token/revoke-accessor':
            self.revoked = True
            return 204, {}
        if path == '/v1/sys/capabilities':
            caps = {p: (['read'] if p.startswith(('transit/keys/d02-', 'transit/keys/d10-')) else ['update'] if p.startswith('transit/sign/') else ['deny']) for p in body['paths']}
            if self.scenario == 'D10':
                for p in caps:
                    if p.endswith('-unpublished'):
                        caps[p] = ['deny']
            if self.bad_caps:
                caps['sys/mounts'] = ['read']
            return 200, {'data': caps}
        if '/sys/policies/acl/' in path:
            if method == 'PUT':
                self.policy = True
                return 204, {}
            if method == 'DELETE':
                self.policy = False
                return 204, {}
            return (200, {'data': {'policy': 'owned'}}) if self.policy else (404, {})
        if '/transit/keys/' in path:
            if self.revoked and token != b'private-test-root':
                return 403, {}
            if path.endswith('-unpublished'):
                return self.absence_status, {}
            if method == 'POST':
                self.exists = True
                return 204, {}
            if not self.exists:
                return 404, {}
            return 200, {'data': {'type': 'ecdsa-p256', 'exportable': False,
                                  'allow_plaintext_backup': False, 'latest_version': 1,
                                  'keys': {'1': {'public_key': 'public-only'}}, **self.key_flags}}
        raise AssertionError('Unexpected provider route')


class TransitFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)/'owned'
        self.provider = Provider()
        self.guard_calls = []
        self.config = {'runId': '13da81b5-e0b2-4dfd-8b28-9a38da899cba', 'scenario': 'D02',
                       'sourceSha256': m.sha(SOURCE)}
        self.ctx = {'config': self.config, 'output': self.output, 'owner': self.provider,
                    'ca': Path(self.temp.name)/'ca', 'root': b'private-test-root',
                    'phase': {'clusterId': 'actual-cluster'},
                    'key': 'd02-external-'+self.config['runId']}

    def guard(self, config, **kwargs):
        self.guard_calls.append(kwargs)
        return {'state': 'CURRENT_NATIVE_22_LIVE_VERIFIED', 'binding': 'same-actual-owner-check'}

    def provision(self):
        return m.provision(self.ctx, self.guard)

    def assert_no_success(self):
        self.assertFalse((self.output/'result.json').exists())
        self.assertFalse((self.output/'environment.json').exists())

    def test_shared_d02_d10_policy_contract(self):
        for scenario in ('D02', 'D10'):
            key = scenario.lower()+'-external-unit'
            expected = f'path "transit/keys/{key}" {{ capabilities = ["read"] }}\npath "transit/sign/{key}" {{ capabilities = ["update"] }}\n'
            if scenario == 'D02':
                expected += f'path "transit/keys/{key}-unpublished" {{ capabilities = ["read"] }}'
            self.assertEqual(m.policy_text(key), expected)
        with self.assertRaises(m.FixtureError):
            m.policy_text('other/key')

    def test_live_guard_precedes_any_provider_call(self):
        def deny(*args, **kwargs):
            raise m.FixtureError('CURRENT_NATIVE_RUNTIME_REFUSED')
        with self.assertRaisesRegex(m.FixtureError, 'CURRENT_NATIVE_RUNTIME_REFUSED'):
            m.provision(self.ctx, deny)
        self.assertEqual(self.provider.calls, [])

    def test_cluster_drift_refuses_before_writes(self):
        self.ctx['phase']['clusterId'] = 'foreign'
        with self.assertRaisesRegex(m.FixtureError, 'KMS_CLUSTER_CHANGED'):
            self.provision()
        self.assertTrue(all(c[0] == 'GET' for c in self.provider.calls))

    def test_owned_collision_refuses_no_mint(self):
        self.provider.exists = True
        with self.assertRaisesRegex(m.FixtureError, 'OWNED_RESOURCE_NOT_ABSENT'):
            self.provision()
        self.assertTrue(all(c[0] == 'GET' for c in self.provider.calls))

    def test_nonexportable_key_contract(self):
        self.provider.key_flags['exportable'] = True
        with self.assertRaisesRegex(m.FixtureError, 'OWNED_KEY_METADATA_CHANGED'):
            self.provision()
        self.assertFalse(any(c[1].endswith('create-orphan') for c in self.provider.calls))
        self.assert_no_success()

    def test_http_denial_is_not_unpublished_absence(self):
        self.provider.absence_status = 403
        with self.assertRaisesRegex(m.FixtureError, 'OWNED_RESOURCE_NOT_ABSENT'):
            self.provision()
        self.assert_no_success()

    def test_unknown_mint_preserves_intent_without_fake_custody(self):
        self.provider.mint_unknown = True
        with self.assertRaises(TimeoutError):
            self.provision()
        journal = json.loads((self.output/'custody.json').read_bytes())
        self.assertEqual(journal['mintState'], 'UNKNOWN_UNTIL_OBSERVED')
        self.assertEqual(journal['pending'], 'TOKEN_MINT')
        self.assertIsNone(journal['accessor'])
        self.assertFalse((self.output/'token.txt').exists())
        self.assert_no_success()
        before = list(self.provider.calls)
        with self.assertRaises(FileExistsError):
            self.provision()
        self.assertEqual(self.provider.calls, before)

    def test_scope_failure_retains_exact_accessor_for_revoke(self):
        self.provider.bad_caps = True
        with self.assertRaisesRegex(m.FixtureError, 'SCOPED_CAPABILITIES_CHANGED'):
            self.provision()
        self.assertEqual(json.loads((self.output/'custody.json').read_bytes())['accessor'], 'private-accessor')
        self.assertTrue((self.output/'token.txt').exists())
        self.assert_no_success()
        result = m.revoke(self.ctx, self.guard)
        self.assertTrue(result['oldScopedTokenDenied'])
        self.assertEqual((self.output/'token.txt').read_bytes(), b'0'*24)

    def test_real_absence_scope_and_before_after_contract(self):
        result = self.provision()
        self.assertEqual(len(self.guard_calls), 2)
        self.assertEqual(result['freshUnpublishedKeyControl']['httpStatus'], 404)
        self.assertFalse(result['demoQualified'])
        self.assertNotIn('rootAuthorityLeftKms', result)
        self.assertNotIn('private-test', json.dumps(result))
        create = next(c for c in self.provider.calls if c[0] == 'POST' and '/transit/keys/' in c[1])
        self.assertEqual(create[2], {'type': 'ecdsa-p256', 'exportable': False, 'allow_plaintext_backup': False})

    def test_d10_unpublished_capability_stays_denied(self):
        self.provider.scenario = self.config['scenario'] = 'D10'
        self.ctx['key'] = 'd10-external-'+self.config['runId']
        result = self.provision()
        self.assertEqual(result['capabilities']['transit/keys/'+self.ctx['key']+'-unpublished'], ['deny'])
        self.assertIsNone(result['freshUnpublishedKeyControl'])

    def test_after_guard_drift_never_publishes_environment(self):
        def drift(*args, **kwargs):
            self.guard_calls.append(kwargs)
            return {'binding': len(self.guard_calls)}
        with self.assertRaisesRegex(m.FixtureError, 'CURRENT_NATIVE_RUNTIME_CHANGED'):
            m.provision(self.ctx, drift)
        self.assert_no_success()
        self.assertTrue((self.output/'token.txt').exists())

    def test_revoke_denial_and_policy_absence_keep_key_lineage(self):
        self.provision()
        result = m.revoke(self.ctx, self.guard)
        self.assertTrue(result['nonexportableKeyRetained'])
        self.assertTrue(self.provider.exists)
        self.assertFalse(self.provider.policy)
        self.assertTrue(self.provider.revoked)
        self.assertNotIn('private-test-leaf', (self.output/'environment.json').read_text())
        self.assertTrue((self.output/'environment.retired.json').exists())
        self.assertFalse(any(c[0] == 'DELETE' and '/transit/keys/' in c[1] for c in self.provider.calls))

    def test_wrong_run_and_replaced_bearer_refuse_before_revoke(self):
        self.provision()
        self.config['runId'] = 'foreign'
        previous = len(self.provider.calls)
        with self.assertRaisesRegex(m.FixtureError, 'EXACT_CUSTODY_REQUIRED'):
            m.revoke(self.ctx, self.guard)
        self.assertEqual(len(self.provider.calls), previous)
        self.config['runId'] = '13da81b5-e0b2-4dfd-8b28-9a38da899cba'
        (self.output/'token.txt').write_bytes(b'replaced-user-data')
        with self.assertRaisesRegex(m.FixtureError, 'TOKEN_CUSTODY_CHANGED'):
            m.revoke(self.ctx, self.guard)
        self.assertFalse(self.provider.revoked)

    def test_replaced_environment_is_not_erased(self):
        self.provision()
        (self.output/'environment.json').write_bytes(b'user replacement')
        with self.assertRaisesRegex(m.FixtureError, 'ENVIRONMENT_CUSTODY_CHANGED'):
            m.revoke(self.ctx, self.guard)
        self.assertEqual((self.output/'environment.json').read_bytes(), b'user replacement')
        self.assertFalse(self.provider.revoked)

    def test_raw_provider_exception_is_not_public_diagnostic(self):
        result = m.safe_failure(TimeoutError('PRIVATE_PROVIDER_SECRET'))
        self.assertEqual(result['code'], 'EXTERNAL_TRANSIT_OPERATION_FAILED')
        self.assertNotIn('SECRET', json.dumps(result))

    def test_observed_mint_body_is_private_and_retired(self):
        self.provision()
        response_file = self.output/'mint-response.private.json'
        self.assertIn(b'private-test-leaf', response_file.read_bytes())
        m.revoke(self.ctx, self.guard)
        self.assertNotIn(b'private-test-leaf', response_file.read_bytes())

    def test_genuine_membership_limits_are_checked_not_environment(self):
        observation = {'schema': 'marty.windows-job-observation/v1', 'controllerPid': m.os.getpid(),
                       'controllerMemberVerified': True, 'inspectorMemberVerified': True,
                       'queryOpenedJobHandle': True, 'queryHandleClosed': True,
                       'controllerQueryHandleClosed': True, 'queryAccessMask': 4,
                       'queryHandleInheritable': False, 'jobMemoryBytes': m.MEMORY,
                       'activeProcessLimit': 32, 'limitFlags': 0x2208}
        with patch.object(m, 'bound', return_value=Path('unused-helper')), patch.object(m.subprocess, 'run') as run:
            run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps(observation).encode())
            self.assertEqual(m.require_job({'jobHelper': {'sha256': m.JOB_SHA}}), observation)
            for field, value in [('controllerMemberVerified', False), ('jobMemoryBytes', m.MEMORY//2), ('queryHandleInheritable', True)]:
                changed = dict(observation, **{field: value})
                run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps(changed).encode())
                with self.subTest(field=field), self.assertRaisesRegex(m.FixtureError, 'GENUINE_JOB_LIMITS_CHANGED'):
                    m.require_job({'jobHelper': {'sha256': m.JOB_SHA}})

    def test_short_intent_write_stops_before_provider_mutation(self):
        real_fdopen = m.os.fdopen

        class ShortIntentStream:
            def __init__(self, fd, mode):
                self.stream = real_fdopen(fd, mode)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return self.stream.__exit__(*args)
            def write(self, data):
                if b'"pending": "KEY_CREATE"' in data:
                    return self.stream.write(data[:-1])
                return self.stream.write(data)
            def flush(self):
                return self.stream.flush()
            def fileno(self):
                return self.stream.fileno()

        with patch.object(m.os, 'fdopen', ShortIntentStream):
            with self.assertRaisesRegex(m.FixtureError, 'CUSTODY_SHORT_WRITE'):
                self.provision()
        self.assertTrue(all(call[0] == 'GET' for call in self.provider.calls))
        self.assertNotEqual(json.loads((self.output/'custody.json').read_bytes()).get('pending'), 'KEY_CREATE')
        self.assertTrue((self.output/'custody.next').exists())
        self.assert_no_success()

    def test_known_mint_token_publication_failure_can_be_explicitly_revoked(self):
        durable = m.durable_new
        def fail_token(file, value):
            if Path(file).name == 'token.txt':
                raise OSError('test publication denied')
            return durable(file, value)
        with patch.object(m, 'durable_new', fail_token):
            with self.assertRaises(OSError):
                self.provision()
        self.assert_no_success()
        token_file = self.output/'token.txt'
        self.assertFalse(token_file.exists())
        journal = json.loads((self.output/'custody.json').read_bytes())
        self.assertEqual(journal['mintState'], 'OBSERVED')
        self.assertEqual(journal['accessor'], 'private-accessor')
        self.assertEqual(m.sha(self.output/'mint-response.private.json'), journal['mintResponseSha256'])
        # An existing replacement must never be bypassed via response fallback.
        token_file.write_bytes(b'foreign-file-retain-me')
        with self.assertRaisesRegex(m.FixtureError, 'TOKEN_CUSTODY_CHANGED'):
            m.revoke(self.ctx, self.guard)
        self.assertEqual(token_file.read_bytes(), b'foreign-file-retain-me')
        self.assertFalse(self.provider.revoked)
        token_file.unlink()  # Remove only the test-owned replacement fixture.
        result = m.revoke(self.ctx, self.guard)
        self.assertTrue(result['tokenRevoked'])
        self.assertTrue(result['oldScopedTokenDenied'])
        self.assertTrue(result['policyDeleted'])
        self.assertFalse(token_file.exists())
        self.assertTrue(self.provider.exists)
        self.assertNotIn(b'private-test-leaf', (self.output/'mint-response.private.json').read_bytes())
        self.assert_no_success()

    def test_missing_bearer_fallback_does_not_adopt_unknown_or_changed_response(self):
        self.provision()
        token_file = self.output/'token.txt'
        token_file.unlink()
        response = self.output/'mint-response.private.json'
        original = response.read_bytes()
        response.write_bytes(original+b' ')
        with self.assertRaisesRegex(m.FixtureError, 'MINT_CUSTODY_CHANGED'):
            m.revoke(self.ctx, self.guard)
        self.assertFalse(self.provider.revoked)
        response.write_bytes(original)
        journal_file = self.output/'custody.json'
        journal = json.loads(journal_file.read_bytes())
        journal['mintState'] = 'UNKNOWN_UNTIL_OBSERVED'
        journal_file.write_bytes(m.encoded(journal))
        with self.assertRaisesRegex(m.FixtureError, 'UNKNOWN_MINT_REQUIRES_RECONCILIATION'):
            m.revoke(self.ctx, self.guard)
        self.assertFalse(self.provider.revoked)
        self.assertFalse(token_file.exists())

    def test_ready_receipt_has_actual_utc_lookup_remaining_ttl(self):
        started = datetime.now(timezone.utc)
        result = self.provision()
        ended = datetime.now(timezone.utc)
        observed = datetime.fromisoformat(result['observedAtUtc'])
        self.assertLessEqual(started, observed)
        self.assertLessEqual(observed, ended)
        self.assertEqual(observed.utcoffset().total_seconds(), 0)
        self.assertEqual(result['ttlSeconds'], 3500)
        self.assertEqual(result['mintLeaseSeconds'], 3600)
        self.assertTrue(result['accessorMatched'])
        self.assertTrue(result['orphan'])
        self.assertFalse(result['renewable'])
        self.assertEqual(m.sha(self.output/'grant-lookup.private.json'), result['lookupResponseSha256'])
        self.assertNotIn('private-accessor', json.dumps(result))
        self.assertEqual(sum(c[1].endswith('/lookup-accessor') for c in self.provider.calls), 1)

    def test_expired_or_foreign_lookup_refuses_publication_but_allows_revoke(self):
        for changes in ({'ttl': 0}, {'ttl': True}, {'ttl': 3601}, {'policies': ['foreign']},
                        {'accessor': 'foreign-accessor'}, {'orphan': False}, {'renewable': True}):
            with self.subTest(changes=changes):
                self.output = Path(self.temp.name)/('case-'+str(len(list(Path(self.temp.name).iterdir()))))
                self.ctx['output'] = self.output
                self.provider = Provider()
                self.ctx['owner'] = self.provider
                self.provider.lookup_changes = changes
                with self.assertRaisesRegex(m.FixtureError, 'GRANT_LOOKUP_NOT_READY'):
                    self.provision()
                self.assert_no_success()
                self.assertTrue((self.output/'grant-lookup.private.json').exists())
                self.assertTrue(m.revoke(self.ctx, self.guard)['oldScopedTokenDenied'])

    def test_unknown_lookup_never_becomes_ready_and_retains_revoke_custody(self):
        self.provider.lookup_unknown = True
        with self.assertRaises(TimeoutError):
            self.provision()
        self.assert_no_success()
        self.assertEqual(json.loads((self.output/'custody.json').read_bytes())['mintState'], 'OBSERVED')
        self.assertTrue(m.revoke(self.ctx, self.guard)['oldScopedTokenDenied'])

    def test_input_composes_existing_authority_preflight_only(self):
        artifact = Path(self.temp.name)/'bound.json'
        artifact.write_bytes(b'{}')
        ref = {'path': str(artifact), 'sha256': m.sha(artifact)}
        fake_owner = SimpleNamespace(inputs=lambda value, mode: (self.assertEqual(mode, 'preflight') or
                                    ({'clusterId': 'actual-cluster'}, artifact, b'root-in-memory-only', 'unused-svc-policy', artifact)))
        config = dict(self.config, schema=m.SCHEMA, executeAuthorized=True, outputDir=str(self.output),
                      authorityOwner={'sha256': m.OWNER_SHA}, kmsAuthorityInput=ref, jobHelper=ref,
                      runtime={'recorderRevision': 'a'*40, 'observation': ref, 'profile': ref,
                               'dockerTransport': ref, 'dockerCanary': ref, 'nodeExecutable': ref,
                               'sourceFiles': {'owner': ref}})
        # Keep the production private-root rule; only the test's home is private.
        with patch.object(m.Path, 'home', return_value=Path(self.temp.name)), patch.object(m, 'load_owner', return_value=fake_owner), patch.object(m, 'JOB_SHA', ref['sha256']):
            private = Path(self.temp.name)/'.codex/private'
            private.mkdir(parents=True)
            config['outputDir'] = str(private/'new-output')
            ctx = m.inputs(config, 'provision')
            self.assertEqual(ctx['root'], b'root-in-memory-only')
            self.assertEqual(ctx['key'], 'd02-external-'+self.config['runId'])
            self.assertFalse(ctx['output'].exists())
            self.assertEqual(self.provider.calls, [])

    def test_bound_source_and_owner_refusals_have_no_network(self):
        with self.assertRaisesRegex(m.FixtureError, 'AUTHORITY_OWNER_CHANGED'):
            m.load_owner({'sha256': '0'*64})
        with self.assertRaisesRegex(m.FixtureError, 'OPERATOR_SOURCE_CHANGED'):
            m.inputs({'schema': m.SCHEMA, 'sourceSha256': '0'*64}, 'provision')
        with self.assertRaisesRegex(m.FixtureError, 'MUTATION_NOT_ARMED'):
            m.inputs({'schema': m.SCHEMA, 'sourceSha256': m.sha(SOURCE)}, 'provision')
        self.assertEqual(self.provider.calls, [])


if __name__ == '__main__':
    unittest.main()
