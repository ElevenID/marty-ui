"""Real NTFS ancestry and record parsing; synthetic subjects are not admission.

No deployment entry point or fresh signature verification is simulated here.
"""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path[:0] = [str(Path(__file__).resolve().parents[1]/'scripts'), str(Path(__file__).resolve().parent)]
import selfhost_windows_product_journal as journal
import selfhost_windows_product as product
import selfhost_windows_product_probe as probe
import selfhost_windows_selection as selection
import selfhost_windows_continuation as continuation
from test_selfhost_windows_selection import fixture
from test_windows_product_transition import runtime_candidate


@contextmanager
def installed(monkeypatch):
    with fixture(monkeypatch) as (root, phase, tx, outcome, path, config):
        before, after, old_model, new_model, admitted, ids = runtime_candidate(root)
        # Real metadata parser, deliberately unsigned synthetic payloads. Only
        # verified_package may authorize a fresh deployment of actual artifacts.
        admitted.update(producer={'repository': product.composition.ui.REPOSITORY,
            'workflow': product.composition.ui.WORKFLOW, 'source_sha': '1'*40,
            'ref': 'refs/heads/main', 'run_id': '1', 'run_attempt': '1'},
            route_contract={'version': 1, 'sha256': 'sha256:'+'2'*64}, website={}, backend={},
            qualification={'runtime_tested': False, 'billing_journey_tested': False},
            files={name: {'sha256': 'sha256:'+'3'*64, 'bytes': 1} for name in product.composition.PAYLOAD_NAMES})
        admitted['composition_id'] = product.composition.ui.digest(product.composition.ui.canonical(admitted))
        product.composition.validate_record(admitted)
        hashes = {'old': {}, 'new': {}}
        for side, rows, value in [('old', before, '3'*64), ('new', after, '4'*64)]:
            for item in rows:
                role = product.renewal._service(item)
                if role in product.HISTORICAL_ROLES:continue
                hashes[side][role] = value
                item['Config']['Labels']['com.docker.compose.config-hash'] = value
        model_path = Path(config['compose_file'])
        model_path.write_bytes(selection.packed(old_model))
        config['compose_sha256'] = selection.digest(model_path.read_bytes())
        path.write_bytes(selection.packed(config))
        edge = product.checked_runtime_change(before, after, old_model, new_model, admitted, ids,
                                                       expected_project=config['project'])
        phase['data'] = edge['before_sha256']
        selection.adopt(path)
        attempt = root/('windows-product-'+'1'*32);attempt.mkdir()
        target = root/('.'+config['project']+'.generation-product-'+'2'*32)
        new_path = model_path.with_name('product.compose.json');new_path.write_bytes(selection.packed(new_model))
        binding = {'compose_file': str(new_path), 'compose_sha256': selection.digest(new_path.read_bytes())}
        new_config = journal.successor_configuration(config, binding, attempt)
        (attempt/'activation').mkdir()
        for key in ('intent', 'result', 'new_log', 'rollback_log'):Path(new_config[key]).write_bytes(b'')
        for step in new_config['step_receipts']:
            for receipt in step.values():Path(receipt).write_bytes(b'')
        (attempt/'config.private.json').write_bytes(selection.packed(new_config))
        (attempt/'inputs').mkdir()
        for name in journal.ARTIFACTS:
            (attempt/'inputs'/name).write_bytes(selection.packed(admitted) if name == 'web-composition.json' else b'PUBLIC_SYNTHETIC_SUBJECT')
        profile = probe.LedgerProfile()
        schema = {'schema': probe.SCHEMA, 'probe': probe.PROBE, 'profile': probe.PROFILE_ID, 'consistency': probe.CONSISTENCY,
                  'database_roles': {'application': profile.application, 'keycloak': profile.keycloak, 'applicants': profile.applicants},
                  'databases': {name: {'catalog_sha256': 'b'*64, 'migration_sha256': 'c'*64 if tables else selection.digest(b'{}')}
                                for name, tables in profile.tables.items()}}
        provider = {'schema': 'marty.windows-provider-custody/v1', 'cluster_id': '00000000-0000-0000-0000-000000000001',
                    'bao_version': 'OpenBao v2.5.5 synthetic', **{key: 'd'*64 for key in
                    ('ca_sha256', 'plugin_sha256', 'unseal_sha256', 'ready_sha256', 'bao_sha256')}}
        phases = {'before.json': selection.packed(before), 'after.json': selection.packed(after),
                  'schema-before.json': selection.packed(schema), 'schema-after.json': selection.packed(schema),
                  'provider-before.json': selection.packed(provider), 'provider-after.json': selection.packed(provider),
                  'admission.json': selection.packed({'schema': journal.SCHEMA, 'composition_id': admitted['composition_id'],
                                                    'subjects_verified': True, 'images_verified': True}), 'new.log': b'PUBLIC_SYNTHETIC_LOG'}
        with selection._session(path) as (_cfg, _cfg_raw, expected, source, raw, stack):
            previous = dict(raw)
            _first, record, generation = journal.anchor(raw, expected)
            marker = {'schema': journal.SCHEMA, 'project': config['project'], 'engine_id': config['engine_id'],
                'source_dir': str(source), 'target_dir': str(target),
                'source_sha256': {name: selection.digest(body) for name, body in raw.items()},
                'selection_sequence': record['sequence'], 'generation_sequence': generation,
                'selection_sha256': selection.digest(raw[f'{record["sequence"]:06}.selection.json']),
                'selected_sha256': selection.digest(selection.packed(record['selected'])),
                'old': {'compose_file': str(model_path), 'compose_sha256': config['compose_sha256']}, 'new': binding,
                'attempt_dir': str(attempt), 'config_sha256': selection.digest((attempt/'config.private.json').read_bytes()),
                'composition_sha256': {name: selection.digest((attempt/'inputs'/name).read_bytes()) for name in journal.ARTIFACTS},
                'image_ids': ids, 'configuration_hashes': hashes,
                'native': expected['native'], 'native_mirror': record['selected']['native_mirror'],
                'minimum_ttl': config['native']['minimum_ttl'],
                'data_before_sha256': edge['before_sha256'], 'data_after_sha256': edge['after_sha256'],
                'observations_before_sha256': selection.digest(phases['before.json']),
                'schema_before_sha256': selection.digest(phases['schema-before.json']),
                'provider_before_sha256': selection.digest(phases['provider-before.json']), 'candidate_only': True}
            phases['intent.json'] = selection.packed(marker)
            for side in ('before', 'after'):
                for event in ('started', 'completed'):
                    phases[f'native-{side}.{event}.json'] = selection.packed({'schema': journal.SCHEMA,
                        'operation': 'native-current', 'side': side, 'event': event, 'native': marker['native'],
                        'native_mirror': marker['native_mirror'], 'minimum_ttl': marker['minimum_ttl'],
                        'selected_sha256': marker['selected_sha256']})
            phases['result.json'] = selection.packed({'schema': journal.SCHEMA, 'project': config['project'],
                'result': 'product-transitioned', 'generation_sequence': generation, 'selected_sha256': marker['selected_sha256'],
                'data_sha256': edge['after_sha256'], 'composition_id': admitted['composition_id'], 'credential_rotation': False})
            change = product.checked_model_change(old_model, new_model, admitted)
            layers = product.renewal.dependency_layers(new_model, set(new_model['services'])-product.renewal.INITIALIZERS,
                                                               set(change['mutable_roles']))
            for index, layer in enumerate(layers):
                for event in ('started', 'completed'):
                    phases[f'{index:03}.{event}.json'] = selection.packed({'index': index, 'roles': layer, 'event': event})
            for name, body in phases.items():(attempt/name).write_bytes(body)
            phase_hashes = {name: selection.digest(body) for name, body in phases.items()}
            selection._append(source, raw, journal.INTENT, marker, stack)
            journal.validate_marker(raw, expected, marker['old'], source)
            initial = journal.seed(raw, expected, marker['old'], marker, phase_hashes, stack)
            target.mkdir()
            for name, body in initial.items():(target/name).write_bytes(body)
            selection._append(source, raw, journal.DECISION, journal.decision(marker, initial, phase_hashes), stack)
        phase['data'] = edge['after_sha256']
        yield {'root': root, 'path': path, 'config': config, 'new_config': new_config, 'source': source,
               'target': target, 'attempt': attempt, 'marker': marker, 'previous': previous, 'initial': initial,
               'phase': phase, 'tx': tx, 'outcome': outcome}


def test_product_successor_retains_credential_identity_and_every_predecessor_byte(monkeypatch):
    with installed(monkeypatch) as data:
        state = selection.status(data['path'])
        previous = selection.decode(data['previous']['000001.selection.json'])
        assert state['selected'] == previous['selected']
        assert state['generation_sequence'] == 1 and state['sequence'] == 1 and state['decision'] == 'product-selected-new'
        assert all((data['source']/name).read_bytes() == body for name, body in data['previous'].items())
        with selection.selected_inputs(data['path']) as lease:
            assert lease.compose_file == Path(data['new_config']['compose_file'])
            assert lease.check_current() == data['phase']['data']
            assert lease.generation_sequence == 1


@pytest.mark.parametrize('target', ['subject', 'model', 'phase', 'schema', 'provider', 'config', 'credential-output', 'seed'])
def test_changed_retained_product_evidence_refuses_without_falling_back(monkeypatch, target):
    with installed(monkeypatch) as data:
        paths = {'subject': data['attempt']/'inputs/web-composition.zip', 'model': Path(data['new_config']['compose_file']),
                 'phase': data['attempt']/'000.completed.json', 'schema': data['attempt']/'schema-after.json',
                 'provider': data['attempt']/'provider-after.json', 'config': data['attempt']/'config.private.json',
                 'credential-output': Path(data['new_config']['result']), 'seed': data['target']/'000001.selection.json'}
        paths[target].write_bytes(b'PUBLIC_TAMPER')
        with pytest.raises((ValueError, KeyError)):
            selection.status(data['path'])
        assert all((data['source']/name).read_bytes() == body for name, body in data['previous'].items())


def test_pending_product_does_not_admit_predecessor_or_ordinary_continuation(monkeypatch):
    with installed(monkeypatch) as data:
        # Isolated synthetic metadata only; preserve the decision for cleanup.
        decision = data['source']/journal.DECISION
        saved = decision.read_bytes();decision.unlink()
        try:
            with pytest.raises(ValueError):selection.status(data['path'])
            guard = product.renewal.product_transition_guard(data['config'])
            guard.write_bytes(selection.packed(data['marker']))
            with pytest.raises(ValueError):
                with selection.selected_inputs(data['path']):pytest.fail('Pending product admitted ordinary lease')
            with selection._session(data['path'], _pending_product_sha256=selection.digest(guard.read_bytes())) as session:
                assert session[3] == data['source']
            assert guard.exists()
        finally:decision.write_bytes(saved)


def test_ordinary_continuation_after_product_cannot_relabel_the_runtime_edge_as_rotation(monkeypatch):
    with installed(monkeypatch) as data:
        class Docker:
            def containers(self):return []
        def inspect(_config, _choice, _values, _stack, *, expected_data, require_ready):
            assert expected_data == data['marker']['data_after_sha256'] and require_ready is False
            return {'docker': Docker(), 'baseline': []}
        monkeypatch.setattr(selection, '_inspect', inspect)
        prior = selection.status(data['path'])
        with selection.selected_inputs(data['path']) as lease:
            result = lease.continue_journal()
        state = selection.status(data['path'])
        assert state['generation_sequence'] == prior['generation_sequence'] == result['generation_sequence'] == 1
        assert state['selected'] == prior['selected'] and state['decision'] == 'continued-new'
        assert (data['source']/journal.DECISION).exists() and (data['target']/continuation.DECISION).exists()


def test_next_credential_prepare_uses_new_data_binding_with_original_selected_credentials(monkeypatch):
    with installed(monkeypatch) as data:
        next_path, config = data['tx'](2)
        config.update(data['marker']['new'])
        next_path.write_bytes(selection.packed(config))
        assert selection.prepare(next_path) == 2
        with ExitStack() as stack:
            raw = selection._read(data['target'], stack)
        first = selection.decode(raw['000001.selection.json'])
        pending = selection.decode(raw['000002.intent.json'])
        assert first['data_sha256'] == data['marker']['data_after_sha256']
        assert pending['inputs']['old'] == first['selected']
        assert pending['operation'] == 'activation' and first['decision'] == 'product-selected-new'


@pytest.mark.parametrize('fault', ['empty-schema', 'unknown-probe', 'empty-databases', 'provider-flag', 'provider-version'])
def test_matching_phase_hashes_do_not_admit_empty_or_unknown_compatibility_witness(monkeypatch, fault):
    with installed(monkeypatch) as data:
        marker = deepcopy(data['marker'])
        category = 'provider' if fault.startswith('provider') else 'schema'
        witness = selection.decode((data['attempt']/(category+'-before.json')).read_bytes())
        if fault == 'empty-schema':witness = {}
        elif fault == 'unknown-probe':witness['probe'] = 'unqualified'
        elif fault == 'empty-databases':witness['databases'] = {}
        elif fault == 'provider-flag':witness = {'verified': True}
        else:witness['bao_version'] = 'OpenBao v3.0.0 synthetic'
        body = selection.packed(witness)
        for side in ('before', 'after'):(data['attempt']/(category+'-'+side+'.json')).write_bytes(body)
        marker[category+'_before_sha256'] = selection.digest(body)
        (data['attempt']/'intent.json').write_bytes(selection.packed(marker))
        decision = selection.decode((data['source']/journal.DECISION).read_bytes())
        hashes = {name: selection.digest((data['attempt']/name).read_bytes()) for name in decision['phase_sha256']}
        with ExitStack() as stack, pytest.raises(ValueError):journal.hold_transition(marker, hashes, stack)


@pytest.mark.parametrize('fault', ['ttl', 'mirror', 'source', 'selected'])
def test_rehashed_native_completion_cannot_substitute_different_custody_or_lifetime(monkeypatch, fault):
    with installed(monkeypatch) as data:
        path = data['attempt']/'native-after.completed.json'
        witness = selection.decode(path.read_bytes())
        if fault == 'ttl':witness['minimum_ttl'] = 1
        elif fault == 'mirror':witness['native_mirror'] = '/control/other/generation'
        elif fault == 'source':witness['native']['source_sha'] = 'f'*40
        else:witness['selected_sha256'] = 'f'*64
        path.write_bytes(selection.packed(witness))
        decision = selection.decode((data['source']/journal.DECISION).read_bytes())
        hashes = {name: selection.digest((data['attempt']/name).read_bytes()) for name in decision['phase_sha256']}
        with ExitStack() as stack, pytest.raises(ValueError):journal.hold_transition(data['marker'], hashes, stack)
