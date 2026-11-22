"""NTFS website owner publication using a real guarded history and synthetic runtime."""
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest

from tests.test_package_web_composition import candidate as candidate
from tests.test_selfhost_windows_selection import fixture
from tests.test_windows_website_plan import planned, rehash
import selfhost_windows_website as website
import selfhost_windows_website_owner as owner

selection, store, forward, renewal = owner.selection, owner.store, owner.forward, owner.renewal
digest = forward.contract.digest


def prepare(planned, root, original, config, *, combined_runtime=None):
    config['tls_init_receipt'] = {'synthetic': 'historical-tls'}
    original.write_bytes(selection.packed(config))
    selection.adopt(original)
    source = selection.directory(config)
    raw = {path.name: path.read_bytes() for path in source.iterdir()}
    expected = selection.binding(config)
    _intents, records = selection._parse(raw, expected)
    record = records[1]
    source_model = {key: config[key] for key in ('compose_file', 'compose_sha256')}
    model_bytes = Path(source_model['compose_file']).read_bytes()
    plan = forward.contract.plan(**planned)
    attempt = root / ('windows-website-' + 'a'*32)
    plan['attempt_directory'], plan['route_directory'] = str(attempt), str(attempt / 'routes')
    plan['owner'] = {
        'project': config['project'], 'engine_id': config['engine_id'], 'docker_host': config['docker_host'],
        'root': str(root), 'selection_sequence': 1, 'generation_sequence': 1,
        'binding_sha256': digest(expected), 'journal_sha256': digest({name: selection.digest(body) for name,body in raw.items()}),
        'configuration_sha256': selection.digest(original.read_bytes()), 'selection_sha256': selection.digest(raw['000001.selection.json']),
        'selected_sha256': digest(record['selected']), 'native_sha256': digest(expected['native']),
        'historical_tls_sha256': digest(config['tls_init_receipt']), 'data_sha256': record['data_sha256'],
        'model_sha256': digest(selection.decode(model_bytes)),
    }
    plan['states']['combined'].update(data_sha256=record['data_sha256'], model_sha256=plan['owner']['model_sha256'])
    plan['backout']['preserved_selected_sha256'] = plan['owner']['selected_sha256']
    assets = root / 'assets'
    assets.mkdir()
    for name in plan['proof_sha256']:
        body = name.encode()
        plan['proof_sha256'][name] = selection.digest(body)
        (assets / name).write_bytes(body)
    split = root / ('website-' + 'a'*32 + '.compose.json')
    split.write_bytes(selection.packed(selection.decode(model_bytes)))
    model = {'compose_file': str(split), 'compose_sha256': selection.digest(split.read_bytes())}
    candidate_id = 'a'*64
    candidate_row = {'project': config['project'], 'service': forward.contract.SLOT, 'image': 'sha256:' + 'a'*64,
                     'mounts': [], 'status': 'running'}
    runtime = ([{'synthetic': 'runtime'}] if combined_runtime is None
               else {**combined_runtime, candidate_id: candidate_row})
    if combined_runtime is not None:
        plan['states']['split']['data_sha256'] = digest(forward.edge._retained_data(runtime))
    rehash(plan)
    routing = {'synthetic': 'edge-configuration'}
    with ExitStack() as held:
        status = owner.guard.initialize(config, plan, held)
        guard_pin = status['guard_sha256']
        for phase in store.journal.FORWARD[:-1]:
            started = {key: 'a'*64 for key in store.journal.START_EVIDENCE}
            if phase == 'stage-candidate' and combined_runtime is not None:
                before = dict.fromkeys(store.journal.START_EVIDENCE)
                before['runtime_before'] = combined_runtime
                started = forward.stage._evidence(attempt / 'stage-before.json', before, held)
            status = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=phase, event='started',
                evidence_sha256=started)
            after = ({key: {} for key in store.journal.COMPLETION_EVIDENCE[phase]} | {'runtime_after': runtime})
            if phase == 'stage-candidate' and combined_runtime is not None:
                after['candidate_health'] = {'container_id': candidate_id}
            if phase == 'route-website':
                after.update(mounted_template=plan['edge_template'], edge_configuration=routing)
            filename = 'stage-after.json' if phase == 'stage-candidate' else phase + '-after.json'
            evidence = forward.stage._evidence(attempt / filename, after, held)
            status = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=phase,
                                  event='completed', evidence_sha256=evidence)
        _, _, retained = forward._retain_successor(config, model, attempt, assets, plan,
                {**status, 'guard_sha256': guard_pin}, record, {'old': ({}, {}), 'new': ({}, {})}, held)
        candidate_pin = digest(retained)
        native = {key: plan['owner'][key] for key in ('native_sha256', 'selected_sha256')}
        qualification = {'schema': forward.SCHEMA, 'candidate_sha256': candidate_pin, 'runtime_sha256': digest(runtime),
            'public_routes_sha256': 'b'*64, 'anonymous_handoff_sha256': 'c'*64, **native,
            'authenticated_account_sha256': 'd'*64, 'authenticated_organization_sha256': 'e'*64,
            'foreign_storage_sha256': None, 'foreign_storage_changes': 0, 'authenticated_application': {
                'account_matched': True, 'organization_matched': True, 'authenticated_application_exercised': True}}
        qualification_pin = digest(qualification)
        forward.stage._material(attempt / ('forward-qualification-' + qualification_pin + '.json'), qualification, held)
        foreign = {'engine_id': config['engine_id'], 'inventory_sha256': 'b'*64, 'changes_sha256': None, 'changes': 0}
        start = {'owner_lease': {'owner':plan['owner'], 'guard_sha256': guard_pin}, 'native_custody': native,
                 'foreign_storage': foreign, 'runtime_before': {'containers': runtime, 'edge_configuration': routing}}
        end = {'runtime_after': runtime, 'native_custody': native, 'foreign_storage': foreign,
               'successor_candidate': {'candidate_sha256': candidate_pin, 'qualification_sha256': qualification_pin}}
        verified = status['anchor_sha256']
        for event, filename, evidence in [('started', 'before', start), ('completed', 'after', end)]:
            status = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase='seal-forward', event=event,
                evidence_sha256=forward.stage._evidence(attempt / f'seal-forward-{filename}.json', evidence, held))
    pins = {'terminal_sha256': status['anchor_sha256'], 'candidate_sha256': candidate_pin,
            'qualification_sha256': qualification_pin}
    return source, raw, plan, guard_pin, pins, split, verified


@pytest.mark.parametrize('fault', [None, 'wrong-tail', 'changed-source', 'changed-seal', 'changed-proof',
                                  'changed-candidate', 'premature-activation', 'live-check', 'rename-interrupted'])
def test_forward_guarded_selection_checks_and_resumes_exact_publication(planned, monkeypatch, capsys, fault):
    with fixture(monkeypatch) as (root, phase, _tx, _outcome, path, config):
        source, starting, plan, guard_pin, pins, split, verified = prepare(planned, root, path, config)
        phase['data'] = plan['states']['split']['data_sha256']
        check_calls = []
        attempt = Path(plan['attempt_directory'])

        def check_live(bound, choice, _values, selected, link, _stack):
            assert bound['compose_file'] == config['compose_file'] and choice == selected['choice'] == 'new'
            assert link['terminal_sha256'] == pins['terminal_sha256']
            check_calls.append('qualified')
            if fault == 'live-check':
                raise ValueError('Fixture refused live admission')

        options = {'guard_sha256': guard_pin, 'check_live': check_live, **pins}
        if fault == 'wrong-tail':
            options['terminal_sha256'] = verified
        elif fault == 'changed-source':
            path.write_bytes(path.read_bytes() + b' ')
        elif fault == 'changed-seal':
            (attempt / 'seal-forward-after.json').write_bytes(b'{}')
        elif fault == 'changed-proof':
            (attempt / 'successor/proofs/web-composition.zip').write_bytes(b'bad')
        elif fault == 'changed-candidate':
            split.write_bytes(b'{}')
        elif fault == 'premature-activation':
            (attempt / 'successor/activation/credential-result.json').write_bytes(b'changed')

        if fault == 'rename-interrupted':
            @contextmanager
            def interrupt(candidate_path, **kwargs):
                if kwargs.get('_rename_to') == source / owner.DECISION:
                    raise RuntimeError('Interrupted before commit rename')
                with hold(candidate_path, **kwargs) as evidence:
                    yield evidence

            hold = owner._held_private_input
            with monkeypatch.context() as injected:
                injected.setattr(owner, '_held_private_input', interrupt)
                with pytest.raises(RuntimeError, match='Interrupted before commit rename'):
                    owner.finish(path, plan, **options)
            assert (source / owner.PENDING).is_file() and not (source / owner.DECISION).exists()
            with pytest.raises(ValueError):
                with selection._session(path, _pending_website_sha256=guard_pin):
                    pytest.fail('A dangling link cannot fall back to the old selection')
            options['intent_sha256'] = selection.digest((source / owner.INTENT).read_bytes())
            with pytest.raises(ValueError):
                owner.finish(path, plan, **dict(options, intent_sha256='e'*64))
        elif fault:
            with pytest.raises(ValueError):
                owner.finish(path, plan, **options)
            assert not (source / owner.INTENT).exists()
            assert check_calls == (['qualified'] if fault == 'live-check' else [])
            return

        if fault is None:
            verified_prefix = store.forward_verification_prefix(plan, expected_anchor_sha256=pins['terminal_sha256'])
            assert verified_prefix['anchor_sha256'] == verified
            qualification_file = attempt / ('forward-qualification-' + pins['qualification_sha256'] + '.json')
            qualification = selection.decode(qualification_file.read_bytes())

            def qualify(bound, choice, _values, selected, supplied_plan, status, *, candidate_status, **_options):
                assert supplied_plan == plan and status['anchor_sha256'] == pins['terminal_sha256']
                assert candidate_status == {**verified_prefix, 'guard_sha256': guard_pin}
                check_live(bound, choice, None, selected, {'terminal_sha256': status['anchor_sha256']}, None)
                return attempt / 'successor', qualification, [], {}, []

            monkeypatch.setattr(forward, '_qualify', qualify)
            args = ['--publish-forward', '--selection-file', str(path),
                    '--plan-file', str(attempt / 'journal' / store.PLAN), '--composition-dir', str(root / 'assets'),
                    '--gh', str(root / 'gh'), '--cosign', str(root / 'cosign'), '--guard-sha256', guard_pin,
                    '--expected-anchor-sha256', pins['terminal_sha256'], '--session-state-file', str(root / 'session.json'),
                    '--expected-account-sha256', 'd'*64, '--expected-organization-sha256', 'e'*64,
                    '--candidate-sha256', pins['candidate_sha256'], '--qualification-sha256', pins['qualification_sha256']]
            assert website.main([*args, '--intent-sha256', 'wrong-pin']) == 2
            captured = capsys.readouterr()
            assert not captured.out and captured.err == website.FORWARD_ERROR + '\n'
            assert check_calls == []
            assert website.main(args) == 0
            captured = capsys.readouterr()
            assert not captured.err
            result = selection.decode(captured.out.encode())
        else:
            result = owner.finish(path, plan, **options)
        assert check_calls == ['qualified'] * (2 if fault == 'rename-interrupted' else 1)
        assert result['generation_sequence'] == 1 and result['guards_retained'] is True
        assert result['selected_sha256'] == digest(selection.decode(starting['000001.selection.json'])['selected'])
        assert {name:(source/name).read_bytes() for name in starting} == starting
        assert (source / owner.DECISION).is_file() and not (source / owner.PENDING).exists()
        assert renewal.product_transition_guard(config).is_file()
        target = Path(result['journal'])
        with selection._session(path, _pending_website_sha256=guard_pin) as (_, _, binding, active, raw, _stack):
            assert active == target and binding['compose_file'] == str(split)
            _, records = selection._parse(raw, binding)
            assert records[1]['decision'] == 'website-selected-new'
            assert records[1]['data_sha256'] == plan['states']['split']['data_sha256']
        with pytest.raises(ValueError):
            selection.status(path)
        repeated = owner.finish(path, plan, **dict(options, intent_sha256=result['intent_sha256']))
        assert repeated == result
        (target / 'checkpoint.json').write_bytes(b'{}')
        with pytest.raises(ValueError):
            with selection._session(path, _pending_website_sha256=guard_pin):
                pytest.fail('A changed target checkpoint cannot be selected')


@pytest.mark.parametrize('fault', [None, 'changed-split', 'missing-decision', 'wrong-intent'])
def test_published_backout_binds_actual_selected_split(monkeypatch, planned, capsys, fault):
    import selfhost_windows_website_backout as backout

    with fixture(monkeypatch) as (root, phase, _tx, _outcome, path, config):
        source, original_records, plan, guard_pin, pins, split, _verified = prepare(planned, root, path, config)
        phase['data'] = plan['states']['split']['data_sha256']
        options = {'assets': root/'assets', 'gh': None, 'cosign': None, 'registry_config': None}
        committed = owner.finish(path, plan, guard_sha256=guard_pin, **pins, check_live=lambda *_: None)
        intent = committed['intent_sha256']
        attempt = Path(plan['attempt_directory'])
        target = Path(committed['journal'])
        old_choice = selection.decode(original_records['000001.selection.json'])['choice']
        calls = []

        def run(combined, choice, _values, selected, active_plan, status, step, *, held, **kwargs):
            assert combined['compose_file'] == config['compose_file'] and choice == old_choice
            assert selected['data_sha256'] == plan['owner']['data_sha256']
            assert active_plan == plan and status['guard_sha256'] == guard_pin
            calls.append(step)
            start_value = {key: {} for key in store.journal.START_EVIDENCE}
            start_value['owner_lease'] = {'owner': plan['owner'], 'guard_sha256': guard_pin}
            if step == 'restore-combined':
                binding = status['published_selection']
                assert binding == {'intent_sha256': intent, 'selection_sha256': selection.digest((source / owner.DECISION).read_bytes()),
                                   'sealed_anchor_sha256': pins['terminal_sha256'],
                                   'split_selection_sha256': selection.digest((target / '000001.selection.json').read_bytes())}
                start_value['owner_lease']['published_selection'] = binding
            start = forward.stage._evidence(attempt / (step + '-before.json'), start_value, held)
            started = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=step, event='started',
                                   evidence_sha256=start)
            if step == 'retire-candidate':
                started = store.append(plan, expected_anchor_sha256=started['anchor_sha256'], phase=step,
                                       event=store.journal.RETIRE_RETURNED, evidence_sha256={'candidate_retirement':'a'*64})
            end = {key: 'a'*64 for key in store.journal.COMPLETION_EVIDENCE[step]}
            return store.append(plan, expected_anchor_sha256=started['anchor_sha256'], phase=step,
                                event='completed', evidence_sha256=end)

        monkeypatch.setattr(forward.edge, 'run', run)
        monkeypatch.setattr(forward.verify, 'run', run)
        monkeypatch.setattr(backout, 'run', run)
        if fault == 'changed-split':
            (target / '000001.selection.json').write_bytes(b'{}')
        elif fault == 'missing-decision':
            (source / owner.DECISION).rename(source / owner.PENDING)

        args = ['--backout-published', '--selection-file', str(path),
                '--composition-dir', str(root/'assets'), '--gh', str(root/'gh'), '--cosign', str(root/'cosign'),
                '--plan-file', str(attempt/'journal'/store.PLAN), '--guard-sha256', guard_pin,
                '--intent-sha256', 'a'*64 if fault == 'wrong-intent' else intent,
                '--backout-phase', 'restore-combined', '--expected-anchor-sha256', pins['terminal_sha256']]
        if fault:
            assert website.main(args) == 2
            output = capsys.readouterr()
            assert not output.out and output.err == website.BACKOUT_ERROR + '\n'
            assert not calls
            assert store.inspect(plan, expected_anchor_sha256=pins['terminal_sha256'])['classification'] == 'forward-evidence-complete'
            return
        with pytest.raises(ValueError):
            selection.backout_published_website(path, plan, guard_sha256=guard_pin, intent_sha256=intent,
                expected_anchor_sha256=pins['terminal_sha256'], backout_phase='verify-combined', **options)
        assert website.main(args) == 0
        response = capsys.readouterr()
        assert not response.err
        result = selection.decode(response.out.encode())
        assert result['guards_retained'] and result['anchor_sha256'] != pins['terminal_sha256']
        assert result['published_intent_sha256'] == intent

        assert website.main(args) == 2
        capsys.readouterr()
        with selection._session(path, _pending_website_sha256=guard_pin) as (_, _, binding, active, _, _stack):
            assert active == target and binding['compose_file'] == str(split)
        for step in ('verify-combined', 'retire-candidate'):
            result = selection.backout_published_website(path, plan, guard_sha256=guard_pin, intent_sha256=intent,
                expected_anchor_sha256=result['anchor_sha256'], backout_phase=step, **options)
        assert calls == list(store.journal.BACKOUT)
        assert result['classification'] == 'combined-backout-evidence-complete'
        assert set(original_records) <= {item.name for item in source.iterdir()}
        assert renewal.product_transition_guard(config).exists()
        with pytest.raises(ValueError):
            selection.release_website_backout(path, plan, guard_sha256=guard_pin,
                                             expected_anchor_sha256=result['anchor_sha256'], **options)
        (attempt / 'seal-forward-after.json').write_bytes(b'{}')
        with pytest.raises(ValueError):
            with selection._session(path, _pending_website_sha256=guard_pin):
                pytest.fail('Backout cannot disguise damage to the committed forward seal')


def _retire_published(plan, published, guard_pin, anchor, combined_runtime, *, readmission=None):
    import selfhost_windows_website_backout as retirement

    attempt = Path(plan['attempt_directory'])
    with ExitStack() as held:
        routed = store.read_evidence(plan, expected_anchor_sha256=anchor, held=held,
            references={'stage-after.json': ('stage-candidate', 'completed')})['stage-after.json']
        candidate_id = routed['candidate_health']['container_id']
        staged = routed['runtime_after']
        status = store.inspect(plan, expected_anchor_sha256=anchor)

        def append(phase, event, name, observations):
            nonlocal status
            evidence = forward.stage._evidence(attempt / name, observations, held)
            status = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=phase,
                                  event=event, evidence_sha256=evidence)

        lease = {'owner': plan['owner'], 'guard_sha256': guard_pin}
        start = {'owner_lease': lease, 'native_custody': {}, 'foreign_storage': {}, 'runtime_before': {}}
        routes = {'synthetic': 'combined-overlay'}
        restored = {**start, 'owner_lease': {**lease, 'published_selection': published}}
        if readmission is not None:
            restored['runtime_before'] = readmission
        append('restore-combined', 'started', 'restore-combined-before.json', restored)
        append('restore-combined', 'completed', 'restore-combined-after.json',
               {'runtime_after': staged, 'mounted_template': plan['edge_template'], 'edge_configuration': routes})
        append('verify-combined', 'started', 'verify-combined-before.json', start)
        append('verify-combined', 'completed', 'verify-combined-after.json',
               {'runtime_after': staged, 'public_routes': {}, 'application_handoffs': {}})
        normalized_model = {'sha256': plan['owner']['model_sha256']}
        custody = {'candidate_id': candidate_id, 'observed_candidate': staged[candidate_id],
                   'remove_command': ['container', 'rm', candidate_id]}
        append(retirement.PHASE, 'started', retirement.BEFORE,
               {**start, 'runtime_before': {'containers': staged, 'edge_configuration': routes,
                  'retained_route_directory': 'materialized', 'normalized_model': normalized_model,
                  'candidate_retirement': custody}})
        result = {'candidate_id': candidate_id, 'stop_completed': True, 'remove_returncode': 0,
                  'completed_cli_job': True, 'candidate_absent': True}
        append(retirement.PHASE, store.journal.RETIRE_RETURNED, retirement.RETURNED, {'candidate_retirement': result})
        retained = {'runtime_after': combined_runtime, 'edge_configuration': routes, 'normalized_model': normalized_model,
                    'retained_route_directory': 'materialized'}
        qualification = {'runtime_sha256': digest(combined_runtime), 'edge_sha256': digest(routes),
            'public_routes_sha256': 'b'*64, 'application_handoffs_sha256': 'c'*64,
            'native_sha256': plan['owner']['native_sha256'], 'foreign_storage_sha256': None, 'foreign_storage_changes': 0}
        append(retirement.PHASE, 'completed', retirement.AFTER, retirement._completion(plan, retained, result, qualification))
    return status


@pytest.mark.parametrize('fault', [None, 'retirement-tamper', 'live-refused', 'interrupted'])
def test_reverse_publication_selects_exact_combined_owner(monkeypatch, planned, capsys, fault):
    import selfhost_windows_website_abort_release as release

    with fixture(monkeypatch) as (root, phase, _tx, _outcome, path, config):
        runtime = {'b'*64: {'project': config['project'], 'service': 'edge', 'image': 'sha256:'+'b'*64,
                            'mounts': [], 'status': 'running'}}
        phase['data'] = digest(forward.edge._retained_data(runtime))
        source, starting, plan, guard_pin, pins, split, _ = prepare(planned, root, path, config, combined_runtime=runtime)
        phase['data'] = plan['states']['split']['data_sha256']
        committed = owner.finish(path, plan, guard_sha256=guard_pin, **pins, check_live=lambda *_: None)
        split_source = Path(committed['journal'])
        split_raw = {entry.name: entry.read_bytes() for entry in split_source.iterdir()}
        original_raw = {entry.name: entry.read_bytes() for entry in source.iterdir()}
        proof = owner._published_binding(original_raw, selection.decode(original_raw[owner.INTENT]), split_raw)
        terminal = _retire_published(plan, proof, guard_pin, pins['terminal_sha256'], runtime)
        attempt = Path(plan['attempt_directory'])
        calls = []

        def refresh(combined, choice, _values, record, planned, retained, owner_attempt, **kwargs):
            calls.append('combined-proof')
            assert choice == record['choice'] == 'new' and record['data_sha256'] == plan['owner']['data_sha256']
            assert combined['compose_file'] == config['compose_file'] and owner_attempt == attempt and plan == planned
            assert retained['runtime_after'] == runtime
            if fault == 'live-refused':
                raise ValueError('Fixture rejected live combined qualification')
            return {'runtime_sha256': digest(runtime), 'edge_sha256': digest(retained['edge_configuration']),
                    'public_routes_sha256': 'd'*64, 'application_handoffs_sha256': 'e'*64,
                    'native_sha256': plan['owner']['native_sha256'], 'foreign_storage_sha256': None,
                    'foreign_storage_changes': 0}

        monkeypatch.setattr(release, '_refresh', refresh)
        options = {'guard_sha256': guard_pin, 'expected_anchor_sha256': terminal['anchor_sha256'],
                   'forward_intent_sha256': committed['intent_sha256'],
                   'assets': root/'assets', 'gh': None, 'cosign': None, 'registry_config': None}
        with pytest.raises(ValueError):
            selection.select_combined_website(path, plan, **dict(options, expected_anchor_sha256=pins['terminal_sha256']))
        if fault == 'retirement-tamper':
            (attempt / 'retire-candidate-after.json').write_bytes(b'{}')
        if fault in {'retirement-tamper', 'live-refused'}:
            with pytest.raises(ValueError):
                selection.select_combined_website(path, plan, **options)
            assert not (split_source / owner.COMBINED_INTENT).exists()
            assert calls == (['combined-proof'] if fault == 'live-refused' else [])
            return
        if fault == 'interrupted':
            hold = owner._held_private_input

            @contextmanager
            def interrupt(candidate_path, **kwargs):
                if kwargs.get('_rename_to') == split_source / owner.COMBINED_DECISION:
                    raise RuntimeError('Stopped before selecting combined')
                with hold(candidate_path, **kwargs) as value:
                    yield value

            with monkeypatch.context() as injected:
                injected.setattr(owner, '_held_private_input', interrupt)
                with pytest.raises(RuntimeError, match='before selecting combined'):
                    selection.select_combined_website(path, plan, **options)
            assert (split_source / owner.COMBINED_PENDING).is_file()
            assert not (split_source / owner.COMBINED_DECISION).exists()
            with pytest.raises(ValueError):
                with selection._session(path, _pending_website_sha256=guard_pin):
                    pytest.fail('Pending reversal cannot fall back to split')
            pin = selection.digest((split_source / owner.COMBINED_INTENT).read_bytes())
            with pytest.raises(ValueError):
                selection.select_combined_website(path, plan, **dict(options, intent_sha256='0'*64))
            options['intent_sha256'] = pin

        args = ['--select-combined', '--selection-file', str(path), '--composition-dir', str(root/'assets'),
                '--gh', str(root/'gh'), '--cosign', str(root/'cosign'), '--plan-file', str(attempt/'journal'/store.PLAN),
                '--guard-sha256', guard_pin, '--expected-anchor-sha256', terminal['anchor_sha256'],
                '--forward-intent-sha256', committed['intent_sha256']]
        if fault == 'interrupted':
            args.extend(['--intent-sha256', options['intent_sha256']])
        assert website.main(args) == 0
        output = capsys.readouterr()
        assert not output.err
        result = selection.decode(output.out.encode())
        assert result['result'] == 'website-combined-selected-guarded'
        assert result['generation_sequence'] == committed['generation_sequence']
        assert result['selected_sha256'] == committed['selected_sha256'] and result['guards_retained']
        assert {name: (source/name).read_bytes() for name in starting} == starting
        assert {name: (split_source/name).read_bytes() for name in split_raw} == split_raw
        assert renewal.product_transition_guard(config).is_file()
        target = Path(result['journal'])
        with selection._session(path, _pending_website_sha256=guard_pin) as (_, _, expected, active, raw, _stack):
            assert active == target and expected['compose_file'] == config['compose_file']
            first, selected, _generation = owner.product.anchor(raw, expected)
            assert selected['decision'] == 'website-combined-new'
            assert selected['data_sha256'] == plan['owner']['data_sha256']
            selected_config = selection.decode(Path(first['config_path']).read_bytes())
            assert selected_config['compose_file'] != str(split)
            assert Path(selected_config['intent']).read_bytes() == Path(selected_config['result']).read_bytes() == b''
        repeated = selection.select_combined_website(path, plan, **dict(options, intent_sha256=result['intent_sha256']))
        assert repeated == result
        assert calls == ['combined-proof'] * (3 if fault == 'interrupted' else 2)
        with pytest.raises(ValueError):
            selection.status(path)
        release_args = {key: value for key, value in options.items()
                        if key not in {'forward_intent_sha256', 'intent_sha256'}}
        _, active, archive = release._paths(config, plan, 'combined')
        original_identity = release._path_identities(active)
        original_guard = active.read_bytes()
        with pytest.raises(ValueError):
            selection.release_selected_website(path, plan, mode='combined', intent_sha256=committed['intent_sha256'],
                                              **release_args)
        closed = selection.release_selected_website(path, plan, mode='combined', intent_sha256=result['intent_sha256'],
                                                    **release_args)
        assert closed['result'] == 'website-combined-guard-archived' and closed['guard_archived']
        assert not active.exists() and archive.read_bytes() == original_guard
        assert release._path_identities(archive) == original_identity
        assert selection.release_selected_website(path, plan, mode='combined', intent_sha256=result['intent_sha256'],
                                                  **release_args) == closed
        assert calls == ['combined-proof'] * (4 if fault == 'interrupted' else 3)
        phase['data'] = plan['owner']['data_sha256']
        with selection.selected_inputs(path) as lease:
            assert lease.compose_file == Path(config['compose_file']) and lease.journal_path == target
            assert lease.generation_sequence == committed['generation_sequence']
            assert lease.selected_sha256 == committed['selected_sha256']
            assert lease.check_current() == phase['data']


@pytest.mark.parametrize('fault', [None, 'live-refused', 'before-rename', 'after-rename', 'tampered-receipt'])
def test_release_forward_archives_exact_guard_with_locked_readback(monkeypatch, planned, capsys, fault):
    import selfhost_windows_website_abort_release as release

    with fixture(monkeypatch) as (root, phase, _tx, _outcome, path, config):
        _source, _starting, plan, guard_pin, pins, split, _verified = prepare(planned, root, path, config)
        phase['data'] = plan['states']['split']['data_sha256']
        committed = owner.finish(path, plan, guard_sha256=guard_pin, **pins, check_live=lambda *_: None)
        attempt, active, archive = release._paths(config, plan, 'forward')
        qualification = attempt / ('forward-qualification-' + pins['qualification_sha256'] + '.json')
        original = active.read_bytes()
        original_identity = release._path_identities(active)
        calls = []

        def check_publication(combined, choice, _values, record, supplied, link, **kwargs):
            assert combined['compose_file'] == config['compose_file'] and choice == record['choice']
            assert supplied == plan and link['terminal_sha256'] == pins['terminal_sha256']
            assert kwargs['guard_sha256'] == guard_pin and kwargs['expected_account_sha256'] == 'd'*64
            calls.append('live')
            if fault == 'live-refused':
                raise ValueError('Synthetic public failure')
            return selection.decode(qualification.read_bytes())

        monkeypatch.setattr(forward, 'check_publication', check_publication)
        args = ['--release-forward', '--selection-file', str(path), '--composition-dir', str(root/'assets'),
                '--gh', str(root/'gh'), '--cosign', str(root/'cosign'), '--plan-file', str(attempt/'journal'/store.PLAN),
                '--guard-sha256', guard_pin, '--expected-anchor-sha256', pins['terminal_sha256'],
                '--intent-sha256', committed['intent_sha256'], '--session-state-file', str(root/'session.private.json'),
                '--expected-account-sha256', 'd'*64, '--expected-organization-sha256', 'e'*64]
        wrong = list(args)
        wrong[wrong.index('--intent-sha256') + 1] = '0'*64
        assert website.main(wrong) == 2
        assert not calls and active.exists() and not archive.exists()
        capsys.readouterr()

        if fault in {'before-rename', 'after-rename'}:
            hold = release._held_private_input

            @contextmanager
            def interrupt(path_to_hold, **options):
                archiving = options.get('_rename_to') == archive
                if archiving and fault == 'before-rename':
                    raise RuntimeError('Synthetic interruption before rename')
                with hold(path_to_hold, **options) as body:
                    yield body
                if archiving and fault == 'after-rename':
                    raise RuntimeError('Synthetic interruption after rename')

            with monkeypatch.context() as injected:
                injected.setattr(release, '_held_private_input', interrupt)
                assert website.main(args) == 2
            assert archive.exists() is (fault == 'after-rename')
            assert active.exists() is (fault == 'before-rename')
            assert (attempt/'forward-owner-release.json').exists()
            capsys.readouterr()

        if fault == 'live-refused':
            assert website.main(args) == 2
            assert calls == ['live'] and active.read_bytes() == original
            assert not archive.exists() and not (attempt/'forward-owner-release.json').exists()
            return
        assert website.main(args) == 0
        output = capsys.readouterr()
        assert not output.err
        released = selection.decode(output.out.encode())
        assert released['result'] == 'website-forward-guard-archived' and released['guard_archived']
        assert released['selected_sha256'] == committed['selected_sha256']
        assert not active.exists() and archive.read_bytes() == original
        assert release._path_identities(archive) == original_identity
        with selection.selected_inputs(path) as lease:
            assert lease.compose_file == split and lease.generation_sequence == committed['generation_sequence']
            assert lease.selected_sha256 == committed['selected_sha256'] and lease.check_current() == phase['data']

        if fault == 'tampered-receipt':
            proof = attempt / ('forward-release-proof-' + released['qualification_sha256'] + '.json')
            proof.write_bytes(b'{}')
            assert website.main(args) == 2
            assert not active.exists() and archive.read_bytes() == original
        else:
            assert website.main(args) == 0
            assert selection.decode(capsys.readouterr().out.encode()) == released
        assert calls == ['live'] * (2 if fault == 'before-rename' else 1)


@pytest.mark.parametrize('fault', [None, 'wrong-release', 'renewal-intent', 'interrupted-after', 'failed-live'])
def test_readmit_archived_split_guard_and_require_the_exact_fresh_baseline(monkeypatch, planned, capsys, fault):
    import selfhost_windows_website_abort_release as release

    with fixture(monkeypatch) as (root, phase, _tx, _outcome, path, config):
        combined = {'b'*64: {'project': config['project'], 'service': 'edge', 'image': 'sha256:'+'b'*64,
                             'mounts': [], 'status': 'running'}}
        phase['data'] = digest(forward.edge._retained_data(combined))
        _, _, plan, guard_pin, pins, _, _ = prepare(planned, root, path, config, combined_runtime=combined)
        phase['data'] = plan['states']['split']['data_sha256']
        committed = owner.finish(path, plan, guard_sha256=guard_pin, **pins, check_live=lambda *_: None)
        attempt, active, archive = release._paths(config, plan, 'forward')
        qualification = selection.decode((attempt / ('forward-qualification-' + pins['qualification_sha256'] + '.json')).read_bytes())
        monkeypatch.setattr(forward, 'check_publication', lambda *_, **_kw: qualification)
        options = {'guard_sha256': guard_pin, 'expected_anchor_sha256': pins['terminal_sha256'],
                   'intent_sha256': committed['intent_sha256'], 'assets': root/'assets',
                   'gh': None, 'cosign': None, 'registry_config': None}
        original = active.read_bytes()
        original_identity = release._path_identities(active)
        released = selection.release_selected_website(path, plan, **options, mode='forward')
        assert not active.exists() and archive.exists()
        calls = []

        with ExitStack() as held:
            historical = store.read_evidence(plan, expected_anchor_sha256=pins['terminal_sha256'], held=held,
                references={'route-website-after.json': ('route-website', 'completed')})['route-website-after.json']['runtime_after']
        runtime = {'c'*64: dict(historical['b'*64], pid=412),
                   'd'*64: dict(historical['a'*64], pid=513)}
        fresh = {'runtime_after': runtime, 'edge_configuration': {'container_id': 'c'*64},
                 'native_custody': {key: plan['owner'][key] for key in ('selected_sha256', 'native_sha256')},
                 'foreign_storage': {'engine_id': config['engine_id'], 'inventory_sha256': 'e'*64,
                                     'changes_sha256': None, 'changes': 0}}

        def qualify(combined_cfg, choice, _values, _record, supplied_plan, status, **kwargs):
            assert combined_cfg['compose_file'] == config['compose_file'] and choice == 'new'
            assert supplied_plan == plan and status['anchor_sha256'] == pins['terminal_sha256']
            calls.append('readmit')
            if fault == 'failed-live':
                raise ValueError('Synthetic storage refusal')
            return fresh

        monkeypatch.setattr(release, '_qualify_released_split', qualify)
        if fault == 'renewal-intent':
            selected = Path(committed['journal'])
            first = selection.decode((selected/'000001.intent.json').read_bytes())
            first.update(sequence=2, operation='activation',
                         parent=selection.digest((selected/'000001.selection.json').read_bytes()))
            first['inputs']['old'] = first['inputs']['new']
            selection._new_private(selected/'000002.intent.json', selection.packed(first))
        args = ['--readmit-backout', '--selection-file', str(path), '--composition-dir', str(root/'assets'),
                '--gh', str(root/'gh'), '--cosign', str(root/'cosign'), '--plan-file', str(attempt/'journal'/store.PLAN),
                '--guard-sha256', guard_pin, '--expected-anchor-sha256', pins['terminal_sha256'],
                '--intent-sha256', committed['intent_sha256'], '--release-sha256',
                '0'*64 if fault == 'wrong-release' else released['release_sha256']]

        if fault in {'wrong-release', 'renewal-intent', 'failed-live'}:
            assert website.main(args) == 2
            assert calls == (['readmit'] if fault == 'failed-live' else [])
            assert not active.exists() and archive.read_bytes() == original
            assert not (attempt/release.READMISSION).exists()
            return
        if fault == 'interrupted-after':
            hold = release._held_private_input

            @contextmanager
            def interrupt(path_to_hold, **kwargs):
                with hold(path_to_hold, **kwargs) as value:
                    yield value
                if kwargs.get('_rename_to') == active:
                    raise RuntimeError('Interrupted after reopening the guard')

            with monkeypatch.context() as injected:
                injected.setattr(release, '_held_private_input', interrupt)
                assert website.main(args) == 2
            assert active.exists() and not archive.exists()
            capsys.readouterr()

        assert website.main(args) == 0
        output = capsys.readouterr()
        result = selection.decode(output.out.encode())
        assert not output.err and calls == ['readmit']
        assert result['result'] == 'website-forward-backout-readmitted'
        assert not archive.exists() and active.read_bytes() == original
        assert release._path_identities(active) == original_identity
        with pytest.raises(ValueError):
            selection.release_selected_website(path, plan, **options, mode='forward')
        with pytest.raises(ValueError):
            selection.status(path)

        def restore(*_args, **_kwargs):
            status = _args[5]
            assert status['readmitted_runtime'] == fresh
            assert status['readmission_sha256'] == result['readmission_sha256']
            calls.append('restore')
            return status

        monkeypatch.setattr(forward.edge, 'run', restore)
        with pytest.raises(ValueError):
            selection.backout_published_website(path, plan, **options, backout_phase='restore-combined')
        assert selection.backout_published_website(path, plan, **options, backout_phase='restore-combined',
            readmission_sha256=result['readmission_sha256'])['guards_retained']
        assert calls == ['readmit', 'restore']
        (attempt / ('forward-backout-runtime-' + result['runtime_sha256'] + '.json')).write_bytes(b'{}')
        with pytest.raises(ValueError):
            selection.backout_published_website(path, plan, **options, backout_phase='restore-combined',
                readmission_sha256=result['readmission_sha256'])
        assert calls == ['readmit', 'restore']


@pytest.mark.parametrize(('fault', 'retirement_fault'), [
    (None, None), (None, 'missing-return'), (None, 'post-removal-http'), ('timeout', None),
    ('nonzero', None), ('after-return', None), ('protected-drift', None), ('historical-evidence', None)])
def test_rollback_plan_follows_selected_renewal_and_refuses_unreleased_history(monkeypatch, planned, capsys, fault, retirement_fault):
    import selfhost_windows_website_current_backout as backout
    from types import SimpleNamespace

    with fixture(monkeypatch) as (root, phase, transaction, outcome, path, config):
        combined = {'b'*64: {'service': 'edge', 'image': 'sha256:'+'b'*64, 'mounts': []}}
        phase['data'] = digest(forward.edge._retained_data(combined))
        _, _, plan, guard_pin, pins, split, _ = prepare(planned, root, path, config, combined_runtime=combined)
        phase['data'] = plan['states']['split']['data_sha256']
        committed = owner.finish(path, plan, guard_sha256=guard_pin, **pins, check_live=lambda *_: None)
        attempt = Path(plan['attempt_directory'])
        qualification = attempt / ('forward-qualification-' + pins['qualification_sha256'] + '.json')
        monkeypatch.setattr(forward, 'check_publication', lambda *_, **_kw: selection.decode(qualification.read_bytes()))
        released = selection.release_selected_website(path, plan, mode='forward', guard_sha256=guard_pin,
            expected_anchor_sha256=pins['terminal_sha256'], intent_sha256=committed['intent_sha256'],
            assets=root/'assets', gh=None, cosign=None, registry_config=None)
        args = ['--plan-current-backout', '--selection-file', str(path), '--composition-dir', str(root/'assets'),
                '--gh', str(root/'gh'), '--cosign', str(root/'cosign'), '--plan-file', str(attempt/'journal'/store.PLAN),
                '--guard-sha256', guard_pin, '--expected-anchor-sha256', pins['terminal_sha256'],
                '--intent-sha256', committed['intent_sha256'], '--release-sha256', released['release_sha256']]
        assert website.main(args) == 2  # No intervening renewal.
        capsys.readouterr()

        next_path, next_config = transaction(2)
        next_config.update(compose_file=str(split), compose_sha256=selection.digest(split.read_bytes()),
                           tls_init_receipt=config['tls_init_receipt'])
        next_path.write_bytes(selection.packed(next_config))
        assert selection.prepare(next_path) == 2
        assert website.main(args) == 2  # Incomplete selection.
        capsys.readouterr()
        phase['active'] = Path(next_config['renewed_secrets'])
        outcome(next_config, 'activated')
        selected = selection.complete(next_path)
        calls = []

        def layouts(current, combined, choice, values, record, historical, *_args, **_options):
            assert current['compose_file'] == str(split) and combined['compose_file'] == config['compose_file']
            assert combined['renewed_env'] == current['renewed_env'] == next_config['renewed_env']
            assert choice == 'new' and record['selected'] == selected['selected'] and historical == plan
            calls.append('layout')
            models = {}
            for side, env in [('old', current['current_env']), ('new', current['renewed_env'])]:
                base = ['docker', 'compose', '--env-file', env, '-f', combined['compose_file']]
                staged = base + ['-f', str(attempt / 'stage.compose.json')]
                commands = {'combined': base, 'staged': staged, 'split': staged + ['-f', str(attempt / 'route.compose.json')]}
                models[side] = {state: (command, {'side': side}, {'state': state}) for state, command in commands.items()}
            return None, models, {}

        monkeypatch.setattr(backout, '_layouts', layouts)
        monkeypatch.setattr(backout, '_context', lambda _cfg, choice, _values, _record, _plan, _docker, layouts, *_:
                            (SimpleNamespace(layouts=layouts[choice]), lambda: None))
        operation_state = {'layout': 'split', 'dispatched': 0, 'fail_readback': fault == 'after-return'}

        def observe(_context, _proposal, _routes, state, *, before_intent):
            assert state == operation_state['layout']
            if state == 'staged' and operation_state['fail_readback']:
                raise RuntimeError('Synthetic readback interruption')
            edge_id = 'c'*64 if state == 'split' else 'd'*64
            runtime = {edge_id: {'service': 'edge', 'restarts': 0}}
            if state != 'combined':
                runtime['1'*64] = {'service': backout.contract.SLOT, 'status': 'running'}
            return runtime, {'runtime_sha256': digest(runtime), 'ingress_sha256': 'e'*64, 'networks': ['owned'],
                'protected_runtime_sha256': 'f'*64 if state == 'staged' and fault == 'protected-drift' else 'a'*64,
                'edge_configuration': {'container_id': edge_id, 'default_sha256': 'b'*64,
                                       'routes_sha256': plan['states'][state]['routes_sha256']}}

        monkeypatch.setattr(backout, '_observe', observe)
        assert website.main(args[:-1] + ['0'*64]) == 2
        assert calls == []
        capsys.readouterr()
        assert website.main(args) == 0
        output = selection.decode(capsys.readouterr().out.encode())
        assert output['owner']['generation_sequence'] == 2
        assert output['owner']['selected_sha256'] == digest(selected['selected']) != plan['owner']['selected_sha256']
        assert output['historical_release']['release_sha256'] == released['release_sha256']
        assert output['plan_sha256'] == digest({k: v for k, v in output.items() if k != 'plan_sha256'})
        assert calls == ['layout'] and not renewal.product_transition_guard(config).exists()
        class Runtime:
            def containers(self):
                return []

        monkeypatch.setattr(selection, '_inspect', lambda *_, **_kw: {'docker': Runtime(), 'baseline': []})
        with selection.selected_inputs(path) as lease:
            assert lease.compose_file == split and lease.secrets_dir == phase['active']
            new_journal = lease.continue_journal()['journal']
        assert website.main(args) == 0
        continued = selection.decode(capsys.readouterr().out.encode())
        assert continued['selected_journal'] == new_journal
        assert continued['owner']['selection_sequence'] == 1 and continued['owner']['generation_sequence'] == 2
        assert continued['owner']['selected_sha256'] == output['owner']['selected_sha256']
        assert continued['plan_sha256'] != output['plan_sha256']
        if fault == 'historical-evidence':
            (attempt/'stage-before.json').write_bytes(b'{}')
            assert website.main(args) == 2 and calls == ['layout', 'layout']
            return

        def mutate(command, *, timeout):
            assert timeout == 120 and command == forward.edge.recreate_command(
                ['docker', 'compose', '--env-file', next_config['renewed_env'], '-f', config['compose_file'],
                 '-f', str(attempt / 'stage.compose.json')])
            assert operation_state['dispatched'] == 0
            assert selection.decode(renewal.product_transition_guard(config).read_bytes()) == backout.edge_guard(plan, continued['plan_sha256'])
            operation_state['dispatched'] += 1
            if fault == 'timeout':
                raise renewal.UncertainComposeMutation('Synthetic timeout')
            if fault == 'nonzero':
                return SimpleNamespace(returncode=1)
            operation_state['layout'] = 'staged'
            return SimpleNamespace(returncode=0)

        monkeypatch.setattr(renewal, 'run_owned_mutation', mutate)
        restore = ['--restore-current-edge', *args[1:], '--current-plan-sha256', continued['plan_sha256']]
        reconcile = ['--reconcile-current-edge', *restore[1:]]
        assert website.main(restore[:-1] + [output['plan_sha256']]) == 2  # Stale pre-continuation pin.
        assert website.main(reconcile) == 2
        assert not renewal.product_transition_guard(config).exists()
        capsys.readouterr()
        rc = website.main(restore)
        assert operation_state['dispatched'] == 1
        assert rc == (0 if fault is None else 2)
        first = capsys.readouterr().out
        if rc == 0:
            assert selection.decode(first.encode())['guard_retained']
        with pytest.raises(ValueError):
            selection.status(path)
        assert website.main(restore) == 2
        capsys.readouterr()
        operation_state['fail_readback'] = False
        assert website.main(reconcile) == (2 if fault in {'timeout', 'nonzero', 'protected-drift'} else 0)
        if rc == 0:
            assert capsys.readouterr().out == first
        assert operation_state['dispatched'] == 1
        if fault is not None:
            return

        subject = ('4'*64, '5'*64)
        session_file = root / 'test.session'
        verified_args = ['--backout-published', *restore[1:], '--session-state-file', str(session_file),
                         '--expected-account-sha256', subject[0], '--expected-organization-sha256', subject[1],
                         '--backout-phase', 'verify-combined']
        interruptions = {'public': True, 'post': retirement_fault == 'post-removal-http'}
        def http(context, routes, proposal, state, held, session, identity):
            assert Path(session) == session_file
            if interruptions['public'] or identity != subject or (state == 'combined' and interruptions['post']):
                raise ValueError('HTTP qualification failed')
            runtime, obs = observe(context, proposal, routes, state, before_intent=True)
            del obs['protected_runtime_sha256']
            return [], runtime, obs, {'application_handoffs_sha256': '9'*64}

        custody = {'candidate_id': '1'*64, 'observed_candidate': {'service': backout.contract.SLOT, 'status': 'running'},
                   'remove_command': ['container', 'rm', '1'*64]}
        monkeypatch.setattr(backout, '_http_acceptance', http)
        monkeypatch.setattr(backout, '_retirement_inputs', lambda *_: (None, custody))
        removals = []
        def remove(context, observed):
            assert observed == custody and not removals
            removals.append(observed['candidate_id'])
            assert backout._evidence_path(plan, continued['plan_sha256'], 'retire-intent').is_file()
            operation_state['layout'] = 'combined'
            if retirement_fault == 'missing-return':
                raise renewal.UncertainComposeMutation('Synthetic missing return after removal')
            return {'candidate_id': observed['candidate_id'], 'stop_completed': True, 'completed_cli_job': True,
                    'remove_returncode': 0, 'candidate_absent': True}

        monkeypatch.setattr(backout.reconcile, '_remove_candidate', remove)
        assert website.main(verified_args) == 2 and not removals
        interruptions['public'] = False
        assert website.main(verified_args) == 0
        audit = selection.decode(capsys.readouterr().out.encode())
        retire = [*verified_args[:-1], 'retire-candidate', '--qualification-sha256', audit['qualification_sha256']]
        assert website.main(retire[:-1] + ['0'*64]) == 2 and not removals
        interruptions['public'] = True
        assert website.main(retire) == 2 and not removals
        interruptions['public'] = False
        assert website.main(retire) == (0 if retirement_fault is None else 2)
        interruptions['post'] = False
        assert website.main(retire) == (2 if retirement_fault == 'missing-return' else 0)
        assert website.main(verified_args) == 2 and removals == ['1'*64]
        assert website.main(reconcile) == 2
        assert renewal.product_transition_guard(config).is_file()
        if retirement_fault is None:
            returned = backout._evidence_path(plan, continued['plan_sha256'], 'retire-returned')
            invalid = dict(selection.decode(returned.read_bytes()), remove_returncode=False)
            returned.write_bytes(selection.packed(invalid))
            assert website.main(retire) == 2 and removals == ['1'*64]
