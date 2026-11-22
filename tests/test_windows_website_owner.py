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


def prepare(planned, root, original, config):
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
    rehash(plan)
    split = root / ('website-' + 'a'*32 + '.compose.json')
    split.write_bytes(selection.packed(selection.decode(model_bytes)))
    model = {'compose_file': str(split), 'compose_sha256': selection.digest(split.read_bytes())}
    runtime = [{'synthetic': 'runtime'}]
    routing = {'synthetic': 'edge-configuration'}
    with ExitStack() as held:
        status = owner.guard.initialize(config, plan, held)
        guard_pin = status['guard_sha256']
        for phase in store.journal.FORWARD[:-1]:
            status = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=phase, event='started',
                evidence_sha256={key: 'a'*64 for key in store.journal.START_EVIDENCE})
            after = ({key: {} for key in store.journal.COMPLETION_EVIDENCE[phase]} | {'runtime_after': runtime})
            if phase == 'route-website':
                after.update(mounted_template=plan['edge_template'], edge_configuration=routing)
            evidence = forward.stage._evidence(attempt / (phase + '-after.json'), after, held)
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
