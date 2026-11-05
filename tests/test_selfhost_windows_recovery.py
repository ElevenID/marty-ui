"""Real NTFS recovery guard/receipt boundaries; Docker/native calls substituted."""
import os
import subprocess
import sys
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from subprocess import CompletedProcess

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import selfhost_windows_recovery as recovery
import selfhost_windows_selection as selection
from test_selfhost_windows_renewal import states
from test_selfhost_windows_selection import fixture


@contextmanager
def candidate(monkeypatch, *, warm=False, fault=None):
    with fixture(monkeypatch) as (root, _phase, tx, _outcome, path, cfg):
        selection.adopt(path)
        model = selection.decode(Path(cfg['compose_file']).read_bytes())
        model['services']['gateway']['depends_on'] = {'postgres': {'condition': 'service_healthy'}}
        roles = {x['Service'] for x in states(model)}
        items = []
        for index, role in enumerate(sorted(roles)):
            completed = role in recovery.COMPLETED
            items.append({'Id': f'{index+1:064x}', 'Image': 'sha256:'+'a'*64,
                'Config': {'Labels': {'com.docker.compose.project': cfg['project'],
                                      'com.docker.compose.service': role}},
                'State': {'Status': 'exited' if completed or not warm else 'running',
                          'ExitCode': 0, 'StartedAt': 'before'}, 'Mounts': [], 'RestartCount': 0})
        events = [];baseline = deepcopy(items)
        class Docker:
            prefix = ['docker', '--host', 'SYNTHETIC']
            def containers(self):return deepcopy(items)
        observed = {'docker': Docker(), 'owned': deepcopy(baseline), 'baseline': baseline,
                    'services': roles, 'model': model, 'command': ['SYNTHETIC_COMPOSE'], 'data_sha256': 'd'*64,
                    'cwd': root}
        def native(*_a, **_kw):
            events.append('native')
            if fault == 'native':raise ValueError('PUBLIC_NATIVE_REFUSAL')
        def start(args, **_kw):
            assert args[:4] == ['docker', '--host', 'SYNTHETIC', 'start']
            selected = [x for x in items if x['Id'] in args[4:]]
            assert len(selected) == len(args[4:]) and selected
            selected_roles = [selection.renewal._service(x) for x in selected]
            assert not set(selected_roles) & recovery.COMPLETED
            events.append(selected_roles)
            if fault == 'uncertain':raise selection.renewal.UncertainComposeMutation('PUBLIC_TIMEOUT')
            if fault == 'cli':return CompletedProcess(args, 1, b'PUBLIC_FAIL', b'')
            for item in selected:item['State'].update(Status='running', StartedAt='after')
            if fault == 'foreign':items.append({'Id': 'f'*64, 'Image': 'foreign', 'Config': {},
                'Mounts': [], 'State': {'Status': 'running', 'StartedAt': 'other'}, 'RestartCount': 0})
            return CompletedProcess(args, 0, b'PUBLIC_OK', b'')
        def status(*_a, **_kw):
            return [{'Service': selection.renewal._service(x), 'State': x['State']['Status'],
                     'ExitCode': x['State']['ExitCode'],
                     'Health': 'healthy' if model['services'][selection.renewal._service(x)].get('healthcheck') else ''}
                    for x in items if selection.renewal._project(x) == cfg['project']]
        monkeypatch.setattr(selection, '_inspect', lambda *_a, **_kw: observed)
        monkeypatch.setattr(selection, '_native_current', native)
        monkeypatch.setattr(selection.renewal, 'run_owned_mutation', start)
        monkeypatch.setattr(selection.renewal, 'statuses', status)
        output = root/'windows-recovery-attempt';output.mkdir()
        yield root, path, cfg, output, events, items, observed, tx


@pytest.mark.parametrize('warm', [False, True])
def test_existing_ids_only_and_result_waits_for_selection_exit(monkeypatch, warm):
    with candidate(monkeypatch, warm=warm) as (_root, path, cfg, output, events, _items, _observed, _tx):
        with selection.selected_inputs(path) as lease:
            provisional = lease.recover_existing(output)
            assert provisional['result'] == 'recovered-existing'
            assert (output/'result.json').read_bytes() == b''
            assert selection.renewal.recovery_guard(cfg).exists()
        result = selection.decode((output/'result.json').read_bytes())
        assert result == provisional and not selection.renewal.recovery_guard(cfg).exists()
        if warm:assert events == ['native']
        else:
            assert set(events[0]) == {'openbao', 'openbao-unseal'}
            assert events[1] == 'native'
            flattened = [role for event in events if isinstance(event, list) for role in event]
            assert len(flattened) == len(set(flattened)) and not set(flattened) & recovery.COMPLETED
        with pytest.raises(ValueError):lease.recover_existing(output)


@pytest.mark.parametrize('fault', ['native', 'cli', 'uncertain', 'foreign'])
def test_failed_or_uncertain_start_retains_guard_and_blocks_new_selection(monkeypatch, fault):
    with candidate(monkeypatch, fault=fault) as (_root, path, cfg, output, _events, _items, _observed, tx):
        with pytest.raises((ValueError, selection.renewal.UncertainComposeMutation)):
            with selection.selected_inputs(path) as lease:lease.recover_existing(output)
        assert selection.renewal.recovery_guard(cfg).exists()
        assert (output/'result.json').read_bytes() == b''
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):pytest.fail('Interrupted recovery was ignored')
        next_path, _ = tx(2)
        with pytest.raises(ValueError):selection.prepare(next_path)


@pytest.mark.parametrize('bad', ['completed-running', 'completed-failed', 'paused', 'invalid-id',
                               'foundation-app-dependency', 'foundation-reverse', 'unseal-health-dependency'])
def test_invalid_recovery_plan_refuses_before_guard_or_cli(monkeypatch, bad):
    with candidate(monkeypatch) as (_root, path, cfg, output, events, _items, observed, _tx):
        by_role = {selection.renewal._service(x): x for x in observed['owned']}
        if bad == 'completed-running':by_role['db-migrate']['State']['Status'] = 'running'
        elif bad == 'completed-failed':by_role['db-migrate']['State']['ExitCode'] = 1
        elif bad == 'paused':by_role['gateway']['State']['Status'] = 'paused'
        elif bad == 'invalid-id':by_role['gateway']['Id'] = 'other-project-name'
        elif bad == 'foundation-app-dependency':observed['model']['services']['openbao']['depends_on'] = {'postgres': {'condition': 'service_healthy'}}
        elif bad == 'foundation-reverse':observed['model']['services']['openbao']['depends_on'] = {'openbao-unseal': {'condition': 'service_started'}}
        else:observed['model']['services']['openbao-unseal']['depends_on'] = {'openbao': {'condition': 'service_healthy'}}
        with pytest.raises(ValueError):
            with selection.selected_inputs(path) as lease:lease.recover_existing(output)
        assert not events and not selection.renewal.recovery_guard(cfg).exists()
        assert not list(output.iterdir())


@pytest.mark.parametrize('tamper', ['extra', 'receipt', 'body-exception', 'held-exit'])
def test_successful_cli_cannot_publish_after_input_or_receipt_failure(monkeypatch, tamper):
    with candidate(monkeypatch) as (_root, path, cfg, output, _events, _items, _observed, _tx):
        if tamper == 'held-exit':
            actual = selection.renewal.hold_private_generation
            @contextmanager
            def held(*a, **kw):
                with actual(*a, **kw) as value:yield value
                raise ValueError('PUBLIC_HELD_EXIT_FAILURE')
            monkeypatch.setattr(selection.renewal, 'hold_private_generation', held)
        with pytest.raises((ValueError, RuntimeError)):
            with selection.selected_inputs(path) as lease:
                lease.recover_existing(output)
                if tamper == 'extra':(output/'unexpected').write_text('PUBLIC_EXTRA')
                elif tamper == 'receipt':(output/'000.completed.json').write_text('PUBLIC_TAMPER')
                elif tamper == 'body-exception':raise RuntimeError('PUBLIC_CALLER_FAILURE')
        assert (output/'result.json').read_bytes() == b''
        assert selection.renewal.recovery_guard(cfg).exists()


def test_final_publication_lock_exit_failure_keeps_authoritative_guard(monkeypatch):
    with candidate(monkeypatch) as (root, path, cfg, output, _events, _items, _observed, _tx):
        actual = selection.renewal.hold_private_input
        @contextmanager
        def held(p, *a, **kw):
            with actual(p, *a, **kw) as value:yield value
            if Path(p) == root/f'.{cfg["project"]}.renewal.lock' and (output/'result.json').exists() and (output/'result.json').read_bytes():
                raise ValueError('PUBLIC_FINAL_LOCK_EXIT_FAILURE')
        monkeypatch.setattr(selection.renewal, 'hold_private_input', held)
        with pytest.raises(ValueError, match='PUBLIC_FINAL_LOCK_EXIT_FAILURE'):
            with selection.selected_inputs(path) as lease:lease.recover_existing(output)
        assert selection.renewal.recovery_pending(cfg)
        with pytest.raises(ValueError):
            with selection.selected_inputs(path):pytest.fail('Failed finalization was accepted')


def test_diagnostic_failure_preserves_uncertain_outcome(monkeypatch):
    with candidate(monkeypatch, fault='uncertain') as (_root, path, cfg, output, _events, _items, _observed, _tx):
        actual = selection.renewal.write_empty_private_file
        def write(p, value):
            if Path(p).name == 'diagnostic.private.log':raise OSError('PUBLIC_LOG_FAILURE')
            return actual(p, value)
        monkeypatch.setattr(selection.renewal, 'write_empty_private_file', write)
        with pytest.raises(selection.renewal.UncertainComposeMutation):
            with selection.selected_inputs(path) as lease:lease.recover_existing(output)
        assert (output/'result.json').read_bytes() == b'' and selection.renewal.recovery_pending(cfg)


def dangling_directory(path, target):
    try:os.symlink(target, path, target_is_directory=True)
    except OSError:
        p = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(path), str(target)],
                           capture_output=True, timeout=15)
        assert p.returncode == 0
    assert not path.exists()
    path.lstat()


def test_dangling_recovery_marker_blocks_all_mutating_admission(monkeypatch):
    with fixture(monkeypatch) as (root, _phase, tx, _outcome, path, cfg):
        selection.adopt(path)
        guard = selection.renewal.recovery_guard(cfg)
        dangling_directory(guard, root/'absent-target')
        try:
            assert selection.renewal.recovery_pending(cfg)
            checks = [];actual = selection.renewal.recovery_pending
            def pending(value):
                checks.append(True);return actual(value)
            monkeypatch.setattr(selection.renewal, 'recovery_pending', pending)
            with pytest.raises(ValueError):selection.renewal.activate(cfg)
            assert checks  # The private-lock owner sanitizes caller exceptions.
            with pytest.raises(ValueError):selection.adopt(path)
            with pytest.raises(ValueError):selection.complete(path)
            next_path, _ = tx(2)
            with pytest.raises(ValueError):selection.prepare(next_path)
            with pytest.raises(ValueError):
                with selection.selected_inputs(path):pytest.fail('Dangling marker bypassed')
            with pytest.raises(ValueError):
                with selection.activation_admission(cfg, {}, {}, b'', b''):pytest.fail('Dangling marker bypassed')
        finally:guard.rmdir()


def test_dangling_selection_owner_never_uses_legacy_admission(monkeypatch):
    with fixture(monkeypatch) as (root, _phase, _tx, _outcome, _path, cfg):
        owner = selection.directory(cfg)
        dangling_directory(owner, root/'absent-target')
        try:
            with pytest.raises((ValueError, OSError)):
                with selection.activation_admission(cfg, {}, {}, b'', b''):pytest.fail('Dangling owner bypassed')
        finally:owner.rmdir()


def test_guard_metadata_error_fails_closed(monkeypatch, tmp_path):
    path = tmp_path/'guard';actual = Path.lstat
    def stat(p, *a, **kw):
        if p == path:raise PermissionError('PUBLIC_METADATA_FAILURE')
        return actual(p, *a, **kw)
    monkeypatch.setattr(Path, 'lstat', stat)
    with pytest.raises(PermissionError):selection.renewal.namespace_entry_exists(path)


@pytest.mark.parametrize('late', ['final-census', 'completed-receipt', 'native', 'diagnostic'])
def test_late_operations_cannot_publish_recovery(monkeypatch, late):
    with candidate(monkeypatch) as (_root, path, cfg, output, _events, _items, observed, _tx):
        clock = {'now': 0, 'reads': 0}
        monkeypatch.setattr(recovery.time, 'monotonic', lambda: clock['now'])
        actual_read = observed['docker'].containers
        actual_native = selection._native_current
        actual_write = selection.renewal.write_empty_private_file
        def containers():
            clock['reads'] += 1
            result = actual_read()
            if late == 'final-census' and clock['reads'] == 7:clock['now'] = 601
            return result
        def native(*a, **kw):
            actual_native(*a, **kw)
            if late == 'native':clock['now'] = 601
        def write(p, value):
            actual_write(p, value)
            if (late == 'completed-receipt' and Path(p).name == '002.completed.json'
                or late == 'diagnostic' and Path(p).name == 'diagnostic.private.log'):clock['now'] = 601
        monkeypatch.setattr(observed['docker'], 'containers', containers)
        monkeypatch.setattr(selection, '_native_current', native)
        monkeypatch.setattr(selection.renewal, 'write_empty_private_file', write)
        with pytest.raises(ValueError):
            with selection.selected_inputs(path) as lease:lease.recover_existing(output)
        assert selection.renewal.recovery_pending(cfg) and (output/'result.json').read_bytes() == b''
