"""Generation admission under unrelated engine activity; no real Docker calls."""
from contextlib import ExitStack
from pathlib import Path
import sys

import pytest

sys.path[:0] = [str(Path(__file__).resolve().parents[1]/'scripts'), str(Path(__file__).resolve().parent)]
import selfhost_windows_selection as selection
import selfhost_windows_renewal_native as native
from test_selfhost_windows_renewal import foreign_context, context_container, PROJECT
from test_selfhost_windows_staging import staged_candidate
from test_windows_materialized_staging_reconciliation import materialized


@pytest.mark.parametrize('change', ['create', 'unlabelled', 'remove', 'restart', 'overlap', 'candidate', 'witness'])
def test_current_native_admission_allows_only_independent_foreign_activity(monkeypatch, change):
    docker, context = foreign_context()
    observed = {'docker': docker, 'context': context, 'data_sha256': 'd'*64}
    monkeypatch.setattr(selection, '_inspect', lambda *_a, **_kw: observed)
    admitted = []
    def current(config, choice, values, supplied_docker, authority):
        assert config['project'] == PROJECT and choice == 'old' and supplied_docker is docker
        assert values == {'old': {}} and authority == 'PUBLIC_SCOPED_AUTHORITY'
        admitted.append(True)
        if change in {'create', 'unlabelled', 'overlap', 'witness'}:
            docker.items.append(context_container('new', None if change == 'unlabelled' else 'other',
                                                  volume='candidate-data' if change == 'overlap' else 'other-data'))
        elif change == 'remove':docker.items.pop()
        elif change == 'restart':docker.items[1]['State'].update(Pid=99, StartedAt='RESTARTED')
        else:docker.items[0]['State']['StartedAt'] = 'CHANGED'
        if change == 'witness':
            def unavailable(*_):raise ValueError('PUBLIC_MISSING_WITNESS')
            monkeypatch.setattr(docker, 'native_witnesses', unavailable)
    monkeypatch.setattr(selection, '_native_current', current)
    with ExitStack() as stack:
        if change in {'overlap', 'candidate', 'witness'}:
            with pytest.raises(selection.renewal.UnsafeRenewalContext):
                selection._prove({'project': PROJECT}, 'old', {'old': {}}, stack, authority_file='PUBLIC_SCOPED_AUTHORITY')
        else:
            assert selection._prove({'project': PROJECT}, 'old', {'old': {}}, stack,
                                    authority_file='PUBLIC_SCOPED_AUTHORITY') == 'd'*64
    assert admitted == [True]


def test_foreign_qualification_never_substitutes_for_native_admission(monkeypatch):
    docker, context = foreign_context()
    monkeypatch.setattr(selection, '_inspect', lambda *_a, **_kw:
                        {'docker': docker, 'context': context, 'data_sha256': 'd'*64})
    def refuse(*_):raise ValueError('PUBLIC_NATIVE_REFUSAL')
    monkeypatch.setattr(selection, '_native_current', refuse)
    with ExitStack() as stack, pytest.raises(ValueError, match='PUBLIC_NATIVE_REFUSAL'):
        selection._prove({'project': PROJECT}, 'old', {'old': {}}, stack)
    assert docker.witness_calls == 0 and context.proof_count == 0


@pytest.mark.parametrize('change', ['independent', 'unlabelled', 'unknown-storage', 'producer-helper', 'candidate'])
def test_staging_keeps_guard_and_never_accepts_unsafe_context(monkeypatch, change):
    with staged_candidate(monkeypatch) as (_root, path, cfg, output, events):
        observed = selection._inspect(cfg, None, {}, None)
        docker = observed['docker'];containers = docker.containers
        produce = native.produce_generation
        def changing_producer(*args):
            result = produce(*args)
            rows = containers()
            if change == 'candidate':
                rows[0]['State']['StartedAt'] = 'CHANGED'
            else:
                item = context_container('b'*64 if change == 'producer-helper' else 'f'*64,
                                         None if change == 'unlabelled' else 'other')
                if change != 'unknown-storage':item['Mounts'] = []
                rows.append(item)
            monkeypatch.setattr(docker, 'containers', lambda: rows)
            return result
        monkeypatch.setattr(native, 'produce_generation', changing_producer)
        if change in {'independent', 'unlabelled'}:
            with selection.selected_inputs(path) as lease:lease.stage_renewal(output, 'marty-selfhost-synthetic')
            assert (output/'publication.json').exists()
        else:
            with pytest.raises((ValueError, selection.renewal.UnsafeRenewalContext)):
                with selection.selected_inputs(path) as lease:lease.stage_renewal(output, 'marty-selfhost-synthetic')
            assert not (output/'publication.json').exists() and not (output/'result.json').read_bytes()
        assert events.count('produce') == 1 and events.count('authority') == 1
        assert selection.renewal.renewal_staging_guard(cfg).exists()
        assert selection.status(path)['state'] == 'pending-staging'


@pytest.mark.parametrize('identity', ['id', 'name', 'label'])
def test_helper_appearing_during_native_reproof_still_blocks_reconciliation(monkeypatch, identity):
    with materialized(monkeypatch) as (_root, path, cfg, output, events):
        observed = selection._inspect(cfg, None, {}, None)
        docker = observed['docker'];containers = docker.containers
        helper = context_container('b'*64 if identity == 'id' else 'f'*64, 'other')
        helper['Mounts'] = []
        if identity == 'name':helper['Name'] = '/'+cfg['project']+'-renew-prepare-'+'a'*32
        elif identity == 'label':helper['Config']['Labels']['marty.windows.renewal'] = 'a'*32
        def native_with_new_helper(*_):
            monkeypatch.setattr(docker, 'containers', lambda: [*containers(), helper])
        monkeypatch.setattr(selection, '_native_current', native_with_new_helper)
        before = list(events)
        with pytest.raises(ValueError):selection.reconcile_materialized(path)
        assert events == before and not (output/'result.json').read_bytes()
        assert not (output/'publication.json').exists()
        assert selection.renewal.renewal_staging_guard(cfg).exists()
