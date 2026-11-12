"""Physical projections supplement the exact semantic repair witnesses."""
from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_windows_product_membership_data import before as membership_before
from test_windows_product_startup import before as startup_before
from test_windows_product_probe import PROJECT, item
import selfhost_windows_product_probe as probe


def records():
    scope = probe._mutable_scope(membership_before(), startup_before())
    return [{'kind': 'support', 'supported': True}]+[{'kind': 'rows', 'table': entry['table'],
        'rows': entry['rows'], 'masked': len(entry['keys']), 'columns': ['id', 'unknown physical column'],
        'excluded': sorted(entry['excluded']), 'sha256': 'a'*64} for _,entry in sorted(scope.items())]


def capture(monkeypatch, rows):
    def text(_docker, args, *, stdin_bytes):
        assert '--file=-' in args and probe.PG_OPTIONS in args
        sql = stdin_bytes.decode()
        assert 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;' in sql
        assert "format('t.%I',attname)" in sql and 'ROW(%s)::text ELSE t::text' in sql
        assert 'SET LOCAL extra_float_digits=3' in sql and probe.ROW_UNSUPPORTED in sql
        return '\n'.join(json.dumps(row) for row in rows)
    monkeypatch.setattr(probe, '_text', text)
    return probe.retained_mutable_rows_snapshot(object(), [item('postgres')], PROJECT,
                                               membership_before(), startup_before())


def test_exact_seven_scoped_projections_return_only_metadata_and_hashes(monkeypatch):
    result = capture(monkeypatch, records())
    assert set(result['tables']) == {table for table,_ in probe.MUTABLE_TABLES.values()}
    assert result['schema'] == 'marty.windows-retained-mutable-rows/v1'
    assert probe.SHA.fullmatch(result['scope_sha256'])
    assert all(row['columns'] == ['id','unknown physical column'] for row in result['tables'].values())


@pytest.mark.parametrize('fault', ['unsupported', 'missing-table', 'extra-table', 'table-swap', 'row-count',
    'boolean-count', 'masked-count', 'missing-id', 'duplicate-column', 'excluded-kept', 'missing-exclusion',
    'extra-exclusion', 'raw-payload', 'bad-hash'])
def test_projection_never_omits_rows_fields_or_tables(monkeypatch, fault):
    rows = records();row = rows[1]
    if fault == 'unsupported':rows[0]['supported'] = False
    elif fault == 'missing-table':rows.pop()
    elif fault == 'extra-table':rows.append(deepcopy(row))
    elif fault == 'table-swap':row['table'] = 'unknown.table'
    elif fault == 'row-count':row['rows'] += 1
    elif fault == 'boolean-count':row['rows'] = True
    elif fault == 'masked-count':row['masked'] += 1
    elif fault == 'missing-id':row['columns'].remove('id')
    elif fault == 'duplicate-column':row['columns'].append('id')
    elif fault == 'excluded-kept':row['columns'].append(row['excluded'][0])
    elif fault == 'missing-exclusion':row['excluded'].pop()
    elif fault == 'extra-exclusion':row['excluded'].append('unknown')
    elif fault == 'raw-payload':row['data'] = 'never accept raw row values'
    elif fault == 'bad-hash':row['sha256'] = 'raw-row'
    with pytest.raises(ValueError):capture(monkeypatch, rows)
