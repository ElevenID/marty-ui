"""Retained-ledger fragment; never native execution or deployment admission."""
import re
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import selfhost_windows_product_ledger as ledger


def pair():
    before={'schema':ledger.SCHEMA,'side':'before','database_clock':'2026-01-01T00:00:00+00:00','ledgers':{}}
    after=dict(before,side='after',database_clock='2026-01-01T00:01:00+00:00',ledgers={})
    for name, versions in ledger.BASELINES.items():
        before['ledgers'][name]={'versions':sorted(versions),'row_count':len(versions),
            'rows_sha256':'a'*64,'canonical_rows':True}
        after['ledgers'][name]={'versions':sorted((*versions,ledger.ADDITIONS[name])),
            'row_count':len(versions)+1,'rows_sha256':'b'*64,'canonical_rows':True,
            'retained_sha256':'a'*64,'new_row_valid':True}
    return before,after


def test_baseline_plus_addition_matches_native_owner_version_inventory():
    ct=(ROOT/'rust/services/credential-template/src/migration.rs').read_text(encoding='utf-8')
    issuance=(ROOT/'rust/services/issuance/src/migration.rs').read_text(encoding='utf-8')
    trust=(ROOT/'rust/services/trust-profile/src/migration.rs').read_text(encoding='utf-8')
    expected=[set(re.findall(r'"(rust_credential_template_\d+)"',ct.split('const ADVISORY_LOCK_ID')[0])),
        set(re.findall(r'"(issuance_service_baseline_v1|\d{4}_[a-z0-9_]+)"',issuance.split('const BASE_TABLES')[0])),
        set(re.findall(r'const [A-Z_]+VERSION: &str = "([^"]+)"',trust))]
    for (name,versions), actual in zip(ledger.BASELINES.items(),expected):
        assert set(versions)|{ledger.ADDITIONS[name]}==actual


@pytest.mark.parametrize('table',list(ledger.BASELINES))
@pytest.mark.parametrize('fault',['old-edited','missing-old','unknown-version','new-missing',
    'timestamp-invalid','canonical-invalid','duplicate','boolean-count','extra-evidence'])
def test_exact_retained_rows_and_addition_required(table,fault):
    before,after=pair();row=after['ledgers'][table]
    if fault=='old-edited':row['retained_sha256']='c'*64
    elif fault=='missing-old':row['versions'].pop(0)
    elif fault=='unknown-version':row['versions'].append('unexpected')
    elif fault=='new-missing':row['versions'].remove(ledger.ADDITIONS[table])
    elif fault=='timestamp-invalid':row['new_row_valid']=False
    elif fault=='canonical-invalid':row['canonical_rows']=False
    elif fault=='duplicate':row['versions'].append(row['versions'][0])
    elif fault=='boolean-count':row['row_count']=True
    else:row['unbound']='extra'
    with pytest.raises(ValueError):ledger.validate_delta(before,after)


@pytest.mark.parametrize('fault',['upgraded','historical','missing','clock','ledger-extra'])
def test_before_refuses_partial_unknown_or_injected_state(fault):
    before,_=pair();name=next(iter(ledger.BASELINES))
    if fault=='upgraded':before['ledgers'][name]['versions'].append(ledger.ADDITIONS[name])
    elif fault=='historical':before['ledgers'][name]['versions']=['alembic']
    elif fault=='missing':del before['ledgers'][name]
    elif fault=='clock':before['database_clock']="';SELECT"
    else:before['ledgers']['injected']={}
    with pytest.raises(ValueError):ledger.statement(before)


def test_fragment_queries_read_only_and_never_grant_admission():
    before,after=pair()
    for sql in [ledger.statement(),ledger.statement(before)]:
        assert not re.search(r'\b(UPDATE|INSERT|DELETE|ALTER|CREATE|DROP|TRUNCATE)\b',sql,re.I)
    receipt=ledger.validate_delta(before,after)
    assert receipt['native_admission']is False and receipt['product_transition_admission']is False
