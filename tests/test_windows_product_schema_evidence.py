"""No single migration witness may stand in for the complete application proof."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_windows_product_ledger import profiles
from test_windows_product_membership_data import before as member_before, after as member_after
from test_windows_product_startup import before as system_before, after as system_after
from test_windows_product_catalog import pair as catalogs
import selfhost_windows_product_journal as journal
import selfhost_windows_product_probe as probe
import selfhost_windows_product_ledger as ledger


def pair():
    profile_before, profile_after, ledger_before, ledger_after = profiles()
    catalog_before, catalog_after = catalogs()
    old = {'schema': profile_before, 'ledger': ledger_before, 'catalog': catalog_before,
           'membership': member_before(), 'startup': system_before()}
    new = {'schema': profile_after, 'ledger': ledger_after, 'catalog': catalog_after,
           'membership': member_after(), 'startup': system_after()}
    scope = probe._mutable_scope(old['membership'], old['startup'])
    retained = {'schema': 'marty.windows-retained-mutable-rows/v1', 'database': 'marty',
        'scope_sha256': hashlib.sha256(json.dumps(scope, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'tables': {entry['table']: {'rows': entry['rows'], 'masked': len(entry['keys']),
            'columns': ['id','unknown physical column'], 'sha256':'a'*64} for entry in scope.values()}}
    old['mutable_rows'] = retained;new['mutable_rows'] = deepcopy(retained)
    tables = {name:{'rows': 4,'sha256':'a'*64} for name in profile_before['databases']['marty']['migration_ledgers']}
    for name, row in ledger_before['ledgers'].items():tables[name]['rows'] = row['row_count']
    tables.update({entry['table']: {'rows':entry['rows'], 'sha256':'a'*64} for entry in scope.values()})
    tables['customer_schema.accounts'] = {'rows':1, 'sha256':'e'*64}
    old['rows'] = {'schema':'marty.windows-retained-application-rows/v1','database':'marty','tables':tables}
    new['rows'] = deepcopy(old['rows'])
    for table in set(ledger.BASELINES) | set(retained['tables']):new['rows']['tables'][table]['sha256'] = 'b'*64
    for name, row in ledger_after['ledgers'].items():new['rows']['tables'][name]['rows'] = row['row_count']
    new['rows']['tables']['trust_profile_service.credential_authority_revisions'] = {
        'rows':0, 'sha256':hashlib.sha256(b'[]').hexdigest()}
    for parts in (old,new):
        inventory = parts['schema']['databases']['marty']['row_inventory']
        inventory.update({table:['id'] for table in parts['rows']['tables'] if table not in inventory})
        for entry in scope.values():inventory[entry['table']] = ['id', 'unknown physical column', *entry['excluded']]
    for parts in (old,new):parts['catalog']['source_catalog_sha256'] = parts['schema']['databases']['marty']['catalog_sha256']
    return ({'schema':'marty.windows-application-schema-evidence/v1','side':'before','parts':old},
            {'schema':'marty.windows-application-schema-evidence/v1','side':'after','parts':new})


def test_all_proofs_bind_without_granting_runtime_or_release_admission():
    before, after = pair()
    result = journal.validate_application_schema_evidence(before, after)
    assert result['native_admission'] is False and result['product_transition_admission'] is False
    assert result['before_sha256'] == journal.selection.digest(journal.selection.packed(before))


@pytest.mark.parametrize('part', ['schema','rows','membership','startup','ledger','catalog','mutable_rows'])
def test_every_proof_is_mandatory(part):
    before, after = pair();del after['parts'][part]
    with pytest.raises(ValueError):journal.validate_application_schema_evidence(before, after)


@pytest.mark.parametrize('fault', ['customer-row','customer-removed','new-unreviewed-table','populated-authority',
    'authority-hash','missing-mutable','mutable-extra','mutable-scope','mutable-row-count','mutable-hash',
    'mutable-columns','masked-known-field','ledger-count','ledger-retention','catalog-unbound','catalog-v1',
    'semantic-repair','startup-payload','wrong-database','boolean-rows','rows-extra-field','known-ledger-omitted-both',
    'customer-omitted-both','physical-column-omitted-both'])
def test_combined_evidence_refuses_unbound_or_unexpected_changes(fault):
    before, after = pair();old=before['parts'];new=after['parts'];rows=new['rows']['tables']
    physical=new['mutable_rows']['tables']['credential_template_service.credential_templates']
    if fault=='customer-row':rows['customer_schema.accounts']['sha256']='f'*64
    elif fault=='customer-removed':del rows['customer_schema.accounts']
    elif fault=='new-unreviewed-table':rows['unknown.table']={'rows':0,'sha256':hashlib.sha256(b'[]').hexdigest()}
    elif fault=='populated-authority':rows['trust_profile_service.credential_authority_revisions']['rows']=1
    elif fault=='authority-hash':rows['trust_profile_service.credential_authority_revisions']['sha256']='f'*64
    elif fault=='missing-mutable':del new['mutable_rows']['tables']['credential_template_service.credential_templates']
    elif fault=='mutable-extra':physical['raw']='never accept raw rows'
    elif fault=='mutable-scope':new['mutable_rows']['scope_sha256']='f'*64
    elif fault=='mutable-row-count':physical['rows']+=1
    elif fault=='mutable-hash':physical['sha256']='f'*64
    elif fault=='mutable-columns':physical['columns'].append('other column')
    elif fault=='masked-known-field':physical['columns'].append('claims')
    elif fault=='ledger-count':rows[next(iter(ledger.BASELINES))]['rows']+=1
    elif fault=='ledger-retention':new['ledger']['ledgers'][next(iter(ledger.BASELINES))]['retained_sha256']='f'*64
    elif fault=='catalog-unbound':new['catalog']['source_catalog_sha256']='f'*64
    elif fault=='catalog-v1':old['catalog']['schema']='marty.windows-authority-catalog/v1'
    elif fault=='semantic-repair':new['membership']['credential_template']['observed_sha256']='f'*64
    elif fault=='startup-payload':new['startup']['roles']['observed_sha256']='f'*64
    elif fault=='wrong-database':new['rows']['database']='other'
    elif fault=='boolean-rows':rows['customer_schema.accounts']['rows']=True
    elif fault=='rows-extra-field':new['rows']['raw']='extra'
    elif fault=='known-ledger-omitted-both':
        for parts in (old,new):del parts['rows']['tables']['flow_service.rust_schema_versions']
    elif fault=='customer-omitted-both':
        for parts in (old,new):del parts['rows']['tables']['customer_schema.accounts']
    elif fault=='physical-column-omitted-both':
        for parts in (old,new):parts['mutable_rows']['tables']['credential_template_service.credential_templates']['columns'].remove('unknown physical column')
    with pytest.raises(ValueError):journal.validate_application_schema_evidence(before, after)
