"""Read-only ledger fragment for the retained Rust-owned membership cohort.

This does not run migrations or grant product/native admission. The complete
source/image, catalog, full-startup data and custody proofs remain mandatory.
The existing product owner does not consume this fragment yet.
"""
import hashlib
import json

import selfhost_windows_product_probe as probe
from selfhost_windows_product_schema import _clock

SCHEMA = 'marty.windows-membership-ledgers/v1'
BASELINES = {
    'credential_template_service.rust_schema_versions': (
        'rust_credential_template_0001', 'rust_credential_template_0002'),
    'issuance_service.rust_schema_migrations': (
        'issuance_service_baseline_v1', '0001_oid4vci_public_protocol',
        '0002_physical_document_jobs', '0003_passport_bureau_provider_binding',
        '0004_passport_submission_intent', '0005_passport_submission_provenance',
        '0006_passport_beta_batch_identity', '0007_passport_beta_batch_provenance',
        '0008_passport_beta_batch_wire_evidence', '0009_authenticated_mdoc_status_binding',
        '0010_passport_start_idempotency', '0011_passport_administrative_cancellation'),
    'trust_profile_service.native_migrations': ('trust-profile-rust-v1',),
}
ADDITIONS = {
    'credential_template_service.rust_schema_versions': 'rust_credential_template_0003',
    'issuance_service.rust_schema_migrations': '0012_membership_achievement_criteria',
    'trust_profile_service.native_migrations': 'trust-profile-credential-authority-v1',
}


def require(value):
    if not value:raise ValueError('Retained membership ledger witness refused')


def _hash(expression):
    return "encode(sha256(convert_to(coalesce("+expression+",'[]'::jsonb)::text,'UTF8')),'hex')"


def statement(before=None):
    """One bounded read-only MVCC statement; no caller-provided SQL/identifiers."""
    if before is not None:validate_before(before)
    floor = None if before is None else _clock(before['database_clock']).isoformat()
    parts=[]
    for table, baseline in BASELINES.items():
        target=ADDITIONS[table]
        old_filter="version <> '"+target+"'"
        all_rows='jsonb_agg(to_jsonb(ledger) ORDER BY version)'
        values=["'versions',coalesce(jsonb_agg(version ORDER BY version),'[]'::jsonb)",
                "'row_count',count(*)", "'rows_sha256',"+_hash(all_rows),
                "'canonical_rows',coalesce(bool_and(applied_at IS NOT NULL AND (to_jsonb(ledger)-ARRAY['version','applied_at'])='{}'::jsonb),false)"]
        if before is not None:
            values += ["'retained_sha256',"+_hash(all_rows+' FILTER (WHERE '+old_filter+')'),
                       "'new_row_valid',coalesce(bool_and((to_jsonb(ledger)-'applied_at')=jsonb_build_object('version','"+target+"') AND coalesce(applied_at >= '"+floor+"'::timestamptz AND applied_at <= clock_timestamp(),false)) FILTER (WHERE NOT ("+old_filter+")),false)"]
        # Limits bound the proof, not an allowance to omit unexpected rows.
        query='SELECT jsonb_build_object('+','.join(values)+') FROM (SELECT * FROM '+table+' LIMIT 65) ledger'
        parts += ["'"+table+"',("+query+")"]
    return "SELECT jsonb_build_object('schema','"+SCHEMA+"','side','"+('before' if before is None else 'after')+"','database_clock',clock_timestamp(),'ledgers',jsonb_build_object("+','.join(parts)+'));'


def _validate(value, side):
    require(type(value) is dict and set(value)=={'schema','side','database_clock','ledgers'})
    require(value['schema']==SCHEMA and value['side']==side)
    _clock(value['database_clock'])
    require(type(value['ledgers']) is dict and set(value['ledgers'])==set(BASELINES))
    for name, baseline in BASELINES.items():
        row=value['ledgers'][name]
        keys={'versions','row_count','rows_sha256','canonical_rows'}
        if side=='after':keys|={'retained_sha256','new_row_valid'}
        require(type(row) is dict and set(row)==keys)
        expected=sorted((*baseline, *((ADDITIONS[name],) if side=='after' else ())))
        require(type(row['versions']) is list and row['versions']==expected
                and type(row['row_count']) is int and row['row_count']==len(expected)
                and row['canonical_rows'] is True)
        for key in ('rows_sha256','retained_sha256') if side=='after' else ('rows_sha256',):
            require(type(row[key]) is str and probe.SHA.fullmatch(row[key]))
        if side=='after':require(row['new_row_valid'] is True)


def validate_before(before):
    _validate(before,'before')


def validate_delta(before, after):
    validate_before(before);_validate(after,'after')
    require(_clock(after['database_clock'])>=_clock(before['database_clock']))
    for table in BASELINES:
        require(after['ledgers'][table]['retained_sha256']==before['ledgers'][table]['rows_sha256'])
    digest=lambda v:hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'schema':'marty.windows-membership-ledger-delta/v1',
            'before_sha256':digest(before),'after_sha256':digest(after),
            'native_admission':False,'product_transition_admission':False}


def capture(docker, items, project, *, before=None, profile=probe.LedgerProfile()):
    require(type(profile) is probe.LedgerProfile)
    base=probe._postgres_base(items,project)
    result=json.loads(probe._text(docker,[base[0],'--interactive',*base[1:],
        '--dbname',profile.application,'--file=-'],stdin_bytes=statement(before).encode()))
    if before is None:validate_before(result)
    else:validate_delta(before,result)
    return result
