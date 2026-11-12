"""Read-only data witnesses for the reviewed membership repair cohort.

These fingerprints are fragments of migration evidence, never permission to
migrate, change a product selection, or waive catalog/native/custody admission.
Ordinary rows stay inside PostgreSQL. Qualify the entire startup transition on
isolated retained state before integrating this witness into the product owner.
"""
import datetime
import hashlib
import json
import re

import selfhost_windows_product_probe as probe

SCHEMA = 'marty.windows-membership-data-witness/v1'
TABLES = ('credential_template', 'issuance_application')
MAX_KEYS = 64
MAX_ROWS = 2048
SHA = re.compile(r'[0-9a-f]{64}\Z')
STOCK_ID = '50000000-0000-0000-0000-000000000040'

CREDENTIAL_REPAIR = r'''-- Forward repair of the stable membership seed only. A custom badge,
-- an existing criteria claim, or a nested achievement mapping retains its
-- existing contract and must be reviewed by its owner before stricter issuance.
UPDATE credential_template_service.credential_templates
SET claims = claims::jsonb || '[{
        "id":"marty-ob-achievement-criteria",
        "name":"achievement_criteria",
        "display_name":"Badge Criteria",
        "description":"Issuer-configured criteria for the membership achievement",
        "claim_type":"object",
        "required":true,
        "selectively_disclosable":false,
        "derivable":false,
        "derived_from":null,
        "pattern":null,
        "enum_values":null,
        "min_value":null,
        "max_value":null,
        "mdoc_namespace":null,
        "mdoc_element_identifier":null,
        "display_icon":null
    }]'::jsonb,
    version = coalesce(version, 0) + 1,
    updated_at = now()
WHERE id = '50000000-0000-0000-0000-000000000040'
  AND name = 'Marty Verified Member Badge'
  AND lower(credential_type) IN ('open_badge', 'open_badge_v3', 'openbadgecredential')
  AND doctype = 'org.openbadges.v3'
  AND vct LIKE '%/credentials/marty-verified-member-badge'
  AND jsonb_typeof(claims::jsonb) = 'array'
  AND NOT EXISTS (
      SELECT 1 FROM jsonb_array_elements(
          CASE WHEN jsonb_typeof(claims::jsonb) = 'array' THEN claims::jsonb ELSE '[]'::jsonb END
      ) AS claim
      WHERE claim->>'name' IN ('achievement_criteria', 'achievement')
  );

INSERT INTO credential_template_service.rust_schema_versions(version)
VALUES ('rust_credential_template_0003')
ON CONFLICT (version) DO NOTHING;
'''
CREDENTIAL_REPAIR_SHA256 = '8d4a006db83610c3253bf00504f779939e43069b9e45dde2074694891d9a0987'

APPLICATION_REPAIR = r'''-- The stock membership application must reach APPROVED before it can issue.
-- AUTO approval is a valid configured policy; this narrative does not claim
-- manual review, independent identity verification, or course attainment.
-- Append only to the generated stock application. Preserve existing criteria,
-- nested achievement mappings, forms, approval policy and customer templates.
DO $repair$
DECLARE
    retained_stock_application boolean;
BEGIN
SELECT EXISTS (
    SELECT 1 FROM issuance_service.application_templates
    WHERE credential_template_id = '50000000-0000-0000-0000-000000000040'
      AND name = 'Marty Verified Member Badge Application'
      AND ui_config::jsonb ? 'mip_0_3_system_claim_migration'
) INTO retained_stock_application;
IF to_regclass('credential_template_service.credential_templates') IS NULL THEN
    IF retained_stock_application THEN
        RAISE EXCEPTION 'MEMBERSHIP_CRITERIA_CATALOG_MISSING: migrate the credential template catalog before repairing the retained membership application';
    END IF;
    RETURN;
END IF;
IF retained_stock_application AND NOT EXISTS (
    SELECT 1 FROM credential_template_service.credential_templates
    WHERE id = '50000000-0000-0000-0000-000000000040'
) THEN
    RAISE EXCEPTION 'MEMBERSHIP_CRITERIA_CATALOG_MISSING: restore the retained membership credential template before repairing its application';
END IF;

UPDATE issuance_service.application_templates AS application
SET claim_collection_rules = application.claim_collection_rules::jsonb || '[{
        "claim_name":"achievement_criteria",
        "source":"SYSTEM",
        "source_config":{
            "system_field":"constant",
            "value":{"narrative":"Submit a membership application that is approved under the issuing organization\u0027s configured approval policy."}
        }
    }]'::jsonb,
    management_version = application.management_version + 1,
    updated_at = now()
FROM credential_template_service.credential_templates AS credential
WHERE credential.id = '50000000-0000-0000-0000-000000000040'
  AND credential.name = 'Marty Verified Member Badge'
  AND lower(credential.credential_type) IN ('open_badge', 'open_badge_v3', 'openbadgecredential')
  AND credential.doctype = 'org.openbadges.v3'
  AND credential.vct LIKE '%/credentials/marty-verified-member-badge'
  -- Accept the legacy stock catalog too, so the two service owners can migrate
  -- in either order. Custom flat/nested claim definitions remain untouched.
  AND jsonb_typeof(credential.claims::jsonb) = 'array'
  AND NOT EXISTS (
      SELECT 1 FROM jsonb_array_elements(
          CASE WHEN jsonb_typeof(credential.claims::jsonb) = 'array'
              THEN credential.claims::jsonb ELSE '[]'::jsonb END
      ) AS claim
      WHERE claim->>'name' = 'achievement'
  )
  AND (
      SELECT count(*) <= 1 AND coalesce(bool_and(claim = '{
          "id":"marty-ob-achievement-criteria",
          "name":"achievement_criteria",
          "display_name":"Badge Criteria",
          "description":"Issuer-configured criteria for the membership achievement",
          "claim_type":"object",
          "required":true,
          "selectively_disclosable":false,
          "derivable":false,
          "derived_from":null,
          "pattern":null,
          "enum_values":null,
          "min_value":null,
          "max_value":null,
          "mdoc_namespace":null,
          "mdoc_element_identifier":null,
          "display_icon":null
      }'::jsonb), true)
      FROM jsonb_array_elements(
          CASE WHEN jsonb_typeof(credential.claims::jsonb) = 'array'
              THEN credential.claims::jsonb ELSE '[]'::jsonb END
      ) AS claim
      WHERE claim->>'name' = 'achievement_criteria'
  )
  AND application.credential_template_id = credential.id
  AND application.organization_id = credential.organization_id
  AND application.name = 'Marty Verified Member Badge Application'
  AND application.ui_config::jsonb ? 'mip_0_3_system_claim_migration'
  AND jsonb_typeof(application.form_fields::jsonb) = 'array'
  AND jsonb_typeof(application.claim_collection_rules::jsonb) = 'array'
  AND application.claim_collection_rules::jsonb @> '[
      {"claim_name":"achievement_name","source":"SYSTEM","source_config":{"system_field":"template.name"}},
      {"claim_name":"achievement_description","source":"SYSTEM","source_config":{"system_field":"template.description"}}
  ]'::jsonb
  AND NOT EXISTS (
      SELECT 1 FROM jsonb_array_elements(
          CASE WHEN jsonb_typeof(application.claim_collection_rules::jsonb) = 'array'
              THEN application.claim_collection_rules::jsonb ELSE '[]'::jsonb END
      ) AS rule
      WHERE rule->>'claim_name' IN ('achievement_criteria', 'achievement')
  )
  AND NOT EXISTS (
      SELECT 1 FROM jsonb_array_elements(
          CASE WHEN jsonb_typeof(application.form_fields::jsonb) = 'array'
              THEN application.form_fields::jsonb ELSE '[]'::jsonb END
      ) AS field
      WHERE field->>'field_id' IN ('achievement_criteria', 'achievement')
  );
END
$repair$;
'''
APPLICATION_REPAIR_SHA256 = '2becfb8d83bfe775f75a95d6b1aa17b317cdcec825f1350e181e93347d67bb7e'


def require(value, message='Membership data witness refused'):
    if not value:raise ValueError(message)


def _parts():
    # Only these exact reviewed statements are translated to SELECT projections.
    # This is not an SQL parser and never accepts artifact/caller supplied SQL.
    require(hashlib.sha256(CREDENTIAL_REPAIR.encode()).hexdigest() == CREDENTIAL_REPAIR_SHA256)
    require(hashlib.sha256(APPLICATION_REPAIR.encode()).hexdigest() == APPLICATION_REPAIR_SHA256)
    claims = CREDENTIAL_REPAIR.split('\nSET claims = ', 1)[1].split(',\n    version = ', 1)[0]
    template_where = CREDENTIAL_REPAIR.split('\nWHERE ', 1)[1].split(';\n\nINSERT INTO', 1)[0]
    rules = APPLICATION_REPAIR.split('\nSET claim_collection_rules = ', 1)[1].split(',\n    management_version = ', 1)[0]
    application_where = APPLICATION_REPAIR.split('\nWHERE ', 1)[1].rsplit(';\nEND\n$repair$;', 1)[0]
    return claims, template_where, rules, application_where


def _hash(expression):
    return "encode(sha256(convert_to(COALESCE("+expression+",'[]'::jsonb)::text,'UTF8')),'hex')"


def _raw(alias, *, eligible):
    # Keep the complete physical row nested; projection names may also be real columns.
    return alias+"._cohort_row"


def _before_table(alias, change):
    payload = _raw(alias,eligible=True)
    expected = "CASE WHEN _cohort_eligible THEN ("+payload+"-'updated_at') || "+change+" ELSE "+payload+" END"
    return "jsonb_build_object('row_count',count(*),'eligible_id_sha256',COALESCE(jsonb_agg(_cohort_id_sha256 ORDER BY _cohort_id_sha256) FILTER (WHERE _cohort_eligible),'[]'::jsonb),'observed_sha256',"+_hash('jsonb_agg('+payload+' ORDER BY _cohort_order_id)')+",'expected_after_sha256',"+_hash('jsonb_agg(('+expected+') ORDER BY _cohort_order_id)')+")"


def before_sql():
    claims, template_where, rules, application_where = _parts()
    template_change = "jsonb_build_object('claims',("+claims+"),'version',coalesce(version,0)+1)"
    application_change = "jsonb_build_object('claim_collection_rules',("+rules+"),'management_version',management_version+1)"
    return """WITH template_rows AS (
        SELECT to_jsonb(candidate) AS _cohort_row, candidate.id AS _cohort_order_id, candidate.claims, candidate.version, encode(sha256(convert_to(candidate.id::text,'UTF8')),'hex') AS _cohort_id_sha256,
            coalesce(("""+template_where+"""),false) AS _cohort_eligible
        FROM credential_template_service.credential_templates candidate LIMIT """+str(MAX_ROWS+1)+"""
    ), application_rows AS (
        SELECT to_jsonb(application) AS _cohort_row, application.id AS _cohort_order_id, application.claim_collection_rules, application.management_version, encode(sha256(convert_to(application.id::text,'UTF8')),'hex') AS _cohort_id_sha256,
            EXISTS (SELECT 1 FROM credential_template_service.credential_templates credential WHERE """+application_where+""") AS _cohort_eligible
        FROM issuance_service.application_templates application LIMIT """+str(MAX_ROWS+1)+"""
    ) SELECT jsonb_build_object('schema','"""+SCHEMA+"""','side','before','database_clock',clock_timestamp(),
        'catalog_ready',NOT(EXISTS(SELECT 1 FROM issuance_service.application_templates
            WHERE credential_template_id='"""+STOCK_ID+"""' AND name='Marty Verified Member Badge Application'
            AND ui_config::jsonb ? 'mip_0_3_system_claim_migration')
            AND NOT EXISTS(SELECT 1 FROM credential_template_service.credential_templates WHERE id='"""+STOCK_ID+"""')),
        'credential_template',(SELECT """+_before_table('template_rows',template_change)+""" FROM template_rows),
        'issuance_application',(SELECT """+_before_table('application',application_change)+""" FROM application_rows application));"""


def _clock(value):
    require(type(value) is str)
    moment = datetime.datetime.fromisoformat(value)
    require(moment.tzinfo is not None)
    return moment.astimezone(datetime.timezone.utc)


def validate_before(value):
    require(type(value) is dict and set(value) == {'schema','side','database_clock','catalog_ready',*TABLES})
    require(value['schema'] == SCHEMA and value['side'] == 'before' and value['catalog_ready'] is True)
    _clock(value['database_clock'])
    for name in TABLES:
        row=value[name]
        require(type(row) is dict and set(row)=={'row_count','eligible_id_sha256','observed_sha256','expected_after_sha256'})
        require(type(row['row_count']) is int and 0<=row['row_count']<=MAX_ROWS)
        keys=row['eligible_id_sha256']
        require(type(keys) is list and len(keys)<=min(MAX_KEYS,row['row_count'])
                and all(type(key) is str and SHA.fullmatch(key) for key in keys)
                and keys==sorted(set(keys)))
        require(all(type(row[key]) is str and SHA.fullmatch(row[key]) for key in ('observed_sha256','expected_after_sha256')))


def _after_table(alias, keys, floor):
    # Values are canonical timestamps or fixed-length lowercase hex, never SQL.
    selected="_cohort_id_sha256 = ANY(ARRAY["+','.join("'"+key+"'" for key in keys)+"]::text[])"
    payload=_raw(alias,eligible=False)
    normalized="CASE WHEN "+selected+" THEN "+payload+"-'updated_at' ELSE "+payload+" END"
    return "jsonb_build_object('row_count',count(*),'masked_rows',count(*) FILTER (WHERE "+selected+"),'updated_at_in_window',coalesce(bool_and(CASE WHEN "+selected+" THEN coalesce(updated_at >= '"+floor+"'::timestamptz AND updated_at <= clock_timestamp(),false) ELSE true END),true),'observed_sha256',"+_hash('jsonb_agg(('+normalized+') ORDER BY _cohort_order_id)')+")"


def after_sql(before):
    validate_before(before)
    floor=_clock(before['database_clock']).isoformat()
    return """WITH template_rows AS (
        SELECT to_jsonb(candidate) AS _cohort_row, candidate.id AS _cohort_order_id, candidate.updated_at, encode(sha256(convert_to(candidate.id::text,'UTF8')),'hex') AS _cohort_id_sha256
        FROM credential_template_service.credential_templates candidate LIMIT """+str(MAX_ROWS+1)+"""
    ), application_rows AS (
        SELECT to_jsonb(candidate) AS _cohort_row, candidate.id AS _cohort_order_id, candidate.updated_at, encode(sha256(convert_to(candidate.id::text,'UTF8')),'hex') AS _cohort_id_sha256
        FROM issuance_service.application_templates candidate LIMIT """+str(MAX_ROWS+1)+"""
    ) SELECT jsonb_build_object('schema','"""+SCHEMA+"""','side','after','database_clock',clock_timestamp(),
        'credential_template',(SELECT """+_after_table('template_rows',before['credential_template']['eligible_id_sha256'],floor)+""" FROM template_rows),
        'issuance_application',(SELECT """+_after_table('application_rows',before['issuance_application']['eligible_id_sha256'],floor)+""" FROM application_rows));"""


def capture(docker, items, project, *, before=None, profile=probe.LedgerProfile()):
    require(type(profile) is probe.LedgerProfile)
    statement=before_sql() if before is None else after_sql(before)
    base=probe._postgres_base(items,project)
    raw=probe._text(docker,[base[0],'--interactive',*base[1:],'--dbname',profile.application,'--file=-'],stdin_bytes=statement.encode())
    result=json.loads(raw)
    if before is None:validate_before(result)
    else:validate_delta(before,result)
    return result


def validate_delta(before, after):
    validate_before(before)
    require(type(after) is dict and set(after)=={'schema','side','database_clock',*TABLES})
    require(after['schema']==SCHEMA and after['side']=='after'
            and _clock(after['database_clock'])>=_clock(before['database_clock']))
    for name in TABLES:
        row=after[name];prior=before[name]
        require(type(row) is dict and set(row)=={'row_count','masked_rows','updated_at_in_window','observed_sha256'})
        require(type(row['row_count']) is int and row['row_count']==prior['row_count']
                and type(row['masked_rows']) is int and row['masked_rows']==len(prior['eligible_id_sha256'])
                and row['updated_at_in_window'] is True
                and type(row['observed_sha256']) is str and SHA.fullmatch(row['observed_sha256'])
                and row['observed_sha256']==prior['expected_after_sha256'])
    return {'schema':'marty.windows-membership-data-delta/v1',
            'before_sha256':hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest(),
            'after_sha256':hashlib.sha256(json.dumps(after,sort_keys=True).encode()).hexdigest(),
            'ordinary_row_data_returned':False,'native_admission':False,'product_transition_admission':False}
