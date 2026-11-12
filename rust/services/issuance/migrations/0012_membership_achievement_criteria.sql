-- The stock membership application must reach APPROVED before it can issue.
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
  AND (credential.claims::jsonb @> '[{"id":"marty-ob-achievement-criteria","name":"achievement_criteria","claim_type":"object","required":true,"description":"Issuer-configured criteria for the membership achievement"}]'::jsonb
      OR NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(
              CASE WHEN jsonb_typeof(credential.claims::jsonb) = 'array'
                  THEN credential.claims::jsonb ELSE '[]'::jsonb END
          ) AS claim
          WHERE claim->>'name' IN ('achievement_criteria', 'achievement')
      ))
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
