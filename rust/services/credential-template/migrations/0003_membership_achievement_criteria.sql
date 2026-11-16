-- Forward repair of the stable membership seed only. A custom badge,
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
