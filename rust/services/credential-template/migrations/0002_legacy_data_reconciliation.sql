-- Final-state, one-way repairs retained from the Python Alembic history.
-- Statements are idempotent and scoped to known system records or invalid
-- legacy states; tenant-authored valid templates are not rewritten.

UPDATE credential_template_service.credential_templates
SET compliance_profile = jsonb_build_object(
        'compliance_code', 'CUSTOM',
        'credential_format', CASE
            WHEN lower(coalesce(credential_payload_format, '')) LIKE '%mdoc%' THEN 'mdoc'
            ELSE 'sd_jwt_vc'
        END
    )
WHERE compliance_profile IS NULL;

UPDATE credential_template_service.credential_templates
SET status = 'deprecated',
    name = CASE id
        WHEN '50000000-0000-0000-0000-000000000060' THEN 'Legacy ePassport Prototype'
        ELSE 'Legacy Travel Credential Prototype'
    END,
    description = 'Legacy prototype retained for migration history. It is not an ICAO eMRTD or ICAO Digital Travel Credential implementation.',
    wallet_configs = '[]'::jsonb,
    updated_at = now()
WHERE id IN (
        '40000000-0000-0000-0000-000000000006',
        '50000000-0000-0000-0000-000000000060',
        '50000000-0000-0000-0000-000000000070',
        '50000000-0000-0000-0000-000000000080'
    )
   OR credential_type IN ('dtc', 'com.icao.mrv', 'com.icao.dtc.1', 'com.icao.dtc.2');

UPDATE credential_template_service.credential_templates
SET name = 'Passport-style Credential (Demo)',
    description = 'Demo passport-style application credential. It is not an ICAO eMRTD and does not represent ICAO conformance.',
    doctype = NULL,
    compliance_profile = jsonb_build_object(
        'compliance_code', 'CUSTOM',
        'credential_format', 'sd_jwt_vc'
    ),
    updated_at = now()
WHERE credential_type = 'passport';

UPDATE credential_template_service.credential_templates
SET status = 'deprecated',
    name = 'Legacy mDL Issuance Prototype',
    description = 'Legacy prototype retained for migration history. It is not an authorized AAMVA mDL issuer, does not establish wallet compatibility, and must not be used for production issuance.',
    wallet_configs = '[]'::jsonb,
    updated_at = now()
WHERE id IN (
    '40000000-0000-0000-0000-000000000008',
    '50000000-0000-0000-0000-000000000020'
);

UPDATE credential_template_service.credential_templates
SET credential_payload_format = 'jwt_vc',
    supported_formats = '["jwt_vc"]'::jsonb,
    selective_disclosure_fields = '[]'::jsonb,
    wallet_configs = COALESCE((
        SELECT jsonb_agg(
            CASE WHEN entry->>'wallet_id' = 'wr-spruce-001'
                THEN (entry
                    || jsonb_build_object('format_variant', 'jwt_vc_json')
                    || jsonb_build_object('credential_configuration_id', 'OpenBadgeCredential#jwt-vc'))
                    - 'issuer_url_suffix'
                ELSE entry
            END
            ORDER BY ordinal
        )
        FROM jsonb_array_elements(COALESCE(wallet_configs::jsonb, '[]'::jsonb))
            WITH ORDINALITY AS config(entry, ordinal)
    ), '[]'::jsonb),
    version = greatest(version, 4),
    updated_at = now()
WHERE id = '50000000-0000-0000-0000-000000000040'
  AND organization_id = '00000000-0000-0000-0000-000000000001';

WITH normalized AS (
    SELECT template.id,
        jsonb_agg(
            CASE
                WHEN config->>'format_variant' = 'spruce-vc+sd-jwt'
                  OR config->>'credential_configuration_id' LIKE '%#spruce-sd-jwt'
                  OR config->>'issuer_url_suffix' = '/spruce'
                THEN config - 'format_variant' - 'credential_configuration_id' - 'issuer_url_suffix'
                ELSE config
            END
            ORDER BY ordinal
        ) AS wallet_configs
    FROM credential_template_service.credential_templates AS template
    CROSS JOIN LATERAL jsonb_array_elements(COALESCE(template.wallet_configs::jsonb, '[]'::jsonb))
        WITH ORDINALITY AS entry(config, ordinal)
    GROUP BY template.id
    HAVING bool_or(
        config->>'format_variant' = 'spruce-vc+sd-jwt'
        OR config->>'credential_configuration_id' LIKE '%#spruce-sd-jwt'
        OR config->>'issuer_url_suffix' = '/spruce'
    )
)
UPDATE credential_template_service.credential_templates AS template
SET wallet_configs = normalized.wallet_configs,
    updated_at = now()
FROM normalized
WHERE template.id = normalized.id;

UPDATE credential_template_service.credential_templates
SET compliance_profile_id = CASE
        WHEN id IN (
            '40000000-0000-0000-0000-000000000007',
            '50000000-0000-0000-0000-000000000040'
        ) THEN '10000000-0000-0000-0000-000000000003'
        WHEN lower(coalesce(credential_payload_format, '')) IN ('mdoc', 'mso_mdoc')
            THEN '10000000-0000-0000-0000-000000000002'
        WHEN lower(coalesce(credential_payload_format, '')) = 'vds_nc'
            THEN '10000000-0000-0000-0000-000000000004'
        ELSE '10000000-0000-0000-0000-000000000001'
    END,
    version = coalesce(version, 0) + 1,
    updated_at = now()
WHERE nullif(trim(compliance_profile_id), '') IS NULL;

ALTER TABLE credential_template_service.credential_templates
    ALTER COLUMN compliance_profile_id SET NOT NULL;

INSERT INTO credential_template_service.rust_schema_versions(version)
VALUES ('rust_credential_template_0002')
ON CONFLICT (version) DO NOTHING;
