-- Included by passport-beta-fence-install.sql after its ACCESS EXCLUSIVE locks.
-- Keep the count predicates identical to the frozen beta drain preflight.
DO $drain$
DECLARE pending_jobs bigint;
DECLARE incompatible_artifacts bigint;
DECLARE active_flows bigint;
BEGIN
    SELECT count(*) INTO pending_jobs
    FROM issuance_service.physical_document_jobs
    WHERE status NOT IN ('ACTIVE', 'FAILED', 'CANCELLED');

    WITH artifacts AS (
        SELECT CASE WHEN left(secure_artifact_ciphertext, 1) = '{'
            THEN secure_artifact_ciphertext::jsonb ELSE NULL END AS manifest,
            CASE WHEN left(secure_artifact_ciphertext, 1) = '{'
            THEN secure_artifact_ciphertext::json ELSE NULL END AS raw_manifest
        FROM issuance_service.physical_document_jobs
    )
    SELECT count(*) INTO incompatible_artifacts FROM artifacts WHERE CASE
        WHEN manifest IS NULL THEN true
        WHEN jsonb_typeof(manifest) IS DISTINCT FROM 'object' THEN true
        WHEN (SELECT count(*) FROM json_each(raw_manifest)) <> 2 THEN true
        WHEN manifest->>'schema' IS DISTINCT FROM 'marty.passport-artifact-manifest/v1'
            OR jsonb_typeof(manifest->'chunks') IS DISTINCT FROM 'array'
            OR manifest - 'schema' - 'chunks' <> '{}'::jsonb THEN true
        WHEN jsonb_array_length(manifest->'chunks') NOT BETWEEN 1 AND 4096 THEN true
        WHEN EXISTS (
            SELECT 1 FROM jsonb_array_elements(manifest->'chunks') AS chunk(value)
            WHERE jsonb_typeof(chunk.value) <> 'string'
                OR left(chunk.value #>> '{}', 7) <> 'vault:v'
                OR length(chunk.value #>> '{}') > 2000000
        ) THEN true
        ELSE false
    END;

    SELECT count(*) INTO active_flows
    FROM flow_service.flow_instances AS instance
    LEFT JOIN flow_service.flow_definitions AS definition
        ON definition.id = instance.flow_definition_id
    WHERE ((definition.id IS NULL AND NOT COALESCE((
            instance.status = 'awaiting_wallet'
            AND instance.expires_at < clock_timestamp()
            AND instance.current_step_id IS NULL
            AND instance.application_flow_key_hash IS NULL
            AND instance.step_history::jsonb = '[]'::jsonb
            AND instance.context::jsonb->>'flow_definition_reference' = '__verification__'
            AND instance.context::jsonb->>'flow_type' = 'verification'
            AND instance.context::jsonb->>'protocol_flow_type' = 'oid4vp_presentation'
            AND jsonb_typeof(instance.context::jsonb->'auth_request') = 'string'
            AND nullif(btrim(instance.context::jsonb->>'auth_request'), '') IS NOT NULL
            AND jsonb_typeof(instance.context::jsonb->'oid4vp_profile') = 'string'
            AND nullif(btrim(instance.context::jsonb->>'oid4vp_profile'), '') IS NOT NULL
            AND jsonb_typeof(instance.context::jsonb->'request_uri') = 'string'
            AND nullif(btrim(instance.context::jsonb->>'request_uri'), '') IS NOT NULL
            AND instance.context::jsonb::text NOT ILIKE '%physical_document%'
            AND instance.context::jsonb::text NOT ILIKE '%passport%'
            AND ((instance.subject_type = 'holder'
                    AND instance.state_history::jsonb->0->>'event' = 'verification_started'
                    AND instance.state_history::jsonb->0->>'actor' = 'verification_api')
                OR (instance.subject_type = 'applicant'
                    AND instance.state_history::jsonb = '[]'::jsonb))
        ), false))
        OR lower(definition.flow_type) = 'physical_document_issuance'
        OR (lower(definition.flow_type) = 'custom'
            AND definition.extension::jsonb->>'extends_flow_type'
                = 'physical_document_issuance')
        OR instance.context::jsonb ? 'physical_document_job')
        AND lower(instance.status) NOT IN ('completed', 'failed', 'cancelled', 'expired');

    IF pending_jobs <> 0 OR incompatible_artifacts <> 0 OR active_flows <> 0 THEN
        RAISE EXCEPTION 'beta passport drain is not empty: jobs %, artifacts %, flows %',
            pending_jobs, incompatible_artifacts, active_flows;
    END IF;
END
$drain$;
