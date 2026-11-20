-- Only explicitly selected templates acquire the new prerequisite boundary.
ALTER TABLE credential_template_service.credential_templates
    ADD COLUMN IF NOT EXISTS verification_prerequisite jsonb;
ALTER TABLE credential_template_service.credential_templates
    ALTER COLUMN status TYPE varchar(40);

CREATE OR REPLACE FUNCTION credential_template_service.template_verification_prerequisite_valid(
    verification_prerequisite jsonb,
    credential_payload_format text,
    status text,
    issuance_protocol text,
    supported_formats jsonb,
    wallet_configs jsonb,
    validity_rules jsonb,
    application_template_id text,
    jwt_vc_profile jsonb,
    version integer
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER AS $prerequisite_check$
BEGIN
    IF verification_prerequisite IS NULL THEN
        RETURN status NOT LIKE 'prerequisite1_%';
    END IF;
    RETURN ((
        status IN ('prerequisite1_draft', 'prerequisite1_active', 'prerequisite1_deprecated', 'prerequisite1_archived')
        AND credential_payload_format = 'SD_JWT_VC'
        AND issuance_protocol = 'OID4VCI_PRE_AUTH'
        AND supported_formats = '["SD_JWT_VC"]'::jsonb
        AND wallet_configs = '[]'::jsonb
        AND validity_rules->'renewable' = 'false'::jsonb
        AND application_template_id IS NULL
        AND jwt_vc_profile IS NULL
        AND version > 0
        AND jsonb_typeof(verification_prerequisite) = 'object'
        AND verification_prerequisite ?& ARRAY['profile', 'flow_definition_id', 'flow_definition_version', 'policy', 'verifier_issuer_did', 'ttl_seconds']
        AND verification_prerequisite - ARRAY['profile', 'flow_definition_id', 'flow_definition_version', 'policy', 'verifier_issuer_did', 'ttl_seconds'] = '{}'::jsonb
        AND verification_prerequisite->>'profile' = 'managed_sd_jwt_dcql_same_holder_v1'
        AND jsonb_typeof(verification_prerequisite->'flow_definition_id') = 'string'
        AND octet_length(verification_prerequisite->>'flow_definition_id') BETWEEN 1 AND 255
        AND btrim(verification_prerequisite->>'flow_definition_id') = verification_prerequisite->>'flow_definition_id'
        AND (verification_prerequisite->>'flow_definition_id') !~ '[[:cntrl:]]'
        AND jsonb_typeof(verification_prerequisite->'flow_definition_version') = 'number'
        AND (verification_prerequisite->>'flow_definition_version') ~ '^[0-9]+$'
        AND (verification_prerequisite->>'flow_definition_version')::numeric BETWEEN 1 AND 4294967295
        AND jsonb_typeof(verification_prerequisite->'verifier_issuer_did') = 'string'
        AND octet_length(verification_prerequisite->>'verifier_issuer_did') BETWEEN 5 AND 255
        AND btrim(verification_prerequisite->>'verifier_issuer_did') = verification_prerequisite->>'verifier_issuer_did'
        AND (verification_prerequisite->>'verifier_issuer_did') ~ '^did:'
        AND (verification_prerequisite->>'verifier_issuer_did') !~ '[[:cntrl:]]'
        AND jsonb_typeof(verification_prerequisite->'ttl_seconds') = 'number'
        AND (verification_prerequisite->>'ttl_seconds') ~ '^[0-9]+$'
        AND (verification_prerequisite->>'ttl_seconds')::numeric BETWEEN 60 AND 900
        AND jsonb_typeof(verification_prerequisite->'policy') = 'object'
        AND (verification_prerequisite->'policy') ?& ARRAY['id', 'version', 'content_digest']
        AND (verification_prerequisite->'policy') - ARRAY['id', 'version', 'content_digest'] = '{}'::jsonb
        AND jsonb_typeof(verification_prerequisite->'policy'->'id') = 'string'
        AND octet_length(verification_prerequisite->'policy'->>'id') BETWEEN 1 AND 255
        AND (verification_prerequisite->'policy'->>'id') !~ '[[:cntrl:]]'
        AND jsonb_typeof(verification_prerequisite->'policy'->'version') = 'number'
        AND (verification_prerequisite->'policy'->>'version') ~ '^[0-9]+$'
        AND (verification_prerequisite->'policy'->>'version')::numeric BETWEEN 1 AND 4294967295
        AND jsonb_typeof(verification_prerequisite->'policy'->'content_digest') = 'string'
        AND (verification_prerequisite->'policy'->>'content_digest') ~ '^sha256:[0-9a-f]{64}$'
    ) IS TRUE);
END;
$prerequisite_check$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_template_verification_prerequisite'
        AND conrelid = 'credential_template_service.credential_templates'::regclass) THEN
        ALTER TABLE credential_template_service.credential_templates
            ADD CONSTRAINT ck_template_verification_prerequisite CHECK (credential_template_service.template_verification_prerequisite_valid(verification_prerequisite::jsonb, credential_payload_format::text, status::text, issuance_protocol::text, supported_formats::jsonb, wallet_configs::jsonb, validity_rules::jsonb, application_template_id::text, jwt_vc_profile::jsonb, version::integer) IS TRUE);
    END IF;
END $$;

-- The private lifecycle namespace makes unaware readers reject opted-in rows.
-- The trigger also prevents older writers from dropping the policy or moving
-- it back into the legacy lifecycle namespace. Activation is unavailable until
-- the issuance owner has installed its anti-omission and signing guards.
CREATE OR REPLACE FUNCTION credential_template_service.guard_verification_prerequisite_readiness()
RETURNS trigger LANGUAGE plpgsql AS $prerequisite_readiness$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.verification_prerequisite IS NOT NULL THEN
        IF NEW.verification_prerequisite IS NULL
            OR (OLD.status <> 'prerequisite1_draft' AND (
                NEW.status = 'prerequisite1_draft'
                OR NEW.verification_prerequisite IS DISTINCT FROM OLD.verification_prerequisite
                OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
                OR NEW.id IS DISTINCT FROM OLD.id
                OR NEW.version IS DISTINCT FROM OLD.version)) THEN
            RAISE EXCEPTION 'verification prerequisite cannot be removed or rebound';
        END IF;
    END IF;
    IF NEW.verification_prerequisite IS NOT NULL THEN
        IF (SELECT count(*) FROM (VALUES
                ('issuance_transactions', 'guard_verification_prerequisite_transaction', 23, '22f42cf430c5493a3db95161e91da94f'),
                ('issuance_prerequisite_continuations', 'guard_verification_prerequisite_continuation', 31, '1fd25f3a322f5ed0ea7509f64c2ffb20'),
                ('authorization_sessions', 'guard_verification_prerequisite_authorization', 23, '79a287212f27799b1eb7b95ed77c6e34')
            ) AS expected(table_name, guard_name, trigger_type, source_md5)
            JOIN pg_trigger t ON t.tgrelid=to_regclass('issuance_service.' || expected.table_name)
                AND t.tgname=expected.guard_name
            JOIN pg_proc p ON p.oid=t.tgfoid
            JOIN pg_language l ON l.oid=p.prolang
            WHERE t.tgenabled='O' AND t.tgtype=expected.trigger_type AND NOT t.tgisinternal
                AND t.tgqual IS NULL AND t.tgattr::text='' AND t.tgnargs=0
                AND p.oid=to_regprocedure('issuance_service.' || expected.guard_name || '()')
                AND p.prorettype='trigger'::regtype AND p.provolatile='v' AND NOT p.proisstrict
                AND NOT p.prosecdef AND p.proconfig IS NULL AND p.prokind='f'
                AND p.pronargs=0 AND p.proargmodes IS NULL AND p.pronargdefaults=0 AND p.provariadic=0
                AND l.lanname='plpgsql' AND md5(p.prosrc)=expected.source_md5
        ) <> 3
        OR NOT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema='issuance_service' AND table_name='issuance_transactions'
                AND column_name='issuance_intent' AND udt_name='jsonb'
                AND is_nullable='YES' AND column_default IS NULL) THEN
            RAISE EXCEPTION 'verification prerequisite issuance guards are unavailable';
        END IF;
    END IF;
    RETURN NEW;
END;
$prerequisite_readiness$;
DROP TRIGGER IF EXISTS guard_verification_prerequisite_readiness ON credential_template_service.credential_templates;
CREATE TRIGGER guard_verification_prerequisite_readiness BEFORE INSERT OR UPDATE
ON credential_template_service.credential_templates FOR EACH ROW
EXECUTE FUNCTION credential_template_service.guard_verification_prerequisite_readiness();

INSERT INTO credential_template_service.rust_schema_versions(version)
VALUES ('rust_credential_template_0005') ON CONFLICT DO NOTHING;
