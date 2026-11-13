-- Opt-in source support only. Existing templates and issued credentials are unchanged.
ALTER TABLE credential_template_service.credential_templates
    ADD COLUMN IF NOT EXISTS jwt_vc_profile jsonb;

-- Old discovery and authorization readers select only active/draft, and old
-- template adapters reject these storage statuses. Public lifecycle names are
-- mapped by the profile-aware adapter; old nodes cannot advertise an opt-in
-- template under a legacy wallet variant and issue a different format.
-- The check is one fixed call so read-only schema verification can bind
-- both its exact arguments and the complete predicate source.
CREATE OR REPLACE FUNCTION credential_template_service.template_explicit_jwt_vc_profile_valid(
    jwt_vc_profile jsonb,
    credential_payload_format text,
    status text,
    issuance_protocol text,
    supported_formats jsonb,
    wallet_configs jsonb,
    validity_rules jsonb
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER AS $profile_check$
BEGIN
    RETURN ((
                (jwt_vc_profile IS NULL AND credential_payload_format <> 'VC_JWT_DIRECT_V1'
                    AND status NOT LIKE 'jose1_%')
                OR
                (credential_payload_format = 'VC_JWT_DIRECT_V1'
                    AND status IN ('jose1_draft', 'jose1_active', 'jose1_deprecated', 'jose1_archived')
                    AND issuance_protocol = 'OID4VCI_PRE_AUTH'
                    AND supported_formats::jsonb = '["VC_JWT_DIRECT_V1"]'::jsonb
                    AND wallet_configs::jsonb = '[]'::jsonb
                    AND validity_rules::jsonb->'renewable' = 'false'::jsonb
                    AND jsonb_typeof(jwt_vc_profile) = 'object'
                    AND jwt_vc_profile - ARRAY['contract', 'securing_profile', 'signature_lifetime_seconds'] = '{}'::jsonb
                    AND jwt_vc_profile->>'contract' = 'marty.jwt-vc-template-profile/v1'
                    AND jwt_vc_profile->>'securing_profile' = 'w3c_vc2_jose_2026_v1'
                    AND jsonb_typeof(jwt_vc_profile->'signature_lifetime_seconds') = 'number'
                    AND (jwt_vc_profile->>'signature_lifetime_seconds') ~ '^[0-9]+$'
                    AND (jwt_vc_profile->>'signature_lifetime_seconds')::numeric BETWEEN 1 AND 31622400)
            ) IS TRUE);
END;
$profile_check$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_template_explicit_jwt_vc_profile'
        AND conrelid = 'credential_template_service.credential_templates'::regclass) THEN
        ALTER TABLE credential_template_service.credential_templates
            ADD CONSTRAINT ck_template_explicit_jwt_vc_profile CHECK (credential_template_service.template_explicit_jwt_vc_profile_valid(jwt_vc_profile::jsonb, credential_payload_format::text, status::text, issuance_protocol::text, supported_formats::jsonb, wallet_configs::jsonb, validity_rules::jsonb) IS TRUE);
    END IF;
END $$;

-- A template-only migration must not enable a profile before the shared
-- issuance database refuses old authorization writers. No caller readiness
-- flag can substitute for these installed, enabled database guards.
CREATE OR REPLACE FUNCTION credential_template_service.guard_jwt_vc_profile_readiness()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.jwt_vc_profile IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                WHERE conrelid = to_regclass('issuance_service.issuance_transactions')
                  AND conname = 'ck_issuance_explicit_jwt_vc_profile' AND convalidated AND contype='c'
                  AND regexp_replace(replace(replace(replace(pg_get_constraintdef(oid), '::text', ''), '::jsonb', ''), 'issuance_service.', ''), '[()[:space:]]', '', 'g') = 'CHECKissuance_explicit_jwt_vc_profile_validjwt_vc_profile,jwt_vc_signing_timing,credential_payload_format,credential_type,credential_template_id,application_id,renewal_of_credential_id,delivery_mode,wallet_configs,renewable,statusISTRUE'
                  AND EXISTS (SELECT 1 FROM pg_depend d
                    WHERE d.classid='pg_constraint'::regclass AND d.objid=pg_constraint.oid
                      AND d.refclassid='pg_proc'::regclass
                      AND d.refobjid=to_regprocedure('issuance_service.issuance_explicit_jwt_vc_profile_valid(jsonb,jsonb,text,text,text,text,text,text,jsonb,boolean,text)')))
            OR NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
                WHERE p.oid=to_regprocedure('issuance_service.issuance_explicit_jwt_vc_profile_valid(jsonb,jsonb,text,text,text,text,text,text,jsonb,boolean,text)')
                  AND p.proargnames=ARRAY['jwt_vc_profile','jwt_vc_signing_timing','credential_payload_format','credential_type','credential_template_id','application_id','renewal_of_credential_id','delivery_mode','wallet_configs','renewable','status']::text[] AND p.proargmodes IS NULL AND p.pronargdefaults=0 AND p.provariadic=0
                  AND md5(p.prosrc) = '38f08eebebc5d85f6bc954b53a8d74c7'
                  AND p.prorettype='boolean'::regtype AND p.provolatile='i' AND NOT p.proisstrict
                  AND NOT p.prosecdef AND p.proconfig IS NULL AND p.prokind='f' AND l.lanname='plpgsql')
            OR NOT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
                WHERE t.tgrelid = to_regclass('issuance_service.issuance_transactions')
                  AND t.tgname = 'guard_explicit_jwt_vc_transaction' AND t.tgenabled = 'O'
                  AND t.tgtype=23 AND NOT t.tgisinternal AND t.tgqual IS NULL AND t.tgattr::text='' AND t.tgnargs=0
                  AND p.oid=to_regprocedure('issuance_service.guard_explicit_jwt_vc_transaction()') AND md5(p.prosrc)='85e19ebca421d249e0772cabeb8d6c1b'
                  AND p.prorettype='trigger'::regtype AND p.provolatile='v' AND NOT p.proisstrict
                  AND NOT p.prosecdef AND p.proconfig IS NULL AND p.prokind='f' AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql'))
            OR NOT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
                WHERE t.tgrelid = to_regclass('issuance_service.authorization_sessions')
                  AND t.tgname = 'guard_explicit_jwt_vc_authorization' AND t.tgenabled = 'O'
                  AND t.tgtype=23 AND NOT t.tgisinternal AND t.tgqual IS NULL AND t.tgattr::text='' AND t.tgnargs=0
                  AND p.oid=to_regprocedure('issuance_service.guard_explicit_jwt_vc_authorization()') AND md5(p.prosrc)='1815cc2378d2bafbe6415bde633bfa04'
                  AND p.prorettype='trigger'::regtype AND p.provolatile='v' AND NOT p.proisstrict
                  AND NOT p.prosecdef AND p.proconfig IS NULL AND p.prokind='f' AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')) THEN
            RAISE EXCEPTION 'explicit JWT-VC issuance database guards are unavailable';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS guard_jwt_vc_profile_readiness ON credential_template_service.credential_templates;
CREATE TRIGGER guard_jwt_vc_profile_readiness BEFORE INSERT OR UPDATE
ON credential_template_service.credential_templates FOR EACH ROW
EXECUTE FUNCTION credential_template_service.guard_jwt_vc_profile_readiness();

INSERT INTO credential_template_service.rust_schema_versions(version)
VALUES ('rust_credential_template_0004') ON CONFLICT DO NOTHING;
