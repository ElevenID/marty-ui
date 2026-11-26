-- The additive Issuance owner row-lock boundary must be present before a
-- prerequisite template can be selected. Preserve the original lifecycle and
-- guard admission checks while pinning the revised invoker and narrow helper.
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
                ('issuance_transactions', 'guard_verification_prerequisite_transaction', 23, '26d1c0e53536560fbff9eb79ae11727c'),
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
        OR NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
            WHERE p.oid=to_regprocedure('issuance_service.verification_prerequisite_lock_template(text,text)')
                AND p.proargnames=ARRAY['requested_template','requested_organization']::text[]
                AND p.pronargs=2 AND p.proargmodes IS NULL AND p.pronargdefaults=0 AND p.provariadic=0
                AND p.prorettype='jsonb'::regtype AND p.provolatile='v' AND NOT p.proisstrict AND NOT p.proretset
                AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog']::text[] AND p.prokind='f'
                AND l.lanname='plpgsql' AND md5(p.prosrc)='7ed10a1343af9b382ce279fdb88b4d0c'
                AND p.proowner=(SELECT relowner FROM pg_class WHERE oid=to_regclass('issuance_service.issuance_transactions'))
                AND NOT EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0))
        OR (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='issuance_service' AND p.proname ~ '^verification_prerequisite_lock_') <> 1
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

INSERT INTO credential_template_service.rust_schema_versions(version)
VALUES ('rust_credential_template_0006') ON CONFLICT DO NOTHING;
