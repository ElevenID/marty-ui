-- Read-only shared catalog guard for released Rust companion triggers.
-- Called only after the enclosing exact-target fence/owner verifier succeeds.
DO $native_triggers$
DECLARE
    owner_phase text;
    has_submission boolean;
    has_cancellation boolean;
BEGIN
    SELECT phase INTO STRICT owner_phase FROM passport_cutover.state WHERE singleton;
    IF owner_phase NOT IN ('fully_fenced', 'rust_owner') THEN
        RAISE EXCEPTION 'passport companion trigger verification phase changed';
    END IF;
    SELECT EXISTS (SELECT 1 FROM issuance_service.rust_schema_migrations
                   WHERE version='0004_passport_submission_intent'),
           EXISTS (SELECT 1 FROM issuance_service.rust_schema_migrations
                   WHERE version='0011_passport_administrative_cancellation')
        INTO has_submission, has_cancellation;
    IF (has_cancellation AND NOT has_submission)
        OR (owner_phase='rust_owner' AND NOT (has_submission AND has_cancellation)) THEN
        RAISE EXCEPTION 'passport companion trigger migration lineage changed';
    END IF;
    IF (SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='flow_service' AND c.relname IN ('flow_definitions','flow_instances')
          AND NOT t.tgisinternal) <> 4 THEN
        RAISE EXCEPTION 'passport fence trigger inventory changed';
    END IF;
    IF EXISTS (
        WITH expected AS (
            SELECT * FROM (VALUES
                ('trg_physical_document_submission_intent', 'guard_physical_document_submission_intent',
                 19, has_submission, '2cf46bf0d5d5d2794b8eb6346ef30622', '936f63e7df56a3d116b98dadc7645158'),
                ('trg_administratively_cancelled_passport_job', 'guard_administratively_cancelled_passport_job',
                 27, has_cancellation, '30a8af741bf12bceace35a829087a886', '3cb9d58f302868d19a0b5cf52d34fcd8')
            ) AS released(trigger_name,function_name,trigger_type,installed,trigger_md5,function_md5)
            WHERE installed
        ), actual AS (
            SELECT t.*, p.oid AS function_oid, p.proname, p.proowner, p.prosecdef,
                   fn.nspname AS function_schema
            FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace
            JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace fn ON fn.oid=p.pronamespace
            WHERE n.nspname='issuance_service' AND c.relname='physical_document_jobs'
              AND NOT t.tgisinternal
              AND t.tgname NOT IN ('passport_fence_job','passport_fence_job_truncate')
        )
        SELECT 1 FROM expected e FULL JOIN actual a ON a.tgname=e.trigger_name
        WHERE e.trigger_name IS NULL OR a.oid IS NULL
           OR a.tgtype::integer <> e.trigger_type OR a.tgenabled NOT IN ('O','A')
           OR a.tgqual IS NOT NULL OR a.tgconstraint <> 0 OR a.tgdeferrable OR a.tginitdeferred
           OR a.tgattr::text <> '' OR encode(a.tgargs,'hex') <> ''
           OR a.function_schema <> 'issuance_service' OR a.proname <> e.function_name
           OR a.prosecdef
           OR pg_get_userbyid(a.proowner) NOT IN ('marty','marty_passport_fence_owner')
           OR (owner_phase='rust_owner' AND pg_get_userbyid(a.proowner) <> 'marty_passport_fence_owner')
           OR (owner_phase='rust_owner' AND e.trigger_name='trg_physical_document_submission_intent'
               AND has_function_privilege('marty',a.function_oid,'EXECUTE'))
           OR md5(pg_get_triggerdef(a.oid)) <> e.trigger_md5
           OR md5(replace(pg_get_functiondef(a.function_oid), E'\r\n', E'\n')) <> e.function_md5
    ) THEN
        RAISE EXCEPTION 'passport fence trigger inventory changed';
    END IF;
END
$native_triggers$;
