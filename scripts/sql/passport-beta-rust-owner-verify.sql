-- Read-only post-transition check for the beta Rust passport owner.
-- The protected operator must bind every session setting to the exact beta
-- target, original fence epoch, and committed transition marker.
DO $verify$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolsuper)
        OR current_database() <> 'marty'
        OR current_setting('marty.passport_beta_verified_project', true)
            IS DISTINCT FROM 'elevenid-beta'
        OR current_setting('marty.passport_beta_expected_system_identifier', true)
            IS DISTINCT FROM (SELECT system_identifier::text FROM pg_control_system())
        OR current_setting('marty.passport_beta_expected_database_oid', true)
            IS DISTINCT FROM (SELECT oid::text FROM pg_database WHERE datname = current_database())
        OR current_setting('marty.passport_beta_expected_fence_epoch', true)
            IS DISTINCT FROM (SELECT epoch::text FROM passport_cutover.state
                              WHERE singleton=true AND phase='rust_owner')
        OR current_setting('marty.passport_beta_expected_transition_txid', true)
            IS DISTINCT FROM (SELECT transition_txid::text FROM passport_cutover.state
                              WHERE singleton=true AND phase='rust_owner') THEN
        RAISE EXCEPTION 'Rust owner verification lacks exact beta transition attestation';
    END IF;
    IF (SELECT count(*) FROM passport_cutover.state
        WHERE singleton = true AND phase = 'rust_owner' AND epoch > 0
          AND transition_txid > epoch AND transitioned_at IS NOT NULL) <> 1
        OR (SELECT count(*) FROM passport_cutover.state) <> 1 THEN
        RAISE EXCEPTION 'Rust owner phase or transition marker changed';
    END IF;
    IF (SELECT count(*) FROM pg_constraint
        WHERE conrelid='passport_cutover.state'::regclass) <> 5
        OR EXISTS (SELECT 1 FROM (VALUES
            ('state_epoch_check', '542480a8da1ec524fa52b99f57b19ee8'),
            ('state_phase_check', '66d6ef6ae756526442fb7cc2aa496309'),
            ('state_pkey', '7511e9a8e50c073e1d6eff73afcc0f24'),
            ('state_singleton_check', 'ae6f6dfbe38290d5bfa8f3e96d1aff91'),
            ('state_transition_shape_check', '95620ebd22d3cd5ce1f460921e9e9e14')
        ) AS expected(name, definition_md5)
        LEFT JOIN pg_constraint AS c ON c.conrelid='passport_cutover.state'::regclass
            AND c.conname=expected.name
        WHERE c.oid IS NULL OR NOT c.convalidated
            OR md5(pg_get_constraintdef(c.oid))<>expected.definition_md5) THEN
        RAISE EXCEPTION 'Rust owner state constraint changed';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname IN
            ('marty_passport_fence_owner', 'marty_beta_migrator')
          AND (rolcanlogin OR rolinherit OR rolsuper OR rolcreaterole
               OR rolcreatedb OR rolbypassrls)
    ) OR (SELECT count(*) FROM pg_roles WHERE rolname IN
        ('marty_passport_fence_owner', 'marty_beta_migrator')) <> 2
        OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member IN
            (SELECT oid FROM pg_roles WHERE rolcanlogin))
        OR EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid IN
            ('marty_passport_fence_owner'::regrole, 'marty_beta_migrator'::regrole)
            OR member IN ('marty_passport_fence_owner'::regrole,
                          'marty_beta_migrator'::regrole))
        THEN
        RAISE EXCEPTION 'passport fence role attributes or memberships changed';
    END IF;
    IF (SELECT count(*) FROM pg_namespace
        WHERE nspname IN ('passport_cutover', 'issuance_service', 'flow_service')
          AND pg_get_userbyid(nspowner) = 'marty_passport_fence_owner') <> 3
        OR (SELECT count(*) FROM pg_class AS c JOIN pg_namespace AS n
            ON n.oid = c.relnamespace
            WHERE (n.nspname, c.relname) IN (
                ('passport_cutover', 'state'),
                ('issuance_service', 'physical_document_jobs'),
                ('flow_service', 'flow_definitions'),
                ('flow_service', 'flow_instances'))
              AND pg_get_userbyid(c.relowner) = 'marty_passport_fence_owner') <> 4
        OR has_schema_privilege('marty', 'issuance_service', 'CREATE')
        OR has_schema_privilege('marty', 'flow_service', 'CREATE')
        OR has_schema_privilege('marty', 'passport_cutover', 'USAGE, CREATE')
        OR has_table_privilege('marty', 'issuance_service.physical_document_jobs',
                               'TRUNCATE, TRIGGER')
        OR has_table_privilege('marty', 'flow_service.flow_definitions',
                               'TRUNCATE, TRIGGER')
        OR has_table_privilege('marty', 'flow_service.flow_instances',
                               'TRUNCATE, TRIGGER')
        OR NOT (has_table_privilege('marty',
            'issuance_service.physical_document_jobs', 'INSERT')
            AND has_table_privilege('marty',
                'issuance_service.physical_document_jobs', 'UPDATE')
            AND has_table_privilege('marty',
                'issuance_service.physical_document_jobs', 'DELETE')
            AND has_table_privilege('marty',
                'flow_service.flow_definitions', 'INSERT')
            AND has_table_privilege('marty',
                'flow_service.flow_definitions', 'UPDATE')
            AND has_table_privilege('marty',
                'flow_service.flow_definitions', 'DELETE')
            AND has_table_privilege('marty',
                'flow_service.flow_instances', 'INSERT')
            AND has_table_privilege('marty',
                'flow_service.flow_instances', 'UPDATE')
            AND has_table_privilege('marty',
                'flow_service.flow_instances', 'DELETE'))
        OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'marty'
                   AND (rolsuper OR rolcreaterole OR rolbypassrls))
        OR EXISTS (SELECT 1 FROM pg_roles AS role
                   WHERE role.rolsuper AND pg_has_role('marty', role.oid, 'MEMBER')) THEN
        RAISE EXCEPTION 'passport fence ownership or app ACL changed';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles AS role
        WHERE role.rolcanlogin AND role.rolname NOT IN ('marty', 'postgres')
          AND (role.rolsuper OR role.rolcreaterole OR role.rolbypassrls
               OR EXISTS (SELECT 1 FROM pg_roles AS privileged
                          WHERE privileged.rolsuper
                            AND pg_has_role(role.rolname, privileged.oid, 'MEMBER'))
               OR has_schema_privilege(role.rolname, 'issuance_service', 'CREATE')
               OR has_schema_privilege(role.rolname, 'flow_service', 'CREATE')
               OR has_table_privilege(role.rolname,
                    'issuance_service.physical_document_jobs',
                    'INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER')
               OR has_table_privilege(role.rolname,
                    'flow_service.flow_definitions',
                    'INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER')
               OR has_table_privilege(role.rolname,
                    'flow_service.flow_instances',
                    'INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER'))) THEN
        RAISE EXCEPTION 'unexpected passport writer role after cutover';
    END IF;
    IF EXISTS (
        SELECT 1 FROM (VALUES
            ('issuance_service', 'physical_document_jobs', 'passport_fence_job', 'guard_job', 31),
            ('flow_service', 'flow_definitions', 'passport_fence_definition', 'guard_definition', 31),
            ('flow_service', 'flow_instances', 'passport_fence_instance', 'guard_instance', 31),
            ('issuance_service', 'physical_document_jobs', 'passport_fence_job_truncate', 'guard_truncate', 34),
            ('flow_service', 'flow_definitions', 'passport_fence_definition_truncate', 'guard_truncate', 34),
            ('flow_service', 'flow_instances', 'passport_fence_instance_truncate', 'guard_truncate', 34)
        ) AS expected(schema_name, table_name, trigger_name, function_name, trigger_type)
        LEFT JOIN pg_namespace AS n ON n.nspname = expected.schema_name
        LEFT JOIN pg_class AS c ON c.relnamespace = n.oid
            AND c.relname = expected.table_name
        LEFT JOIN pg_trigger AS t ON t.tgrelid = c.oid
            AND t.tgname = expected.trigger_name
        LEFT JOIN pg_proc AS p ON p.oid = t.tgfoid
        LEFT JOIN pg_namespace AS fn ON fn.oid = p.pronamespace
        WHERE t.oid IS NULL OR t.tgenabled <> 'A' OR t.tgisinternal
            OR t.tgtype::integer <> expected.trigger_type OR t.tgqual IS NOT NULL
            OR t.tgconstraint <> 0 OR t.tgdeferrable OR t.tginitdeferred
            OR t.tgattr::text <> '' OR encode(t.tgargs, 'hex') <> ''
            OR fn.nspname <> 'passport_cutover'
            OR p.proname <> expected.function_name
    ) THEN
        RAISE EXCEPTION 'passport fence trigger changed';
    END IF;
    -- Exact released companion-trigger inventory is checked by the shared source below.
    IF (SELECT count(*) FROM pg_proc AS p JOIN pg_namespace AS n
        ON n.oid = p.pronamespace WHERE n.nspname = 'passport_cutover') <> 7
        OR EXISTS (
            SELECT 1 FROM (VALUES
                ('passport_cutover.phase()', true, '6665ae165c3cf603ded9d1229c541e7e'),
                ('passport_cutover.physical_definition(text)', true, 'a41e40797122817e0cb0b99eed233e03'),
                ('passport_cutover.physical_context(json)', false, '412b8becd4997115f5b7138ec9ec40e0'),
                ('passport_cutover.guard_job()', true, 'a7dff18ea78e154b59ef6441a6e6df78'),
                ('passport_cutover.guard_definition()', true, '489f584bbf1b83b1cfa7b9866a0b608e'),
                ('passport_cutover.guard_instance()', true, 'e17b02bf1bf33f03d0f313a113863730'),
                ('passport_cutover.guard_truncate()', true, '342940ead31f82daecbd6bdcfbad9487')
            ) AS expected(signature, definer, definition_md5)
            LEFT JOIN pg_proc AS p
                ON p.oid = to_regprocedure(expected.signature)
            WHERE p.oid IS NULL
                OR pg_get_userbyid(p.proowner) <> 'marty_passport_fence_owner'
                OR NOT ('search_path=pg_catalog' = ANY(p.proconfig))
                OR p.prosecdef <> expected.definer
                OR has_function_privilege('marty', p.oid, 'EXECUTE')
                OR md5(pg_get_functiondef(p.oid)) <> expected.definition_md5
        ) THEN
        RAISE EXCEPTION 'Rust owner guard function owner or definition changed';
    END IF;
END
$verify$;

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


SELECT jsonb_build_object(
    'schema', 'marty.passport-beta-rust-owner-verification/v1',
    'phase', (SELECT phase FROM passport_cutover.state WHERE singleton),
    'fence_epoch', (SELECT epoch FROM passport_cutover.state WHERE singleton),
    'transition_txid', (SELECT transition_txid FROM passport_cutover.state WHERE singleton),
    'transitioned_at', (SELECT transitioned_at FROM passport_cutover.state WHERE singleton),
    'functions_md5', (
        SELECT jsonb_object_agg(p.proname, md5(pg_get_functiondef(p.oid))
                                ORDER BY p.proname)
        FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace
        WHERE n.nspname = 'passport_cutover'
    )
);

DO $cancellation_access$
BEGIN
    IF NOT issuance_service.passport_cancellation_acl_ready()
        OR NOT flow_service.physical_start_acl_ready() THEN
        RAISE EXCEPTION 'passport cancellation/Flow intent access violates fenced role contract';
    END IF;
END
$cancellation_access$;
