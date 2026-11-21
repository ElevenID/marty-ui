-- Read-only upgrade inspection. This file never installs or repairs evidence.
-- Supply the actual connection-role identities, not merely their grant groups.
-- Run with psql -X --no-password --set=ON_ERROR_STOP=1 and the five variables
-- documented in docs/delegated-authority-upgrade.md.
\set ON_ERROR_STOP on
\if :{?phase}
\else
  DO $$ BEGIN RAISE EXCEPTION 'DA_PREFLIGHT_REQUIRED_VARIABLE: phase=pre-migration or phase=post-migration'; END $$;
\endif
\if :{?migration_owner}
\else
  DO $$ BEGIN RAISE EXCEPTION 'DA_PREFLIGHT_REQUIRED_VARIABLE: migration_owner'; END $$;
\endif
\if :{?request_role}
\else
  DO $$ BEGIN RAISE EXCEPTION 'DA_PREFLIGHT_REQUIRED_VARIABLE: request_role'; END $$;
\endif
\if :{?confirmation_role}
\else
  DO $$ BEGIN RAISE EXCEPTION 'DA_PREFLIGHT_REQUIRED_VARIABLE: confirmation_role'; END $$;
\endif
\if :{?authority_role}
\else
  DO $$ BEGIN RAISE EXCEPTION 'DA_PREFLIGHT_REQUIRED_VARIABLE: authority_role'; END $$;
\endif

BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path = pg_catalog;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SET LOCAL row_security = off;

-- psql's quoted-literal expansion is intentional. Never interpolate these
-- values as raw SQL or within a dollar-quoted DO body.
SELECT set_config('marty.preflight.phase', :'phase', true) AS phase,
       set_config('marty.preflight.owner', :'migration_owner', true) AS owner,
       set_config('marty.preflight.request', :'request_role', true) AS request,
       set_config('marty.preflight.confirmation', :'confirmation_role', true) AS confirmation,
       set_config('marty.preflight.authority', :'authority_role', true) AS authority
\gset preflight_input_

DO $preflight$
DECLARE
    selected_phase TEXT := current_setting('marty.preflight.phase');
    role_names TEXT[] := ARRAY[current_setting('marty.preflight.owner'),
        current_setting('marty.preflight.request'), current_setting('marty.preflight.confirmation'),
        current_setting('marty.preflight.authority')];
    role_ids OID[];
    schema_id OID;
    schema_owner OID;
    grants_id REGCLASS := to_regclass('delegated_authority_service.delegation_grants');
    journal_id REGCLASS := to_regclass('delegated_authority_service.grant_lifecycle_events');
    results_id REGCLASS := to_regclass('delegated_authority_service.command_results');
    migrations_id REGCLASS := to_regclass('delegated_authority_service.schema_migrations');
    grant_count BIGINT := 0;
    event_count BIGINT := 0;
    result_count BIGINT := 0;
    review_count BIGINT := 0;
    confirmation_count BIGINT := 0;
    observation_count BIGINT := 0;
    schema_version INTEGER := 0;
    versions INTEGER[] := ARRAY[]::INTEGER[];
    -- File-byte SHA-256 values. The Rust migrator stores them with the mandatory
    -- "sha256:" prefix; compare that exact ledger representation below.
    expected_checksums TEXT[] := ARRAY[
        'bd7c8d273f0824099fcd230667e64e40bb1cd42107f3bf419b25fe0c60887945',
        '9e1f6df883edeaf1abba52b3ff8ceafed0e9ecbf32f5ee723a9f458b09f29ff6',
        '63cb2d26f3efff51c6725f0c67e3c6c4541f70bce69a0559c6ed0afa53a295c1',
        'cedcf39d7d2cc35defe20066c5fad80e2c00b39f422fb0ffe9590ac508e9f16a',
        '2dbd6187782f4e53608adfce3a60a8619eb0d598bb66ec78cd83cb013a6596f6',
        '11682b6f2a646ded3a56f05f0f6dc7c66f183f35cad4b2892bb7c5a089495287',
        'b7bf6fe2257c3869b3d35088c5892ad719f7e86b466cbf42d58ebf41bd9c115f',
        '1281908a88452a7068fa123047a82a680a5e60842e53bfead470b9277b4b84fe',
        '5d97df8bba281edc60806d691cadb66e5beea7781a4217962591e88e2a627afa'
    ];
    evidence_tables TEXT[] := ARRAY['consent_confirmations','consent_withdrawals',
        'representation_authority_sources','representation_authority_assertions'];
    evidence_count INTEGER := 0;
    approval_tables TEXT[] := ARRAY['approval_storage_identity','approval_reviews',
        'approval_confirmation_bindings','organization_authority_observations'];
    approval_count INTEGER := 0;
    use_tables TEXT[] := ARRAY['command_identities','use_command_claims','use_admissions','use_receipts','use_command_results'];
    use_table_count INTEGER := 0;
    use_claim_count BIGINT := 0;
    use_result_count BIGINT := 0;
    machine_evidence_count BIGINT := 0;
    legacy_machine_receipt_count BIGINT := 0;
    machine_policy_evidence_count BIGINT := 0;
    legacy_machine_policy_audit_count BIGINT := 0;
    bad BOOLEAN;
    role_index INTEGER;
    object_record RECORD;
    assumed_role RECORD;
    migration_record RECORD;
    trigger_record RECORD;
    table_name TEXT;
    privilege_name TEXT;
    privileges TEXT[] := ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'];
    permitted BOOLEAN;
    effective BOOLEAN;
    grantable BOOLEAN;
    helper_id OID := to_regprocedure('delegated_authority_service.grant_instant(text)');
BEGIN
    IF selected_phase NOT IN ('pre-migration','post-migration') THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_PHASE: select pre-migration or post-migration';
    END IF;
    IF NOT pg_try_advisory_xact_lock(5566821136635019521) THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_MIGRATION_BUSY: another migration/preflight holds the service lock';
    END IF;
    SELECT array_agg(r.oid ORDER BY n.ordinality) INTO role_ids
      FROM unnest(role_names) WITH ORDINALITY AS n(name,ordinality)
      JOIN pg_roles r ON r.rolname = n.name;
    IF cardinality(role_ids) IS DISTINCT FROM 4
       OR (SELECT count(DISTINCT value) FROM unnest(role_ids) value) <> 4 THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_ROLES: provision four distinct existing role identities';
    END IF;

    SELECT oid,nspowner INTO schema_id,schema_owner FROM pg_namespace
      WHERE nspname='delegated_authority_service';
    IF schema_id IS NOT NULL AND schema_owner <> role_ids[1] THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_OWNER: service schema is not owned by the selected migration owner';
    END IF;
    IF grants_id IS NOT NULL THEN
        EXECUTE 'SELECT count(*) FROM delegated_authority_service.delegation_grants' INTO grant_count;
    END IF;
    -- Check this before version/privilege reporting: migration 0002 must never
    -- be made to succeed by deleting snapshots or inventing an initial event.
    IF grants_id IS NOT NULL AND journal_id IS NULL AND grant_count <> 0 THEN
        RAISE EXCEPTION USING
          MESSAGE='DA_PREFLIGHT_UNJOURNALED_GRANTS: nonempty initial grant table has no lifecycle journal',
          HINT='Stop the upgrade. Preserve the database and authoritative evidence read-only. No automatic import exists; use docs/delegated-authority-upgrade.md.';
    END IF;

    IF migrations_id IS NOT NULL THEN
        FOR migration_record IN EXECUTE
          'SELECT version,checksum FROM delegated_authority_service.schema_migrations ORDER BY version'
        LOOP
            IF migration_record.version < 1 OR migration_record.version > cardinality(expected_checksums)
               OR migration_record.checksum IS DISTINCT FROM ('sha256:' || expected_checksums[migration_record.version]) THEN
                RAISE EXCEPTION 'DA_PREFLIGHT_MIGRATION_HISTORY: unsupported version or original migration checksum mismatch';
            END IF;
            versions := array_append(versions,migration_record.version);
        END LOOP;
        schema_version := COALESCE(versions[cardinality(versions)],0);
        IF versions IS DISTINCT FROM ARRAY(SELECT generate_series(1,schema_version)) THEN
            RAISE EXCEPTION 'DA_PREFLIGHT_MIGRATION_HISTORY: migration versions are not a contiguous prefix';
        END IF;
    END IF;
    IF (schema_version >= 1 AND grants_id IS NULL)
       OR (schema_version >= 2 AND journal_id IS NULL)
       OR (schema_version < 2 AND journal_id IS NOT NULL) THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_SCHEMA_STATE: installed objects disagree with recorded migrations';
    END IF;
    FOREACH table_name IN ARRAY evidence_tables LOOP
        IF to_regclass(format('delegated_authority_service.%I',table_name)) IS NOT NULL THEN
            evidence_count := evidence_count + 1;
        END IF;
    END LOOP;
    IF (schema_version >= 3 AND evidence_count <> 4)
       OR (schema_version < 3 AND evidence_count <> 0) THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_SCHEMA_STATE: trusted evidence tables are partial or untracked';
    END IF;
    IF (schema_version >= 4 AND results_id IS NULL)
       OR (schema_version < 4 AND results_id IS NOT NULL) THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_SCHEMA_STATE: command results table disagrees with recorded migrations';
    END IF;
    FOREACH table_name IN ARRAY approval_tables LOOP
        IF to_regclass(format('delegated_authority_service.%I',table_name)) IS NOT NULL THEN
            approval_count := approval_count + 1;
        END IF;
    END LOOP;
    IF (schema_version >= 5 AND approval_count <> 4)
       OR (schema_version < 5 AND approval_count <> 0) THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_SCHEMA_STATE: organization approval tables are partial or untracked';
    END IF;
    FOREACH table_name IN ARRAY use_tables LOOP
        IF to_regclass(format('delegated_authority_service.%I',table_name)) IS NOT NULL THEN use_table_count := use_table_count + 1; END IF;
    END LOOP;
    IF (schema_version >= 6 AND use_table_count <> 5) OR (schema_version < 6 AND use_table_count <> 0) THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_SCHEMA_STATE: retained use tables are partial or untracked';
    END IF;
    IF (schema_version>=7) IS DISTINCT FROM (to_regclass('delegated_authority_service.machine_authentication_evidence') IS NOT NULL) THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_SCHEMA_STATE: machine audit table disagrees with recorded migrations';
    END IF;
    IF (schema_version>=8) IS DISTINCT FROM (to_regclass('delegated_authority_service.machine_authorization_evidence') IS NOT NULL) THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_SCHEMA_STATE: machine policy audit table disagrees with recorded migrations';
    END IF;
    SELECT count(*) INTO use_table_count FROM pg_proc WHERE pronamespace=schema_id
      AND proname IN ('lock_use_grant','lock_use_claim','lock_use_admission');
    IF (schema_version>=9 AND use_table_count<>3) OR (schema_version<9 AND use_table_count<>0) THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_USE_LOCK_SCHEMA: serving lock helpers do not match migration history';
    END IF;
    IF selected_phase='post-migration' AND schema_version <> cardinality(expected_checksums) THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_SCHEMA_STATE: post-migration inspection requires every bundled migration';
    END IF;
    IF schema_version >= 2 AND helper_id IS NULL THEN
        RAISE EXCEPTION 'DA_PREFLIGHT_SCHEMA_STATE: canonical timestamp helper is missing';
    END IF;
    IF schema_version=0 AND grants_id IS NOT NULL AND grant_count=0 THEN
        RAISE NOTICE 'DA_PREFLIGHT_EMPTY_UNTRACKED_INITIAL_TABLE: no records to import; original migration checks still apply';
    END IF;

    IF schema_id IS NOT NULL THEN
        FOR object_record IN SELECT oid,relname,relowner,relrowsecurity,relkind
            FROM pg_class WHERE relnamespace=schema_id AND relkind IN ('r','p','S','v','m','f')
        LOOP
            IF object_record.relowner <> role_ids[1] OR object_record.relrowsecurity
               OR object_record.relkind <> 'r' THEN
                RAISE EXCEPTION 'DA_PREFLIGHT_OBJECT_OWNER: unexpected ownership, row-security policy or relation kind';
            END IF;
        END LOOP;
        IF EXISTS (SELECT 1 FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
            WHERE t.relnamespace=schema_id AND NOT c.convalidated) THEN
            RAISE EXCEPTION 'DA_PREFLIGHT_CONSTRAINT: unvalidated service constraint';
        END IF;
        IF EXISTS (SELECT 1 FROM pg_proc WHERE pronamespace=schema_id
            AND (proowner<>role_ids[1] OR prokind<>'f'
                 OR proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']::TEXT[]
                 OR prosecdef IS DISTINCT FROM (proname IN
                    ('journal_grant_lifecycle','guard_consent_source','guard_authority_assertion',
                     'guard_approval_review','guard_approval_confirmation_binding',
                     'guard_organization_authority_observation','lock_use_grant',
                     'lock_use_claim','lock_use_admission')))) THEN
            RAISE EXCEPTION 'DA_PREFLIGHT_FUNCTION_OWNER: service function owner, security mode or fixed search path differs';
        END IF;
    END IF;

    -- Audit every membership path, including NOINHERIT/SET ROLE paths. Checking
    -- just direct grants or the currently selected role can miss escalation.
    IF current_setting('server_version_num')::INTEGER >= 170000 THEN
        privileges := array_append(privileges,'MAINTAIN');
    END IF;
    FOR role_index IN 2..4 LOOP
        FOR assumed_role IN SELECT * FROM pg_roles r
            WHERE r.oid=role_ids[role_index] OR pg_has_role(role_ids[role_index],r.oid,'MEMBER')
        LOOP
            IF assumed_role.rolsuper OR assumed_role.rolcreaterole OR assumed_role.rolcreatedb
               OR assumed_role.rolreplication OR assumed_role.rolbypassrls
               OR left(assumed_role.rolname::TEXT,3)='pg_'
               OR assumed_role.oid=role_ids[1]
               OR (assumed_role.oid=ANY(role_ids[2:4]) AND assumed_role.oid<>role_ids[role_index])
               OR has_database_privilege(assumed_role.oid,current_database(),'CREATE') THEN
                RAISE EXCEPTION 'DA_PREFLIGHT_ROLE_ESCALATION: request/producer identity can reach administrative or another component authority';
            END IF;
            -- Parameter ACLs can suppress ordinary integrity triggers without
            -- changing role flags, table grants or the trigger definitions.
            -- Ordinary USERSET configuration remains allowed; administrative
            -- settings, unknown extension settings and delegation do not.
            IF current_setting('server_version_num')::INTEGER >= 150000 THEN
                IF EXISTS(SELECT 1 FROM pg_parameter_acl parameter
                    LEFT JOIN pg_settings setting ON setting.name=parameter.parname
                    WHERE has_parameter_privilege(assumed_role.oid,parameter.parname,
                        'ALTER SYSTEM,SET WITH GRANT OPTION,ALTER SYSTEM WITH GRANT OPTION')
                    OR (NOT coalesce(setting.context='user',false)
                        AND has_parameter_privilege(assumed_role.oid,parameter.parname,'SET'))) THEN
                    RAISE EXCEPTION 'DA_PREFLIGHT_PARAMETER_PRIVILEGE: request/producer identity can change or delegate administrative parameter settings';
                END IF;
            END IF;
            IF schema_id IS NOT NULL AND has_schema_privilege(assumed_role.oid,schema_id,'CREATE') THEN
                RAISE EXCEPTION 'DA_PREFLIGHT_SCHEMA_PRIVILEGE: request/producer identity can create service objects';
            END IF;
            FOR object_record IN SELECT oid,relname FROM pg_class
                WHERE relnamespace=schema_id AND relkind='r'
            LOOP
                FOREACH privilege_name IN ARRAY privileges LOOP
                    permitted := CASE
                        WHEN role_index=2 THEN
                            (privilege_name='SELECT' AND object_record.relname IN
                              ('schema_migrations','delegation_grants','grant_lifecycle_events',
                               'consent_confirmations','consent_withdrawals',
                               'representation_authority_sources','representation_authority_assertions','command_results','command_identities',
                               'approval_storage_identity','approval_reviews','approval_confirmation_bindings',
                               'organization_authority_observations'))
                            OR (object_record.relname='delegation_grants' AND privilege_name IN ('INSERT','UPDATE'))
                            OR (object_record.relname IN ('command_results','command_identities') AND privilege_name='INSERT')
                        WHEN role_index=3 THEN
                            (object_record.relname IN ('consent_confirmations','consent_withdrawals',
                                'approval_reviews','approval_confirmation_bindings')
                            AND privilege_name IN ('SELECT','INSERT'))
                            OR (object_record.relname='approval_storage_identity' AND privilege_name='SELECT')
                        ELSE
                            (object_record.relname IN ('representation_authority_sources','representation_authority_assertions',
                                'organization_authority_observations') AND privilege_name IN ('SELECT','INSERT'))
                            OR (object_record.relname IN ('delegation_grants','approval_storage_identity')
                                AND privilege_name='SELECT') END;
                    effective := has_table_privilege(assumed_role.oid,object_record.oid,privilege_name);
                    grantable := has_table_privilege(assumed_role.oid,object_record.oid,privilege_name || ' WITH GRANT OPTION');
                    IF privilege_name IN ('SELECT','INSERT','UPDATE','REFERENCES') THEN
                        effective := effective OR has_any_column_privilege(assumed_role.oid,object_record.oid,privilege_name);
                        grantable := grantable OR has_any_column_privilege(assumed_role.oid,object_record.oid,privilege_name || ' WITH GRANT OPTION');
                    END IF;
                    IF (effective AND NOT permitted) OR grantable THEN
                        RAISE EXCEPTION 'DA_PREFLIGHT_TABLE_PRIVILEGE: request/producer has forbidden table, column or grant-option access';
                    END IF;
                END LOOP;
            END LOOP;
            FOR object_record IN SELECT oid FROM pg_proc WHERE pronamespace=schema_id LOOP
                IF (object_record.oid IS DISTINCT FROM helper_id
                    AND has_function_privilege(assumed_role.oid,object_record.oid,'EXECUTE'))
                   OR has_function_privilege(assumed_role.oid,object_record.oid,'EXECUTE WITH GRANT OPTION') THEN
                    RAISE EXCEPTION 'DA_PREFLIGHT_FUNCTION_PRIVILEGE: only the pure timestamp helper may be directly executable';
                END IF;
            END LOOP;
        END LOOP;
        IF selected_phase='post-migration' THEN
            -- These are the existing lifecycle-service minimum privileges.
            -- Approval-host-only grants above are allowed but not required for
            -- a lifecycle-only deployment. Its separate runtime-read and
            -- Organization-read identities are checked by approval readiness.
            IF NOT has_schema_privilege(role_ids[role_index],schema_id,'USAGE') THEN
                RAISE EXCEPTION 'DA_PREFLIGHT_MISSING_PRIVILEGE: component requires schema USAGE';
            END IF;
            FOR object_record IN SELECT oid,relname FROM pg_class WHERE relnamespace=schema_id AND relkind='r' LOOP
                FOREACH privilege_name IN ARRAY ARRAY['SELECT','INSERT','UPDATE'] LOOP
                    permitted := CASE WHEN role_index=2 THEN
                        (privilege_name='SELECT' AND object_record.relname IN
                          ('schema_migrations','delegation_grants','grant_lifecycle_events',
                           'consent_confirmations','consent_withdrawals','representation_authority_sources',
                           'representation_authority_assertions','command_results','command_identities'))
                        OR (object_record.relname='delegation_grants' AND privilege_name IN ('INSERT','UPDATE'))
                        OR (object_record.relname IN ('command_results','command_identities') AND privilege_name='INSERT')
                      WHEN role_index=3 THEN object_record.relname IN ('consent_confirmations','consent_withdrawals')
                        AND privilege_name IN ('SELECT','INSERT')
                      ELSE object_record.relname IN ('representation_authority_sources','representation_authority_assertions')
                        AND privilege_name IN ('SELECT','INSERT') END;
                    IF permitted AND NOT has_table_privilege(role_ids[role_index],object_record.oid,privilege_name) THEN
                        RAISE EXCEPTION 'DA_PREFLIGHT_MISSING_PRIVILEGE: component lacks its required bounded table access';
                    END IF;
                END LOOP;
            END LOOP;
            IF role_index IN (2,3) AND NOT has_function_privilege(role_ids[role_index],helper_id,'EXECUTE') THEN
                RAISE EXCEPTION 'DA_PREFLIGHT_MISSING_PRIVILEGE: request/confirmation role requires the pure timestamp helper';
            END IF;
        END IF;
    END LOOP;

    FOR trigger_record IN SELECT * FROM (VALUES
        (2,'delegation_grants','delegation_grants_guard','guard_grant_lifecycle',31),
        (2,'delegation_grants','delegation_grants_journal','journal_grant_lifecycle',21),
        (2,'delegation_grants','delegation_grants_no_truncate','reject_lifecycle_event_mutation',34),
        (2,'grant_lifecycle_events','grant_lifecycle_events_append_only','reject_lifecycle_event_mutation',27),
        (2,'grant_lifecycle_events','grant_lifecycle_events_no_truncate','reject_lifecycle_event_mutation',34),
        (3,'consent_confirmations','consent_confirmations_binding','guard_consent_source',7),
        (3,'consent_confirmations','consent_confirmations_immutable','reject_lifecycle_event_mutation',27),
        (3,'consent_confirmations','consent_confirmations_no_truncate','reject_lifecycle_event_mutation',34),
        (3,'consent_withdrawals','consent_withdrawals_stamp','stamp_consent_withdrawal',7),
        (3,'consent_withdrawals','consent_withdrawals_immutable','reject_lifecycle_event_mutation',27),
        (3,'consent_withdrawals','consent_withdrawals_no_truncate','reject_lifecycle_event_mutation',34),
        (3,'representation_authority_sources','representation_authority_sources_binding','guard_consent_source',7),
        (3,'representation_authority_sources','representation_authority_sources_immutable','reject_lifecycle_event_mutation',27),
        (3,'representation_authority_sources','representation_authority_sources_no_truncate','reject_lifecycle_event_mutation',34),
        (3,'representation_authority_assertions','representation_authority_assertions_guard','guard_authority_assertion',7),
        (3,'representation_authority_assertions','representation_authority_assertions_immutable','reject_lifecycle_event_mutation',27),
        (3,'representation_authority_assertions','representation_authority_assertions_no_truncate','reject_lifecycle_event_mutation',34),
        (4,'command_results','command_results_binding','guard_command_result',7),
        (4,'command_results','command_results_immutable','reject_lifecycle_event_mutation',27),
        (4,'command_results','command_results_no_truncate','reject_lifecycle_event_mutation',34),
        (5,'approval_storage_identity','approval_storage_identity_immutable','reject_lifecycle_event_mutation',27),
        (5,'approval_storage_identity','approval_storage_identity_no_truncate','reject_lifecycle_event_mutation',34),
        (5,'approval_reviews','approval_reviews_binding','guard_approval_review',7),
        (5,'approval_reviews','approval_reviews_immutable','reject_lifecycle_event_mutation',27),
        (5,'approval_reviews','approval_reviews_no_truncate','reject_lifecycle_event_mutation',34),
        (5,'approval_confirmation_bindings','approval_confirmation_bindings_guard','guard_approval_confirmation_binding',7),
        (5,'approval_confirmation_bindings','approval_confirmation_bindings_immutable','reject_lifecycle_event_mutation',27),
        (5,'approval_confirmation_bindings','approval_confirmation_bindings_no_truncate','reject_lifecycle_event_mutation',34),
        (5,'organization_authority_observations','organization_authority_observations_guard','guard_organization_authority_observation',7),
        (5,'organization_authority_observations','organization_authority_observations_immutable','reject_lifecycle_event_mutation',27),
        (5,'organization_authority_observations','organization_authority_observations_no_truncate','reject_lifecycle_event_mutation',34),
        (6,'command_results','command_results_identity','register_lifecycle_command_identity',7),
        (6,'use_command_claims','use_command_claims_binding','guard_use_command_claim',7),
        (6,'use_admissions','use_admissions_binding','guard_use_admission',7),
        (6,'use_receipts','use_receipts_binding','guard_use_receipt',7),
        (6,'use_command_results','use_command_results_binding','guard_use_result',7),
        (6,'use_command_results','use_command_results_commit','check_use_result_commit',5),
        (6,'command_identities','command_identities_immutable','reject_lifecycle_event_mutation',27),
        (6,'command_identities','command_identities_no_truncate','reject_lifecycle_event_mutation',34),
        (6,'use_command_claims','use_command_claims_immutable','reject_lifecycle_event_mutation',27),
        (6,'use_command_claims','use_command_claims_no_truncate','reject_lifecycle_event_mutation',34),
        (6,'use_admissions','use_admissions_immutable','reject_lifecycle_event_mutation',27),
        (6,'use_admissions','use_admissions_no_truncate','reject_lifecycle_event_mutation',34),
        (6,'use_receipts','use_receipts_immutable','reject_lifecycle_event_mutation',27),
        (6,'use_receipts','use_receipts_no_truncate','reject_lifecycle_event_mutation',34),
        (6,'use_command_results','use_command_results_immutable','reject_lifecycle_event_mutation',27),
        (6,'use_command_results','use_command_results_no_truncate','reject_lifecycle_event_mutation',34),
        (7,'machine_authentication_evidence','machine_authentication_evidence_binding','guard_machine_authentication_evidence',7),
        (7,'machine_authentication_evidence','machine_authentication_evidence_commit','check_machine_authentication_evidence_commit',5),
        (7,'machine_authentication_evidence','machine_authentication_evidence_immutable','reject_lifecycle_event_mutation',27),
        (7,'machine_authentication_evidence','machine_authentication_evidence_no_truncate','reject_lifecycle_event_mutation',34),
        (7,'use_receipts','use_receipts_machine_evidence','guard_use_machine_evidence',7),
        (8,'machine_authorization_evidence','machine_authorization_evidence_binding','guard_machine_authorization_evidence',7),
        (8,'machine_authorization_evidence','machine_authorization_evidence_commit','check_machine_authorization_evidence_commit',5),
        (8,'machine_authorization_evidence','machine_authorization_evidence_immutable','reject_lifecycle_event_mutation',58),
        (8,'machine_authentication_evidence','machine_authentication_authorization_binding','guard_machine_authentication_authorization',7)
      ) AS expected(version,table_name,trigger_name,function_name,trigger_type)
      WHERE version<=schema_version
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
            WHERE t.tgrelid=to_regclass(format('delegated_authority_service.%I',trigger_record.table_name))
              AND t.tgname=trigger_record.trigger_name AND NOT t.tgisinternal
              AND t.tgenabled='O' AND t.tgtype=trigger_record.trigger_type
              AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector
              AND t.tgdeferrable=(trigger_record.trigger_name IN ('use_command_results_commit','machine_authentication_evidence_commit','machine_authorization_evidence_commit'))
              AND t.tginitdeferred=(trigger_record.trigger_name IN ('use_command_results_commit','machine_authentication_evidence_commit','machine_authorization_evidence_commit'))
              AND (t.tgconstraint<>0)=(trigger_record.trigger_name IN ('use_command_results_commit','machine_authentication_evidence_commit','machine_authorization_evidence_commit'))
              AND p.pronamespace=schema_id AND p.proname=trigger_record.function_name
              AND p.pronargs=0) THEN
            RAISE EXCEPTION 'DA_PREFLIGHT_TRIGGER: required guard/journal trigger is absent, disabled or retargeted';
        END IF;
    END LOOP;

    IF journal_id IS NOT NULL THEN
        BEGIN
            SELECT count(*) INTO event_count FROM delegated_authority_service.grant_lifecycle_events;
            SELECT EXISTS (
              SELECT 1 FROM delegated_authority_service.delegation_grants g
              LEFT JOIN delegated_authority_service.grant_lifecycle_events e
                ON e.organization_id=g.organization_id AND e.grant_id=g.id
              GROUP BY g.organization_id,g.id,g.revision
              HAVING count(e.revision)<>g.revision OR min(e.revision)<>1 OR max(e.revision)<>g.revision
            ) OR EXISTS (
              SELECT 1 FROM delegated_authority_service.grant_lifecycle_events e
              LEFT JOIN delegated_authority_service.delegation_grants g
                ON e.organization_id=g.organization_id AND e.grant_id=g.id WHERE g.id IS NULL
            ) INTO bad;
            IF bad THEN
                RAISE EXCEPTION 'invalid journal coverage';
            END IF;
            WITH ordered AS (
              SELECT e.*,row_number() OVER w AS position,lag(status) OVER w AS prior_status,
                     lag(occurred_at) OVER w AS prior_time
              FROM delegated_authority_service.grant_lifecycle_events e
              WINDOW w AS (PARTITION BY organization_id,grant_id ORDER BY revision)
            )
            SELECT EXISTS (
              SELECT 1 FROM ordered e JOIN delegated_authority_service.delegation_grants g
                ON e.organization_id=g.organization_id AND e.grant_id=g.id
              WHERE e.revision<>e.position OR e.terms_digest IS DISTINCT FROM g.terms_digest
                OR (e.revision=1 AND (e.previous_status IS NOT NULL OR e.status<>'PENDING'
                     OR e.occurred_at IS DISTINCT FROM (g.grant_document->>'created_at')))
                OR (e.revision>1 AND (e.previous_status IS DISTINCT FROM e.prior_status
                    OR delegated_authority_service.grant_instant(e.occurred_at)
                       <=delegated_authority_service.grant_instant(e.prior_time)
                    OR NOT ((e.prior_status='PENDING' AND e.status IN ('ACTIVE','REVOKED','EXPIRED'))
                         OR (e.prior_status='ACTIVE' AND e.status IN ('SUSPENDED','REVOKED','EXPIRED'))
                         OR (e.prior_status='SUSPENDED' AND e.status IN ('ACTIVE','REVOKED','EXPIRED')))))
                OR (e.revision=g.revision AND (e.status IS DISTINCT FROM g.status
                     OR e.occurred_at IS DISTINCT FROM (g.grant_document->>'updated_at')))
            ) OR EXISTS (
              SELECT 1 FROM delegated_authority_service.delegation_grants g
              WHERE jsonb_typeof(g.grant_document) IS DISTINCT FROM 'object'
                OR g.grant_document->>'id' IS DISTINCT FROM g.id::TEXT
                OR g.grant_document->>'organization_id' IS DISTINCT FROM g.organization_id::TEXT
                OR g.grant_document->>'status' IS DISTINCT FROM g.status
                OR g.grant_document->>'revision' IS DISTINCT FROM g.revision::TEXT
                OR g.grant_document->>'terms_digest' IS DISTINCT FROM g.terms_digest
                OR g.grant_document#>>'{authority,mode}' IS DISTINCT FROM 'MANAGED'
                OR (g.grant_document->>'created_at')::TIMESTAMPTZ IS DISTINCT FROM g.created_at
                OR (g.grant_document->>'updated_at')::TIMESTAMPTZ IS DISTINCT FROM g.updated_at
                OR delegated_authority_service.grant_instant(g.grant_document->>'created_at')
                   >delegated_authority_service.grant_instant(g.grant_document->>'updated_at')
            ) INTO bad;
            IF bad THEN
                RAISE EXCEPTION 'invalid journal or current snapshot binding';
            END IF;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION USING MESSAGE='DA_PREFLIGHT_JOURNAL: lifecycle continuity or current snapshot consistency failed',
              HINT='Keep every original record and source audit artifact; investigate without rewriting or synthesizing history.';
        END;
    END IF;

    IF results_id IS NOT NULL THEN
        -- Original outcomes are historical evidence. Later lifecycle changes
        -- must not force their status/revision/time to match the latest grant.
        -- This check cannot authenticate the original actor or recompute the
        -- protocol's canonical command digest; the runtime does those checks.
        BEGIN
            SELECT count(*) INTO result_count FROM delegated_authority_service.command_results;
            SELECT EXISTS (
              SELECT 1 FROM delegated_authority_service.command_results c
              LEFT JOIN delegated_authority_service.grant_lifecycle_events e
                ON e.organization_id=c.organization_id AND e.grant_id=c.grant_id
                   AND e.revision=c.grant_revision
              LEFT JOIN delegated_authority_service.delegation_grants g
                ON g.organization_id=c.organization_id AND g.id=c.grant_id
              WHERE e.revision IS NULL OR g.id IS NULL
                OR c.result_document->>'organization_id' IS DISTINCT FROM c.organization_id::TEXT
                OR c.result_document->>'id' IS DISTINCT FROM c.grant_id::TEXT
                OR c.result_document->>'revision' IS DISTINCT FROM c.grant_revision::TEXT
                OR c.result_document->>'status' IS DISTINCT FROM e.status
                OR c.result_document->>'terms_digest' IS DISTINCT FROM e.terms_digest
                OR c.result_document->>'updated_at' IS DISTINCT FROM e.occurred_at
                OR (c.result_document - ARRAY['status','revision','updated_at','approval'])
                   IS DISTINCT FROM (g.grant_document - ARRAY['status','revision','updated_at','approval'])
                OR (c.result_document ? 'approval' AND c.result_document->'approval'
                    IS DISTINCT FROM g.grant_document->'approval')
                OR (c.grant_revision=g.revision AND c.result_document IS DISTINCT FROM g.grant_document)
                OR c.command_document->>'profile' IS DISTINCT FROM 'urn:marty:delegation-command:v1'
                OR c.command_document->>'command_id' IS DISTINCT FROM c.command_id::TEXT
                OR CASE c.command_document->>'command'
                    WHEN 'CREATE_GRANT' THEN
                        e.status IS DISTINCT FROM 'PENDING' OR c.grant_revision<>1
                        OR c.command_document->'terms' IS DISTINCT FROM c.result_document->'terms'
                    WHEN 'APPROVE_GRANT' THEN
                        e.status IS DISTINCT FROM 'ACTIVE' OR e.previous_status IS DISTINCT FROM 'PENDING'
                        OR c.result_document#>>'{approval,approver,type}' IS DISTINCT FROM c.actor_type
                        OR c.result_document#>>'{approval,approver,id}' IS DISTINCT FROM c.actor_id
                    WHEN 'SUSPEND_GRANT' THEN
                        e.status IS DISTINCT FROM 'SUSPENDED' OR e.previous_status IS DISTINCT FROM 'ACTIVE'
                    WHEN 'REINSTATE_GRANT' THEN
                        e.status IS DISTINCT FROM 'ACTIVE' OR e.previous_status IS DISTINCT FROM 'SUSPENDED'
                    WHEN 'REVOKE_GRANT' THEN e.status IS DISTINCT FROM 'REVOKED'
                    ELSE true END
                OR (c.command_document->>'command' IS DISTINCT FROM 'CREATE_GRANT' AND (
                    c.command_document#>>'{grant,id}' IS DISTINCT FROM c.grant_id::TEXT
                    OR c.command_document#>>'{grant,terms_digest}' IS DISTINCT FROM e.terms_digest
                    OR c.command_document#>>'{grant,revision}' IS DISTINCT FROM (c.grant_revision-1)::TEXT))
            ) INTO bad;
            IF bad THEN
                RAISE EXCEPTION 'invalid command result historical binding';
            END IF;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION USING MESSAGE='DA_PREFLIGHT_COMMAND_RESULTS: original result disagrees with its lifecycle history',
              HINT='Preserve original command identities, snapshots and audit records. Never delete a result to reuse its identity.';
        END;
    END IF;

    IF schema_version >= 5 THEN
        -- Review and confirmation history is immutable even after the grant
        -- becomes terminal or consent expires/withdraws. Check original binding,
        -- never require old evidence to be current or renew its timestamps.
        BEGIN
            IF (SELECT count(*) FROM delegated_authority_service.approval_storage_identity) <> 1
               OR EXISTS (SELECT 1 FROM delegated_authority_service.approval_storage_identity
                    WHERE NOT singleton OR instance_id='00000000-0000-0000-0000-000000000000'::UUID) THEN
                RAISE EXCEPTION 'invalid approval storage identity';
            END IF;
            SELECT count(*) INTO review_count FROM delegated_authority_service.approval_reviews;
            SELECT count(*) INTO confirmation_count FROM delegated_authority_service.approval_confirmation_bindings;
            SELECT count(*) INTO observation_count FROM delegated_authority_service.organization_authority_observations;
            SELECT EXISTS (
                SELECT 1 FROM delegated_authority_service.approval_reviews r
                LEFT JOIN delegated_authority_service.delegation_grants g
                  ON g.organization_id=r.organization_id AND g.id=r.grant_id
                LEFT JOIN delegated_authority_service.grant_lifecycle_events e
                  ON e.organization_id=r.organization_id AND e.grant_id=r.grant_id AND e.revision=r.grant_revision
                WHERE g.id IS NULL OR e.revision IS NULL OR e.status IS DISTINCT FROM 'PENDING'
                  OR r.terms_digest IS DISTINCT FROM g.terms_digest
                  OR r.grant_document->>'id' IS DISTINCT FROM r.grant_id::TEXT
                  OR r.grant_document->>'organization_id' IS DISTINCT FROM r.organization_id::TEXT
                  OR r.grant_document->>'revision' IS DISTINCT FROM r.grant_revision::TEXT
                  OR r.grant_document->>'status' IS DISTINCT FROM e.status
                  OR r.grant_document ? 'approval'
                  OR r.grant_document->>'terms_digest' IS DISTINCT FROM r.terms_digest
                  OR r.grant_document->>'updated_at' IS DISTINCT FROM e.occurred_at
                  OR (r.grant_document - ARRAY['status','revision','updated_at','approval'])
                     IS DISTINCT FROM (g.grant_document - ARRAY['status','revision','updated_at','approval'])
                  OR r.grant_document#>>'{terms,grantor,type}' IS DISTINCT FROM 'USER'
                  OR r.grant_document#>>'{terms,grantor,id}' IS DISTINCT FROM ('urn:marty:user:' || r.actor_id::TEXT)
                  OR r.grant_document#>>'{terms,subject,type}' IS DISTINCT FROM 'ORGANIZATION'
                  OR r.grant_document#>>'{terms,subject,id}' IS DISTINCT FROM ('urn:marty:organization:' || r.organization_id::TEXT)
                  OR r.grant_document#>>'{terms,binding,method}' IS DISTINCT FROM 'KEY'
                  OR r.grant_document#>>'{authority,issuer,type}' IS DISTINCT FROM 'ORGANIZATION'
                  OR delegated_authority_service.grant_instant(r.created_at)
                       < delegated_authority_service.grant_instant(r.grant_document->>'created_at')
                  OR delegated_authority_service.grant_instant(r.expires_at)
                       > delegated_authority_service.grant_instant(r.grant_document#>>'{terms,valid_until}')
            ) OR EXISTS (
                SELECT 1 FROM delegated_authority_service.approval_confirmation_bindings b
                LEFT JOIN delegated_authority_service.approval_reviews r
                  ON r.organization_id=b.organization_id AND r.review_id=b.review_id
                LEFT JOIN delegated_authority_service.consent_confirmations c
                  ON c.organization_id=b.organization_id AND c.evidence_ref=b.evidence_ref
                LEFT JOIN delegated_authority_service.representation_authority_sources a
                  ON a.organization_id=b.organization_id AND a.authority_evidence_ref=b.authority_evidence_ref
                WHERE r.review_id IS NULL OR c.evidence_ref IS NULL OR a.authority_evidence_ref IS NULL
                  OR b.actor_id IS DISTINCT FROM r.actor_id OR b.grant_id IS DISTINCT FROM r.grant_id
                  OR b.terms_digest IS DISTINCT FROM r.terms_digest OR b.session_ref IS DISTINCT FROM r.session_ref
                  OR c.grant_id IS DISTINCT FROM b.grant_id OR c.terms_digest IS DISTINCT FROM b.terms_digest
                  OR c.authority_evidence_ref IS DISTINCT FROM b.authority_evidence_ref
                  OR c.confirmed_at IS DISTINCT FROM b.confirmed_at OR c.valid_until IS DISTINCT FROM b.valid_until
                  OR c.profile IS DISTINCT FROM r.profile OR c.adapter_version IS DISTINCT FROM r.adapter_version
                  OR c.artifact_digest IS DISTINCT FROM r.artifact_digest
                  OR c.grantor IS DISTINCT FROM r.grant_document#>'{terms,grantor}'
                  OR c.subject IS DISTINCT FROM r.grant_document#>'{terms,subject}'
                  OR c.issuer IS DISTINCT FROM r.grant_document#>'{authority,issuer}'
                  OR a.evidence_ref IS DISTINCT FROM b.evidence_ref OR a.grant_id IS DISTINCT FROM b.grant_id
                  OR a.terms_digest IS DISTINCT FROM b.terms_digest
                  OR a.grantor IS DISTINCT FROM c.grantor OR a.subject IS DISTINCT FROM c.subject
                  OR a.issuer IS DISTINCT FROM c.issuer OR a.profile IS DISTINCT FROM c.profile
                  OR a.adapter_version IS DISTINCT FROM c.adapter_version OR a.artifact_digest IS DISTINCT FROM c.artifact_digest
                  OR delegated_authority_service.grant_instant(b.confirmed_at) < delegated_authority_service.grant_instant(r.created_at)
                  OR delegated_authority_service.grant_instant(b.confirmed_at) >= delegated_authority_service.grant_instant(r.expires_at)
                  OR delegated_authority_service.grant_instant(b.valid_until) <= delegated_authority_service.grant_instant(b.confirmed_at)
                  OR delegated_authority_service.grant_instant(b.valid_until) > delegated_authority_service.grant_instant(b.confirmed_at) + 300
                  OR delegated_authority_service.grant_instant(b.valid_until) > delegated_authority_service.grant_instant(r.grant_document#>>'{terms,valid_until}')
            ) OR EXISTS (
                SELECT 1 FROM delegated_authority_service.organization_authority_observations o
                LEFT JOIN delegated_authority_service.representation_authority_assertions a
                  ON a.organization_id=o.organization_id AND a.authority_evidence_ref=o.authority_evidence_ref AND a.revision=o.revision
                LEFT JOIN delegated_authority_service.representation_authority_sources s
                  ON s.organization_id=o.organization_id AND s.authority_evidence_ref=o.authority_evidence_ref
                WHERE a.revision IS NULL OR s.authority_evidence_ref IS NULL
                  OR s.grantor->>'type' IS DISTINCT FROM 'USER'
                  OR s.grantor->>'id' IS DISTINCT FROM ('urn:marty:user:' || o.user_id::TEXT)
                  OR s.subject->>'type' IS DISTINCT FROM 'ORGANIZATION'
                  OR s.subject->>'id' IS DISTINCT FROM ('urn:marty:organization:' || o.organization_id::TEXT)
                  OR o.authorized IS DISTINCT FROM (a.state='AUTHORIZED')
                  OR o.observed_at IS DISTINCT FROM a.asserted_at OR o.valid_until IS DISTINCT FROM a.valid_until
                  OR (o.authorized AND (o.member_id IS NULL
                      OR delegated_authority_service.grant_instant(o.valid_until) <= delegated_authority_service.grant_instant(o.observed_at)
                      OR delegated_authority_service.grant_instant(o.valid_until) > delegated_authority_service.grant_instant(o.observed_at) + 15))
            ) OR EXISTS (
                SELECT 1 FROM delegated_authority_service.approval_confirmation_bindings b
                LEFT JOIN delegated_authority_service.representation_authority_assertions a
                  ON a.organization_id=b.organization_id AND a.authority_evidence_ref=b.authority_evidence_ref
                LEFT JOIN delegated_authority_service.organization_authority_observations o
                  ON o.organization_id=a.organization_id AND o.authority_evidence_ref=a.authority_evidence_ref AND o.revision=a.revision
                WHERE a.revision IS NULL OR o.revision IS NULL
            ) INTO bad;
            IF bad THEN
                RAISE EXCEPTION 'invalid approval or authority observation binding';
            END IF;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION USING MESSAGE='DA_PREFLIGHT_APPROVAL_HISTORY: organization approval evidence disagrees with its original binding',
                HINT='Preserve the original review, confirmation, authority and grant records; never recreate consent to make inspection pass.';
        END;
    END IF;

    IF schema_version >= 6 THEN
        WITH expected(table_name,index_name,columns,predicate) AS (VALUES
        ('command_identities','command_identities_pkey',ARRAY['organization_id','actor_type','actor_id','command_id'],NULL::TEXT),
        ('use_command_claims','use_command_claims_pkey',ARRAY['organization_id','actor_type','actor_id','command_id'],NULL::TEXT),
        ('use_command_claims','use_command_start_challenge',ARRAY['organization_id','challenge_id'],'START_USE'),
        ('use_command_claims','use_command_final_challenge',ARRAY['organization_id','challenge_id'],'FINALIZE_USE'),
        ('use_admissions','use_admissions_pkey',ARRAY['organization_id','challenge_id'],NULL::TEXT),
        ('use_admissions','use_admissions_organization_id_verifier_id_nonce_key',ARRAY['organization_id','verifier_id','nonce'],NULL::TEXT),
        ('use_receipts','use_receipts_pkey',ARRAY['organization_id','challenge_id'],NULL::TEXT),
        ('use_receipts','use_receipts_organization_id_receipt_ref_key',ARRAY['organization_id','receipt_ref'],NULL::TEXT),
        ('use_command_results','use_command_results_pkey',ARRAY['organization_id','actor_type','actor_id','command_id'],NULL::TEXT))
        SELECT count(*) INTO use_table_count FROM expected e JOIN pg_class t ON t.oid=to_regclass('delegated_authority_service.'||e.table_name)
        JOIN pg_index i ON i.indrelid=t.oid JOIN pg_class x ON x.oid=i.indexrelid
        WHERE x.relname=e.index_name AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indexprs IS NULL
        AND i.indnatts=cardinality(e.columns) AND i.indnkeyatts=cardinality(e.columns)
        AND ARRAY(SELECT a.attname::TEXT FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ord) JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=k.attnum ORDER BY k.ord)=e.columns
        AND pg_get_expr(i.indpred,i.indrelid) IS NOT DISTINCT FROM CASE WHEN e.predicate IS NULL THEN NULL ELSE format('(command_name = %L::text)',e.predicate) END;
        IF use_table_count<>9 THEN
            RAISE EXCEPTION 'DA_PREFLIGHT_USE_INDEX: retained command/challenge/nonce unique index is missing or weakened';
        END IF;
        -- Preserve unresolved claims and historical decisions after expiry or
        -- revocation. This is structural evidence inspection, not signature,
        -- command canonicalization, current authority or Flow qualification.
        BEGIN
            SELECT count(*) INTO use_claim_count FROM delegated_authority_service.use_command_claims;
            SELECT count(*) INTO use_result_count FROM delegated_authority_service.use_command_results;
            SELECT EXISTS (
                SELECT 1 FROM delegated_authority_service.command_identities i
                LEFT JOIN delegated_authority_service.command_results l USING(organization_id,actor_type,actor_id,command_id)
                LEFT JOIN delegated_authority_service.use_command_claims u USING(organization_id,actor_type,actor_id,command_id)
                WHERE (l.command_id IS NULL)=(u.command_id IS NULL)
                    OR i.command_digest IS DISTINCT FROM COALESCE(l.command_digest,u.command_digest)
                    OR i.command_name IS DISTINCT FROM COALESCE(l.command_document->>'command',u.command_name)
            ) OR EXISTS (
                SELECT 1 FROM delegated_authority_service.command_results l
                LEFT JOIN delegated_authority_service.command_identities i USING(organization_id,actor_type,actor_id,command_id)
                WHERE i.command_id IS NULL
            ) OR EXISTS (
                SELECT 1 FROM delegated_authority_service.use_command_claims c
                LEFT JOIN delegated_authority_service.command_identities i USING(organization_id,actor_type,actor_id,command_id)
                LEFT JOIN delegated_authority_service.delegation_grants g ON g.organization_id=c.organization_id AND g.id=c.grant_id
                LEFT JOIN delegated_authority_service.grant_lifecycle_events e ON e.organization_id=c.organization_id AND e.grant_id=c.grant_id AND e.revision=c.grant_revision
                WHERE i.command_id IS NULL OR g.id IS NULL OR e.revision IS NULL OR e.status IS DISTINCT FROM 'ACTIVE'
                    OR c.grant_document->>'organization_id' IS DISTINCT FROM c.organization_id::TEXT
                    OR c.grant_document->>'id' IS DISTINCT FROM c.grant_id::TEXT
                    OR c.grant_document->>'revision' IS DISTINCT FROM c.grant_revision::TEXT
                    OR c.grant_document->>'status' IS DISTINCT FROM 'ACTIVE'
                    OR c.grant_document->>'terms_digest' IS DISTINCT FROM e.terms_digest
                    OR c.grant_document->>'updated_at' IS DISTINCT FROM e.occurred_at
                    OR c.grant_document#>>'{terms,delegate,type}' IS DISTINCT FROM c.actor_type
                    OR c.grant_document#>>'{terms,delegate,id}' IS DISTINCT FROM c.actor_id
                    OR c.grant_document#>>'{terms,binding,method}' IS DISTINCT FROM 'KEY'
                    OR (c.grant_document - ARRAY['status','revision','updated_at']) IS DISTINCT FROM (g.grant_document - ARRAY['status','revision','updated_at'])
                    OR c.command_document->>'profile' IS DISTINCT FROM 'urn:marty:delegation-command:v1'
                    OR c.command_document->>'command_id' IS DISTINCT FROM c.command_id::TEXT
                    OR c.command_document->>'command' IS DISTINCT FROM c.command_name
                    OR CASE c.command_name WHEN 'START_USE' THEN
                        c.command_document#>>'{grant,id}' IS DISTINCT FROM c.grant_id::TEXT
                        OR c.command_document#>>'{grant,revision}' IS DISTINCT FROM c.grant_revision::TEXT
                        OR c.command_document#>>'{grant,terms_digest}' IS DISTINCT FROM e.terms_digest
                        WHEN 'FINALIZE_USE' THEN c.command_document->>'challenge_id' IS DISTINCT FROM c.challenge_id::TEXT
                        ELSE true END
            ) OR EXISTS (
                SELECT 1 FROM delegated_authority_service.use_admissions a
                LEFT JOIN delegated_authority_service.use_command_claims c USING(organization_id,actor_type,actor_id,command_id)
                LEFT JOIN delegated_authority_service.use_command_results r USING(organization_id,actor_type,actor_id,command_id)
                WHERE c.command_id IS NULL OR r.command_id IS NULL OR c.command_name IS DISTINCT FROM 'START_USE'
                    OR c.challenge_id IS DISTINCT FROM a.challenge_id
                    OR a.challenge_document->>'organization_id' IS DISTINCT FROM a.organization_id::TEXT
                    OR a.challenge_document->>'challenge_id' IS DISTINCT FROM a.challenge_id::TEXT
                    OR a.challenge_document->'grant' IS DISTINCT FROM c.grant_document
                    OR a.challenge_document->'operation' IS DISTINCT FROM c.command_document->'operation'
                    OR a.challenge_document->>'verifier_id' IS DISTINCT FROM a.verifier_id
                    OR a.challenge_document->>'nonce' IS DISTINCT FROM a.nonce
                    OR (a.challenge_document->>'created_at')::TIMESTAMPTZ IS DISTINCT FROM a.created_at
                    OR (a.challenge_document->>'expires_at')::TIMESTAMPTZ IS DISTINCT FROM a.expires_at
                    OR a.expires_at<=a.created_at
            ) OR EXISTS (
                SELECT 1 FROM delegated_authority_service.use_receipts r
                LEFT JOIN delegated_authority_service.use_command_claims c USING(organization_id,actor_type,actor_id,command_id)
                LEFT JOIN delegated_authority_service.use_admissions a ON a.organization_id=r.organization_id AND a.challenge_id=r.challenge_id
                LEFT JOIN delegated_authority_service.use_command_results o ON o.organization_id=r.organization_id AND o.actor_type=r.actor_type AND o.actor_id=r.actor_id AND o.command_id=r.command_id
                WHERE c.command_id IS NULL OR a.challenge_id IS NULL OR o.command_id IS NULL
                    OR c.command_name IS DISTINCT FROM 'FINALIZE_USE' OR c.challenge_id IS DISTINCT FROM r.challenge_id
                    OR a.actor_type IS DISTINCT FROM r.actor_type OR a.actor_id IS DISTINCT FROM r.actor_id
                    OR c.command_document->>'proof_submission_id' IS DISTINCT FROM r.proof_submission_id::TEXT
                    OR r.receipt_document->>'profile' IS DISTINCT FROM 'urn:marty:delegated-decision-receipt:v1'
                    OR COALESCE(r.receipt_document->>'decision','') NOT IN ('PERMIT','DENY')
                    OR r.receipt_ref IS DISTINCT FROM ('urn:marty:delegated-receipt:'||(r.receipt_document->>'id'))
                    OR r.receipt_document#>>'{evaluation,organization_id}' IS DISTINCT FROM r.organization_id::TEXT
                    OR r.receipt_document#>>'{evaluation,challenge}' IS DISTINCT FROM a.nonce
                    OR r.receipt_document#>>'{evaluation,actor,type}' IS DISTINCT FROM r.actor_type
                    OR r.receipt_document#>>'{evaluation,actor,id}' IS DISTINCT FROM r.actor_id
                    OR r.receipt_document#>'{evaluation,operation}' IS DISTINCT FROM a.challenge_document->'operation'
                    OR r.receipt_document#>>'{evaluation,grant,id}' IS DISTINCT FROM c.grant_id::TEXT
                    OR r.receipt_document#>>'{evaluation,grant,revision}' IS DISTINCT FROM c.grant_revision::TEXT
                    OR r.receipt_document#>>'{evaluation,grant,terms_digest}' IS DISTINCT FROM c.grant_document->>'terms_digest'
                    OR cardinality(string_to_array(r.compact_jws,'.')) IS DISTINCT FROM 3
                    OR r.receipt_document IS DISTINCT FROM convert_from(decode(translate(split_part(r.compact_jws,'.',2),'-_','+/') || repeat('=',(4-length(split_part(r.compact_jws,'.',2))%4)%4),'base64'),'UTF8')::JSONB
                    OR r.receipt_digest IS DISTINCT FROM ('sha256:'||encode(sha256(convert_to(r.compact_jws,'UTF8')),'hex'))
                    OR r.authorization_expires_at IS DISTINCT FROM (r.receipt_document->>'expires_at')::TIMESTAMPTZ
                    OR r.authorization_expires_at>a.expires_at OR r.authorization_expires_at<=r.recorded_at
            ) OR EXISTS (
                SELECT 1 FROM delegated_authority_service.use_command_results r
                LEFT JOIN delegated_authority_service.use_command_claims c USING(organization_id,actor_type,actor_id,command_id)
                LEFT JOIN delegated_authority_service.use_admissions a ON a.organization_id=c.organization_id AND a.challenge_id=c.challenge_id
                LEFT JOIN delegated_authority_service.use_receipts s ON s.organization_id=c.organization_id AND s.challenge_id=c.challenge_id
                WHERE c.command_id IS NULL OR a.challenge_id IS NULL
                    OR r.response_document->>'profile' IS DISTINCT FROM 'urn:marty:delegation-command-response:v1'
                    OR r.response_document->>'original_command_id' IS DISTINCT FROM r.command_id::TEXT
                    OR r.response_document->>'command_digest' IS DISTINCT FROM c.command_digest
                    OR r.response_document->>'recovered' IS DISTINCT FROM 'false'
                    OR r.response_document#>>'{result,challenge_id}' IS DISTINCT FROM c.challenge_id::TEXT
                    OR CASE c.command_name WHEN 'START_USE' THEN
                        r.response_document#>>'{result,kind}' IS DISTINCT FROM 'CHALLENGE'
                        OR r.response_document#>'{result,operation}' IS DISTINCT FROM a.challenge_document->'operation'
                        OR r.response_document#>'{result,grant}' IS DISTINCT FROM c.command_document->'grant'
                        OR (r.response_document#>>'{result,created_at}')::TIMESTAMPTZ IS DISTINCT FROM a.created_at
                        OR (r.response_document#>>'{result,expires_at}')::TIMESTAMPTZ IS DISTINCT FROM a.expires_at
                      WHEN 'FINALIZE_USE' THEN s.challenge_id IS NULL OR s.command_id IS DISTINCT FROM c.command_id
                        OR r.response_document#>>'{result,kind}' IS DISTINCT FROM 'FINAL_USE'
                        OR r.response_document#>>'{result,semantics}' IS DISTINCT FROM 'EVIDENCE_ONLY'
                        OR r.response_document#>>'{result,decision}' IS DISTINCT FROM s.receipt_document->>'decision'
                        OR r.response_document#>>'{result,receipt_ref}' IS DISTINCT FROM s.receipt_ref
                        OR r.response_document#>>'{result,receipt_digest}' IS DISTINCT FROM s.receipt_digest
                        OR (r.response_document#>>'{result,recorded_at}')::TIMESTAMPTZ IS DISTINCT FROM s.recorded_at
                        OR (r.response_document#>>'{result,authorization_expires_at}')::TIMESTAMPTZ IS DISTINCT FROM s.authorization_expires_at
                      ELSE true END
            ) INTO bad;
            IF bad THEN RAISE EXCEPTION 'invalid retained use identity or history'; END IF;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION USING MESSAGE='DA_PREFLIGHT_USE_HISTORY: retained command identity, admission or receipt evidence is inconsistent',
                HINT='Preserve pending claims and original receipts. Inspection cannot clear an ambiguous command or authorize retry/signing.';
        END;
    END IF;

    IF schema_version>=7 THEN
        IF (WITH expected(name,expression) AS (VALUES
            ('machine_evidence_digest_matches_bytes','(evidence_digest = (''sha256:''::text || encode(sha256(audit_bytes), ''hex''::text)))'),
            ('machine_evidence_document_matches_bytes','((convert_from(audit_bytes, ''UTF8''::name))::jsonb = audit_document)'),
            ('machine_evidence_reference_matches_digest','(evidence_ref = (''urn:marty:machine-authentication:''::text || evidence_digest))'))
            SELECT count(*) FROM expected e JOIN pg_constraint c ON c.conname=e.name
              AND c.conrelid='delegated_authority_service.machine_authentication_evidence'::regclass
            WHERE c.contype='c' AND c.convalidated AND c.conislocal AND pg_get_expr(c.conbin,c.conrelid)=e.expression)<>3 THEN
            RAISE EXCEPTION 'DA_PREFLIGHT_MACHINE_CONSTRAINT: exact audit bytes/digest/document checks are missing or weakened';
        END IF;
        IF NOT EXISTS(SELECT 1 FROM pg_index i JOIN pg_constraint c ON c.conindid=i.indexrelid
            WHERE i.indrelid='delegated_authority_service.machine_authentication_evidence'::regclass
              AND c.contype='p' AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
              AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
              AND ARRAY(SELECT a.attname::TEXT FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
                  JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.ord)
                  =ARRAY['organization_id','evidence_ref']) THEN
            RAISE EXCEPTION 'DA_PREFLIGHT_MACHINE_INDEX: exact tenant/audit identity index is missing or weakened';
        END IF;
        BEGIN
            SELECT count(*) INTO machine_evidence_count FROM delegated_authority_service.machine_authentication_evidence;
            SELECT EXISTS(SELECT 1 FROM delegated_authority_service.machine_authentication_evidence e
                WHERE octet_length(e.audit_bytes) NOT BETWEEN 1 AND 65536
                  OR e.evidence_digest IS DISTINCT FROM ('sha256:'||encode(sha256(e.audit_bytes),'hex'))
                  OR e.evidence_ref IS DISTINCT FROM ('urn:marty:machine-authentication:'||e.evidence_digest)
                  OR convert_from(e.audit_bytes,'UTF8')::JSONB IS DISTINCT FROM e.audit_document
                  OR e.audit_document->>'profile' IS DISTINCT FROM 'urn:marty:machine-authentication-evidence:v1'
                  OR e.actor_type IS DISTINCT FROM 'MACHINE_IDENTITY'
                  OR e.audit_document#>>'{scope,organization_id}' IS DISTINCT FROM e.organization_id::TEXT
                  OR e.audit_document#>>'{scope,principal,type}' IS DISTINCT FROM e.actor_type
                  OR e.audit_document#>>'{scope,principal,id}' IS DISTINCT FROM e.actor_id
                  OR e.audit_document#>>'{scope,machine_identity_id}' IS DISTINCT FROM e.machine_identity_id::TEXT
                  OR e.audit_document#>>'{scope,grant_id}' IS DISTINCT FROM e.grant_id::TEXT
                  OR e.audit_document#>>'{scope,grant_revision}' IS DISTINCT FROM e.grant_revision::TEXT
                  OR e.audit_document#>>'{scope,challenge_id}' IS DISTINCT FROM e.challenge_id::TEXT
                  OR e.audit_document#>>'{scope,proof_evidence_ref}' IS DISTINCT FROM e.audit_document#>>'{proof,evidence_ref}'
                  OR (e.audit_document->>'completed_at')::TIMESTAMPTZ IS DISTINCT FROM e.completed_at
                  OR (e.audit_document->>'valid_until')::TIMESTAMPTZ IS DISTINCT FROM e.valid_until
                  OR e.completed_at>e.retained_at OR e.retained_at>=e.valid_until
            ) INTO bad;
            IF bad THEN RAISE EXCEPTION 'invalid retained machine authentication evidence'; END IF;
            -- Migration 0007 does not synthesize audit for original pre-0007
            -- machine receipts. Count that history explicitly; it is not a new
            -- qualification or permission to execute/retry an old outcome.
            SELECT count(*) INTO legacy_machine_receipt_count
              FROM delegated_authority_service.use_receipts r
              WHERE r.actor_type='MACHINE_IDENTITY'
                AND r.recorded_at<(SELECT applied_at FROM delegated_authority_service.schema_migrations WHERE version=7)
                AND NOT EXISTS(SELECT 1 FROM delegated_authority_service.machine_authentication_evidence e
                    WHERE e.organization_id=r.organization_id AND e.evidence_ref=r.receipt_document#>>'{evaluation,proof_evidence_ref}');
            SELECT EXISTS(SELECT 1 FROM delegated_authority_service.use_receipts r
                LEFT JOIN delegated_authority_service.machine_authentication_evidence e
                    ON e.organization_id=r.organization_id AND e.evidence_ref=r.receipt_document#>>'{evaluation,proof_evidence_ref}'
                WHERE (r.actor_type<>'MACHINE_IDENTITY' AND r.receipt_document#>>'{evaluation,proof_evidence_ref}' LIKE 'urn:marty:machine-authentication:%')
                   OR (r.actor_type='MACHINE_IDENTITY' AND
                       (e.evidence_ref IS NOT NULL OR r.recorded_at>=(SELECT applied_at FROM delegated_authority_service.schema_migrations WHERE version=7)) AND (
                    e.evidence_ref IS NULL OR e.actor_type IS DISTINCT FROM r.actor_type OR e.actor_id IS DISTINCT FROM r.actor_id
                    OR e.challenge_id IS DISTINCT FROM r.challenge_id
                    OR e.audit_document#>'{scope,principal}' IS DISTINCT FROM r.receipt_document#>'{evaluation,actor}'
                    OR e.audit_document#>>'{scope,organization_id}' IS DISTINCT FROM r.receipt_document#>>'{evaluation,organization_id}'
                    OR e.audit_document#>>'{scope,grant_id}' IS DISTINCT FROM r.receipt_document#>>'{evaluation,grant,id}'
                    OR e.audit_document#>>'{scope,grant_revision}' IS DISTINCT FROM r.receipt_document#>>'{evaluation,grant,revision}'
                    OR e.audit_document#>>'{scope,proof_evidence_ref}' IS DISTINCT FROM ('urn:marty:oid4vp-proof:'||substr(r.proof_digest,8))
                    OR e.audit_document#>>'{scope,challenge_digest}' IS DISTINCT FROM ('sha256:'||encode(sha256(convert_to(r.receipt_document#>>'{evaluation,challenge}','UTF8')),'hex'))
                    OR e.audit_document#>>'{scope,action}' IS DISTINCT FROM r.receipt_document#>>'{evaluation,operation,action}'
                    OR e.audit_document#>>'{scope,audience}' IS DISTINCT FROM r.receipt_document#>>'{evaluation,operation,audience}'
                    OR e.audit_document#>>'{scope,resource}' IS DISTINCT FROM r.receipt_document#>>'{evaluation,operation,resource_id}'
                    OR e.audit_document#>>'{scope,operation_profile}' IS DISTINCT FROM r.receipt_document#>>'{evaluation,operation,request_profile}'
                    OR e.audit_document#>>'{scope,operation_digest}' IS DISTINCT FROM r.receipt_document#>>'{evaluation,operation,request_digest}'
                    OR r.receipt_document#>>'{evaluation,binding,method}' IS DISTINCT FROM 'KEY'
                    OR e.audit_document#>>'{scope,key_thumbprint}' IS DISTINCT FROM r.receipt_document#>>'{evaluation,binding,key_thumbprint}'
                    OR (r.receipt_document#>>'{evaluation,proof_verified_at}')::TIMESTAMPTZ IS DISTINCT FROM (e.audit_document#>>'{proof,verified_at}')::TIMESTAMPTZ
                    OR (r.receipt_document#>>'{evaluation,proof_valid_until}')::TIMESTAMPTZ IS DISTINCT FROM e.valid_until
                    OR (r.receipt_document#>>'{evaluation,evaluated_at}')::TIMESTAMPTZ IS NULL
                    OR (r.receipt_document#>>'{evaluation,evaluated_at}')::TIMESTAMPTZ<e.completed_at
                    OR (r.receipt_document#>>'{evaluation,evaluated_at}')::TIMESTAMPTZ>=e.valid_until
                    OR e.retained_at>r.recorded_at OR r.authorization_expires_at>e.valid_until))) INTO bad;
            IF bad THEN RAISE EXCEPTION 'invalid retained machine receipt binding'; END IF;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION USING MESSAGE='DA_PREFLIGHT_MACHINE_HISTORY: exact audit bytes, scope or receipt binding is inconsistent',
                HINT='Preserve original private evidence. Historical audit never authenticates a new proof or renews a deadline.';
        END;
    END IF;

    IF schema_version>=8 THEN
        IF (WITH expected(name,expression) AS (VALUES
            ('machine_authorization_evidence_bytes','((convert_from(evidence_bytes, ''UTF8''::name))::jsonb = evidence_document)'),
            ('machine_authorization_evidence_digest','(evidence_digest = (''sha256:''::text || encode(sha256(evidence_bytes), ''hex''::text)))'),
            ('machine_authorization_evidence_reference','(evidence_ref = (CASE kind WHEN ''SOURCE''::text THEN ''urn:marty:machine-policy-source:''::text ELSE ''urn:marty:machine-authorization:''::text END || evidence_digest))'))
            SELECT count(*) FROM expected e JOIN pg_constraint c ON c.conname=e.name
              AND c.conrelid='delegated_authority_service.machine_authorization_evidence'::regclass
            WHERE c.contype='c' AND c.convalidated AND c.conislocal
              AND regexp_replace(pg_get_expr(c.conbin,c.conrelid),'[[:space:]]','','g')=regexp_replace(e.expression,'[[:space:]]','','g'))<>3 THEN
            RAISE EXCEPTION 'DA_PREFLIGHT_MACHINE_POLICY_CONSTRAINT: exact source/evaluation bytes, digest and reference checks are missing or weakened';
        END IF;
        IF NOT EXISTS(SELECT 1 FROM pg_index i JOIN pg_constraint c ON c.conindid=i.indexrelid
            WHERE i.indrelid='delegated_authority_service.machine_authorization_evidence'::regclass
              AND c.contype='p' AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
              AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnkeyatts=2 AND i.indnatts=2
              AND ARRAY(SELECT a.attname::TEXT FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ord)
                  JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.ord)=ARRAY['organization_id','evidence_ref']) THEN
            RAISE EXCEPTION 'DA_PREFLIGHT_MACHINE_POLICY_INDEX: exact source/evaluation identity is missing';
        END IF;
        -- A correctly named trigger whose function was replaced is not a guard.
        IF (WITH expected(name,body_digest) AS (VALUES
            ('guard_machine_authorization_evidence','af3084df9dd020ddb71735eabcb9858bfe3470d67de8c124295f8ab89ca65198'),
            ('check_machine_authorization_evidence_commit','83848cf57d41e129183b740d5af0817568eae4750d8b258fdb6a1bc34d7f579f'),
            ('guard_machine_authentication_authorization','1e10ce21bd4811a885f457ace4ea628768ab2c1e6530d979819a21d325bb1b37'))
            SELECT count(*) FROM expected e JOIN pg_proc p ON p.pronamespace=schema_id AND p.proname=e.name
              JOIN pg_language l ON l.oid=p.prolang
            WHERE p.pronargs=0 AND NOT p.prosecdef AND p.prorettype='trigger'::regtype AND p.prokind='f'
              AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog']::TEXT[]
              AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=e.body_digest)<>3 THEN
            RAISE EXCEPTION 'DA_PREFLIGHT_MACHINE_POLICY_GUARD: exact source/evaluation binding or commit function is missing or changed';
        END IF;
        BEGIN
            SELECT count(*) INTO machine_policy_evidence_count FROM delegated_authority_service.machine_authorization_evidence;
            SELECT EXISTS(SELECT 1 FROM delegated_authority_service.machine_authorization_evidence e
                LEFT JOIN delegated_authority_service.machine_authorization_evidence s
                  ON s.organization_id=e.organization_id AND s.evidence_ref=e.evidence_document->>'source_evidence_ref' AND s.kind='SOURCE'
                WHERE e.evidence_document IS DISTINCT FROM convert_from(e.evidence_bytes,'UTF8')::JSONB
                   OR e.evidence_digest IS DISTINCT FROM 'sha256:'||encode(sha256(e.evidence_bytes),'hex')
                   OR e.evidence_ref IS DISTINCT FROM (CASE e.kind WHEN 'SOURCE' THEN 'urn:marty:machine-policy-source:' ELSE 'urn:marty:machine-authorization:' END)||e.evidence_digest
                   OR e.evidence_document#>>'{scope,organization_id}' IS DISTINCT FROM e.organization_id::TEXT
                   OR e.evidence_document#>>'{scope,principal,type}' IS DISTINCT FROM 'MACHINE_IDENTITY'
                   OR (e.evidence_document->>'observed_at')::TIMESTAMPTZ IS DISTINCT FROM e.observed_at
                   OR (e.evidence_document->>'valid_until')::TIMESTAMPTZ IS DISTINCT FROM e.valid_until
                   OR e.completed_at<e.observed_at OR e.retained_at<e.completed_at OR e.retained_at>=e.valid_until
                   OR e.valid_until>e.observed_at+INTERVAL '30 seconds'
                   OR (e.kind='SOURCE' AND (
                        e.evidence_document->>'profile' IS DISTINCT FROM 'urn:marty:machine-policy-source-evidence:v1'
                        OR (e.evidence_document->>'completed_at')::TIMESTAMPTZ IS DISTINCT FROM e.completed_at
                        OR e.evidence_document#>>'{policy_snapshot,organization_id}' IS DISTINCT FROM e.organization_id::TEXT
                        OR e.evidence_document#>>'{policy_snapshot,policy_set_id}' IS DISTINCT FROM e.evidence_document->>'policy_set_id'
                        OR e.evidence_document#>>'{policy_snapshot,revision}' IS DISTINCT FROM e.evidence_document->>'policy_revision'
                        OR e.evidence_document#>>'{policy_snapshot,policy_type}' IS DISTINCT FROM 'MACHINE_AUTHORIZATION'
                        OR e.evidence_document#>>'{policy_snapshot,status}' IS DISTINCT FROM 'ACTIVE'
                        OR e.evidence_document#>>'{policy_snapshot,schema_version}' IS DISTINCT FROM 'MartyMachine/1.0'
                        OR e.evidence_document#>>'{policy_snapshot,schema_digest}' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(e.evidence_document->>'schema','UTF8')),'hex')
                        OR e.evidence_document->>'history_ref' IS NULL OR e.evidence_document->'entities' IS NULL))
                   OR (e.kind='EVALUATION' AND (s.evidence_ref IS NULL
                        OR e.evidence_document->>'profile' IS DISTINCT FROM 'urn:marty:machine-authorization-evidence:v1'
                        OR e.evidence_document->>'decision' IS DISTINCT FROM 'PERMIT'
                        OR (e.evidence_document->>'evaluated_at')::TIMESTAMPTZ IS DISTINCT FROM e.completed_at
                        OR e.evidence_document->'scope' IS DISTINCT FROM s.evidence_document->'scope'
                        OR e.evidence_document->>'policy_set_id' IS DISTINCT FROM s.evidence_document->>'policy_set_id'
                        OR e.evidence_document->>'policy_revision' IS DISTINCT FROM s.evidence_document->>'policy_revision'
                        OR e.evidence_document->>'policy_digest' IS DISTINCT FROM s.evidence_document->>'policy_digest'
                        OR e.observed_at IS DISTINCT FROM s.observed_at
                        OR e.completed_at<s.retained_at OR e.valid_until>s.valid_until))) INTO bad;
            IF bad THEN RAISE EXCEPTION 'inconsistent source/evaluation evidence'; END IF;
            SELECT count(*) INTO legacy_machine_policy_audit_count FROM delegated_authority_service.machine_authentication_evidence a
                WHERE a.audit_document->'machine_authorization' IS NOT NULL AND a.audit_document->'machine_authorization'<>'null'::JSONB
                  AND a.retained_at<(SELECT applied_at FROM delegated_authority_service.schema_migrations WHERE version=8);
            SELECT EXISTS(SELECT 1 FROM delegated_authority_service.machine_authentication_evidence a
                LEFT JOIN delegated_authority_service.machine_authorization_evidence e
                  ON e.organization_id=a.organization_id AND e.evidence_ref=a.audit_document#>>'{machine_authorization,evidence_ref}' AND e.kind='EVALUATION'
                WHERE a.audit_document->'machine_authorization' IS NOT NULL AND a.audit_document->'machine_authorization'<>'null'::JSONB
                  AND a.retained_at>=(SELECT applied_at FROM delegated_authority_service.schema_migrations WHERE version=8)
                  AND (e.evidence_ref IS NULL OR e.evidence_document->'scope' IS DISTINCT FROM a.audit_document->'scope'
                    OR a.audit_document#>>'{machine_authorization,policy_type}' IS DISTINCT FROM 'MACHINE_AUTHORIZATION'
                    OR a.audit_document#>>'{machine_authorization,policy_set_id}' IS DISTINCT FROM e.evidence_document->>'policy_set_id'
                    OR a.audit_document#>>'{machine_authorization,revision}' IS DISTINCT FROM e.evidence_document->>'policy_revision'
                    OR a.audit_document#>>'{machine_authorization,policy_digest}' IS DISTINCT FROM e.evidence_document->>'policy_digest'
                    OR (a.audit_document#>>'{machine_authorization,observed_at}')::TIMESTAMPTZ IS DISTINCT FROM e.observed_at
                    OR (a.audit_document#>>'{machine_authorization,valid_until}')::TIMESTAMPTZ IS DISTINCT FROM e.valid_until
                    OR a.completed_at<e.retained_at OR a.valid_until>e.valid_until)) INTO bad;
            IF bad THEN RAISE EXCEPTION 'machine audit has no matching retained machine permit'; END IF;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION USING MESSAGE='DA_PREFLIGHT_MACHINE_POLICY_HISTORY: retained machine policy source/evaluation evidence is inconsistent',
                HINT='Preserve original source observations and outcomes. Inspection never fabricates missing source or permission records.';
        END;
    END IF;

    PERFORM set_config('marty.preflight.result',CASE WHEN selected_phase='post-migration'
        THEN 'DATABASE_PREFLIGHT_PASSED' ELSE 'PRE_MIGRATION_INSPECTION_PASSED' END,true);
    IF schema_version>=9 THEN
        IF NOT EXISTS(SELECT 1 FROM pg_proc WHERE oid=to_regprocedure('delegated_authority_service.guard_use_command_claim()')
          AND encode(sha256(convert_to(prosrc,'UTF8')),'hex')='1421459962bb49b3d91a3d7b82e56d7cd5430b0cc9e6f771144b20912ed064c6') THEN
            RAISE EXCEPTION 'DA_PREFLIGHT_USE_LOCK_HELPER: use claim lock delegation or binding guard differs';
        END IF;
        SELECT count(*) INTO use_table_count FROM (VALUES
            ('lock_use_grant(uuid,uuid)','delegation_grants','d1aa2f9582901679fe383ccfe423b0c2437c163727cc3d8036af88ee3e23d2ae'),
            ('lock_use_claim(uuid,text,text,uuid)','use_command_claims','3e08d33df8a634589311359b388ca8eb3255b9f49d0c0b2fb9b764648af6cca3'),
            ('lock_use_admission(uuid,text,text,uuid)','use_admissions','0090bcd7bb36e1be9bf9579f63e7ce518de80530119d3d7486c2a72efa36b317')
        ) expected(signature,table_name,body_digest)
        JOIN pg_proc p ON p.oid=to_regprocedure('delegated_authority_service.'||expected.signature)
        JOIN pg_class t ON t.oid=to_regclass('delegated_authority_service.'||expected.table_name)
        JOIN pg_language l ON l.oid=p.prolang
        WHERE p.prosecdef AND p.proretset AND p.prorettype=t.reltype AND p.prokind='f'
          AND p.provolatile='v' AND p.proparallel='u' AND NOT p.proisstrict AND p.pronargdefaults=0
          AND l.lanname='sql' AND p.proconfig=ARRAY['search_path=pg_catalog']::TEXT[]
          AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.body_digest
          AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                         WHERE a.grantee=0 AND a.privilege_type='EXECUTE');
        IF use_table_count<>3 THEN
            RAISE EXCEPTION 'DA_PREFLIGHT_USE_LOCK_HELPER: serving lock body, shape or PUBLIC access differs';
        END IF;
    END IF;

    PERFORM set_config('marty.preflight.version',schema_version::TEXT,true);
    PERFORM set_config('marty.preflight.grants',grant_count::TEXT,true);
    PERFORM set_config('marty.preflight.events',event_count::TEXT,true);
    PERFORM set_config('marty.preflight.results',result_count::TEXT,true);
    PERFORM set_config('marty.preflight.reviews',review_count::TEXT,true);
    PERFORM set_config('marty.preflight.confirmations',confirmation_count::TEXT,true);
    PERFORM set_config('marty.preflight.observations',observation_count::TEXT,true);
    PERFORM set_config('marty.preflight.use_claims',use_claim_count::TEXT,true);
    PERFORM set_config('marty.preflight.use_results',use_result_count::TEXT,true);
    PERFORM set_config('marty.preflight.machine_evidence',machine_evidence_count::TEXT,true);
    PERFORM set_config('marty.preflight.legacy_machine_receipts',legacy_machine_receipt_count::TEXT,true);
    PERFORM set_config('marty.preflight.machine_policy_evidence',machine_policy_evidence_count::TEXT,true);
    PERFORM set_config('marty.preflight.legacy_machine_policy_audits',legacy_machine_policy_audit_count::TEXT,true);
END
$preflight$;

SELECT jsonb_build_object(
    'result',current_setting('marty.preflight.result'),
    'phase',current_setting('marty.preflight.phase'),
    'schema_version',current_setting('marty.preflight.version')::INTEGER,
    'grant_count',current_setting('marty.preflight.grants')::BIGINT,
    'event_count',current_setting('marty.preflight.events')::BIGINT,
    'command_result_count',current_setting('marty.preflight.results')::BIGINT,
    'approval_review_count',current_setting('marty.preflight.reviews')::BIGINT,
    'approval_confirmation_count',current_setting('marty.preflight.confirmations')::BIGINT,
    'organization_authority_observation_count',current_setting('marty.preflight.observations')::BIGINT,
    'use_command_claim_count',current_setting('marty.preflight.use_claims')::BIGINT,
    'use_command_result_count',current_setting('marty.preflight.use_results')::BIGINT,
    'machine_authentication_evidence_count',current_setting('marty.preflight.machine_evidence')::BIGINT,
    'legacy_machine_receipt_count',current_setting('marty.preflight.legacy_machine_receipts')::BIGINT,
    'machine_authorization_evidence_count',current_setting('marty.preflight.machine_policy_evidence')::BIGINT,
    'legacy_machine_authorization_audit_count',current_setting('marty.preflight.legacy_machine_policy_audits')::BIGINT,
    'runtime_qualification','NOT_ASSESSED',
    'execution_authorized',false
) AS delegated_authority_database_preflight;
ROLLBACK;
