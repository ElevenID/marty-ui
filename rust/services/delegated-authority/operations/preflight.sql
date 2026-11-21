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
    schema_version INTEGER := 0;
    versions INTEGER[] := ARRAY[]::INTEGER[];
    -- File-byte SHA-256 values. The Rust migrator stores them with the mandatory
    -- "sha256:" prefix; compare that exact ledger representation below.
    expected_checksums TEXT[] := ARRAY[
        'bd7c8d273f0824099fcd230667e64e40bb1cd42107f3bf419b25fe0c60887945',
        '9e1f6df883edeaf1abba52b3ff8ceafed0e9ecbf32f5ee723a9f458b09f29ff6',
        '63cb2d26f3efff51c6725f0c67e3c6c4541f70bce69a0559c6ed0afa53a295c1',
        'cedcf39d7d2cc35defe20066c5fad80e2c00b39f422fb0ffe9590ac508e9f16a'
    ];
    evidence_tables TEXT[] := ARRAY['consent_confirmations','consent_withdrawals',
        'representation_authority_sources','representation_authority_assertions'];
    evidence_count INTEGER := 0;
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
                    ('journal_grant_lifecycle','guard_consent_source','guard_authority_assertion')))) THEN
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
               OR assumed_role.oid=role_ids[1]
               OR (assumed_role.oid=ANY(role_ids[2:4]) AND assumed_role.oid<>role_ids[role_index])
               OR has_database_privilege(assumed_role.oid,current_database(),'CREATE') THEN
                RAISE EXCEPTION 'DA_PREFLIGHT_ROLE_ESCALATION: request/producer identity can reach administrative or another component authority';
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
                               'representation_authority_sources','representation_authority_assertions','command_results'))
                            OR (object_record.relname='delegation_grants' AND privilege_name IN ('INSERT','UPDATE'))
                            OR (object_record.relname='command_results' AND privilege_name='INSERT')
                        WHEN role_index=3 THEN
                            object_record.relname IN ('consent_confirmations','consent_withdrawals')
                            AND privilege_name IN ('SELECT','INSERT')
                        ELSE
                            object_record.relname IN ('representation_authority_sources','representation_authority_assertions')
                            AND privilege_name IN ('SELECT','INSERT') END;
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
            IF NOT has_schema_privilege(role_ids[role_index],schema_id,'USAGE') THEN
                RAISE EXCEPTION 'DA_PREFLIGHT_MISSING_PRIVILEGE: component requires schema USAGE';
            END IF;
            FOR object_record IN SELECT oid,relname FROM pg_class WHERE relnamespace=schema_id AND relkind='r' LOOP
                FOREACH privilege_name IN ARRAY ARRAY['SELECT','INSERT','UPDATE'] LOOP
                    permitted := CASE WHEN role_index=2 THEN
                        (privilege_name='SELECT' AND object_record.relname IN
                          ('schema_migrations','delegation_grants','grant_lifecycle_events',
                           'consent_confirmations','consent_withdrawals','representation_authority_sources',
                           'representation_authority_assertions','command_results'))
                        OR (object_record.relname='delegation_grants' AND privilege_name IN ('INSERT','UPDATE'))
                        OR (object_record.relname='command_results' AND privilege_name='INSERT')
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
        (4,'command_results','command_results_no_truncate','reject_lifecycle_event_mutation',34)
      ) AS expected(version,table_name,trigger_name,function_name,trigger_type)
      WHERE version<=schema_version
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
            WHERE t.tgrelid=to_regclass(format('delegated_authority_service.%I',trigger_record.table_name))
              AND t.tgname=trigger_record.trigger_name AND NOT t.tgisinternal
              AND t.tgenabled='O' AND t.tgtype=trigger_record.trigger_type
              AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector
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

    PERFORM set_config('marty.preflight.result',CASE WHEN selected_phase='post-migration'
        THEN 'DATABASE_PREFLIGHT_PASSED' ELSE 'PRE_MIGRATION_INSPECTION_PASSED' END,true);
    PERFORM set_config('marty.preflight.version',schema_version::TEXT,true);
    PERFORM set_config('marty.preflight.grants',grant_count::TEXT,true);
    PERFORM set_config('marty.preflight.events',event_count::TEXT,true);
    PERFORM set_config('marty.preflight.results',result_count::TEXT,true);
END
$preflight$;

SELECT jsonb_build_object(
    'result',current_setting('marty.preflight.result'),
    'phase',current_setting('marty.preflight.phase'),
    'schema_version',current_setting('marty.preflight.version')::INTEGER,
    'grant_count',current_setting('marty.preflight.grants')::BIGINT,
    'event_count',current_setting('marty.preflight.events')::BIGINT,
    'command_result_count',current_setting('marty.preflight.results')::BIGINT,
    'runtime_qualification','NOT_ASSESSED',
    'execution_authorized',false
) AS delegated_authority_database_preflight;
ROLLBACK;
