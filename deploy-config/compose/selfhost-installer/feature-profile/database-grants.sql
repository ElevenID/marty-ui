-- Fixed native-managed feature role grants. Existing product migrations run
-- unchanged under their owners before this phase. No broad runtime ownership,
-- role memberships, grant options or journal rewrites are introduced.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('elevenid.native-feature-database/v1',0));
DO $feature_owner$
BEGIN
    IF current_user <> 'postgres' OR current_user <> session_user OR current_database() <> 'marty'
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
       OR to_regnamespace('passport_cutover') IS NOT NULL
       OR pg_catalog.pg_get_userbyid((SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='delegated_authority_service')) IS DISTINCT FROM 'feature_delegation_owner'
       OR pg_catalog.pg_get_userbyid((SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='machine_credential_source')) IS DISTINCT FROM 'feature_credential_owner'
       OR (SELECT count(*) FROM delegated_authority_service.schema_migrations) <> 9
       OR (SELECT count(*) FROM machine_credential_source.schema_migrations) <> 1 THEN
        RAISE EXCEPTION 'feature grants require the original native database and completed source migrations';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE left(r.rolname,8)='feature_' AND
         (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR r.rolinherit
          OR NOT r.rolcanlogin OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid))) THEN
        RAISE EXCEPTION 'feature roles have changed authority';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE left(r.rolname,8)='feature_'
        AND r.rolname NOT IN ('feature_delegation_owner','feature_credential_owner')
        AND (EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspowner=r.oid)
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.relowner=r.oid)
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner=r.oid))) THEN
        RAISE EXCEPTION 'feature runtime role owns an object';
    END IF;
END
$feature_owner$;
REVOKE CREATE ON DATABASE marty FROM feature_delegation_owner,feature_credential_owner;
REVOKE CREATE,TEMPORARY ON DATABASE marty FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA delegated_authority_service TO feature_approval_runtime;
GRANT SELECT ON TABLE delegated_authority_service.schema_migrations,
    delegated_authority_service.delegation_grants,
    delegated_authority_service.grant_lifecycle_events,
    delegated_authority_service.consent_confirmations,
    delegated_authority_service.consent_withdrawals,
    delegated_authority_service.representation_authority_sources,
    delegated_authority_service.representation_authority_assertions,
    delegated_authority_service.command_results,
    delegated_authority_service.approval_reviews,
    delegated_authority_service.approval_confirmation_bindings,
    delegated_authority_service.organization_authority_observations,
    delegated_authority_service.approval_storage_identity TO feature_approval_runtime;
GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(text) TO feature_approval_runtime;
GRANT USAGE ON SCHEMA delegated_authority_service TO feature_command_runtime;
GRANT SELECT ON TABLE delegated_authority_service.schema_migrations,
    delegated_authority_service.delegation_grants,
    delegated_authority_service.grant_lifecycle_events,
    delegated_authority_service.consent_confirmations,
    delegated_authority_service.consent_withdrawals,
    delegated_authority_service.representation_authority_sources,
    delegated_authority_service.representation_authority_assertions,
    delegated_authority_service.command_results,
    delegated_authority_service.approval_reviews,
    delegated_authority_service.approval_confirmation_bindings,
    delegated_authority_service.organization_authority_observations,
    delegated_authority_service.approval_storage_identity TO feature_command_runtime;
GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(text) TO feature_command_runtime;
GRANT USAGE ON SCHEMA organization_service TO feature_approval_organization;
GRANT SELECT ON TABLE organization_service.organizations,
    organization_service.members,
    organization_service.roles,
    organization_service.permissions,
    organization_service.member_roles,
    organization_service.role_permissions TO feature_approval_organization;
GRANT USAGE ON SCHEMA organization_service TO feature_command_organization;
GRANT SELECT ON TABLE organization_service.organizations,
    organization_service.members,
    organization_service.roles,
    organization_service.permissions,
    organization_service.member_roles,
    organization_service.role_permissions TO feature_command_organization;
GRANT USAGE ON SCHEMA delegated_authority_service TO feature_command_writer;
GRANT SELECT ON TABLE delegated_authority_service.schema_migrations,
    delegated_authority_service.delegation_grants,
    delegated_authority_service.grant_lifecycle_events,
    delegated_authority_service.consent_confirmations,
    delegated_authority_service.consent_withdrawals,
    delegated_authority_service.representation_authority_sources,
    delegated_authority_service.representation_authority_assertions,
    delegated_authority_service.command_results,
    delegated_authority_service.approval_reviews,
    delegated_authority_service.approval_confirmation_bindings,
    delegated_authority_service.organization_authority_observations,
    delegated_authority_service.approval_storage_identity TO feature_command_writer;
GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(text) TO feature_command_writer;
GRANT INSERT,UPDATE ON TABLE delegated_authority_service.delegation_grants TO feature_command_writer;
GRANT INSERT ON TABLE delegated_authority_service.command_results TO feature_command_writer;
GRANT SELECT,INSERT ON TABLE delegated_authority_service.command_identities TO feature_command_writer;
GRANT USAGE ON SCHEMA delegated_authority_service TO feature_approval_consent;
GRANT SELECT ON TABLE delegated_authority_service.consent_confirmations,
    delegated_authority_service.consent_withdrawals,
    delegated_authority_service.approval_reviews,
    delegated_authority_service.approval_confirmation_bindings,
    delegated_authority_service.approval_storage_identity TO feature_approval_consent;
GRANT INSERT ON TABLE delegated_authority_service.consent_confirmations,
    delegated_authority_service.consent_withdrawals,
    delegated_authority_service.approval_reviews,
    delegated_authority_service.approval_confirmation_bindings TO feature_approval_consent;
GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(text) TO feature_approval_consent;
GRANT USAGE ON SCHEMA delegated_authority_service TO feature_approval_authority;
GRANT SELECT ON TABLE delegated_authority_service.delegation_grants,
    delegated_authority_service.representation_authority_sources,
    delegated_authority_service.representation_authority_assertions,
    delegated_authority_service.organization_authority_observations,
    delegated_authority_service.approval_storage_identity TO feature_approval_authority;
GRANT INSERT ON TABLE delegated_authority_service.representation_authority_sources,
    delegated_authority_service.representation_authority_assertions,
    delegated_authority_service.organization_authority_observations TO feature_approval_authority;
GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(text) TO feature_approval_authority;

-- use_writer: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA delegated_authority_service,
    flow_service TO feature_use_writer;
GRANT SELECT ON TABLE delegated_authority_service.schema_migrations,
    delegated_authority_service.approval_storage_identity,
    delegated_authority_service.delegation_grants,
    delegated_authority_service.command_identities,
    delegated_authority_service.use_command_claims,
    delegated_authority_service.use_admissions,
    delegated_authority_service.use_receipts,
    delegated_authority_service.use_command_results,
    delegated_authority_service.machine_authentication_evidence,
    flow_service.rust_schema_versions,
    flow_service.delegated_use_storage_identity,
    flow_service.flow_definitions,
    flow_service.flow_instances,
    flow_service.delegated_challenge_bindings,
    flow_service.delegated_proof_submissions,
    flow_service.delegated_use_consumptions TO feature_use_writer;
GRANT INSERT ON TABLE delegated_authority_service.command_identities,
    delegated_authority_service.use_command_claims,
    delegated_authority_service.use_admissions,
    delegated_authority_service.use_receipts,
    delegated_authority_service.use_command_results,
    flow_service.flow_instances,
    flow_service.delegated_challenge_bindings,
    flow_service.delegated_use_consumptions TO feature_use_writer;
GRANT UPDATE(status,current_step_id,completed_at,updated_at,result,state_history) ON TABLE flow_service.flow_instances TO feature_use_writer;
GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(text),
    delegated_authority_service.lock_use_grant(uuid,uuid),
    delegated_authority_service.lock_use_claim(uuid,text,text,uuid),
    delegated_authority_service.lock_use_admission(uuid,text,text,uuid),
    flow_service.lock_delegated_use_definition(text,text),
    flow_service.lock_delegated_use_proof(uuid,uuid,uuid) TO feature_use_writer;

-- runtime_reader: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA delegated_authority_service TO feature_use_runtime_reader;
GRANT SELECT ON TABLE delegated_authority_service.schema_migrations,
    delegated_authority_service.delegation_grants,
    delegated_authority_service.grant_lifecycle_events,
    delegated_authority_service.consent_confirmations,
    delegated_authority_service.consent_withdrawals,
    delegated_authority_service.representation_authority_sources,
    delegated_authority_service.representation_authority_assertions,
    delegated_authority_service.command_results,
    delegated_authority_service.approval_reviews,
    delegated_authority_service.approval_confirmation_bindings,
    delegated_authority_service.organization_authority_observations,
    delegated_authority_service.approval_storage_identity TO feature_use_runtime_reader;
GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(text) TO feature_use_runtime_reader;

-- organization_authority: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA organization_service TO feature_use_organization_authority;
GRANT SELECT ON TABLE organization_service.organizations,
    organization_service.members,
    organization_service.roles,
    organization_service.permissions,
    organization_service.member_roles,
    organization_service.role_permissions TO feature_use_organization_authority;

-- registry_source: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA organization_service TO feature_use_registry_source;
GRANT SELECT ON TABLE organization_service.rust_schema_versions,
    organization_service.organizations,
    organization_service.machine_registry_entries,
    organization_service.machine_registry_history,
    organization_service.machine_registry_observations TO feature_use_registry_source;
GRANT INSERT ON TABLE organization_service.machine_registry_observations TO feature_use_registry_source;

-- access_source: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA organization_service TO feature_use_access_source;
GRANT SELECT ON TABLE organization_service.rust_schema_versions,
    organization_service.organizations,
    organization_service.machine_registry_entries,
    organization_service.machine_registry_history,
    organization_service.machine_use_access,
    organization_service.machine_use_access_history TO feature_use_access_source;

-- machine_policy_source: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA organization_service TO feature_use_machine_policy_source;
GRANT SELECT ON TABLE organization_service.rust_schema_versions,
    organization_service.organizations,
    organization_service.policy_sets,
    organization_service.machine_authorization_policy_history TO feature_use_machine_policy_source;

-- machine_policy_evidence: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA delegated_authority_service TO feature_use_machine_policy_evidence;
GRANT SELECT ON TABLE delegated_authority_service.schema_migrations,
    delegated_authority_service.machine_authorization_evidence TO feature_use_machine_policy_evidence;
GRANT INSERT ON TABLE delegated_authority_service.machine_authorization_evidence TO feature_use_machine_policy_evidence;

-- delegation_policy_source: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA organization_service TO feature_use_delegation_policy_source;
GRANT SELECT ON TABLE organization_service.rust_schema_versions,
    organization_service.organizations,
    organization_service.delegation_use_policies,
    organization_service.delegation_use_policy_history,
    organization_service.delegation_use_policy_observations TO feature_use_delegation_policy_source;
GRANT INSERT ON TABLE organization_service.delegation_use_policy_observations TO feature_use_delegation_policy_source;

-- machine_audit: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA delegated_authority_service TO feature_use_machine_audit;
GRANT SELECT ON TABLE delegated_authority_service.schema_migrations,
    delegated_authority_service.machine_authentication_evidence,
    delegated_authority_service.machine_authorization_evidence TO feature_use_machine_audit;
GRANT INSERT ON TABLE delegated_authority_service.machine_authentication_evidence TO feature_use_machine_audit;

-- flow_reader: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA flow_service TO feature_use_flow_reader;
GRANT SELECT ON TABLE flow_service.rust_schema_versions,
    flow_service.delegated_use_storage_identity,
    flow_service.flow_definitions,
    flow_service.flow_instances,
    flow_service.delegated_challenge_bindings,
    flow_service.delegated_proof_submissions,
    flow_service.delegated_use_consumptions TO feature_use_flow_reader;

-- flow_ingress: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA flow_service TO feature_use_flow_ingress;
GRANT SELECT ON TABLE flow_service.rust_schema_versions,
    flow_service.delegated_use_storage_identity,
    flow_service.flow_definitions,
    flow_service.flow_instances,
    flow_service.delegated_challenge_bindings,
    flow_service.delegated_proof_submissions,
    flow_service.delegated_use_consumptions,
    flow_service.delegated_request_claims,
    flow_service.delegated_request_results,
    flow_service.delegated_proof_ingress TO feature_use_flow_ingress;
GRANT INSERT ON TABLE flow_service.delegated_proof_submissions,
    flow_service.delegated_request_claims,
    flow_service.delegated_request_results,
    flow_service.delegated_proof_ingress TO feature_use_flow_ingress;
GRANT UPDATE(current_step_id,context,step_history,state_history,updated_at) ON TABLE flow_service.flow_instances TO feature_use_flow_ingress;
GRANT EXECUTE ON FUNCTION flow_service.lock_delegated_ingress_definition(uuid,uuid) TO feature_use_flow_ingress;

-- credential_trust: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA trust_profile_service TO feature_use_credential_trust;
GRANT SELECT ON TABLE trust_profile_service.trust_profiles,
    trust_profile_service.issuer_entities,
    trust_profile_service.trust_profile_issuers,
    trust_profile_service.machine_jwt_vc_authority_revisions TO feature_use_credential_trust;
GRANT INSERT ON TABLE trust_profile_service.machine_jwt_vc_authority_revisions TO feature_use_credential_trust;
GRANT UPDATE ON TABLE trust_profile_service.machine_jwt_vc_authority_revisions TO feature_use_credential_trust;

-- credential_status: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA issuance_service TO feature_use_credential_status;
GRANT SELECT ON TABLE issuance_service.issued_credentials,
    issuance_service.issuance_transactions TO feature_use_credential_status;

-- credential_evidence: mirrors the source-owned delegated-use role contract.
GRANT USAGE ON SCHEMA machine_credential_source TO feature_use_credential_evidence;
GRANT SELECT ON TABLE machine_credential_source.schema_migrations,
    machine_credential_source.observations TO feature_use_credential_evidence;
GRANT INSERT ON TABLE machine_credential_source.observations TO feature_use_credential_evidence;

-- Canonical Issuance runtime is a separate login. Product migrations remain
-- owned by marty; no runtime role inherits that owner or gets schema CREATE.
GRANT USAGE ON SCHEMA issuance_service,organization_service,credential_template_service,flow_service TO feature_issuance_runtime;
GRANT SELECT ON issuance_service.rust_schema_migrations TO feature_issuance_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON
    issuance_service.application_templates,issuance_service.applications,
    issuance_service.authorization_sessions,issuance_service.credential_delivery_records,
    issuance_service.evidence_fact_heads,issuance_service.evidence_facts,
    issuance_service.evidence_policy_reviews,issuance_service.issuance_events,
    issuance_service.issuance_transactions,issuance_service.issued_credentials,
    issuance_service.oid4vci_client_assertions,issuance_service.oid4vci_ephemeral_capabilities,
    issuance_service.oid4vci_registered_clients,issuance_service.organization_integration_secrets,
    issuance_service.physical_document_jobs,issuance_service.passport_beta_batch_intents,
    issuance_service.issuance_prerequisite_continuations TO feature_issuance_runtime;
GRANT SELECT,INSERT ON issuance_service.passport_job_administrative_cancellations TO feature_issuance_runtime;
GRANT SELECT ON organization_service.policy_sets,
    credential_template_service.credential_templates,credential_template_service.delivery_destinations,
    flow_service.flow_definitions,flow_service.flow_instances TO feature_issuance_runtime;
GRANT SELECT,INSERT ON issuance_service.application_ownerships,issuance_service.application_ownership_operations TO feature_issuance_runtime;
GRANT UPDATE(user_id,subject_id,application_revision,status,revision,proposed_by,confirmed_at,updated_at)
    ON issuance_service.application_ownerships TO feature_issuance_runtime;
GRANT EXECUTE ON FUNCTION issuance_service.external_observation_lock_organization(uuid),
    issuance_service.external_observation_lock_application(text,text),
    issuance_service.application_ownership_lock_administrator(uuid,text),
    issuance_service.mutate_application_ownership(uuid,text,text,uuid,text,bigint,bigint,text),
    issuance_service.read_application_ownership(uuid,text,text,uuid),
    issuance_service.external_observation_lock_administrator(uuid,text),
    issuance_service.materialization_lock_binding(uuid,text,text),
    issuance_service.materialization_lock_journal(uuid,text),
    issuance_service.materialization_lock_head(text,text,text),
    issuance_service.verification_prerequisite_lock_template(text,text)
    TO feature_issuance_runtime;
GRANT SELECT ON issuance_service.external_observation_receipts,issuance_service.external_observation_audit,
    issuance_service.external_observation_heads,issuance_service.external_observation_bindings TO feature_issuance_runtime;
-- The canonical writer gets no UPDATE on the immutable receipts or audit.
-- Its narrowly pinned owner helpers retain the original row locks.

-- Observation ingress owns only its journal/management surfaces, never the
-- canonical application/evidence writer or Organization source authority.
GRANT USAGE ON SCHEMA organization_service,issuance_service TO feature_observation;
GRANT SELECT ON issuance_service.rust_schema_migrations,
    issuance_service.external_observation_producer_grants,issuance_service.external_observation_bindings,
    issuance_service.external_observation_grant_bindings,issuance_service.external_observation_receipts,
    issuance_service.external_observation_heads,issuance_service.external_observation_audit TO feature_observation;
GRANT SELECT(id,organization_id,applicant_identifier,status,updated_at,expires_at)
    ON issuance_service.applications TO feature_observation;
GRANT SELECT,INSERT ON organization_service.audit_events TO feature_observation;
GRANT INSERT ON issuance_service.external_observation_producer_grants,issuance_service.external_observation_bindings,
    issuance_service.external_observation_grant_bindings,issuance_service.external_observation_receipts,
    issuance_service.external_observation_heads,issuance_service.external_observation_audit TO feature_observation;
GRANT DELETE ON issuance_service.external_observation_grant_bindings TO feature_observation;
GRANT UPDATE(grant_id) ON issuance_service.external_observation_grant_bindings TO feature_observation;
GRANT UPDATE(active,api_key_id,expires_at,approved_by,approved_at,revision)
    ON issuance_service.external_observation_producer_grants TO feature_observation;
GRANT UPDATE(resource_scope,claim_rules,max_age_ms,max_clock_skew_ms,active,updated_by,revision)
    ON issuance_service.external_observation_bindings TO feature_observation;
GRANT UPDATE(sequence,receipt_id) ON issuance_service.external_observation_heads TO feature_observation;
GRANT EXECUTE ON FUNCTION issuance_service.external_observation_lock_organization(uuid),
    issuance_service.external_observation_lock_api_keys(uuid,uuid[]),
    issuance_service.external_observation_lock_application(text,text),
    issuance_service.external_observation_lock_administrator(uuid,text),
    issuance_service.external_observation_lock_receipt(text,text,text) TO feature_observation;

-- Association owns only its source/consent journal, never the canonical
-- ownership, observation binding, application or Organization authority.
GRANT USAGE ON SCHEMA organization_service,issuance_service TO feature_association;
GRANT SELECT ON issuance_service.rust_schema_migrations TO feature_association;
GRANT SELECT,INSERT ON issuance_service.external_association_sources,issuance_service.external_association_operations,
    issuance_service.external_association_challenges,issuance_service.external_association_identities,
    issuance_service.external_association_bindings TO feature_association;
GRANT UPDATE(api_key_id,key_revision,active,revision,expires_at,approved_by,approved_at,updated_at)
    ON issuance_service.external_association_sources TO feature_association;
GRANT UPDATE(phase,revision,updated_at) ON issuance_service.external_association_challenges TO feature_association;
GRANT UPDATE(active,consent_generation,revision,updated_at) ON issuance_service.external_association_identities TO feature_association;
GRANT UPDATE(binding_revision,challenge_id,active,revision,updated_at) ON issuance_service.external_association_bindings TO feature_association;
GRANT EXECUTE ON FUNCTION issuance_service.external_observation_lock_organization(uuid),
    issuance_service.external_observation_lock_api_keys(uuid,uuid[]),
    issuance_service.external_association_lock_administrator(uuid,text),
    issuance_service.mutate_external_association_source(uuid,text,uuid,uuid,text,bigint,jsonb),
    issuance_service.read_external_association_source(uuid,text,uuid,uuid),
    issuance_service.external_association_lock_context(uuid,uuid,uuid,bigint,text,bigint),
    issuance_service.create_external_association_challenge(uuid,uuid,uuid,uuid,uuid,bigint,text,bigint,text,bigint,text,bigint),
    issuance_service.mutate_external_association_consent(uuid,text,uuid,uuid,text,bigint,text,bigint),
    issuance_service.read_external_association_challenge(uuid,text,text,uuid,uuid),
    issuance_service.close_external_association_challenge(uuid,uuid,uuid,uuid,text,bigint),
    issuance_service.unlink_external_association(uuid,text,uuid,uuid,bigint),
    issuance_service.read_external_association_unlink_receipt(uuid,text,uuid,uuid) TO feature_association;
COMMIT;
