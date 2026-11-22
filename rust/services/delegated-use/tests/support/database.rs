//! Fresh loopback databases and independently connected minimal LOGIN roles.
//! SQL identifiers below contain only fixed prefixes and generated UUID hex.
use std::collections::BTreeMap;

use marty_delegated_authority::PgDelegationGrantRepository;
use marty_delegated_use::{config::DatabaseUrls, database::DatabasePools};
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe, PgPool};
use uuid::Uuid;

use super::TestResult;

const EVIDENCE_READS: &str = "delegated_authority_service.schema_migrations,
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
    delegated_authority_service.approval_storage_identity";

const FLOW_READ_GRANTS: &str = "
    GRANT USAGE ON SCHEMA flow_service TO $ROLE;
    GRANT SELECT ON flow_service.rust_schema_versions,
        flow_service.delegated_use_storage_identity,
        flow_service.flow_definitions,flow_service.flow_instances,
        flow_service.delegated_challenge_bindings,
        flow_service.delegated_proof_submissions,
        flow_service.delegated_use_consumptions TO $ROLE;";

pub struct Database {
    pub admin: PgPool,
    pub pools: DatabasePools,
    pub urls: DatabaseUrls,
    pub runtime_reader: PgPool,
    pub organization_authority: PgPool,
    pub lifecycle_writer: PgPool,
    pub consent_writer: PgPool,
    pub authority_writer: PgPool,
    pub roles: BTreeMap<&'static str, String>,
    control: PgPool,
    admin_url: url::Url,
}

impl Database {
    pub async fn new() -> TestResult<Self> {
        let configured = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL")?;
        let base = url::Url::parse(&configured)?;
        assert!(matches!(
            base.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]")
        ));
        assert!(matches!(base.scheme(), "postgres" | "postgresql"));
        let control = PgPoolOptions::new()
            .max_connections(2)
            .connect(base.as_str())
            .await?;
        let name = format!("delegated_host_test_{}", Uuid::new_v4().simple());
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&control)
            .await?;
        let mut admin_url = base;
        admin_url.set_path(&name);
        let admin = PgPoolOptions::new()
            .max_connections(8)
            .connect(admin_url.as_str())
            .await?;
        Self::migrate(&admin).await?;

        let mut roles = BTreeMap::new();
        let mut urls = BTreeMap::new();
        for (purpose, grants) in grants() {
            let role = format!("du_test_{}", Uuid::new_v4().simple());
            sqlx::raw_sql(AssertSqlSafe(format!(
                "CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; {}",
                grants.replace("$ROLE", &role)
            )))
            .execute(&admin)
            .await?;
            let mut role_url = admin_url.clone();
            role_url
                .set_username(&role)
                .map_err(|_| "invalid generated role")?;
            urls.insert(purpose, role_url.to_string());
            roles.insert(purpose, role);
        }
        let urls = DatabaseUrls {
            use_writer: urls["use_writer"].clone(),
            runtime_reader: urls["runtime_reader"].clone(),
            organization_authority: urls["organization_authority"].clone(),
            registry_source: urls["registry_source"].clone(),
            access_source: urls["access_source"].clone(),
            machine_policy_source: urls["machine_policy_source"].clone(),
            machine_policy_evidence: urls["machine_policy_evidence"].clone(),
            delegation_policy_source: urls["delegation_policy_source"].clone(),
            machine_audit: urls["machine_audit"].clone(),
            flow_reader: urls["flow_reader"].clone(),
            flow_ingress: urls["flow_ingress"].clone(),
            credential_trust: urls["credential_trust"].clone(),
            credential_status: urls["credential_status"].clone(),
            credential_evidence: urls["credential_evidence"].clone(),
        };
        let pools = DatabasePools::connect(&urls).await?;
        let runtime_reader = pools.runtime_reader.clone();
        let organization_authority = pools.organization_authority.clone();
        let mut producer_pools = Vec::new();
        for (purpose, grants) in [
            (
                "lifecycle_writer",
                format!(
                    "GRANT USAGE ON SCHEMA delegated_authority_service TO $ROLE;
                     GRANT SELECT ON {EVIDENCE_READS} TO $ROLE;
                     GRANT INSERT,UPDATE ON delegated_authority_service.delegation_grants TO $ROLE;
                     GRANT INSERT ON delegated_authority_service.command_results TO $ROLE;
                     GRANT SELECT,INSERT ON delegated_authority_service.command_identities TO $ROLE;
                     GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(text) TO $ROLE;"
                ),
            ),
            (
                "consent_writer",
                "GRANT USAGE ON SCHEMA delegated_authority_service TO $ROLE;
                 GRANT SELECT ON delegated_authority_service.consent_confirmations,
                     delegated_authority_service.consent_withdrawals,
                     delegated_authority_service.approval_reviews,
                     delegated_authority_service.approval_confirmation_bindings,
                     delegated_authority_service.approval_storage_identity TO $ROLE;
                 GRANT INSERT ON delegated_authority_service.consent_confirmations,
                     delegated_authority_service.consent_withdrawals,
                     delegated_authority_service.approval_reviews,
                     delegated_authority_service.approval_confirmation_bindings TO $ROLE;
                 GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(text) TO $ROLE;"
                    .into(),
            ),
            (
                "authority_writer",
                "GRANT USAGE ON SCHEMA delegated_authority_service TO $ROLE;
                 GRANT SELECT ON delegated_authority_service.delegation_grants,
                     delegated_authority_service.representation_authority_sources,
                     delegated_authority_service.representation_authority_assertions,
                     delegated_authority_service.organization_authority_observations,
                     delegated_authority_service.approval_storage_identity TO $ROLE;
                 GRANT INSERT ON delegated_authority_service.representation_authority_sources,
                     delegated_authority_service.representation_authority_assertions,
                     delegated_authority_service.organization_authority_observations TO $ROLE;
                 GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(text) TO $ROLE;"
                    .into(),
            ),
        ] {
            let role = format!("du_producer_{}", Uuid::new_v4().simple());
            sqlx::raw_sql(AssertSqlSafe(format!(
                "CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; {}",
                grants.replace("$ROLE", &role)
            )))
            .execute(&admin)
            .await?;
            let pool = PgPoolOptions::new()
                .max_connections(3)
                .connect_with(admin.connect_options().as_ref().clone().username(&role))
                .await?;
            roles.insert(purpose, role);
            producer_pools.push(pool);
        }
        Ok(Self {
            admin,
            pools,
            urls,
            runtime_reader,
            organization_authority,
            lifecycle_writer: producer_pools.remove(0),
            consent_writer: producer_pools.remove(0),
            authority_writer: producer_pools.remove(0),
            roles,
            control,
            admin_url,
        })
    }

    async fn migrate(admin: &PgPool) -> TestResult<()> {
        sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
            .execute(admin)
            .await?;
        // No long-lived test advisory lock is held across any owner migration.
        marty_organization::migration::migrate_organization_schema(admin).await?;
        marty_credential_template::migration::migrate_credential_template_schema(admin).await?;
        marty_trust_profile::run_migrations(admin).await?;
        marty_issuance_service::migration::migrate_owned_schema(admin, Uuid::new_v4()).await?;
        marty_machine_credential_source::run_migrations(admin).await?;
        PgDelegationGrantRepository::new(admin.clone())
            .migrate()
            .await?;
        marty_flow::migrate_flow_schema(admin).await?;
        Ok(())
    }

    pub async fn sql(&self, query: String) -> TestResult<()> {
        sqlx::raw_sql(AssertSqlSafe(query))
            .execute(&self.admin)
            .await?;
        Ok(())
    }

    /// An otherwise valid separately migrated Flow store on the same cluster.
    /// Its distinct immutable storage identity must not join the ledger commit.
    pub async fn foreign_flow_reader(&self) -> TestResult<PgPool> {
        let name = format!("delegated_host_foreign_{}", Uuid::new_v4().simple());
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&self.control)
            .await?;
        let mut url = self.admin_url.clone();
        url.set_path(&name);
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(url.as_str())
            .await?;
        sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS pgcrypto")
            .execute(&admin)
            .await?;
        marty_flow::migrate_flow_schema(&admin).await?;
        let role = &self.roles["flow_reader"];
        sqlx::raw_sql(AssertSqlSafe(FLOW_READ_GRANTS.replace("$ROLE", role)))
            .execute(&admin)
            .await?;
        let reader = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(admin.connect_options().as_ref().clone().username(role))
            .await?;
        admin.close().await;
        Ok(reader)
    }

    /// A legitimately separate Issuance source. The status login's original
    /// table reads are removed so this test does not accidentally give it
    /// application authority in two different selected databases.
    pub async fn foreign_credential_status(&self) -> TestResult<(PgPool, PgPool)> {
        let name = format!("delegated_host_source_{}", Uuid::new_v4().simple());
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&self.control)
            .await?;
        let mut url = self.admin_url.clone();
        url.set_path(&name);
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(url.as_str())
            .await?;
        Self::migrate(&admin).await?;
        let role = &self.roles["credential_status"];
        sqlx::raw_sql(AssertSqlSafe(format!(
            "GRANT USAGE ON SCHEMA issuance_service TO {role};
             GRANT SELECT ON issuance_service.issued_credentials,issuance_service.issuance_transactions TO {role}"
        )))
        .execute(&admin)
        .await?;
        self.sql(format!(
            "REVOKE SELECT ON issuance_service.issued_credentials,issuance_service.issuance_transactions FROM {role}"
        )).await?;
        let status = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(admin.connect_options().as_ref().clone().username(role))
            .await?;
        Ok((admin, status))
    }

    pub async fn close(&self) {
        self.pools.close().await;
        self.lifecycle_writer.close().await;
        self.consent_writer.close().await;
        self.authority_writer.close().await;
        self.admin.close().await;
        self.control.close().await;
        // The enclosing explicitly disposable PostgreSQL fixture removes all
        // generated databases and roles when its process exits.
    }
}

fn grants() -> Vec<(&'static str, String)> {
    vec![
        (
            "use_writer",
            "GRANT USAGE ON SCHEMA delegated_authority_service,flow_service TO $ROLE;
             GRANT SELECT ON delegated_authority_service.schema_migrations,
                 delegated_authority_service.approval_storage_identity,
                 delegated_authority_service.delegation_grants,
                 delegated_authority_service.command_identities,
                 delegated_authority_service.use_command_claims,
                 delegated_authority_service.use_admissions,
                 delegated_authority_service.use_receipts,
                 delegated_authority_service.use_command_results,
                 delegated_authority_service.machine_authentication_evidence TO $ROLE;
             GRANT INSERT ON delegated_authority_service.command_identities,
                 delegated_authority_service.use_command_claims,
                 delegated_authority_service.use_admissions,
                 delegated_authority_service.use_receipts,
                 delegated_authority_service.use_command_results TO $ROLE;
             GRANT SELECT ON flow_service.rust_schema_versions,
                 flow_service.delegated_use_storage_identity,flow_service.flow_definitions,
                 flow_service.flow_instances,flow_service.delegated_challenge_bindings,
                 flow_service.delegated_proof_submissions,flow_service.delegated_use_consumptions TO $ROLE;
             GRANT INSERT ON flow_service.flow_instances,flow_service.delegated_challenge_bindings,
                 flow_service.delegated_use_consumptions TO $ROLE;
             GRANT UPDATE(status,current_step_id,completed_at,updated_at,result,state_history)
                 ON flow_service.flow_instances TO $ROLE;
             GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(text),
                 delegated_authority_service.lock_use_grant(uuid,uuid),
                 delegated_authority_service.lock_use_claim(uuid,text,text,uuid),
                 delegated_authority_service.lock_use_admission(uuid,text,text,uuid),
                 flow_service.lock_delegated_use_definition(text,text),
                 flow_service.lock_delegated_use_proof(uuid,uuid,uuid) TO $ROLE;"
                .into(),
        ),
        (
            "runtime_reader",
            format!(
                "GRANT USAGE ON SCHEMA delegated_authority_service TO $ROLE;
                 GRANT SELECT ON {EVIDENCE_READS} TO $ROLE;
                 GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(text) TO $ROLE;"
            ),
        ),
        (
            "organization_authority",
            "GRANT USAGE ON SCHEMA organization_service TO $ROLE;
             GRANT SELECT ON organization_service.organizations,organization_service.members,
                 organization_service.roles,organization_service.permissions,
                 organization_service.member_roles,organization_service.role_permissions TO $ROLE;"
                .into(),
        ),
        (
            "registry_source",
            "GRANT USAGE ON SCHEMA organization_service TO $ROLE;
             GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,
                 organization_service.machine_registry_entries,organization_service.machine_registry_history,
                 organization_service.machine_registry_observations TO $ROLE;
             GRANT INSERT ON organization_service.machine_registry_observations TO $ROLE;"
                .into(),
        ),
        (
            "access_source",
            "GRANT USAGE ON SCHEMA organization_service TO $ROLE;
             GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,
                 organization_service.machine_registry_entries,organization_service.machine_registry_history,
                 organization_service.machine_use_access,organization_service.machine_use_access_history TO $ROLE;"
                .into(),
        ),
        (
            "machine_policy_source",
            "GRANT USAGE ON SCHEMA organization_service TO $ROLE;
             GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,
                 organization_service.policy_sets,organization_service.machine_authorization_policy_history TO $ROLE;"
                .into(),
        ),
        (
            "machine_policy_evidence",
            "GRANT USAGE ON SCHEMA delegated_authority_service TO $ROLE;
             GRANT SELECT ON delegated_authority_service.schema_migrations,
                 delegated_authority_service.machine_authorization_evidence TO $ROLE;
             GRANT INSERT ON delegated_authority_service.machine_authorization_evidence TO $ROLE;"
                .into(),
        ),
        (
            "delegation_policy_source",
            "GRANT USAGE ON SCHEMA organization_service TO $ROLE;
             GRANT SELECT ON organization_service.rust_schema_versions,organization_service.organizations,
                 organization_service.delegation_use_policies,organization_service.delegation_use_policy_history,
                 organization_service.delegation_use_policy_observations TO $ROLE;
             GRANT INSERT ON organization_service.delegation_use_policy_observations TO $ROLE;"
                .into(),
        ),
        (
            "machine_audit",
            "GRANT USAGE ON SCHEMA delegated_authority_service TO $ROLE;
             GRANT SELECT ON delegated_authority_service.schema_migrations,
                 delegated_authority_service.machine_authentication_evidence,
                 delegated_authority_service.machine_authorization_evidence TO $ROLE;
             GRANT INSERT ON delegated_authority_service.machine_authentication_evidence TO $ROLE;"
                .into(),
        ),
        ("flow_reader", FLOW_READ_GRANTS.into()),
        (
            "flow_ingress",
            format!(
                "{FLOW_READ_GRANTS}
                 GRANT SELECT,INSERT ON flow_service.delegated_request_claims,
                     flow_service.delegated_request_results,flow_service.delegated_proof_ingress TO $ROLE;
                 GRANT INSERT ON flow_service.delegated_proof_submissions TO $ROLE;
                 GRANT UPDATE(current_step_id,context,step_history,state_history,updated_at)
                     ON flow_service.flow_instances TO $ROLE;
                 GRANT EXECUTE ON FUNCTION flow_service.lock_delegated_ingress_definition(uuid,uuid) TO $ROLE;"
            ),
        ),
        (
            "credential_trust",
            "GRANT USAGE ON SCHEMA trust_profile_service TO $ROLE;
             GRANT SELECT ON trust_profile_service.trust_profiles,trust_profile_service.issuer_entities,
                 trust_profile_service.trust_profile_issuers TO $ROLE;
             GRANT SELECT,INSERT,UPDATE ON trust_profile_service.machine_jwt_vc_authority_revisions TO $ROLE;"
                .into(),
        ),
        (
            "credential_status",
            "GRANT USAGE ON SCHEMA issuance_service TO $ROLE;
             GRANT SELECT ON issuance_service.issued_credentials,issuance_service.issuance_transactions TO $ROLE;"
                .into(),
        ),
        (
            "credential_evidence",
            "GRANT USAGE ON SCHEMA machine_credential_source TO $ROLE;
             GRANT SELECT ON machine_credential_source.schema_migrations,
                 machine_credential_source.observations TO $ROLE;
             GRANT INSERT ON machine_credential_source.observations TO $ROLE;"
                .into(),
        ),
    ]
}
