//! Actual restricted-login and cross-owner database checks for one serving host.
//! Configuration strings never establish role separation or a storage identity.
use crate::config::DatabaseUrls;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::Duration,
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("delegated use database boundary is unavailable: {0}")]
pub struct DatabaseBoundaryError(pub &'static str);
type Result<T> = std::result::Result<T, DatabaseBoundaryError>;

#[derive(Clone, Copy, Debug)]
pub struct DatabaseRoleContract {
    pub name: &'static str,
    pub select: &'static [&'static str],
    pub insert: &'static [&'static str],
    pub update: &'static [&'static str],
    pub column_updates: &'static [&'static str],
    pub functions: &'static [&'static str],
}

pub const ROLE_CONTRACTS: &[DatabaseRoleContract] = &[
    DatabaseRoleContract {
        name: "use_writer",
        select: &[
            "delegated_authority_service.schema_migrations",
            "delegated_authority_service.approval_storage_identity",
            "delegated_authority_service.delegation_grants",
            "delegated_authority_service.command_identities",
            "delegated_authority_service.use_command_claims",
            "delegated_authority_service.use_admissions",
            "delegated_authority_service.use_receipts",
            "delegated_authority_service.use_command_results",
            "delegated_authority_service.machine_authentication_evidence",
            "flow_service.rust_schema_versions",
            "flow_service.delegated_use_storage_identity",
            "flow_service.flow_definitions",
            "flow_service.flow_instances",
            "flow_service.delegated_challenge_bindings",
            "flow_service.delegated_proof_submissions",
            "flow_service.delegated_use_consumptions",
        ],
        insert: &[
            "delegated_authority_service.command_identities",
            "delegated_authority_service.use_command_claims",
            "delegated_authority_service.use_admissions",
            "delegated_authority_service.use_receipts",
            "delegated_authority_service.use_command_results",
            "flow_service.flow_instances",
            "flow_service.delegated_challenge_bindings",
            "flow_service.delegated_use_consumptions",
        ],
        update: &[],
        column_updates: &[
            "flow_service.flow_instances.status",
            "flow_service.flow_instances.current_step_id",
            "flow_service.flow_instances.completed_at",
            "flow_service.flow_instances.updated_at",
            "flow_service.flow_instances.result",
            "flow_service.flow_instances.state_history",
        ],
        functions: &[
            "delegated_authority_service.grant_instant(text)",
            "delegated_authority_service.lock_use_grant(uuid,uuid)",
            "delegated_authority_service.lock_use_claim(uuid,text,text,uuid)",
            "delegated_authority_service.lock_use_admission(uuid,text,text,uuid)",
            "flow_service.lock_delegated_use_definition(text,text)",
            "flow_service.lock_delegated_use_proof(uuid,uuid,uuid)",
        ],
    },
    DatabaseRoleContract {
        name: "runtime_reader",
        select: &[
            "delegated_authority_service.schema_migrations",
            "delegated_authority_service.delegation_grants",
            "delegated_authority_service.grant_lifecycle_events",
            "delegated_authority_service.consent_confirmations",
            "delegated_authority_service.consent_withdrawals",
            "delegated_authority_service.representation_authority_sources",
            "delegated_authority_service.representation_authority_assertions",
            "delegated_authority_service.command_results",
            "delegated_authority_service.approval_reviews",
            "delegated_authority_service.approval_confirmation_bindings",
            "delegated_authority_service.organization_authority_observations",
            "delegated_authority_service.approval_storage_identity",
        ],
        insert: &[],
        update: &[],
        column_updates: &[],
        functions: &["delegated_authority_service.grant_instant(text)"],
    },
    DatabaseRoleContract {
        name: "organization_authority",
        select: &[
            "organization_service.organizations",
            "organization_service.members",
            "organization_service.roles",
            "organization_service.permissions",
            "organization_service.member_roles",
            "organization_service.role_permissions",
        ],
        insert: &[],
        update: &[],
        column_updates: &[],
        functions: &[],
    },
    DatabaseRoleContract {
        name: "registry_source",
        select: &[
            "organization_service.rust_schema_versions",
            "organization_service.organizations",
            "organization_service.machine_registry_entries",
            "organization_service.machine_registry_history",
            "organization_service.machine_registry_observations",
        ],
        insert: &["organization_service.machine_registry_observations"],
        update: &[],
        column_updates: &[],
        functions: &[],
    },
    DatabaseRoleContract {
        name: "access_source",
        select: &[
            "organization_service.rust_schema_versions",
            "organization_service.organizations",
            "organization_service.machine_registry_entries",
            "organization_service.machine_registry_history",
            "organization_service.machine_use_access",
            "organization_service.machine_use_access_history",
        ],
        insert: &[],
        update: &[],
        column_updates: &[],
        functions: &[],
    },
    DatabaseRoleContract {
        name: "machine_policy_source",
        select: &[
            "organization_service.rust_schema_versions",
            "organization_service.organizations",
            "organization_service.policy_sets",
            "organization_service.machine_authorization_policy_history",
        ],
        insert: &[],
        update: &[],
        column_updates: &[],
        functions: &[],
    },
    DatabaseRoleContract {
        name: "machine_policy_evidence",
        select: &[
            "delegated_authority_service.schema_migrations",
            "delegated_authority_service.machine_authorization_evidence",
        ],
        insert: &["delegated_authority_service.machine_authorization_evidence"],
        update: &[],
        column_updates: &[],
        functions: &[],
    },
    DatabaseRoleContract {
        name: "delegation_policy_source",
        select: &[
            "organization_service.rust_schema_versions",
            "organization_service.organizations",
            "organization_service.delegation_use_policies",
            "organization_service.delegation_use_policy_history",
            "organization_service.delegation_use_policy_observations",
        ],
        insert: &["organization_service.delegation_use_policy_observations"],
        update: &[],
        column_updates: &[],
        functions: &[],
    },
    DatabaseRoleContract {
        name: "machine_audit",
        select: &[
            "delegated_authority_service.schema_migrations",
            "delegated_authority_service.machine_authentication_evidence",
            "delegated_authority_service.machine_authorization_evidence",
        ],
        insert: &["delegated_authority_service.machine_authentication_evidence"],
        update: &[],
        column_updates: &[],
        functions: &[],
    },
    DatabaseRoleContract {
        name: "flow_reader",
        select: &[
            "flow_service.rust_schema_versions",
            "flow_service.delegated_use_storage_identity",
            "flow_service.flow_definitions",
            "flow_service.flow_instances",
            "flow_service.delegated_challenge_bindings",
            "flow_service.delegated_proof_submissions",
            "flow_service.delegated_use_consumptions",
        ],
        insert: &[],
        update: &[],
        column_updates: &[],
        functions: &[],
    },
    DatabaseRoleContract {
        name: "flow_ingress",
        select: &[
            "flow_service.rust_schema_versions",
            "flow_service.delegated_use_storage_identity",
            "flow_service.flow_definitions",
            "flow_service.flow_instances",
            "flow_service.delegated_challenge_bindings",
            "flow_service.delegated_proof_submissions",
            "flow_service.delegated_use_consumptions",
            "flow_service.delegated_request_claims",
            "flow_service.delegated_request_results",
            "flow_service.delegated_proof_ingress",
        ],
        insert: &[
            "flow_service.delegated_proof_submissions",
            "flow_service.delegated_request_claims",
            "flow_service.delegated_request_results",
            "flow_service.delegated_proof_ingress",
        ],
        update: &[],
        column_updates: &[
            "flow_service.flow_instances.current_step_id",
            "flow_service.flow_instances.context",
            "flow_service.flow_instances.step_history",
            "flow_service.flow_instances.state_history",
            "flow_service.flow_instances.updated_at",
        ],
        functions: &["flow_service.lock_delegated_ingress_definition(uuid,uuid)"],
    },
    DatabaseRoleContract {
        name: "credential_trust",
        select: &[
            "trust_profile_service.trust_profiles",
            "trust_profile_service.issuer_entities",
            "trust_profile_service.trust_profile_issuers",
            "trust_profile_service.machine_jwt_vc_authority_revisions",
        ],
        insert: &["trust_profile_service.machine_jwt_vc_authority_revisions"],
        update: &["trust_profile_service.machine_jwt_vc_authority_revisions"],
        column_updates: &[],
        functions: &[],
    },
    DatabaseRoleContract {
        name: "credential_status",
        select: &[
            "issuance_service.issued_credentials",
            "issuance_service.issuance_transactions",
        ],
        insert: &[],
        update: &[],
        column_updates: &[],
        functions: &[],
    },
    DatabaseRoleContract {
        name: "credential_evidence",
        select: &[
            "machine_credential_source.schema_migrations",
            "machine_credential_source.observations",
        ],
        insert: &["machine_credential_source.observations"],
        update: &[],
        column_updates: &[],
        functions: &[],
    },
];

#[derive(Clone)]
pub struct DatabasePools {
    pub use_writer: PgPool,
    pub runtime_reader: PgPool,
    pub organization_authority: PgPool,
    pub registry_source: PgPool,
    pub access_source: PgPool,
    pub machine_policy_source: PgPool,
    pub machine_policy_evidence: PgPool,
    pub delegation_policy_source: PgPool,
    pub machine_audit: PgPool,
    pub flow_reader: PgPool,
    pub flow_ingress: PgPool,
    pub credential_trust: PgPool,
    pub credential_status: PgPool,
    pub credential_evidence: PgPool,
}

impl fmt::Debug for DatabasePools {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DatabasePools { <restricted connections> }")
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct StorageIdentity {
    database: String,
    database_oid: i64,
    address: Option<String>,
    port: Option<i32>,
}

impl DatabasePools {
    pub async fn connect(urls: &DatabaseUrls) -> Result<Self> {
        Self::connect_with_limit(urls, 4).await
    }

    pub(crate) async fn connect_with_limit(urls: &DatabaseUrls, maximum: u32) -> Result<Self> {
        Ok(Self {
            use_writer: connect(&urls.use_writer, maximum).await?,
            runtime_reader: connect(&urls.runtime_reader, maximum).await?,
            organization_authority: connect(&urls.organization_authority, maximum).await?,
            registry_source: connect(&urls.registry_source, maximum).await?,
            access_source: connect(&urls.access_source, maximum).await?,
            machine_policy_source: connect(&urls.machine_policy_source, maximum).await?,
            machine_policy_evidence: connect(&urls.machine_policy_evidence, maximum).await?,
            delegation_policy_source: connect(&urls.delegation_policy_source, maximum).await?,
            machine_audit: connect(&urls.machine_audit, maximum).await?,
            flow_reader: connect(&urls.flow_reader, maximum).await?,
            flow_ingress: connect(&urls.flow_ingress, maximum).await?,
            credential_trust: connect(&urls.credential_trust, maximum).await?,
            credential_status: connect(&urls.credential_status, maximum).await?,
            credential_evidence: connect(&urls.credential_evidence, maximum).await?,
        })
    }
    pub fn entries(&self) -> [(&'static DatabaseRoleContract, &PgPool); 14] {
        [
            (&ROLE_CONTRACTS[0], &self.use_writer),
            (&ROLE_CONTRACTS[1], &self.runtime_reader),
            (&ROLE_CONTRACTS[2], &self.organization_authority),
            (&ROLE_CONTRACTS[3], &self.registry_source),
            (&ROLE_CONTRACTS[4], &self.access_source),
            (&ROLE_CONTRACTS[5], &self.machine_policy_source),
            (&ROLE_CONTRACTS[6], &self.machine_policy_evidence),
            (&ROLE_CONTRACTS[7], &self.delegation_policy_source),
            (&ROLE_CONTRACTS[8], &self.machine_audit),
            (&ROLE_CONTRACTS[9], &self.flow_reader),
            (&ROLE_CONTRACTS[10], &self.flow_ingress),
            (&ROLE_CONTRACTS[11], &self.credential_trust),
            (&ROLE_CONTRACTS[12], &self.credential_status),
            (&ROLE_CONTRACTS[13], &self.credential_evidence),
        ]
    }
    pub async fn close(&self) {
        for (_, pool) in self.entries() {
            pool.close().await;
        }
    }
    pub async fn readiness(&self) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), self.check())
            .await
            .map_err(|_| DatabaseBoundaryError("readiness timeout"))?
    }
    async fn check(&self) -> Result<()> {
        let entries = self.entries();
        let mut identities = Vec::with_capacity(entries.len());
        let mut names = Vec::with_capacity(entries.len());
        for (contract, pool) in entries {
            let row = sqlx::query("SELECT current_user::TEXT AS role, current_database() AS database, d.oid::BIGINT AS database_oid, inet_server_addr()::TEXT AS address, inet_server_port() AS port FROM pg_database d WHERE d.datname=current_database() AND current_user=session_user AND current_setting('session_replication_role')='origin' AND NOT pg_is_in_recovery()")
                .fetch_optional(pool).await.map_err(|_| DatabaseBoundaryError(contract.name))?
                .ok_or(DatabaseBoundaryError(contract.name))?;
            let name: String = row
                .try_get("role")
                .map_err(|_| DatabaseBoundaryError(contract.name))?;
            if names.contains(&name) {
                return Err(DatabaseBoundaryError(
                    "distinct authenticated roles required",
                ));
            }
            validate_required(pool, contract).await?;
            names.push(name);
            identities.push(StorageIdentity {
                database: row
                    .try_get("database")
                    .map_err(|_| DatabaseBoundaryError(contract.name))?,
                database_oid: row
                    .try_get("database_oid")
                    .map_err(|_| DatabaseBoundaryError(contract.name))?,
                address: row
                    .try_get("address")
                    .map_err(|_| DatabaseBoundaryError(contract.name))?,
                port: row
                    .try_get("port")
                    .map_err(|_| DatabaseBoundaryError(contract.name))?,
            });
        }
        // The use transaction, Flow owner, source/evaluation linkage and audit
        // must reach the same actual writable database. Organization sources
        // also share their actual owner, not merely a tenant UUID in two stores.
        for group in [&[0usize, 1, 6, 8, 9, 10][..], &[2usize, 3, 4, 5, 7][..]] {
            if group.iter().any(|&i| identities[i] != identities[group[0]]) {
                return Err(DatabaseBoundaryError("owner database mismatch"));
            }
        }
        let da_identity: Uuid = sqlx::query_scalar("SELECT instance_id FROM delegated_authority_service.approval_storage_identity WHERE singleton")
            .fetch_one(&self.use_writer).await.map_err(|_| DatabaseBoundaryError("grant storage identity"))?;
        let da_read: Uuid = sqlx::query_scalar("SELECT instance_id FROM delegated_authority_service.approval_storage_identity WHERE singleton")
            .fetch_one(&self.runtime_reader).await.map_err(|_| DatabaseBoundaryError("grant storage identity"))?;
        if da_identity != da_read {
            return Err(DatabaseBoundaryError("grant storage identity mismatch"));
        }
        let mut flow_identity = None;
        for pool in [&self.use_writer, &self.flow_reader, &self.flow_ingress] {
            let identity: Uuid = sqlx::query_scalar("SELECT storage_id FROM flow_service.delegated_use_storage_identity WHERE singleton")
                .fetch_one(pool).await.map_err(|_| DatabaseBoundaryError("Flow storage identity"))?;
            if flow_identity.is_some_and(|previous| previous != identity) {
                return Err(DatabaseBoundaryError("Flow storage identity mismatch"));
            }
            flow_identity = Some(identity);
        }
        // PostgreSQL roles are cluster-wide. Audit every configured login in
        // each selected database where it exists, including NOINHERIT/SET ROLE
        // paths. A different URL alone does not isolate source mutation rights.
        let mut representatives = BTreeMap::new();
        for (i, identity) in identities.iter().enumerate() {
            representatives.entry(identity.clone()).or_insert(i);
        }
        for &index in representatives.values() {
            for (role_index, (contract, _)) in entries.iter().enumerate() {
                // A name is allowed only in that role's actual selected owner
                // database. A same-named table or SECURITY DEFINER function in
                // another connected source database is not the verified owner.
                let foreign_database = DatabaseRoleContract {
                    name: contract.name,
                    select: &[],
                    insert: &[],
                    update: &[],
                    column_updates: &[],
                    functions: &[],
                };
                let scoped_contract = if identities[index] == identities[role_index] {
                    *contract
                } else {
                    &foreign_database
                };
                validate_boundary(entries[index].1, &names[role_index], scoped_contract).await?;
            }
        }
        Ok(())
    }
}

async fn connect(url: &str, maximum: u32) -> Result<PgPool> {
    tokio::time::timeout(
        Duration::from_secs(5),
        PgPoolOptions::new()
            .max_connections(maximum)
            .acquire_timeout(Duration::from_secs(5))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    // Reject unsafe login/database defaults as well as ACLs.
                    // Every new pooled connection must execute ordinary guards.
                    let guards_enabled: bool = sqlx::query_scalar(
                        "SELECT current_user=session_user AND current_setting('session_replication_role')='origin'",
                    )
                    .fetch_one(&mut *connection)
                    .await?;
                    if !guards_enabled {
                        return Err(sqlx::Error::Protocol(
                            "delegated use connection settings unavailable".into(),
                        ));
                    }
                    sqlx::raw_sql(
                        "SET statement_timeout='5s'; SET lock_timeout='3s'; SET TIME ZONE 'UTC';",
                    )
                    .execute(connection)
                    .await?;
                    Ok(())
                })
            })
            .connect(url),
    )
    .await
    .map_err(|_| DatabaseBoundaryError("connection timeout"))?
    .map_err(|_| DatabaseBoundaryError("connection failed"))
}

async fn validate_required(pool: &PgPool, contract: &DatabaseRoleContract) -> Result<()> {
    let schemas = contract
        .select
        .iter()
        .chain(contract.insert.iter())
        .map(|name| name.split('.').next().unwrap_or_default())
        .collect::<BTreeSet<_>>();
    for schema in schemas {
        let valid: bool = sqlx::query_scalar(
            "SELECT coalesce(has_schema_privilege(current_user,to_regnamespace($1),'USAGE'),false)",
        )
        .bind(schema)
        .fetch_one(pool)
        .await
        .map_err(|_| DatabaseBoundaryError(contract.name))?;
        if !valid {
            return Err(DatabaseBoundaryError(contract.name));
        }
    }
    for (tables, privilege) in [
        (contract.select, "SELECT"),
        (contract.insert, "INSERT"),
        (contract.update, "UPDATE"),
    ] {
        for table in tables {
            let valid: bool = sqlx::query_scalar("SELECT coalesce(has_table_privilege(current_user,to_regclass($1),$2),false) AND NOT coalesce((SELECT relrowsecurity OR relforcerowsecurity FROM pg_class WHERE oid=to_regclass($1)),true)")
                .bind(table).bind(privilege).fetch_one(pool).await.map_err(|_| DatabaseBoundaryError(contract.name))?;
            if !valid {
                return Err(DatabaseBoundaryError(contract.name));
            }
        }
    }
    for column in contract.column_updates {
        let valid: bool = sqlx::query_scalar("SELECT coalesce(has_column_privilege(current_user,to_regclass(split_part($1,'.',1)||'.'||split_part($1,'.',2)),split_part($1,'.',3),'UPDATE'),false)")
            .bind(column).fetch_one(pool).await.map_err(|_| DatabaseBoundaryError(contract.name))?;
        if !valid {
            return Err(DatabaseBoundaryError(contract.name));
        }
    }
    for function in contract.functions {
        let valid: bool = sqlx::query_scalar("SELECT coalesce(has_function_privilege(current_user,to_regprocedure($1),'EXECUTE'),false)")
            .bind(function).fetch_one(pool).await.map_err(|_| DatabaseBoundaryError(contract.name))?;
        if !valid {
            return Err(DatabaseBoundaryError(contract.name));
        }
    }
    Ok(())
}

async fn validate_boundary(
    pool: &PgPool,
    role: &str,
    contract: &DatabaseRoleContract,
) -> Result<()> {
    let excessive: bool = sqlx::query_scalar("SELECT EXISTS(
      SELECT 1 FROM pg_roles subject JOIN pg_roles r ON (r.oid=subject.oid OR pg_has_role(subject.oid,r.oid,'MEMBER'))
      WHERE subject.rolname=$1 AND (
        r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls OR left(r.rolname::TEXT,3)='pg_'
        OR EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid AND m.admin_option)
        OR EXISTS(SELECT 1 FROM pg_parameter_acl parameter LEFT JOIN pg_settings setting ON setting.name=parameter.parname
            WHERE has_parameter_privilege(r.oid,parameter.parname,'ALTER SYSTEM,SET WITH GRANT OPTION,ALTER SYSTEM WITH GRANT OPTION')
            OR (NOT coalesce(setting.context='user',false) AND has_parameter_privilege(r.oid,parameter.parname,'SET')))
        OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND d.datdba=r.oid)
        OR has_database_privilege(r.oid,current_database(),'CREATE,CREATE WITH GRANT OPTION,CONNECT WITH GRANT OPTION,TEMPORARY WITH GRANT OPTION')
        OR EXISTS(SELECT 1 FROM pg_namespace n WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema'
            AND (n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE,CREATE WITH GRANT OPTION,USAGE WITH GRANT OPTION')))
        OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
          WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema' AND t.relkind IN('r','p','v','m','f','S') AND (
            t.relowner=r.oid
            OR has_table_privilege(r.oid,t.oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,DELETE WITH GRANT OPTION,TRUNCATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION,TRIGGER WITH GRANT OPTION')
            OR CASE WHEN current_setting('server_version_num')::INT>=170000 THEN has_table_privilege(r.oid,t.oid,'MAINTAIN') ELSE false END
            OR has_any_column_privilege(r.oid,t.oid,'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION')
            OR ((has_table_privilege(r.oid,t.oid,'SELECT') OR has_any_column_privilege(r.oid,t.oid,'SELECT')) AND NOT((n.nspname||'.'||t.relname)=ANY($2::TEXT[])))
            OR ((has_table_privilege(r.oid,t.oid,'INSERT') OR has_any_column_privilege(r.oid,t.oid,'INSERT')) AND NOT((n.nspname||'.'||t.relname)=ANY($3::TEXT[])))
            OR (has_table_privilege(r.oid,t.oid,'UPDATE') AND NOT((n.nspname||'.'||t.relname)=ANY($4::TEXT[])))
            OR (NOT((n.nspname||'.'||t.relname)=ANY($4::TEXT[])) AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
                AND has_column_privilege(r.oid,t.oid,a.attnum,'UPDATE') AND NOT((n.nspname||'.'||t.relname||'.'||a.attname)=ANY($5::TEXT[]))))))
        OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema' AND (
            p.proowner=r.oid OR has_function_privilege(r.oid,p.oid,'EXECUTE WITH GRANT OPTION')
            OR (p.prosecdef AND has_function_privilege(r.oid,p.oid,'EXECUTE') AND NOT coalesce(p.oid=ANY(ARRAY(SELECT to_regprocedure(f)::OID FROM unnest($6::TEXT[]) f)),false))))))")
        .bind(role).bind(contract.select).bind(contract.insert).bind(contract.update).bind(contract.column_updates).bind(contract.functions)
        .fetch_one(pool).await.map_err(|_| DatabaseBoundaryError(contract.name))?;
    if excessive {
        return Err(DatabaseBoundaryError(contract.name));
    }
    Ok(())
}
