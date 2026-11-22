//! Bounded startup/readiness checks for three actual connected command roles.
use crate::{
    approval_postgres::{
        check_role, check_role_boundary, check_role_boundary_mutations, role_identity,
        storage_identity, EVIDENCE_READ_TABLES,
    },
    ApprovalProducerError,
};
use sqlx::PgPool;

pub(crate) async fn check_command_roles(
    writer: &PgPool,
    reader: &PgPool,
    organization: &PgPool,
) -> Result<(), ApprovalProducerError> {
    let read_role = check_role(
        reader,
        "delegated_authority_service",
        &[],
        &EVIDENCE_READ_TABLES,
    )
    .await?;
    let organization_role = check_role(
        organization,
        "organization_service",
        &[],
        &[
            "organizations",
            "members",
            "roles",
            "permissions",
            "member_roles",
            "role_permissions",
        ],
    )
    .await?;
    let writer_role = role_identity(writer).await?;
    if writer_role == read_role
        || writer_role == organization_role
        || read_role == organization_role
    {
        return Err(ApprovalProducerError::NotReady);
    }
    check_role_boundary_mutations(
        writer,
        "delegated_authority_service",
        &writer_role,
        &["delegation_grants", "command_results", "command_identities"],
        &["delegation_grants"],
    )
    .await?;
    for table in EVIDENCE_READ_TABLES {
        let select: bool = sqlx::query_scalar("SELECT has_table_privilege(current_user,format('delegated_authority_service.%I',$1::TEXT),'SELECT')")
            .bind(table).fetch_one(writer).await.map_err(|_| ApprovalProducerError::NotReady)?;
        if !select {
            return Err(ApprovalProducerError::NotReady);
        }
    }
    let required: bool = sqlx::query_scalar("SELECT
        has_table_privilege(current_user,'delegated_authority_service.delegation_grants','INSERT')
        AND has_table_privilege(current_user,'delegated_authority_service.delegation_grants','UPDATE')
        AND has_table_privilege(current_user,'delegated_authority_service.command_results','INSERT')
        AND has_table_privilege(current_user,'delegated_authority_service.command_identities','SELECT')
        AND has_table_privilege(current_user,'delegated_authority_service.command_identities','INSERT')
        AND has_schema_privilege(current_user,'delegated_authority_service','USAGE')
        AND has_function_privilege(current_user,'delegated_authority_service.grant_instant(TEXT)','EXECUTE')")
        .fetch_one(writer).await.map_err(|_| ApprovalProducerError::NotReady)?;
    if !required || storage_identity(writer).await? != storage_identity(reader).await? {
        return Err(ApprovalProducerError::NotReady);
    }
    // Lifecycle/evidence identities must not gain retained use proof/receipt
    // visibility through direct, inherited or SET ROLE membership. The shared
    // identity registry is the sole new lifecycle serving privilege.
    for role in [&writer_role, &read_role] {
        let reads_use: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_roles r CROSS JOIN pg_class t
             JOIN pg_namespace n ON n.oid=t.relnamespace
             WHERE n.nspname='delegated_authority_service'
               AND t.relname IN ('use_command_claims','use_admissions','use_receipts','use_command_results','machine_authentication_evidence')
               AND (r.rolname=$1 OR pg_has_role($1::TEXT,r.oid,'MEMBER'))
               AND (has_table_privilege(r.oid,t.oid,'SELECT') OR has_any_column_privilege(r.oid,t.oid,'SELECT')))",
        )
        .bind(role)
        .fetch_one(writer)
        .await
        .map_err(|_| ApprovalProducerError::NotReady)?;
        if reads_use {
            return Err(ApprovalProducerError::NotReady);
        }
    }
    for role in [&writer_role, &read_role] {
        check_role_boundary(organization, "organization_service", role, &[]).await?;
    }
    check_role_boundary(
        reader,
        "delegated_authority_service",
        &organization_role,
        &[],
    )
    .await?;
    Ok(())
}
