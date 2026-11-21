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
        &["delegation_grants", "command_results"],
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
        AND has_schema_privilege(current_user,'delegated_authority_service','USAGE')
        AND has_function_privilege(current_user,'delegated_authority_service.grant_instant(TEXT)','EXECUTE')")
        .fetch_one(writer).await.map_err(|_| ApprovalProducerError::NotReady)?;
    if !required || storage_identity(writer).await? != storage_identity(reader).await? {
        return Err(ApprovalProducerError::NotReady);
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
