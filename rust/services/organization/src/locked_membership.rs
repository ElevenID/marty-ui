use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{postgres::PostgresOrganizationStore, Member};

pub(crate) enum Error {
    MemberRead,
    RoleLock(sqlx::Error),
}

/// Lock the member, role and permission rows used by an organization write.
/// Reload after any lock wait so the decision uses the current membership.
pub(crate) async fn load(
    store: &PostgresOrganizationStore,
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    organization_id: Uuid,
) -> Result<Option<Member>, Error> {
    let Some(member) = store
        .member_by_user_and_organization_for_update_in_transaction(tx, user_id, organization_id)
        .await
        .map_err(|_| Error::MemberRead)?
    else {
        return Ok(None);
    };
    sqlx::query(
        "SELECT r.id FROM organization_service.member_roles mr
         JOIN organization_service.roles r ON r.id=mr.role_id
         WHERE mr.member_id=$1 AND r.organization_id=$2 ORDER BY r.id FOR SHARE OF mr,r",
    )
    .bind(member.id)
    .bind(organization_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(Error::RoleLock)?;
    sqlx::query(
        "SELECT p.id FROM organization_service.member_roles mr
         JOIN organization_service.roles r ON r.id=mr.role_id
         JOIN organization_service.role_permissions rp ON rp.role_id=r.id
         JOIN organization_service.permissions p ON p.id=rp.permission_id
         WHERE mr.member_id=$1 AND r.organization_id=$2 ORDER BY p.id FOR SHARE OF rp,p",
    )
    .bind(member.id)
    .bind(organization_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(Error::RoleLock)?;
    let member = store
        .member_by_user_and_organization_for_update_in_transaction(tx, user_id, organization_id)
        .await
        .map_err(|_| Error::MemberRead)?;
    Ok(member.filter(|member| {
        member
            .roles
            .iter()
            .all(|role| role.organization_id == organization_id)
    }))
}
