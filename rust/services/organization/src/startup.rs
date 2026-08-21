use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    catalog::{seed_system_roles, SeedError},
    postgres::{PostgresOrganizationStore, RepositoryError},
    Member, MemberStatus, Role,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OrganizationStartupReport {
    pub organizations_reconciled: usize,
    pub bootstrap_memberships_reconciled: usize,
}

#[derive(Debug, Error)]
pub enum OrganizationStartupError {
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    Seed(#[from] SeedError),
    #[error("ORGANIZATION.STARTUP_ROLE_MISSING: {0}")]
    MissingRole(String),
}

pub async fn reconcile_organization_startup(
    store: &PostgresOrganizationStore,
    marty_organization_id: Uuid,
    admin_email: Option<&str>,
    reviewer_email: Option<&str>,
    now: DateTime<Utc>,
) -> Result<OrganizationStartupReport, OrganizationStartupError> {
    let mut report = OrganizationStartupReport::default();
    let mut offset = 0_u32;
    loop {
        let organizations = store.list_organizations(1_000, offset).await?;
        if organizations.is_empty() {
            break;
        }
        for organization in &organizations {
            seed_system_roles(store, organization.id, now).await?;
            report.organizations_reconciled += 1;
        }
        offset = offset.saturating_add(u32::try_from(organizations.len()).unwrap_or(u32::MAX));
        if organizations.len() < 1_000 {
            break;
        }
    }

    for (email, role_name) in [(admin_email, "admin"), (reviewer_email, "reviewer")] {
        if let Some(email) = email.map(str::trim).filter(|email| !email.is_empty()) {
            ensure_bootstrap_membership(store, marty_organization_id, email, role_name, now)
                .await?;
            report.bootstrap_memberships_reconciled += 1;
        }
    }
    Ok(report)
}

async fn ensure_bootstrap_membership(
    store: &PostgresOrganizationStore,
    organization_id: Uuid,
    email: &str,
    role_name: &str,
    now: DateTime<Utc>,
) -> Result<(), OrganizationStartupError> {
    let role = store
        .role_by_name(organization_id, role_name)
        .await?
        .ok_or_else(|| OrganizationStartupError::MissingRole(role_name.into()))?;
    let mut member = match store
        .member_by_email_and_organization(email, organization_id)
        .await?
    {
        Some(member) => member,
        None => {
            let member = Member::create(
                organization_id,
                "",
                Some(email.to_ascii_lowercase()),
                MemberStatus::Active,
                now,
            );
            store.save_member(&member).await?;
            member
        }
    };
    let role_ids = bootstrap_role_ids(&member.roles, &role);
    if role_ids.contains(&role.id)
        && role_ids.len() == member.roles.len()
        && member
            .roles
            .iter()
            .all(|existing| role_ids.contains(&existing.id))
    {
        return Ok(());
    }
    store.set_member_roles(member.id, &role_ids).await?;
    member.roles = store.roles_for_member(member.id).await?;
    member.updated_at = now;
    store.save_member(&member).await?;
    Ok(())
}

#[must_use]
pub fn bootstrap_role_ids(existing: &[Role], target: &Role) -> Vec<Uuid> {
    if existing.iter().any(|role| role.id == target.id) {
        return existing.iter().map(|role| role.id).collect();
    }
    if existing.is_empty() || existing.iter().all(|role| role.name == "applicant") {
        return vec![target.id];
    }
    let mut roles = existing.iter().map(|role| role.id).collect::<Vec<_>>();
    roles.push(target.id);
    roles
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(name: &str) -> Role {
        Role {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            name: name.into(),
            display_name: None,
            description: None,
            is_system: true,
            is_default_for_new_members: name == "applicant",
            permissions: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn bootstrap_role_port_preserves_replace_append_and_idempotent_behavior() {
        let applicant = role("applicant");
        let viewer = role("viewer");
        let admin = role("admin");
        assert_eq!(bootstrap_role_ids(&[], &admin), [admin.id]);
        assert_eq!(
            bootstrap_role_ids(std::slice::from_ref(&applicant), &admin),
            [admin.id]
        );
        assert_eq!(
            bootstrap_role_ids(std::slice::from_ref(&viewer), &admin),
            [viewer.id, admin.id]
        );
        assert_eq!(
            bootstrap_role_ids(&[viewer.clone(), admin.clone()], &admin),
            [viewer.id, admin.id]
        );
    }
}
