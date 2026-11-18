use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::application::{OrganizationApplication, OrganizationApplicationError};
use crate::domain::{ConsoleContextPreference, ViewMode};
use crate::postgres::RepositoryError;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateConsolePreferencePatch {
    pub last_view_mode: Option<ViewMode>,
    pub last_active_organization_id: Option<Option<Uuid>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateConsolePreferenceCommand {
    pub user_id: String,
    pub patch: UpdateConsolePreferencePatch,
    pub now: DateTime<Utc>,
}

impl OrganizationApplication {
    pub async fn get_console_preferences(
        &self,
        user_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ConsoleContextPreference, OrganizationApplicationError> {
        require_user_id(user_id)?;
        Ok(self
            .store
            .preference_by_user(user_id)
            .await?
            .unwrap_or_else(|| default_preference(user_id, now)))
    }

    pub async fn update_console_preferences(
        &self,
        command: UpdateConsolePreferenceCommand,
    ) -> Result<ConsoleContextPreference, OrganizationApplicationError> {
        require_user_id(&command.user_id)?;
        let mut transaction = self.store.begin_transaction().await?;
        let preference = self
            .store
            .preference_by_user_for_update_in_transaction(&mut transaction, &command.user_id)
            .await?
            .unwrap_or_else(|| default_preference(&command.user_id, command.now));
        let preference = apply_console_preference_patch(&preference, &command.patch, command.now);
        self.store
            .save_preference_in_transaction(&mut transaction, &preference)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(preference)
    }
}

#[must_use]
pub fn apply_console_preference_patch(
    current: &ConsoleContextPreference,
    patch: &UpdateConsolePreferencePatch,
    now: DateTime<Utc>,
) -> ConsoleContextPreference {
    let mut preference = current.clone();
    if let Some(view_mode) = patch.last_view_mode {
        preference.last_view_mode = view_mode;
    }
    if let Some(organization_id) = patch.last_active_organization_id {
        preference.last_active_org_id = organization_id;
    }
    preference.updated_at = now;
    preference
}

fn default_preference(user_id: &str, now: DateTime<Utc>) -> ConsoleContextPreference {
    ConsoleContextPreference {
        id: Uuid::new_v4(),
        user_id: user_id.into(),
        last_view_mode: ViewMode::Applicant,
        last_active_org_id: None,
        created_at: now,
        updated_at: now,
    }
}

fn require_user_id(user_id: &str) -> Result<(), OrganizationApplicationError> {
    if user_id.trim().is_empty() {
        Err(OrganizationApplicationError::InvalidCommand(
            "user_id is required",
        ))
    } else {
        Ok(())
    }
}
