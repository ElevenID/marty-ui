//! Fresh-schema device metadata with transactional holder revocation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};

use crate::domain::reject_private_preferences;
use crate::{DeviceError, DeviceRegistration, DeviceRepository, Platform};

#[derive(Debug, Clone)]
pub struct PostgresDeviceRepository {
    pool: PgPool,
}

impl PostgresDeviceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

pub(crate) fn persistence(error: sqlx::Error) -> DeviceError {
    DeviceError::Persistence(error.to_string())
}

pub(crate) fn registration(row: &PgRow) -> Result<DeviceRegistration, DeviceError> {
    let platform = match row
        .try_get::<String, _>("platform")
        .map_err(persistence)?
        .as_str()
    {
        "ios" => Platform::Ios,
        "android" => Platform::Android,
        "web" => Platform::Web,
        value => {
            return Err(DeviceError::Persistence(format!(
                "invalid stored device platform: {value}"
            )))
        }
    };
    let preferences_json: serde_json::Value = row.try_get("preferences").map_err(persistence)?;
    reject_private_preferences(&preferences_json).map_err(|_| {
        DeviceError::Persistence("stored device preferences contain private key material".into())
    })?;
    let preferences = serde_json::from_value(preferences_json)
        .map_err(|error| DeviceError::Persistence(error.to_string()))?;
    Ok(DeviceRegistration {
        id: row.try_get("id").map_err(persistence)?,
        user_id: row.try_get("user_id").map_err(persistence)?,
        organization_id: row.try_get("organization_id").map_err(persistence)?,
        device_id: row.try_get("device_id").map_err(persistence)?,
        platform,
        fcm_token: row.try_get("fcm_token").map_err(persistence)?,
        app_version: row.try_get("app_version").map_err(persistence)?,
        os_version: row.try_get("os_version").map_err(persistence)?,
        device_model: row.try_get("device_model").map_err(persistence)?,
        preferences,
        is_active: row.try_get("is_active").map_err(persistence)?,
        created_at: row.try_get("created_at").map_err(persistence)?,
        updated_at: row.try_get("updated_at").map_err(persistence)?,
        last_seen_at: row.try_get("last_seen_at").map_err(persistence)?,
    })
}

async fn fetch_registration(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<DeviceRegistration, DeviceError> {
    let row =
        sqlx::query("SELECT * FROM device_registration_service.device_registrations WHERE id=$1")
            .bind(id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(persistence)?;
    registration(&row)
}

async fn write_registration(
    transaction: &mut Transaction<'_, Postgres>,
    value: &DeviceRegistration,
    exists: bool,
    preferences: serde_json::Value,
) -> Result<(), DeviceError> {
    let platform = match value.platform {
        Platform::Ios => "ios",
        Platform::Android => "android",
        Platform::Web => "web",
    };
    if exists {
        sqlx::query("UPDATE device_registration_service.device_registrations SET platform=$2,fcm_token=$3,app_version=$4,os_version=$5,device_model=$6,preferences=$7,updated_at=$8,last_seen_at=$9 WHERE id=$1")
            .bind(&value.id).bind(platform).bind(&value.fcm_token).bind(&value.app_version)
            .bind(&value.os_version).bind(&value.device_model).bind(preferences)
            .bind(value.updated_at).bind(value.last_seen_at)
            .execute(&mut **transaction).await.map_err(persistence)?;
    } else {
        sqlx::query("INSERT INTO device_registration_service.device_registrations (id,user_id,organization_id,device_id,platform,fcm_token,app_version,os_version,device_model,preferences,is_active,created_at,updated_at,last_seen_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
            .bind(&value.id).bind(&value.user_id).bind(&value.organization_id)
            .bind(&value.device_id).bind(platform).bind(&value.fcm_token)
            .bind(&value.app_version).bind(&value.os_version).bind(&value.device_model)
            .bind(preferences).bind(value.is_active).bind(value.created_at)
            .bind(value.updated_at).bind(value.last_seen_at)
            .execute(&mut **transaction).await.map_err(persistence)?;
    }
    Ok(())
}

#[async_trait]
impl DeviceRepository for PostgresDeviceRepository {
    async fn save(&self, mut value: DeviceRegistration) -> Result<DeviceRegistration, DeviceError> {
        let preferences = serde_json::to_value(&value.preferences)
            .map_err(|error| DeviceError::Persistence(error.to_string()))?;
        reject_private_preferences(&preferences)?;
        let mut transaction = self.pool.begin().await.map_err(persistence)?;
        let by_id = sqlx::query(
            "SELECT * FROM device_registration_service.device_registrations WHERE id=$1 FOR UPDATE",
        )
        .bind(&value.id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(persistence)?;
        let existing = if let Some(row) = by_id {
            let current = registration(&row)?;
            if current.user_id != value.user_id
                || current.organization_id != value.organization_id
                || current.device_id != value.device_id
            {
                return Err(DeviceError::Conflict(
                    "device registration identity is immutable".into(),
                ));
            }
            if current.is_active != value.is_active {
                return Err(DeviceError::Conflict(
                    "device activation changes require a lifecycle transition".into(),
                ));
            }
            Some(current)
        } else {
            sqlx::query("SELECT * FROM device_registration_service.device_registrations WHERE user_id=$1 AND organization_id IS NOT DISTINCT FROM $2 AND device_id=$3 AND is_active=true FOR UPDATE")
                .bind(&value.user_id).bind(&value.organization_id).bind(&value.device_id)
                .fetch_optional(&mut *transaction).await.map_err(persistence)?
                .as_ref().map(registration).transpose()?
        };
        if let Some(existing) = existing.as_ref() {
            if existing.is_active && !value.is_active {
                return Err(DeviceError::Conflict(
                    "device deactivation must use the revocation transition".into(),
                ));
            }
            value.id = existing.id.clone();
            value.created_at = existing.created_at;
        }
        write_registration(&mut transaction, &value, existing.is_some(), preferences).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(value)
    }

    async fn get(&self, id: &str) -> Result<Option<DeviceRegistration>, DeviceError> {
        sqlx::query("SELECT * FROM device_registration_service.device_registrations WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(persistence)?
            .as_ref()
            .map(registration)
            .transpose()
    }

    async fn list_for_user(
        &self,
        user_id: &str,
        organization_id: Option<&str>,
    ) -> Result<Vec<DeviceRegistration>, DeviceError> {
        let rows = sqlx::query("SELECT * FROM device_registration_service.device_registrations WHERE user_id=$1 AND ($2::text IS NULL OR organization_id=$2) ORDER BY updated_at DESC")
            .bind(user_id).bind(organization_id).fetch_all(&self.pool).await.map_err(persistence)?;
        rows.iter().map(registration).collect()
    }

    async fn deactivate(&self, id: &str) -> Result<Option<DeviceRegistration>, DeviceError> {
        let mut transaction = self.pool.begin().await.map_err(persistence)?;
        let Some(row) = sqlx::query(
            "SELECT * FROM device_registration_service.device_registrations WHERE id=$1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(persistence)?
        else {
            return Ok(None);
        };
        let current = registration(&row)?;
        if !current.is_active {
            transaction.commit().await.map_err(persistence)?;
            return Ok(Some(current));
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(persistence)?;
        sqlx::query("UPDATE device_registration_service.device_holder_credentials SET revoked_at=GREATEST($2,issued_at) WHERE registration_id=$1 AND revoked_at IS NULL")
            .bind(id).bind(now).execute(&mut *transaction).await.map_err(persistence)?;
        crate::holder_key_repository::revoke_and_queue(&mut transaction, id, None, now).await?;
        sqlx::query("UPDATE device_registration_service.device_registrations SET is_active=false,updated_at=$2 WHERE id=$1")
            .bind(id).bind(now).execute(&mut *transaction).await.map_err(persistence)?;
        let value = fetch_registration(&mut transaction, id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(Some(value))
    }
}

#[cfg(test)]
mod custody_tests {
    use super::PostgresDeviceRepository;
    use crate::{CreateRegistration, DeviceError, DeviceRegistration, DeviceRepository, Platform};
    use chrono::Utc;
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn direct_repository_rejects_private_material_before_database_access() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://127.0.0.1:1/unused")
            .unwrap();
        let store = PostgresDeviceRepository::new(pool);
        let input = CreateRegistration {
            user_id: None,
            organization_id: None,
            device_id: "synthetic-device".into(),
            platform: Platform::Web,
            fcm_token: "synthetic-push-token".into(),
            app_version: None,
            os_version: None,
            device_model: None,
            preferences: Default::default(),
            is_active: true,
        };
        let mut registration = DeviceRegistration::new("synthetic-user".into(), input, Utc::now());
        registration.preferences.quiet_hours_start =
            Some("-----BEGIN PRIVATE KEY-----synthetic-----END PRIVATE KEY-----".into());
        assert!(matches!(
            store.save(registration).await,
            Err(DeviceError::BadRequest(_))
        ));
    }
}
