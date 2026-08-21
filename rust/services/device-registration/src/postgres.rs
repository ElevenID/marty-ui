use async_trait::async_trait;
use chrono::{Duration, Utc};
use marty_verification::device_auth::{
    evaluate_device_key_eligibility, DeviceChallengeRecord, DeviceKeyEligibilityRequest,
    DeviceKeyRecord, DeviceKeyState, MAX_KEY_VERSION, MAX_ROTATION_GRACE_SECONDS,
};
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

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

fn persistence(error: sqlx::Error) -> DeviceError {
    DeviceError::Persistence(error.to_string())
}

fn registration(row: &PgRow) -> Result<DeviceRegistration, DeviceError> {
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
    let preferences = serde_json::from_value(row.try_get("preferences").map_err(persistence)?)
        .map_err(|error| DeviceError::Persistence(error.to_string()))?;
    let version: Option<i64> = row.try_get("key_version").map_err(persistence)?;
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
        public_key_der: row.try_get("public_key_der").map_err(persistence)?,
        public_key_kid: row.try_get("public_key_kid").map_err(persistence)?,
        key_valid_from: row.try_get("key_valid_from").map_err(persistence)?,
        key_valid_until: row.try_get("key_valid_until").map_err(persistence)?,
        key_version: version.map(|value| value as u64),
        is_active: row.try_get("is_active").map_err(persistence)?,
        created_at: row.try_get("created_at").map_err(persistence)?,
        updated_at: row.try_get("updated_at").map_err(persistence)?,
        last_seen_at: row.try_get("last_seen_at").map_err(persistence)?,
    })
}

fn key(row: &PgRow) -> Result<DeviceKeyRecord, DeviceError> {
    let state = match row
        .try_get::<String, _>("state")
        .map_err(persistence)?
        .as_str()
    {
        "CURRENT" => DeviceKeyState::Current,
        "RETIRING" => DeviceKeyState::Retiring,
        "RETIRED" => DeviceKeyState::Retired,
        "REVOKED" => DeviceKeyState::Revoked,
        value => {
            return Err(DeviceError::Persistence(format!(
                "invalid stored device key state: {value}"
            )))
        }
    };
    let valid_from: chrono::DateTime<Utc> = row.try_get("valid_from").map_err(persistence)?;
    let valid_until: Option<chrono::DateTime<Utc>> =
        row.try_get("valid_until").map_err(persistence)?;
    let rotated_at: Option<chrono::DateTime<Utc>> =
        row.try_get("rotated_at").map_err(persistence)?;
    let retire_at: Option<chrono::DateTime<Utc>> = row.try_get("retire_at").map_err(persistence)?;
    let revoked_at: Option<chrono::DateTime<Utc>> =
        row.try_get("revoked_at").map_err(persistence)?;
    let created_at: chrono::DateTime<Utc> = row.try_get("created_at").map_err(persistence)?;
    Ok(DeviceKeyRecord {
        id: row.try_get("id").map_err(persistence)?,
        registration_id: row.try_get("registration_id").map_err(persistence)?,
        key_version: row.try_get::<i64, _>("key_version").map_err(persistence)? as u64,
        public_key_der: row.try_get("public_key_der").map_err(persistence)?,
        public_key_kid: row.try_get("public_key_kid").map_err(persistence)?,
        state,
        valid_from: valid_from.to_rfc3339(),
        valid_until: valid_until.map(|value| value.to_rfc3339()),
        rotated_at: rotated_at.map(|value| value.to_rfc3339()),
        retire_at: retire_at.map(|value| value.to_rfc3339()),
        revoked_at: revoked_at.map(|value| value.to_rfc3339()),
        created_at: Some(created_at.to_rfc3339()),
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
) -> Result<(), DeviceError> {
    let preferences = serde_json::to_value(&value.preferences)
        .map_err(|error| DeviceError::Persistence(error.to_string()))?;
    let platform = match value.platform {
        Platform::Ios => "ios",
        Platform::Android => "android",
        Platform::Web => "web",
    };
    if exists {
        sqlx::query("UPDATE device_registration_service.device_registrations SET organization_id=$2, platform=$3, fcm_token=$4, app_version=$5, os_version=$6, device_model=$7, preferences=$8, public_key_der=$9, public_key_kid=$10, key_valid_from=$11, key_valid_until=$12, key_version=$13, is_active=$14, updated_at=$15, last_seen_at=$16 WHERE id=$1")
            .bind(&value.id).bind(&value.organization_id).bind(platform).bind(&value.fcm_token).bind(&value.app_version).bind(&value.os_version).bind(&value.device_model).bind(preferences).bind(&value.public_key_der).bind(&value.public_key_kid).bind(value.key_valid_from).bind(value.key_valid_until).bind(value.key_version.map(|v| v as i64)).bind(value.is_active).bind(value.updated_at).bind(value.last_seen_at)
            .execute(&mut **transaction).await.map_err(persistence)?;
    } else {
        sqlx::query("INSERT INTO device_registration_service.device_registrations (id,user_id,organization_id,device_id,platform,fcm_token,app_version,os_version,device_model,preferences,public_key_der,public_key_kid,key_valid_from,key_valid_until,key_version,is_active,created_at,updated_at,last_seen_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)")
            .bind(&value.id).bind(&value.user_id).bind(&value.organization_id).bind(&value.device_id).bind(platform).bind(&value.fcm_token).bind(&value.app_version).bind(&value.os_version).bind(&value.device_model).bind(preferences).bind(&value.public_key_der).bind(&value.public_key_kid).bind(value.key_valid_from).bind(value.key_valid_until).bind(value.key_version.map(|v| v as i64)).bind(value.is_active).bind(value.created_at).bind(value.updated_at).bind(value.last_seen_at)
            .execute(&mut **transaction).await.map_err(persistence)?;
    }
    Ok(())
}

#[async_trait]
impl DeviceRepository for PostgresDeviceRepository {
    async fn save(&self, mut value: DeviceRegistration) -> Result<DeviceRegistration, DeviceError> {
        let mut transaction = self.pool.begin().await.map_err(persistence)?;
        let existing = sqlx::query("SELECT * FROM device_registration_service.device_registrations WHERE user_id=$1 AND device_id=$2 AND is_active=true AND organization_id IS NOT DISTINCT FROM $3 FOR UPDATE")
            .bind(&value.user_id).bind(&value.device_id).bind(&value.organization_id).fetch_optional(&mut *transaction).await.map_err(persistence)?;
        let mut create_key = value.public_key_der.is_some();
        if let Some(row) = existing.as_ref() {
            let current = registration(row)?;
            value.id = current.id.clone();
            value.created_at = current.created_at;
            if current.is_active && !value.is_active {
                return Err(DeviceError::Conflict(
                    "device deactivation must use the revocation transition".into(),
                ));
            }
            if current.key_version.is_some() {
                if value.public_key_der != current.public_key_der
                    || value.public_key_kid != current.public_key_kid
                {
                    return Err(DeviceError::Conflict(
                        "existing device keys must use the rotation transition".into(),
                    ));
                }
                value.public_key_der = current.public_key_der;
                value.public_key_kid = current.public_key_kid;
                value.key_valid_from = current.key_valid_from;
                value.key_valid_until = current.key_valid_until;
                value.key_version = current.key_version;
                create_key = false;
            }
        }
        if create_key {
            let committed_at: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT now()")
                .fetch_one(&mut *transaction)
                .await
                .map_err(persistence)?;
            value.key_version = Some(1);
            value.key_valid_from = Some(committed_at);
            value.key_valid_until = None;
        }
        write_registration(&mut transaction, &value, existing.is_some()).await?;
        if create_key {
            let committed_at = value.key_valid_from.expect("assigned");
            sqlx::query("INSERT INTO device_registration_service.device_registration_keys (id,registration_id,key_version,public_key_der,public_key_kid,state,valid_from,created_at) VALUES ($1,$2,1,$3,$4,'CURRENT',$5,$5)")
                .bind(Uuid::new_v4().to_string()).bind(&value.id).bind(value.public_key_der.as_deref()).bind(value.public_key_kid.as_deref()).bind(committed_at).execute(&mut *transaction).await.map_err(persistence)?;
            sqlx::query("INSERT INTO device_registration_service.device_key_transitions (id,registration_id,event,from_version,to_version,committed_at) VALUES ($1,$2,'KEY_REGISTERED',NULL,1,$3)")
                .bind(Uuid::new_v4().to_string()).bind(&value.id).bind(committed_at).execute(&mut *transaction).await.map_err(persistence)?;
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(value)
    }

    async fn get(&self, id: &str) -> Result<Option<DeviceRegistration>, DeviceError> {
        let row = sqlx::query(
            "SELECT * FROM device_registration_service.device_registrations WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(persistence)?;
        row.as_ref().map(registration).transpose()
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

    async fn rotate_key(
        &self,
        id: &str,
        expected: u64,
        public_key_der: &str,
        public_key_kid: &str,
        grace: u64,
    ) -> Result<DeviceRegistration, DeviceError> {
        if grace > MAX_ROTATION_GRACE_SECONDS {
            return Err(DeviceError::BadRequest(
                "device key rotation grace is outside server bounds".into(),
            ));
        }
        let mut transaction = self.pool.begin().await.map_err(persistence)?;
        let row = sqlx::query(
            "SELECT * FROM device_registration_service.device_registrations WHERE id=$1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(persistence)?
        .ok_or_else(|| DeviceError::Conflict("device registration no longer exists".into()))?;
        let current = registration(&row)?;
        if !current.is_active {
            return Err(DeviceError::Conflict(
                "inactive device registrations cannot rotate keys".into(),
            ));
        }
        if current.key_version != Some(expected) {
            return Err(DeviceError::Conflict(
                "current device key version changed".into(),
            ));
        }
        if expected >= MAX_KEY_VERSION {
            return Err(DeviceError::Conflict(
                "device key version limit reached".into(),
            ));
        }
        let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT now()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(persistence)?;
        let retired = sqlx::query("UPDATE device_registration_service.device_registration_keys SET state='RETIRING',rotated_at=$3,retire_at=$4 WHERE registration_id=$1 AND key_version=$2 AND state='CURRENT'")
            .bind(id).bind(expected as i64).bind(now).bind(now + Duration::seconds(grace as i64)).execute(&mut *transaction).await.map_err(persistence)?;
        if retired.rows_affected() != 1 {
            return Err(DeviceError::Conflict(
                "current device key version changed".into(),
            ));
        }
        let next = expected + 1;
        sqlx::query("INSERT INTO device_registration_service.device_registration_keys (id,registration_id,key_version,public_key_der,public_key_kid,state,valid_from,created_at) VALUES ($1,$2,$3,$4,$5,'CURRENT',$6,$6)")
            .bind(Uuid::new_v4().to_string()).bind(id).bind(next as i64).bind(public_key_der).bind(public_key_kid).bind(now).execute(&mut *transaction).await.map_err(persistence)?;
        let projected = sqlx::query("UPDATE device_registration_service.device_registrations SET public_key_der=$3,public_key_kid=$4,key_valid_from=$5,key_valid_until=NULL,key_version=$6,updated_at=$5,last_seen_at=$5 WHERE id=$1 AND key_version=$2")
            .bind(id).bind(expected as i64).bind(public_key_der).bind(public_key_kid).bind(now).bind(next as i64).execute(&mut *transaction).await.map_err(persistence)?;
        if projected.rows_affected() != 1 {
            return Err(DeviceError::Conflict(
                "current device key version changed".into(),
            ));
        }
        sqlx::query("INSERT INTO device_registration_service.device_key_transitions (id,registration_id,event,from_version,to_version,committed_at) VALUES ($1,$2,'KEY_ROTATED',$3,$4,$5)")
            .bind(Uuid::new_v4().to_string()).bind(id).bind(expected as i64).bind(next as i64).bind(now).execute(&mut *transaction).await.map_err(persistence)?;
        let value = fetch_registration(&mut transaction, id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(value)
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
        let now: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT now()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(persistence)?;
        sqlx::query("UPDATE device_registration_service.device_registration_keys SET state='REVOKED',revoked_at=$2 WHERE registration_id=$1 AND state IN ('CURRENT','RETIRING')").bind(id).bind(now).execute(&mut *transaction).await.map_err(persistence)?;
        sqlx::query("UPDATE device_registration_service.device_registrations SET is_active=false,public_key_der=NULL,public_key_kid=NULL,key_valid_from=NULL,key_valid_until=NULL,key_version=NULL,updated_at=$2 WHERE id=$1").bind(id).bind(now).execute(&mut *transaction).await.map_err(persistence)?;
        sqlx::query("INSERT INTO device_registration_service.device_key_transitions (id,registration_id,event,from_version,to_version,committed_at) VALUES ($1,$2,'KEYS_REVOKED',$3,NULL,$4)").bind(Uuid::new_v4().to_string()).bind(id).bind(current.key_version.map(|value| value as i64)).bind(now).execute(&mut *transaction).await.map_err(persistence)?;
        let value = fetch_registration(&mut transaction, id).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(Some(value))
    }

    async fn resolve_challenge_key(
        &self,
        challenge: &DeviceChallengeRecord,
        purpose: &str,
        audience: &str,
    ) -> Result<Option<DeviceKeyRecord>, DeviceError> {
        let (Some(id), Some(version)) = (&challenge.registration_id, challenge.key_version) else {
            return Ok(None);
        };
        let row = sqlx::query("SELECT k.*,r.is_active FROM device_registration_service.device_registration_keys k JOIN device_registration_service.device_registrations r ON r.id=k.registration_id WHERE k.registration_id=$1 AND k.key_version=$2 AND k.public_key_kid=$3")
            .bind(id).bind(version as i64).bind(&challenge.public_key_kid).fetch_optional(&self.pool).await.map_err(persistence)?;
        let Some(row) = row else { return Ok(None) };
        let active: bool = row.try_get("is_active").map_err(persistence)?;
        let value = key(&row)?;
        let result = evaluate_device_key_eligibility(&DeviceKeyEligibilityRequest {
            key: value.clone(),
            registration_active: active,
            challenge: challenge.clone(),
            purpose: purpose.into(),
            audience: audience.into(),
            now: Utc::now().to_rfc3339(),
        })?;
        Ok(result.eligible.then_some(value))
    }
}
