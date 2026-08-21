use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Map, Value};
use sqlx::{PgPool, Postgres, Row, Transaction};
use tokio::sync::Mutex;

use crate::{DeploymentEnvironment, DeploymentError, DeploymentProfile, Lane, ProfileStatus};

#[async_trait]
pub trait DeploymentRepository: Send + Sync {
    async fn save_profile(&self, profile: DeploymentProfile) -> Result<(), DeploymentError>;
    async fn profile(&self, id: &str) -> Result<Option<DeploymentProfile>, DeploymentError>;
    async fn profiles(
        &self,
        organization_id: &str,
    ) -> Result<Vec<DeploymentProfile>, DeploymentError>;
    async fn delete_profile(&self, id: &str) -> Result<(), DeploymentError>;
    async fn save_lane(&self, lane: Lane) -> Result<(), DeploymentError>;
    async fn lane(&self, id: &str) -> Result<Option<Lane>, DeploymentError>;
    async fn lanes(&self, profile_id: &str) -> Result<Vec<Lane>, DeploymentError>;
    async fn delete_lane(&self, id: &str) -> Result<(), DeploymentError>;
    async fn assign_device(
        &self,
        profile_id: &str,
        lane_id: &str,
        device_id: &str,
    ) -> Result<Lane, DeploymentError>;
}

#[derive(Clone, Default)]
pub struct MemoryDeploymentRepository {
    inner: Arc<Mutex<MemoryState>>,
}

#[derive(Default)]
struct MemoryState {
    profiles: BTreeMap<String, DeploymentProfile>,
    lanes: BTreeMap<String, Lane>,
}

impl MemoryDeploymentRepository {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl DeploymentRepository for MemoryDeploymentRepository {
    async fn save_profile(&self, profile: DeploymentProfile) -> Result<(), DeploymentError> {
        self.inner
            .lock()
            .await
            .profiles
            .insert(profile.id.clone(), profile);
        Ok(())
    }

    async fn profile(&self, id: &str) -> Result<Option<DeploymentProfile>, DeploymentError> {
        Ok(self.inner.lock().await.profiles.get(id).cloned())
    }

    async fn profiles(
        &self,
        organization_id: &str,
    ) -> Result<Vec<DeploymentProfile>, DeploymentError> {
        let mut values = self
            .inner
            .lock()
            .await
            .profiles
            .values()
            .filter(|profile| profile.organization_id == organization_id)
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by_key(|profile| std::cmp::Reverse(profile.created_at));
        Ok(values)
    }

    async fn delete_profile(&self, id: &str) -> Result<(), DeploymentError> {
        self.inner.lock().await.profiles.remove(id);
        Ok(())
    }

    async fn save_lane(&self, lane: Lane) -> Result<(), DeploymentError> {
        self.inner.lock().await.lanes.insert(lane.id.clone(), lane);
        Ok(())
    }

    async fn lane(&self, id: &str) -> Result<Option<Lane>, DeploymentError> {
        Ok(self.inner.lock().await.lanes.get(id).cloned())
    }

    async fn lanes(&self, profile_id: &str) -> Result<Vec<Lane>, DeploymentError> {
        let mut values = self
            .inner
            .lock()
            .await
            .lanes
            .values()
            .filter(|lane| lane.deployment_profile_id == profile_id)
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by_key(|lane| lane.created_at);
        Ok(values)
    }

    async fn delete_lane(&self, id: &str) -> Result<(), DeploymentError> {
        self.inner.lock().await.lanes.remove(id);
        Ok(())
    }

    async fn assign_device(
        &self,
        profile_id: &str,
        lane_id: &str,
        device_id: &str,
    ) -> Result<Lane, DeploymentError> {
        let mut state = self.inner.lock().await;
        if let Some(other) = state.lanes.values().find(|lane| {
            lane.deployment_profile_id == profile_id
                && lane.id != lane_id
                && lane.device_ids.iter().any(|id| id == device_id)
        }) {
            return Err(DeploymentError::Conflict(format!(
                "Device {device_id} is already assigned to lane {}",
                other.id
            )));
        }
        let lane = state
            .lanes
            .get_mut(lane_id)
            .filter(|lane| lane.deployment_profile_id == profile_id)
            .ok_or_else(|| DeploymentError::NotFound("Lane not found".into()))?;
        if !lane.device_ids.iter().any(|id| id == device_id) {
            lane.device_ids.push(device_id.into());
            lane.updated_at = Utc::now();
        }
        Ok(lane.clone())
    }
}

#[derive(Clone)]
pub struct PostgresDeploymentRepository {
    pool: PgPool,
}

impl PostgresDeploymentRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DeploymentRepository for PostgresDeploymentRepository {
    async fn save_profile(&self, profile: DeploymentProfile) -> Result<(), DeploymentError> {
        sqlx::query(
            "INSERT INTO deployment_profile_service.deployment_profiles
             (id,organization_id,name,description,status,environment,site_id,trust_profile_id,
              presentation_policy_ids,credential_template_ids,default_policy_id,network_mode,
              key_access_mode,environment_config,enabled_flow_ids,update_channel,update_policy,
              offline_cache_ttl_hours,operator_biometric_authentication_required,audit_all_events,
              api_key,api_key_prefix,callbacks,api_auth,rate_limits,feature_flags,branding,
              created_at,updated_at)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)
             ON CONFLICT(id) DO UPDATE SET
              organization_id=EXCLUDED.organization_id,name=EXCLUDED.name,description=EXCLUDED.description,
              status=EXCLUDED.status,environment=EXCLUDED.environment,site_id=EXCLUDED.site_id,
              trust_profile_id=EXCLUDED.trust_profile_id,presentation_policy_ids=EXCLUDED.presentation_policy_ids,
              credential_template_ids=EXCLUDED.credential_template_ids,default_policy_id=EXCLUDED.default_policy_id,
              network_mode=EXCLUDED.network_mode,key_access_mode=EXCLUDED.key_access_mode,
              environment_config=EXCLUDED.environment_config,enabled_flow_ids=EXCLUDED.enabled_flow_ids,
              update_channel=EXCLUDED.update_channel,update_policy=EXCLUDED.update_policy,
              offline_cache_ttl_hours=EXCLUDED.offline_cache_ttl_hours,
              operator_biometric_authentication_required=EXCLUDED.operator_biometric_authentication_required,
              audit_all_events=EXCLUDED.audit_all_events,api_key=EXCLUDED.api_key,
              api_key_prefix=EXCLUDED.api_key_prefix,callbacks=EXCLUDED.callbacks,api_auth=EXCLUDED.api_auth,
              rate_limits=EXCLUDED.rate_limits,feature_flags=EXCLUDED.feature_flags,branding=EXCLUDED.branding,
              updated_at=EXCLUDED.updated_at",
        )
        .bind(&profile.id)
        .bind(&profile.organization_id)
        .bind(&profile.name)
        .bind(&profile.description)
        .bind(status_name(profile.status))
        .bind(environment_name(profile.environment))
        .bind(&profile.site_id)
        .bind(&profile.trust_profile_id)
        .bind(json(&profile.presentation_policy_ids)?)
        .bind(json(&profile.credential_template_ids)?)
        .bind(&profile.default_policy_id)
        .bind(&profile.network_mode)
        .bind(&profile.key_access_mode)
        .bind(Value::Object(profile.environment_config.clone()))
        .bind(json(&profile.enabled_flow_ids)?)
        .bind(&profile.update_channel)
        .bind(Value::Object(profile.update_policy.clone()))
        .bind(profile.offline_cache_ttl_hours)
        .bind(profile.operator_biometric_authentication_required)
        .bind(profile.audit_all_events)
        .bind(&profile.api_key)
        .bind(&profile.api_key_prefix)
        .bind(json(&profile.callbacks)?)
        .bind(json(&profile.api_auth)?)
        .bind(json(&profile.rate_limits)?)
        .bind(json(&profile.feature_flags)?)
        .bind(json(&profile.branding)?)
        .bind(profile.created_at)
        .bind(profile.updated_at)
        .execute(&self.pool)
        .await
        .map_err(persistence)?;
        Ok(())
    }

    async fn profile(&self, id: &str) -> Result<Option<DeploymentProfile>, DeploymentError> {
        sqlx::query("SELECT * FROM deployment_profile_service.deployment_profiles WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(persistence)?
            .map(profile_from_row)
            .transpose()
    }

    async fn profiles(
        &self,
        organization_id: &str,
    ) -> Result<Vec<DeploymentProfile>, DeploymentError> {
        sqlx::query("SELECT * FROM deployment_profile_service.deployment_profiles WHERE organization_id=$1 ORDER BY created_at DESC")
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(profile_from_row)
            .collect()
    }

    async fn delete_profile(&self, id: &str) -> Result<(), DeploymentError> {
        sqlx::query("DELETE FROM deployment_profile_service.deployment_profiles WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(persistence)?;
        Ok(())
    }

    async fn save_lane(&self, lane: Lane) -> Result<(), DeploymentError> {
        save_lane(&self.pool, &lane).await
    }

    async fn lane(&self, id: &str) -> Result<Option<Lane>, DeploymentError> {
        sqlx::query("SELECT * FROM deployment_profile_service.lanes WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(persistence)?
            .map(lane_from_row)
            .transpose()
    }

    async fn lanes(&self, profile_id: &str) -> Result<Vec<Lane>, DeploymentError> {
        sqlx::query("SELECT * FROM deployment_profile_service.lanes WHERE deployment_profile_id=$1 ORDER BY created_at")
            .bind(profile_id)
            .fetch_all(&self.pool)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(lane_from_row)
            .collect()
    }

    async fn delete_lane(&self, id: &str) -> Result<(), DeploymentError> {
        sqlx::query("DELETE FROM deployment_profile_service.lanes WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(persistence)?;
        Ok(())
    }

    async fn assign_device(
        &self,
        profile_id: &str,
        lane_id: &str,
        device_id: &str,
    ) -> Result<Lane, DeploymentError> {
        let mut tx = self.pool.begin().await.map_err(persistence)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(profile_id)
            .execute(&mut *tx)
            .await
            .map_err(persistence)?;
        let rows = sqlx::query("SELECT * FROM deployment_profile_service.lanes WHERE deployment_profile_id=$1 ORDER BY id FOR UPDATE")
            .bind(profile_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(persistence)?;
        let mut lanes = rows
            .into_iter()
            .map(lane_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(other) = lanes
            .iter()
            .find(|lane| lane.id != lane_id && lane.device_ids.iter().any(|id| id == device_id))
        {
            return Err(DeploymentError::Conflict(format!(
                "Device {device_id} is already assigned to lane {}",
                other.id
            )));
        }
        let lane = lanes
            .iter_mut()
            .find(|lane| lane.id == lane_id)
            .ok_or_else(|| DeploymentError::NotFound("Lane not found".into()))?;
        if !lane.device_ids.iter().any(|id| id == device_id) {
            lane.device_ids.push(device_id.into());
            lane.updated_at = Utc::now();
            save_lane_tx(&mut tx, lane).await?;
        }
        let result = lane.clone();
        tx.commit().await.map_err(persistence)?;
        Ok(result)
    }
}

async fn save_lane(pool: &PgPool, lane: &Lane) -> Result<(), DeploymentError> {
    sqlx::query(
        "INSERT INTO deployment_profile_service.lanes
         (id,deployment_profile_id,name,description,location,device_type,default_policy_id,metadata,device_ids,created_at,updated_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,
         location=EXCLUDED.location,device_type=EXCLUDED.device_type,default_policy_id=EXCLUDED.default_policy_id,
         metadata=EXCLUDED.metadata,device_ids=EXCLUDED.device_ids,updated_at=EXCLUDED.updated_at",
    )
    .bind(&lane.id).bind(&lane.deployment_profile_id).bind(&lane.name).bind(&lane.description)
    .bind(&lane.location).bind(&lane.device_type).bind(&lane.default_policy_id)
    .bind(Value::Object(lane.metadata.clone())).bind(json(&lane.device_ids)?)
    .bind(lane.created_at).bind(lane.updated_at).execute(pool).await.map_err(persistence)?;
    Ok(())
}

async fn save_lane_tx(
    tx: &mut Transaction<'_, Postgres>,
    lane: &Lane,
) -> Result<(), DeploymentError> {
    sqlx::query(
        "UPDATE deployment_profile_service.lanes SET device_ids=$1,updated_at=$2 WHERE id=$3",
    )
    .bind(json(&lane.device_ids)?)
    .bind(lane.updated_at)
    .bind(&lane.id)
    .execute(&mut **tx)
    .await
    .map_err(persistence)?;
    Ok(())
}

fn profile_from_row(row: sqlx::postgres::PgRow) -> Result<DeploymentProfile, DeploymentError> {
    Ok(DeploymentProfile {
        id: row.try_get("id").map_err(persistence)?,
        organization_id: row.try_get("organization_id").map_err(persistence)?,
        name: row.try_get("name").map_err(persistence)?,
        description: row.try_get("description").map_err(persistence)?,
        status: parse_status(&row.try_get::<String, _>("status").map_err(persistence)?)?,
        environment: parse_environment(
            &row.try_get::<String, _>("environment")
                .map_err(persistence)?,
        )?,
        callbacks: from_json(row.try_get("callbacks").map_err(persistence)?, "callbacks")?,
        api_auth: from_json(row.try_get("api_auth").map_err(persistence)?, "api_auth")?,
        rate_limits: from_json(
            row.try_get("rate_limits").map_err(persistence)?,
            "rate_limits",
        )?,
        feature_flags: from_json(
            row.try_get("feature_flags").map_err(persistence)?,
            "feature_flags",
        )?,
        branding: from_json(row.try_get("branding").map_err(persistence)?, "branding")?,
        trust_profile_id: row.try_get("trust_profile_id").map_err(persistence)?,
        presentation_policy_ids: from_json(
            row.try_get("presentation_policy_ids")
                .map_err(persistence)?,
            "presentation_policy_ids",
        )?,
        credential_template_ids: from_json(
            row.try_get("credential_template_ids")
                .map_err(persistence)?,
            "credential_template_ids",
        )?,
        default_policy_id: row.try_get("default_policy_id").map_err(persistence)?,
        site_id: row.try_get("site_id").map_err(persistence)?,
        network_mode: row.try_get("network_mode").map_err(persistence)?,
        key_access_mode: row.try_get("key_access_mode").map_err(persistence)?,
        environment_config: object(
            row.try_get("environment_config").map_err(persistence)?,
            "environment_config",
        )?,
        update_channel: row.try_get("update_channel").map_err(persistence)?,
        update_policy: object(
            row.try_get("update_policy").map_err(persistence)?,
            "update_policy",
        )?,
        offline_cache_ttl_hours: row
            .try_get("offline_cache_ttl_hours")
            .map_err(persistence)?,
        operator_biometric_authentication_required: row
            .try_get("operator_biometric_authentication_required")
            .map_err(persistence)?,
        audit_all_events: row.try_get("audit_all_events").map_err(persistence)?,
        enabled_flow_ids: from_json(
            row.try_get("enabled_flow_ids").map_err(persistence)?,
            "enabled_flow_ids",
        )?,
        api_key: row.try_get("api_key").map_err(persistence)?,
        api_key_prefix: row.try_get("api_key_prefix").map_err(persistence)?,
        created_at: row.try_get("created_at").map_err(persistence)?,
        updated_at: row.try_get("updated_at").map_err(persistence)?,
    })
}

fn lane_from_row(row: sqlx::postgres::PgRow) -> Result<Lane, DeploymentError> {
    Ok(Lane {
        id: row.try_get("id").map_err(persistence)?,
        deployment_profile_id: row.try_get("deployment_profile_id").map_err(persistence)?,
        name: row.try_get("name").map_err(persistence)?,
        description: row.try_get("description").map_err(persistence)?,
        location: row.try_get("location").map_err(persistence)?,
        device_type: row.try_get("device_type").map_err(persistence)?,
        default_policy_id: row.try_get("default_policy_id").map_err(persistence)?,
        metadata: object(row.try_get("metadata").map_err(persistence)?, "metadata")?,
        device_ids: from_json(
            row.try_get("device_ids").map_err(persistence)?,
            "device_ids",
        )?,
        created_at: row.try_get("created_at").map_err(persistence)?,
        updated_at: row.try_get("updated_at").map_err(persistence)?,
    })
}

fn json(value: &impl serde::Serialize) -> Result<Value, DeploymentError> {
    serde_json::to_value(value)
        .map_err(|_| DeploymentError::Persistence("Deployment Profile record is invalid".into()))
}

fn from_json<T: serde::de::DeserializeOwned>(
    value: Value,
    field: &str,
) -> Result<T, DeploymentError> {
    serde_json::from_value(value)
        .map_err(|_| DeploymentError::Persistence(format!("Deployment Profile {field} is invalid")))
}

fn object(value: Value, field: &str) -> Result<Map<String, Value>, DeploymentError> {
    value.as_object().cloned().ok_or_else(|| {
        DeploymentError::Persistence(format!("Deployment Profile {field} is invalid"))
    })
}

const fn status_name(value: ProfileStatus) -> &'static str {
    match value {
        ProfileStatus::Draft => "draft",
        ProfileStatus::Active => "active",
        ProfileStatus::Suspended => "suspended",
        ProfileStatus::Archived => "archived",
    }
}

fn parse_status(value: &str) -> Result<ProfileStatus, DeploymentError> {
    match value {
        "draft" => Ok(ProfileStatus::Draft),
        "active" => Ok(ProfileStatus::Active),
        "suspended" => Ok(ProfileStatus::Suspended),
        "archived" => Ok(ProfileStatus::Archived),
        _ => Err(DeploymentError::Persistence(
            "Deployment Profile status is invalid".into(),
        )),
    }
}

const fn environment_name(value: DeploymentEnvironment) -> &'static str {
    match value {
        DeploymentEnvironment::Development => "development",
        DeploymentEnvironment::Staging => "staging",
        DeploymentEnvironment::Production => "production",
        DeploymentEnvironment::Sandbox => "sandbox",
    }
}

fn parse_environment(value: &str) -> Result<DeploymentEnvironment, DeploymentError> {
    match value {
        "development" => Ok(DeploymentEnvironment::Development),
        "staging" => Ok(DeploymentEnvironment::Staging),
        "production" => Ok(DeploymentEnvironment::Production),
        "sandbox" => Ok(DeploymentEnvironment::Sandbox),
        _ => Err(DeploymentError::Persistence(
            "Deployment Profile environment is invalid".into(),
        )),
    }
}

fn persistence(error: sqlx::Error) -> DeploymentError {
    DeploymentError::Persistence(error.to_string())
}
