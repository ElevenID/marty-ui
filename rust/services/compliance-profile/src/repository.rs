use crate::{ComplianceError, ComplianceProfile, ComplianceStatus};
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

#[async_trait]
pub trait ComplianceRepository: Send + Sync {
    async fn save(&self, profile: ComplianceProfile) -> Result<(), ComplianceError>;
    async fn get(&self, id: &str) -> Result<Option<ComplianceProfile>, ComplianceError>;
    async fn list(&self, organization_id: &str) -> Result<Vec<ComplianceProfile>, ComplianceError>;
    async fn discoverable(&self) -> Result<Vec<ComplianceProfile>, ComplianceError>;
    async fn delete(&self, id: &str) -> Result<(), ComplianceError>;
}

#[derive(Clone, Default)]
pub struct MemoryComplianceRepository {
    inner: Arc<Mutex<BTreeMap<String, ComplianceProfile>>>,
}
impl MemoryComplianceRepository {
    pub fn new() -> Self {
        Self::default()
    }
}
#[async_trait]
impl ComplianceRepository for MemoryComplianceRepository {
    async fn save(&self, p: ComplianceProfile) -> Result<(), ComplianceError> {
        self.inner.lock().await.insert(p.id.clone(), p);
        Ok(())
    }
    async fn get(&self, id: &str) -> Result<Option<ComplianceProfile>, ComplianceError> {
        Ok(self.inner.lock().await.get(id).cloned())
    }
    async fn list(&self, org: &str) -> Result<Vec<ComplianceProfile>, ComplianceError> {
        let mut v = self
            .inner
            .lock()
            .await
            .values()
            .filter(|p| p.is_system || p.organization_id.as_deref() == Some(org))
            .cloned()
            .collect::<Vec<_>>();
        v.sort_by_key(|p| p.created_at);
        Ok(v)
    }
    async fn discoverable(&self) -> Result<Vec<ComplianceProfile>, ComplianceError> {
        let mut v = self
            .inner
            .lock()
            .await
            .values()
            .filter(|p| p.is_system && p.discoverable && p.status == ComplianceStatus::Active)
            .cloned()
            .collect::<Vec<_>>();
        v.sort_by_key(|p| p.id.clone());
        Ok(v)
    }
    async fn delete(&self, id: &str) -> Result<(), ComplianceError> {
        self.inner.lock().await.remove(id);
        Ok(())
    }
}

#[derive(Clone)]
pub struct PostgresComplianceRepository {
    pool: PgPool,
}
impl PostgresComplianceRepository {
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
#[async_trait]
impl ComplianceRepository for PostgresComplianceRepository {
    async fn save(&self, p: ComplianceProfile) -> Result<(), ComplianceError> {
        let payload = serde_json::to_value(&p).map_err(|_| bad("record serialization failed"))?;
        sqlx::query("INSERT INTO compliance_profile_service.profiles(id,organization_id,status,is_system,discoverable,payload,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET organization_id=EXCLUDED.organization_id,status=EXCLUDED.status,is_system=EXCLUDED.is_system,discoverable=EXCLUDED.discoverable,payload=EXCLUDED.payload,updated_at=EXCLUDED.updated_at")
            .bind(&p.id).bind(&p.organization_id).bind(status(p.status)).bind(p.is_system).bind(p.discoverable).bind(payload).bind(p.created_at).bind(p.updated_at).execute(&self.pool).await.map_err(db)?;
        Ok(())
    }
    async fn get(&self, id: &str) -> Result<Option<ComplianceProfile>, ComplianceError> {
        sqlx::query("SELECT payload FROM compliance_profile_service.profiles WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .map(row)
            .transpose()
    }
    async fn list(&self, org: &str) -> Result<Vec<ComplianceProfile>, ComplianceError> {
        sqlx::query("SELECT payload FROM compliance_profile_service.profiles WHERE is_system OR organization_id=$1 ORDER BY created_at,id").bind(org).fetch_all(&self.pool).await.map_err(db)?.into_iter().map(row).collect()
    }
    async fn discoverable(&self) -> Result<Vec<ComplianceProfile>, ComplianceError> {
        sqlx::query("SELECT payload FROM compliance_profile_service.profiles WHERE is_system AND discoverable AND status='ACTIVE' ORDER BY id").fetch_all(&self.pool).await.map_err(db)?.into_iter().map(row).collect()
    }
    async fn delete(&self, id: &str) -> Result<(), ComplianceError> {
        sqlx::query("DELETE FROM compliance_profile_service.profiles WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }
}
fn row(r: sqlx::postgres::PgRow) -> Result<ComplianceProfile, ComplianceError> {
    let v: serde_json::Value = r.try_get("payload").map_err(db)?;
    serde_json::from_value(v).map_err(|_| bad("persisted record is invalid"))
}
const fn status(v: ComplianceStatus) -> &'static str {
    match v {
        ComplianceStatus::Draft => "DRAFT",
        ComplianceStatus::Active => "ACTIVE",
        ComplianceStatus::Suspended => "SUSPENDED",
        ComplianceStatus::Deprecated => "DEPRECATED",
    }
}
fn db(e: sqlx::Error) -> ComplianceError {
    ComplianceError::Persistence(e.to_string())
}
fn bad(m: &str) -> ComplianceError {
    ComplianceError::Persistence(m.into())
}
