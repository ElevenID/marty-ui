use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use marty_verification::device_auth::{DeviceChallengeRecord, CHALLENGE_AUDIENCE};
use rand::RngCore;
use redis::{aio::ConnectionManager, AsyncCommands, Script};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

use crate::DeviceError;

const PREFIX: &str = "device-registration:challenge:";
const CONSUME: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 0 end
redis.call('DEL', KEYS[1])
return 1
"#;

#[derive(Debug, Clone)]
pub struct ChallengeIssue {
    pub user_id: String,
    pub device_id: String,
    pub public_key_kid: String,
    pub public_key_sha256: String,
    pub registration_id: Option<String>,
    pub key_version: Option<u64>,
    pub purpose: String,
}

#[async_trait]
pub trait ChallengeRepository: Send + Sync {
    async fn issue(&self, request: ChallengeIssue) -> Result<DeviceChallengeRecord, DeviceError>;
    async fn get(&self, challenge_id: &str) -> Result<Option<DeviceChallengeRecord>, DeviceError>;
    async fn consume(&self, record: &DeviceChallengeRecord) -> Result<bool, DeviceError>;
    fn ttl_seconds(&self) -> u64;
}

fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn issue_record(ttl_seconds: u64, request: &ChallengeIssue) -> DeviceChallengeRecord {
    let now = Utc::now();
    DeviceChallengeRecord {
        challenge_id: random_token(24),
        user_id: request.user_id.clone(),
        device_id: request.device_id.clone(),
        public_key_kid: request.public_key_kid.clone(),
        public_key_sha256: request.public_key_sha256.clone(),
        nonce: random_token(32),
        created_at: now.to_rfc3339(),
        expires_at: (now + Duration::seconds(ttl_seconds as i64)).to_rfc3339(),
        registration_id: request.registration_id.clone(),
        key_version: request.key_version,
        purpose: request.purpose.clone(),
        audience: CHALLENGE_AUDIENCE.into(),
        message_version: 2,
    }
}

fn encode(record: &DeviceChallengeRecord) -> Result<String, DeviceError> {
    serde_json::to_string(record).map_err(|error| DeviceError::ChallengeStore(error.to_string()))
}

fn decode(raw: &str) -> Result<DeviceChallengeRecord, DeviceError> {
    serde_json::from_str(raw).map_err(|error| DeviceError::ChallengeStore(error.to_string()))
}

#[derive(Debug, Clone)]
pub struct MemoryChallengeRepository {
    ttl_seconds: u64,
    records: Arc<Mutex<HashMap<String, String>>>,
}

impl MemoryChallengeRepository {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            ttl_seconds,
            records: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ChallengeRepository for MemoryChallengeRepository {
    async fn issue(&self, request: ChallengeIssue) -> Result<DeviceChallengeRecord, DeviceError> {
        for _ in 0..4 {
            let record = issue_record(self.ttl_seconds, &request);
            let mut records = self.records.lock().await;
            if !records.contains_key(&record.challenge_id) {
                records.insert(record.challenge_id.clone(), encode(&record)?);
                return Ok(record);
            }
        }
        Err(DeviceError::ChallengeStore(
            "could not allocate a unique device challenge".into(),
        ))
    }

    async fn get(&self, challenge_id: &str) -> Result<Option<DeviceChallengeRecord>, DeviceError> {
        let raw = self.records.lock().await.get(challenge_id).cloned();
        let Some(raw) = raw else { return Ok(None) };
        let record = decode(&raw)?;
        if record.is_expired_at(&Utc::now().to_rfc3339())? {
            self.consume(&record).await?;
            return Ok(None);
        }
        Ok(Some(record))
    }

    async fn consume(&self, record: &DeviceChallengeRecord) -> Result<bool, DeviceError> {
        let expected = encode(record)?;
        let mut records = self.records.lock().await;
        if records.get(&record.challenge_id) != Some(&expected) {
            return Ok(false);
        }
        records.remove(&record.challenge_id);
        Ok(true)
    }

    fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }
}

#[derive(Clone)]
pub struct RedisChallengeRepository {
    ttl_seconds: u64,
    connection: ConnectionManager,
}

impl std::fmt::Debug for RedisChallengeRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisChallengeRepository")
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

impl RedisChallengeRepository {
    pub async fn connect(url: &str, ttl_seconds: u64) -> Result<Self, DeviceError> {
        // redis-rs natively supports password-only URLs. Preserve that form;
        // adding an ACL username failed database selection against the beta
        // requirepass deployment.
        let client = redis::Client::open(url)
            .map_err(|error| DeviceError::ChallengeStore(error.to_string()))?;
        let mut connection = ConnectionManager::new(client)
            .await
            .map_err(|error| DeviceError::ChallengeStore(error.to_string()))?;
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await
            .map_err(|error| DeviceError::ChallengeStore(error.to_string()))?;
        Ok(Self {
            ttl_seconds,
            connection,
        })
    }
}

#[async_trait]
impl ChallengeRepository for RedisChallengeRepository {
    async fn issue(&self, request: ChallengeIssue) -> Result<DeviceChallengeRecord, DeviceError> {
        let mut connection = self.connection.clone();
        for _ in 0..4 {
            let record = issue_record(self.ttl_seconds, &request);
            let result: Option<String> = redis::cmd("SET")
                .arg(format!("{PREFIX}{}", record.challenge_id))
                .arg(encode(&record)?)
                .arg("EX")
                .arg(self.ttl_seconds)
                .arg("NX")
                .query_async(&mut connection)
                .await
                .map_err(|error| DeviceError::ChallengeStore(error.to_string()))?;
            if result.is_some() {
                return Ok(record);
            }
        }
        Err(DeviceError::ChallengeStore(
            "could not allocate a unique device challenge".into(),
        ))
    }

    async fn get(&self, challenge_id: &str) -> Result<Option<DeviceChallengeRecord>, DeviceError> {
        let mut connection = self.connection.clone();
        let raw: Option<String> = connection
            .get(format!("{PREFIX}{challenge_id}"))
            .await
            .map_err(|error| DeviceError::ChallengeStore(error.to_string()))?;
        let Some(raw) = raw else { return Ok(None) };
        let record = decode(&raw)?;
        if record.is_expired_at(&Utc::now().to_rfc3339())? {
            self.consume(&record).await?;
            return Ok(None);
        }
        Ok(Some(record))
    }

    async fn consume(&self, record: &DeviceChallengeRecord) -> Result<bool, DeviceError> {
        let mut connection = self.connection.clone();
        let result: i64 = Script::new(CONSUME)
            .key(format!("{PREFIX}{}", record.challenge_id))
            .arg(encode(record)?)
            .invoke_async(&mut connection)
            .await
            .map_err(|error| DeviceError::ChallengeStore(error.to_string()))?;
        Ok(result == 1)
    }

    fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn redis_client_preserves_password_only_authentication_and_database() {
        let client =
            redis::Client::open("redis://:secret@redis:6379/5").expect("password-only Redis URL");
        let settings = client.get_connection_info().redis_settings();
        assert_eq!(settings.username(), None);
        assert_eq!(settings.password(), Some("secret"));
        assert_eq!(settings.db(), 5);
    }
}
