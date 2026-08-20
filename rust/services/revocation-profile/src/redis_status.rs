use crate::status::{StatusError, StatusListFormat, StatusListRecord, StatusRepository};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use redis::{aio::ConnectionManager, AsyncCommands, Script};
use serde::{Deserialize, Serialize};

const DEFAULT_KEY_PREFIX: &str = "marty:revocation";
const MAX_CAS_ATTEMPTS: usize = 16;

const ALLOCATE_INDEX_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then
  current = 0
else
  current = tonumber(current)
end
local size = tonumber(ARGV[1])
if current >= size then
  return -1
end
redis.call('SET', KEYS[1], current + 1)
return current
"#;

const ADVANCE_ALLOCATION_FLOOR_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
local requested = tonumber(ARGV[1])
if not current or tonumber(current) < requested then
  redis.call('SET', KEYS[1], requested)
end
return 1
"#;

const COMPARE_AND_SWAP_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if current == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2])
  return 1
end
return 0
"#;

#[derive(Clone)]
pub struct RedisStatusRepository {
    connection: ConnectionManager,
    key_prefix: String,
}

impl std::fmt::Debug for RedisStatusRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisStatusRepository")
            .field("key_prefix", &self.key_prefix)
            .finish_non_exhaustive()
    }
}

impl RedisStatusRepository {
    pub async fn connect(redis_url: &str) -> Result<Self, StatusError> {
        let client = redis::Client::open(redis_url).map_err(redis_error)?;
        let connection = client.get_connection_manager().await.map_err(redis_error)?;
        Ok(Self {
            connection,
            key_prefix: DEFAULT_KEY_PREFIX.into(),
        })
    }

    pub fn from_connection(connection: ConnectionManager) -> Self {
        Self {
            connection,
            key_prefix: DEFAULT_KEY_PREFIX.into(),
        }
    }

    pub fn with_key_prefix(mut self, key_prefix: impl Into<String>) -> Self {
        self.key_prefix = key_prefix.into().trim_end_matches(':').to_string();
        self
    }

    fn status_key(&self, scope: &str, format: StatusListFormat) -> String {
        format!(
            "{}:{{{scope}}}:status_list:{}",
            self.key_prefix,
            format_name(format)
        )
    }

    fn next_index_key(&self, scope: &str, format: StatusListFormat) -> String {
        format!("{}:next_index", self.status_key(scope, format))
    }

    async fn load_raw(
        &self,
        scope: &str,
        format: StatusListFormat,
    ) -> Result<Option<Vec<u8>>, StatusError> {
        let mut connection = self.connection.clone();
        connection
            .get(self.status_key(scope, format))
            .await
            .map_err(redis_error)
    }

    async fn create_if_absent(&self, record: &StatusListRecord) -> Result<bool, StatusError> {
        let serialized = serialize_record(record)?;
        let mut connection = self.connection.clone();
        let response: Option<String> = redis::cmd("SET")
            .arg(self.status_key(&record.scope, record.format))
            .arg(serialized)
            .arg("NX")
            .query_async(&mut connection)
            .await
            .map_err(redis_error)?;
        Ok(response.as_deref() == Some("OK"))
    }
}

#[async_trait]
impl StatusRepository for RedisStatusRepository {
    async fn get_or_create(
        &self,
        scope: &str,
        format: StatusListFormat,
        size: usize,
    ) -> Result<StatusListRecord, StatusError> {
        if let Some(raw) = self.load_raw(scope, format).await? {
            return deserialize_record(&raw, scope, format, size);
        }

        let record = StatusListRecord::empty(scope.to_string(), format, size)?;
        if self.create_if_absent(&record).await? {
            return Ok(record);
        }
        let raw = self
            .load_raw(scope, format)
            .await?
            .ok_or_else(|| StatusError::Repository("status-list create race lost data".into()))?;
        deserialize_record(&raw, scope, format, size)
    }

    async fn allocate_index(
        &self,
        scope: &str,
        format: StatusListFormat,
        size: usize,
    ) -> Result<usize, StatusError> {
        self.get_or_create(scope, format, size).await?;
        let mut connection = self.connection.clone();
        let allocated: i64 = Script::new(ALLOCATE_INDEX_SCRIPT)
            .key(self.next_index_key(scope, format))
            .arg(size)
            .invoke_async(&mut connection)
            .await
            .map_err(redis_error)?;
        if allocated < 0 {
            return Err(StatusError::Full(scope.to_string()));
        }
        usize::try_from(allocated)
            .map_err(|_| StatusError::Repository("allocated index is invalid".into()))
    }

    async fn allocation_floor(
        &self,
        scope: &str,
        format: StatusListFormat,
    ) -> Result<usize, StatusError> {
        let mut connection = self.connection.clone();
        let value: Option<i64> = connection
            .get(self.next_index_key(scope, format))
            .await
            .map_err(redis_error)?;
        match value {
            Some(value) => usize::try_from(value)
                .map_err(|_| StatusError::Repository("allocation floor is invalid".into())),
            None => Ok(0),
        }
    }

    async fn advance_allocation_floor(
        &self,
        scope: &str,
        format: StatusListFormat,
        next_index: usize,
    ) -> Result<(), StatusError> {
        let mut connection = self.connection.clone();
        Script::new(ADVANCE_ALLOCATION_FLOOR_SCRIPT)
            .key(self.next_index_key(scope, format))
            .arg(next_index)
            .invoke_async::<i64>(&mut connection)
            .await
            .map_err(redis_error)?;
        Ok(())
    }

    async fn set_status(
        &self,
        scope: &str,
        format: StatusListFormat,
        size: usize,
        index: usize,
        status: u8,
    ) -> Result<StatusListRecord, StatusError> {
        self.get_or_create(scope, format, size).await?;
        let key = self.status_key(scope, format);

        for _ in 0..MAX_CAS_ATTEMPTS {
            let raw = self
                .load_raw(scope, format)
                .await?
                .ok_or_else(|| StatusError::Repository("status list disappeared".into()))?;
            let mut record = deserialize_record(&raw, scope, format, size)?;
            record.set(index, status)?;
            let replacement = serialize_record(&record)?;
            let mut connection = self.connection.clone();
            let swapped: i64 = Script::new(COMPARE_AND_SWAP_SCRIPT)
                .key(&key)
                .arg(&raw)
                .arg(replacement)
                .invoke_async(&mut connection)
                .await
                .map_err(redis_error)?;
            if swapped == 1 {
                return Ok(record);
            }
        }
        Err(StatusError::Repository(format!(
            "status-list update conflicted after {MAX_CAS_ATTEMPTS} attempts"
        )))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredStatusList {
    id: String,
    tenant_id: String,
    format: String,
    size: usize,
    bits_per_status: u8,
    data: String,
    version: u64,
    published_at: Option<DateTime<Utc>>,
    url: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn serialize_record(record: &StatusListRecord) -> Result<Vec<u8>, StatusError> {
    serde_json::to_vec(&StoredStatusList {
        id: record.id.clone(),
        tenant_id: record.scope.clone(),
        format: format_name(record.format).into(),
        size: record.size,
        bits_per_status: record.bits_per_status,
        data: STANDARD.encode(&record.data),
        version: record.version,
        published_at: record.published_at,
        url: record.url.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    })
    .map_err(storage_json_error)
}

fn deserialize_record(
    raw: &[u8],
    expected_scope: &str,
    expected_format: StatusListFormat,
    expected_size: usize,
) -> Result<StatusListRecord, StatusError> {
    let stored: StoredStatusList = serde_json::from_slice(raw).map_err(storage_json_error)?;
    let format = parse_format(&stored.format)?;
    if stored.tenant_id != expected_scope || format != expected_format {
        return Err(StatusError::Repository(
            "persisted status-list identity does not match its key".into(),
        ));
    }
    if stored.size != expected_size {
        return Err(StatusError::Repository(format!(
            "stored size {} differs from configured size {expected_size}",
            stored.size
        )));
    }
    let expected_bits = match format {
        StatusListFormat::Bitstring => 1,
        StatusListFormat::TokenStatusList => 8,
    };
    if stored.bits_per_status != expected_bits {
        return Err(StatusError::Repository(
            "persisted bits-per-status does not match format".into(),
        ));
    }
    let record = StatusListRecord {
        id: stored.id,
        scope: stored.tenant_id,
        format,
        size: stored.size,
        bits_per_status: stored.bits_per_status,
        data: STANDARD
            .decode(stored.data)
            .map_err(|error| StatusError::Repository(error.to_string()))?,
        version: stored.version,
        published_at: stored.published_at,
        url: stored.url,
        created_at: stored.created_at,
        updated_at: stored.updated_at,
    };
    // Construction validates the exact byte length before any operation can use
    // persisted state. This is a compatibility check, not a second kernel.
    record.get(0)?;
    Ok(record)
}

fn format_name(format: StatusListFormat) -> &'static str {
    match format {
        StatusListFormat::Bitstring => "bitstring",
        StatusListFormat::TokenStatusList => "token_status_list",
    }
}

fn parse_format(value: &str) -> Result<StatusListFormat, StatusError> {
    match value {
        "bitstring" => Ok(StatusListFormat::Bitstring),
        "token_status_list" => Ok(StatusListFormat::TokenStatusList),
        _ => Err(StatusError::Repository(format!(
            "unknown persisted status-list format: {value}"
        ))),
    }
}

fn redis_error(error: impl std::fmt::Display) -> StatusError {
    StatusError::Repository(error.to_string())
}

fn storage_json_error(error: impl std::fmt::Display) -> StatusError {
    StatusError::Repository(format!("invalid persisted status-list JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_status::W3C_MIN_STATUS_LIST_BITS;

    #[test]
    fn python_storage_shape_roundtrips() {
        let mut record = StatusListRecord::empty(
            "org-a:profile-a".into(),
            StatusListFormat::Bitstring,
            W3C_MIN_STATUS_LIST_BITS,
        )
        .unwrap();
        record.set(7, 1).unwrap();
        let encoded = serialize_record(&record).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["tenant_id"], "org-a:profile-a");
        assert_eq!(value["format"], "bitstring");
        assert!(value["data"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        let restored = deserialize_record(
            &encoded,
            "org-a:profile-a",
            StatusListFormat::Bitstring,
            W3C_MIN_STATUS_LIST_BITS,
        )
        .unwrap();
        assert_eq!(restored.get(7).unwrap(), 1);
    }

    #[test]
    fn malformed_or_cross_scope_state_fails_closed() {
        assert!(deserialize_record(
            br#"{}"#,
            "org-a:profile-a",
            StatusListFormat::Bitstring,
            W3C_MIN_STATUS_LIST_BITS,
        )
        .is_err());
        let record = StatusListRecord::empty(
            "org-a:profile-a".into(),
            StatusListFormat::Bitstring,
            W3C_MIN_STATUS_LIST_BITS,
        )
        .unwrap();
        assert!(deserialize_record(
            &serialize_record(&record).unwrap(),
            "org-b:profile-a",
            StatusListFormat::Bitstring,
            W3C_MIN_STATUS_LIST_BITS,
        )
        .is_err());
    }
}
