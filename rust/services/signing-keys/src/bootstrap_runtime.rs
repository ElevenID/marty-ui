//! PostgreSQL, selected remote KMS, and Redis adapters for the bootstrap engine.

use std::{collections::BTreeMap, env, fs, path::Path, time::Duration};

use chrono::{SecondsFormat, Utc};
use marty_openbao_http::OpenBaoHttp;
use marty_service_runtime::SecretKmsSelection;
use mmf_aws_kms::{AwsKmsConfig, AwsKmsKey, KeyCapability};
use redis::AsyncCommands;
use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use sqlx::{Connection, PgConnection};

use crate::bootstrap::{public_jwk_from_openbao, KeyRecord, KeySpec, MANAGED_SERVICE_ID};
use crate::bootstrap_engine::{self, Backend, Config, RunError, StampKind};

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false)
}

fn secret(name: &str) -> String {
    let direct = env::var(name).unwrap_or_default();
    if !direct.is_empty() {
        return direct.trim().into();
    }
    let file = env::var(format!("{name}_FILE")).unwrap_or_default();
    if file.is_empty() {
        return String::new();
    }
    fs::read_to_string(file).unwrap_or_default().trim().into()
}

fn environment_values(
    verify_only: bool,
    mut read: impl FnMut(&str) -> Result<String, env::VarError>,
) -> Result<BTreeMap<String, String>, RunError> {
    let names = [
        "DATABASE_URL",
        "BAO_ADDR",
        "REDIS_URL",
        "REDIS_DB_GATEWAY",
        "MARTY_KMS_BOOTSTRAP_ENABLED",
        "MARTY_ORG_ID",
        "MARTY_ORG_SLUG",
        "MARTY_ISSUER_DID",
        "MARTY_ISSUER_BASE_URL",
        "ISSUER_BASE_URL",
        "PUBLIC_API_URL",
        "PUBLIC_DOMAIN",
        "PASSPORT_DISPOSABLE_ICAO_BOOTSTRAP",
        "PASSPORT_ACCEPTANCE_PROJECT",
        "PASSPORT_ACCEPTANCE_GATEWAY_PORT",
        "NOTIFICATION_SECRET_KMS_PROVIDER",
        "NOTIFICATION_SECRET_AWS_REGION",
        "NOTIFICATION_SECRET_AWS_KEY_ARN",
        "NOTIFICATION_OPENBAO_TOKEN",
        "NOTIFICATION_OPENBAO_TOKEN_FILE",
        "NOTIFICATION_OPENBAO_CA_CERT_FILE",
    ];
    let mut environment = BTreeMap::new();
    for name in names {
        match read(name) {
            Ok(value) => {
                environment.insert(name.into(), value);
            }
            Err(env::VarError::NotUnicode(_))
                if !verify_only && name.starts_with("NOTIFICATION_") =>
            {
                return Err(RunError::Notification(
                    "Notification KMS configuration must be valid Unicode".into(),
                ));
            }
            Err(_) => {}
        }
    }
    Ok(environment)
}

pub async fn run(verify_only: bool) -> Result<(), RunError> {
    let mut environment = environment_values(verify_only, |name| env::var(name))?;
    for name in ["OPENBAO_SERVICE_TOKEN", "BAO_TOKEN"] {
        environment.insert(name.into(), secret(name));
    }
    let mut config = Config {
        environment,
        verify_only,
    };
    let client = if verify_only {
        None
    } else {
        let notification = config.notification_kms().map_err(RunError::Notification)?;
        if notification == SecretKmsSelection::OpenBao {
            config.environment.insert(
                "NOTIFICATION_OPENBAO_TOKEN".into(),
                secret("NOTIFICATION_OPENBAO_TOKEN"),
            );
        }
        let address = config.get("BAO_ADDR");
        if notification == SecretKmsSelection::OpenBao
            || (config.enabled("MARTY_KMS_BOOTSTRAP_ENABLED") && !address.is_empty())
        {
            let ca_file = env::var("BAO_CACERT").ok();
            let transport = OpenBaoHttp::connect(
                address,
                ca_file.as_deref().map(Path::new),
                Duration::from_secs(8),
            )
            .map_err(RunError::Identity)?;
            Some(transport.client().clone())
        } else {
            None
        }
    };
    bootstrap_engine::run(&config, &mut LiveBackend::new(client)).await
}

struct LiveBackend {
    client: Option<Client>,
    redis: Option<redis::aio::MultiplexedConnection>,
}

impl LiveBackend {
    fn new(client: Option<Client>) -> Self {
        Self {
            client,
            redis: None,
        }
    }

    async fn bao(
        &self,
        method: Method,
        address: &str,
        token: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        let mut request = self
            .client
            .as_ref()
            .ok_or("OpenBao bootstrap transport is not configured")?
            .request(
                method,
                format!(
                    "{}/v1/{}",
                    address.trim_end_matches('/'),
                    path.trim_start_matches('/')
                ),
            )
            .header("X-Vault-Token", token)
            .timeout(Duration::from_secs(8));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "HTTP {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(json!({}));
        }
        let bytes = response.bytes().await.map_err(|error| error.to_string())?;
        if bytes.is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())
    }

    async fn bao_key(
        &self,
        address: &str,
        token: &str,
        key: &str,
    ) -> Result<Option<Value>, String> {
        match self
            .bao(
                Method::GET,
                address,
                token,
                &format!("transit/keys/{key}"),
                None,
            )
            .await
        {
            Ok(response) => Ok(response.get("data").cloned()),
            Err(error) if error.starts_with("HTTP 404") => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn redis(&mut self) -> Result<&mut redis::aio::MultiplexedConnection, String> {
        self.redis
            .as_mut()
            .ok_or_else(|| "Redis connection was not established".into())
    }
}

#[cfg(test)]
impl Default for LiveBackend {
    fn default() -> Self {
        Self::new(Some(Client::new()))
    }
}

impl Backend for LiveBackend {
    async fn notification_aws(
        &mut self,
        config: &AwsKmsConfig,
        key_arn: &str,
    ) -> Result<(), String> {
        tokio::time::timeout(config.request_timeout, async {
            let key = AwsKmsKey::connect(config.clone(), key_arn.into())
                .await
                .map_err(|_| "AWS notification KMS is unavailable".to_owned())?;
            key.validate(KeyCapability::SymmetricEncryption)
                .await
                .map(|_| ())
                .map_err(|_| "AWS notification KMS key is unavailable or unsuitable".to_owned())
        })
        .await
        .map_err(|_| "AWS notification KMS readiness timed out".to_owned())?
    }

    async fn verify_database(&mut self, database_url: &str) -> Result<(), String> {
        let mut connection = PgConnection::connect(database_url)
            .await
            .map_err(|error| error.to_string())?;
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&mut connection)
            .await
            .map_err(|error| error.to_string())?;
        connection.close().await.map_err(|error| error.to_string())
    }

    async fn schemas(&mut self, database_url: &str, schemas: &[&str]) -> Result<(), String> {
        let mut connection = PgConnection::connect(database_url)
            .await
            .map_err(|error| error.to_string())?;
        sqlx::query("BEGIN")
            .execute(&mut connection)
            .await
            .map_err(|error| error.to_string())?;
        // Identifiers are literals; sqlx 0.9 rejects dynamic SQL unless explicitly audited.
        for schema in schemas {
            let statement = match *schema {
                "organization_service" => "CREATE SCHEMA IF NOT EXISTS organization_service",
                "auth_service" => "CREATE SCHEMA IF NOT EXISTS auth_service",
                "credential_template_service" => {
                    "CREATE SCHEMA IF NOT EXISTS credential_template_service"
                }
                "issuance_service" => "CREATE SCHEMA IF NOT EXISTS issuance_service",
                "presentation_policy_service" => {
                    "CREATE SCHEMA IF NOT EXISTS presentation_policy_service"
                }
                "notification_service" => "CREATE SCHEMA IF NOT EXISTS notification_service",
                "device_registration_service" => {
                    "CREATE SCHEMA IF NOT EXISTS device_registration_service"
                }
                "revocation_profile_service" => {
                    "CREATE SCHEMA IF NOT EXISTS revocation_profile_service"
                }
                unknown => return Err(format!("unsupported shared schema: {unknown}")),
            };
            sqlx::query(statement)
                .execute(&mut connection)
                .await
                .map_err(|error| error.to_string())?;
        }
        sqlx::query("COMMIT")
            .execute(&mut connection)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn mount(&mut self, address: &str, token: &str) -> Result<(), String> {
        match self
            .bao(Method::GET, address, token, "sys/mounts", None)
            .await
        {
            Ok(mounts) if mounts["data"].get("transit/").is_some() => Ok(()),
            Ok(_) => match self
                .bao(
                    Method::POST,
                    address,
                    token,
                    "sys/mounts/transit",
                    Some(json!({"type":"transit"})),
                )
                .await
            {
                Ok(_) => Ok(()),
                Err(error) if error.starts_with("HTTP 400") || error.starts_with("HTTP 403") => {
                    Ok(())
                }
                Err(error) => Err(error),
            },
            Err(error) if error.starts_with("HTTP 400") || error.starts_with("HTTP 403") => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn symmetric(
        &mut self,
        address: &str,
        token: &str,
        key: &str,
        description: &str,
    ) -> Result<(), String> {
        if let Some(data) = self.bao_key(address, token, key).await? {
            if data["type"] != "aes256-gcm96" || data["exportable"] != false {
                return Err(format!("OpenBao {description} key has unsafe attributes"));
            }
            return Ok(());
        }
        self.bao(
            Method::POST,
            address,
            token,
            &format!("transit/keys/{key}"),
            Some(json!({"type":"aes256-gcm96", "exportable":false})),
        )
        .await?;
        Ok(())
    }

    async fn ping(&mut self, redis_url: &str) -> Result<(), String> {
        let client = redis::Client::open(redis_url).map_err(|error| error.to_string())?;
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|error| error.to_string())?;
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await
            .map_err(|error| error.to_string())?;
        self.redis = Some(connection);
        Ok(())
    }

    async fn sleep(&mut self, seconds: u64) {
        tokio::time::sleep(Duration::from_secs(seconds)).await;
    }

    async fn key(
        &mut self,
        address: &str,
        token: &str,
        spec: KeySpec,
        reference: &str,
        create: bool,
    ) -> Result<KeyRecord, String> {
        let mut data = self.bao_key(address, token, reference).await?;
        if data.is_none() && create {
            self.bao(
                Method::POST,
                address,
                token,
                &format!("transit/keys/{reference}"),
                Some(json!({"type":spec.key_type})),
            )
            .await?;
            data = self.bao_key(address, token, reference).await?;
        }
        let data = data.ok_or_else(|| format!("OpenBao key {reference} is missing"))?;
        if data["type"] != spec.key_type || data["exportable"] != false {
            return Err(format!(
                "OpenBao key {reference} must have the expected type and be non-exportable"
            ));
        }
        let versions = data["keys"]
            .as_object()
            .filter(|values| !values.is_empty())
            .ok_or_else(|| format!("OpenBao key {reference} has no public key versions"))?;
        let latest = data.get("latest_version").cloned().unwrap_or(Value::Null);
        let version = if latest.is_null() || latest == 0 || latest == "" {
            versions
                .keys()
                .filter_map(|key| key.parse::<u64>().ok())
                .max()
                .ok_or_else(|| format!("OpenBao key {reference} has no public key versions"))?
                .to_string()
        } else {
            latest
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| latest.to_string())
        };
        let material = data["keys"][&version]["public_key"]
            .as_str()
            .ok_or_else(|| {
                format!(
                    "OpenBao key {} does not expose public key material",
                    reference
                )
            })?;
        let mut public_jwk =
            public_jwk_from_openbao(spec, material).map_err(|error| error.to_string())?;
        public_jwk["kid"] = json!(reference);
        Ok(KeyRecord {
            spec,
            reference: reference.into(),
            public_jwk,
            latest_version: latest,
        })
    }

    async fn load(&mut self, key: &str) -> Result<Option<Value>, String> {
        let value: Option<Vec<u8>> = self
            .redis()?
            .get(key)
            .await
            .map_err(|error| error.to_string())?;
        Ok(decode_json_document(value.as_deref()))
    }

    async fn save(&mut self, key: &str, document: &Value) -> Result<(), String> {
        let payload = serde_json::to_string(&document).map_err(|error| error.to_string())?;
        self.redis()?
            .set::<_, _, ()>(key, payload)
            .await
            .map_err(|error| error.to_string())
    }

    async fn slug(&mut self, key: &str, org: &str) -> Result<(), String> {
        self.redis()?
            .set::<_, _, ()>(key, org)
            .await
            .map_err(|error| error.to_string())
    }

    fn stamp(&mut self, kind: StampKind, document: &mut Value) {
        match kind {
            StampKind::Registry => {
                if let Some(service) = document["services"]
                    .as_array_mut()
                    .and_then(|values| values.first_mut())
                {
                    if service["id"] == MANAGED_SERVICE_ID {
                        service["created_at"] = json!(now());
                        service["updated_at"] = json!(now());
                    }
                }
            }
            StampKind::IssuerDid | StampKind::Jwks => {
                document["updated_at"] = json!(now());
            }
            StampKind::SeededProfiles => {
                if let Some(profiles) = document["profiles"].as_array_mut() {
                    for profile in profiles {
                        if crate::bootstrap::STANDARD_PROFILES
                            .iter()
                            .any(|spec| profile["id"] == spec.id)
                        {
                            if profile.get("created_at").is_none() {
                                profile["created_at"] = json!(now());
                            }
                            profile["updated_at"] = json!(now());
                        }
                    }
                }
            }
        }
    }
}

fn decode_json_document(bytes: Option<&[u8]>) -> Option<Value> {
    bytes
        .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
        .filter(Value::is_object)
}

#[cfg(test)]
mod tests {
    use super::{decode_json_document, environment_values, LiveBackend, OpenBaoHttp};
    use crate::bootstrap_engine::{Backend, RunError, StampKind};
    use reqwest::Method;
    use serde_json::json;
    use std::{env, path::Path, time::Duration};

    #[test]
    fn malformed_notification_environment_cannot_silently_select_openbao() {
        for malformed in [
            "NOTIFICATION_SECRET_KMS_PROVIDER",
            "NOTIFICATION_SECRET_AWS_REGION",
            "NOTIFICATION_SECRET_AWS_KEY_ARN",
            "NOTIFICATION_OPENBAO_TOKEN_FILE",
        ] {
            let read = |name: &str| {
                if name == malformed {
                    Err(env::VarError::NotUnicode("redacted-invalid-value".into()))
                } else {
                    Err(env::VarError::NotPresent)
                }
            };
            assert!(matches!(
                environment_values(false, read),
                Err(RunError::Notification(_))
            ));
            // Database-only verification never activates either provider.
            assert!(environment_values(true, read).unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn aws_notification_readiness_is_read_only_and_checks_native_key_custody() {
        use axum::{
            body::{to_bytes, Body},
            extract::Request,
            routing::post,
            Json, Router,
        };
        use mmf_aws_kms::{AwsAuth, AwsKmsConfig};
        use serde_json::Value;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        };

        const ARN: &str = "arn:aws:kms:us-east-2:111122223333:key/bootstrap-notification";
        let native_origin = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let handler_origin = native_origin.clone();
        let handler_calls = calls.clone();
        let app = Router::new().route(
            "/",
            post(move |request: Request<Body>| {
                let origin = handler_origin.clone();
                let calls = handler_calls.clone();
                async move {
                    assert_eq!(request.headers()["x-amz-target"], "TrentService.DescribeKey");
                    assert_eq!(
                        request.headers()["content-type"],
                        "application/x-amz-json-1.1"
                    );
                    let body: Value = serde_json::from_slice(
                        &to_bytes(request.into_body(), 20_000).await.unwrap(),
                    )
                    .unwrap();
                    calls.lock().unwrap().push(body);
                    Json(json!({"KeyMetadata": {
                        "Arn": ARN, "KeyId": "bootstrap-notification",
                        "Enabled": true, "KeyState": "Enabled",
                        "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT",
                        "Origin": if origin.load(Ordering::Acquire) { "AWS_KMS" } else { "EXTERNAL" },
                        "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"]
                    }}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
        let config = AwsKmsConfig {
            region: "us-east-2".into(),
            authentication: AwsAuth::AccessKey {
                access_key_id: "test-only-explicit-key".into(),
                secret_access_key: "test-only-secret".into(),
                session_token: None,
            },
            endpoint: Some(endpoint),
            request_timeout: Duration::from_secs(2),
        };
        let mut backend = LiveBackend::new(None);
        backend.notification_aws(&config, ARN).await.unwrap();
        native_origin.store(false, Ordering::Release);
        assert!(backend.notification_aws(&config, ARN).await.is_err());
        assert_eq!(
            *calls.lock().unwrap(),
            vec![json!({"KeyId": ARN}), json!({"KeyId": ARN})]
        );
        assert!(backend.client.is_none());
        assert!(backend.redis.is_none());
        server.abort();
    }

    #[tokio::test]
    #[ignore = "requires a guarded disposable HTTPS OpenBao instance"]
    async fn live_migration_openbao_transport_is_ca_verified() {
        let address = env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
        let parsed = reqwest::Url::parse(&address).expect("disposable OpenBao URL syntax");
        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("127.0.0.1"));
        assert_eq!(env::var("BAO_ADDR").as_deref(), Ok(address.as_str()));
        let ca_file = env::var("BAO_CACERT").expect("disposable OpenBao public CA");
        let transport =
            OpenBaoHttp::connect(&address, Some(Path::new(&ca_file)), Duration::from_secs(8))
                .expect("CA-verified OpenBao transport");
        let adapter = LiveBackend::new(Some(transport.client().clone()));
        let root_token = env::var("MARTY_TEST_OPENBAO_ROOT_TOKEN").expect("disposable guard token");
        let nonce =
            env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE").expect("disposable guard nonce");
        assert!(nonce.len() >= 16);
        let marker = adapter
            .bao(
                Method::GET,
                &address,
                &root_token,
                "secret/data/marty-test-disposable-guard",
                None,
            )
            .await
            .expect("read disposable guard through migration adapter");
        assert_eq!(marker["data"]["data"]["nonce"], nonce);
    }

    #[test]
    fn malformed_or_non_utf8_redis_documents_use_seed_default() {
        assert_eq!(decode_json_document(Some(b"{broken")), None);
        assert_eq!(decode_json_document(Some(&[0xff, 0xfe])), None);
        assert_eq!(
            decode_json_document(Some(br#"{"ok":true}"#)),
            Some(json!({"ok":true}))
        );
    }

    #[test]
    fn timestamp_stamping_preserves_customer_and_backfill_metadata() {
        let mut adapter = LiveBackend::default();
        let mut profiles = json!({"profiles": [
            {"id":"customer-profile", "status":"active", "updated_at":"customer-time"},
            {"id":"ip-marty-vc-jwt-issuer", "created_at":"seed-created"}
        ]});
        adapter.stamp(StampKind::SeededProfiles, &mut profiles);
        assert_eq!(profiles["profiles"][0]["updated_at"], "customer-time");
        assert!(profiles["profiles"][0].get("created_at").is_none());
        assert_eq!(profiles["profiles"][1]["created_at"], "seed-created");
        assert!(profiles["profiles"][1]["updated_at"].is_string());
    }
}
