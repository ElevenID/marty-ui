//! In-memory PG/OpenBao/Redis adapter for the same engine used by live bootstrap.

use std::collections::BTreeMap;

use mmf_aws_kms::AwsKmsConfig;
use serde_json::{json, Map, Value};

use crate::bootstrap::{public_jwk_from_pem, KeyRecord, KeySpec, NOTIFICATION_ENVELOPE_KEY};
use crate::bootstrap_engine::{self, Backend, Config, RunError, StampKind};

struct MemoryBackend<'a> {
    input: &'a Value,
    effects: Vec<String>,
    schemas: Vec<String>,
    mounted: bool,
    roles: Vec<String>,
    keys: Map<String, Value>,
    redis: Map<String, Value>,
    ping_failures: u64,
    fail_set: Option<String>,
}

impl MemoryBackend<'_> {
    fn role(&mut self, token: &str) {
        let role = match token {
            "fixture-token" => "service",
            "fixture-bao-token" => "bao",
            _ => "other",
        };
        if !self.roles.iter().any(|existing| existing == role) {
            self.roles.push(role.into());
        }
    }
}

impl Backend for MemoryBackend<'_> {
    async fn notification_aws(
        &mut self,
        _config: &AwsKmsConfig,
        _key_arn: &str,
    ) -> Result<(), String> {
        self.effects
            .push("aws-kms.describe-key:notification-envelope".into());
        if self.input["notification_aws_failure"] == true {
            Err("injected AWS notification key readiness failure".into())
        } else {
            Ok(())
        }
    }

    async fn verify_database(&mut self, _database_url: &str) -> Result<(), String> {
        if self.input["database_connect_failure"] == true {
            return Err("injected database connectivity failure".into());
        }
        Ok(())
    }

    async fn schemas(&mut self, _database: &str, schemas: &[&str]) -> Result<(), String> {
        let mut pending = vec![];
        for schema in schemas {
            if self.input["schema_failure"] == true && *schema == "notification_service" {
                self.effects
                    .push(format!("postgres.create_schema_failed:{schema}"));
                return Err("injected schema failure".into());
            }
            self.effects
                .push(format!("postgres.create_schema:{schema}"));
            if !self.schemas.iter().any(|existing| existing == schema) {
                pending.push((*schema).into());
            }
        }
        self.effects.push("postgres.commit".into());
        self.schemas.extend(pending);
        Ok(())
    }

    async fn mount(&mut self, _address: &str, token: &str) -> Result<(), String> {
        self.role(token);
        if !self.mounted {
            self.effects.push("openbao.post:sys/mounts/transit".into());
            self.mounted = true;
        }
        Ok(())
    }

    async fn symmetric(
        &mut self,
        _address: &str,
        token: &str,
        key: &str,
        description: &str,
    ) -> Result<(), String> {
        self.role(token);
        if let Some(data) = self.keys.get(key) {
            if data["type"] != "aes256-gcm96" || data["exportable"] != false {
                return Err(format!("OpenBao {description} key has unsafe attributes"));
            }
            return Ok(());
        }
        self.effects
            .push(format!("openbao.post:transit/keys/{key}"));
        if key == NOTIFICATION_ENVELOPE_KEY && self.input["deny_notification_create"] == true {
            return Err("injected OpenBao create failure".into());
        }
        self.keys.insert(
            key.into(),
            json!({"type":"aes256-gcm96", "exportable":false}),
        );
        Ok(())
    }

    async fn ping(&mut self, _redis_url: &str) -> Result<(), String> {
        self.effects.push("redis.ping".into());
        if self.ping_failures > 0 {
            self.ping_failures -= 1;
            Err("injected Redis ping failure".into())
        } else {
            Ok(())
        }
    }

    async fn sleep(&mut self, seconds: u64) {
        self.effects.push(format!("sleep:{seconds}"));
    }

    async fn key(
        &mut self,
        _address: &str,
        token: &str,
        spec: KeySpec,
        reference: &str,
        create: bool,
    ) -> Result<KeyRecord, String> {
        self.role(token);
        if let Some(data) = self.keys.get(reference) {
            if data["type"] != spec.key_type || data["exportable"] != false {
                return Err(format!(
                    "OpenBao key {reference} must have the expected type and be non-exportable"
                ));
            }
        } else if create {
            self.effects
                .push(format!("openbao.post:transit/keys/{reference}"));
            self.keys.insert(
                reference.into(),
                json!({"type":spec.key_type, "exportable":false}),
            );
        } else {
            return Err("Disposable ICAO key must be precreated and non-exportable".into());
        }
        let pem = self.input["public_pem_by_type"][spec.key_type]
            .as_str()
            .ok_or_else(|| format!("missing test public PEM for {}", spec.key_type))?;
        let mut public_jwk = public_jwk_from_pem(spec, pem).map_err(|error| error.to_string())?;
        public_jwk["kid"] = json!(reference);
        Ok(KeyRecord {
            spec,
            reference: reference.into(),
            public_jwk,
            latest_version: json!(1),
        })
    }

    async fn load(&mut self, key: &str) -> Result<Option<Value>, String> {
        Ok(self.redis.get(key).cloned().filter(Value::is_object))
    }

    async fn save(&mut self, key: &str, document: &Value) -> Result<(), String> {
        if self.fail_set.as_deref() == Some(key) {
            self.fail_set = None;
            self.effects.push(format!("redis.set_failed:{key}"));
            return Err("injected Redis write failure".into());
        }
        self.effects.push(format!("redis.set:{key}"));
        self.redis.insert(key.into(), document.clone());
        Ok(())
    }

    async fn slug(&mut self, key: &str, org: &str) -> Result<(), String> {
        self.effects.push(format!("redis.set:{key}"));
        self.redis.insert(key.into(), json!(org));
        Ok(())
    }

    fn stamp(&mut self, kind: StampKind, document: &mut Value) {
        const CLOCK: &str = "reference-time";
        match kind {
            StampKind::Registry => {
                if let Some(managed) = document["services"]
                    .as_array_mut()
                    .and_then(|values| values.first_mut())
                {
                    managed["created_at"] = json!(CLOCK);
                    managed["updated_at"] = json!(CLOCK);
                }
            }
            StampKind::IssuerDid | StampKind::Jwks => {
                document["updated_at"] = json!(CLOCK);
            }
            StampKind::SeededProfiles => {
                if let Some(profiles) = document["profiles"].as_array_mut() {
                    for profile in profiles {
                        if crate::bootstrap::STANDARD_PROFILES
                            .iter()
                            .any(|spec| profile["id"] == spec.id)
                        {
                            if profile.get("created_at").is_none() {
                                profile["created_at"] = json!(CLOCK);
                            }
                            profile["updated_at"] = json!(CLOCK);
                        }
                    }
                }
            }
        }
    }
}

fn normalize_reference_state(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("created_at");
            object.remove("updated_at");
            for child in object.values_mut() {
                normalize_reference_state(child);
            }
        }
        Value::Array(array) => {
            for child in array {
                normalize_reference_state(child);
            }
        }
        _ => {}
    }
}

fn tags(error: RunError) -> Vec<String> {
    match error {
        RunError::MissingDatabase => vec!["DATABASE_URL environment variable not set".into()],
        RunError::Database => vec!["Database connectivity verification failed".into()],
        RunError::Schemas(_) => vec!["Error creating schemas".into()],
        RunError::MissingNotificationKms => vec![
            "Notification webhook KMS preparation failed".into(),
            "OpenBao address/token are required".into(),
        ],
        RunError::Notification(_) => vec!["Notification webhook KMS preparation failed".into()],
        RunError::MissingIdentityKms | RunError::Identity(_) => {
            vec!["Failed Marty KMS/DID bootstrap".into()]
        }
    }
}

pub async fn replay(invocation: &Value) -> Result<Value, String> {
    let input = invocation.get("input").ok_or("missing input")?;
    let env = input["environment"]
        .as_object()
        .ok_or("missing environment")?;
    let environment: BTreeMap<String, String> = env
        .iter()
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.into())))
        .collect();
    let config = Config {
        environment,
        verify_only: input["verify_only"] == true,
    };
    let mut keys = Map::new();
    if input["unsafe_notification"] == true {
        keys.insert(
            NOTIFICATION_ENVELOPE_KEY.into(),
            json!({"type":"aes256-gcm96", "exportable":true}),
        );
    }
    if input["precreated_disposable"] == true {
        for spec in config.disposable(&config.org(), &config.did(), &config.url())? {
            keys.insert(
                spec.id.into(),
                json!({"type":spec.key_type, "exportable":false}),
            );
        }
    }
    if let Some(existing) = input["existing_openbao_keys"].as_object() {
        keys.extend(existing.clone());
    }
    let mut memory = MemoryBackend {
        input,
        effects: vec![],
        schemas: vec![],
        mounted: false,
        roles: vec![],
        keys,
        redis: input["initial_redis"]
            .as_object()
            .cloned()
            .unwrap_or_default(),
        ping_failures: input["ping_failures"].as_u64().unwrap_or(0),
        fail_set: input["fail_set"].as_str().map(str::to_owned),
    };
    let mut codes = vec![];
    let mut errors = vec![];
    for attempt in 0..input["runs"].as_u64().unwrap_or(1) {
        memory.effects.push(format!("run:{}", attempt + 1));
        match bootstrap_engine::run(&config, &mut memory).await {
            Ok(()) => codes.push(0),
            Err(error) => {
                codes.push(1);
                errors.extend(tags(error));
            }
        }
    }
    memory.schemas.sort();
    errors.sort();
    errors.dedup();
    for value in memory.redis.values_mut() {
        normalize_reference_state(value);
    }
    Ok(json!({ "exit_codes": codes, "effects": memory.effects,
        "state": { "postgres_schemas": memory.schemas, "openbao_mounted": memory.mounted,
            "openbao_token_roles_used": memory.roles, "openbao_keys": memory.keys, "redis": memory.redis },
        "error_tags": errors }))
}

#[cfg(test)]
mod tests {
    use super::replay;
    use serde_json::json;

    fn aws_notification_input() -> serde_json::Value {
        json!({
            "environment": {
                "DATABASE_URL": "postgresql://marty@postgres/marty",
                "MARTY_KMS_BOOTSTRAP_ENABLED": "false",
                "NOTIFICATION_SECRET_KMS_PROVIDER": "aws-kms",
                "NOTIFICATION_SECRET_AWS_REGION": "us-east-2",
                "NOTIFICATION_SECRET_AWS_KEY_ARN": "arn:aws:kms:us-east-2:111122223333:key/notification-envelope"
            }
        })
    }

    #[tokio::test]
    async fn aws_notification_readiness_precedes_disabled_issuer_seeding_without_openbao() {
        let input = aws_notification_input();
        let successful = replay(&json!({"input": input})).await.unwrap();
        assert_eq!(successful["exit_codes"], json!([0]));
        assert_eq!(
            successful["effects"].as_array().unwrap().last().unwrap(),
            "aws-kms.describe-key:notification-envelope"
        );
        assert_eq!(successful["state"]["openbao_mounted"], false);
        assert_eq!(successful["state"]["openbao_keys"], json!({}));
        assert_eq!(successful["state"]["openbao_token_roles_used"], json!([]));
        assert_eq!(successful["state"]["redis"], json!({}));

        let mut failed = aws_notification_input();
        failed["notification_aws_failure"] = json!(true);
        let result = replay(&json!({"input": failed})).await.unwrap();
        assert_eq!(result["exit_codes"], json!([1]));
        assert_eq!(
            result["error_tags"],
            json!(["Notification webhook KMS preparation failed"])
        );
        assert_eq!(result["state"]["openbao_mounted"], false);
    }

    #[tokio::test]
    async fn aws_notification_rejects_mixed_configuration_and_cannot_silently_skip_enabled_identity(
    ) {
        for (field, value) in [
            ("NOTIFICATION_OPENBAO_TOKEN", "unexpected-token"),
            ("NOTIFICATION_OPENBAO_TOKEN_FILE", "/unused/token"),
            ("NOTIFICATION_OPENBAO_CA_CERT_FILE", "/unused/ca.pem"),
            ("NOTIFICATION_SECRET_KMS_PROVIDER", "unknown"),
            ("NOTIFICATION_SECRET_AWS_KEY_ARN", "alias/notification"),
        ] {
            let mut input = aws_notification_input();
            input["environment"][field] = json!(value);
            let result = replay(&json!({"input": input})).await.unwrap();
            assert_eq!(result["exit_codes"], json!([1]));
            assert!(!result["effects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|effect| effect.as_str().unwrap().starts_with("aws-kms")
                    || effect.as_str().unwrap().starts_with("openbao")));
        }
        let mut input = aws_notification_input();
        input["environment"]["MARTY_KMS_BOOTSTRAP_ENABLED"] = json!("true");
        input["environment"]["REDIS_URL"] = json!("redis://redis/2");
        let result = replay(&json!({"input": input})).await.unwrap();
        assert_eq!(result["exit_codes"], json!([1]));
        assert_eq!(
            result["error_tags"],
            json!(["Failed Marty KMS/DID bootstrap"])
        );
        assert_eq!(result["state"]["redis"], json!({}));
    }

    #[tokio::test]
    async fn verify_only_checks_database_and_never_writes() {
        assert_eq!(
            super::RunError::Database.to_string(),
            "Database connectivity verification failed"
        );
        let successful = replay(&json!({"input": {
            "environment": {"DATABASE_URL": "postgresql://marty@postgres/marty"},
            "verify_only": true
        }}))
        .await
        .unwrap();
        assert_eq!(successful["exit_codes"], json!([0]));
        assert_eq!(successful["effects"], json!(["run:1"]));

        let disconnected = replay(&json!({"input": {
            "environment": {"DATABASE_URL": "postgresql://marty@postgres/marty"},
            "verify_only": true,
            "database_connect_failure": true
        }}))
        .await
        .unwrap();
        assert_eq!(disconnected["exit_codes"], json!([1]));
        assert_eq!(disconnected["effects"], json!(["run:1"]));
        assert_eq!(
            disconnected["error_tags"],
            json!(["Database connectivity verification failed"])
        );
    }

    #[tokio::test]
    async fn existing_exportable_standard_key_fails_closed() {
        let org = "00000000-0000-0000-0000-000000000001";
        let reference = crate::bootstrap::tenant_standard_key_reference(
            org,
            crate::bootstrap::STANDARD_KEYS[0].id,
        );
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/migration-bootstrap-python-reference.json"
        ))
        .unwrap();
        let clean = corpus["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "clean_apply")
            .unwrap();
        let mut input = clean["input"].clone();
        input["existing_openbao_keys"] = json!({
            reference: {"type":"ecdsa-p256", "exportable":true}
        });
        let result = replay(&json!({"input": input})).await.unwrap();
        assert_eq!(result["exit_codes"], json!([1]));
        assert!(!result["state"]["redis"]
            .as_object()
            .unwrap()
            .contains_key(&crate::bootstrap::signing_registry_key(org)));
    }
}
