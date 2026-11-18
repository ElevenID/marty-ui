//! Canonical service expectations shared by rendered and observed deployment policy.
use crate::passport_model::{require, PolicyResult};
use serde_json::{json, Map, Value};
use std::sync::LazyLock;
static EXPECTED: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(r#"{
  "organization": {
    "SERVICE_NAME": "organization",
    "ORGANIZATION_SERVICE_PORT": "8002",
    "ORG_GRPC_PORT": "9002",
    "DATABASE_URL_TEMPLATE": "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
    "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
    "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
    "ES_GRPC_TARGET": "https://event-stream:9015",
    "ES_GRPC_CA_CERT": "/run/secrets/workload_identity_ca_cert",
    "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
    "PASSPORT_ACCEPTANCE_PROJECT": "__PROJECT__",
    "PASSPORT_ACCEPTANCE_RUN_ID": "__RUN_ID__",
    "PASSPORT_ACCEPTANCE_SOURCE_COMMIT": "__SOURCE__",
    "PASSPORT_ACCEPTANCE_EXPIRES_AT": "__EXPIRY__"
  },
  "revocation-profile": {
    "SERVICE_NAME": "revocation_profile",
    "ENVIRONMENT": "development",
    "REVOCATION_PROFILE_SERVICE_PORT": "8013",
    "RP_GRPC_ENABLED": "true",
    "RP_GRPC_PORT": "9013",
    "DATABASE_URL_TEMPLATE": "postgresql://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
    "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
    "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
    "REDIS_URL": "redis://redis:6379/4",
    "ORG_GRPC_TARGET": "https://organization:9002",
    "ORG_GRPC_CA_CERT": "/run/secrets/workload_identity_ca_cert",
    "PUBLIC_API_URL": "http://gateway:8000",
    "STATUS_LIST_BASE_URL": "https://localhost:__PORT__",
    "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001"
  },
  "compliance-profile": {
    "ENVIRONMENT": "development",
    "DATABASE_URL_TEMPLATE": "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
    "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
    "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
    "ORG_GRPC_TARGET": "https://organization:9002",
    "SERVICE_NAME": "compliance_profile",
    "COMPLIANCE_PROFILE_SERVICE_PORT": "8008",
    "GRPC_WORKLOAD_TLS_CLIENT_CERT": "/run/secrets/compliance_profile_workload_client_cert",
    "GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert",
    "GRPC_WORKLOAD_TLS_KMS_ADDR": "https://openbao:8200",
    "GRPC_WORKLOAD_TLS_KMS_CA_CERT": "/bao/public-ca/ca.crt",
    "GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE": "/run/secrets/compliance_profile_workload_client_kms_token",
    "GRPC_WORKLOAD_TLS_KMS_KEY_NAME": "__PROJECT__-compliance-profile-client",
    "GRPC_WORKLOAD_TLS_KMS_KEY_VERSION": "1"
  },
  "trust-profile": {
    "ENVIRONMENT": "development",
    "DATABASE_URL_TEMPLATE": "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
    "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
    "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
    "ORG_GRPC_TARGET": "https://organization:9002",
    "SERVICE_NAME": "trust_profile",
    "TRUST_PROFILE_SERVICE_PORT": "8004",
    "SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/signing_keys_internal_api_key",
    "MARTY_ISSUER_DID": "did:web:localhost%3A__PORT__:orgs:marty",
    "MARTY_ISSUER_BASE_URL": "https://localhost:__PORT__",
    "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
    "MARTY_ORG_SLUG": "marty",
    "PUBLIC_DOMAIN": "localhost:__PORT__",
    "DID_RESOLUTION_BASE_URL": "http://gateway:8000",
    "ORG_GRPC_CA_CERT": "/run/secrets/workload_identity_ca_cert"
  },
  "credential-template": {
    "ENVIRONMENT": "development",
    "DATABASE_URL_TEMPLATE": "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
    "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
    "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
    "ORG_GRPC_TARGET": "https://organization:9002",
    "SERVICE_NAME": "credential_template",
    "CREDENTIAL_TEMPLATE_SERVICE_PORT": "8003",
    "CT_GRPC_PORT": "9003",
    "ORG_GRPC_CA_CERT": "/run/secrets/workload_identity_ca_cert",
    "RP_GRPC_TARGET": "https://revocation-profile:9013",
    "RP_GRPC_CA_CERT": "/run/secrets/workload_identity_ca_cert",
    "SIGNING_KEYS_INTERNAL_URL": "http://gateway:8000/internal/signing-keys",
    "SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/signing_keys_internal_api_key",
    "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
    "PUBLIC_API_URL": "https://localhost:__PORT__",
    "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
    "MARTY_MIGRATION_PROFILE": "dev"
  },
  "presentation-policy": {
    "ENVIRONMENT": "development",
    "DATABASE_URL_TEMPLATE": "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
    "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
    "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
    "ORG_GRPC_TARGET": "https://organization:9002",
    "SERVICE_NAME": "presentation_policy",
    "PRESENTATION_POLICY_SERVICE_PORT": "8009",
    "PP_GRPC_PORT": "9009",
    "ISSUANCE_API_KEY_FILE": "/run/secrets/issuance_api_key",
    "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
    "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
    "PUBLIC_BASE_URL": "https://localhost:__PORT__",
    "ISSUER_BASE_URL": "https://localhost:__PORT__",
    "DID_RESOLUTION_BASE_URL": "http://gateway:8000",
    "PUBLIC_DOMAIN": "localhost:__PORT__",
    "MARTY_ORG_SLUG": "marty",
    "ORG_GRPC_CA_CERT": "/run/secrets/workload_identity_ca_cert",
    "GRPC_WORKLOAD_TLS_SERVER_CERT": "/run/secrets/pp_workload_server_cert",
    "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR": "https://openbao:8200",
    "GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT": "/bao/public-ca/ca.crt",
    "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE": "/run/secrets/pp_workload_server_kms_token",
    "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME": "__PROJECT__-pp-server",
    "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION": "1",
    "GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert"
  },
  "deployment-profile": {
    "ENVIRONMENT": "development",
    "DATABASE_URL_TEMPLATE": "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
    "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
    "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
    "ORG_GRPC_TARGET": "https://organization:9002",
    "SERVICE_NAME": "deployment_profile",
    "DEPLOYMENT_PROFILE_SERVICE_PORT": "8010",
    "GRPC_WORKLOAD_TLS_CLIENT_CERT": "/run/secrets/deployment_profile_workload_client_cert",
    "GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert",
    "GRPC_WORKLOAD_TLS_KMS_ADDR": "https://openbao:8200",
    "GRPC_WORKLOAD_TLS_KMS_CA_CERT": "/bao/public-ca/ca.crt",
    "GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE": "/run/secrets/deployment_profile_workload_client_kms_token",
    "GRPC_WORKLOAD_TLS_KMS_KEY_NAME": "__PROJECT__-deployment-profile-client",
    "GRPC_WORKLOAD_TLS_KMS_KEY_VERSION": "1"
  },
  "flow": {
    "FLOW_CALLBACK_DESTINATIONS": "00000000-0000-0000-0000-000000000001|https://edge:8443/__disposable/flow-callback?nonce=__MARTY_TOKEN__",
    "FLOW_WEBHOOK_SECRET_FILE": "/run/secrets/flow_webhook_secret",
    "FLOW_CALLBACK_CA_CERT_FILE": "/run/secrets/workload_identity_ca_cert",
    "GRPC_WORKLOAD_TLS_CLIENT_CERT": "/run/secrets/flow_workload_client_cert",
    "GRPC_WORKLOAD_TLS_CLIENT_KMS_ADDR": "https://openbao:8200",
    "GRPC_WORKLOAD_TLS_CLIENT_KMS_CA_CERT": "/bao/public-ca/ca.crt",
    "GRPC_WORKLOAD_TLS_CLIENT_KMS_TOKEN_FILE": "/run/secrets/flow_workload_client_kms_token",
    "GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_NAME": "__PROJECT__-flow-client",
    "GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_VERSION": "1",
    "GRPC_WORKLOAD_TLS_SERVER_CERT": "/run/secrets/flow_workload_server_cert",
    "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR": "https://openbao:8200",
    "GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT": "/bao/public-ca/ca.crt",
    "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE": "/run/secrets/flow_workload_server_kms_token",
    "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME": "__PROJECT__-flow-server",
    "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION": "1",
    "GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert"
  }
}"#).expect("embedded deployment expectations")
});

pub(crate) fn expected(
    service: &str,
    project: &str,
    origin: &str,
    selfhost: bool,
    record: &Value,
) -> Result<Value, String> {
    let mut value = EXPECTED
        .get(service)
        .cloned()
        .ok_or("Unsupported deployment service")?;
    let port = origin.rsplit(':').next().unwrap_or("");
    for entry in value
        .as_object_mut()
        .expect("service expectation map")
        .values_mut()
    {
        let raw = entry.as_str().expect("service expectation string");
        *entry = match raw {
            "__RUN_ID__" => record["run_id"].clone(),
            "__SOURCE__" => record["source_commit"].clone(),
            "__EXPIRY__" => record["expires_at"].clone(),
            _ => json!(raw
                .replace("__PROJECT__", project)
                .replace("__PORT__", port)),
        };
    }
    if selfhost && service == "presentation-policy" {
        value["ENVIRONMENT"] = json!("production");
    }
    Ok(value)
}

/// Model-only differences: interpolation and organization identity stay bound to
/// the rendered Organization authority; observed runtimes require fixed values.
pub(crate) fn model_support(
    service: &str,
    project: &str,
    origin: &str,
    selfhost: bool,
    organization: &Value,
) -> Result<Value, String> {
    let mut value = expected(service, project, origin, selfhost, &Value::Null)?;
    value["DATABASE_URL_TEMPLATE"] = organization["DATABASE_URL_TEMPLATE"].clone();
    if value.get("MARTY_ORG_ID").is_some() {
        value["MARTY_ORG_ID"] = organization["MARTY_ORG_ID"].clone();
    }
    if service == "credential-template" {
        value.as_object_mut().unwrap().extend(
            crate::compose_model::grpc_environment(
                project,
                "ct_workload_server",
                "credential-template-server",
                true,
            )
            .as_object()
            .unwrap()
            .clone(),
        );
    }
    if service == "presentation-policy" {
        value["SIGNING_KEYS_SERVICE_URL"] = json!("http://signing-keys:8017");
        value["SIGNING_KEYS_INTERNAL_API_KEY_FILE"] =
            json!("/run/secrets/signing_keys_internal_api_key");
    }
    Ok(value)
}

pub(crate) fn runtime_environment(actual: &Value, service: &str) -> Result<Value, String> {
    let mut result = Map::new();
    let entries = actual
        .as_array()
        .ok_or_else(|| format!("{service} runtime identity is invalid"))?;
    for entry in entries {
        let (key, value) = entry
            .as_str()
            .and_then(|s| s.split_once('='))
            .filter(|(k, _)| !k.is_empty())
            .ok_or_else(|| format!("{service} runtime identity is invalid"))?;
        require(
            result.insert(key.to_owned(), json!(value)).is_none(),
            format!("{service} runtime identity has duplicate environment keys"),
        )?;
    }
    Ok(Value::Object(result))
}
fn matches(environment: &Value, expected: &Value) -> bool {
    expected
        .as_object()
        .is_some_and(|values| values.iter().all(|(k, v)| environment.get(k) == Some(v)))
}
fn no_keys(environment: &Value, keys: &[&str]) -> bool {
    keys.iter().all(|key| environment.get(key).is_none())
}

pub(crate) fn evaluate(operation: &str, input: &Value) -> PolicyResult {
    if operation == "environment-kms-transport" {
        let image = input["image"].as_str().unwrap_or("").trim();
        require(
            regex::Regex::new(r"\Aghcr\.io/elevenid/marty-ui-oss/keycloak@sha256:[0-9a-f]{64}\z")
                .unwrap()
                .is_match(image),
            "MARTY_KEYCLOAK_KMS_IMAGE must pin the released Keycloak digest.",
        )?;
        let origins = input["origins"]
            .as_object()
            .ok_or("Self-host KMS HTTPS origins are incomplete.")?;
        require(
            origins.contains_key("BAO_ADDR") && origins.contains_key("KEYCLOAK_KMS_ADDR"),
            "Self-host KMS HTTPS origins are incomplete.",
        )?;
        for (name, origin) in origins {
            require(
                origin["scheme"] == "https"
                    && origin["hostname"].as_str().is_some_and(|s| !s.is_empty())
                    && origin["port"] != 0
                    && origin["userinfo"] == false
                    && matches!(origin["path"].as_str(), Some("" | "/"))
                    && origin["query"] == ""
                    && origin["fragment"] == "",
                format!("{name} must be a trusted HTTPS OpenBao origin."),
            )?;
        }
        return Ok(json!(format!(
            "keycloak_image=immutable https_origins={}",
            origins.len()
        )));
    }
    let service = input["service"]
        .as_str()
        .ok_or("Invalid deployment service")?;
    if operation == "ownership-runtime-observation" {
        let surface = input["surface"].as_str().unwrap_or("");
        let observed = &input["record"];
        let config = &observed["Config"];
        let state = &observed["State"];
        require(
            config.is_object() && state.is_object(),
            format!("{surface} {service} has no runtime state"),
        )?;
        let labels = &config["Labels"];
        require(
            labels.is_object()
                && labels["com.docker.compose.project"] == input["project"]
                && labels["com.docker.compose.service"] == service,
            format!("{surface} {service} is outside the disposable project"),
        )?;
        require(
            state["Running"] == true
                && state["Status"] == "running"
                && (!state["Health"].is_object() || state["Health"]["Status"] == "healthy"),
            format!("{surface} {service} is not ready"),
        )?;
        require(
            config["Image"] == input["services_reference"]
                && observed["Image"].as_str().is_some_and(|s| {
                    regex::Regex::new(r"\Asha256:[0-9a-f]{64}\z")
                        .unwrap()
                        .is_match(s)
                }),
            format!("{surface} {service} is not running the released services image"),
        )?;
        return Ok(Value::Null);
    }
    require(
        matches!(
            operation,
            "ownership-runtime-identity" | "ownership-issuer-origin"
        ),
        "Deployment environment operation is invalid",
    )?;
    let label = match service {
        "organization" => "Organization",
        "revocation-profile" => "Revocation Profile",
        "flow" => "Flow",
        _ => service,
    };
    let environment = runtime_environment(&input["actual"], label)?;
    let project = input["project"].as_str().unwrap_or("");
    let origin = input["status_origin"].as_str().unwrap_or("");
    let selfhost = input["surface"] == "selfhost";
    if operation == "ownership-issuer-origin" {
        let key = if service == "db-migrate" {
            "MARTY_ISSUER_BASE_URL"
        } else {
            "ISSUER_BASE_URL"
        };
        require(
            environment.get(key) == Some(&input["status_origin"]),
            format!("{service} issuer origin differs from disposable Gateway"),
        )?;
        return Ok(Value::Null);
    }
    let mut wanted = expected(service, project, origin, selfhost, &input["record"])?;
    let diagnostic = match service {
        "organization" => "Organization runtime identity differs from protected run".to_owned(),
        "revocation-profile" => {
            "Revocation Profile runtime identity differs from disposable model".to_owned()
        }
        "flow" => {
            require(
                environment["FLOW_APPLICATION_EVENT_HMAC_KEY_FILE"]
                    == "/run/secrets/flow_application_event_hmac_key",
                "Disposable Flow application event authentication differs from model",
            )?;
            wanted["ENVIRONMENT"] = json!(if selfhost {
                "production"
            } else {
                "development"
            });
            if !selfhost {
                for key in [
                    "FLOW_CALLBACK_DESTINATIONS",
                    "FLOW_WEBHOOK_SECRET_FILE",
                    "FLOW_CALLBACK_CA_CERT_FILE",
                ] {
                    wanted.as_object_mut().unwrap().remove(key);
                }
            }
            "Disposable Flow callback or workload TLS runtime differs from surface".to_owned()
        }
        _ => format!("{service} runtime identity differs from disposable model"),
    };
    let forbidden: &[&str] = match service {
        "organization" => &["MARTY_DB_PASSWORD", "GRPC_SERVICE_TOKEN"],
        "revocation-profile" => &["RP_MIGRATE_ONLY", "MARTY_DB_PASSWORD", "GRPC_SERVICE_TOKEN"],
        "flow" => &[],
        _ => &[
            "MARTY_DB_PASSWORD",
            "GRPC_SERVICE_TOKEN",
            "ISSUANCE_API_KEY",
            "SIGNING_KEYS_INTERNAL_API_KEY",
        ],
    };
    require(
        matches(&environment, &wanted) && no_keys(&environment, forbidden),
        diagnostic,
    )?;
    Ok(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observed_credentials_never_appear_in_policy_results_or_unknown_operations() {
        let record =
            json!({"run_id":"7","source_commit":"a".repeat(40),"expires_at":"synthetic-expiry"});
        let wanted = expected("organization", "project", "", false, &record).unwrap();
        let mut actual = wanted
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| format!("{k}={}", v.as_str().unwrap()))
            .collect::<Vec<_>>();
        actual.push("UNRELATED_CREDENTIAL=synthetic-private-marker".into());
        let input =
            json!({"service":"organization","project":"project","record":record,"actual":actual});
        assert_eq!(
            evaluate("ownership-runtime-identity", &input),
            Ok(Value::Null)
        );
        let error = evaluate("ownership-runtime-environment", &input).unwrap_err();
        assert!(!error.contains("synthetic-private-marker"));
    }
}
