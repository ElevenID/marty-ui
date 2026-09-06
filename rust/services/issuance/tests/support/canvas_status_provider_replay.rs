//! Frozen provider protocol replay. HTTP and secret lookup are the same
//! controlled boundaries as the independently captured published Python run.
use async_trait::async_trait;
use marty_issuance_service::{
    canvas_credentials_status::{
        CanvasCredentialsStatusError, CanvasCredentialsStatusService, CanvasStatusRequest,
        CanvasStatusResponse, CanvasStatusTransport,
    },
    canvas_credentials_validation::CanvasCredentialsSecretResolver,
    canvas_lifecycle_delivery::CanvasLifecycleCredential,
    credential_management::{CredentialLifecycleAction, ManagedCredential},
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

struct Ports {
    case: Value,
    requests: Mutex<Vec<Value>>,
    secrets: Mutex<Vec<Value>>,
}

#[async_trait]
impl CanvasCredentialsSecretResolver for Ports {
    async fn secret_value(&self, organization: &str, id: &str) -> Result<Option<String>, ()> {
        self.secrets
            .lock()
            .unwrap()
            .push(json!({"organization_id":organization,"secret_id":id}));
        Ok(self.case["secrets"][id]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(|_| "synthetic-tenant-token".into()))
    }
}

#[async_trait]
impl CanvasStatusTransport for Ports {
    async fn send(&self, request: CanvasStatusRequest) -> Result<CanvasStatusResponse, String> {
        let bearer = match request.token.as_deref() {
            None => None,
            Some("synthetic-operator-token") => Some("Bearer $operator-token"),
            Some("synthetic-tenant-token") => Some("Bearer $tenant-token"),
            Some(_) => panic!("unexpected synthetic token source"),
        };
        let mut body = request.body;
        timestamps(&mut body);
        self.requests.lock().unwrap().push(json!({"method":request.method.as_str(),"url":request.url,
            "headers":{"accept":"application/json","content-type":"application/json","authorization":bearer},"body":body}));
        if self.case["transport_error"] == true {
            return Err("Synthetic transport unavailable".into());
        }
        Ok(CanvasStatusResponse {
            status: self.case["response_status"]
                .as_u64()
                .unwrap_or(200)
                .try_into()
                .unwrap(),
            request_id: Some("synthetic-provider-request".into()),
            content_type: self.case["response_content_type"]
                .as_str()
                .map(str::to_owned),
            body: if let Some(encoded) = self.case["response_hex"].as_str() {
                hex::decode(encoded).unwrap()
            } else {
                self.case["response_text"]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| {
                        self.case
                            .get("response_json")
                            .cloned()
                            .unwrap_or(json!({"accepted":true}))
                            .to_string()
                    })
                    .into_bytes()
            },
        })
    }
}

fn timestamps(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key.ends_with("_at") && value.is_string() {
                    chrono::DateTime::parse_from_rfc3339(value.as_str().unwrap())
                        .expect("valid actual timestamp");
                    *value = json!("$timestamp");
                } else {
                    timestamps(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                timestamps(value);
            }
        }
        _ => (),
    }
}

pub fn frozen() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-status-provider-oracle.json"
    ))
    .unwrap()
}

pub async fn replay(expected: &Value) {
    let scenarios: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-status-provider-scenarios.json"
    ))
    .unwrap();
    let cases = scenarios["cases"].as_array().unwrap();
    let observations = expected["observations"].as_array().unwrap();
    assert_eq!(cases.len(), observations.len());
    for (case, expected) in cases.iter().zip(observations) {
        assert_eq!(case["name"], expected["name"]);
        let ports = Arc::new(Ports {
            case: case.clone(),
            requests: Mutex::new(Vec::new()),
            secrets: Mutex::new(Vec::new()),
        });
        let action = match case["action"].as_str().unwrap() {
            "suspend" => CredentialLifecycleAction::Suspend,
            "revoke" => CredentialLifecycleAction::Revoke,
            "reinstate" => CredentialLifecycleAction::Reinstate,
            _ => panic!("unknown fixture action"),
        };
        let credential = ManagedCredential {
            id: "credential-review".into(),
            organization_id: "org-review".into(),
            credential_template_id: "credential-template".into(),
            issuer_did: None,
            status: action.target_status(),
            status_updated_at: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .into(),
            revoked: action == CredentialLifecycleAction::Revoke,
            revoked_at: if action == CredentialLifecycleAction::Revoke {
                Some(
                    chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                        .unwrap()
                        .into(),
                )
            } else {
                None
            },
            revocation_reason: case["revocation_reason"].as_str().map(str::to_owned),
            revocation_profile_id: None,
            status_list_entries: Vec::new(),
        };
        let platform = json!({"id":"platform-review","organization_id":case["platform_organization"].as_str().unwrap_or("org-review"),"canvas_account_id":"account"});
        let delivery = json!({"id":"delivery-provider","organization_id":case["delivery_organization"].as_str().unwrap_or("org-review"),
            "credential_id":case["delivery_credential"].as_str().unwrap_or("credential-review"),
            "transaction_id":case["delivery_transaction"].as_str().unwrap_or("transaction-review"),
            "external_credential_id":case.get("external_credential_id").cloned().unwrap_or(json!("external-assertion")),
            "external_issuer_id":case["external_issuer_id"],
            "metadata":case.get("metadata").cloned().unwrap_or(json!({"canvas_program_binding_id":"binding-review"}))});
        let entries = [
            (
                "CANVAS_PORTABLE_INTEGRATION_ENABLED",
                if case["rollout"] == false {
                    "false"
                } else {
                    "true"
                },
            ),
            (
                "CANVAS_PILOT_ORGANIZATION_IDS",
                case["pilot_organizations"].as_str().unwrap_or("org-review"),
            ),
            (
                "CANVAS_CREDENTIALS_PROVIDER",
                case["provider"].as_str().unwrap(),
            ),
            (
                "CANVAS_CREDENTIALS_PUBLISH_URL",
                case["publish_url"].as_str().unwrap_or(""),
            ),
            (
                "CANVAS_CREDENTIALS_ISSUER_ID",
                case["issuer_id"].as_str().unwrap_or("configured-issuer"),
            ),
            (
                "CANVAS_CREDENTIALS_API_BASE_URL",
                case["api_base_url"]
                    .as_str()
                    .unwrap_or("https://api.badgr.io"),
            ),
            (
                "CANVAS_CREDENTIALS_BASE_URL",
                case["legacy_base_url"].as_str().unwrap_or(""),
            ),
            (
                "CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST",
                case["allowed_api_origins"].as_str().unwrap_or(""),
            ),
            (
                "CANVAS_CREDENTIALS_STATUS_SYNC_URL",
                case["sync_url"]
                    .as_str()
                    .unwrap_or("https://bridge.example.invalid/status"),
            ),
            (
                "CANVAS_CREDENTIALS_REVOKE_URL_TEMPLATE",
                case["revoke_url_template"].as_str().unwrap_or(""),
            ),
            (
                "CANVAS_CREDENTIALS_API_TOKEN",
                if case["operator_token"].as_str() == Some("") {
                    ""
                } else {
                    "synthetic-operator-token"
                },
            ),
        ];
        let runtime = marty_issuance_service::config::IssuanceServiceConfig::from_values(
            entries
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned())),
        )
        .expect("actual runtime configuration");
        let config = runtime.canvas_credentials_status;
        let service = CanvasCredentialsStatusService::new(config, ports.clone(), ports.clone());
        let reason = case
            .get("reason")
            .map(|value| value.as_str())
            .unwrap_or(Some("synthetic reason"));
        let outcome = service
            .synchronize_provider(
                CanvasLifecycleCredential {
                    credential: &credential,
                    transaction_id: "transaction-review",
                },
                &platform,
                &delivery,
                action,
                reason,
            )
            .await;
        let mut actual = match outcome {
            Ok(metadata) => json!({"metadata":metadata}),
            Err(error) => json!({"error_class":match &error {
                CanvasCredentialsStatusError::Runtime(_) => "RuntimeError",
                CanvasCredentialsStatusError::ResponseText(error) => error.diagnostic_class(),
            },"error":error.to_string()}),
        };
        timestamps(&mut actual);
        actual["name"] = case["name"].clone();
        actual["requests"] = json!(*ports.requests.lock().unwrap());
        actual["secrets"] = json!(*ports.secrets.lock().unwrap());
        assert_eq!(
            &actual, expected,
            "published provider case {}",
            case["name"]
        );
    }
}
