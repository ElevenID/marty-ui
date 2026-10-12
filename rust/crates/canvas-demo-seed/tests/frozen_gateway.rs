use async_trait::async_trait;
use marty_canvas_demo_seed::{
    application_template_payload, credential_template_payload, demo_scope, remote_signing_config,
    upsert_binding, upsert_platform, GatewaySeedConfig, GatewayTransport, Operation,
};
use serde_json::{json, Value};
use std::{collections::VecDeque, sync::Mutex};

struct Stub {
    responses: Mutex<VecDeque<Value>>,
    operations: Mutex<Vec<Value>>,
}

#[test]
fn badge_template_payloads_match_frozen_python_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let cfg = config();
    for (case, scope) in [
        ("modern_schema", json!({})),
        (
            "legacy_remote_columns",
            json!({"course_id": "42", "quiz_id": "9"}),
        ),
    ] {
        let writes = &contract["database_seed"][case]["writes"];
        assert_eq!(credential_template_payload(&cfg), writes[0]["payload"]);
        assert_eq!(
            application_template_payload(&cfg, &scope),
            writes[1]["payload"]
        );
    }
}

#[async_trait]
impl GatewayTransport for Stub {
    async fn request(&self, operation: Operation) -> Result<Value, String> {
        self.operations.lock().unwrap().push(json!({
            "method": operation.method,
            "url": operation.url,
            "payload": operation.payload,
        }));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| "unexpected gateway operation".into())
    }
}

fn config() -> GatewaySeedConfig {
    GatewaySeedConfig {
        base_url: "http://localhost:8000".into(),
        organization_id: "org-1".into(),
        canvas_account_id: "account-1".into(),
        credential_template_id: "ct-1".into(),
        application_template_id: "at-1".into(),
        display_name: "Canvas Demo".into(),
        canvas_base_url: "https://canvas.example".into(),
        lti_client_id: "client-1".into(),
        lti_deployment_id: "deployment-1".into(),
        probe_after_upsert: true,
        program_binding_display_name: "Program Demo".into(),
        program_binding_evidence_type: "canvas.quiz_score".into(),
        program_binding_delivery_mode: "wallet_plus_canvas_mirror".into(),
        program_binding_auto_approve: true,
        program_binding_direct_issue: false,
        program_binding_score_threshold: 80,
        signing_keys_internal_base_url: "http://signing-keys:8000".into(),
    }
}

#[tokio::test]
async fn gateway_operations_match_frozen_python_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let scope = demo_scope(Some("42"), Some("9"), None, None);
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![
            json!([]),
            json!({"id": "platform-1"}),
            json!({"platform": {"id": "platform-1"}}),
            json!([{"id": "platform-1", "organization_id": "org-1", "canvas_account_id": "account-1", "lti_issuer": "https://canvas.example", "lti_jwks_json": {"keys": []}}]),
            json!({"id": "platform-1"}),
            json!({"platform": {"id": "platform-1"}}),
            json!([]),
            json!({"id": "binding-1"}),
            json!([{"id": "binding-1", "credential_template_id": "ct-1", "canvas_scope": scope}]),
            json!({"id": "binding-1"}),
        ])),
        operations: Mutex::new(Vec::new()),
    };
    let mut cfg = config();
    let created_platform = upsert_platform(&stub, &cfg).await.unwrap();
    let updated_platform = upsert_platform(&stub, &cfg).await.unwrap();
    let created_binding = upsert_binding(&stub, &cfg, &json!({"id": "platform-1"}), &scope)
        .await
        .unwrap();
    cfg.program_binding_evidence_type = "canvas.course_completion".into();
    cfg.program_binding_delivery_mode = "wallet_only".into();
    let updated_binding = upsert_binding(&stub, &cfg, &json!({"id": "platform-1"}), &scope)
        .await
        .unwrap();
    assert_eq!(created_platform.action, "created");
    assert_eq!(updated_platform.action, "updated");
    assert_eq!(created_binding.action, "created");
    assert_eq!(updated_binding.action, "updated");
    assert_eq!(
        *stub.operations.lock().unwrap(),
        *contract["gateway_seed"]["operations"].as_array().unwrap()
    );
    assert!(stub.responses.lock().unwrap().is_empty());
    assert_eq!(
        demo_scope(Some("42"), Some("9"), Some("0"), None),
        contract["gateway_seed"]["scope"]
    );
    assert_eq!(
        remote_signing_config(&cfg.signing_keys_internal_base_url),
        contract["gateway_seed"]["remote_signing"]
    );
}

#[tokio::test]
async fn invalid_gateway_lists_fail_before_any_upsert() {
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![json!({"error": "bad list"})])),
        operations: Mutex::new(Vec::new()),
    };
    assert!(upsert_platform(&stub, &config()).await.is_err());
    assert_eq!(stub.operations.lock().unwrap().len(), 1);
}
