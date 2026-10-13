use async_trait::async_trait;
use marty_canvas_demo_seed::{
    ags_score_payload, application_payload, application_template_payload,
    binding_evidence_requirement, binding_feature_flags, credential_template_payload, demo_scope,
    install_platform, remote_signing_config, resolve_issuer_context, run_mirror_publish,
    signed_ags_wire, upsert_binding, upsert_platform, DemoEvidenceConfig, GatewaySeedConfig,
    GatewayTransport, IssuerProfileContext, Operation,
};
use serde_json::{json, Value};
use std::{collections::VecDeque, sync::Mutex};

struct Stub {
    responses: Mutex<VecDeque<Value>>,
    operations: Mutex<Vec<Value>>,
}

fn issuer() -> IssuerProfileContext {
    IssuerProfileContext {
        issuer_profile_id: "ip-marty-vc-jwt-issuer".into(),
        issuer_did: "did:web:beta.elevenidllc.com:orgs:marty".into(),
        signing_service_id: "managed-openbao-transit".into(),
        signing_key_reference: "cred-issuer-marty-es256".into(),
        verification_method_id: "did:web:beta.elevenidllc.com:orgs:marty#cred-issuer-marty-es256"
            .into(),
    }
}

struct MirrorStub {
    responses: Mutex<VecDeque<Result<Value, String>>>,
    operations: Mutex<Vec<Operation>>,
}

#[async_trait]
impl GatewayTransport for MirrorStub {
    async fn request(&self, operation: Operation) -> Result<Value, String> {
        self.operations.lock().unwrap().push(operation);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| String::from("unexpected mirror operation"))?
    }
}

#[tokio::test]
async fn mirror_and_issuer_context_match_frozen_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let frozen = &contract["mirror_and_issuer_context"];
    let stub = MirrorStub {
        responses: Mutex::new(VecDeque::from(vec![
            Ok(frozen["mirror"].clone()),
            Ok(json!({
                "issuer_profile_id": "profile-1",
                "issuer_did": "did:web:marty.example",
                "signing_service_id": "managed-openbao-transit",
                "signing_key_reference": "key-ref",
                "verification_method_id": "did:web:marty.example#key-ref",
                "ignored": "never expose"
            })),
        ])),
        operations: Mutex::new(Vec::new()),
    };
    assert_eq!(
        run_mirror_publish(&stub, &config()).await.unwrap(),
        frozen["mirror"]
    );
    assert_eq!(
        resolve_issuer_context(
            &stub,
            "org-1",
            "http://signing-keys:8000",
            "test-signing-key"
        )
        .await
        .unwrap(),
        frozen["issuer_context"]
    );
    let operations = stub.operations.lock().unwrap();
    for (operation, expected) in operations
        .iter()
        .zip(frozen["operations"].as_array().unwrap())
    {
        assert_eq!(operation.method, expected["method"]);
        assert_eq!(operation.url, expected["url"]);
        assert_eq!(
            operation.payload.clone().unwrap_or(Value::Null),
            expected["payload"]
        );
        assert_eq!(operation.timeout_seconds, expected["timeout"]);
    }
    assert_eq!(operations.len(), 2);
}

#[tokio::test]
async fn optional_issuer_context_fails_closed_to_none() {
    let stub = MirrorStub {
        responses: Mutex::new(VecDeque::from(vec![Err("unavailable".into())])),
        operations: Mutex::new(Vec::new()),
    };
    assert!(
        resolve_issuer_context(&stub, "org-1", "http://signing-keys:8000", "")
            .await
            .is_none()
    );
    assert!(stub.operations.lock().unwrap().is_empty());
    assert!(
        resolve_issuer_context(&stub, "org-1", "http://signing-keys:8000", "key")
            .await
            .is_none()
    );
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
        assert_eq!(
            credential_template_payload(&cfg, &issuer()),
            writes[0]["payload"]
        );
        assert_eq!(
            application_template_payload(&cfg, &scope, &issuer()),
            writes[1]["payload"]
        );
    }
}

#[test]
fn demo_application_and_ags_payloads_match_frozen_python_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let demo = DemoEvidenceConfig {
        learner_name: "First Last".into(),
        learner_email: "learner@example.com".into(),
        course_name: "Fallback Course".into(),
        quiz_title: "Fallback Quiz".into(),
        quiz_passing_score_percent: 92,
        quiz_points_possible: 100,
    };
    let canvas_seed = json!({
        "course": {"id": 42, "name": "Canvas Course"},
        "quiz": {"id": 9, "title": "Canvas Quiz"},
        "learner": {"id": 77},
        "enrollment": {"id": 88}
    });
    let cfg = config();
    let expected = &contract["demo_evidence"]["operations"];
    let mut expected_profile_payload = expected[0]["payload"].clone();
    expected_profile_payload["integration_context"]["issuer"]["issuer_profile_id"] =
        json!("ip-marty-vc-jwt-issuer");
    assert_eq!(
        application_payload(&cfg, &demo, &canvas_seed, "2025-04-05", &issuer()),
        expected_profile_payload
    );
    let rotated = IssuerProfileContext {
        issuer_profile_id: "profile-rotated".into(),
        issuer_did: "did:web:rotated.example".into(),
        signing_service_id: "kms-v2".into(),
        signing_key_reference: "kms://profile-rotated/key-2".into(),
        verification_method_id: "did:web:rotated.example#key-2".into(),
    };
    let rotated_payload = application_payload(&cfg, &demo, &canvas_seed, "2025-04-05", &rotated);
    assert_eq!(
        rotated_payload["integration_context"]["issuer"]["issuer_profile_id"],
        "profile-rotated"
    );
    assert_eq!(
        rotated_payload["integration_context"]["issuer"]["issuer_did"],
        "did:web:rotated.example"
    );
    assert_eq!(
        rotated_payload["integration_context"]["issuer"]["signing_service_id"],
        "kms-v2"
    );
    assert_eq!(
        rotated_payload["integration_context"]["issuer"]["signing_key_reference"],
        "kms://profile-rotated/key-2"
    );
    assert_eq!(
        ags_score_payload(
            &cfg,
            &demo,
            &canvas_seed,
            "application-1",
            "2025-04-05",
            "abc12345"
        ),
        expected[1]["payload"]
    );
}

#[test]
fn disposable_badge_vct_stays_local_across_templates_and_evidence() {
    let mut cfg = config();
    cfg.badge_vct =
        "http://localhost:5173/credentials/canvas-interoperability-foundations-badge".into();
    let credential = credential_template_payload(&cfg, &issuer());
    let application = application_template_payload(&cfg, &json!({"id": "scope-1"}), &issuer());
    let demo = DemoEvidenceConfig {
        learner_name: "First Last".into(),
        learner_email: "learner@example.com".into(),
        course_name: "Course".into(),
        quiz_title: "Quiz".into(),
        quiz_passing_score_percent: 80,
        quiz_points_possible: 100,
    };
    let evidence = application_payload(&cfg, &demo, &json!({}), "2025-04-05", &issuer());
    for payload in [&credential, &application, &evidence] {
        assert!(!payload
            .to_string()
            .contains("beta.elevenidllc.com/credentials"));
        assert!(payload.to_string().contains(&cfg.badge_vct));
    }
}

#[test]
fn signed_ags_body_and_hmac_match_frozen_python_wire() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let wire = &contract["signed_ags_wire"];
    let payload = json!({"z": 2, "a": {"y": 2, "x": 1}});
    let signed = signed_ags_wire(&payload, "test-shared-secret", 1743811200).unwrap();
    assert_eq!(signed.body, wire["body"]);
    assert_eq!(signed.timestamp, wire["headers"]["x-canvas-timestamp"]);
    assert_eq!(signed.signature, wire["headers"]["x-canvas-signature-256"]);
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
        badge_vct:
            "https://beta.elevenidllc.com/credentials/canvas-interoperability-foundations-badge"
                .into(),
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
            json!([{"id": "platform-1", "organization_id": "org-1", "canvas_account_id": "account-1", "canvas_base_url": "https://canvas.example", "lti_issuer": "https://canvas.example", "lti_jwks_json": {"keys": []}}]),
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
    let created_platform = upsert_platform(&stub, &cfg, false).await.unwrap();
    let updated_platform = upsert_platform(&stub, &cfg, true).await.unwrap();
    let created_binding = upsert_binding(
        &stub,
        &cfg,
        &json!({"id": "platform-1"}),
        &scope,
        &scope,
        false,
    )
    .await
    .unwrap();
    cfg.program_binding_evidence_type = "canvas.course_completion".into();
    cfg.program_binding_delivery_mode = "wallet_only".into();
    let updated_binding = upsert_binding(
        &stub,
        &cfg,
        &json!({"id": "platform-1"}),
        &scope,
        &scope,
        false,
    )
    .await
    .unwrap();
    assert_eq!(created_platform.action, "created");
    assert_eq!(updated_platform.action, "updated");
    assert_eq!(created_binding.action, "created");
    assert_eq!(updated_binding.action, "updated");
    let mut accepted_operations = contract["gateway_seed"]["operations"]
        .as_array()
        .unwrap()
        .clone();
    let mut binding_index = 0;
    for operation in &mut accepted_operations {
        if operation["url"]
            .as_str()
            .is_some_and(|url| url.contains("/v1/integrations/canvas/platforms"))
            && matches!(operation["method"].as_str(), Some("POST" | "PUT"))
            && operation["payload"].is_object()
            && operation["payload"].get("canvas_base_url").is_some()
        {
            let payload = operation["payload"].as_object_mut().unwrap();
            for field in contract["api_corrections"]["platform_rejected_fields"]
                .as_array()
                .unwrap()
            {
                payload.remove(field.as_str().unwrap());
            }
        }
        if operation["url"]
            .as_str()
            .is_some_and(|url| url.contains("/program-bindings"))
            && matches!(operation["method"].as_str(), Some("POST" | "PUT"))
        {
            let payload = operation["payload"].as_object_mut().unwrap();
            for field in contract["api_corrections"]["program_binding_rejected_fields"]
                .as_array()
                .unwrap()
            {
                payload.remove(field.as_str().unwrap());
            }
            payload.insert(
                "evidence_requirements".into(),
                json!(
                    [contract["api_corrections"]["accepted_binding_requirements"][binding_index]]
                ),
            );
            binding_index += 1;
        }
    }
    assert_eq!(binding_index, 2);
    assert_eq!(*stub.operations.lock().unwrap(), accepted_operations);
    assert!(stub.responses.lock().unwrap().is_empty());
    assert_eq!(
        demo_scope(Some("42"), Some("9"), Some("0"), None),
        contract["gateway_seed"]["scope"]
    );
    assert_eq!(
        remote_signing_config(&cfg.signing_keys_internal_base_url, &issuer()),
        contract["gateway_seed"]["remote_signing"]
    );
}

#[tokio::test]
async fn invalid_gateway_lists_fail_before_any_upsert() {
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![json!({"error": "bad list"})])),
        operations: Mutex::new(Vec::new()),
    };
    assert!(upsert_platform(&stub, &config(), false).await.is_err());
    assert_eq!(stub.operations.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn first_pass_preserves_installed_platform_until_canvas_identifiers_are_known() {
    let existing = json!({
        "id": "platform-1", "organization_id": "org-1",
        "canvas_base_url": "https://canvas.example", "enabled": true,
        "registration_status": "installed", "lti_client_id": "live-client",
        "lti_deployment_id": "live-deployment"
    });
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![json!([existing.clone()])])),
        operations: Mutex::new(Vec::new()),
    };
    let result = upsert_platform(&stub, &config(), false).await.unwrap();
    assert_eq!(result.action, "preserved");
    assert_eq!(result.value, existing);
    assert_eq!(stub.operations.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn post_lms_upsert_repairs_disabled_platform_with_same_identifiers() {
    let mut cfg = config();
    cfg.probe_after_upsert = false;
    let existing = json!({
        "id": "platform-1", "organization_id": "org-1",
        "canvas_base_url": cfg.canvas_base_url, "display_name": cfg.display_name,
        "lti_client_id": cfg.lti_client_id, "lti_deployment_id": cfg.lti_deployment_id,
        "enabled": false
    });
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![
            json!([existing]),
            json!({"id": "platform-1", "enabled": true}),
        ])),
        operations: Mutex::new(Vec::new()),
    };
    let result = upsert_platform(&stub, &cfg, true).await.unwrap();
    assert_eq!(result.action, "updated");
    let operations = stub.operations.lock().unwrap();
    assert_eq!(operations.len(), 2);
    assert_eq!(operations[1]["method"], "PUT");
    assert_eq!(operations[1]["payload"]["enabled"], true);
}

#[tokio::test]
async fn current_platform_installation_confirms_active_runtime() {
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![
            json!({"platform_id": "platform-1", "installation": {}}),
            json!({"id": "platform-1", "enabled": true, "registration_status": "installed", "canvas_account_id": "unverified:platform-1"}),
        ])),
        operations: Mutex::new(Vec::new()),
    };
    let platform = install_platform(&stub, &config(), "platform-1")
        .await
        .unwrap();
    assert_eq!(platform["enabled"], true);
    let operations = stub.operations.lock().unwrap();
    assert_eq!(operations.len(), 2);
    assert_eq!(operations[0]["method"], "PUT");
    assert_eq!(
        operations[0]["url"],
        "http://localhost:8000/v1/integrations/canvas/platforms/platform-1/lti-installation"
    );
    assert_eq!(operations[0]["payload"]["lti_client_id"], "client-1");
    assert_eq!(
        operations[0]["payload"]["lti_deployment_id"],
        "deployment-1"
    );
    assert_eq!(
        operations[1]["url"],
        "http://localhost:8000/v1/integrations/canvas/platforms/platform-1"
    );
}

#[tokio::test]
async fn lti_binding_scope_excludes_quiz_while_evidence_pins_activity() {
    let binding_scope = demo_scope(Some("42"), None, None, None);
    let evidence_scope = demo_scope(Some("42"), Some("9"), None, None);
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![json!([]), json!({"id": "binding-1"})])),
        operations: Mutex::new(Vec::new()),
    };
    upsert_binding(
        &stub,
        &config(),
        &json!({"id": "platform-1"}),
        &binding_scope,
        &evidence_scope,
        false,
    )
    .await
    .unwrap();
    let operations = stub.operations.lock().unwrap();
    assert_eq!(operations.len(), 2);
    assert_eq!(operations[1]["payload"]["canvas_scope"], binding_scope);
    assert_eq!(
        operations[1]["payload"]["evidence_requirements"][0]["scope"]["activity_id"],
        "9"
    );
}

#[tokio::test]
async fn current_binding_activation_requires_validated_config_and_preserves_active_repeat() {
    let scope = demo_scope(Some("42"), Some("9"), None, None);
    let cfg = config();
    let active = json!({"id": "binding-1", "enabled": true, "activated_at": "2026-10-13T08:00:00Z", "config_version": 1, "validated_config_version": 1});
    let active_list_item = json!({
        "id": "binding-1", "application_template_id": cfg.application_template_id,
        "credential_template_id": cfg.credential_template_id,
        "display_name": cfg.program_binding_display_name,
        "auto_approve_on_evidence": cfg.program_binding_auto_approve,
        "canvas_scope": scope, "delivery_mode": cfg.program_binding_delivery_mode,
        "approval_policy_set_id": null, "deployment_profile_id": null,
        "feature_flags": binding_feature_flags(&cfg.program_binding_delivery_mode),
        "evidence_requirements": [binding_evidence_requirement(&cfg, &scope).unwrap()],
        "enabled": true, "activated_at": "2026-10-13T08:00:00Z"
    });
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![
            json!([]),
            json!({"id": "binding-1"}),
            json!({"binding_id": "binding-1", "ready": true, "valid": true, "active": false, "config_version": 1}),
            json!({"binding_id": "binding-1", "ready": true, "valid": true, "active": true, "config_version": 1}),
            active.clone(),
            json!([active_list_item.clone()]),
            active.clone(),
            json!({"binding_id": "binding-1", "ready": true, "valid": true, "active": true, "config_version": 1}),
            active,
            json!([active_list_item]),
        ])),
        operations: Mutex::new(Vec::new()),
    };
    let created = upsert_binding(
        &stub,
        &cfg,
        &json!({"id": "platform-1"}),
        &scope,
        &scope,
        true,
    )
    .await
    .unwrap();
    let repeat = upsert_binding(
        &stub,
        &cfg,
        &json!({"id": "platform-1"}),
        &scope,
        &scope,
        true,
    )
    .await
    .unwrap();
    assert_eq!(created.action, "created");
    assert_eq!(repeat.action, "preserved");
    let mut changed = cfg.clone();
    changed.program_binding_score_threshold = 90;
    assert!(upsert_binding(
        &stub,
        &changed,
        &json!({"id": "platform-1"}),
        &scope,
        &scope,
        true
    )
    .await
    .err()
    .unwrap()
    .contains("differs from the requested seed policy"));
    let operations = stub.operations.lock().unwrap();
    assert_eq!(operations.len(), 10);
    assert_eq!(
        operations[2]["url"],
        "http://localhost:8000/v1/integrations/canvas/program-bindings/binding-1/validate"
    );
    assert_eq!(operations[2]["payload"], Value::Null);
    assert_eq!(
        operations[3]["url"],
        "http://localhost:8000/v1/integrations/canvas/program-bindings/binding-1/activate"
    );
    assert_eq!(
        operations[7]["url"],
        "http://localhost:8000/v1/integrations/canvas/program-bindings/binding-1/validate"
    );
    assert!(!operations
        .iter()
        .skip(5)
        .any(|operation| operation["method"] == "PUT"));
}
