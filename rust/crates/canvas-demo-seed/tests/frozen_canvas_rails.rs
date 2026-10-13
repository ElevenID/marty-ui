use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use marty_canvas_demo_seed::{
    docker_container_env_value, ensure_canvas_developer_key, ensure_canvas_external_tool,
    ensure_canvas_initial_data, ensure_canvas_public_domain, mint_canvas_admin_token,
    CanvasDockerOperation, CanvasDockerOutput, CanvasDockerTransport, CanvasRailsConfig,
    CANVAS_ADMIN_TOKEN_SCRIPT, CANVAS_LTI_SETUP_SCRIPT,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, sync::Mutex};

struct Stub {
    responses: Mutex<VecDeque<Value>>,
    operations: Mutex<Vec<Value>>,
}

struct InspectStub(Mutex<Vec<Value>>);

#[async_trait]
impl CanvasDockerTransport for InspectStub {
    async fn run(&self, operation: CanvasDockerOperation) -> Result<CanvasDockerOutput, String> {
        self.0.lock().unwrap().push(json!({
            "command": std::iter::once("docker".to_owned()).chain(operation.args).collect::<Vec<_>>(),
            "timeout": operation.timeout_seconds
        }));
        Ok(CanvasDockerOutput {
            exit_code: 0,
            stdout: json!([
                "OTHER=value",
                "CANVAS_CREDENTIALS_SHARED_SECRET=test-shared-secret"
            ])
            .to_string(),
            stderr: String::new(),
        })
    }
}

#[tokio::test]
async fn docker_secret_fallback_matches_frozen_python() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let stub = InspectStub(Mutex::new(Vec::new()));
    assert_eq!(
        docker_container_env_value(&stub, "marty-issuance", "CANVAS_CREDENTIALS_SHARED_SECRET")
            .await,
        contract["canvas_secret_fallback"]["secret"]
    );
    assert_eq!(
        json!(*stub.0.lock().unwrap()),
        contract["canvas_secret_fallback"]["operations"]
    );
}

#[async_trait]
impl CanvasDockerTransport for Stub {
    async fn run(&self, operation: CanvasDockerOperation) -> Result<CanvasDockerOutput, String> {
        if operation.args[0] == "ps" {
            return Ok(CanvasDockerOutput {
                exit_code: 0,
                stdout: "stack_marty-canvas-real\n".into(),
                stderr: String::new(),
            });
        }
        let mut args = operation.args;
        let encoded = args[3].strip_prefix("CANVAS_LTI_SETUP_B64=").unwrap();
        let payload: Value = serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
        args[3] = "CANVAS_LTI_SETUP_B64=<payload>".into();
        let script = operation.input.unwrap();
        let command: Vec<String> = std::iter::once("docker".to_owned()).chain(args).collect();
        self.operations.lock().unwrap().push(json!({
            "command": command,
            "payload": payload,
            "script_sha256": hex::encode(Sha256::digest(script.as_bytes())),
            "timeout": operation.timeout_seconds,
        }));
        Ok(CanvasDockerOutput {
            exit_code: 0,
            stdout: format!(
                "__CANVAS_LTI_RESULT__{}\n",
                self.responses.lock().unwrap().pop_front().unwrap()
            ),
            stderr: String::new(),
        })
    }
}

fn cfg() -> CanvasRailsConfig {
    CanvasRailsConfig {
        container_name: "marty-canvas-real".into(),
        account_id: "1".into(),
        admin_email: "admin@example.com".into(),
        admin_password: "test-admin-password".into(),
        browser_base_url: "https://canvas.example".into(),
        lti_client_id: "client-1".into(),
        lti_tool_base_url: "https://marty.example".into(),
        display_name: "Canvas Demo".into(),
    }
}

struct AdminStub {
    outputs: Mutex<VecDeque<String>>,
    operations: Mutex<Vec<Value>>,
}

#[async_trait]
impl CanvasDockerTransport for AdminStub {
    async fn run(&self, operation: CanvasDockerOperation) -> Result<CanvasDockerOutput, String> {
        if operation.args[0] == "ps" {
            return Ok(CanvasDockerOutput {
                exit_code: 0,
                stdout: "stack_marty-canvas-real\n".into(),
                stderr: String::new(),
            });
        }
        let mut args = operation.args;
        let mut input = operation.input;
        let mut record = json!({
            "command": null,
            "input": input,
            "timeout": operation.timeout_seconds
        });
        if let Some(index) = args
            .iter()
            .position(|arg| arg.starts_with("CANVAS_ADMIN_TOKEN_SETUP_B64="))
        {
            let encoded = args[index]
                .strip_prefix("CANVAS_ADMIN_TOKEN_SETUP_B64=")
                .unwrap();
            record["payload"] = serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
            args[index] = "CANVAS_ADMIN_TOKEN_SETUP_B64=<payload>".into();
            let script = input.take().unwrap();
            record["input"] = json!("<token-script>");
            record["script_sha256"] = json!(hex::encode(Sha256::digest(script.as_bytes())));
        }
        record["command"] = json!(std::iter::once("docker".to_owned())
            .chain(args.into_iter())
            .collect::<Vec<_>>());
        self.operations.lock().unwrap().push(record);
        Ok(CanvasDockerOutput {
            exit_code: 0,
            stdout: self.outputs.lock().unwrap().pop_front().unwrap(),
            stderr: String::new(),
        })
    }
}

#[tokio::test]
async fn canvas_admin_bootstrap_matches_frozen_python() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let frozen = &contract["canvas_admin_bootstrap"];
    let initial = AdminStub {
        outputs: Mutex::new(VecDeque::from(vec![
            "no\n".into(),
            "".into(),
            "yes\n".into(),
        ])),
        operations: Mutex::new(Vec::new()),
    };
    assert!(ensure_canvas_initial_data(&initial, &cfg()).await.unwrap());
    assert_eq!(
        json!(*initial.operations.lock().unwrap()),
        frozen["initial_data"]["operations"]
    );
    let mint = AdminStub {
        outputs: Mutex::new(VecDeque::from(vec![
            "yes\n".into(),
            "__CANVAS_ADMIN_TOKEN__test-admin-token\n".into(),
        ])),
        operations: Mutex::new(Vec::new()),
    };
    assert_eq!(
        mint_canvas_admin_token(&mint, &cfg()).await.unwrap(),
        frozen["mint_token"]["result"]
    );
    assert_eq!(
        json!(*mint.operations.lock().unwrap()),
        frozen["mint_token"]["operations"]
    );
    assert_eq!(
        hex::encode(Sha256::digest(CANVAS_ADMIN_TOKEN_SCRIPT.as_bytes())),
        frozen["mint_token"]["operations"][1]["script_sha256"]
    );
}

#[tokio::test]
async fn canvas_rails_lti_requests_match_frozen_python() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let frozen = &contract["canvas_rails_lti"];
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![
            json!({"developer_key": frozen["developer_key"]["key"]}),
            json!({"public_domain": {"action": "updated", "host": "canvas.example", "accounts": [{"id": 1}]}}),
            json!({"external_tool": frozen["external_tool"]["tool"]}),
        ])),
        operations: Mutex::new(Vec::new()),
    };
    let cfg = cfg();
    assert_eq!(
        ensure_canvas_developer_key(&stub, &cfg, "platform-1")
            .await
            .unwrap(),
        frozen["developer_key"]
    );
    assert_eq!(
        ensure_canvas_public_domain(&stub, &cfg).await.unwrap(),
        frozen["public_domain"]
    );
    assert_eq!(
        ensure_canvas_external_tool(&stub, &cfg, "platform-1", "42")
            .await
            .unwrap(),
        frozen["external_tool"]
    );
    assert_eq!(
        json!(*stub.operations.lock().unwrap()),
        frozen["operations"]
    );
    assert_eq!(
        hex::encode(Sha256::digest(CANVAS_LTI_SETUP_SCRIPT.as_bytes())),
        frozen["operations"][0]["script_sha256"]
    );
}
