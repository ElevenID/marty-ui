use async_trait::async_trait;
use marty_canvas_demo_seed::{
    seed_canvas_lms_objects, CanvasDockerOperation, CanvasDockerOutput, CanvasDockerTransport,
    CanvasOperation, CanvasRestError, CanvasRestTransport, SeedRunConfig,
};
use serde_json::{json, Value};
use std::{collections::VecDeque, sync::Mutex};

struct DockerStub {
    results: Mutex<VecDeque<Value>>,
}

#[async_trait]
impl CanvasDockerTransport for DockerStub {
    async fn run(&self, operation: CanvasDockerOperation) -> Result<CanvasDockerOutput, String> {
        if operation.args[0] == "ps" {
            return Ok(CanvasDockerOutput {
                exit_code: 0,
                stdout: "marty-canvas-real\n".into(),
                stderr: String::new(),
            });
        }
        Ok(CanvasDockerOutput {
            exit_code: 0,
            stdout: format!(
                "__CANVAS_LTI_RESULT__{}\n",
                self.results.lock().unwrap().pop_front().unwrap()
            ),
            stderr: String::new(),
        })
    }
}

struct RestStub {
    results: Mutex<VecDeque<Result<Value, CanvasRestError>>>,
}

#[async_trait]
impl CanvasRestTransport for RestStub {
    async fn request(&self, _operation: CanvasOperation) -> Result<Value, CanvasRestError> {
        self.results
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected Canvas REST request")
    }
}

fn config(contract: &Value) -> SeedRunConfig {
    let mut config: SeedRunConfig =
        serde_json::from_value(contract["canvas_cli_config"].clone()).unwrap();
    config.canvas.browser_base_url = "https://canvas.example".into();
    config.canvas.course_name = "Marty Course".into();
    config.canvas.course_code = "MARTY-101".into();
    config.canvas.course_sis_id = "marty-course".into();
    config.canvas.learner_name = "Test Learner".into();
    config.canvas.learner_email = "learner@example.com".into();
    config.canvas.launch_module_name = "Credential Launch".into();
    config.canvas.launch_item_title = "Launch Credential".into();
    config.canvas.launch_assignment_name = "Credential Assignment".into();
    config.canvas.quiz_title = "Credential Quiz".into();
    config.connector.display_name = "Canvas Demo".into();
    config.connector.lti_client_id = "client-1".into();
    config.connector.lti_tool_base_url = "https://marty.example".into();
    config
}

fn docker_stub() -> DockerStub {
    DockerStub {
        results: Mutex::new(VecDeque::from(vec![
            json!({"public_domain": {"action": "updated", "host": "canvas.example", "accounts": []}}),
            json!({"developer_key": {
                "id": 5, "name": "client-1", "global_id": "client-1", "action": "created",
                "owner_binding_account_id": 1, "owner_binding_workflow_state": "on",
                "requested_binding_account_id": 1, "requested_binding_workflow_state": "on"
            }}),
            json!({"external_tool": {
                "id": 99, "name": "Canvas Demo", "deployment_id": "deployment-1", "action": "created"
            }}),
        ])),
    }
}

fn rest_results(summary: &Value, case: &str) -> VecDeque<Result<Value, CanvasRestError>> {
    let mut values = vec![
        Ok(json!([])),
        Ok(summary["course"].clone()),
        Ok(json!([])),
        Ok(json!([summary["learner"]])),
        Ok(json!([])),
        Ok(summary["enrollment"].clone()),
        Ok(json!([])),
        Ok(json!({"id": 10, "name": "Credential Launch"})),
        Ok(json!([])),
        Ok(
            json!({"id": 11, "title": "Launch Credential", "html_url": "https://canvas.example/items/11"}),
        ),
        Ok(json!([])),
    ];
    if case == "assignment_error" {
        values.push(Err(CanvasRestError::Http(422, "unsupported".into())));
    } else {
        values.push(Ok(json!({"id": 14, "name": "Credential Assignment", "html_url": "https://canvas.example/assignments/14"})));
    }
    if case == "quiz_error" {
        values.push(Err(CanvasRestError::Http(422, "unsupported".into())));
    } else {
        values.extend([
            Ok(json!([])), Ok(json!({"id": 12, "title": "Credential Quiz", "html_url": "https://canvas.example/quizzes/12"})),
            Ok(json!([])), Ok(json!({"id": 13, "title": "Credential Quiz", "html_url": "https://canvas.example/items/13"})),
        ]);
    }
    values.into()
}

#[tokio::test]
async fn full_lms_summary_and_assignment_failure_match_frozen_python() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let cfg = config(&contract);
    for case in ["complete", "assignment_error", "quiz_error"] {
        let expected = &contract["canvas_lms_summary"][case];
        let docker = docker_stub();
        let rest = RestStub {
            results: Mutex::new(rest_results(expected, case)),
        };
        let result =
            seed_canvas_lms_objects(&docker, &rest, &cfg.canvas, &cfg.connector, "platform-1")
                .await
                .unwrap();
        assert_eq!(result.summary, *expected, "{case}");
        assert!(rest.results.lock().unwrap().is_empty());
        assert!(docker.results.lock().unwrap().is_empty());
    }
}
